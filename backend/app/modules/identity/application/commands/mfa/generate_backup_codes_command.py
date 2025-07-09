"""
Generate backup codes command implementation.

Handles generation of new MFA backup codes.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.response import MFASetupResponse
from app.modules.identity.domain.entities import MFADevice, User
from app.modules.identity.domain.enums import AuditAction, DeviceStatus, MFAMethod
from app.modules.identity.domain.events import BackupCodesGenerated
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    MFANotEnabledError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import (
    IMFADeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    ICachePort,
)
    MFAService,
    PasswordService,
    SecurityService,
)


class GenerateBackupCodesCommand(Command[MFASetupResponse]):
    """Command to generate new backup codes."""
    
    def __init__(
        self,
        user_id: UUID,
        password: str,
        invalidate_old: bool = True,
        code_count: int = 10,
        ip_address: str | None = None
    ):
        self.user_id = user_id
        self.password = password
        self.invalidate_old = invalidate_old
        self.code_count = code_count
        self.ip_address = ip_address


class GenerateBackupCodesCommandHandler(CommandHandler[GenerateBackupCodesCommand, MFASetupResponse]):
    """Handler for generating backup codes."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        mfa_device_repository: IMFADeviceRepository,
        mfa_service: MFAService,
        password_service: PasswordService,
        security_service: SecurityService,
        email_service: IEmailService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._mfa_device_repository = mfa_device_repository
        self._mfa_service = mfa_service
        self._password_service = password_service
        self._security_service = security_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.BACKUP_CODES_GENERATED,
        resource_type="mfa_device",
        include_request=False  # Don't log password
    )
    @require_auth
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: GenerateBackupCodesCommand) -> MFASetupResponse:
        """
        Generate new backup codes with password verification.
        
        Process:
        1. Load user and verify password
        2. Check MFA is enabled
        3. Find or create backup code device
        4. Generate new codes
        5. Invalidate old codes if requested
        6. Save hashed codes
        7. Send notification
        8. Return plaintext codes
        
        Returns:
            MFASetupResponse with backup codes
            
        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If password wrong
            MFANotEnabledError: If MFA not enabled
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Verify password for security
            is_valid = await self._password_service.verify_password(
                command.password,
                user.password_hash
            )
            
            if not is_valid:
                # Log failed attempt
                await self._log_failed_generation_attempt(user, command)
                raise InvalidCredentialsError("Invalid password")
            
            # 3. Check if user has MFA enabled
            if not user.mfa_enabled:
                raise MFANotEnabledError(
                    "MFA must be enabled before generating backup codes"
                )
            
            # 4. Check if user has any active MFA devices
            active_devices = await self._mfa_device_repository.get_active_devices(
                user.id
            )
            
            non_backup_devices = [
                d for d in active_devices 
                if d.method != MFAMethod.BACKUP_CODES
            ]
            
            if not non_backup_devices:
                raise MFANotEnabledError(
                    "You must have at least one primary MFA method enabled"
                )
            
            # 5. Find existing backup code device
            backup_devices = await self._mfa_device_repository.get_by_user_and_method(
                user_id=user.id,
                method=MFAMethod.BACKUP_CODES
            )
            
            device = None
            old_codes_count = 0
            
            if backup_devices:
                device = backup_devices[0]
                
                if device.status == DeviceStatus.DISABLED:
                    # Reactivate if disabled
                    device.status = DeviceStatus.ACTIVE
                
                # Count remaining old codes
                old_codes_count = len(device.backup_codes)
                
                if command.invalidate_old:
                    # Clear old codes
                    device.backup_codes = []
                    device.backup_codes_invalidated_at = datetime.now(UTC)
            else:
                # Create new backup code device
                device = MFADevice.create(
                    user_id=user.id,
                    method=MFAMethod.BACKUP_CODES,
                    name="Backup Codes",
                    is_primary=False
                )
                device.verify()  # Backup codes are pre-verified
                await self._mfa_device_repository.add(device)
            
            # 6. Generate new codes
            if command.code_count < 5 or command.code_count > 20:
                command.code_count = 10  # Default to 10 codes
            
            backup_codes = await self._mfa_service.generate_backup_codes(
                count=command.code_count
            )
            
            # 7. Hash and store codes
            hashed_codes = []
            for code in backup_codes:
                hashed = await self._mfa_service.hash_backup_code(code)
                hashed_codes.append(hashed)
            
            # Add new codes to existing if not invalidating
            if not command.invalidate_old and device.backup_codes:
                device.backup_codes.extend(hashed_codes)
            else:
                device.backup_codes = hashed_codes
            
            device.backup_codes_generated_at = datetime.now(UTC)
            device.backup_codes_used = 0 if command.invalidate_old else device.backup_codes_used
            
            # 8. Update device
            await self._mfa_device_repository.update(device)
            
            # 9. Clear MFA cache
            await self._cache_service.delete(f"mfa_devices:{user.id}")
            
            # 10. Send notification
            await self._send_codes_generated_notification(
                user=user,
                new_codes_count=len(backup_codes),
                old_codes_invalidated=command.invalidate_old,
                old_codes_count=old_codes_count
            )
            
            # 11. Log security event
            await self._security_service.log_security_event(
                user_id=user.id,
                event_type="backup_codes_generated",
                ip_address=command.ip_address,
                details={
                    "codes_generated": len(backup_codes),
                    "old_codes_invalidated": command.invalidate_old,
                    "old_codes_count": old_codes_count
                }
            )
            
            # 12. Publish event
            await self._event_bus.publish(
                BackupCodesGenerated(
                    aggregate_id=user.id,
                    device_id=device.id,
                    codes_count=len(backup_codes),
                    old_codes_invalidated=command.invalidate_old
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return MFASetupResponse(
                device_id=device.id,
                backup_codes=backup_codes,
                verification_required=False,
                success=True,
                message=f"Generated {len(backup_codes)} backup codes. Store them securely."
            )
    
    async def _log_failed_generation_attempt(
        self,
        user: User,
        command: GenerateBackupCodesCommand
    ) -> None:
        """Log failed backup code generation attempt."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="backup_codes_generation_failed",
            ip_address=command.ip_address,
            details={
                "reason": "invalid_password"
            }
        )
    
    async def _send_codes_generated_notification(
        self,
        user: User,
        new_codes_count: int,
        old_codes_invalidated: bool,
        old_codes_count: int
    ) -> None:
        """Send backup codes generated notification."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="backup_codes_generated",
                subject="New backup codes generated",
                variables={
                    "username": user.username,
                    "codes_count": new_codes_count,
                    "old_codes_invalidated": old_codes_invalidated,
                    "old_codes_count": old_codes_count,
                    "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "security_tip": "Store these codes in a secure location. Each code can only be used once.",
                    "manage_url": "https://app.example.com/settings/security"
                },
                priority="high"
            )
        )