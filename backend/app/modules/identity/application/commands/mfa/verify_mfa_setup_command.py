"""
Verify MFA setup command implementation.

Handles verification of newly setup MFA devices.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import IMFADeviceRepository
from app.modules.identity.domain.interfaces.services.communication.notification_service import INotificationService
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import VerifyMFASetupRequest
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import MFADevice
from app.modules.identity.domain.enums import AuditAction, DeviceStatus, MFAMethod
from app.modules.identity.domain.events import MFADeviceVerified
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    InvalidVerificationCodeError,
    MFAAlreadyVerifiedError,
    MFADeviceNotFoundError,
)
from app.modules.identity.domain.services import MFAService, SecurityService


class VerifyMFASetupCommand(Command[BaseResponse]):
    """Command to verify MFA device setup."""
    
    def __init__(
        self,
        user_id: UUID,
        device_id: UUID,
        verification_code: str,
        ip_address: str | None = None
    ):
        self.user_id = user_id
        self.device_id = device_id
        self.verification_code = verification_code
        self.ip_address = ip_address


class VerifyMFASetupCommandHandler(CommandHandler[VerifyMFASetupCommand, BaseResponse]):
    """Handler for verifying MFA setup."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        mfa_device_repository: IMFADeviceRepository,
        mfa_service: MFAService,
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
        self._security_service = security_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.MFA_DEVICE_VERIFIED,
        resource_type="mfa_device",
        resource_id_attr="device_id",
        include_request=True
    )
    @require_auth
    @validate_request(VerifyMFASetupRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=300,  # 5 minutes
        strategy='user'
    )
    async def handle(self, command: VerifyMFASetupCommand) -> BaseResponse:
        """
        Verify MFA device setup.
        
        Process:
        1. Load device and validate ownership
        2. Check if already verified
        3. Verify the code based on method
        4. Mark device as verified
        5. Update user MFA status
        6. Send confirmation
        7. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            MFADeviceNotFoundError: If device not found
            InvalidVerificationCodeError: If code invalid
            MFAAlreadyVerifiedError: If already verified
        """
        async with self._unit_of_work:
            # 1. Load MFA device
            device = await self._mfa_device_repository.find_by_id(command.device_id)
            
            if not device:
                raise MFADeviceNotFoundError(
                    f"MFA device {command.device_id} not found"
                )
            
            # 2. Verify ownership
            if device.user_id != command.user_id:
                raise InvalidOperationError("Device does not belong to user")
            
            # 3. Check if already verified
            if device.is_verified:
                raise MFAAlreadyVerifiedError("MFA device is already verified")
            
            # 4. Check device status
            if device.status != DeviceStatus.PENDING:
                raise InvalidOperationError(
                    f"Cannot verify device with status: {device.status.value}"
                )
            
            # 5. Verify code based on method
            is_valid = await self._verify_code(
                device=device,
                code=command.verification_code
            )
            
            if not is_valid:
                # Log failed attempt
                await self._log_failed_verification(device, command)
                
                # Increment failure count
                device.verification_attempts += 1
                
                # Disable device after too many attempts
                if device.verification_attempts >= 5:
                    device.disable("Too many failed verification attempts")
                    await self._mfa_device_repository.update(device)
                    
                    raise InvalidOperationError(
                        "Device disabled due to too many failed attempts"
                    )
                
                await self._mfa_device_repository.update(device)
                
                raise InvalidVerificationCodeError("Invalid verification code")
            
            # 6. Mark device as verified
            device.verify()
            await self._mfa_device_repository.update(device)
            
            # 7. Load user and update MFA status
            user = await self._user_repository.find_by_id(device.user_id)
            
            if not user.mfa_enabled:
                user.mfa_enabled = True
                user.mfa_enabled_at = datetime.now(UTC)
                await self._user_repository.update(user)
            
            # 8. Clear verification cache
            if device.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
                await self._cache_service.delete(f"mfa_verify:{device.id}")
            
            # 9. Clear MFA device cache
            await self._cache_service.delete(f"mfa_devices:{user.id}")
            
            # 10. Send confirmation
            await self._send_verification_confirmation(
                user=user,
                device=device
            )
            
            # 11. Log security event
            await self._security_service.log_security_event(
                user_id=user.id,
                event_type="mfa_device_verified",
                ip_address=command.ip_address,
                details={
                    "device_id": str(device.id),
                    "method": device.method.value,
                    "device_name": device.name
                }
            )
            
            # 12. Publish event
            await self._event_bus.publish(
                MFADeviceVerified(
                    aggregate_id=user.id,
                    device_id=device.id,
                    method=device.method,
                    is_first_device=await self._is_first_verified_device(user.id)
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message=f"MFA device '{device.name}' verified successfully"
            )
    
    async def _verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> bool:
        """Verify code based on device method."""
        if device.method == MFAMethod.AUTHENTICATOR_APP:
            # Verify TOTP code
            secret = await self._mfa_service.decrypt_secret(device.secret)
            return await self._mfa_service.verify_totp(secret, code)
            
        if device.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            # Verify against cached code
            cached_code = await self._cache_service.get(f"mfa_verify:{device.id}")
            
            if not cached_code:
                return False
            
            return code == cached_code
            
        # Backup codes don't need verification
        return False
    
    async def _log_failed_verification(
        self,
        device: MFADevice,
        command: VerifyMFASetupCommand
    ) -> None:
        """Log failed verification attempt."""
        await self._security_service.log_security_event(
            user_id=device.user_id,
            event_type="mfa_verification_failed",
            ip_address=command.ip_address,
            details={
                "device_id": str(device.id),
                "method": device.method.value,
                "attempts": device.verification_attempts + 1
            }
        )
    
    async def _send_verification_confirmation(
        self,
        user: any,
        device: MFADevice
    ) -> None:
        """Send MFA verification confirmation."""
        method_names = {
            MFAMethod.AUTHENTICATOR_APP: "Authenticator app",
            MFAMethod.SMS: "SMS",
            MFAMethod.EMAIL: "Email",
            MFAMethod.BACKUP_CODES: "Backup codes"
        }
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="mfa_device_verified",
                subject="MFA device verified",
                variables={
                    "username": user.username,
                    "device_name": device.name,
                    "method": method_names.get(device.method, "Unknown"),
                    "verified_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "manage_url": "https://app.example.com/settings/security"
                }
            )
        )
    
    async def _is_first_verified_device(self, user_id: UUID) -> bool:
        """Check if this is the first verified MFA device."""
        devices = await self._mfa_device_repository.get_verified_devices(user_id)
        return len(devices) == 1