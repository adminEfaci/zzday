"""
Disable MFA command implementation.

Handles disabling of MFA devices with security verification.
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
from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import MFADevice, User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeviceStatus,
    MFAMethod,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import MFADisabled
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidOperationError,
    LastMFADeviceError,
    MFADeviceNotFoundError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    MFAService,
    PasswordService,
    SecurityService,
)


class DisableMFACommand(Command[BaseResponse]):
    """Command to disable MFA device."""
    
    def __init__(
        self,
        user_id: UUID,
        device_id: UUID,
        password: str,
        disable_all: bool = False,
        reason: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None
    ):
        self.user_id = user_id
        self.device_id = device_id
        self.password = password
        self.disable_all = disable_all
        self.reason = reason
        self.ip_address = ip_address
        self.user_agent = user_agent


class DisableMFACommandHandler(CommandHandler[DisableMFACommand, BaseResponse]):
    """Handler for disabling MFA."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        mfa_device_repository: IMFADeviceRepository,
        session_repository: ISessionRepository,
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
        self._session_repository = session_repository
        self._mfa_service = mfa_service
        self._password_service = password_service
        self._security_service = security_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.MFA_DISABLED,
        resource_type="mfa_device",
        resource_id_attr="device_id",
        include_request=False  # Don't log password
    )
    @require_auth
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: DisableMFACommand) -> BaseResponse:
        """
        Disable MFA device with password verification.
        
        Process:
        1. Load user and verify password
        2. Load device(s) and validate
        3. Check if last device (security risk)
        4. Disable device(s)
        5. Update user MFA status
        6. Send notifications
        7. Log security events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If password wrong
            MFADeviceNotFoundError: If device not found
            LastMFADeviceError: If trying to disable last device
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
                await self._log_failed_disable_attempt(user, command)
                raise InvalidCredentialsError("Invalid password")
            
            # 3. Handle disable all vs single device
            devices_to_disable = []
            
            if command.disable_all:
                # Get all active devices
                all_devices = await self._mfa_device_repository.get_active_devices(
                    user.id
                )
                devices_to_disable = all_devices
                
            else:
                # Load specific device
                device = await self._mfa_device_repository.find_by_id(command.device_id)
                
                if not device:
                    raise MFADeviceNotFoundError(
                        f"MFA device {command.device_id} not found"
                    )
                
                if device.user_id != command.user_id:
                    raise InvalidOperationError("Device does not belong to user")
                
                if device.status == DeviceStatus.DISABLED:
                    raise InvalidOperationError("Device is already disabled")
                
                devices_to_disable = [device]
            
            # 4. Check if this would disable all MFA
            if not command.disable_all:
                active_devices = await self._mfa_device_repository.get_active_devices(
                    user.id
                )
                
                # Don't count backup codes as a standalone method
                non_backup_devices = [
                    d for d in active_devices 
                    if d.method != MFAMethod.BACKUP_CODES
                ]
                
                if len(non_backup_devices) <= 1 and devices_to_disable[0].method != MFAMethod.BACKUP_CODES:
                    # This is the last real MFA device
                    if not await self._allow_last_device_removal(user, command):
                        raise LastMFADeviceError(
                            "Cannot disable last MFA device. Add another device first."
                        )
            
            # 5. Disable devices
            disabled_count = 0
            for device in devices_to_disable:
                device.disable(command.reason or "User requested")
                await self._mfa_device_repository.update(device)
                disabled_count += 1
            
            # 6. Update user MFA status if all disabled
            remaining_active = await self._mfa_device_repository.count_active_devices(
                user.id
            )
            
            if remaining_active == 0 or (
                remaining_active == 1 and 
                await self._only_backup_codes_remain(user.id)
            ):
                user.mfa_enabled = False
                user.mfa_disabled_at = datetime.now(UTC)
                await self._user_repository.update(user)
            
            # 7. Clear MFA caches
            await self._clear_mfa_caches(user.id)
            
            # 8. Send notifications
            await self._send_disable_notification(
                user=user,
                devices=devices_to_disable,
                all_disabled=command.disable_all or remaining_active == 0
            )
            
            # 9. Log security event
            await self._log_mfa_disable(
                user=user,
                devices=devices_to_disable,
                command=command
            )
            
            # 10. Check for suspicious activity
            if await self._is_suspicious_disable(user, command):
                await self._handle_suspicious_disable(user, command)
            
            # 11. Publish event
            await self._event_bus.publish(
                MFADisabled(
                    aggregate_id=user.id,
                    device_ids=[d.id for d in devices_to_disable],
                    all_disabled=command.disable_all or remaining_active == 0,
                    ip_address=command.ip_address
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            message = f"Disabled {disabled_count} MFA device(s)."
            if remaining_active == 0:
                message += " MFA is now completely disabled for your account."
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _log_failed_disable_attempt(
        self,
        user: User,
        command: DisableMFACommand
    ) -> None:
        """Log failed MFA disable attempt."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="mfa_disable_failed",
            ip_address=command.ip_address,
            details={
                "reason": "invalid_password",
                "device_id": str(command.device_id),
                "disable_all": command.disable_all
            }
        )
    
    async def _allow_last_device_removal(
        self,
        user: User,
        command: DisableMFACommand
    ) -> bool:
        """Check if we should allow removal of last MFA device."""
        # Could check user roles, admin override, etc.
        # For now, prevent it for security
        return False
    
    async def _only_backup_codes_remain(self, user_id: UUID) -> bool:
        """Check if only backup codes remain as MFA."""
        active_devices = await self._mfa_device_repository.get_active_devices(user_id)
        
        return all(d.method == MFAMethod.BACKUP_CODES for d in active_devices)
    
    async def _clear_mfa_caches(self, user_id: UUID) -> None:
        """Clear MFA-related caches."""
        cache_keys = [
            f"mfa_devices:{user_id}",
            f"mfa_status:{user_id}",
            f"user:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _send_disable_notification(
        self,
        user: User,
        devices: list[MFADevice],
        all_disabled: bool
    ) -> None:
        """Send MFA disable notification."""
        device_list = []
        for device in devices:
            device_list.append({
                "name": device.name,
                "method": device.method.value,
                "disabled_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            })
        
        template = "mfa_all_disabled" if all_disabled else "mfa_device_disabled"
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template=template,
                subject="MFA has been disabled on your account",
                variables={
                    "username": user.username,
                    "devices": device_list,
                    "device_count": len(devices),
                    "security_warning": "Your account is now less secure without MFA.",
                    "enable_url": "https://app.example.com/settings/security",
                    "support_url": "https://app.example.com/support"
                },
                priority="high"
            )
        )
    
    async def _log_mfa_disable(
        self,
        user: User,
        devices: list[MFADevice],
        command: DisableMFACommand
    ) -> None:
        """Log MFA disable event."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="mfa_disabled",
            ip_address=command.ip_address,
            details={
                "devices": [
                    {
                        "id": str(d.id),
                        "name": d.name,
                        "method": d.method.value
                    }
                    for d in devices
                ],
                "disable_all": command.disable_all,
                "reason": command.reason
            }
        )
    
    async def _is_suspicious_disable(
        self,
        user: User,
        command: DisableMFACommand
    ) -> bool:
        """Check if MFA disable seems suspicious."""
        # Check for recent password changes
        if user.password_changed_at:
            time_since_change = datetime.now(UTC) - user.password_changed_at
            if time_since_change.hours < 1:
                return True
        
        # Check for unusual IP
        if command.ip_address:
            recent_ips = await self._get_user_recent_ips(user.id)
            if recent_ips and command.ip_address not in recent_ips:
                return True
        
        # Check if disabling all at once
        return bool(command.disable_all)
    
    async def _handle_suspicious_disable(
        self,
        user: User,
        command: DisableMFACommand
    ) -> None:
        """Handle suspicious MFA disable."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_MFA_DISABLE,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                ip_address=command.ip_address,
                details={
                    "disable_all": command.disable_all,
                    "user_agent": command.user_agent
                }
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "Suspicious MFA disable detected",
            {
                "user_id": str(user.id),
                "username": user.username,
                "ip_address": command.ip_address,
                "disable_all": command.disable_all
            }
        )
    
    async def _get_user_recent_ips(self, user_id: UUID) -> list[str]:
        """Get user's recent IP addresses."""
        # This would typically query session/login history
        return []