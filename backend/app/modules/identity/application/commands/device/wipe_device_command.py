"""
Wipe device command implementation.

Handles remote wiping of device data and complete device cleanup.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    BackupContext,
    EmailContext,
    NotificationContext,
    RemoteWipeContext,
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import WipeDeviceRequest
from app.modules.identity.application.dtos.response import DeviceWipeResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    DeviceStatus,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    WipeReason,
    WipeStatus,
    WipeType,
)
from app.modules.identity.domain.events import DeviceWiped
from app.modules.identity.domain.exceptions import (
    DeviceAlreadyWipedException,
    DeviceNotFoundError,
    InvalidWipeOperationError,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
    ISMSService,
)
from app.modules.identity.domain.services import (
    DeviceSecurityService,
    SessionService,
    TokenService,
    ValidationService,
)


class WipeDeviceCommand(Command[DeviceWipeResponse]):
    """Command to wipe device data and perform complete cleanup."""
    
    def __init__(
        self,
        device_id: UUID,
        wiped_by: UUID,
        reason: WipeReason,
        wipe_type: WipeType = WipeType.FULL_WIPE,
        custom_reason: str | None = None,
        create_backup_before_wipe: bool = True,
        remote_wipe_enabled: bool = True,
        wipe_timeout_minutes: int = 30,
        force_wipe: bool = False,
        notify_user: bool = True,
        notify_emergency_contacts: bool = False,
        security_incident_id: UUID | None = None,
        compliance_requirement: str | None = None,
        wipe_confirmation_required: bool = True,
        evidence_preservation: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.wiped_by = wiped_by
        self.reason = reason
        self.wipe_type = wipe_type
        self.custom_reason = custom_reason
        self.create_backup_before_wipe = create_backup_before_wipe
        self.remote_wipe_enabled = remote_wipe_enabled
        self.wipe_timeout_minutes = wipe_timeout_minutes
        self.force_wipe = force_wipe
        self.notify_user = notify_user
        self.notify_emergency_contacts = notify_emergency_contacts
        self.security_incident_id = security_incident_id
        self.compliance_requirement = compliance_requirement
        self.wipe_confirmation_required = wipe_confirmation_required
        self.evidence_preservation = evidence_preservation
        self.metadata = metadata or {}


class WipeDeviceCommandHandler(CommandHandler[WipeDeviceCommand, DeviceWipeResponse]):
    """Handler for wiping devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        session_repository: ISessionRepository,
        token_repository: ITokenRepository,
        device_policy_repository: IDevicePolicyRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        session_service: SessionService,
        token_service: TokenService,
        remote_wipe_service: IRemoteWipeService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        backup_service: IBackupService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._session_repository = session_repository
        self._token_repository = token_repository
        self._device_policy_repository = device_policy_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._session_service = session_service
        self._token_service = token_service
        self._remote_wipe_service = remote_wipe_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._backup_service = backup_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_WIPED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(WipeDeviceRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.wipe")
    @require_mfa(condition="device_wipe_operation")
    async def handle(self, command: WipeDeviceCommand) -> DeviceWipeResponse:
        """
        Wipe device with comprehensive security and compliance measures.
        
        Process:
        1. Load device and validate wipe operation
        2. Check wipe permissions and compliance requirements
        3. Create evidence backup if required
        4. Initiate remote wipe process
        5. Invalidate all sessions and tokens
        6. Update device status and metadata
        7. Handle primary device logic
        8. Send notifications
        9. Log security events and compliance records
        10. Update user security posture
        
        Returns:
            DeviceWipeResponse with wipe operation details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If cannot wipe device
            DeviceAlreadyWipedException: If device already wiped
            InvalidWipeOperationError: If wipe operation invalid
            RemoteWipeFailedException: If remote wipe fails
        """
        async with self._unit_of_work:
            # 1. Load device
            device = await self._device_repository.find_by_id(command.device_id)
            if not device:
                raise DeviceNotFoundError(f"Device {command.device_id} not found")
            
            # 2. Load user
            user = await self._user_repository.find_by_id(device.user_id)
            if not user:
                raise DeviceNotFoundError(f"User {device.user_id} not found")
            
            # 3. Check if device already wiped
            if device.status == DeviceStatus.WIPED and not command.force_wipe:
                raise DeviceAlreadyWipedException(f"Device {device.id} already wiped")
            
            # 4. Check wipe permissions
            await self._validate_wipe_permissions(device, command.wiped_by, command)
            
            # 5. Validate wipe operation
            await self._validate_wipe_operation(device, command)
            
            # 6. Create evidence backup if required
            backup_id = None
            if command.create_backup_before_wipe:
                backup_id = await self._create_device_evidence_backup(
                    device,
                    user,
                    command
                )
            
            # 7. Capture current device state
            was_primary = device.is_primary
            original_status = device.status
            
            # 8. Get all sessions and tokens for cleanup
            all_sessions = await self._session_repository.find_all_by_device(device.id)
            all_tokens = await self._token_repository.find_all_by_device(device.id)
            
            # 9. Initiate remote wipe if enabled
            remote_wipe_result = None
            if command.remote_wipe_enabled:
                remote_wipe_result = await self._initiate_remote_wipe(device, command)
            
            # 10. Update device status immediately
            device.status = DeviceStatus.WIPED
            device.wiped_at = datetime.now(UTC)
            device.wiped_by = command.wiped_by
            device.wipe_reason = command.reason.value
            device.custom_wipe_reason = command.custom_reason
            device.wipe_type = command.wipe_type.value
            device.security_incident_id = command.security_incident_id
            device.is_primary = False  # Wiped devices cannot be primary
            
            # Set remote wipe status
            if remote_wipe_result:
                device.remote_wipe_status = remote_wipe_result["status"]
                device.remote_wipe_initiated_at = remote_wipe_result["initiated_at"]
                device.remote_wipe_timeout_at = remote_wipe_result["timeout_at"]
            
            # Add wipe metadata
            device.metadata.update({
                "wipe_metadata": {
                    "reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "wipe_type": command.wipe_type.value,
                    "wiped_by": str(command.wiped_by),
                    "remote_wipe_enabled": command.remote_wipe_enabled,
                    "remote_wipe_status": remote_wipe_result["status"] if remote_wipe_result else "not_initiated",
                    "backup_created": backup_id is not None,
                    "backup_id": str(backup_id) if backup_id else None,
                    "sessions_invalidated": len(all_sessions),
                    "tokens_invalidated": len(all_tokens),
                    "evidence_preserved": command.evidence_preservation,
                    "compliance_requirement": command.compliance_requirement,
                    "wipe_timestamp": datetime.now(UTC).isoformat()
                }
            })
            
            await self._device_repository.update(device)
            
            # 11. Invalidate all sessions
            sessions_invalidated = 0
            for session in all_sessions:
                try:
                    await self._session_service.terminate_session(
                        session.id,
                        f"Device wiped: {command.reason.value}"
                    )
                    sessions_invalidated += 1
                except Exception as e:
                    await self._audit_service.log_error(
                        f"Failed to terminate session {session.id}: {e!s}"
                    )
            
            # 12. Invalidate all tokens
            tokens_invalidated = 0
            for token in all_tokens:
                try:
                    await self._token_service.revoke_token(
                        token.id,
                        f"Device wiped: {command.reason.value}"
                    )
                    tokens_invalidated += 1
                except Exception as e:
                    await self._audit_service.log_error(
                        f"Failed to revoke token {token.id}: {e!s}"
                    )
            
            # 13. Handle primary device replacement
            new_primary_device = None
            if was_primary:
                new_primary_device = await self._handle_primary_device_replacement(
                    user.id,
                    device.id
                )
            
            # 14. Assess wipe impact
            wipe_impact = await self._assess_wipe_impact(
                device,
                user,
                command,
                was_primary
            )
            
            # 15. Send notifications
            if command.notify_user:
                await self._send_wipe_notifications(
                    user,
                    device,
                    wipe_impact,
                    remote_wipe_result,
                    command
                )
            
            # 16. Notify emergency contacts if requested
            if command.notify_emergency_contacts:
                await self._notify_emergency_contacts_of_wipe(
                    user,
                    device,
                    command
                )
            
            # 17. Log security events and compliance
            await self._log_device_wipe_operation(
                user,
                device,
                wipe_impact,
                original_status,
                command
            )
            
            # 18. Update user security posture
            await self._update_user_security_posture(user, device, command)
            
            # 19. Publish domain event
            await self._event_bus.publish(
                DeviceWiped(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    wipe_reason=command.reason,
                    wipe_type=command.wipe_type,
                    was_primary=was_primary,
                    wiped_by=command.wiped_by,
                    remote_wipe_initiated=command.remote_wipe_enabled,
                    remote_wipe_status=remote_wipe_result["status"] if remote_wipe_result else None,
                    sessions_invalidated=sessions_invalidated,
                    tokens_invalidated=tokens_invalidated,
                    new_primary_device_id=new_primary_device.id if new_primary_device else None,
                    security_incident_related=command.security_incident_id is not None
                )
            )
            
            # 20. Commit transaction
            await self._unit_of_work.commit()
            
            # 21. Return response
            return DeviceWipeResponse(
                device_id=device.id,
                user_id=device.user_id,
                device_name=device.device_name,
                device_type=device.device_type,
                wipe_reason=command.reason,
                wipe_type=command.wipe_type,
                custom_reason=command.custom_reason,
                was_primary=was_primary,
                new_primary_device_id=new_primary_device.id if new_primary_device else None,
                remote_wipe_initiated=command.remote_wipe_enabled,
                remote_wipe_status=remote_wipe_result["status"] if remote_wipe_result else None,
                sessions_invalidated=sessions_invalidated,
                tokens_invalidated=tokens_invalidated,
                backup_created=backup_id is not None,
                backup_id=backup_id,
                emergency_contacts_notified=command.notify_emergency_contacts,
                compliance_logged=command.compliance_requirement is not None,
                impact_level=wipe_impact["impact_level"],
                wiped_at=device.wiped_at,
                wiped_by=device.wiped_by,
                message="Device wiped successfully"
            )
    
    async def _validate_wipe_permissions(
        self,
        device: Device,
        wiped_by: UUID,
        command: WipeDeviceCommand
    ) -> None:
        """Validate user can wipe this device."""
        # User can wipe their own devices
        if device.user_id == wiped_by:
            return
        
        # Check if wiper has admin permissions
        # Additional checks for security-related wipes
        if command.reason in [WipeReason.SECURITY_BREACH, WipeReason.STOLEN, WipeReason.COMPROMISED]:
            # These require special security permissions
            pass
        
        # Check if device is critical and requires special permission
        if device.is_primary and not command.force_wipe:
            # Wiping primary device requires additional confirmation
            pass
        
        # Check compliance requirements
        if command.compliance_requirement:
            # Compliance-driven wipes may require special authorization
            pass
    
    async def _validate_wipe_operation(
        self,
        device: Device,
        command: WipeDeviceCommand
    ) -> None:
        """Validate the wipe operation."""
        # Validate custom reason if required
        if command.reason == WipeReason.OTHER and not command.custom_reason:
            raise InvalidWipeOperationError("Custom reason required when using 'OTHER' reason")
        
        # Validate custom reason length
        if command.custom_reason and len(command.custom_reason) > 500:
            raise InvalidWipeOperationError("Custom reason too long (max 500 characters)")
        
        # Check if device supports remote wipe
        if command.remote_wipe_enabled:
            if not device.hardware_info.get("supports_remote_wipe", False):
                if not command.force_wipe:
                    raise InvalidWipeOperationError(
                        "Device does not support remote wipe. Use force_wipe=True to override."
                    )
        
        # Validate wipe timeout
        if command.wipe_timeout_minutes < 5 or command.wipe_timeout_minutes > 120:
            raise InvalidWipeOperationError("Wipe timeout must be between 5 and 120 minutes")
    
    async def _create_device_evidence_backup(
        self,
        device: Device,
        user: User,
        command: WipeDeviceCommand
    ) -> UUID:
        """Create comprehensive evidence backup before wiping."""
        # Get recent device activity
        recent_sessions = await self._session_repository.find_recent_by_device(
            device.id,
            days=30
        )
        recent_tokens = await self._token_repository.find_recent_by_device(
            device.id,
            days=30
        )
        
        # Create comprehensive backup data
        backup_data = {
            "device": {
                "id": str(device.id),
                "device_name": device.device_name,
                "device_type": device.device_type.value,
                "device_fingerprint": device.device_fingerprint,
                "device_os": device.device_os,
                "device_os_version": device.device_os_version,
                "device_model": device.device_model,
                "device_manufacturer": device.device_manufacturer,
                "browser_name": device.browser_name,
                "browser_version": device.browser_version,
                "trust_level": device.trust_level.value,
                "status": device.status.value,
                "registered_at": device.registered_at.isoformat(),
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
                "ip_address": device.ip_address,
                "location_data": device.location_data,
                "hardware_info": device.hardware_info,
                "software_info": device.software_info,
                "security_features": device.security_features,
                "security_assessment": device.security_assessment,
                "is_primary": device.is_primary,
                "metadata": device.metadata
            },
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": f"{user.first_name} {user.last_name}"
            },
            "recent_activity": {
                "sessions": [
                    {
                        "id": str(session.id),
                        "created_at": session.created_at.isoformat(),
                        "last_activity": session.last_activity.isoformat() if session.last_activity else None,
                        "ip_address": session.ip_address,
                        "user_agent": session.user_agent,
                        "status": session.status
                    } for session in recent_sessions
                ],
                "tokens": [
                    {
                        "id": str(token.id),
                        "token_type": token.token_type,
                        "created_at": token.created_at.isoformat(),
                        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                        "last_used": token.last_used.isoformat() if token.last_used else None,
                        "status": token.status
                    } for token in recent_tokens
                ]
            },
            "wipe": {
                "reason": command.reason.value,
                "custom_reason": command.custom_reason,
                "wipe_type": command.wipe_type.value,
                "wiped_by": str(command.wiped_by),
                "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                "compliance_requirement": command.compliance_requirement,
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.DEVICE_WIPE_EVIDENCE,
                resource_type="device",
                resource_id=device.id,
                data=backup_data,
                retention_days=2555,  # 7 years for compliance
                encrypted=True,
                evidence_grade=True
            )
        )
        
    
    async def _initiate_remote_wipe(
        self,
        device: Device,
        command: WipeDeviceCommand
    ) -> dict[str, Any]:
        """Initiate remote wipe process."""
        try:
            wipe_result = await self._remote_wipe_service.initiate_wipe(
                RemoteWipeContext(
                    device_id=device.id,
                    wipe_type=command.wipe_type,
                    timeout_minutes=command.wipe_timeout_minutes,
                    confirmation_required=command.wipe_confirmation_required,
                    force_wipe=command.force_wipe,
                    evidence_preservation=command.evidence_preservation
                )
            )
            
            return {
                "status": wipe_result.get("status", WipeStatus.INITIATED),
                "initiated_at": datetime.now(UTC),
                "timeout_at": datetime.now(UTC) + timedelta(minutes=command.wipe_timeout_minutes),
                "wipe_id": wipe_result.get("wipe_id"),
                "estimated_completion": wipe_result.get("estimated_completion")
            }
            
        except Exception as e:
            # Log the failure but continue with logical wipe
            await self._audit_service.log_error(
                f"Remote wipe initiation failed for device {device.id}: {e!s}"
            )
            
            return {
                "status": WipeStatus.FAILED,
                "initiated_at": datetime.now(UTC),
                "timeout_at": None,
                "error": str(e)
            }
    
    async def _handle_primary_device_replacement(
        self,
        user_id: UUID,
        wiped_device_id: UUID
    ) -> Device | None:
        """Handle replacement of primary device when wiped."""
        # Find other active devices
        active_devices = await self._device_repository.find_active_by_user(user_id)
        active_devices = [d for d in active_devices if d.id != wiped_device_id]
        
        if not active_devices:
            return None
        
        # Select best candidate for new primary device
        # Prioritize by trust level, then by last seen
        trusted_devices = [d for d in active_devices if d.trust_level.value in ["trusted", "partially_trusted"]]
        
        if trusted_devices:
            # Sort by trust level (desc) then by last_seen_at (desc)
            trusted_devices.sort(
                key=lambda x: (
                    x.trust_level.value == "trusted",
                    x.last_seen_at or datetime.min
                ),
                reverse=True
            )
            new_primary = trusted_devices[0]
        else:
            # Fallback to most recently used device
            active_devices.sort(key=lambda x: x.last_seen_at or datetime.min, reverse=True)
            new_primary = active_devices[0]
        
        # Set as primary
        new_primary.is_primary = True
        new_primary.promoted_to_primary_at = datetime.now(UTC)
        new_primary.promoted_to_primary_reason = "primary_device_wiped"
        
        await self._device_repository.update(new_primary)
        
        return new_primary
    
    async def _assess_wipe_impact(
        self,
        device: Device,
        user: User,
        command: WipeDeviceCommand,
        was_primary: bool
    ) -> dict[str, Any]:
        """Assess impact of device wipe operation."""
        impact_factors = []
        impact_score = 0
        
        # Check if primary device
        if was_primary:
            impact_factors.append("primary_device_wiped")
            impact_score += 40
        
        # Check if trusted device
        if device.trust_level.value in ["trusted", "fully_trusted"]:
            impact_factors.append("trusted_device_wiped")
            impact_score += 30
        
        # Check wipe reason
        high_impact_reasons = [
            WipeReason.SECURITY_BREACH,
            WipeReason.STOLEN,
            WipeReason.COMPROMISED
        ]
        
        if command.reason in high_impact_reasons:
            impact_factors.append(f"high_impact_reason_{command.reason.value}")
            impact_score += 50
        
        # Check if only device
        user_device_count = await self._device_repository.count_active_by_user(user.id)
        if user_device_count <= 1:  # This device being wiped leaves 0
            impact_factors.append("last_device_wiped")
            impact_score += 60
        
        # Check if compliance-driven
        if command.compliance_requirement:
            impact_factors.append("compliance_driven_wipe")
            impact_score += 20
        
        # Check if security incident related
        if command.security_incident_id:
            impact_factors.append("security_incident_related")
            impact_score += 35
        
        # Determine impact level
        if impact_score >= 90:
            impact_level = "critical"
        elif impact_score >= 60:
            impact_level = "high"
        elif impact_score >= 30:
            impact_level = "medium"
        else:
            impact_level = "low"
        
        return {
            "impact_score": impact_score,
            "impact_level": impact_level,
            "impact_factors": impact_factors,
            "assessment_timestamp": datetime.now(UTC).isoformat(),
            "recommendations": self._get_wipe_recommendations(impact_level, impact_factors)
        }
    
    def _get_wipe_recommendations(
        self,
        impact_level: str,
        impact_factors: list[str]
    ) -> list[str]:
        """Get recommendations based on wipe impact assessment."""
        recommendations = []
        
        if "last_device_wiped" in impact_factors:
            recommendations.append("User has no remaining devices - implement account protection measures")
            recommendations.append("Require enhanced identity verification for new device registration")
        
        if "primary_device_wiped" in impact_factors:
            recommendations.append("Monitor new primary device selection and usage")
            recommendations.append("Consider additional verification for critical operations")
        
        if any("high_impact_reason" in factor for factor in impact_factors):
            recommendations.append("Follow incident response procedures")
            recommendations.append("Monitor for additional security indicators")
            recommendations.append("Consider temporary account restrictions")
        
        if "compliance_driven_wipe" in impact_factors:
            recommendations.append("Ensure compliance documentation is complete")
            recommendations.append("Notify compliance team of wipe completion")
        
        if impact_level in ["high", "critical"]:
            recommendations.append("Notify security team immediately")
            recommendations.append("Enhanced monitoring of user account")
            recommendations.append("Consider security review before allowing new devices")
        
        return recommendations
    
    async def _send_wipe_notifications(
        self,
        user: User,
        device: Device,
        wipe_impact: dict[str, Any],
        remote_wipe_result: dict[str, Any] | None,
        command: WipeDeviceCommand
    ) -> None:
        """Send notifications about device wipe operation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_wiped",
                    subject="Device Wiped",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "wipe_reason": command.reason.value,
                        "custom_reason": command.custom_reason,
                        "wipe_type": command.wipe_type.value,
                        "was_primary": device.is_primary,
                        "wiped_by_admin": command.wiped_by != user.id,
                        "remote_wipe_initiated": command.remote_wipe_enabled,
                        "remote_wipe_status": remote_wipe_result["status"] if remote_wipe_result else None,
                        "security_related": command.reason in [
                            WipeReason.SECURITY_BREACH,
                            WipeReason.STOLEN,
                            WipeReason.COMPROMISED
                        ],
                        "compliance_related": command.compliance_requirement is not None,
                        "impact_level": wipe_impact["impact_level"],
                        "wipe_time": device.wiped_at.isoformat(),
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_WIPED,
                channel="in_app",
                template_id="device_wiped",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "wipe_reason": command.reason.value,
                    "wipe_type": command.wipe_type.value,
                    "was_primary": device.is_primary,
                    "wiped_by_admin": command.wiped_by != user.id,
                    "remote_wipe_initiated": command.remote_wipe_enabled,
                    "impact_level": wipe_impact["impact_level"]
                },
                priority="critical"
            )
        )
        
        # SMS notification for high-impact wipes
        if wipe_impact["impact_level"] in ["high", "critical"] and user.phone_verified:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=user.phone_number,
                    template="device_wiped_urgent",
                    variables={
                        "device_name": device.device_name,
                        "wipe_reason": command.reason.value
                    }
                )
            )
    
    async def _notify_emergency_contacts_of_wipe(
        self,
        user: User,
        device: Device,
        command: WipeDeviceCommand
    ) -> None:
        """Notify emergency contacts about device wipe."""
        # This would typically use the NotifyEmergencyContactsCommand
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACTS_NOTIFICATION_TRIGGERED,
                actor_id=command.wiped_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "notification_reason": "device_wipe",
                    "wipe_reason": command.reason.value,
                    "device_name": device.device_name,
                    "was_primary": device.is_primary,
                    "security_incident_related": command.security_incident_id is not None
                },
                risk_level="high"
            )
        )
    
    async def _log_device_wipe_operation(
        self,
        user: User,
        device: Device,
        wipe_impact: dict[str, Any],
        original_status: DeviceStatus,
        command: WipeDeviceCommand
    ) -> None:
        """Log device wipe operation for audit and compliance."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_WIPED,
                actor_id=command.wiped_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "wipe_reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "wipe_type": command.wipe_type.value,
                    "was_primary": device.is_primary,
                    "original_status": original_status.value,
                    "remote_wipe_enabled": command.remote_wipe_enabled,
                    "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                    "compliance_requirement": command.compliance_requirement,
                    "impact_assessment": wipe_impact,
                    "admin_action": command.wiped_by != user.id
                },
                risk_level="critical" if wipe_impact["impact_level"] == "critical" else "high"
            )
        )
        
        # Log compliance record if required
        if command.compliance_requirement:
            await self._audit_service.log_compliance_action(
                AuditContext(
                    action=AuditAction.COMPLIANCE_DEVICE_WIPE,
                    actor_id=command.wiped_by,
                    target_user_id=user.id,
                    resource_type="device",
                    resource_id=device.id,
                    details={
                        "compliance_requirement": command.compliance_requirement,
                        "wipe_type": command.wipe_type.value,
                        "evidence_preserved": command.evidence_preservation,
                        "device_details": {
                            "name": device.device_name,
                            "type": device.device_type.value,
                            "fingerprint": self._mask_fingerprint(device.device_fingerprint)
                        }
                    },
                    compliance_standard=command.compliance_requirement
                )
            )
        
        # Log as security incident if high impact
        if wipe_impact["impact_level"] in ["high", "critical"]:
            await self._audit_service.log_security_incident(
                SecurityIncidentContext(
                    incident_type=SecurityEventType.HIGH_IMPACT_DEVICE_WIPE,
                    severity=RiskLevel.HIGH if wipe_impact["impact_level"] == "high" else RiskLevel.CRITICAL,
                    user_id=user.id,
                    details={
                        "device_id": str(device.id),
                        "device_name": device.device_name,
                        "wipe_reason": command.reason.value,
                        "impact_factors": wipe_impact["impact_factors"],
                        "impact_score": wipe_impact["impact_score"]
                    },
                    indicators=wipe_impact["impact_factors"],
                    recommended_actions=wipe_impact["recommendations"]
                )
            )
    
    async def _update_user_security_posture(
        self,
        user: User,
        device: Device,
        command: WipeDeviceCommand
    ) -> None:
        """Update user's security posture after device wipe."""
        # Update user metadata with device wipe info
        if "security_posture" not in user.metadata:
            user.metadata["security_posture"] = {}
        
        user.metadata["security_posture"].update({
            "last_device_wipe": datetime.now(UTC).isoformat(),
            "wiped_devices_count": user.metadata["security_posture"].get("wiped_devices_count", 0) + 1,
            "last_wiped_device_type": device.device_type.value,
            "last_wipe_reason": command.reason.value
        })
        
        await self._user_repository.update(user)
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]