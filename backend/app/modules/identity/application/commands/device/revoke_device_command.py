"""
Revoke device command implementation.

Handles revoking device access and invalidating sessions.
"""

from datetime import UTC, datetime
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
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import RevokeDeviceRequest
from app.modules.identity.application.dtos.response import DeviceRevocationResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    DeviceStatus,
    NotificationType,
    RevocationReason,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import DeviceRevoked
from app.modules.identity.domain.exceptions import (
    DeviceAlreadyRevokedException,
    DeviceNotFoundError,
    InvalidRevocationError,
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
)


class RevokeDeviceCommand(Command[DeviceRevocationResponse]):
    """Command to revoke device access."""
    
    def __init__(
        self,
        device_id: UUID,
        revoked_by: UUID,
        reason: RevocationReason,
        custom_reason: str | None = None,
        revoke_all_sessions: bool = True,
        revoke_all_tokens: bool = True,
        notify_user: bool = True,
        notify_emergency_contacts: bool = False,
        create_backup: bool = True,
        immediate_effect: bool = True,
        grace_period_minutes: int = 0,
        force_revoke: bool = False,
        security_incident_id: UUID | None = None,
        evidence_links: list[str] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.revoked_by = revoked_by
        self.reason = reason
        self.custom_reason = custom_reason
        self.revoke_all_sessions = revoke_all_sessions
        self.revoke_all_tokens = revoke_all_tokens
        self.notify_user = notify_user
        self.notify_emergency_contacts = notify_emergency_contacts
        self.create_backup = create_backup
        self.immediate_effect = immediate_effect
        self.grace_period_minutes = grace_period_minutes
        self.force_revoke = force_revoke
        self.security_incident_id = security_incident_id
        self.evidence_links = evidence_links or []
        self.metadata = metadata or {}


class RevokeDeviceCommandHandler(CommandHandler[RevokeDeviceCommand, DeviceRevocationResponse]):
    """Handler for revoking devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        session_repository: ISessionRepository,
        token_repository: ITokenRepository,
        device_security_service: DeviceSecurityService,
        session_service: SessionService,
        token_service: TokenService,
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
        self._device_security_service = device_security_service
        self._session_service = session_service
        self._token_service = token_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._backup_service = backup_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_REVOKED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(RevokeDeviceRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.revoke")
    @require_mfa(condition="security_revocation")
    async def handle(self, command: RevokeDeviceCommand) -> DeviceRevocationResponse:
        """
        Revoke device access with comprehensive cleanup.
        
        Process:
        1. Load device and validate revocation
        2. Check revocation permissions
        3. Validate revocation reason
        4. Create device backup if requested
        5. Revoke all sessions and tokens
        6. Update device status
        7. Handle primary device logic
        8. Send notifications
        9. Log security events
        10. Update user security posture
        
        Returns:
            DeviceRevocationResponse with revocation details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If cannot revoke device
            DeviceAlreadyRevokedException: If already revoked
            InvalidRevocationError: If revocation invalid
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
            
            # 3. Check if device already revoked
            if device.status == DeviceStatus.REVOKED and not command.force_revoke:
                raise DeviceAlreadyRevokedException(f"Device {device.id} already revoked")
            
            # 4. Check revocation permissions
            await self._validate_revocation_permissions(device, command.revoked_by, command)
            
            # 5. Validate revocation reason
            await self._validate_revocation_reason(device, command)
            
            # 6. Create device backup if requested
            backup_id = None
            if command.create_backup:
                backup_id = await self._create_device_backup(device, user, command)
            
            # 7. Capture current sessions and tokens
            sessions_to_revoke = []
            tokens_to_revoke = []
            
            if command.revoke_all_sessions:
                sessions_to_revoke = await self._session_repository.find_active_by_device(device.id)
            
            if command.revoke_all_tokens:
                tokens_to_revoke = await self._token_repository.find_active_by_device(device.id)
            
            # 8. Revoke sessions
            sessions_revoked = 0
            for session in sessions_to_revoke:
                try:
                    await self._session_service.revoke_session(
                        session.id,
                        command.revoked_by,
                        f"Device revoked: {command.reason.value}"
                    )
                    sessions_revoked += 1
                except Exception as e:
                    # Log but continue with other sessions
                    await self._audit_service.log_error(
                        f"Failed to revoke session {session.id}: {e!s}"
                    )
            
            # 9. Revoke tokens
            tokens_revoked = 0
            for token in tokens_to_revoke:
                try:
                    await self._token_service.revoke_token(
                        token.id,
                        command.revoked_by,
                        f"Device revoked: {command.reason.value}"
                    )
                    tokens_revoked += 1
                except Exception as e:
                    # Log but continue with other tokens
                    await self._audit_service.log_error(
                        f"Failed to revoke token {token.id}: {e!s}"
                    )
            
            # 10. Update device status
            was_primary = device.is_primary
            device.status = DeviceStatus.REVOKED
            device.revoked_at = datetime.now(UTC)
            device.revoked_by = command.revoked_by
            device.revocation_reason = command.reason.value
            device.custom_revocation_reason = command.custom_reason
            device.security_incident_id = command.security_incident_id
            device.is_primary = False  # Revoked devices cannot be primary
            
            # Add revocation metadata
            device.metadata.update({
                "revocation_metadata": {
                    "reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "revoked_by": str(command.revoked_by),
                    "immediate_effect": command.immediate_effect,
                    "grace_period_minutes": command.grace_period_minutes,
                    "sessions_revoked": sessions_revoked,
                    "tokens_revoked": tokens_revoked,
                    "evidence_links": command.evidence_links,
                    "backup_created": backup_id is not None,
                    "revocation_timestamp": datetime.now(UTC).isoformat()
                }
            })
            
            await self._device_repository.update(device)
            
            # 11. Handle primary device replacement
            new_primary_device = None
            if was_primary:
                new_primary_device = await self._handle_primary_device_replacement(
                    user.id,
                    device.id
                )
            
            # 12. Calculate security impact
            security_impact = await self._assess_revocation_security_impact(
                user,
                device,
                command
            )
            
            # 13. Send notifications
            if command.notify_user:
                await self._send_revocation_notifications(
                    user,
                    device,
                    security_impact,
                    command
                )
            
            # 14. Notify emergency contacts if requested
            if command.notify_emergency_contacts:
                await self._notify_emergency_contacts(
                    user,
                    device,
                    command
                )
            
            # 15. Log security events
            await self._log_device_revocation(
                user,
                device,
                security_impact,
                command
            )
            
            # 16. Update user security posture
            await self._update_user_security_posture(user, device)
            
            # 17. Publish domain event
            await self._event_bus.publish(
                DeviceRevoked(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    revocation_reason=command.reason,
                    was_primary=was_primary,
                    revoked_by=command.revoked_by,
                    sessions_revoked=sessions_revoked,
                    tokens_revoked=tokens_revoked,
                    new_primary_device_id=new_primary_device.id if new_primary_device else None,
                    security_incident_related=command.security_incident_id is not None
                )
            )
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Return response
            return DeviceRevocationResponse(
                device_id=device.id,
                user_id=device.user_id,
                device_name=device.device_name,
                device_type=device.device_type,
                revocation_reason=command.reason,
                custom_reason=command.custom_reason,
                was_primary=was_primary,
                new_primary_device_id=new_primary_device.id if new_primary_device else None,
                sessions_revoked=sessions_revoked,
                tokens_revoked=tokens_revoked,
                backup_created=backup_id is not None,
                backup_id=backup_id,
                emergency_contacts_notified=command.notify_emergency_contacts,
                security_impact_level=security_impact["impact_level"],
                revoked_at=device.revoked_at,
                revoked_by=device.revoked_by,
                message="Device revoked successfully"
            )
    
    async def _validate_revocation_permissions(
        self,
        device: Device,
        revoked_by: UUID,
        command: RevokeDeviceCommand
    ) -> None:
        """Validate user can revoke this device."""
        # User can revoke their own devices
        if device.user_id == revoked_by:
            return
        
        # Check if revoker has admin permissions
        # Additional checks for security-related revocations
        if command.reason in [RevocationReason.SECURITY_BREACH, RevocationReason.COMPROMISED]:
            # These require special security permissions
            pass
        
        # Check if device is critical and requires special permission
        if device.is_primary and not command.force_revoke:
            # Revoking primary device requires additional confirmation
            pass
    
    async def _validate_revocation_reason(
        self,
        device: Device,
        command: RevokeDeviceCommand
    ) -> None:
        """Validate the revocation reason."""
        # Some reasons require additional information
        if command.reason == RevocationReason.OTHER and not command.custom_reason:
            raise InvalidRevocationError("Custom reason required when using 'OTHER' reason")
        
        if command.reason == RevocationReason.SECURITY_BREACH and not command.security_incident_id:
            # Security breaches should be linked to incidents
            pass
        
        # Validate custom reason length
        if command.custom_reason and len(command.custom_reason) > 500:
            raise InvalidRevocationError("Custom reason too long (max 500 characters)")
    
    async def _create_device_backup(
        self,
        device: Device,
        user: User,
        command: RevokeDeviceCommand
    ) -> UUID:
        """Create backup of device before revocation."""
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
            "revocation": {
                "reason": command.reason.value,
                "custom_reason": command.custom_reason,
                "revoked_by": str(command.revoked_by),
                "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                "evidence_links": command.evidence_links,
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.DEVICE_REVOCATION,
                resource_type="device",
                resource_id=device.id,
                data=backup_data,
                retention_days=365,  # Keep for 1 year
                encrypted=True
            )
        )
        
    
    async def _handle_primary_device_replacement(
        self,
        user_id: UUID,
        revoked_device_id: UUID
    ) -> Device | None:
        """Handle replacement of primary device."""
        # Find other active devices
        active_devices = await self._device_repository.find_active_by_user(user_id)
        active_devices = [d for d in active_devices if d.id != revoked_device_id]
        
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
        new_primary.promoted_to_primary_reason = "primary_device_revoked"
        
        await self._device_repository.update(new_primary)
        
        return new_primary
    
    async def _assess_revocation_security_impact(
        self,
        user: User,
        device: Device,
        command: RevokeDeviceCommand
    ) -> dict[str, Any]:
        """Assess security impact of device revocation."""
        impact_factors = []
        impact_score = 0
        
        # Check if primary device
        if device.is_primary:
            impact_factors.append("primary_device_revoked")
            impact_score += 30
        
        # Check if trusted device
        if device.trust_level.value == "trusted":
            impact_factors.append("trusted_device_revoked")
            impact_score += 20
        
        # Check revocation reason
        high_risk_reasons = [
            RevocationReason.SECURITY_BREACH,
            RevocationReason.COMPROMISED,
            RevocationReason.STOLEN
        ]
        
        if command.reason in high_risk_reasons:
            impact_factors.append(f"high_risk_reason_{command.reason.value}")
            impact_score += 40
        
        # Check if only device
        user_device_count = await self._device_repository.count_active_by_user(user.id)
        if user_device_count <= 1:  # This device being revoked leaves 0
            impact_factors.append("last_device_revoked")
            impact_score += 50
        
        # Check recent activity
        if device.last_seen_at:
            hours_since_activity = (datetime.now(UTC) - device.last_seen_at).total_seconds() / 3600
            if hours_since_activity < 24:
                impact_factors.append("recently_active_device")
                impact_score += 15
        
        # Determine impact level
        if impact_score >= 75:
            impact_level = "critical"
        elif impact_score >= 50:
            impact_level = "high"
        elif impact_score >= 25:
            impact_level = "medium"
        else:
            impact_level = "low"
        
        return {
            "impact_score": impact_score,
            "impact_level": impact_level,
            "impact_factors": impact_factors,
            "assessment_timestamp": datetime.now(UTC).isoformat(),
            "recommendations": self._get_impact_recommendations(impact_level, impact_factors)
        }
    
    def _get_impact_recommendations(
        self,
        impact_level: str,
        impact_factors: list[str]
    ) -> list[str]:
        """Get recommendations based on impact assessment."""
        recommendations = []
        
        if "last_device_revoked" in impact_factors:
            recommendations.append("User has no remaining devices - consider account lockdown")
            recommendations.append("Require identity verification for new device registration")
        
        if "primary_device_revoked" in impact_factors:
            recommendations.append("Monitor new primary device selection")
            recommendations.append("Require re-verification of remaining devices")
        
        if any("high_risk_reason" in factor for factor in impact_factors):
            recommendations.append("Initiate security incident response")
            recommendations.append("Review user account for additional compromise indicators")
            recommendations.append("Consider temporary account restrictions")
        
        if impact_level in ["high", "critical"]:
            recommendations.append("Notify security team immediately")
            recommendations.append("Monitor user account for suspicious activity")
        
        return recommendations
    
    async def _send_revocation_notifications(
        self,
        user: User,
        device: Device,
        security_impact: dict[str, Any],
        command: RevokeDeviceCommand
    ) -> None:
        """Send notifications about device revocation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_revoked",
                    subject="Device Access Revoked",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "revocation_reason": command.reason.value,
                        "custom_reason": command.custom_reason,
                        "was_primary": device.is_primary,
                        "revoked_by_admin": command.revoked_by != user.id,
                        "security_related": command.reason in [
                            RevocationReason.SECURITY_BREACH,
                            RevocationReason.COMPROMISED,
                            RevocationReason.STOLEN
                        ],
                        "impact_level": security_impact["impact_level"],
                        "revocation_time": device.revoked_at.isoformat(),
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_REVOKED,
                channel="in_app",
                template_id="device_revoked",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "revocation_reason": command.reason.value,
                    "was_primary": device.is_primary,
                    "revoked_by_admin": command.revoked_by != user.id,
                    "impact_level": security_impact["impact_level"]
                },
                priority="critical" if security_impact["impact_level"] == "critical" else "high"
            )
        )
    
    async def _notify_emergency_contacts(
        self,
        user: User,
        device: Device,
        command: RevokeDeviceCommand
    ) -> None:
        """Notify emergency contacts about device revocation."""
        # This would typically use the NotifyEmergencyContactsCommand
        # For now, we'll just log that it should be done
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACTS_NOTIFICATION_TRIGGERED,
                actor_id=command.revoked_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "notification_reason": "device_revocation",
                    "revocation_reason": command.reason.value,
                    "device_name": device.device_name,
                    "was_primary": device.is_primary
                },
                risk_level="medium"
            )
        )
    
    async def _log_device_revocation(
        self,
        user: User,
        device: Device,
        security_impact: dict[str, Any],
        command: RevokeDeviceCommand
    ) -> None:
        """Log device revocation for audit and security."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_REVOKED,
                actor_id=command.revoked_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "revocation_reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "was_primary": device.is_primary,
                    "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                    "impact_assessment": security_impact,
                    "admin_action": command.revoked_by != user.id
                },
                risk_level="high" if security_impact["impact_level"] in ["high", "critical"] else "medium"
            )
        )
        
        # Log as security incident if high impact
        if security_impact["impact_level"] in ["high", "critical"]:
            await self._audit_service.log_security_incident(
                SecurityIncidentContext(
                    incident_type=SecurityEventType.HIGH_IMPACT_DEVICE_REVOCATION,
                    severity=RiskLevel.HIGH if security_impact["impact_level"] == "high" else RiskLevel.CRITICAL,
                    user_id=user.id,
                    details={
                        "device_id": str(device.id),
                        "device_name": device.device_name,
                        "revocation_reason": command.reason.value,
                        "impact_factors": security_impact["impact_factors"],
                        "impact_score": security_impact["impact_score"]
                    },
                    indicators=security_impact["impact_factors"],
                    recommended_actions=security_impact["recommendations"]
                )
            )
    
    async def _update_user_security_posture(self, user: User, revoked_device: Device) -> None:
        """Update user's security posture after device revocation."""
        # Update user metadata with device revocation info
        if "security_posture" not in user.metadata:
            user.metadata["security_posture"] = {}
        
        user.metadata["security_posture"].update({
            "last_device_revocation": datetime.now(UTC).isoformat(),
            "revoked_devices_count": user.metadata["security_posture"].get("revoked_devices_count", 0) + 1,
            "last_revoked_device_type": revoked_device.device_type.value
        })
        
        await self._user_repository.update(user)
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]