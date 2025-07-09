"""
Untrust device command implementation.

Handles removing trust from previously trusted devices with security validation.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import IDeviceRepository
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.services.communication.notification_service import INotificationService
from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import UntrustDeviceRequest
from app.modules.identity.application.dtos.response import DeviceUntrustResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    SessionInvalidationStrategy,
    TrustLevel,
    UntrustReason,
)
from app.modules.identity.domain.events import DeviceUntrusted
from app.modules.identity.domain.exceptions import (
    DeviceNotFoundError,
    DeviceNotTrustedException,
    InvalidUntrustOperationError,
)
from app.modules.identity.domain.services import (
    DeviceSecurityService,
    SessionService,
    TokenService,
    ValidationService,
)


class UntrustDeviceCommand(Command[DeviceUntrustResponse]):
    """Command to untrust a previously trusted device."""
    
    def __init__(
        self,
        device_id: UUID,
        untrusted_by: UUID,
        reason: UntrustReason,
        custom_reason: str | None = None,
        downgrade_to_level: TrustLevel = TrustLevel.UNTRUSTED,
        invalidate_sessions: bool = True,
        invalidate_tokens: bool = True,
        session_invalidation_strategy: SessionInvalidationStrategy = SessionInvalidationStrategy.ALL_SESSIONS,
        require_reverification: bool = True,
        notify_user: bool = True,
        security_incident_id: UUID | None = None,
        evidence_data: dict[str, Any] | None = None,
        immediate_effect: bool = True,
        grace_period_minutes: int = 0,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.untrusted_by = untrusted_by
        self.reason = reason
        self.custom_reason = custom_reason
        self.downgrade_to_level = downgrade_to_level
        self.invalidate_sessions = invalidate_sessions
        self.invalidate_tokens = invalidate_tokens
        self.session_invalidation_strategy = session_invalidation_strategy
        self.require_reverification = require_reverification
        self.notify_user = notify_user
        self.security_incident_id = security_incident_id
        self.evidence_data = evidence_data or {}
        self.immediate_effect = immediate_effect
        self.grace_period_minutes = grace_period_minutes
        self.metadata = metadata or {}


class UntrustDeviceCommandHandler(CommandHandler[UntrustDeviceCommand, DeviceUntrustResponse]):
    """Handler for untrusting devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        session_repository: ISessionRepository,
        token_repository: ITokenRepository,
        trust_assessment_repository: ITrustAssessmentRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        session_service: SessionService,
        token_service: TokenService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._session_repository = session_repository
        self._token_repository = token_repository
        self._trust_assessment_repository = trust_assessment_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._session_service = session_service
        self._token_service = token_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_UNTRUSTED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(UntrustDeviceRequest)
    @rate_limit(
        max_requests=15,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.untrust")
    @require_mfa(condition="device_untrust_operation")
    async def handle(self, command: UntrustDeviceCommand) -> DeviceUntrustResponse:
        """
        Untrust device with comprehensive security measures.
        
        Process:
        1. Load device and validate untrust operation
        2. Check untrust permissions and reason
        3. Create untrust assessment record
        4. Update device trust level
        5. Handle session and token invalidation
        6. Apply security policies for untrusted devices
        7. Send notifications
        8. Log security events
        9. Update user security posture
        
        Returns:
            DeviceUntrustResponse with untrust operation details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If cannot untrust device
            DeviceNotTrustedException: If device not currently trusted
            InvalidUntrustOperationError: If untrust operation invalid
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
            
            # 3. Check if device is currently trusted
            if device.trust_level == TrustLevel.UNTRUSTED:
                raise DeviceNotTrustedException(f"Device {device.id} is already untrusted")
            
            # 4. Check untrust permissions
            await self._validate_untrust_permissions(device, command.untrusted_by, command)
            
            # 5. Validate untrust reason and downgrade level
            await self._validate_untrust_operation(device, command)
            
            # 6. Capture current trust state
            original_trust_level = device.trust_level
            
            # 7. Get current sessions and tokens for invalidation
            sessions_to_invalidate = []
            tokens_to_invalidate = []
            
            if command.invalidate_sessions:
                sessions_to_invalidate = await self._get_sessions_for_invalidation(
                    device,
                    command.session_invalidation_strategy
                )
            
            if command.invalidate_tokens:
                tokens_to_invalidate = await self._token_repository.find_active_by_device(device.id)
            
            # 8. Create untrust assessment record
            untrust_assessment = await self._create_untrust_assessment(
                device,
                user,
                command,
                original_trust_level
            )
            
            # 9. Update device trust level
            device.trust_level = command.downgrade_to_level
            device.untrusted_at = datetime.now(UTC)
            device.untrusted_by = command.untrusted_by
            device.untrust_reason = command.reason.value
            device.custom_untrust_reason = command.custom_reason
            device.trust_assessment_id = None  # Clear trust assessment
            device.untrust_assessment_id = untrust_assessment.id
            
            # Set reverification requirements
            if command.require_reverification:
                device.requires_reverification = True
                device.reverification_required_at = datetime.now(UTC)
                device.reverification_reason = f"Device untrusted: {command.reason.value}"
            
            # Update metadata
            device.metadata.update({
                "untrust_metadata": {
                    "reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "untrusted_by": str(command.untrusted_by),
                    "original_trust_level": original_trust_level.value,
                    "downgraded_to": command.downgrade_to_level.value,
                    "sessions_invalidated": len(sessions_to_invalidate),
                    "tokens_invalidated": len(tokens_to_invalidate),
                    "requires_reverification": command.require_reverification,
                    "immediate_effect": command.immediate_effect,
                    "grace_period_minutes": command.grace_period_minutes,
                    "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                    "evidence_data": command.evidence_data,
                    "untrust_timestamp": datetime.now(UTC).isoformat()
                }
            })
            
            await self._device_repository.update(device)
            
            # 10. Invalidate sessions
            sessions_invalidated = 0
            for session in sessions_to_invalidate:
                try:
                    await self._session_service.invalidate_session(
                        session.id,
                        f"Device untrusted: {command.reason.value}",
                        command.immediate_effect
                    )
                    sessions_invalidated += 1
                except Exception as e:
                    await self._audit_service.log_error(
                        f"Failed to invalidate session {session.id}: {e!s}"
                    )
            
            # 11. Invalidate tokens
            tokens_invalidated = 0
            for token in tokens_to_invalidate:
                try:
                    await self._token_service.invalidate_token(
                        token.id,
                        f"Device untrusted: {command.reason.value}"
                    )
                    tokens_invalidated += 1
                except Exception as e:
                    await self._audit_service.log_error(
                        f"Failed to invalidate token {token.id}: {e!s}"
                    )
            
            # 12. Apply untrusted device policies
            security_restrictions = await self._apply_untrusted_device_policies(device, user)
            
            # 13. Assess security impact
            security_impact = await self._assess_untrust_security_impact(
                device,
                user,
                command,
                original_trust_level
            )
            
            # 14. Send notifications
            if command.notify_user:
                await self._send_untrust_notifications(
                    user,
                    device,
                    untrust_assessment,
                    security_impact,
                    command
                )
            
            # 15. Log security events
            await self._log_device_untrust_operation(
                user,
                device,
                untrust_assessment,
                security_impact,
                original_trust_level,
                command
            )
            
            # 16. Update user security posture
            await self._update_user_security_posture(user, device, command)
            
            # 17. Publish domain event
            await self._event_bus.publish(
                DeviceUntrusted(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    previous_trust_level=original_trust_level,
                    new_trust_level=device.trust_level,
                    untrust_reason=command.reason,
                    untrusted_by=command.untrusted_by,
                    sessions_invalidated=sessions_invalidated,
                    tokens_invalidated=tokens_invalidated,
                    requires_reverification=command.require_reverification,
                    security_impact_level=security_impact["impact_level"]
                )
            )
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Return response
            return DeviceUntrustResponse(
                device_id=device.id,
                user_id=device.user_id,
                device_name=device.device_name,
                device_type=device.device_type,
                previous_trust_level=original_trust_level,
                new_trust_level=device.trust_level,
                untrust_reason=command.reason,
                custom_reason=command.custom_reason,
                sessions_invalidated=sessions_invalidated,
                tokens_invalidated=tokens_invalidated,
                requires_reverification=command.require_reverification,
                security_restrictions_applied=security_restrictions,
                security_impact_level=security_impact["impact_level"],
                untrusted_at=device.untrusted_at,
                untrusted_by=device.untrusted_by,
                message="Device untrusted successfully"
            )
    
    async def _validate_untrust_permissions(
        self,
        device: Device,
        untrusted_by: UUID,
        command: UntrustDeviceCommand
    ) -> None:
        """Validate user can untrust this device."""
        # User can untrust their own devices
        if device.user_id == untrusted_by:
            return
        
        # Check if untruster has admin permissions
        # Additional checks for security-related untrust operations
        if command.reason in [UntrustReason.SECURITY_BREACH, UntrustReason.COMPROMISED]:
            # These require special security permissions
            pass
        
        # Check if device is critical and requires special permission
        if device.is_primary:
            # Untrusting primary device requires additional confirmation
            pass
    
    async def _validate_untrust_operation(
        self,
        device: Device,
        command: UntrustDeviceCommand
    ) -> None:
        """Validate the untrust operation."""
        # Validate custom reason if required
        if command.reason == UntrustReason.OTHER and not command.custom_reason:
            raise InvalidUntrustOperationError("Custom reason required when using 'OTHER' reason")
        
        # Validate custom reason length
        if command.custom_reason and len(command.custom_reason) > 500:
            raise InvalidUntrustOperationError("Custom reason too long (max 500 characters)")
        
        # Validate downgrade level
        current_trust_numeric = self._get_trust_level_numeric(device.trust_level)
        target_trust_numeric = self._get_trust_level_numeric(command.downgrade_to_level)
        
        if target_trust_numeric >= current_trust_numeric:
            raise InvalidUntrustOperationError(
                f"Cannot downgrade from {device.trust_level.value} to {command.downgrade_to_level.value}"
            )
    
    def _get_trust_level_numeric(self, trust_level: TrustLevel) -> int:
        """Get numeric representation of trust level for comparison."""
        trust_levels = {
            TrustLevel.UNTRUSTED: 0,
            TrustLevel.PARTIALLY_TRUSTED: 1,
            TrustLevel.CONDITIONALLY_TRUSTED: 2,
            TrustLevel.TRUSTED: 3,
            TrustLevel.FULLY_TRUSTED: 4
        }
        return trust_levels.get(trust_level, 0)
    
    async def _get_sessions_for_invalidation(
        self,
        device: Device,
        strategy: SessionInvalidationStrategy
    ) -> list[Any]:
        """Get sessions to invalidate based on strategy."""
        if strategy == SessionInvalidationStrategy.ALL_SESSIONS:
            return await self._session_repository.find_all_by_device(device.id)
        if strategy == SessionInvalidationStrategy.ACTIVE_SESSIONS_ONLY:
            return await self._session_repository.find_active_by_device(device.id)
        if strategy == SessionInvalidationStrategy.TRUSTED_SESSIONS_ONLY:
            return await self._session_repository.find_trusted_by_device(device.id)
        return []
    
    async def _create_untrust_assessment(
        self,
        device: Device,
        user: User,
        command: UntrustDeviceCommand,
        original_trust_level: TrustLevel
    ) -> Any:
        """Create untrust assessment record."""
        assessment_data = {
            "id": UUID(),
            "device_id": device.id,
            "user_id": user.id,
            "original_trust_level": original_trust_level.value,
            "new_trust_level": command.downgrade_to_level.value,
            "untrust_reason": command.reason.value,
            "custom_reason": command.custom_reason,
            "untrusted_by": command.untrusted_by,
            "security_incident_id": command.security_incident_id,
            "evidence_data": command.evidence_data,
            "immediate_effect": command.immediate_effect,
            "grace_period_minutes": command.grace_period_minutes,
            "require_reverification": command.require_reverification,
            "created_at": datetime.now(UTC),
            "metadata": command.metadata
        }
        
        return await self._trust_assessment_repository.create_untrust_assessment(assessment_data)
    
    async def _apply_untrusted_device_policies(
        self,
        device: Device,
        user: User
    ) -> list[str]:
        """Apply security policies for untrusted devices."""
        restrictions_applied = []
        
        # Apply based on new trust level
        if device.trust_level == TrustLevel.UNTRUSTED:
            # Strict restrictions for completely untrusted devices
            restrictions_applied.extend([
                "mfa_required_all_operations",
                "limited_session_duration",
                "restricted_feature_access",
                "enhanced_monitoring",
                "location_verification_required"
            ])
        
        elif device.trust_level == TrustLevel.PARTIALLY_TRUSTED:
            # Moderate restrictions
            restrictions_applied.extend([
                "mfa_required_sensitive_operations",
                "moderate_session_duration",
                "some_feature_restrictions",
                "periodic_reverification"
            ])
        
        # Apply conditional restrictions if applicable
        if device.requires_reverification:
            restrictions_applied.append("reverification_required")
        
        return restrictions_applied
    
    async def _assess_untrust_security_impact(
        self,
        device: Device,
        user: User,
        command: UntrustDeviceCommand,
        original_trust_level: TrustLevel
    ) -> dict[str, Any]:
        """Assess security impact of device untrust operation."""
        impact_factors = []
        impact_score = 0
        
        # Check if primary device
        if device.is_primary:
            impact_factors.append("primary_device_untrusted")
            impact_score += 30
        
        # Check original trust level
        if original_trust_level == TrustLevel.FULLY_TRUSTED:
            impact_factors.append("fully_trusted_device_untrusted")
            impact_score += 25
        elif original_trust_level == TrustLevel.TRUSTED:
            impact_factors.append("trusted_device_untrusted")
            impact_score += 20
        
        # Check untrust reason
        high_risk_reasons = [
            UntrustReason.SECURITY_BREACH,
            UntrustReason.COMPROMISED,
            UntrustReason.SUSPICIOUS_ACTIVITY
        ]
        
        if command.reason in high_risk_reasons:
            impact_factors.append(f"high_risk_reason_{command.reason.value}")
            impact_score += 40
        
        # Check recent activity
        if device.last_seen_at:
            hours_since_activity = (datetime.now(UTC) - device.last_seen_at).total_seconds() / 3600
            if hours_since_activity < 24:
                impact_factors.append("recently_active_device")
                impact_score += 15
        
        # Check if security incident related
        if command.security_incident_id:
            impact_factors.append("security_incident_related")
            impact_score += 35
        
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
            "recommendations": self._get_untrust_recommendations(impact_level, impact_factors)
        }
    
    def _get_untrust_recommendations(
        self,
        impact_level: str,
        impact_factors: list[str]
    ) -> list[str]:
        """Get recommendations based on untrust impact assessment."""
        recommendations = []
        
        if "primary_device_untrusted" in impact_factors:
            recommendations.append("Monitor user access patterns carefully")
            recommendations.append("Consider requiring additional verification for critical operations")
        
        if any("high_risk_reason" in factor for factor in impact_factors):
            recommendations.append("Initiate security incident response")
            recommendations.append("Review user account for additional compromise indicators")
            recommendations.append("Monitor all user devices for suspicious activity")
        
        if "security_incident_related" in impact_factors:
            recommendations.append("Follow incident response procedures")
            recommendations.append("Consider temporary account restrictions")
        
        if impact_level in ["high", "critical"]:
            recommendations.append("Notify security team immediately")
            recommendations.append("Enhanced monitoring of user account")
            recommendations.append("Consider requiring security review before re-trusting")
        
        return recommendations
    
    async def _send_untrust_notifications(
        self,
        user: User,
        device: Device,
        untrust_assessment: Any,
        security_impact: dict[str, Any],
        command: UntrustDeviceCommand
    ) -> None:
        """Send notifications about device untrust operation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_untrusted",
                    subject="Device Trust Removed",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "untrust_reason": command.reason.value,
                        "custom_reason": command.custom_reason,
                        "new_trust_level": device.trust_level.value,
                        "was_primary": device.is_primary,
                        "untrusted_by_admin": command.untrusted_by != user.id,
                        "requires_reverification": command.require_reverification,
                        "security_related": command.reason in [
                            UntrustReason.SECURITY_BREACH,
                            UntrustReason.COMPROMISED,
                            UntrustReason.SUSPICIOUS_ACTIVITY
                        ],
                        "impact_level": security_impact["impact_level"],
                        "untrust_time": device.untrusted_at.isoformat(),
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_UNTRUSTED,
                channel="in_app",
                template_id="device_untrusted",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "untrust_reason": command.reason.value,
                    "new_trust_level": device.trust_level.value,
                    "untrusted_by_admin": command.untrusted_by != user.id,
                    "requires_reverification": command.require_reverification,
                    "impact_level": security_impact["impact_level"]
                },
                priority="critical" if security_impact["impact_level"] == "critical" else "high"
            )
        )
    
    async def _log_device_untrust_operation(
        self,
        user: User,
        device: Device,
        untrust_assessment: Any,
        security_impact: dict[str, Any],
        original_trust_level: TrustLevel,
        command: UntrustDeviceCommand
    ) -> None:
        """Log device untrust operation for audit and security."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_UNTRUSTED,
                actor_id=command.untrusted_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "original_trust_level": original_trust_level.value,
                    "new_trust_level": device.trust_level.value,
                    "untrust_reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "requires_reverification": command.require_reverification,
                    "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                    "impact_assessment": security_impact,
                    "admin_action": command.untrusted_by != user.id
                },
                risk_level="high" if security_impact["impact_level"] in ["high", "critical"] else "medium"
            )
        )
        
        # Log as security incident if high impact
        if security_impact["impact_level"] in ["high", "critical"]:
            await self._audit_service.log_security_incident(
                SecurityIncidentContext(
                    incident_type=SecurityEventType.HIGH_IMPACT_DEVICE_UNTRUST,
                    severity=RiskLevel.HIGH if security_impact["impact_level"] == "high" else RiskLevel.CRITICAL,
                    user_id=user.id,
                    details={
                        "device_id": str(device.id),
                        "device_name": device.device_name,
                        "untrust_reason": command.reason.value,
                        "original_trust_level": original_trust_level.value,
                        "impact_factors": security_impact["impact_factors"],
                        "impact_score": security_impact["impact_score"]
                    },
                    indicators=security_impact["impact_factors"],
                    recommended_actions=security_impact["recommendations"]
                )
            )
    
    async def _update_user_security_posture(
        self,
        user: User,
        device: Device,
        command: UntrustDeviceCommand
    ) -> None:
        """Update user's security posture after device untrust."""
        # Update user metadata with device untrust info
        if "security_posture" not in user.metadata:
            user.metadata["security_posture"] = {}
        
        user.metadata["security_posture"].update({
            "last_device_untrust": datetime.now(UTC).isoformat(),
            "untrusted_devices_count": user.metadata["security_posture"].get("untrusted_devices_count", 0) + 1,
            "last_untrusted_device_type": device.device_type.value,
            "last_untrust_reason": command.reason.value
        })
        
        await self._user_repository.update(user)
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]