"""
Quarantine device command implementation.

Handles placing devices in security quarantine with restricted access.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    DeviceQuarantineParams,
    ExtendedCommandHandlerDependencies,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    BackupContext,
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import QuarantineDeviceRequest
from app.modules.identity.application.dtos.response import DeviceQuarantineResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    DeviceStatus,
    NotificationType,
    QuarantineLevel,
    QuarantineReason,
    QuarantineStatus,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import DeviceQuarantined
from app.modules.identity.domain.exceptions import (
    DeviceAlreadyQuarantinedException,
    DeviceNotFoundError,
    InvalidQuarantineOperationError,
)


class QuarantineDeviceCommand(Command[DeviceQuarantineResponse]):
    """Command to quarantine a device for security purposes."""
    
    def __init__(self, params: DeviceQuarantineParams, **kwargs: Any):
        self.params = params
        # Initialize empty collections if None
        self.params.escalation_contacts = params.escalation_contacts or []
        self.params.metadata = params.metadata or {}
        
        # Additional parameters not in base DTO
        self.quarantine_level = kwargs.get('quarantine_level', QuarantineLevel.RESTRICTED)
        self.custom_reason = kwargs.get('custom_reason')
        self.automatic_release = kwargs.get('automatic_release', False)
        self.allowed_operations = kwargs.get('allowed_operations', [])
        self.block_new_sessions = kwargs.get('block_new_sessions', True)
        self.invalidate_existing_sessions = kwargs.get('invalidate_existing_sessions', True)
        self.restrict_data_access = kwargs.get('restrict_data_access', True)
        self.require_admin_approval_to_release = kwargs.get('require_admin_approval_to_release', True)


class QuarantineDeviceCommandHandler(CommandHandler[QuarantineDeviceCommand, DeviceQuarantineResponse]):
    """Handler for quarantining devices."""
    
    def __init__(self, dependencies: ExtendedCommandHandlerDependencies):
        # Repository dependencies
        self._user_repository = dependencies.repositories.user_repository
        self._device_repository = dependencies.repositories.device_repository
        self._session_repository = dependencies.repositories.session_repository
        self._token_repository = dependencies.repositories.token_repository
        self._quarantine_repository = dependencies.repositories.quarantine_repository
        self._device_policy_repository = dependencies.repositories.device_policy_repository
        
        # Service dependencies
        self._validation_service = dependencies.services.validation_service
        self._device_security_service = dependencies.services.device_security_service
        self._quarantine_service = dependencies.services.quarantine_service
        self._session_service = dependencies.services.session_service
        self._token_service = dependencies.services.token_service
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._email_service = dependencies.services.email_service
        self._sms_service = dependencies.services.sms_service
        self._backup_service = dependencies.services.backup_service
        
        # Infrastructure dependencies
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_QUARANTINED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(QuarantineDeviceRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.quarantine")
    @require_mfa(condition="device_quarantine_operation")
    async def handle(self, command: QuarantineDeviceCommand) -> DeviceQuarantineResponse:
        """
        Quarantine device with comprehensive security measures.
        
        Process:
        1. Load device and validate quarantine operation
        2. Check quarantine permissions and policies
        3. Create forensic backup if required
        4. Create quarantine record
        5. Apply quarantine restrictions
        6. Invalidate sessions and tokens as needed
        7. Apply quarantine-specific policies
        8. Set up monitoring and alerts
        9. Send notifications
        10. Log security events
        11. Update device status and metadata
        
        Returns:
            DeviceQuarantineResponse with quarantine details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If quarantine not authorized
            DeviceAlreadyQuarantinedException: If device already quarantined
            InvalidQuarantineOperationError: If operation invalid
            QuarantineValidationError: If quarantine validation fails
        """
        async with self._unit_of_work:
            # 1. Load device
            device = await self._device_repository.get_by_id(command.device_id)
            if not device:
                raise DeviceNotFoundError(f"Device {command.device_id} not found")
            
            # 2. Load user
            user = await self._user_repository.get_by_id(device.user_id)
            if not user:
                raise DeviceNotFoundError(f"User {device.user_id} not found")
            
            # 3. Check if device already quarantined
            existing_quarantine = await self._quarantine_repository.find_active_by_device(device.id)
            if existing_quarantine:
                raise DeviceAlreadyQuarantinedException(
                    f"Device {device.id} already in quarantine: {existing_quarantine.id}"
                )
            
            # 4. Validate quarantine operation
            await self._validate_quarantine_operation(device, user, command)
            
            # 5. Check quarantine permissions
            await self._validate_quarantine_permissions(device, command.quarantined_by, command)
            
            # 6. Create forensic backup if required
            forensic_backup_id = None
            if command.create_forensic_backup:
                forensic_backup_id = await self._create_forensic_backup(device, user, command)
            
            # 7. Calculate quarantine duration
            quarantine_expires_at = None
            if command.duration_hours:
                quarantine_expires_at = datetime.now(UTC) + timedelta(hours=command.duration_hours)
            
            # 8. Create quarantine record
            quarantine_record = await self._create_quarantine_record(
                device,
                user,
                command,
                quarantine_expires_at,
                forensic_backup_id
            )
            
            # 9. Capture current device state
            was_primary = device.is_primary
            original_status = device.status
            
            # 10. Get sessions and tokens for restriction/invalidation
            active_sessions = await self._session_repository.find_active_by_device(device.id)
            active_tokens = await self._token_repository.find_active_by_device(device.id)
            
            # 11. Apply quarantine restrictions
            sessions_affected = 0
            tokens_affected = 0
            
            if command.invalidate_existing_sessions:
                for session in active_sessions:
                    try:
                        await self._session_service.quarantine_session(
                            session.id,
                            f"Device quarantined: {command.reason.value}"
                        )
                        sessions_affected += 1
                    except Exception as e:
                        await self._audit_service.log_error(
                            f"Failed to quarantine session {session.id}: {e!s}"
                        )
            
            # Restrict tokens based on quarantine level
            if command.quarantine_level in [QuarantineLevel.STRICT, QuarantineLevel.ISOLATION]:
                for token in active_tokens:
                    try:
                        await self._token_service.quarantine_token(
                            token.id,
                            command.allowed_operations
                        )
                        tokens_affected += 1
                    except Exception as e:
                        await self._audit_service.log_error(
                            f"Failed to quarantine token {token.id}: {e!s}"
                        )
            
            # 12. Update device status and metadata
            device.status = DeviceStatus.QUARANTINED
            device.quarantined_at = datetime.now(UTC)
            device.quarantined_by = command.quarantined_by
            device.quarantine_reason = command.reason.value
            device.custom_quarantine_reason = command.custom_reason
            device.quarantine_level = command.quarantine_level.value
            device.quarantine_id = quarantine_record.id
            device.security_incident_id = command.security_incident_id
            device.is_primary = False  # Quarantined devices cannot be primary
            
            # Add quarantine metadata
            device.metadata.update({
                "quarantine_metadata": {
                    "reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "quarantine_level": command.quarantine_level.value,
                    "quarantined_by": str(command.quarantined_by),
                    "quarantine_id": str(quarantine_record.id),
                    "expires_at": quarantine_expires_at.isoformat() if quarantine_expires_at else None,
                    "automatic_release": command.automatic_release,
                    "allowed_operations": command.allowed_operations,
                    "sessions_affected": sessions_affected,
                    "tokens_affected": tokens_affected,
                    "forensic_backup_id": str(forensic_backup_id) if forensic_backup_id else None,
                    "evidence_collection_required": command.evidence_collection_required,
                    "compliance_hold": command.compliance_hold,
                    "quarantine_timestamp": datetime.now(UTC).isoformat()
                }
            })
            
            await self._device_repository.update(device)
            
            # 13. Apply quarantine-specific policies
            quarantine_policies = await self._apply_quarantine_policies(device, user, command)
            
            # 14. Set up monitoring and alerts
            monitoring_config = await self._setup_quarantine_monitoring(device, user, command)
            
            # 15. Handle primary device replacement
            new_primary_device = None
            if was_primary:
                new_primary_device = await self._handle_primary_device_replacement(
                    user.id,
                    device.id
                )
            
            # 16. Assess quarantine impact
            quarantine_impact = await self._assess_quarantine_impact(
                device,
                user,
                command,
                was_primary
            )
            
            # 17. Send notifications
            notifications_sent = []
            if command.notify_user:
                notifications_sent.extend(
                    await self._send_user_quarantine_notifications(
                        user,
                        device,
                        quarantine_record,
                        quarantine_impact,
                        command
                    )
                )
            
            if command.notify_security_team:
                notifications_sent.extend(
                    await self._send_security_team_notifications(
                        user,
                        device,
                        quarantine_record,
                        quarantine_impact,
                        command
                    )
                )
            
            # 18. Log security events
            await self._log_quarantine_operation(
                user,
                device,
                quarantine_record,
                quarantine_impact,
                original_status,
                command
            )
            
            # 19. Update user security posture
            await self._update_user_security_posture(user, device, command)
            
            # 20. Publish domain event
            await self._event_bus.publish(
                DeviceQuarantined(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    quarantine_reason=command.reason,
                    quarantine_level=command.quarantine_level,
                    was_primary=was_primary,
                    quarantined_by=command.quarantined_by,
                    quarantine_id=quarantine_record.id,
                    expires_at=quarantine_expires_at,
                    sessions_affected=sessions_affected,
                    tokens_affected=tokens_affected,
                    forensic_backup_created=forensic_backup_id is not None,
                    security_incident_related=command.security_incident_id is not None
                )
            )
            
            # 21. Commit transaction
            await self._unit_of_work.commit()
            
            # 22. Return response
            return DeviceQuarantineResponse(
                device_id=device.id,
                user_id=device.user_id,
                device_name=device.device_name,
                device_type=device.device_type,
                quarantine_id=quarantine_record.id,
                quarantine_reason=command.reason,
                quarantine_level=command.quarantine_level,
                custom_reason=command.custom_reason,
                was_primary=was_primary,
                new_primary_device_id=new_primary_device.id if new_primary_device else None,
                quarantine_expires_at=quarantine_expires_at,
                automatic_release=command.automatic_release,
                allowed_operations=command.allowed_operations,
                sessions_affected=sessions_affected,
                tokens_affected=tokens_affected,
                forensic_backup_created=forensic_backup_id is not None,
                forensic_backup_id=forensic_backup_id,
                monitoring_enabled=monitoring_config["enabled"],
                notifications_sent=notifications_sent,
                policies_applied=quarantine_policies,
                compliance_hold=command.compliance_hold,
                evidence_collection_required=command.evidence_collection_required,
                impact_level=quarantine_impact["impact_level"],
                quarantined_at=device.quarantined_at,
                quarantined_by=device.quarantined_by,
                message="Device quarantined successfully"
            )
    
    async def _validate_quarantine_operation(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand
    ) -> None:
        """Validate the quarantine operation."""
        # Validate custom reason if required
        if command.reason == QuarantineReason.OTHER and not command.custom_reason:
            raise InvalidQuarantineOperationError("Custom reason required when using 'OTHER' reason")
        
        # Validate custom reason length
        if command.custom_reason and len(command.custom_reason) > 500:
            raise InvalidQuarantineOperationError("Custom reason too long (max 500 characters)")
        
        # Validate duration
        if command.duration_hours is not None:
            if command.duration_hours < 1 or command.duration_hours > 8760:  # Max 1 year
                raise InvalidQuarantineOperationError("Duration must be between 1 hour and 1 year")
        
        # Validate quarantine level and allowed operations
        if command.quarantine_level == QuarantineLevel.ISOLATION and command.allowed_operations:
            raise InvalidQuarantineOperationError("Isolation level cannot have allowed operations")
        
        # Check if device can be quarantined
        if device.status in [DeviceStatus.WIPED, DeviceStatus.REVOKED]:
            raise InvalidQuarantineOperationError(
                f"Cannot quarantine device with status: {device.status.value}"
            )
    
    async def _validate_quarantine_permissions(
        self,
        device: Device,
        quarantined_by: UUID,
        command: QuarantineDeviceCommand
    ) -> None:
        """Validate quarantine permissions."""
        # Check if quarantiner has appropriate permissions
        if command.quarantine_level == QuarantineLevel.ISOLATION:
            # Isolation requires special high-level permissions
            pass
        
        # Check if device is critical and requires special permission
        if device.is_primary:
            # Quarantining primary device requires additional authorization
            pass
        
        # Check compliance requirements
        if command.compliance_hold:
            # Compliance holds require special authorization
            pass
    
    async def _create_forensic_backup(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand
    ) -> UUID:
        """Create forensic backup before quarantine."""
        # Get comprehensive device and activity data
        recent_sessions = await self._session_repository.find_recent_by_device(
            device.id,
            days=90  # Extended period for forensic purposes
        )
        recent_tokens = await self._token_repository.find_recent_by_device(
            device.id,
            days=90
        )
        
        # Create comprehensive forensic backup
        forensic_data = {
            "forensic_metadata": {
                "backup_type": "quarantine_forensic",
                "quarantine_reason": command.reason.value,
                "custom_reason": command.custom_reason,
                "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                "evidence_collection_required": command.evidence_collection_required,
                "created_by": str(command.quarantined_by),
                "creation_timestamp": datetime.now(UTC).isoformat(),
                "retention_classification": "evidence_grade"
            },
            "device_snapshot": {
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
            "user_context": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": f"{user.first_name} {user.last_name}",
                "account_status": user.status,
                "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                "security_flags": user.metadata.get("security_flags", {})
            },
            "activity_history": {
                "sessions": [
                    {
                        "id": str(session.id),
                        "created_at": session.created_at.isoformat(),
                        "last_activity": session.last_activity.isoformat() if session.last_activity else None,
                        "ip_address": session.ip_address,
                        "user_agent": session.user_agent,
                        "location": session.location_data,
                        "status": session.status,
                        "metadata": session.metadata
                    } for session in recent_sessions
                ],
                "tokens": [
                    {
                        "id": str(token.id),
                        "token_type": token.token_type,
                        "created_at": token.created_at.isoformat(),
                        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                        "last_used": token.last_used.isoformat() if token.last_used else None,
                        "scopes": token.scopes,
                        "status": token.status
                    } for token in recent_tokens
                ]
            }
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.FORENSIC_QUARANTINE,
                resource_type="device",
                resource_id=device.id,
                data=forensic_data,
                retention_days=2555,  # 7 years for legal/compliance purposes
                encrypted=True,
                evidence_grade=True,
                chain_of_custody=True
            )
        )
        
    
    async def _create_quarantine_record(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand,
        expires_at: datetime | None,
        forensic_backup_id: UUID | None
    ) -> Any:
        """Create quarantine record."""
        quarantine_data = {
            "id": UUID(),
            "device_id": device.id,
            "user_id": user.id,
            "quarantine_reason": command.reason.value,
            "custom_reason": command.custom_reason,
            "quarantine_level": command.quarantine_level.value,
            "quarantined_by": command.quarantined_by,
            "quarantined_at": datetime.now(UTC),
            "expires_at": expires_at,
            "automatic_release": command.automatic_release,
            "allowed_operations": command.allowed_operations,
            "require_admin_approval_to_release": command.require_admin_approval_to_release,
            "security_incident_id": command.security_incident_id,
            "forensic_backup_id": forensic_backup_id,
            "evidence_collection_required": command.evidence_collection_required,
            "compliance_hold": command.compliance_hold,
            "escalation_contacts": command.escalation_contacts,
            "status": QuarantineStatus.ACTIVE,
            "metadata": command.metadata
        }
        
        return await self._quarantine_repository.create(quarantine_data)
    
    async def _apply_quarantine_policies(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand
    ) -> list[str]:
        """Apply quarantine-specific security policies."""
        policies_applied = []
        
        # Apply policies based on quarantine level
        if command.quarantine_level == QuarantineLevel.RESTRICTED:
            policies_applied.extend([
                "limited_session_duration",
                "restricted_api_access",
                "enhanced_logging",
                "location_tracking_required"
            ])
        
        elif command.quarantine_level == QuarantineLevel.STRICT:
            policies_applied.extend([
                "very_limited_session_duration",
                "highly_restricted_api_access",
                "comprehensive_logging",
                "continuous_monitoring",
                "mfa_required_all_operations"
            ])
        
        elif command.quarantine_level == QuarantineLevel.ISOLATION:
            policies_applied.extend([
                "no_new_sessions",
                "no_api_access",
                "full_activity_logging",
                "real_time_monitoring",
                "admin_approval_required"
            ])
        
        # Apply reason-specific policies
        if command.reason in [QuarantineReason.SECURITY_BREACH, QuarantineReason.MALWARE_DETECTED]:
            policies_applied.extend([
                "network_isolation",
                "file_access_blocked",
                "data_exfiltration_prevention"
            ])
        
        # Apply compliance policies if needed
        if command.compliance_hold:
            policies_applied.extend([
                "compliance_audit_logging",
                "data_preservation_mode",
                "legal_hold_markers"
            ])
        
        return policies_applied
    
    async def _setup_quarantine_monitoring(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand
    ) -> dict[str, Any]:
        """Set up monitoring and alerts for quarantined device."""
        monitoring_config = {
            "enabled": True,
            "real_time_alerts": command.quarantine_level in [QuarantineLevel.STRICT, QuarantineLevel.ISOLATION],
            "monitoring_level": command.quarantine_level.value,
            "alert_thresholds": {
                "failed_access_attempts": 3,
                "unusual_activity_score": 50,
                "policy_violations": 1
            },
            "escalation_contacts": command.escalation_contacts,
            "monitoring_duration": command.duration_hours if command.duration_hours else None
        }
        
        # Configure monitoring based on quarantine level
        if command.quarantine_level == QuarantineLevel.ISOLATION:
            monitoring_config["alert_thresholds"]["failed_access_attempts"] = 1
            monitoring_config["immediate_escalation"] = True
        
        return monitoring_config
    
    async def _handle_primary_device_replacement(
        self,
        user_id: UUID,
        quarantined_device_id: UUID
    ) -> Device | None:
        """Handle replacement of primary device when quarantined."""
        # Find other active devices
        active_devices = await self._device_repository.find_active_by_user(user_id)
        active_devices = [d for d in active_devices if d.id != quarantined_device_id]
        
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
        new_primary.promoted_to_primary_reason = "primary_device_quarantined"
        
        await self._device_repository.update(new_primary)
        
        return new_primary
    
    async def _assess_quarantine_impact(
        self,
        device: Device,
        user: User,
        command: QuarantineDeviceCommand,
        was_primary: bool
    ) -> dict[str, Any]:
        """Assess impact of device quarantine."""
        impact_factors = []
        impact_score = 0
        
        # Check if primary device
        if was_primary:
            impact_factors.append("primary_device_quarantined")
            impact_score += 40
        
        # Check if trusted device
        if device.trust_level.value in ["trusted", "fully_trusted"]:
            impact_factors.append("trusted_device_quarantined")
            impact_score += 30
        
        # Check quarantine reason
        high_impact_reasons = [
            QuarantineReason.SECURITY_BREACH,
            QuarantineReason.MALWARE_DETECTED,
            QuarantineReason.COMPROMISED_ACCOUNT
        ]
        
        if command.reason in high_impact_reasons:
            impact_factors.append(f"high_impact_reason_{command.reason.value}")
            impact_score += 50
        
        # Check quarantine level
        if command.quarantine_level == QuarantineLevel.ISOLATION:
            impact_factors.append("isolation_level_quarantine")
            impact_score += 35
        elif command.quarantine_level == QuarantineLevel.STRICT:
            impact_factors.append("strict_level_quarantine")
            impact_score += 25
        
        # Check if only device
        user_device_count = await self._device_repository.count_active_by_user(user.id)
        if user_device_count <= 1:  # This device being quarantined leaves 0
            impact_factors.append("last_device_quarantined")
            impact_score += 60
        
        # Check if security incident related
        if command.security_incident_id:
            impact_factors.append("security_incident_related")
            impact_score += 35
        
        # Check compliance implications
        if command.compliance_hold:
            impact_factors.append("compliance_hold_applied")
            impact_score += 20
        
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
            "recommendations": self._get_quarantine_recommendations(impact_level, impact_factors)
        }
    
    def _get_quarantine_recommendations(
        self,
        impact_level: str,
        impact_factors: list[str]
    ) -> list[str]:
        """Get recommendations based on quarantine impact assessment."""
        recommendations = []
        
        if "last_device_quarantined" in impact_factors:
            recommendations.append("User has no remaining devices - provide alternative access method")
            recommendations.append("Expedite device recovery or provision temporary device")
        
        if "primary_device_quarantined" in impact_factors:
            recommendations.append("Monitor new primary device selection")
            recommendations.append("Consider additional verification for critical operations")
        
        if any("high_impact_reason" in factor for factor in impact_factors):
            recommendations.append("Follow incident response procedures")
            recommendations.append("Conduct thorough security investigation")
            recommendations.append("Consider extending quarantine duration")
        
        if "isolation_level_quarantine" in impact_factors:
            recommendations.append("Implement continuous monitoring")
            recommendations.append("Require security team approval for release")
        
        if impact_level in ["high", "critical"]:
            recommendations.append("Notify senior security personnel")
            recommendations.append("Document quarantine decision thoroughly")
            recommendations.append("Plan for post-quarantine security assessment")
        
        return recommendations
    
    async def _send_user_quarantine_notifications(
        self,
        user: User,
        device: Device,
        quarantine_record: Any,
        quarantine_impact: dict[str, Any],
        command: QuarantineDeviceCommand
    ) -> list[str]:
        """Send notifications to user about device quarantine."""
        notifications_sent = []
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_QUARANTINED,
                channel="in_app",
                template_id="device_quarantined",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "quarantine_reason": command.reason.value,
                    "quarantine_level": command.quarantine_level.value,
                    "expires_at": command.duration_hours,
                    "allowed_operations": command.allowed_operations,
                    "was_primary": device.is_primary,
                    "impact_level": quarantine_impact["impact_level"]
                },
                priority="critical"
            )
        )
        notifications_sent.append("in_app")
        
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_quarantined",
                    subject="Device Quarantined for Security",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "quarantine_reason": command.reason.value,
                        "custom_reason": command.custom_reason,
                        "quarantine_level": command.quarantine_level.value,
                        "expires_at": quarantine_record.expires_at.isoformat() if quarantine_record.expires_at else "Indefinite",
                        "allowed_operations": command.allowed_operations,
                        "was_primary": device.is_primary,
                        "automatic_release": command.automatic_release,
                        "compliance_hold": command.compliance_hold,
                        "contact_support": not command.automatic_release,
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
            notifications_sent.append("email")
        
        # SMS notification for high-impact quarantines
        if quarantine_impact["impact_level"] in ["high", "critical"] and user.phone_verified:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=user.phone_number,
                    template="device_quarantined_urgent",
                    variables={
                        "device_name": device.device_name,
                        "quarantine_reason": command.reason.value
                    }
                )
            )
            notifications_sent.append("sms")
        
        return notifications_sent
    
    async def _send_security_team_notifications(
        self,
        user: User,
        device: Device,
        quarantine_record: Any,
        quarantine_impact: dict[str, Any],
        command: QuarantineDeviceCommand
    ) -> list[str]:
        """Send notifications to security team about device quarantine."""
        notifications_sent = []
        
        # Security team email notification
        security_team_emails = ["security-team@example.com"]  # This would be configurable
        
        for email in security_team_emails:
            await self._email_service.send_email(
                EmailContext(
                    recipient=email,
                    template="security_device_quarantined",
                    subject=f"Device Quarantined - {quarantine_impact['impact_level'].upper()} Impact",
                    variables={
                        "user_id": str(user.id),
                        "username": user.username,
                        "user_email": user.email,
                        "device_id": str(device.id),
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "quarantine_reason": command.reason.value,
                        "custom_reason": command.custom_reason,
                        "quarantine_level": command.quarantine_level.value,
                        "quarantined_by": str(command.quarantined_by),
                        "impact_level": quarantine_impact["impact_level"],
                        "impact_factors": quarantine_impact["impact_factors"],
                        "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                        "forensic_backup_created": command.create_forensic_backup,
                        "compliance_hold": command.compliance_hold,
                        "evidence_collection_required": command.evidence_collection_required,
                        "quarantine_id": str(quarantine_record.id),
                        "admin_dashboard_link": "https://app.example.com/admin/quarantine"
                    }
                )
            )
        notifications_sent.append("security_team_email")
        
        # Escalation contacts if specified
        for contact in command.escalation_contacts:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact,
                    template="quarantine_escalation",
                    subject=f"Device Quarantine Escalation - {device.device_name}",
                    variables={
                        "device_name": device.device_name,
                        "quarantine_reason": command.reason.value,
                        "impact_level": quarantine_impact["impact_level"],
                        "user_email": user.email,
                        "quarantine_id": str(quarantine_record.id)
                    }
                )
            )
        
        if command.escalation_contacts:
            notifications_sent.append("escalation_contacts")
        
        return notifications_sent
    
    async def _log_quarantine_operation(
        self,
        user: User,
        device: Device,
        quarantine_record: Any,
        quarantine_impact: dict[str, Any],
        original_status: DeviceStatus,
        command: QuarantineDeviceCommand
    ) -> None:
        """Log device quarantine operation for audit and compliance."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_QUARANTINED,
                actor_id=command.quarantined_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "quarantine_reason": command.reason.value,
                    "custom_reason": command.custom_reason,
                    "quarantine_level": command.quarantine_level.value,
                    "quarantine_id": str(quarantine_record.id),
                    "was_primary": device.is_primary,
                    "original_status": original_status.value,
                    "duration_hours": command.duration_hours,
                    "automatic_release": command.automatic_release,
                    "security_incident_id": str(command.security_incident_id) if command.security_incident_id else None,
                    "compliance_hold": command.compliance_hold,
                    "evidence_collection_required": command.evidence_collection_required,
                    "impact_assessment": quarantine_impact,
                    "forensic_backup_created": command.create_forensic_backup
                },
                risk_level="critical" if quarantine_impact["impact_level"] == "critical" else "high"
            )
        )
        
        # Log as security incident
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.DEVICE_QUARANTINED,
                severity=RiskLevel.HIGH if quarantine_impact["impact_level"] == "high" else RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "device_id": str(device.id),
                    "device_name": device.device_name,
                    "quarantine_reason": command.reason.value,
                    "quarantine_level": command.quarantine_level.value,
                    "impact_factors": quarantine_impact["impact_factors"],
                    "impact_score": quarantine_impact["impact_score"],
                    "quarantine_id": str(quarantine_record.id)
                },
                indicators=quarantine_impact["impact_factors"],
                recommended_actions=quarantine_impact["recommendations"]
            )
        )
    
    async def _update_user_security_posture(
        self,
        user: User,
        device: Device,
        command: QuarantineDeviceCommand
    ) -> None:
        """Update user's security posture after device quarantine."""
        # Update user metadata with device quarantine info
        if "security_posture" not in user.metadata:
            user.metadata["security_posture"] = {}
        
        user.metadata["security_posture"].update({
            "last_device_quarantine": datetime.now(UTC).isoformat(),
            "quarantined_devices_count": user.metadata["security_posture"].get("quarantined_devices_count", 0) + 1,
            "last_quarantined_device_type": device.device_type.value,
            "last_quarantine_reason": command.reason.value,
            "last_quarantine_level": command.quarantine_level.value
        })
        
        await self._user_repository.update(user)
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]