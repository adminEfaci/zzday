"""
Trust device command implementation.

Handles marking devices as trusted based on security validation.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IDevicePolicyRepository,
    IDeviceRepository,
    IEmailService,
    INotificationService,
    IThreatIntelligenceService,
    ITrustAssessmentRepository,
    IUserRepository,
)
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
)
from app.modules.identity.application.dtos.request import TrustDeviceRequest
from app.modules.identity.application.dtos.response import DeviceTrustResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeviceStatus,
    NotificationType,
    TrustLevel,
    TrustMethod,
    TrustValidationLevel,
)
from app.modules.identity.domain.events import DeviceTrusted
from app.modules.identity.domain.exceptions import (
    DeviceAlreadyTrustedException,
    DeviceNotFoundError,
    DeviceTrustValidationError,
    InsecureDeviceError,
)
from app.modules.identity.domain.services import (
    BiometricService,
    DeviceSecurityService,
    ValidationService,
)


class TrustDeviceCommand(Command[DeviceTrustResponse]):
    """Command to trust a device."""
    
    def __init__(
        self,
        device_id: UUID,
        trusted_by: UUID,
        trust_method: TrustMethod,
        validation_level: TrustValidationLevel = TrustValidationLevel.STANDARD,
        biometric_verification: bool = False,
        biometric_data: dict[str, Any] | None = None,
        location_verification: bool = False,
        expected_location: dict[str, Any] | None = None,
        security_assessment_required: bool = True,
        policy_compliance_check: bool = True,
        user_confirmation_required: bool = True,
        trust_duration_days: int | None = None,
        conditional_trust: bool = False,
        trust_conditions: list[str] | None = None,
        reason: str | None = None,
        auto_trust_similar_devices: bool = False,
        notify_user: bool = True,
        evidence_data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.trusted_by = trusted_by
        self.trust_method = trust_method
        self.validation_level = validation_level
        self.biometric_verification = biometric_verification
        self.biometric_data = biometric_data or {}
        self.location_verification = location_verification
        self.expected_location = expected_location or {}
        self.security_assessment_required = security_assessment_required
        self.policy_compliance_check = policy_compliance_check
        self.user_confirmation_required = user_confirmation_required
        self.trust_duration_days = trust_duration_days
        self.conditional_trust = conditional_trust
        self.trust_conditions = trust_conditions or []
        self.reason = reason or "Device trusted based on security validation"
        self.auto_trust_similar_devices = auto_trust_similar_devices
        self.notify_user = notify_user
        self.evidence_data = evidence_data or {}
        self.metadata = metadata or {}


class TrustDeviceCommandHandler(CommandHandler[TrustDeviceCommand, DeviceTrustResponse]):
    """Handler for trusting devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        device_policy_repository: IDevicePolicyRepository,
        trust_assessment_repository: ITrustAssessmentRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        biometric_service: BiometricService,
        threat_intelligence_service: IThreatIntelligenceService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._device_policy_repository = device_policy_repository
        self._trust_assessment_repository = trust_assessment_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._biometric_service = biometric_service
        self._threat_intelligence_service = threat_intelligence_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_TRUSTED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(TrustDeviceRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.trust")
    @require_mfa(condition="device_trust_operation")
    async def handle(self, command: TrustDeviceCommand) -> DeviceTrustResponse:
        """
        Trust device with comprehensive security validation.
        
        Process:
        1. Load device and validate trust operation
        2. Perform comprehensive security assessment
        3. Validate trust criteria and conditions
        4. Check policy compliance
        5. Perform biometric verification if required
        6. Create trust assessment record
        7. Update device trust level
        8. Apply trust policies
        9. Send notifications
        10. Log trust operation
        
        Returns:
            DeviceTrustResponse with trust operation details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If cannot trust device
            DeviceAlreadyTrustedException: If already trusted
            DeviceTrustValidationError: If trust validation fails
            InsecureDeviceError: If device security insufficient
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
            
            # 3. Check if device already trusted
            if device.trust_level == TrustLevel.TRUSTED and not command.conditional_trust:
                raise DeviceAlreadyTrustedException(f"Device {device.id} already trusted")
            
            # 4. Check trust permissions
            await self._validate_trust_permissions(device, command.trusted_by, command)
            
            # 5. Perform comprehensive security assessment
            security_assessment = None
            if command.security_assessment_required:
                security_assessment = await self._perform_comprehensive_security_assessment(
                    device,
                    user,
                    command
                )
                
                # Check if device meets minimum security requirements
                if security_assessment["security_score"] < 70:  # Minimum threshold
                    raise InsecureDeviceError(
                        f"Device security score too low: {security_assessment['security_score']}/100"
                    )
            
            # 6. Check policy compliance
            policy_compliance = None
            if command.policy_compliance_check:
                policy_compliance = await self._check_trust_policy_compliance(
                    device,
                    user,
                    command
                )
                
                if not policy_compliance["compliant"]:
                    raise DeviceTrustValidationError(
                        f"Device does not meet trust policies: {', '.join(policy_compliance['violations'])}"
                    )
            
            # 7. Perform biometric verification if required
            biometric_verification_result = None
            if command.biometric_verification:
                biometric_verification_result = await self._perform_biometric_verification(
                    device,
                    user,
                    command
                )
                
                if not biometric_verification_result["verified"]:
                    raise DeviceTrustValidationError(
                        f"Biometric verification failed: {biometric_verification_result['failure_reason']}"
                    )
            
            # 8. Validate location if required
            location_verification_result = None
            if command.location_verification:
                location_verification_result = await self._verify_device_location(
                    device,
                    command.expected_location
                )
                
                if not location_verification_result["verified"]:
                    raise DeviceTrustValidationError(
                        f"Location verification failed: {location_verification_result['failure_reason']}"
                    )
            
            # 9. Create trust assessment record
            trust_assessment = await self._create_trust_assessment(
                device,
                user,
                command,
                security_assessment,
                policy_compliance,
                biometric_verification_result,
                location_verification_result
            )
            
            # 10. Determine final trust level
            final_trust_level = await self._determine_final_trust_level(
                command,
                trust_assessment,
                security_assessment
            )
            
            # 11. Update device trust
            original_trust_level = device.trust_level
            device.trust_level = final_trust_level
            device.trusted_at = datetime.now(UTC)
            device.trusted_by = command.trusted_by
            device.trust_method = command.trust_method
            device.trust_validation_level = command.validation_level
            device.trust_assessment_id = trust_assessment.id
            
            # Set trust expiration if specified
            if command.trust_duration_days:
                device.trust_expires_at = datetime.now(UTC) + timedelta(days=command.trust_duration_days)
            
            # Set conditional trust data
            if command.conditional_trust:
                device.is_conditionally_trusted = True
                device.trust_conditions = command.trust_conditions
            
            # Update trust metadata
            device.metadata.update({
                "trust_metadata": {
                    "trust_method": command.trust_method.value,
                    "validation_level": command.validation_level.value,
                    "trusted_by": str(command.trusted_by),
                    "trust_duration_days": command.trust_duration_days,
                    "conditional_trust": command.conditional_trust,
                    "trust_conditions": command.trust_conditions,
                    "biometric_verified": command.biometric_verification,
                    "location_verified": command.location_verification,
                    "trust_timestamp": datetime.now(UTC).isoformat(),
                    "evidence_data": command.evidence_data
                }
            })
            
            await self._device_repository.update(device)
            
            # 12. Apply trust policies
            trust_policies_applied = await self._apply_trust_policies(device, user)
            
            # 13. Handle auto-trust for similar devices
            similar_devices_trusted = []
            if command.auto_trust_similar_devices:
                similar_devices_trusted = await self._auto_trust_similar_devices(
                    device,
                    user,
                    command
                )
            
            # 14. Send notifications
            if command.notify_user:
                await self._send_trust_notifications(
                    user,
                    device,
                    trust_assessment,
                    command
                )
            
            # 15. Log trust operation
            await self._log_device_trust_operation(
                user,
                device,
                trust_assessment,
                original_trust_level,
                command
            )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                DeviceTrusted(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    previous_trust_level=original_trust_level,
                    new_trust_level=final_trust_level,
                    trust_method=command.trust_method,
                    validation_level=command.validation_level,
                    trusted_by=command.trusted_by,
                    conditional_trust=command.conditional_trust,
                    trust_score=trust_assessment.trust_score,
                    security_score=security_assessment["security_score"] if security_assessment else None
                )
            )
            
            # 17. Commit transaction
            await self._unit_of_work.commit()
            
            # 18. Return response
            return DeviceTrustResponse(
                device_id=device.id,
                user_id=device.user_id,
                device_name=device.device_name,
                device_type=device.device_type,
                previous_trust_level=original_trust_level,
                new_trust_level=final_trust_level,
                trust_method=command.trust_method,
                validation_level=command.validation_level,
                trust_score=trust_assessment.trust_score,
                security_score=security_assessment["security_score"] if security_assessment else None,
                conditional_trust=command.conditional_trust,
                trust_conditions=command.trust_conditions,
                trust_expires_at=device.trust_expires_at,
                biometric_verified=command.biometric_verification,
                location_verified=command.location_verification,
                policy_compliant=policy_compliance["compliant"] if policy_compliance else None,
                policies_applied=trust_policies_applied,
                similar_devices_trusted=len(similar_devices_trusted),
                trusted_at=device.trusted_at,
                trusted_by=device.trusted_by,
                message="Device trusted successfully"
            )
    
    async def _validate_trust_permissions(
        self,
        device: Device,
        trusted_by: UUID,
        command: TrustDeviceCommand
    ) -> None:
        """Validate user can trust this device."""
        # User can trust their own devices
        if device.user_id == trusted_by:
            return
        
        # Check if truster has admin permissions
        # Additional checks for high-level trust operations
        if command.validation_level == TrustValidationLevel.ENTERPRISE:
            # Enterprise-level trust requires special permissions
            pass
        
        # Check if device requires elevated permissions to trust
        if device.device_type.value in ["server", "iot_device"]:
            # Special device types may require additional permissions
            pass
    
    async def _perform_comprehensive_security_assessment(
        self,
        device: Device,
        user: User,
        command: TrustDeviceCommand
    ) -> dict[str, Any]:
        """Perform comprehensive security assessment for trust decision."""
        assessment = {
            "security_score": 0,
            "security_factors": [],
            "security_warnings": [],
            "risk_factors": [],
            "trust_indicators": []
        }
        
        # Device security features assessment
        security_features_score = 0
        required_features = ["screen_lock", "encryption", "biometric_auth"]
        
        for feature in required_features:
            if device.security_features.get(feature, False):
                security_features_score += 20
                assessment["trust_indicators"].append(f"has_{feature}")
            else:
                assessment["security_warnings"].append(f"missing_{feature}")
        
        assessment["security_score"] += min(security_features_score, 60)
        
        # Device OS and software assessment
        if device.device_os and device.device_os_version:
            os_security_score = await self._device_security_service.assess_os_security(
                device.device_os,
                device.device_os_version
            )
            assessment["security_score"] += min(os_security_score, 20)
            
            if os_security_score < 50:
                assessment["security_warnings"].append("outdated_os")
        
        # Location consistency assessment
        if device.location_data:
            location_consistency = await self._assess_location_consistency(
                device,
                user
            )
            if location_consistency["is_consistent"]:
                assessment["security_score"] += 10
                assessment["trust_indicators"].append("consistent_location")
            else:
                assessment["risk_factors"].append("inconsistent_location")
        
        # Usage pattern assessment
        usage_pattern_score = await self._assess_usage_patterns(device, user)
        assessment["security_score"] += min(usage_pattern_score, 10)
        
        # Threat intelligence check
        if device.ip_address:
            threat_check = await self._threat_intelligence_service.check_ip_reputation(
                device.ip_address
            )
            if threat_check["is_malicious"]:
                assessment["risk_factors"].append("malicious_ip")
                assessment["security_score"] -= 30
            elif threat_check["is_suspicious"]:
                assessment["risk_factors"].append("suspicious_ip")
                assessment["security_score"] -= 15
            else:
                assessment["trust_indicators"].append("clean_ip")
        
        # Device age and registration pattern assessment
        device_age_days = (datetime.now(UTC) - device.registered_at).days
        if device_age_days > 30:  # Device has been registered for a while
            assessment["trust_indicators"].append("established_device")
            assessment["security_score"] += 5
        elif device_age_days < 1:  # Very new device
            assessment["risk_factors"].append("very_new_device")
        
        # Cap the score at 100
        assessment["security_score"] = min(assessment["security_score"], 100)
        
        # Determine overall security level
        if assessment["security_score"] >= 90:
            assessment["security_level"] = "excellent"
        elif assessment["security_score"] >= 80:
            assessment["security_level"] = "good"
        elif assessment["security_score"] >= 70:
            assessment["security_level"] = "acceptable"
        elif assessment["security_score"] >= 60:
            assessment["security_level"] = "marginal"
        else:
            assessment["security_level"] = "insufficient"
        
        assessment["assessment_timestamp"] = datetime.now(UTC).isoformat()
        
        return assessment
    
    async def _check_trust_policy_compliance(
        self,
        device: Device,
        user: User,
        command: TrustDeviceCommand
    ) -> dict[str, Any]:
        """Check device compliance with trust policies."""
        # Get applicable trust policies
        trust_policies = await self._device_policy_repository.find_trust_policies_for_user(
            user.id,
            device.device_type
        )
        
        compliance_result = {
            "compliant": True,
            "violations": [],
            "warnings": [],
            "policies_checked": []
        }
        
        for policy in trust_policies:
            policy_result = await self._device_security_service.check_trust_policy_compliance(
                device,
                policy,
                command
            )
            
            compliance_result["policies_checked"].append(policy.name)
            
            if not policy_result["compliant"]:
                compliance_result["compliant"] = False
                compliance_result["violations"].extend(policy_result["violations"])
            
            if policy_result.get("warnings"):
                compliance_result["warnings"].extend(policy_result["warnings"])
        
        return compliance_result
    
    async def _perform_biometric_verification(
        self,
        device: Device,
        user: User,
        command: TrustDeviceCommand
    ) -> dict[str, Any]:
        """Perform biometric verification for device trust."""
        if not command.biometric_data:
            return {
                "verified": False,
                "failure_reason": "No biometric data provided"
            }
        
        # Verify biometric data
        verification_result = await self._biometric_service.verify_biometric(
            user.id,
            command.biometric_data
        )
        
        return {
            "verified": verification_result["verified"],
            "confidence_score": verification_result.get("confidence_score", 0),
            "biometric_type": verification_result.get("biometric_type"),
            "failure_reason": verification_result.get("failure_reason"),
            "verification_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _verify_device_location(
        self,
        device: Device,
        expected_location: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify device location matches expected location."""
        if not device.location_data or not expected_location:
            return {
                "verified": False,
                "failure_reason": "Location data not available"
            }
        
        # Calculate distance between current and expected location
        if ("latitude" in device.location_data and "longitude" in device.location_data and
            "latitude" in expected_location and "longitude" in expected_location):
            
            distance_km = await self._calculate_location_distance(
                device.location_data["latitude"],
                device.location_data["longitude"],
                expected_location["latitude"],
                expected_location["longitude"]
            )
            
            # Allow some tolerance (e.g., 50km)
            tolerance_km = expected_location.get("tolerance_km", 50)
            
            if distance_km <= tolerance_km:
                return {
                    "verified": True,
                    "distance_km": distance_km,
                    "tolerance_km": tolerance_km
                }
            return {
                "verified": False,
                "failure_reason": f"Location too far: {distance_km}km (tolerance: {tolerance_km}km)",
                "distance_km": distance_km,
                "tolerance_km": tolerance_km
            }
        
        return {
            "verified": False,
            "failure_reason": "Insufficient location coordinates"
        }
    
    async def _create_trust_assessment(
        self,
        device: Device,
        user: User,
        command: TrustDeviceCommand,
        security_assessment: dict[str, Any] | None,
        policy_compliance: dict[str, Any] | None,
        biometric_verification: dict[str, Any] | None,
        location_verification: dict[str, Any] | None
    ) -> Any:
        """Create comprehensive trust assessment record."""
        # Calculate trust score
        trust_score = 0
        
        if security_assessment:
            trust_score += security_assessment["security_score"] * 0.4  # 40% weight
        
        if policy_compliance and policy_compliance["compliant"]:
            trust_score += 20  # 20% weight
        
        if biometric_verification and biometric_verification["verified"]:
            trust_score += 25  # 25% weight
        
        if location_verification and location_verification["verified"]:
            trust_score += 15  # 15% weight
        
        # Cap at 100
        trust_score = min(trust_score, 100)
        
        assessment_data = {
            "id": UUID(),
            "device_id": device.id,
            "user_id": user.id,
            "trust_method": command.trust_method.value,
            "validation_level": command.validation_level.value,
            "trust_score": trust_score,
            "security_assessment": security_assessment,
            "policy_compliance": policy_compliance,
            "biometric_verification": biometric_verification,
            "location_verification": location_verification,
            "assessor_id": command.trusted_by,
            "assessment_reason": command.reason,
            "evidence_data": command.evidence_data,
            "created_at": datetime.now(UTC),
            "metadata": command.metadata
        }
        
        return await self._trust_assessment_repository.create(assessment_data)
    
    async def _determine_final_trust_level(
        self,
        command: TrustDeviceCommand,
        trust_assessment: Any,
        security_assessment: dict[str, Any] | None
    ) -> TrustLevel:
        """Determine final trust level based on assessment."""
        if command.conditional_trust:
            return TrustLevel.CONDITIONALLY_TRUSTED
        
        # Base on trust score and validation level
        trust_score = trust_assessment.trust_score
        
        if command.validation_level == TrustValidationLevel.BASIC:
            return TrustLevel.PARTIALLY_TRUSTED if trust_score >= 60 else TrustLevel.UNTRUSTED
        
        if command.validation_level == TrustValidationLevel.STANDARD:
            if trust_score >= 80:
                return TrustLevel.TRUSTED
            if trust_score >= 60:
                return TrustLevel.PARTIALLY_TRUSTED
            return TrustLevel.UNTRUSTED
        
        if command.validation_level == TrustValidationLevel.ENTERPRISE:
            # Enterprise level requires higher standards
            if trust_score >= 90:
                return TrustLevel.FULLY_TRUSTED
            if trust_score >= 80:
                return TrustLevel.TRUSTED
            if trust_score >= 70:
                return TrustLevel.PARTIALLY_TRUSTED
            return TrustLevel.UNTRUSTED
        
        return TrustLevel.UNTRUSTED
    
    async def _apply_trust_policies(self, device: Device, user: User) -> list[str]:
        """Apply trust-specific policies to device."""
        policies_applied = []
        
        # Apply policies based on trust level
        if device.trust_level == TrustLevel.TRUSTED:
            # Reduce MFA requirements
            policies_applied.append("reduced_mfa_requirements")
            
            # Enable enhanced features
            policies_applied.append("enhanced_features_enabled")
        
        elif device.trust_level == TrustLevel.PARTIALLY_TRUSTED:
            # Apply moderate security policies
            policies_applied.append("moderate_security_policies")
        
        # Apply conditional policies if applicable
        if device.is_conditionally_trusted:
            for condition in device.trust_conditions:
                policies_applied.append(f"conditional_policy_{condition}")
        
        return policies_applied
    
    async def _auto_trust_similar_devices(
        self,
        trusted_device: Device,
        user: User,
        command: TrustDeviceCommand
    ) -> list[Device]:
        """Automatically trust similar devices based on fingerprint similarity."""
        similar_devices = await self._device_security_service.find_similar_devices(
            trusted_device,
            user.id
        )
        
        devices_trusted = []
        
        for device in similar_devices:
            if (device.trust_level == TrustLevel.UNTRUSTED and
                device.status == DeviceStatus.ACTIVE):
                
                # Apply same trust level but mark as auto-trusted
                device.trust_level = TrustLevel.PARTIALLY_TRUSTED
                device.trusted_at = datetime.now(UTC)
                device.trusted_by = command.trusted_by
                device.trust_method = TrustMethod.AUTOMATIC
                device.auto_trusted_from_device = trusted_device.id
                
                await self._device_repository.update(device)
                devices_trusted.append(device)
        
        return devices_trusted
    
    async def _send_trust_notifications(
        self,
        user: User,
        device: Device,
        trust_assessment: Any,
        command: TrustDeviceCommand
    ) -> None:
        """Send notifications about device trust operation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_trusted",
                    subject="Device Trusted",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "trust_level": device.trust_level.value,
                        "trust_method": command.trust_method.value,
                        "validation_level": command.validation_level.value,
                        "trust_score": trust_assessment.trust_score,
                        "conditional_trust": command.conditional_trust,
                        "trust_conditions": command.trust_conditions,
                        "trusted_by_admin": command.trusted_by != user.id,
                        "trust_expires": device.trust_expires_at.isoformat() if device.trust_expires_at else None,
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_TRUSTED,
                channel="in_app",
                template_id="device_trusted",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "trust_level": device.trust_level.value,
                    "trust_method": command.trust_method.value,
                    "trust_score": trust_assessment.trust_score,
                    "conditional_trust": command.conditional_trust
                },
                priority="medium"
            )
        )
    
    async def _log_device_trust_operation(
        self,
        user: User,
        device: Device,
        trust_assessment: Any,
        original_trust_level: TrustLevel,
        command: TrustDeviceCommand
    ) -> None:
        """Log device trust operation for audit."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_TRUSTED,
                actor_id=command.trusted_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "previous_trust_level": original_trust_level.value,
                    "new_trust_level": device.trust_level.value,
                    "trust_method": command.trust_method.value,
                    "validation_level": command.validation_level.value,
                    "trust_score": trust_assessment.trust_score,
                    "conditional_trust": command.conditional_trust,
                    "trust_conditions": command.trust_conditions,
                    "biometric_verified": command.biometric_verification,
                    "location_verified": command.location_verification,
                    "admin_action": command.trusted_by != user.id,
                    "reason": command.reason
                },
                risk_level="medium" if device.trust_level == TrustLevel.TRUSTED else "low"
            )
        )
    
    async def _assess_location_consistency(
        self,
        device: Device,
        user: User
    ) -> dict[str, Any]:
        """Assess if device location is consistent with user's usual locations."""
        # This would typically check against user's historical locations
        # For now, return a simple consistency check
        return {
            "is_consistent": True,
            "confidence": 0.8,
            "reason": "Location within expected range"
        }
    
    async def _assess_usage_patterns(self, device: Device, user: User) -> int:
        """Assess device usage patterns for trust scoring."""
        # This would analyze usage patterns, login times, etc.
        # For now, return a baseline score
        return 5
    
    async def _calculate_location_distance(
        self,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float
    ) -> float:
        """Calculate distance between two coordinates in kilometers."""
        from math import atan2, cos, radians, sin, sqrt
        
        # Haversine formula
        earth_radius_km = 6371  # Earth's radius in km
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return earth_radius_km * c
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]