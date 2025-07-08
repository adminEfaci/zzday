"""
Register device command implementation.

Handles registering new devices for users with comprehensive security validation.
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
    ISMSService,
    IThreatIntelligenceService,
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
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import RegisterDeviceRequest
from app.modules.identity.application.dtos.response import DeviceRegistrationResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeviceRegistrationMethod,
    DeviceStatus,
    DeviceType,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    TrustLevel,
)
from app.modules.identity.domain.events import DeviceRegistered
from app.modules.identity.domain.exceptions import (
    DeviceAlreadyRegisteredException,
    DeviceLimitExceededError,
    DeviceSecurityViolationError,
    InvalidDeviceDataError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    DeviceFingerprintService,
    DeviceSecurityService,
    GeoLocationService,
    ValidationService,
)


class RegisterDeviceCommand(Command[DeviceRegistrationResponse]):
    """Command to register a new device for a user."""
    
    def __init__(
        self,
        user_id: UUID,
        device_name: str,
        device_type: DeviceType,
        device_fingerprint: str,
        registration_method: DeviceRegistrationMethod = DeviceRegistrationMethod.USER_INITIATED,
        device_os: str | None = None,
        device_os_version: str | None = None,
        device_model: str | None = None,
        device_manufacturer: str | None = None,
        browser_name: str | None = None,
        browser_version: str | None = None,
        user_agent: str | None = None,
        ip_address: str | None = None,
        location_data: dict[str, Any] | None = None,
        hardware_info: dict[str, Any] | None = None,
        software_info: dict[str, Any] | None = None,
        security_features: dict[str, Any] | None = None,
        auto_trust: bool = False,
        require_verification: bool = True,
        set_as_primary: bool = False,
        policy_compliance_required: bool = True,
        device_encryption_required: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.user_id = user_id
        self.device_name = device_name.strip()
        self.device_type = device_type
        self.device_fingerprint = device_fingerprint.strip()
        self.registration_method = registration_method
        self.device_os = device_os
        self.device_os_version = device_os_version
        self.device_model = device_model
        self.device_manufacturer = device_manufacturer
        self.browser_name = browser_name
        self.browser_version = browser_version
        self.user_agent = user_agent
        self.ip_address = ip_address
        self.location_data = location_data or {}
        self.hardware_info = hardware_info or {}
        self.software_info = software_info or {}
        self.security_features = security_features or {}
        self.auto_trust = auto_trust
        self.require_verification = require_verification
        self.set_as_primary = set_as_primary
        self.policy_compliance_required = policy_compliance_required
        self.device_encryption_required = device_encryption_required
        self.metadata = metadata or {}


class RegisterDeviceCommandHandler(CommandHandler[RegisterDeviceCommand, DeviceRegistrationResponse]):
    """Handler for registering devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        device_policy_repository: IDevicePolicyRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        device_fingerprint_service: DeviceFingerprintService,
        geolocation_service: GeoLocationService,
        threat_intelligence_service: IThreatIntelligenceService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._device_policy_repository = device_policy_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._device_fingerprint_service = device_fingerprint_service
        self._geolocation_service = geolocation_service
        self._threat_intelligence_service = threat_intelligence_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_REGISTERED,
        resource_type="device",
        include_request=True,
        include_response=True
    )
    @validate_request(RegisterDeviceRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.register")
    @require_mfa(condition="untrusted_device_registration")
    async def handle(self, command: RegisterDeviceCommand) -> DeviceRegistrationResponse:
        """
        Register device with comprehensive security validation.
        
        Process:
        1. Load user and validate registration
        2. Validate device data and fingerprint
        3. Check for existing device registration
        4. Perform security risk assessment
        5. Check device policy compliance
        6. Create device record
        7. Apply initial trust level
        8. Send verification if required
        9. Notify user of registration
        10. Log security events
        
        Returns:
            DeviceRegistrationResponse with registration details
            
        Raises:
            UserNotFoundError: If user not found
            DeviceAlreadyRegisteredException: If device already registered
            DeviceLimitExceededError: If too many devices
            DeviceSecurityViolationError: If security validation fails
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Validate device data
            await self._validate_device_data(command)
            
            # 3. Check for existing device
            existing_device = await self._device_repository.find_by_fingerprint(
                command.device_fingerprint
            )
            
            if existing_device:
                # Check if same user
                if existing_device.user_id == user.id:
                    raise DeviceAlreadyRegisteredException(
                        f"Device already registered for user: {existing_device.id}"
                    )
                # Device registered to different user - security concern
                await self._log_cross_user_device_attempt(
                    command,
                    existing_device,
                    user
                )
                raise DeviceSecurityViolationError(
                    "Device fingerprint associated with another user"
                )
            
            # 4. Check device limits
            user_devices = await self._device_repository.count_active_by_user(user.id)
            max_devices = await self._get_max_devices_for_user(user)
            
            if user_devices >= max_devices:
                raise DeviceLimitExceededError(
                    f"User has reached maximum device limit: {max_devices}"
                )
            
            # 5. Perform security risk assessment
            security_assessment = await self._assess_device_security_risk(
                command,
                user
            )
            
            # 6. Check policy compliance
            policy_compliance = await self._check_policy_compliance(
                command,
                user,
                security_assessment
            )
            
            # 7. Determine initial trust level
            initial_trust_level = await self._determine_initial_trust_level(
                command,
                user,
                security_assessment,
                policy_compliance
            )
            
            # 8. Enhance location data
            enhanced_location = await self._enhance_location_data(
                command.ip_address,
                command.location_data
            )
            
            # 9. Create device record
            device = Device(
                id=UUID(),
                user_id=user.id,
                device_name=command.device_name,
                device_type=command.device_type,
                device_fingerprint=command.device_fingerprint,
                device_os=command.device_os,
                device_os_version=command.device_os_version,
                device_model=command.device_model,
                device_manufacturer=command.device_manufacturer,
                browser_name=command.browser_name,
                browser_version=command.browser_version,
                user_agent=command.user_agent,
                trust_level=initial_trust_level,
                status=DeviceStatus.PENDING_VERIFICATION if command.require_verification else DeviceStatus.ACTIVE,
                registration_method=command.registration_method,
                registered_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
                ip_address=command.ip_address,
                location_data=enhanced_location,
                hardware_info=command.hardware_info,
                software_info=command.software_info,
                security_features=command.security_features,
                security_assessment=security_assessment,
                policy_compliance=policy_compliance,
                is_primary=command.set_as_primary,
                metadata=command.metadata
            )
            
            await self._device_repository.create(device)
            
            # 10. Handle primary device logic
            if command.set_as_primary:
                await self._handle_primary_device_change(user.id, device.id)
            
            # 11. Apply device policies
            await self._apply_device_policies(device, user)
            
            # 12. Generate verification token if required
            verification_data = None
            if command.require_verification:
                verification_data = await self._generate_device_verification(device)
            
            # 13. Send notifications
            await self._send_device_registration_notifications(
                user,
                device,
                security_assessment,
                verification_data
            )
            
            # 14. Log security events
            if security_assessment["risk_level"] in ["high", "critical"]:
                await self._log_high_risk_device_registration(
                    user,
                    device,
                    security_assessment,
                    command
                )
            
            # 15. Publish domain event
            await self._event_bus.publish(
                DeviceRegistered(
                    aggregate_id=device.id,
                    user_id=user.id,
                    device_type=device.device_type,
                    device_name=device.device_name,
                    trust_level=device.trust_level,
                    registration_method=device.registration_method,
                    requires_verification=command.require_verification,
                    risk_level=security_assessment["risk_level"]
                )
            )
            
            # 16. Commit transaction
            await self._unit_of_work.commit()
            
            # 17. Return response
            return DeviceRegistrationResponse(
                device_id=device.id,
                user_id=user.id,
                device_name=device.device_name,
                device_type=device.device_type,
                device_fingerprint=self._mask_fingerprint(device.device_fingerprint),
                trust_level=device.trust_level,
                status=device.status,
                requires_verification=command.require_verification,
                verification_sent=verification_data is not None,
                verification_method=verification_data.get("method") if verification_data else None,
                verification_expires_at=verification_data.get("expires_at") if verification_data else None,
                is_primary=device.is_primary,
                security_risk_level=security_assessment["risk_level"],
                policy_compliant=policy_compliance["compliant"],
                registered_at=device.registered_at,
                location=enhanced_location.get("city_country") if enhanced_location else None,
                message="Device registered successfully"
            )
    
    async def _validate_device_data(self, command: RegisterDeviceCommand) -> None:
        """Validate device registration data."""
        # Validate device name
        if not command.device_name or len(command.device_name.strip()) < 2:
            raise InvalidDeviceDataError("Device name must be at least 2 characters")
        
        if len(command.device_name) > 100:
            raise InvalidDeviceDataError("Device name too long (max 100 characters)")
        
        # Validate device fingerprint
        if not command.device_fingerprint or len(command.device_fingerprint) < 10:
            raise InvalidDeviceDataError("Invalid device fingerprint")
        
        # Validate fingerprint format
        if not self._device_fingerprint_service.is_valid_fingerprint(command.device_fingerprint):
            raise InvalidDeviceDataError("Device fingerprint format invalid")
        
        # Validate IP address if provided
        if command.ip_address:
            if not self._validation_service.is_valid_ip_address(command.ip_address):
                raise InvalidDeviceDataError("Invalid IP address format")
        
        # Validate user agent
        if command.user_agent and len(command.user_agent) > 1000:
            raise InvalidDeviceDataError("User agent too long (max 1000 characters)")
    
    async def _get_max_devices_for_user(self, user: User) -> int:
        """Get maximum number of devices allowed for user."""
        user_plan = user.metadata.get("subscription_plan", "basic")
        
        max_devices_by_plan = {
            "basic": 5,
            "premium": 15,
            "enterprise": 50
        }
        
        return max_devices_by_plan.get(user_plan, 5)
    
    async def _assess_device_security_risk(
        self,
        command: RegisterDeviceCommand,
        user: User
    ) -> dict[str, Any]:
        """Assess security risk of device registration."""
        risk_factors = []
        risk_score = 0
        
        # Check IP reputation
        if command.ip_address:
            ip_reputation = await self._threat_intelligence_service.check_ip_reputation(
                command.ip_address
            )
            if ip_reputation["is_malicious"]:
                risk_factors.append("malicious_ip")
                risk_score += 50
            elif ip_reputation["is_suspicious"]:
                risk_factors.append("suspicious_ip")
                risk_score += 25
        
        # Check device fingerprint uniqueness
        fingerprint_analysis = await self._device_fingerprint_service.analyze_fingerprint(
            command.device_fingerprint
        )
        if fingerprint_analysis["is_suspicious"]:
            risk_factors.append("suspicious_fingerprint")
            risk_score += 30
        
        # Check for unusual device characteristics
        if command.device_type == DeviceType.UNKNOWN:
            risk_factors.append("unknown_device_type")
            risk_score += 20
        
        # Check for missing security features
        required_security_features = ["screen_lock", "encryption"]
        missing_features = [
            feature for feature in required_security_features
            if not command.security_features.get(feature, False)
        ]
        
        if missing_features:
            risk_factors.extend([f"missing_{feature}" for feature in missing_features])
            risk_score += len(missing_features) * 15
        
        # Check registration timing
        user_last_login = user.last_login_at
        if user_last_login:
            hours_since_login = (datetime.now(UTC) - user_last_login).total_seconds() / 3600
            if hours_since_login > 168:  # More than a week
                risk_factors.append("long_time_since_login")
                risk_score += 10
        
        # Check location consistency
        if command.location_data and user.metadata.get("usual_locations"):
            location_analysis = await self._geolocation_service.analyze_location_consistency(
                command.location_data,
                user.metadata["usual_locations"]
            )
            if not location_analysis["is_consistent"]:
                risk_factors.append("unusual_location")
                risk_score += 20
        
        # Determine risk level
        if risk_score >= 75:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": datetime.now(UTC).isoformat(),
            "recommendation": self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            "low": "Device can be registered with standard verification",
            "medium": "Require additional verification and monitoring",
            "high": "Require MFA verification and manual review",
            "critical": "Block registration and require security team review"
        }
        return recommendations.get(risk_level, "Unknown risk level")
    
    async def _check_policy_compliance(
        self,
        command: RegisterDeviceCommand,
        user: User,
        security_assessment: dict[str, Any]
    ) -> dict[str, Any]:
        """Check device compliance with security policies."""
        # Get applicable policies
        device_policies = await self._device_policy_repository.find_applicable_for_user(
            user.id,
            command.device_type
        )
        
        compliance_results = {
            "compliant": True,
            "violations": [],
            "warnings": [],
            "policies_checked": []
        }
        
        for policy in device_policies:
            policy_result = await self._device_security_service.check_policy_compliance(
                command,
                policy,
                security_assessment
            )
            
            compliance_results["policies_checked"].append(policy.name)
            
            if not policy_result["compliant"]:
                compliance_results["compliant"] = False
                compliance_results["violations"].extend(policy_result["violations"])
            
            if policy_result.get("warnings"):
                compliance_results["warnings"].extend(policy_result["warnings"])
        
        # Check minimum requirements
        if command.device_encryption_required:
            has_encryption = command.security_features.get("encryption", False)
            if not has_encryption:
                compliance_results["compliant"] = False
                compliance_results["violations"].append("device_encryption_required")
        
        return compliance_results
    
    async def _determine_initial_trust_level(
        self,
        command: RegisterDeviceCommand,
        user: User,
        security_assessment: dict[str, Any],
        policy_compliance: dict[str, Any]
    ) -> TrustLevel:
        """Determine initial trust level for device."""
        # Start with default untrusted
        trust_level = TrustLevel.UNTRUSTED
        
        # Check for auto-trust conditions
        if command.auto_trust and security_assessment["risk_level"] == "low":
            if policy_compliance["compliant"]:
                trust_level = TrustLevel.TRUSTED
            else:
                trust_level = TrustLevel.PARTIALLY_TRUSTED
        
        # Override based on risk level
        if security_assessment["risk_level"] in ["high", "critical"]:
            trust_level = TrustLevel.UNTRUSTED
        elif security_assessment["risk_level"] == "medium":
            trust_level = min(trust_level, TrustLevel.PARTIALLY_TRUSTED)
        
        # Consider user's account status
        if user.status in ["SUSPENDED", "LOCKED"]:
            trust_level = TrustLevel.UNTRUSTED
        
        return trust_level
    
    async def _enhance_location_data(
        self,
        ip_address: str | None,
        location_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enhance location data with geolocation services."""
        enhanced_location = location_data.copy()
        
        if ip_address:
            try:
                geo_data = await self._geolocation_service.get_location_from_ip(ip_address)
                enhanced_location.update({
                    "country": geo_data.get("country"),
                    "region": geo_data.get("region"),
                    "city": geo_data.get("city"),
                    "latitude": geo_data.get("latitude"),
                    "longitude": geo_data.get("longitude"),
                    "timezone": geo_data.get("timezone"),
                    "isp": geo_data.get("isp"),
                    "city_country": f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
                })
            except Exception:
                # Fallback if geolocation service fails
                enhanced_location["city_country"] = "Unknown Location"
        
        return enhanced_location
    
    async def _handle_primary_device_change(
        self,
        user_id: UUID,
        new_primary_device_id: UUID
    ) -> None:
        """Handle setting a new primary device."""
        # Unset existing primary device
        current_primary = await self._device_repository.find_primary_by_user(user_id)
        if current_primary:
            current_primary.is_primary = False
            await self._device_repository.update(current_primary)
    
    async def _apply_device_policies(self, device: Device, user: User) -> None:
        """Apply device policies to newly registered device."""
        # Get applicable policies
        policies = await self._device_policy_repository.find_applicable_for_user(
            user.id,
            device.device_type
        )
        
        # Apply each policy
        for policy in policies:
            await self._device_security_service.apply_policy_to_device(
                device.id,
                policy.id
            )
    
    async def _generate_device_verification(self, device: Device) -> dict[str, Any]:
        """Generate device verification if required."""
        verification_code = await self._device_security_service.generate_verification_code(
            device.id
        )
        
        expires_at = datetime.now(UTC) + timedelta(hours=24)
        
        return {
            "method": "code",
            "code": verification_code,
            "expires_at": expires_at,
            "verification_url": f"https://app.example.com/verify-device/{device.id}"
        }
    
    async def _send_device_registration_notifications(
        self,
        user: User,
        device: Device,
        security_assessment: dict[str, Any],
        verification_data: dict[str, Any] | None
    ) -> None:
        """Send notifications about device registration."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_registered",
                    subject="New Device Registered",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "location": device.location_data.get("city_country", "Unknown"),
                        "registration_time": device.registered_at.isoformat(),
                        "requires_verification": verification_data is not None,
                        "verification_code": verification_data.get("code") if verification_data else None,
                        "verification_url": verification_data.get("verification_url") if verification_data else None,
                        "risk_level": security_assessment["risk_level"],
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_REGISTERED,
                channel="in_app",
                template_id="device_registered",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "location": device.location_data.get("city_country", "Unknown"),
                    "requires_verification": verification_data is not None,
                    "risk_level": security_assessment["risk_level"]
                },
                priority="high" if security_assessment["risk_level"] in ["high", "critical"] else "medium"
            )
        )
    
    async def _log_cross_user_device_attempt(
        self,
        command: RegisterDeviceCommand,
        existing_device: Device,
        attempted_user: User
    ) -> None:
        """Log attempt to register device already associated with another user."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.CROSS_USER_DEVICE_REGISTRATION,
                severity=RiskLevel.HIGH,
                user_id=attempted_user.id,
                details={
                    "device_fingerprint": self._mask_fingerprint(command.device_fingerprint),
                    "existing_device_id": str(existing_device.id),
                    "existing_user_id": str(existing_device.user_id),
                    "attempted_user_id": str(attempted_user.id),
                    "device_name": command.device_name,
                    "ip_address": command.ip_address,
                    "user_agent": command.user_agent
                },
                indicators=["cross_user_device_fingerprint"],
                recommended_actions=[
                    "Investigate potential account takeover",
                    "Review existing device registration",
                    "Monitor both user accounts",
                    "Consider device fingerprint collision"
                ]
            )
        )
    
    async def _log_high_risk_device_registration(
        self,
        user: User,
        device: Device,
        security_assessment: dict[str, Any],
        command: RegisterDeviceCommand
    ) -> None:
        """Log high-risk device registration."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_RISK_DEVICE_REGISTRATION,
                severity=RiskLevel.HIGH if security_assessment["risk_level"] == "high" else RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "device_id": str(device.id),
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "risk_score": security_assessment["risk_score"],
                    "risk_factors": security_assessment["risk_factors"],
                    "ip_address": command.ip_address,
                    "location": device.location_data.get("city_country"),
                    "user_agent": command.user_agent
                },
                indicators=security_assessment["risk_factors"],
                recommended_actions=[
                    "Review device registration details",
                    "Verify user identity",
                    "Monitor device activities",
                    "Consider additional verification requirements"
                ]
            )
        )
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]