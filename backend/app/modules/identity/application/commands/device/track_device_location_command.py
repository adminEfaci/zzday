"""
Track device location command implementation.

Handles updating and tracking device location data with privacy and security controls.
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
    ILocationHistoryRepository,
    INotificationService,
    IThreatIntelligenceService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import TrackDeviceLocationRequest
from app.modules.identity.application.dtos.response import (
    DeviceLocationTrackingResponse,
)
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    LocationAccuracy,
    LocationSource,
    LocationTrackingMode,
    NotificationType,
    PrivacyLevel,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import (
    DeviceLocationUpdated,
)
from app.modules.identity.domain.exceptions import (
    DeviceNotFoundError,
    InvalidLocationDataError,
    LocationTrackingDisabledError,
    PrivacyViolationError,
)
from app.modules.identity.domain.services import (
    DeviceSecurityService,
    GeoLocationService,
    PrivacyService,
    ValidationService,
)


class TrackDeviceLocationCommand(Command[DeviceLocationTrackingResponse]):
    """Command to track and update device location."""
    
    def __init__(
        self,
        device_id: UUID,
        location_data: dict[str, Any],
        tracking_mode: LocationTrackingMode = LocationTrackingMode.ON_DEMAND,
        location_source: LocationSource = LocationSource.IP_GEOLOCATION,
        accuracy_level: LocationAccuracy = LocationAccuracy.CITY,
        privacy_level: PrivacyLevel = PrivacyLevel.STANDARD,
        user_consent: bool = False,
        ip_address: str | None = None,
        user_agent: str | None = None,
        timestamp: datetime | None = None,
        store_history: bool = True,
        enable_notifications: bool = True,
        threat_assessment_enabled: bool = True,
        compliance_mode: bool = False,
        retention_days: int = 90,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.location_data = location_data
        self.tracking_mode = tracking_mode
        self.location_source = location_source
        self.accuracy_level = accuracy_level
        self.privacy_level = privacy_level
        self.user_consent = user_consent
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.timestamp = timestamp or datetime.now(UTC)
        self.store_history = store_history
        self.enable_notifications = enable_notifications
        self.threat_assessment_enabled = threat_assessment_enabled
        self.compliance_mode = compliance_mode
        self.retention_days = retention_days
        self.metadata = metadata or {}


class TrackDeviceLocationCommandHandler(CommandHandler[TrackDeviceLocationCommand, DeviceLocationTrackingResponse]):
    """Handler for tracking device locations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        location_history_repository: ILocationHistoryRepository,
        device_policy_repository: IDevicePolicyRepository,
        validation_service: ValidationService,
        geolocation_service: GeoLocationService,
        device_security_service: DeviceSecurityService,
        privacy_service: PrivacyService,
        threat_intelligence_service: IThreatIntelligenceService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._location_history_repository = location_history_repository
        self._device_policy_repository = device_policy_repository
        self._validation_service = validation_service
        self._geolocation_service = geolocation_service
        self._device_security_service = device_security_service
        self._privacy_service = privacy_service
        self._threat_intelligence_service = threat_intelligence_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_LOCATION_TRACKED,
        resource_type="device_location",
        include_request=True,
        include_response=True,
        include_location=True
    )
    @validate_request(TrackDeviceLocationRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='device'
    )
    @require_permission("devices.track_location")
    async def handle(self, command: TrackDeviceLocationCommand) -> DeviceLocationTrackingResponse:
        """
        Track device location with privacy and security controls.
        
        Process:
        1. Load device and validate tracking permissions
        2. Check privacy policies and user consent
        3. Validate and enhance location data
        4. Perform security risk assessment
        5. Apply privacy filtering based on policies
        6. Update device location data
        7. Store location history if enabled
        8. Detect location anomalies
        9. Send notifications if required
        10. Log tracking events
        
        Returns:
            DeviceLocationTrackingResponse with tracking details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If tracking not authorized
            LocationTrackingDisabledError: If tracking disabled
            InvalidLocationDataError: If location data invalid
            PrivacyViolationError: If privacy policies violated
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
            
            # 3. Check location tracking permissions
            await self._validate_location_tracking_permissions(device, user, command)
            
            # 4. Validate location data
            validated_location = await self._validate_and_enhance_location_data(command)
            
            # 5. Check privacy policies and consent
            privacy_check = await self._check_privacy_compliance(
                device,
                user,
                validated_location,
                command
            )
            
            # 6. Apply privacy filtering
            filtered_location = await self._apply_privacy_filtering(
                validated_location,
                privacy_check,
                command
            )
            
            # 7. Perform security risk assessment
            security_assessment = None
            if command.threat_assessment_enabled:
                security_assessment = await self._assess_location_security_risk(
                    device,
                    user,
                    filtered_location,
                    command
                )
            
            # 8. Check for location anomalies
            anomaly_detection = await self._detect_location_anomalies(
                device,
                user,
                filtered_location
            )
            
            # 9. Update device location
            previous_location = device.location_data.copy() if device.location_data else {}
            distance_moved = await self._calculate_distance_moved(
                previous_location,
                filtered_location
            )
            
            device.location_data = filtered_location
            device.location_updated_at = command.timestamp
            device.location_source = command.location_source.value
            device.location_accuracy = command.accuracy_level.value
            device.ip_address = command.ip_address
            
            # Update location tracking metadata
            device.metadata.update({
                "location_tracking": {
                    "last_update": command.timestamp.isoformat(),
                    "tracking_mode": command.tracking_mode.value,
                    "source": command.location_source.value,
                    "accuracy": command.accuracy_level.value,
                    "privacy_level": command.privacy_level.value,
                    "user_consent": command.user_consent,
                    "distance_moved_km": distance_moved,
                    "anomaly_detected": anomaly_detection["anomaly_detected"],
                    "threat_level": security_assessment["risk_level"] if security_assessment else "unknown"
                }
            })
            
            await self._device_repository.update(device)
            
            # 10. Store location history if enabled
            history_record_id = None
            if command.store_history:
                history_record_id = await self._store_location_history(
                    device,
                    user,
                    filtered_location,
                    previous_location,
                    distance_moved,
                    command
                )
            
            # 11. Handle location change notifications
            notifications_sent = []
            if command.enable_notifications and distance_moved > 0:
                notifications_sent = await self._handle_location_change_notifications(
                    device,
                    user,
                    filtered_location,
                    previous_location,
                    distance_moved,
                    anomaly_detection,
                    security_assessment
                )
            
            # 12. Log security events if needed
            if security_assessment and security_assessment["risk_level"] in ["high", "critical"]:
                await self._log_location_security_event(
                    device,
                    user,
                    filtered_location,
                    security_assessment,
                    command
                )
            
            # 13. Publish domain event
            await self._event_bus.publish(
                DeviceLocationUpdated(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    new_location=filtered_location,
                    previous_location=previous_location,
                    distance_moved_km=distance_moved,
                    location_source=command.location_source,
                    tracking_mode=command.tracking_mode,
                    anomaly_detected=anomaly_detection["anomaly_detected"],
                    risk_level=security_assessment["risk_level"] if security_assessment else None
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            # 15. Return response
            return DeviceLocationTrackingResponse(
                device_id=device.id,
                user_id=device.user_id,
                location_data=filtered_location,
                previous_location=previous_location,
                distance_moved_km=distance_moved,
                tracking_mode=command.tracking_mode,
                location_source=command.location_source,
                accuracy_level=command.accuracy_level,
                privacy_level=command.privacy_level,
                user_consent=command.user_consent,
                history_stored=command.store_history,
                history_record_id=history_record_id,
                anomaly_detected=anomaly_detection["anomaly_detected"],
                anomaly_details=anomaly_detection.get("details"),
                security_risk_level=security_assessment["risk_level"] if security_assessment else None,
                notifications_sent=notifications_sent,
                privacy_compliant=privacy_check["compliant"],
                tracked_at=command.timestamp,
                message="Device location tracked successfully"
            )
    
    async def _validate_location_tracking_permissions(
        self,
        device: Device,
        user: User,
        command: TrackDeviceLocationCommand
    ) -> None:
        """Validate location tracking permissions and policies."""
        # Check if location tracking is enabled for user
        user_preferences = user.metadata.get("privacy_preferences", {})
        if not user_preferences.get("location_tracking_enabled", True):
            raise LocationTrackingDisabledError("Location tracking disabled by user")
        
        # Check device-specific tracking settings
        device_settings = device.metadata.get("tracking_settings", {})
        if not device_settings.get("location_tracking_enabled", True):
            raise LocationTrackingDisabledError("Location tracking disabled for device")
        
        # Check if consent is required for the privacy level
        if command.privacy_level == PrivacyLevel.ENHANCED and not command.user_consent:
            raise PrivacyViolationError("User consent required for enhanced privacy level")
        
        # Check compliance mode requirements
        if command.compliance_mode:
            # Additional validation for compliance-driven tracking
            pass
    
    async def _validate_and_enhance_location_data(
        self,
        command: TrackDeviceLocationCommand
    ) -> dict[str, Any]:
        """Validate and enhance location data."""
        location_data = command.location_data.copy()
        
        # Validate required fields based on source
        if command.location_source == LocationSource.GPS:
            required_fields = ["latitude", "longitude"]
            for field in required_fields:
                if field not in location_data:
                    raise InvalidLocationDataError(f"Missing required field: {field}")
        
        # Validate coordinate ranges
        if "latitude" in location_data:
            lat = location_data["latitude"]
            if not isinstance(lat, int | float) or not -90 <= lat <= 90:
                raise InvalidLocationDataError("Invalid latitude value")
        
        if "longitude" in location_data:
            lon = location_data["longitude"]
            if not isinstance(lon, int | float) or not -180 <= lon <= 180:
                raise InvalidLocationDataError("Invalid longitude value")
        
        # Enhance location data based on source
        if command.location_source == LocationSource.IP_GEOLOCATION and command.ip_address:
            try:
                ip_location = await self._geolocation_service.get_location_from_ip(
                    command.ip_address
                )
                location_data.update(ip_location)
            except Exception:
                # Fallback if IP geolocation fails
                pass
        
        # Add metadata
        location_data.update({
            "timestamp": command.timestamp.isoformat(),
            "source": command.location_source.value,
            "accuracy": command.accuracy_level.value,
            "user_agent": command.user_agent
        })
        
        # Enhance with reverse geocoding if coordinates available
        if "latitude" in location_data and "longitude" in location_data:
            try:
                geocode_data = await self._geolocation_service.reverse_geocode(
                    location_data["latitude"],
                    location_data["longitude"]
                )
                location_data.update({
                    "city": geocode_data.get("city"),
                    "region": geocode_data.get("region"),
                    "country": geocode_data.get("country"),
                    "postal_code": geocode_data.get("postal_code"),
                    "city_country": f"{geocode_data.get('city', 'Unknown')}, {geocode_data.get('country', 'Unknown')}"
                })
            except Exception:
                # Fallback if reverse geocoding fails
                location_data["city_country"] = "Unknown Location"
        
        return location_data
    
    async def _check_privacy_compliance(
        self,
        device: Device,
        user: User,
        location_data: dict[str, Any],
        command: TrackDeviceLocationCommand
    ) -> dict[str, Any]:
        """Check privacy compliance for location tracking."""
        # Get applicable privacy policies
        privacy_policies = await self._device_policy_repository.find_privacy_policies_for_user(
            user.id
        )
        
        compliance_result = {
            "compliant": True,
            "violations": [],
            "requirements": [],
            "consent_required": False
        }
        
        # Check each privacy policy
        for policy in privacy_policies:
            policy_result = await self._privacy_service.check_location_policy_compliance(
                location_data,
                policy,
                command
            )
            
            if not policy_result["compliant"]:
                compliance_result["compliant"] = False
                compliance_result["violations"].extend(policy_result["violations"])
            
            if policy_result.get("consent_required"):
                compliance_result["consent_required"] = True
            
            compliance_result["requirements"].extend(policy_result.get("requirements", []))
        
        # Check accuracy level compliance
        if command.accuracy_level == LocationAccuracy.PRECISE:
            if not command.user_consent:
                compliance_result["compliant"] = False
                compliance_result["violations"].append("precise_location_requires_consent")
        
        return compliance_result
    
    async def _apply_privacy_filtering(
        self,
        location_data: dict[str, Any],
        privacy_check: dict[str, Any],
        command: TrackDeviceLocationCommand
    ) -> dict[str, Any]:
        """Apply privacy filtering to location data."""
        filtered_data = location_data.copy()
        
        # Apply accuracy-based filtering
        if command.accuracy_level == LocationAccuracy.COUNTRY:
            # Only keep country-level information
            filtered_data = {
                k: v for k, v in filtered_data.items()
                if k in ["country", "timestamp", "source", "accuracy"]
            }
        
        elif command.accuracy_level == LocationAccuracy.REGION:
            # Keep region-level information
            filtered_data = {
                k: v for k, v in filtered_data.items()
                if k in ["country", "region", "timestamp", "source", "accuracy"]
            }
        
        elif command.accuracy_level == LocationAccuracy.CITY:
            # Keep city-level information
            allowed_fields = [
                "country", "region", "city", "city_country",
                "timestamp", "source", "accuracy"
            ]
            filtered_data = {
                k: v for k, v in filtered_data.items()
                if k in allowed_fields
            }
        
        # Apply privacy level filtering
        if command.privacy_level == PrivacyLevel.ENHANCED:
            # Remove potentially identifying information
            sensitive_fields = ["postal_code", "street_address", "ip_address"]
            for field in sensitive_fields:
                filtered_data.pop(field, None)
        
        elif command.privacy_level == PrivacyLevel.MINIMAL:
            # Only keep essential location information
            essential_fields = ["city", "country", "city_country", "timestamp", "source"]
            filtered_data = {
                k: v for k, v in filtered_data.items()
                if k in essential_fields
            }
        
        return filtered_data
    
    async def _assess_location_security_risk(
        self,
        device: Device,
        user: User,
        location_data: dict[str, Any],
        command: TrackDeviceLocationCommand
    ) -> dict[str, Any]:
        """Assess security risks associated with location data."""
        risk_factors = []
        risk_score = 0
        
        # Check IP reputation if available
        if command.ip_address:
            ip_reputation = await self._threat_intelligence_service.check_ip_reputation(
                command.ip_address
            )
            if ip_reputation["is_malicious"]:
                risk_factors.append("malicious_ip_location")
                risk_score += 50
            elif ip_reputation["is_suspicious"]:
                risk_factors.append("suspicious_ip_location")
                risk_score += 25
        
        # Check for high-risk countries
        if "country" in location_data:
            high_risk_countries = await self._threat_intelligence_service.get_high_risk_countries()
            if location_data["country"] in high_risk_countries:
                risk_factors.append("high_risk_country")
                risk_score += 30
        
        # Check location consistency with user's usual locations
        if user.metadata.get("usual_locations"):
            consistency = await self._geolocation_service.analyze_location_consistency(
                location_data,
                user.metadata["usual_locations"]
            )
            if not consistency["is_consistent"]:
                risk_factors.append("unusual_location")
                risk_score += 20
        
        # Check for rapid location changes
        if device.location_data and "latitude" in device.location_data and "latitude" in location_data:
            distance = await self._calculate_location_distance(
                device.location_data,
                location_data
            )
            time_diff = (command.timestamp - device.location_updated_at).total_seconds() / 3600
            
            if time_diff > 0:
                speed_kmh = distance / time_diff
                if speed_kmh > 1000:  # Faster than commercial aircraft
                    risk_factors.append("impossible_travel_speed")
                    risk_score += 40
                elif speed_kmh > 500:  # Very fast travel
                    risk_factors.append("very_fast_travel")
                    risk_score += 20
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": command.timestamp.isoformat(),
            "recommendations": self._get_location_risk_recommendations(risk_level, risk_factors)
        }
    
    def _get_location_risk_recommendations(
        self,
        risk_level: str,
        risk_factors: list[str]
    ) -> list[str]:
        """Get recommendations based on location risk assessment."""
        recommendations = []
        
        if "malicious_ip_location" in risk_factors:
            recommendations.append("Block device access immediately")
            recommendations.append("Require additional authentication")
        
        if "impossible_travel_speed" in risk_factors:
            recommendations.append("Investigate potential account compromise")
            recommendations.append("Require device re-verification")
        
        if "high_risk_country" in risk_factors:
            recommendations.append("Apply enhanced security policies")
            recommendations.append("Require additional verification")
        
        if risk_level in ["high", "critical"]:
            recommendations.append("Monitor device activity closely")
            recommendations.append("Consider temporarily restricting access")
        
        return recommendations
    
    async def _detect_location_anomalies(
        self,
        device: Device,
        user: User,
        location_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Detect location anomalies and unusual patterns."""
        anomalies = []
        anomaly_score = 0
        
        # Get location history for pattern analysis
        recent_locations = await self._location_history_repository.find_recent_by_device(
            device.id,
            days=30
        )
        
        if recent_locations:
            # Check for unusual time patterns
            current_hour = datetime.now(UTC).hour
            usual_hours = [loc.timestamp.hour for loc in recent_locations]
            
            if usual_hours:
                avg_hour = sum(usual_hours) / len(usual_hours)
                if abs(current_hour - avg_hour) > 6:  # More than 6 hours difference
                    anomalies.append("unusual_time_pattern")
                    anomaly_score += 15
            
            # Check for unusual frequency
            today_locations = [
                loc for loc in recent_locations
                if loc.timestamp.date() == datetime.now(UTC).date()
            ]
            
            if len(today_locations) > 20:  # More than 20 location updates today
                anomalies.append("high_frequency_updates")
                anomaly_score += 10
        
        # Check for location jumping
        if device.location_data and "latitude" in device.location_data:
            distance = await self._calculate_location_distance(
                device.location_data,
                location_data
            )
            
            if distance > 1000:  # More than 1000km
                anomalies.append("large_distance_jump")
                anomaly_score += 25
            elif distance > 500:  # More than 500km
                anomalies.append("significant_distance_jump")
                anomaly_score += 15
        
        return {
            "anomaly_detected": len(anomalies) > 0,
            "anomaly_score": anomaly_score,
            "anomalies": anomalies,
            "details": {
                "detection_timestamp": datetime.now(UTC).isoformat(),
                "anomaly_types": anomalies,
                "confidence": min(anomaly_score / 50.0, 1.0)  # Normalize to 0-1
            }
        }
    
    async def _calculate_distance_moved(
        self,
        previous_location: dict[str, Any],
        current_location: dict[str, Any]
    ) -> float:
        """Calculate distance moved between two locations."""
        if (not previous_location or not current_location or
            "latitude" not in previous_location or "longitude" not in previous_location or
            "latitude" not in current_location or "longitude" not in current_location):
            return 0.0
        
        return await self._calculate_location_distance(previous_location, current_location)
    
    async def _calculate_location_distance(
        self,
        location1: dict[str, Any],
        location2: dict[str, Any]
    ) -> float:
        """Calculate distance between two locations in kilometers."""
        from math import atan2, cos, radians, sin, sqrt
        
        # Haversine formula
        earth_radius_km = 6371  # Earth's radius in km
        
        lat1 = radians(location1["latitude"])
        lon1 = radians(location1["longitude"])
        lat2 = radians(location2["latitude"])
        lon2 = radians(location2["longitude"])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return earth_radius_km * c
    
    async def _store_location_history(
        self,
        device: Device,
        user: User,
        location_data: dict[str, Any],
        previous_location: dict[str, Any],
        distance_moved: float,
        command: TrackDeviceLocationCommand
    ) -> UUID:
        """Store location data in history."""
        history_record = {
            "id": UUID(),
            "device_id": device.id,
            "user_id": user.id,
            "location_data": location_data,
            "previous_location": previous_location,
            "distance_moved_km": distance_moved,
            "tracking_mode": command.tracking_mode.value,
            "location_source": command.location_source.value,
            "accuracy_level": command.accuracy_level.value,
            "privacy_level": command.privacy_level.value,
            "ip_address": command.ip_address,
            "user_agent": command.user_agent,
            "timestamp": command.timestamp,
            "expires_at": command.timestamp + timedelta(days=command.retention_days),
            "metadata": command.metadata
        }
        
        return await self._location_history_repository.create(history_record)
    
    async def _handle_location_change_notifications(
        self,
        device: Device,
        user: User,
        current_location: dict[str, Any],
        previous_location: dict[str, Any],
        distance_moved: float,
        anomaly_detection: dict[str, Any],
        security_assessment: dict[str, Any] | None
    ) -> list[str]:
        """Handle notifications for location changes."""
        notifications_sent = []
        
        # Determine if notification is needed
        should_notify = False
        notification_priority = "low"
        
        # Check distance threshold
        if distance_moved > 100:  # More than 100km
            should_notify = True
            notification_priority = "medium"
        
        # Check for anomalies
        if anomaly_detection["anomaly_detected"]:
            should_notify = True
            notification_priority = "high"
        
        # Check security risk
        if security_assessment and security_assessment["risk_level"] in ["high", "critical"]:
            should_notify = True
            notification_priority = "critical"
        
        if should_notify:
            # In-app notification
            await self._notification_service.create_notification(
                NotificationContext(
                    notification_id=UUID(),
                    recipient_id=user.id,
                    notification_type=NotificationType.DEVICE_LOCATION_CHANGED,
                    channel="in_app",
                    template_id="device_location_changed",
                    template_data={
                        "device_name": device.device_name,
                        "new_location": current_location.get("city_country", "Unknown"),
                        "previous_location": previous_location.get("city_country", "Unknown"),
                        "distance_moved": round(distance_moved, 1),
                        "anomaly_detected": anomaly_detection["anomaly_detected"],
                        "risk_level": security_assessment["risk_level"] if security_assessment else "low"
                    },
                    priority=notification_priority
                )
            )
            notifications_sent.append("in_app")
            
            # Email notification for high-risk situations
            if notification_priority in ["high", "critical"] and user.email_verified:
                await self._email_service.send_email(
                    EmailContext(
                        recipient=user.email,
                        template="device_location_alert",
                        subject="Device Location Alert",
                        variables={
                            "username": user.username,
                            "device_name": device.device_name,
                            "new_location": current_location.get("city_country", "Unknown"),
                            "distance_moved": round(distance_moved, 1),
                            "anomaly_detected": anomaly_detection["anomaly_detected"],
                            "risk_level": security_assessment["risk_level"] if security_assessment else "low",
                            "manage_devices_link": "https://app.example.com/settings/devices"
                        }
                    )
                )
                notifications_sent.append("email")
        
        return notifications_sent
    
    async def _log_location_security_event(
        self,
        device: Device,
        user: User,
        location_data: dict[str, Any],
        security_assessment: dict[str, Any],
        command: TrackDeviceLocationCommand
    ) -> None:
        """Log location-related security events."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_LOCATION_ACCESS,
                severity=RiskLevel.HIGH if security_assessment["risk_level"] == "high" else RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "device_id": str(device.id),
                    "device_name": device.device_name,
                    "location": location_data.get("city_country", "Unknown"),
                    "risk_factors": security_assessment["risk_factors"],
                    "risk_score": security_assessment["risk_score"],
                    "ip_address": command.ip_address,
                    "tracking_source": command.location_source.value
                },
                indicators=security_assessment["risk_factors"],
                recommended_actions=security_assessment["recommendations"]
            )
        )