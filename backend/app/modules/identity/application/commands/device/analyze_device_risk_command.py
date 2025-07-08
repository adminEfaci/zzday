"""
Analyze device risk command implementation.

Handles comprehensive security risk analysis for devices.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IDeviceRepository,
    IEmailService,
    ILocationHistoryRepository,
    INotificationService,
    IRiskAssessmentRepository,
    ISessionRepository,
    ISMSService,
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
    AuditContext,
    EmailContext,
    NotificationContext,
    RiskAnalysisContext,
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import AnalyzeDeviceRiskRequest
from app.modules.identity.application.dtos.response import DeviceRiskAnalysisResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AnalysisDepth,
    AuditAction,
    NotificationType,
    RiskAnalysisType,
    RiskCategory,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import DeviceRiskAnalyzed
from app.modules.identity.domain.exceptions import (
    DeviceNotFoundError,
    InsufficientDataError,
)
from app.modules.identity.domain.services import (
    BehaviorAnalysisService,
    DeviceSecurityService,
    RiskAnalysisService,
    ValidationService,
)


class AnalyzeDeviceRiskCommand(Command[DeviceRiskAnalysisResponse]):
    """Command to perform comprehensive device risk analysis."""
    
    def __init__(
        self,
        device_id: UUID,
        analysis_type: RiskAnalysisType = RiskAnalysisType.COMPREHENSIVE,
        analysis_depth: AnalysisDepth = AnalysisDepth.STANDARD,
        include_historical_data: bool = True,
        include_behavioral_analysis: bool = True,
        include_threat_intelligence: bool = True,
        include_location_analysis: bool = True,
        include_network_analysis: bool = True,
        analysis_period_days: int = 30,
        real_time_assessment: bool = False,
        generate_recommendations: bool = True,
        create_incident_if_high_risk: bool = True,
        notify_on_high_risk: bool = True,
        store_results: bool = True,
        initiated_by: UUID | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.analysis_type = analysis_type
        self.analysis_depth = analysis_depth
        self.include_historical_data = include_historical_data
        self.include_behavioral_analysis = include_behavioral_analysis
        self.include_threat_intelligence = include_threat_intelligence
        self.include_location_analysis = include_location_analysis
        self.include_network_analysis = include_network_analysis
        self.analysis_period_days = analysis_period_days
        self.real_time_assessment = real_time_assessment
        self.generate_recommendations = generate_recommendations
        self.create_incident_if_high_risk = create_incident_if_high_risk
        self.notify_on_high_risk = notify_on_high_risk
        self.store_results = store_results
        self.initiated_by = initiated_by
        self.reason = reason or "Device security risk analysis"
        self.metadata = metadata or {}


class AnalyzeDeviceRiskCommandHandler(CommandHandler[AnalyzeDeviceRiskCommand, DeviceRiskAnalysisResponse]):
    """Handler for analyzing device risk."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        session_repository: ISessionRepository,
        location_history_repository: ILocationHistoryRepository,
        risk_assessment_repository: IRiskAssessmentRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        risk_analysis_service: RiskAnalysisService,
        threat_intelligence_service: IThreatIntelligenceService,
        behavior_analysis_service: BehaviorAnalysisService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._session_repository = session_repository
        self._location_history_repository = location_history_repository
        self._risk_assessment_repository = risk_assessment_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._risk_analysis_service = risk_analysis_service
        self._threat_intelligence_service = threat_intelligence_service
        self._behavior_analysis_service = behavior_analysis_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_RISK_ANALYZED,
        resource_type="device_risk",
        include_request=True,
        include_response=True,
        include_risk_factors=True
    )
    @validate_request(AnalyzeDeviceRiskRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.analyze_risk")
    async def handle(self, command: AnalyzeDeviceRiskCommand) -> DeviceRiskAnalysisResponse:
        """
        Perform comprehensive device risk analysis.
        
        Process:
        1. Load device and validate analysis requirements
        2. Gather historical data and context
        3. Perform security configuration analysis
        4. Conduct behavioral pattern analysis
        5. Analyze threat intelligence indicators
        6. Assess location and network risks
        7. Calculate composite risk score
        8. Generate security recommendations
        9. Create incident if high risk detected
        10. Send notifications for critical risks
        11. Store analysis results
        
        Returns:
            DeviceRiskAnalysisResponse with comprehensive risk assessment
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If analysis not authorized
            RiskAnalysisFailedException: If analysis fails
            InsufficientDataError: If insufficient data for analysis
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
            
            # 3. Gather analysis data
            analysis_data = await self._gather_analysis_data(device, user, command)
            
            # 4. Validate data sufficiency
            await self._validate_data_sufficiency(analysis_data, command)
            
            # 5. Initialize risk analysis context
            analysis_context = RiskAnalysisContext(
                device_id=device.id,
                user_id=user.id,
                analysis_type=command.analysis_type,
                analysis_depth=command.analysis_depth,
                analysis_period_days=command.analysis_period_days,
                initiated_by=command.initiated_by,
                timestamp=datetime.now(UTC)
            )
            
            # 6. Perform device security configuration analysis
            security_analysis = await self._analyze_device_security(
                device,
                user,
                analysis_data,
                analysis_context
            )
            
            # 7. Perform behavioral pattern analysis
            behavioral_analysis = None
            if command.include_behavioral_analysis:
                behavioral_analysis = await self._analyze_behavioral_patterns(
                    device,
                    user,
                    analysis_data,
                    analysis_context
                )
            
            # 8. Perform threat intelligence analysis
            threat_analysis = None
            if command.include_threat_intelligence:
                threat_analysis = await self._analyze_threat_indicators(
                    device,
                    user,
                    analysis_data,
                    analysis_context
                )
            
            # 9. Perform location risk analysis
            location_analysis = None
            if command.include_location_analysis:
                location_analysis = await self._analyze_location_risks(
                    device,
                    user,
                    analysis_data,
                    analysis_context
                )
            
            # 10. Perform network risk analysis
            network_analysis = None
            if command.include_network_analysis:
                network_analysis = await self._analyze_network_risks(
                    device,
                    user,
                    analysis_data,
                    analysis_context
                )
            
            # 11. Calculate composite risk assessment
            composite_risk = await self._calculate_composite_risk(
                security_analysis,
                behavioral_analysis,
                threat_analysis,
                location_analysis,
                network_analysis
            )
            
            # 12. Generate security recommendations
            recommendations = []
            if command.generate_recommendations:
                recommendations = await self._generate_security_recommendations(
                    composite_risk,
                    security_analysis,
                    behavioral_analysis,
                    threat_analysis,
                    location_analysis,
                    network_analysis
                )
            
            # 13. Create comprehensive analysis result
            analysis_result = {
                "analysis_id": UUID(),
                "device_id": device.id,
                "user_id": user.id,
                "analysis_type": command.analysis_type.value,
                "analysis_depth": command.analysis_depth.value,
                "overall_risk_level": composite_risk["risk_level"],
                "overall_risk_score": composite_risk["risk_score"],
                "risk_categories": composite_risk["risk_categories"],
                "security_analysis": security_analysis,
                "behavioral_analysis": behavioral_analysis,
                "threat_analysis": threat_analysis,
                "location_analysis": location_analysis,
                "network_analysis": network_analysis,
                "composite_risk": composite_risk,
                "recommendations": recommendations,
                "analysis_metadata": {
                    "analysis_duration_ms": (datetime.now(UTC) - analysis_context.timestamp).total_seconds() * 1000,
                    "data_points_analyzed": self._count_data_points(analysis_data),
                    "analysis_confidence": composite_risk.get("confidence", 0.8),
                    "next_analysis_recommended": datetime.now(UTC) + timedelta(days=7)
                },
                "analyzed_at": analysis_context.timestamp,
                "analyzed_by": command.initiated_by
            }
            
            # 14. Store analysis results if requested
            if command.store_results:
                await self._risk_assessment_repository.create(analysis_result)
            
            # 15. Create security incident if high risk
            incident_created = False
            if (command.create_incident_if_high_risk and 
                composite_risk["risk_level"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]):
                await self._create_high_risk_incident(
                    device,
                    user,
                    analysis_result,
                    command
                )
                incident_created = True
            
            # 16. Send notifications for critical risks
            notifications_sent = []
            if (command.notify_on_high_risk and 
                composite_risk["risk_level"] == RiskLevel.CRITICAL):
                notifications_sent = await self._send_critical_risk_notifications(
                    device,
                    user,
                    analysis_result,
                    command
                )
            
            # 17. Update device risk metadata
            device.metadata.update({
                "risk_analysis": {
                    "last_analysis": analysis_context.timestamp.isoformat(),
                    "risk_level": composite_risk["risk_level"].value,
                    "risk_score": composite_risk["risk_score"],
                    "high_risk_factors": composite_risk.get("high_risk_factors", []),
                    "next_analysis_due": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
                    "analysis_count": device.metadata.get("risk_analysis", {}).get("analysis_count", 0) + 1
                }
            })
            
            await self._device_repository.update(device)
            
            # 18. Log analysis operation
            await self._log_risk_analysis_operation(
                device,
                user,
                analysis_result,
                command
            )
            
            # 19. Publish domain event
            await self._event_bus.publish(
                DeviceRiskAnalyzed(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    device_name=device.device_name,
                    analysis_type=command.analysis_type,
                    risk_level=composite_risk["risk_level"],
                    risk_score=composite_risk["risk_score"],
                    high_risk_factors=composite_risk.get("high_risk_factors", []),
                    incident_created=incident_created,
                    analyzed_by=command.initiated_by
                )
            )
            
            # 20. Commit transaction
            await self._unit_of_work.commit()
            
            # 21. Return response
            return DeviceRiskAnalysisResponse(
                analysis_id=analysis_result["analysis_id"],
                device_id=device.id,
                user_id=device.user_id,
                analysis_type=command.analysis_type,
                analysis_depth=command.analysis_depth,
                overall_risk_level=composite_risk["risk_level"],
                overall_risk_score=composite_risk["risk_score"],
                risk_categories=composite_risk["risk_categories"],
                high_risk_factors=composite_risk.get("high_risk_factors", []),
                security_score=security_analysis.get("security_score", 0),
                behavioral_score=behavioral_analysis.get("behavioral_score", 0) if behavioral_analysis else None,
                threat_score=threat_analysis.get("threat_score", 0) if threat_analysis else None,
                location_score=location_analysis.get("location_score", 0) if location_analysis else None,
                network_score=network_analysis.get("network_score", 0) if network_analysis else None,
                recommendations=recommendations,
                incident_created=incident_created,
                notifications_sent=notifications_sent,
                analysis_confidence=composite_risk.get("confidence", 0.8),
                data_points_analyzed=self._count_data_points(analysis_data),
                next_analysis_recommended=datetime.now(UTC) + timedelta(days=7),
                analyzed_at=analysis_context.timestamp,
                analyzed_by=command.initiated_by,
                message="Device risk analysis completed successfully"
            )
    
    async def _gather_analysis_data(
        self,
        device: Device,
        user: User,
        command: AnalyzeDeviceRiskCommand
    ) -> dict[str, Any]:
        """Gather all data needed for risk analysis."""
        analysis_start_date = datetime.now(UTC) - timedelta(days=command.analysis_period_days)
        
        data = {
            "device": device,
            "user": user,
            "analysis_period_start": analysis_start_date
        }
        
        # Gather historical data if requested
        if command.include_historical_data:
            data["sessions"] = await self._session_repository.find_by_device_since(
                device.id,
                analysis_start_date
            )
            
            if command.include_location_analysis:
                data["location_history"] = await self._location_history_repository.find_by_device_since(
                    device.id,
                    analysis_start_date
                )
            
            # Get previous risk assessments for trend analysis
            data["previous_assessments"] = await self._risk_assessment_repository.find_by_device_since(
                device.id,
                analysis_start_date
            )
        
        return data
    
    async def _validate_data_sufficiency(
        self,
        analysis_data: dict[str, Any],
        command: AnalyzeDeviceRiskCommand
    ) -> None:
        """Validate that sufficient data exists for analysis."""
        if command.analysis_depth == AnalysisDepth.DEEP:
            # Deep analysis requires more data
            if command.include_historical_data:
                sessions = analysis_data.get("sessions", [])
                if len(sessions) < 5:
                    raise InsufficientDataError(
                        "Deep analysis requires at least 5 historical sessions"
                    )
        
        if command.include_behavioral_analysis:
            # Behavioral analysis requires session history
            sessions = analysis_data.get("sessions", [])
            if len(sessions) < 3:
                raise InsufficientDataError(
                    "Behavioral analysis requires at least 3 historical sessions"
                )
    
    async def _analyze_device_security(
        self,
        device: Device,
        user: User,
        analysis_data: dict[str, Any],
        context: RiskAnalysisContext
    ) -> dict[str, Any]:
        """Analyze device security configuration and posture."""
        security_factors = []
        security_score = 100  # Start with perfect score and deduct for issues
        
        # Analyze device security features
        security_features = device.security_features or {}
        
        # Check for missing critical security features
        critical_features = ["screen_lock", "encryption", "remote_wipe"]
        for feature in critical_features:
            if not security_features.get(feature, False):
                security_factors.append(f"missing_{feature}")
                security_score -= 20
        
        # Check device OS and version security
        if device.device_os and device.device_os_version:
            os_security = await self._device_security_service.assess_os_security(
                device.device_os,
                device.device_os_version
            )
            security_score = min(security_score, security_score * (os_security / 100))
            
            if os_security < 70:
                security_factors.append("outdated_os")
        
        # Check trust level
        if device.trust_level.value in ["untrusted", "partially_trusted"]:
            security_factors.append(f"low_trust_level_{device.trust_level.value}")
            security_score -= 15
        
        # Check device status
        if device.status.value != "active":
            security_factors.append(f"inactive_status_{device.status.value}")
            security_score -= 10
        
        # Check if device is rooted/jailbroken
        if device.hardware_info.get("is_rooted", False) or device.hardware_info.get("is_jailbroken", False):
            security_factors.append("device_compromised")
            security_score -= 40
        
        # Analyze recent security events
        if "sessions" in analysis_data:
            failed_logins = sum(
                1 for session in analysis_data["sessions"]
                if session.status in ("failed", "expired")
            )
            if failed_logins > 5:
                security_factors.append("high_failed_login_attempts")
                security_score -= 10
        
        return {
            "security_score": max(security_score, 0),
            "security_factors": security_factors,
            "critical_issues": [f for f in security_factors if "missing_" in f or "compromised" in f],
            "os_security_score": os_security if 'os_security' in locals() else None,
            "trust_level": device.trust_level.value,
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _analyze_behavioral_patterns(
        self,
        device: Device,
        user: User,
        analysis_data: dict[str, Any],
        context: RiskAnalysisContext
    ) -> dict[str, Any]:
        """Analyze user behavior patterns for anomalies."""
        if "sessions" not in analysis_data:
            return {"behavioral_score": 0, "insufficient_data": True}
        
        sessions = analysis_data["sessions"]
        behavioral_anomalies = []
        behavioral_score = 100
        
        # Analyze login time patterns
        login_hours = [session.created_at.hour for session in sessions]
        if login_hours:
            unusual_hours = await self._behavior_analysis_service.detect_unusual_login_times(
                login_hours
            )
            if unusual_hours:
                behavioral_anomalies.append("unusual_login_times")
                behavioral_score -= 15
        
        # Analyze session duration patterns
        session_durations = [
            (session.last_activity - session.created_at).total_seconds() / 3600
            for session in sessions
            if session.last_activity
        ]
        
        if session_durations:
            avg_duration = sum(session_durations) / len(session_durations)
            if avg_duration > 12:  # Very long sessions
                behavioral_anomalies.append("unusually_long_sessions")
                behavioral_score -= 10
            elif avg_duration < 0.1:  # Very short sessions
                behavioral_anomalies.append("unusually_short_sessions")
                behavioral_score -= 10
        
        # Analyze session frequency
        recent_sessions = [
            session for session in sessions
            if (datetime.now(UTC) - session.created_at).days <= 7
        ]
        
        if len(recent_sessions) > 50:  # More than 50 sessions in a week
            behavioral_anomalies.append("high_session_frequency")
            behavioral_score -= 15
        elif len(recent_sessions) == 0 and len(sessions) > 0:
            behavioral_anomalies.append("no_recent_activity")
            behavioral_score -= 5
        
        # Analyze IP address patterns
        unique_ips = {session.ip_address for session in sessions if session.ip_address}
        if len(unique_ips) > 10:  # Too many different IPs
            behavioral_anomalies.append("multiple_ip_addresses")
            behavioral_score -= 20
        
        return {
            "behavioral_score": max(behavioral_score, 0),
            "behavioral_anomalies": behavioral_anomalies,
            "session_patterns": {
                "avg_session_duration_hours": sum(session_durations) / len(session_durations) if session_durations else 0,
                "unique_login_hours": len(set(login_hours)),
                "unique_ip_addresses": len(unique_ips),
                "recent_session_count": len(recent_sessions)
            },
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _analyze_threat_indicators(
        self,
        device: Device,
        user: User,
        analysis_data: dict[str, Any],
        context: RiskAnalysisContext
    ) -> dict[str, Any]:
        """Analyze threat intelligence indicators."""
        threat_indicators = []
        threat_score = 0
        
        # Check IP reputation for recent sessions
        if "sessions" in analysis_data:
            for session in analysis_data["sessions"]:
                if session.ip_address:
                    ip_reputation = await self._threat_intelligence_service.check_ip_reputation(
                        session.ip_address
                    )
                    
                    if ip_reputation["is_malicious"]:
                        threat_indicators.append(f"malicious_ip_{session.ip_address}")
                        threat_score += 50
                    elif ip_reputation["is_suspicious"]:
                        threat_indicators.append(f"suspicious_ip_{session.ip_address}")
                        threat_score += 25
        
        # Check device fingerprint against known threats
        fingerprint_threats = await self._threat_intelligence_service.check_device_fingerprint_threats(
            device.device_fingerprint
        )
        
        if fingerprint_threats:
            threat_indicators.extend(fingerprint_threats)
            threat_score += len(fingerprint_threats) * 30
        
        # Check for known malware signatures
        if device.software_info:
            malware_indicators = await self._threat_intelligence_service.check_malware_indicators(
                device.software_info
            )
            
            if malware_indicators:
                threat_indicators.extend(malware_indicators)
                threat_score += len(malware_indicators) * 40
        
        return {
            "threat_score": min(threat_score, 100),
            "threat_indicators": threat_indicators,
            "high_severity_threats": [
                indicator for indicator in threat_indicators
                if "malicious" in indicator or "malware" in indicator
            ],
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _analyze_location_risks(
        self,
        device: Device,
        user: User,
        analysis_data: dict[str, Any],
        context: RiskAnalysisContext
    ) -> dict[str, Any]:
        """Analyze location-based security risks."""
        location_risks = []
        location_score = 0
        
        # Check current location risk
        if device.location_data:
            country = device.location_data.get("country")
            if country:
                high_risk_countries = await self._threat_intelligence_service.get_high_risk_countries()
                if country in high_risk_countries:
                    location_risks.append(f"high_risk_country_{country}")
                    location_score += 30
        
        # Analyze location history patterns
        if "location_history" in analysis_data:
            location_history = analysis_data["location_history"]
            
            # Check for impossible travel
            for i in range(1, len(location_history)):
                prev_location = location_history[i-1]
                curr_location = location_history[i]
                
                if (prev_location.location_data.get("latitude") and 
                    curr_location.location_data.get("latitude")):
                    
                    distance = await self._calculate_distance(
                        prev_location.location_data,
                        curr_location.location_data
                    )
                    
                    time_diff = (curr_location.timestamp - prev_location.timestamp).total_seconds() / 3600
                    
                    if time_diff > 0:
                        speed = distance / time_diff
                        if speed > 1000:  # Faster than commercial aircraft
                            location_risks.append("impossible_travel_detected")
                            location_score += 40
                            break
        
        return {
            "location_score": min(location_score, 100),
            "location_risks": location_risks,
            "current_location_risk": "high" if any("high_risk_country" in risk for risk in location_risks) else "low",
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _analyze_network_risks(
        self,
        device: Device,
        user: User,
        analysis_data: dict[str, Any],
        context: RiskAnalysisContext
    ) -> dict[str, Any]:
        """Analyze network-based security risks."""
        network_risks = []
        network_score = 0
        
        # Analyze IP address patterns from sessions
        if "sessions" in analysis_data:
            ip_addresses = [session.ip_address for session in analysis_data["sessions"] if session.ip_address]
            unique_ips = set(ip_addresses)
            
            # Too many different IP addresses
            if len(unique_ips) > 15:
                network_risks.append("excessive_ip_variation")
                network_score += 20
            
            # Check for VPN/Proxy usage patterns
            vpn_indicators = 0
            for ip in unique_ips:
                vpn_check = await self._threat_intelligence_service.check_vpn_proxy(ip)
                if vpn_check["is_vpn"] or vpn_check["is_proxy"]:
                    vpn_indicators += 1
            
            if vpn_indicators > len(unique_ips) * 0.5:  # More than 50% VPN/Proxy
                network_risks.append("high_vpn_proxy_usage")
                network_score += 15
        
        return {
            "network_score": min(network_score, 100),
            "network_risks": network_risks,
            "unique_ip_count": len(unique_ips) if 'unique_ips' in locals() else 0,
            "vpn_proxy_ratio": vpn_indicators / len(unique_ips) if 'unique_ips' in locals() and unique_ips else 0,
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _calculate_composite_risk(
        self,
        security_analysis: dict[str, Any],
        behavioral_analysis: dict[str, Any] | None,
        threat_analysis: dict[str, Any] | None,
        location_analysis: dict[str, Any] | None,
        network_analysis: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Calculate composite risk score and level."""
        # Weight factors for different analysis types
        weights = {
            "security": 0.3,
            "behavioral": 0.2,
            "threat": 0.25,
            "location": 0.15,
            "network": 0.1
        }
        
        # Calculate weighted risk score
        total_risk_score = 0
        total_weight = 0
        
        # Security analysis (inverted - lower security score = higher risk)
        security_risk = 100 - security_analysis["security_score"]
        total_risk_score += security_risk * weights["security"]
        total_weight += weights["security"]
        
        # Behavioral analysis
        if behavioral_analysis and not behavioral_analysis.get("insufficient_data"):
            behavioral_risk = 100 - behavioral_analysis["behavioral_score"]
            total_risk_score += behavioral_risk * weights["behavioral"]
            total_weight += weights["behavioral"]
        
        # Threat analysis
        if threat_analysis:
            total_risk_score += threat_analysis["threat_score"] * weights["threat"]
            total_weight += weights["threat"]
        
        # Location analysis
        if location_analysis:
            total_risk_score += location_analysis["location_score"] * weights["location"]
            total_weight += weights["location"]
        
        # Network analysis
        if network_analysis:
            total_risk_score += network_analysis["network_score"] * weights["network"]
            total_weight += weights["network"]
        
        # Normalize by actual weights used
        composite_score = total_risk_score / total_weight if total_weight > 0 else 0
        
        # Determine risk level
        if composite_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif composite_score >= 60:
            risk_level = RiskLevel.HIGH
        elif composite_score >= 40:
            risk_level = RiskLevel.MEDIUM
        elif composite_score >= 20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.MINIMAL
        
        # Identify high-risk factors
        high_risk_factors = []
        if security_analysis.get("critical_issues"):
            high_risk_factors.extend(security_analysis["critical_issues"])
        if threat_analysis and threat_analysis.get("high_severity_threats"):
            high_risk_factors.extend(threat_analysis["high_severity_threats"])
        if location_analysis and "high_risk_country" in str(location_analysis.get("location_risks", [])):
            high_risk_factors.append("high_risk_location")
        
        # Categorize risks
        risk_categories = {
            RiskCategory.DEVICE_SECURITY: security_risk,
            RiskCategory.USER_BEHAVIOR: 100 - behavioral_analysis["behavioral_score"] if behavioral_analysis else 0,
            RiskCategory.THREAT_INTELLIGENCE: threat_analysis["threat_score"] if threat_analysis else 0,
            RiskCategory.LOCATION: location_analysis["location_score"] if location_analysis else 0,
            RiskCategory.NETWORK: network_analysis["network_score"] if network_analysis else 0
        }
        
        return {
            "risk_score": round(composite_score, 2),
            "risk_level": risk_level,
            "risk_categories": {cat.value: score for cat, score in risk_categories.items()},
            "high_risk_factors": high_risk_factors,
            "confidence": total_weight / sum(weights.values()),  # How much of the analysis was completed
            "analysis_completeness": {
                "security_analyzed": True,
                "behavioral_analyzed": behavioral_analysis is not None,
                "threat_analyzed": threat_analysis is not None,
                "location_analyzed": location_analysis is not None,
                "network_analyzed": network_analysis is not None
            }
        }
    
    async def _generate_security_recommendations(
        self,
        composite_risk: dict[str, Any],
        security_analysis: dict[str, Any],
        behavioral_analysis: dict[str, Any] | None,
        threat_analysis: dict[str, Any] | None,
        location_analysis: dict[str, Any] | None,
        network_analysis: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Security-based recommendations
        if security_analysis.get("critical_issues"):
            for issue in security_analysis["critical_issues"]:
                if "missing_" in issue:
                    feature = issue.replace("missing_", "")
                    recommendations.append({
                        "category": "device_security",
                        "priority": "high",
                        "recommendation": f"Enable {feature} on the device",
                        "description": f"Device is missing critical security feature: {feature}",
                        "implementation": f"Configure {feature} in device settings"
                    })
        
        # Threat-based recommendations
        if threat_analysis and threat_analysis.get("high_severity_threats"):
            recommendations.append({
                "category": "threat_mitigation",
                "priority": "critical",
                "recommendation": "Immediate threat response required",
                "description": "High-severity threats detected on device",
                "implementation": "Run security scan and consider device quarantine"
            })
        
        # Behavioral recommendations
        if behavioral_analysis and behavioral_analysis.get("behavioral_anomalies"):
            if "high_session_frequency" in behavioral_analysis["behavioral_anomalies"]:
                recommendations.append({
                    "category": "access_control",
                    "priority": "medium",
                    "recommendation": "Review session management policies",
                    "description": "Unusually high session frequency detected",
                    "implementation": "Implement session timeout and concurrent session limits"
                })
        
        # Location-based recommendations
        if location_analysis and location_analysis.get("location_risks"):
            if any("high_risk_country" in risk for risk in location_analysis["location_risks"]):
                recommendations.append({
                    "category": "access_restriction",
                    "priority": "high",
                    "recommendation": "Implement location-based access controls",
                    "description": "Device accessing from high-risk location",
                    "implementation": "Enable geo-blocking or require additional verification"
                })
        
        # Overall risk recommendations
        if composite_risk["risk_level"] == RiskLevel.CRITICAL:
            recommendations.append({
                "category": "risk_mitigation",
                "priority": "critical",
                "recommendation": "Consider immediate device quarantine",
                "description": "Device poses critical security risk",
                "implementation": "Temporarily restrict device access pending security review"
            })
        
        return recommendations
    
    async def _create_high_risk_incident(
        self,
        device: Device,
        user: User,
        analysis_result: dict[str, Any],
        command: AnalyzeDeviceRiskCommand
    ) -> None:
        """Create security incident for high-risk devices."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_RISK_DEVICE_DETECTED,
                severity=RiskLevel.HIGH if analysis_result["overall_risk_level"] == RiskLevel.HIGH else RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "device_id": str(device.id),
                    "device_name": device.device_name,
                    "risk_score": analysis_result["overall_risk_score"],
                    "risk_level": analysis_result["overall_risk_level"].value,
                    "high_risk_factors": analysis_result["composite_risk"]["high_risk_factors"],
                    "analysis_id": str(analysis_result["analysis_id"]),
                    "analysis_type": command.analysis_type.value
                },
                indicators=analysis_result["composite_risk"]["high_risk_factors"],
                recommended_actions=[rec["recommendation"] for rec in analysis_result["recommendations"]]
            )
        )
    
    async def _send_critical_risk_notifications(
        self,
        device: Device,
        user: User,
        analysis_result: dict[str, Any],
        command: AnalyzeDeviceRiskCommand
    ) -> list[str]:
        """Send notifications for critical risk levels."""
        notifications_sent = []
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.CRITICAL_DEVICE_RISK,
                channel="in_app",
                template_id="critical_device_risk",
                template_data={
                    "device_name": device.device_name,
                    "risk_score": analysis_result["overall_risk_score"],
                    "high_risk_factors": analysis_result["composite_risk"]["high_risk_factors"],
                    "recommendations_count": len(analysis_result["recommendations"])
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
                    template="critical_device_risk_alert",
                    subject="Critical Security Risk Detected",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "risk_score": analysis_result["overall_risk_score"],
                        "high_risk_factors": analysis_result["composite_risk"]["high_risk_factors"],
                        "immediate_actions": [
                            rec["recommendation"] for rec in analysis_result["recommendations"]
                            if rec["priority"] == "critical"
                        ],
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
            notifications_sent.append("email")
        
        # SMS notification for critical risks
        if user.phone_verified:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=user.phone_number,
                    template="critical_device_risk_sms",
                    variables={
                        "device_name": device.device_name,
                        "risk_score": analysis_result["overall_risk_score"]
                    }
                )
            )
            notifications_sent.append("sms")
        
        return notifications_sent
    
    def _count_data_points(self, analysis_data: dict[str, Any]) -> int:
        """Count total data points analyzed."""
        count = 1  # Device itself
        count += len(analysis_data.get("sessions", []))
        count += len(analysis_data.get("location_history", []))
        count += len(analysis_data.get("previous_assessments", []))
        return count
    
    async def _calculate_distance(
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
    
    async def _log_risk_analysis_operation(
        self,
        device: Device,
        user: User,
        analysis_result: dict[str, Any],
        command: AnalyzeDeviceRiskCommand
    ) -> None:
        """Log risk analysis operation for audit."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_RISK_ANALYZED,
                actor_id=command.initiated_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "analysis_id": str(analysis_result["analysis_id"]),
                    "device_name": device.device_name,
                    "analysis_type": command.analysis_type.value,
                    "analysis_depth": command.analysis_depth.value,
                    "risk_level": analysis_result["overall_risk_level"].value,
                    "risk_score": analysis_result["overall_risk_score"],
                    "high_risk_factors": analysis_result["composite_risk"]["high_risk_factors"],
                    "recommendations_generated": len(analysis_result["recommendations"]),
                    "data_points_analyzed": analysis_result["analysis_metadata"]["data_points_analyzed"]
                },
                risk_level="medium"
            )
        )