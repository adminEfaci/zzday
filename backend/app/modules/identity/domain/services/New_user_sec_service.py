"""
User Security Domain Service

Handles risk assessment and security decisions for user authentication.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.modules.identity.domain.entities.user.login_attempt import LoginAttempt
from app.modules.identity.domain.value_objects import AuthorizationContext, RiskAssessment
from app.modules.identity.domain.enums import RiskLevel
from app.modules.identity.domain.entities.user.user_constants import SecurityThresholds, BehavioralLimits, LocationRisk, DeviceRisk


class UserSecurityService:
    """Domain service for user security operations."""
    
    def assess_login_risk(
        self,
        attempt: LoginAttempt,
        user_history: dict[str, Any],
        device_history: dict[str, Any]
    ) -> RiskAssessment:
        """Assess risk for a login attempt."""
        factors = {}
        risk_score = 0.0
        
        # Analyze IP/location risk
        if attempt.auth_context and attempt.auth_context.ip_address:
            location_risk = self._assess_location_risk(attempt.auth_context, user_history)
            factors["location"] = location_risk
            risk_score += location_risk * SecurityThresholds.LOCATION_WEIGHT
            
        # Analyze device trust
        device_risk = self._assess_device_risk(attempt.auth_context, device_history)
        factors["device"] = device_risk
        risk_score += device_risk * SecurityThresholds.DEVICE_WEIGHT
        
        # Analyze behavioral patterns
        behavioral_risk = self._assess_behavioral_risk(attempt, user_history)
        factors["behavioral"] = behavioral_risk
        risk_score += behavioral_risk * SecurityThresholds.BEHAVIORAL_WEIGHT
        
        # Check for attack patterns
        attack_risk = self._detect_attack_patterns(attempt, user_history)
        factors["attack_patterns"] = attack_risk
        risk_score += attack_risk * SecurityThresholds.ATTACK_WEIGHT
        
        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score)
        
        return RiskAssessment(
            level=risk_level,
            score=min(risk_score, 1.0),
            factors=factors
        )
    
    def get_security_recommendation(self, risk_assessment: RiskAssessment) -> str:
        """Get security action recommendation based on risk."""
        if risk_assessment.score >= SecurityThresholds.BLOCK_THRESHOLD:
            return "block_and_investigate"
        if risk_assessment.score >= SecurityThresholds.ADDITIONAL_VERIFICATION_THRESHOLD:
            return "require_additional_verification"
        if risk_assessment.score >= SecurityThresholds.MFA_REQUIRED_THRESHOLD:
            return "require_mfa"
        if risk_assessment.score >= SecurityThresholds.MONITOR_THRESHOLD:
            return "monitor_closely"
        return "allow"
    
    def is_suspicious_attempt(self, risk_assessment: RiskAssessment) -> bool:
        """Check if attempt is suspicious."""
        return (
            risk_assessment.score > SecurityThresholds.SUSPICIOUS_THRESHOLD or
            risk_assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )
    
    def _assess_location_risk(self, auth_context: AuthorizationContext, history: dict) -> float:
        """Assess location-based risk."""
        if not auth_context or not auth_context.ip_address:
            return LocationRisk.UNKNOWN_LOCATION
        
        # Check against known locations
        known_locations = history.get("known_locations", [])
        if auth_context.location_country in known_locations:
            return LocationRisk.KNOWN_LOCATION
        
        # Check high-risk countries
        high_risk_countries = {"CN", "RU", "KP", "IR"}  # Example list
        if auth_context.location_country in high_risk_countries:
            return LocationRisk.HIGH_RISK_COUNTRY
        
        return LocationRisk.NEW_LOCATION
    
    def _assess_device_risk(self, auth_context: AuthorizationContext, history: dict) -> float:
        """Assess device-based risk."""
        if not auth_context or not auth_context.device_id:
            return DeviceRisk.UNKNOWN_DEVICE
        
        if auth_context.device_trusted:
            return DeviceRisk.TRUSTED_DEVICE
        
        known_devices = history.get("known_devices", [])
        if auth_context.device_id in known_devices:
            return DeviceRisk.KNOWN_DEVICE
        
        return DeviceRisk.NEW_DEVICE
    
    def _assess_behavioral_risk(self, attempt: LoginAttempt, history: dict) -> float:
        """Assess behavioral risk patterns."""
        risk = 0.0
        
        # High velocity logins
        if attempt.login_velocity > BehavioralLimits.HIGH_VELOCITY_THRESHOLD:
            risk += BehavioralLimits.HIGH_VELOCITY_PENALTY
        
        # Multiple recent failures
        if attempt.failed_attempts_24h > BehavioralLimits.MULTIPLE_FAILURES_THRESHOLD:
            risk += BehavioralLimits.MULTIPLE_FAILURES_PENALTY
        
        # Unusual time patterns
        current_hour = attempt.timestamp.hour
        usual_hours = history.get("usual_login_hours", [])
        if usual_hours and current_hour not in usual_hours:
            risk += BehavioralLimits.UNUSUAL_TIME_PENALTY
        
        return min(risk, 1.0)
    
    def _detect_attack_patterns(self, attempt: LoginAttempt, history: dict) -> float:
        """Detect attack patterns."""
        risk = 0.0
        
        # Credential stuffing indicators
        if attempt.failed_attempts_24h > BehavioralLimits.CREDENTIAL_STUFFING_THRESHOLD:
            risk += BehavioralLimits.CREDENTIAL_STUFFING_PENALTY
        
        # Brute force indicators
        recent_failures = history.get("recent_failure_count", 0)
        if recent_failures > BehavioralLimits.BRUTE_FORCE_THRESHOLD:
            risk += BehavioralLimits.BRUTE_FORCE_PENALTY
        
        # Bot-like behavior
        if attempt.auth_context:
            user_agent = getattr(attempt.auth_context, "user_agent", "")
            if any(bot in user_agent.lower() for bot in BehavioralLimits.BOT_INDICATORS):
                risk += BehavioralLimits.BOT_PENALTY
        
        return min(risk, 1.0)
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if score >= SecurityThresholds.CRITICAL_RISK_SCORE:
            return RiskLevel.CRITICAL
        if score >= SecurityThresholds.HIGH_RISK_SCORE:
            return RiskLevel.HIGH
        if score >= SecurityThresholds.MEDIUM_RISK_SCORE:
            return RiskLevel.MEDIUM
        if score >= SecurityThresholds.LOW_RISK_SCORE:
            return RiskLevel.LOW
        return RiskLevel.MINIMAL