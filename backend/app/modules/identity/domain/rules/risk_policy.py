"""
Risk Assessment Policy

Business rules for risk assessment and fraud detection.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .base import BusinessRule, PolicyViolation


class RiskFactor(Enum):
    """Risk factors to consider."""
    NEW_DEVICE = "new_device"
    NEW_LOCATION = "new_location"
    UNUSUAL_TIME = "unusual_time"
    RAPID_LOCATION_CHANGE = "rapid_location_change"
    HIGH_RISK_COUNTRY = "high_risk_country"
    VPN_DETECTED = "vpn_detected"
    TOR_DETECTED = "tor_detected"
    MULTIPLE_FAILED_ATTEMPTS = "multiple_failed_attempts"
    CREDENTIAL_STUFFING_PATTERN = "credential_stuffing_pattern"
    ACCOUNT_AGE = "account_age"
    UNUSUAL_BEHAVIOR = "unusual_behavior"


@dataclass
class RiskAssessmentPolicy(BusinessRule):
    """Policy for risk assessment and fraud detection."""
    
    # Risk thresholds
    low_risk_threshold: float = 0.3
    medium_risk_threshold: float = 0.6
    high_risk_threshold: float = 0.8
    
    # Risk factor weights
    risk_weights: dict[RiskFactor, float] = field(default_factory=lambda: {
        RiskFactor.NEW_DEVICE: 0.2,
        RiskFactor.NEW_LOCATION: 0.15,
        RiskFactor.UNUSUAL_TIME: 0.1,
        RiskFactor.RAPID_LOCATION_CHANGE: 0.4,
        RiskFactor.HIGH_RISK_COUNTRY: 0.3,
        RiskFactor.VPN_DETECTED: 0.25,
        RiskFactor.TOR_DETECTED: 0.5,
        RiskFactor.MULTIPLE_FAILED_ATTEMPTS: 0.35,
        RiskFactor.CREDENTIAL_STUFFING_PATTERN: 0.6,
        RiskFactor.ACCOUNT_AGE: 0.1,
        RiskFactor.UNUSUAL_BEHAVIOR: 0.3
    })
    
    # Configuration
    require_mfa_above_score: float = 0.5
    block_above_score: float = 0.9
    alert_security_team_above: float = 0.7
    
    # Time windows
    rapid_location_window_hours: int = 2
    unusual_time_start_hour: int = 2
    unusual_time_end_hour: int = 5
    
    # High risk countries (ISO codes)
    high_risk_countries: list[str] = field(default_factory=lambda: [
        'KP', 'IR', 'SY', 'CU', 'VE'  # Example list
    ])
    
    def validate(self, **kwargs) -> list[PolicyViolation]:
        """Validate risk assessment policy."""
        violations = []
        
        # Extract parameters
        risk_score = kwargs.get('risk_score', 0.0)
        risk_factors = kwargs.get('risk_factors', [])
        user_data = kwargs.get('user_data', {})
        
        # Check if action should be blocked
        if risk_score >= self.block_above_score:
            violations.append(PolicyViolation(
                rule_name="RiskAssessmentPolicy",
                description="Risk score too high - action blocked",
                severity="critical",
                current_value=risk_score,
                expected_value=f"< {self.block_above_score}",
                context={
                    "risk_factors": risk_factors,
                    "user_id": user_data.get('id')
                }
            ))
        
        # Check if MFA is required
        elif risk_score >= self.require_mfa_above_score:
            if not user_data.get('mfa_verified'):
                violations.append(PolicyViolation(
                    rule_name="RiskAssessmentPolicy",
                    description="MFA required due to elevated risk",
                    severity="error",
                    current_value="no_mfa",
                    expected_value="mfa_required",
                    context={
                        "risk_score": risk_score,
                        "risk_factors": risk_factors
                    }
                ))
        
        # Check if security alert is needed
        if risk_score >= self.alert_security_team_above:
            violations.append(PolicyViolation(
                rule_name="RiskAssessmentPolicy",
                description="Security team notification required",
                severity="warning",
                current_value=risk_score,
                expected_value=f"< {self.alert_security_team_above}",
                context={
                    "alert_required": True,
                    "risk_factors": risk_factors
                }
            ))
        
        return violations
    
    def is_compliant(self, **kwargs) -> bool:
        """Check if risk level is acceptable."""
        violations = self.validate(**kwargs)
        return not self.has_blocking_violations(violations)
    
    def calculate_risk_score(
        self,
        risk_factors: list[RiskFactor],
        user_context: dict[str, Any]
    ) -> tuple[float, dict[str, Any]]:
        """
        Calculate risk score based on detected factors.
        
        Returns:
            Tuple of (risk_score, risk_details)
        """
        risk_score = 0.0
        risk_details = {
            'factors': [],
            'weights': {},
            'mitigations': []
        }
        
        # Calculate base risk from factors
        for factor in risk_factors:
            weight = self.risk_weights.get(factor, 0.1)
            risk_score += weight
            risk_details['factors'].append(factor.value)
            risk_details['weights'][factor.value] = weight
        
        # Apply user context modifiers
        risk_score = self._apply_context_modifiers(risk_score, user_context, risk_details)
        
        # Normalize score to 0-1 range
        risk_score = min(1.0, max(0.0, risk_score))
        
        risk_details['final_score'] = risk_score
        risk_details['risk_level'] = self._get_risk_level(risk_score)
        
        return risk_score, risk_details
    
    def _apply_context_modifiers(
        self,
        base_score: float,
        user_context: dict[str, Any],
        risk_details: dict[str, Any]
    ) -> float:
        """Apply contextual modifiers to risk score."""
        modified_score = base_score
        
        # Account age modifier
        account_age_days = user_context.get('account_age_days', 0)
        if account_age_days > 365:
            modified_score *= 0.8  # 20% reduction for established accounts
            risk_details['mitigations'].append('established_account')
        elif account_age_days < 7:
            modified_score *= 1.2  # 20% increase for new accounts
            risk_details['factors'].append('new_account')
        
        # Good standing modifier
        if user_context.get('verified_email') and user_context.get('verified_phone'):
            modified_score *= 0.9  # 10% reduction for verified accounts
            risk_details['mitigations'].append('verified_contact_info')
        
        # Previous successful MFA
        recent_mfa_success = user_context.get('recent_mfa_success')
        if recent_mfa_success:
            modified_score *= 0.7  # 30% reduction for recent MFA
            risk_details['mitigations'].append('recent_mfa_success')
        
        return modified_score
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score < self.low_risk_threshold:
            return "low"
        if risk_score < self.medium_risk_threshold:
            return "medium"
        if risk_score < self.high_risk_threshold:
            return "high"
        return "critical"
    
    def detect_risk_factors(self, request_context: dict[str, Any]) -> list[RiskFactor]:
        """Detect risk factors from request context."""
        risk_factors = []
        
        # Check for new device
        if request_context.get('is_new_device'):
            risk_factors.append(RiskFactor.NEW_DEVICE)
        
        # Check for new location
        if request_context.get('is_new_location'):
            risk_factors.append(RiskFactor.NEW_LOCATION)
        
        # Check for unusual time
        current_hour = request_context.get('request_time', datetime.utcnow()).hour
        if self.unusual_time_start_hour <= current_hour <= self.unusual_time_end_hour:
            risk_factors.append(RiskFactor.UNUSUAL_TIME)
        
        # Check for VPN/Tor
        if request_context.get('is_vpn'):
            risk_factors.append(RiskFactor.VPN_DETECTED)
        if request_context.get('is_tor'):
            risk_factors.append(RiskFactor.TOR_DETECTED)
        
        # Check for high-risk country
        country_code = request_context.get('country_code')
        if country_code in self.high_risk_countries:
            risk_factors.append(RiskFactor.HIGH_RISK_COUNTRY)
        
        # Check for rapid location change
        if self._detect_rapid_location_change(request_context):
            risk_factors.append(RiskFactor.RAPID_LOCATION_CHANGE)
        
        # Check for multiple failed attempts
        failed_attempts = request_context.get('recent_failed_attempts', 0)
        if failed_attempts >= 3:
            risk_factors.append(RiskFactor.MULTIPLE_FAILED_ATTEMPTS)
        
        return risk_factors
    
    def _detect_rapid_location_change(self, request_context: dict[str, Any]) -> bool:
        """Detect impossible travel scenarios."""
        last_location = request_context.get('last_location')
        current_location = request_context.get('current_location')
        last_activity_time = request_context.get('last_activity_time')
        
        if not all([last_location, current_location, last_activity_time]):
            return False
        
        # Calculate time difference
        time_diff = datetime.utcnow() - last_activity_time
        if time_diff > timedelta(hours=self.rapid_location_window_hours):
            return False
        
        # Calculate distance (simplified - would use proper geo calculation)
        distance = request_context.get('location_distance_km', 0)
        
        # If distance is greater than reasonable travel in time window
        max_reasonable_distance = 1000  # km
        return distance > max_reasonable_distance
    
    def get_required_actions(self, risk_score: float) -> dict[str, bool]:
        """Get required actions based on risk score."""
        return {
            'require_mfa': risk_score >= self.require_mfa_above_score,
            'block_action': risk_score >= self.block_above_score,
            'alert_security': risk_score >= self.alert_security_team_above,
            'additional_verification': risk_score >= self.medium_risk_threshold,
            'log_for_review': risk_score >= self.low_risk_threshold
        }