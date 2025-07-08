"""
Device Trust Policy

Business rules for device trust management and validation.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .base import BusinessRule, PolicyViolation


@dataclass
class DeviceTrustPolicy(BusinessRule):
    """Policy for device trust management."""
    
    # Configuration parameters
    max_trusted_devices: int = 10
    trust_duration_days: int = 30
    require_mfa_for_new_device: bool = True
    allow_persistent_trust: bool = False
    auto_trust_after_successful_mfa: bool = True
    revoke_trust_on_suspicious_activity: bool = True
    
    def validate(self, **kwargs) -> list[PolicyViolation]:
        """Validate device trust policy."""
        violations = []
        
        # Extract parameters
        device_id = kwargs.get('device_id')
        trusted_devices = kwargs.get('trusted_devices', [])
        is_new_device = kwargs.get('is_new_device', False)
        mfa_completed = kwargs.get('mfa_completed', False)
        
        # Check device limit
        if len(trusted_devices) >= self.max_trusted_devices:
            violations.append(PolicyViolation(
                rule_name="DeviceTrustPolicy",
                description="Maximum number of trusted devices exceeded",
                severity="error",
                current_value=len(trusted_devices),
                expected_value=self.max_trusted_devices,
                context={"device_id": device_id}
            ))
        
        # Check MFA requirement for new devices
        if is_new_device and self.require_mfa_for_new_device and not mfa_completed:
            violations.append(PolicyViolation(
                rule_name="DeviceTrustPolicy",
                description="MFA required for new device trust",
                severity="error",
                current_value="no_mfa",
                expected_value="mfa_required",
                context={"device_id": device_id}
            ))
        
        # Check for expired trusts
        current_time = datetime.utcnow()
        for device in trusted_devices:
            if device.get('trust_expires_at') and device['trust_expires_at'] < current_time:
                violations.append(PolicyViolation(
                    rule_name="DeviceTrustPolicy",
                    description="Device trust has expired",
                    severity="warning",
                    current_value=device['trust_expires_at'],
                    expected_value=current_time,
                    context={"device_id": device['id']}
                ))
        
        return violations
    
    def is_compliant(self, **kwargs) -> bool:
        """Check if device trust is compliant."""
        violations = self.validate(**kwargs)
        return not self.has_blocking_violations(violations)
    
    def check_device_trust(
        self,
        device_id: str,
        trusted_devices: list[dict[str, Any]],
        last_verification: datetime | None = None
    ) -> dict[str, Any]:
        """
        Check if a device is trusted.
        
        Returns:
            Dict with trust status and any required actions
        """
        # Find device in trusted list
        device = next((d for d in trusted_devices if d['id'] == device_id), None)
        
        if not device:
            return {
                'trusted': False,
                'reason': 'device_not_found',
                'action_required': 'device_verification'
            }
        
        # Check expiration
        if device.get('trust_expires_at'):
            if device['trust_expires_at'] < datetime.utcnow():
                return {
                    'trusted': False,
                    'reason': 'trust_expired',
                    'action_required': 're_verification'
                }
        
        # Check if re-verification is needed
        if last_verification and self.should_reverify(last_verification):
            return {
                'trusted': True,
                'reason': 'reverification_recommended',
                'action_required': 'periodic_verification'
            }
        
        return {
            'trusted': True,
            'reason': 'valid_trust',
            'action_required': None
        }
    
    def should_reverify(self, last_verification: datetime) -> bool:
        """Check if device should be re-verified."""
        # Re-verify every 7 days for enhanced security
        reverify_after = timedelta(days=7)
        return datetime.utcnow() - last_verification > reverify_after
    
    def calculate_trust_expiration(self, permanent: bool = False) -> datetime | None:
        """Calculate when device trust should expire."""
        if permanent and self.allow_persistent_trust:
            return None  # No expiration
        
        return datetime.utcnow() + timedelta(days=self.trust_duration_days)
    
    def should_auto_trust(self, mfa_completed: bool, risk_score: float) -> bool:
        """Determine if device should be automatically trusted."""
        if not self.auto_trust_after_successful_mfa:
            return False
        
        if not mfa_completed:
            return False
        
        # Don't auto-trust high-risk scenarios
        return not risk_score > 0.7
    
    def get_trust_requirements(self, is_new_device: bool) -> dict[str, Any]:
        """Get requirements for trusting a device."""
        return {
            'mfa_required': is_new_device and self.require_mfa_for_new_device,
            'user_consent_required': True,
            'risk_assessment_required': True
        }
        
