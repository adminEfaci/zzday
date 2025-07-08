"""
Compromised Session Specification

Specification for detecting potentially compromised sessions.
"""

from ..entities.session import Session
from .base import BaseSpecification
from .session_specs import SuspiciousSessionSpecification


class CompromisedSessionSpecification(BaseSpecification[Session]):
    """Specification for detecting compromised sessions."""
    
    def __init__(self, risk_threshold: float = 0.9):
        super().__init__()
        self.risk_threshold = risk_threshold
        self._suspicious_spec = SuspiciousSessionSpecification(risk_threshold=0.6)
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session appears to be compromised."""
        self.validate_candidate(session)
        
        # Very high risk score indicates compromise
        if session.risk_score >= self.risk_threshold:
            return True
        
        # Multiple suspicious indicators
        if self._suspicious_spec.is_satisfied_by(session):
            return self._has_multiple_compromise_indicators(session)
        
        return False
    
    def _has_multiple_compromise_indicators(self, session: Session) -> bool:
        """Check for multiple indicators of compromise."""
        indicators = 0
        
        # Sudden location change
        if self._has_sudden_location_change(session):
            indicators += 1
        
        # Device fingerprint mismatch
        if self._has_device_mismatch(session):
            indicators += 1
        
        # Unusual activity patterns
        if self._has_unusual_activity(session):
            indicators += 1
        
        # Multiple failed MFA attempts
        if self._has_failed_mfa_attempts(session):
            indicators += 1
        
        return indicators >= 2
    
    def _has_sudden_location_change(self, session: Session) -> bool:
        """Check for sudden geographic location change."""
        # This would require historical location data
        # Placeholder implementation
        return False
    
    def _has_device_mismatch(self, session: Session) -> bool:
        """Check for device fingerprint mismatch."""
        # This would require device fingerprint comparison
        # Placeholder implementation
        return not session.is_trusted
    
    def _has_unusual_activity(self, session: Session) -> bool:
        """Check for unusual activity patterns."""
        # Check for rapid successive actions
        return len(session.security_events) > 10
    
    def _has_failed_mfa_attempts(self, session: Session) -> bool:
        """Check for multiple failed MFA attempts."""
        mfa_failures = [
            event for event in session.security_events 
            if event.get('type') == 'mfa_failure'
        ]
        return len(mfa_failures) >= 3


__all__ = ["CompromisedSessionSpecification"]
