"""
Composite Specifications

Pre-built composite specifications for common business scenarios.
"""

from .base import BaseSpecification
from .security_specs import ComplianceSpecification, HighRiskSpecification
from .session_specs import (
    ActiveSessionSpecification,
    SuspiciousSessionSpecification,
    TrustedSessionSpecification,
)
from .user_specs import (
    ActiveUserSpecification,
    MFAEnabledSpecification,
    PasswordExpiredSpecification,
    VerifiedEmailSpecification,
)


class SecureUserSpecification(BaseSpecification):
    """Composite specification for secure users."""
    
    def __init__(self):
        super().__init__()
        self._active_spec = ActiveUserSpecification()
        self._verified_spec = VerifiedEmailSpecification()
        self._mfa_spec = MFAEnabledSpecification()
        self._password_spec = PasswordExpiredSpecification().not_()
    
    def is_satisfied_by(self, user) -> bool:
        """Check if user meets security requirements."""
        return (
            self._active_spec.and_(self._verified_spec)
            .and_(self._mfa_spec)
            .and_(self._password_spec)
            .is_satisfied_by(user)
        )


class TrustedSessionSpecification(BaseSpecification):
    """Composite specification for trusted sessions."""
    
    def __init__(self):
        super().__init__()
        self._active_spec = ActiveSessionSpecification()
        self._trusted_spec = TrustedSessionSpecification()
        self._not_suspicious_spec = SuspiciousSessionSpecification().not_()
    
    def is_satisfied_by(self, session) -> bool:
        """Check if session is trusted."""
        return (
            self._active_spec
            .and_(self._trusted_spec)
            .and_(self._not_suspicious_spec)
            .is_satisfied_by(session)
        )


class ComplianceReadyUserSpecification(BaseSpecification):
    """Composite specification for compliance-ready users."""
    
    def __init__(self):
        super().__init__()
        self._secure_spec = SecureUserSpecification()
        self._compliance_spec = ComplianceSpecification()
    
    def is_satisfied_by(self, user) -> bool:
        """Check if user is compliance-ready."""
        return (
            self._secure_spec
            .and_(self._compliance_spec)
            .is_satisfied_by(user)
        )


class HighRiskLoginSpecification(BaseSpecification):
    """Composite specification for high-risk login attempts."""
    
    def __init__(self, risk_threshold: float = 0.8):
        super().__init__()
        self._high_risk_spec = HighRiskSpecification(risk_threshold)
    
    def is_satisfied_by(self, login_attempt) -> bool:
        """Check if login attempt is high risk."""
        return self._high_risk_spec.is_satisfied_by(login_attempt)
