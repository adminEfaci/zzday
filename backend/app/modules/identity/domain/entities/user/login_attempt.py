"""
Login Attempt Entity - Refined

Represents a login attempt with composed value objects and extracted services.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.modules.identity.domain.value_objects import (
    AuthorizationContext,
    RiskAssessment,
)

from .user_enums import LoginFailureReason


@dataclass
class LoginAttempt(Entity):
    """Login attempt entity focused on data and simple operations."""
    
    id: UUID
    email: str
    success: bool
    failure_reason: LoginFailureReason | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    user_id: UUID | None = None
    session_id: UUID | None = None
    
    # Composed value objects
    auth_context: AuthorizationContext | None = None
    risk_assessment: RiskAssessment | None = None
    
    # Simple behavioral data (set by service)
    login_velocity: int = 0
    failed_attempts_24h: int = 0
    last_successful_login: datetime | None = None
    
    def __post_init__(self):
        """Initialize login attempt entity."""
        super().__post_init__()
        
        # Basic validation only
        if not self.email:
            raise ValueError("Email is required for login attempt")
        
        if not self.success and not self.failure_reason:
            raise ValueError("Failure reason required for failed login attempts")
        
        if self.success and self.failure_reason:
            raise ValueError("Success and failure reason are mutually exclusive")
    
    @classmethod
    def create_successful(
        cls,
        email: str,
        user_id: UUID,
        session_id: UUID,
        auth_context: AuthorizationContext | None = None
    ) -> 'LoginAttempt':
        """Create a successful login attempt."""
        return cls(
            id=uuid4(),
            email=email,
            success=True,
            user_id=user_id,
            session_id=session_id,
            auth_context=auth_context,
            timestamp=datetime.now(UTC)
        )
    
    @classmethod
    def create_failed(
        cls,
        email: str,
        failure_reason: LoginFailureReason,
        user_id: UUID | None = None,
        auth_context: AuthorizationContext | None = None
    ) -> 'LoginAttempt':
        """Create a failed login attempt."""
        return cls(
            id=uuid4(),
            email=email,
            success=False,
            failure_reason=failure_reason,
            user_id=user_id,
            auth_context=auth_context,
            timestamp=datetime.now(UTC)
        )
    
    def set_risk_assessment(self, risk_assessment: RiskAssessment) -> None:
        """Set risk assessment (called by UserSecurityService)."""
        self.risk_assessment = risk_assessment
    
    def update_behavioral_data(
        self,
        login_velocity: int,
        failed_attempts_24h: int,
        last_successful_login: datetime | None = None
    ) -> None:
        """Update behavioral analysis data (called by UserSecurityService)."""
        self.login_velocity = login_velocity
        self.failed_attempts_24h = failed_attempts_24h
        self.last_successful_login = last_successful_login
    
    # Simple queries only
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.auth_context is not None and self.auth_context.is_authenticated
    
    def has_mfa(self) -> bool:
        """Check if MFA was used."""
        return self.auth_context is not None and self.auth_context.mfa_verified
    
    def is_high_risk(self) -> bool:
        """Check if attempt is high risk."""
        return self.risk_assessment is not None and self.risk_assessment.is_high_risk()
    
    def get_ip_address(self) -> str | None:
        """Get IP address from context."""
        return self.auth_context.ip_address if self.auth_context else None
    
    def get_device_id(self) -> str | None:
        """Get device ID from context."""
        return self.auth_context.device_id if self.auth_context else None
    
    def get_risk_score(self) -> float:
        """Get risk score."""
        return self.risk_assessment.score if self.risk_assessment else 0.0
    
    def get_failure_message(self) -> str:
        """Get user-friendly failure message."""
        if self.success:
            return ""
        
        message_map = {
            LoginFailureReason.INVALID_CREDENTIALS: "Invalid email or password",
            LoginFailureReason.INVALID_EMAIL: "Email not found",
            LoginFailureReason.INVALID_PASSWORD: "Invalid password",
            LoginFailureReason.ACCOUNT_NOT_FOUND: "Account not found",
            LoginFailureReason.ACCOUNT_INACTIVE: "Account is not active",
            LoginFailureReason.ACCOUNT_LOCKED: "Account is locked due to too many failed attempts",
            LoginFailureReason.ACCOUNT_SUSPENDED: "Account has been suspended",
            LoginFailureReason.EMAIL_NOT_VERIFIED: "Please verify your email address",
            LoginFailureReason.MFA_REQUIRED: "Multi-factor authentication required",
            LoginFailureReason.MFA_FAILED: "Invalid verification code",
            LoginFailureReason.PASSWORD_EXPIRED: "Password has expired, please reset",
            LoginFailureReason.TOO_MANY_ATTEMPTS: "Too many login attempts, please try again later",
            LoginFailureReason.SUSPICIOUS_ACTIVITY: "Suspicious activity detected",
            LoginFailureReason.IP_BLOCKED: "Access from this location is blocked",
            LoginFailureReason.MAINTENANCE_MODE: "System is under maintenance"
        }
        
        return message_map.get(self.failure_reason, "Login failed")
    
    def to_audit_format(self) -> dict[str, Any]:
        """Convert to audit log format."""
        return {
            "attempt_id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "email": self.email,
            "user_id": str(self.user_id) if self.user_id else None,
            "success": self.success,
            "failure_reason": self.failure_reason.value if self.failure_reason else None,
            "ip_address": self.get_ip_address(),
            "device_id": self.get_device_id(),
            "risk_score": self.get_risk_score(),
            "mfa_used": self.has_mfa(),
            "high_risk": self.is_high_risk()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "email": self.email,
            "success": self.success,
            "failure_reason": self.failure_reason.value if self.failure_reason else None,
            "timestamp": self.timestamp.isoformat(),
            "user_id": str(self.user_id) if self.user_id else None,
            "session_id": str(self.session_id) if self.session_id else None,
            "auth_context": self.auth_context.to_audit_log() if self.auth_context else None,
            "risk_assessment": {
                "level": self.risk_assessment.level.value,
                "score": self.risk_assessment.score,
                "confidence": self.risk_assessment.confidence
            } if self.risk_assessment else None,
            "behavioral_data": {
                "login_velocity": self.login_velocity,
                "failed_attempts_24h": self.failed_attempts_24h,
                "last_successful_login": self.last_successful_login.isoformat() if self.last_successful_login else None
            }
        }