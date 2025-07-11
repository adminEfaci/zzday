"""
Partial Session Entity

Represents a session pending MFA verification.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.modules.identity.domain.enums import MFAMethod

from ...value_objects.device_fingerprint import DeviceFingerprint
from ...value_objects.geolocation import Geolocation
from ...value_objects.ip_address import IpAddress
from ...value_objects.token import Token, TokenType
from ...value_objects.user_agent import UserAgent
from .session_enums import SessionType
from .session_errors import SessionExpiredError, InvalidTokenError
from .session_constants import (
    MFA_CHALLENGE_TIMEOUT, MFA_SESSION_TIMEOUT, MAX_MFA_ATTEMPTS, MFA_EXTENSION_MINUTES
)
from .session_mixins import RiskManagementMixin, RateLimitingMixin, SessionValidationMixin


@dataclass
class PartialSession(Entity, RiskManagementMixin, RateLimitingMixin, SessionValidationMixin):
    """Entity representing a session pending MFA verification."""
    
    id: UUID
    user_id: UUID
    session_type: SessionType
    
    # MFA challenge details
    mfa_method: MFAMethod
    mfa_device_id: UUID | None = None
    challenge_token: Token | None = None
    challenge_expires_at: datetime | None = None
    challenge_attempts: int = 0
    max_challenge_attempts: int = MAX_MFA_ATTEMPTS
    
    # Session context (preserved from initial auth)
    ip_address: IpAddress | None = None
    user_agent: UserAgent | None = None
    device_fingerprint: DeviceFingerprint | None = None
    geolocation: Geolocation | None = None
    
    # Authentication context
    auth_method: str = "password"
    auth_metadata: dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    
    # Security
    risk_score: float = 0.0
    security_context: dict[str, Any] = field(default_factory=dict)
    security_events: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def last_activity_at(self) -> datetime:
        """Alias for compatibility with mixins."""
        return self.updated_at if hasattr(self, 'updated_at') else self.created_at
    
    def __post_init__(self):
        """Initialize partial session with validation."""
        super().__init__(self.id)
        
        # Validate required fields
        if not self.user_id:
            raise ValueError("User ID is required")
        
        if not isinstance(self.session_type, SessionType):
            raise ValueError("Session type must be a SessionType enum")
        
        if not isinstance(self.mfa_method, MFAMethod):
            raise ValueError("MFA method must be an MFAMethod enum")
        
        # Set default expiration if not provided
        if not self.expires_at:
            self.expires_at = self.created_at + MFA_SESSION_TIMEOUT
        
        # Set challenge expiration if not provided
        if not self.challenge_expires_at:
            self.challenge_expires_at = self.created_at + MFA_CHALLENGE_TIMEOUT
        
        # Generate challenge token if not provided
        if not self.challenge_token:
            self.challenge_token = Token.generate(TokenType.CHALLENGE)
        
        # Validate risk score
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
    
    @classmethod
    def create_from_auth(
        cls,
        user_id: UUID,
        session_type: SessionType,
        mfa_method: MFAMethod,
        mfa_device_id: UUID | None = None,
        ip_address: IpAddress | None = None,
        user_agent: UserAgent | None = None,
        device_fingerprint: DeviceFingerprint | None = None,
        auth_method: str = "password",
        auth_metadata: dict[str, Any] | None = None,
        risk_score: float = 0.0
    ) -> 'PartialSession':
        """Create a partial session from initial authentication."""
        session_id = uuid4()
        
        return cls(
            id=session_id,
            user_id=user_id,
            session_type=session_type,
            mfa_method=mfa_method,
            mfa_device_id=mfa_device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            auth_method=auth_method,
            auth_metadata=auth_metadata or {},
            risk_score=risk_score
        )
    
    @property
    def is_expired(self) -> bool:
        """Check if partial session is expired."""
        return datetime.now(UTC) > self.expires_at
    
    @property
    def is_challenge_expired(self) -> bool:
        """Check if MFA challenge is expired."""
        return datetime.now(UTC) > self.challenge_expires_at
    
    @property
    def can_attempt_challenge(self) -> bool:
        """Check if more challenge attempts are allowed."""
        return (
            not self.is_expired 
            and not self.is_challenge_expired 
            and self.challenge_attempts < self.max_challenge_attempts
        )
    
    def record_challenge_attempt(self) -> None:
        """Record a challenge attempt."""
        if not self.can_attempt_challenge():
            raise InvalidTokenError("No more challenge attempts allowed")
        
        self.challenge_attempts += 1
        self.touch()
        
        # Record in rate limiting
        self.record_rate_limited_action("mfa_attempt")
        
        # Add to security context
        if "challenge_attempts" not in self.security_context:
            self.security_context["challenge_attempts"] = []
        
        self.security_context["challenge_attempts"].append({
            "attempt": self.challenge_attempts,
            "timestamp": datetime.now(UTC).isoformat(),
            "method": self.mfa_method.value
        })
        
        # Add security event for failed attempts
        if self.challenge_attempts > 1:
            self.add_security_event("failed_mfa_attempt", {
                "attempt_number": self.challenge_attempts,
                "method": self.mfa_method.value,
                "remaining_attempts": self.max_challenge_attempts - self.challenge_attempts
            })
    
    def refresh_challenge(self) -> Token:
        """Refresh the MFA challenge with rate limiting."""
        if self.is_expired:
            raise SessionExpiredError()
        
        # Check rate limiting
        if not self.check_rate_limit("challenge_refresh"):
            raise InvalidTokenError("Challenge refresh rate limit exceeded")
        
        self.record_rate_limited_action("challenge_refresh")
        
        # Generate new challenge token
        self.challenge_token = Token.generate(TokenType.CHALLENGE)
        self.challenge_expires_at = datetime.now(UTC) + MFA_CHALLENGE_TIMEOUT
        self.challenge_attempts = 0
        self.touch()
        
        # Record security event
        self.add_security_event("challenge_refreshed", {
            "method": self.mfa_method.value,
            "new_expires_at": self.challenge_expires_at.isoformat()
        })
        
        return self.challenge_token
    
    def extend_expiration(self, minutes: int = MFA_EXTENSION_MINUTES) -> None:
        """Extend session expiration with limits."""
        if self.is_expired:
            raise SessionExpiredError()
        
        # Check rate limiting
        if not self.check_rate_limit("session_extend"):
            raise InvalidTokenError("Session extension rate limit exceeded")
        
        self.record_rate_limited_action("session_extend")
        
        max_extension = datetime.now(UTC) + timedelta(minutes=30)
        new_expiration = self.expires_at + timedelta(minutes=minutes)
        
        # Don't extend beyond maximum
        self.expires_at = min(new_expiration, max_extension)
        self.touch()
    
    def validate_challenge_token(self, token: str) -> bool:
        """Validate challenge token with attempt checks."""
        if not self.challenge_token:
            return False
        
        # Check if attempts are allowed
        if not self.can_attempt_challenge():
            return False
        
        is_valid = (
            self.challenge_token.value == token 
            and not self.is_challenge_expired
        )
        
        if not is_valid:
            self.record_challenge_attempt()
        
        return is_valid
    
    def _handle_high_risk(self) -> None:
        """Handle high-risk scenarios by expiring the session."""
        self.expires_at = datetime.now(UTC)
        self.add_security_event("session_expired_high_risk", {
            "risk_score": self.risk_score,
            "reason": "high_risk_score"
        })
    
    def to_session_context(self) -> dict[str, Any]:
        """Convert to session creation context."""
        return {
            "user_id": self.user_id,
            "session_type": self.session_type,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_fingerprint": self.device_fingerprint,
            "geolocation": self.geolocation,
            "metadata": {
                "auth_method": self.auth_method,
                "mfa_method": self.mfa_method.value,
                "mfa_device_id": str(self.mfa_device_id) if self.mfa_device_id else None,
                "partial_session_id": str(self.id),
                **self.auth_metadata
            },
            "risk_score": self.risk_score
        }
    
    def get_challenge_info(self) -> dict[str, Any]:
        """Get challenge information for client."""
        return {
            "session_id": str(self.id),
            "challenge_token": self.challenge_token.value if self.challenge_token else None,
            "mfa_method": self.mfa_method.value,
            "mfa_device_id": str(self.mfa_device_id) if self.mfa_device_id else None,
            "expires_at": self.challenge_expires_at.isoformat(),
            "attempts_remaining": self.max_challenge_attempts - self.challenge_attempts,
            "can_refresh": not self.is_expired,
            "can_attempt": self.can_attempt_challenge()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for persistence."""
        # Only hash token if it exists
        challenge_hash = None
        if self.challenge_token and self.challenge_token.value:
            challenge_hash = hashlib.sha256(self.challenge_token.value.encode()).hexdigest()
        
        return {
            **super().to_dict(),
            "user_id": str(self.user_id),
            "session_type": self.session_type.value,
            "mfa_method": self.mfa_method.value,
            "mfa_device_id": str(self.mfa_device_id) if self.mfa_device_id else None,
            "challenge_token_hash": challenge_hash,
            "challenge_expires_at": self.challenge_expires_at.isoformat(),
            "challenge_attempts": self.challenge_attempts,
            "max_challenge_attempts": self.max_challenge_attempts,
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "user_agent": self.user_agent.value if self.user_agent else None,
            "device_fingerprint": self.device_fingerprint.value if self.device_fingerprint else None,
            "geolocation": self.geolocation.to_dict() if self.geolocation else None,
            "auth_method": self.auth_method,
            "auth_metadata": self.auth_metadata,
            "expires_at": self.expires_at.isoformat(),
            "risk_score": self.risk_score,
            "security_context": self.security_context,
            "security_events": self.security_events
        }