"""
Security Stamp Value Object

Immutable representation of a security stamp for invalidation tracking.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from app.core.domain.base import ValueObject


class SecurityStampPurpose(Enum):
    """Purpose of security stamp generation/update."""
    
    INITIAL = "initial"  # Initial account creation
    PASSWORD_CHANGE = "password_change"
    EMAIL_CHANGE = "email_change"
    PHONE_CHANGE = "phone_change"
    MFA_CHANGE = "mfa_change"
    ROLE_CHANGE = "role_change"
    PERMISSION_CHANGE = "permission_change"
    SECURITY_RESET = "security_reset"
    ACCOUNT_RECOVERY = "account_recovery"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MANUAL_INVALIDATION = "manual_invalidation"
    PERIODIC_ROTATION = "periodic_rotation"


@dataclass(frozen=True)
class SecurityStamp(ValueObject):
    """
    Value object representing a security stamp.
    
    Security stamps are used to invalidate tokens and sessions when
    critical security changes occur on an account.
    """
    
    value: str
    generated_at: datetime
    purpose: SecurityStampPurpose
    previous_stamp: str | None = None
    
    def __post_init__(self):
        """Validate security stamp."""
        if not self.value:
            raise ValueError("Security stamp value is required")
        
        # Validate format (should be URL-safe base64)
        if len(self.value) < 32:
            raise ValueError("Security stamp too short")
        
        # Ensure timestamp is timezone-aware
        if self.generated_at.tzinfo is None:
            raise ValueError("generated_at must be timezone-aware")
        
        # If previous stamp provided, validate it too
        if self.previous_stamp and len(self.previous_stamp) < 32:
            raise ValueError("Previous stamp too short")
    
    @classmethod
    def generate(
        cls,
        purpose: SecurityStampPurpose,
        previous_stamp: Optional['SecurityStamp'] = None,
        length: int = 32
    ) -> 'SecurityStamp':
        """Generate a new security stamp."""
        # Generate cryptographically secure random stamp
        stamp_value = secrets.token_urlsafe(length)
        
        return cls(
            value=stamp_value,
            generated_at=datetime.utcnow(),
            purpose=purpose,
            previous_stamp=previous_stamp.value if previous_stamp else None
        )
    
    @classmethod
    def generate_initial(cls) -> 'SecurityStamp':
        """Generate initial security stamp for new account."""
        return cls.generate(SecurityStampPurpose.INITIAL)
    
    @property
    def age(self) -> timedelta:
        """Get age of security stamp."""
        return datetime.utcnow() - self.generated_at
    
    @property
    def age_days(self) -> int:
        """Get age in days."""
        return self.age.days
    
    @property
    def should_rotate(self, max_age_days: int = 90) -> bool:
        """
        Check if stamp should be rotated based on age.
        
        Default rotation period is 90 days for enhanced security.
        """
        return self.age_days >= max_age_days
    
    @property
    def is_recent(self, threshold_minutes: int = 5) -> bool:
        """
        Check if stamp was recently generated.
        
        Useful for rate limiting stamp regeneration.
        """
        return self.age.total_seconds() < (threshold_minutes * 60)
    
    @property
    def was_security_event(self) -> bool:
        """Check if stamp was generated due to security event."""
        security_events = {
            SecurityStampPurpose.PASSWORD_CHANGE,
            SecurityStampPurpose.SECURITY_RESET,
            SecurityStampPurpose.ACCOUNT_RECOVERY,
            SecurityStampPurpose.SUSPICIOUS_ACTIVITY,
            SecurityStampPurpose.MANUAL_INVALIDATION
        }
        
        return self.purpose in security_events
    
    @property
    def was_profile_change(self) -> bool:
        """Check if stamp was generated due to profile change."""
        profile_changes = {
            SecurityStampPurpose.EMAIL_CHANGE,
            SecurityStampPurpose.PHONE_CHANGE,
            SecurityStampPurpose.MFA_CHANGE
        }
        
        return self.purpose in profile_changes
    
    @property
    def was_permission_change(self) -> bool:
        """Check if stamp was generated due to permission change."""
        permission_changes = {
            SecurityStampPurpose.ROLE_CHANGE,
            SecurityStampPurpose.PERMISSION_CHANGE
        }
        
        return self.purpose in permission_changes
    
    def get_hash(self) -> str:
        """
        Get hash of security stamp for comparison.
        
        Used when comparing stamps without exposing actual values.
        """
        return hashlib.sha256(self.value.encode()).hexdigest()
    
    def get_short_hash(self) -> str:
        """Get shortened hash for logging."""
        return self.get_hash()[:16]
    
    def matches(self, other_stamp: str) -> bool:
        """Check if this stamp matches another stamp value."""
        return secrets.compare_digest(self.value, other_stamp)
    
    def create_successor(self, purpose: SecurityStampPurpose) -> 'SecurityStamp':
        """Create a new stamp that succeeds this one."""
        return SecurityStamp.generate(
            purpose=purpose,
            previous_stamp=self
        )
    
    def to_audit_entry(self) -> dict:
        """Create audit log entry."""
        return {
            'stamp_hash': self.get_short_hash(),
            'purpose': self.purpose.value,
            'generated_at': self.generated_at.isoformat(),
            'age_days': self.age_days,
            'was_security_event': self.was_security_event,
            'previous_stamp_hash': hashlib.sha256(self.previous_stamp.encode()).hexdigest()[:16] if self.previous_stamp else None
        }
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        return f"SecurityStamp(hash={self.get_short_hash()}, purpose={self.purpose.value})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"SecurityStamp(age={self.age_days}d, purpose={self.purpose.value})"