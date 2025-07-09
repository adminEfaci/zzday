"""
Password History Entity

Represents password history for preventing password reuse.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.core.domain.base import Entity

from .user_constants import PasswordHistoryPolicy


@dataclass
class PasswordHistory(Entity):
    """Password history entity for tracking password changes."""
    
    id: UUID
    user_id: UUID
    password_hash: str  # Store hash as string
    created_at: datetime
    expired_at: datetime | None = None
    
    def __post_init__(self):
        """Initialize password history entity."""
        super().__post_init__()
        
        # Password history entries are immutable after creation
        # No domain events needed as this is internal tracking
    
    @classmethod
    def create(
        cls,
        user_id: UUID,
        password_hash: str
    ) -> 'PasswordHistory':
        """Create a new password history entry."""
        return cls(
            id=uuid4(),
            user_id=user_id,
            password_hash=password_hash,
            created_at=datetime.now(UTC)
        )
    
    def is_reused(self, password_hash: str) -> bool:
        """Check if password matches this history entry."""
        return self.password_hash == password_hash
    
    def is_expired(self) -> bool:
        """Check if password history entry is expired."""
        if self.expired_at:
            return datetime.now(UTC) > self.expired_at
        
        # Default expiry using constant
        age = datetime.now(UTC) - self.created_at
        return age > timedelta(days=PasswordHistoryPolicy.DEFAULT_EXPIRY_DAYS)
    
    def get_age_days(self) -> int:
        """Get age of password in days."""
        age = datetime.now(UTC) - self.created_at
        return age.days
    
    def can_be_reused(self, min_age_days: int = PasswordHistoryPolicy.MIN_REUSE_AGE_DAYS) -> bool:
        """Check if password can be reused based on age."""
        return self.get_age_days() >= min_age_days
    
    def expire(self) -> None:
        """Mark password history entry as expired."""
        self.expired_at = datetime.now(UTC)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "password_hash": self.password_hash,
            "created_at": self.created_at.isoformat(),
            "expired_at": self.expired_at.isoformat() if self.expired_at else None
        }