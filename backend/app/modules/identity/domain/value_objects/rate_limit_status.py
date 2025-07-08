"""
Rate Limit Status Value Object

Represents the status of rate limiting checks.
"""

from dataclasses import dataclass
from datetime import datetime

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class RateLimitStatus(ValueObject):
    """
    Value object representing rate limit status.
    
    Encapsulates rate limit state, remaining quota, and reset timing
    for throttling and quota management.
    """
    
    allowed: bool
    remaining: int
    limit: int
    reset_at: datetime
    retry_after_seconds: int | None = None
    
    def __post_init__(self) -> None:
        """Validate rate limit status data."""
        if self.remaining < 0:
            raise ValueError("Remaining count cannot be negative")
        
        if self.limit < 0:
            raise ValueError("Limit cannot be negative")
        
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("Retry after seconds cannot be negative")
    
    def is_exceeded(self) -> bool:
        """Check if rate limit is exceeded."""
        return not self.allowed
    
    def is_near_limit(self, threshold: float = 0.8) -> bool:
        """Check if near rate limit threshold."""
        if self.limit == 0:
            return False
        return (self.limit - self.remaining) / self.limit >= threshold
    
    def get_usage_percentage(self) -> float:
        """Get usage as percentage of limit."""
        if self.limit == 0:
            return 0.0
        return ((self.limit - self.remaining) / self.limit) * 100
