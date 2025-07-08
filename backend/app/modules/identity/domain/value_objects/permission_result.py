"""
Permission Result Value Object

Represents the result of a permission check operation.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PermissionResult(ValueObject):
    """
    Value object representing a permission check result.
    
    Encapsulates authorization decision with context and reasoning
    for security and audit purposes.
    """
    
    allowed: bool
    permission: str
    resource: str | None = None
    reason: str | None = None
    conditions: dict[str, Any] | None = None
    expires_at: float | None = None  # Unix timestamp
    
    def __post_init__(self) -> None:
        """Validate permission result data."""
        if self.expires_at is not None and self.expires_at < 0:
            raise ValueError("Expiry timestamp cannot be negative")
    
    def is_denied(self) -> bool:
        """Check if permission was denied."""
        return not self.allowed
    
    def has_conditions(self) -> bool:
        """Check if permission has conditions."""
        return bool(self.conditions)
    
    def is_expired(self) -> bool:
        """Check if permission result has expired."""
        if not self.expires_at:
            return False
        import time
        return time.time() > self.expires_at
