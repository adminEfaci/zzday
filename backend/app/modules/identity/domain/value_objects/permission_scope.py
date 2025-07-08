"""
Permission Scope Value Object

Represents the scope and context for permissions.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PermissionScope(ValueObject):
    """Permission scope value object."""
    
    resource_type: str
    resource_ids: list[str] | None = None
    conditions: dict[str, Any] | None = None
    
    def __post_init__(self):
        """Validate scope."""
        if not self.resource_type:
            raise ValueError("Resource type is required")
        
        if self.resource_ids is not None and not isinstance(self.resource_ids, list):
            raise ValueError("Resource IDs must be a list")
    
    def matches(self, resource_type: str, resource_id: str | None = None, context: dict[str, Any] | None = None) -> bool:
        """Check if scope matches given resource and context."""
        # Check resource type
        if self.resource_type not in ("*", resource_type):
            return False
        
        # Check resource ID if specified
        if self.resource_ids and resource_id:
            if resource_id not in self.resource_ids:
                return False
        
        # Check conditions if specified
        if self.conditions and context:
            for key, expected in self.conditions.items():
                if key not in context or context[key] != expected:
                    return False
        
        return True
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "resource_type": self.resource_type,
            "resource_ids": self.resource_ids,
            "conditions": self.conditions
        }
