"""
Shared Base Entity Classes

Common functionality for identity domain entities.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID

from app.core.domain.base import Entity

T = TypeVar('T', bound='IdentityEntity')


@dataclass
class IdentityEntity(Entity, ABC):
    """Base entity for identity domain with common functionality."""
    
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize identity entity."""
        super().__post_init__()
        self._validate_entity()
    
    @abstractmethod
    def _validate_entity(self) -> None:
        """Validate entity-specific business rules."""
    
    def touch(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = datetime.now(UTC)
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata with validation."""
        if not key or not isinstance(key, str):
            raise ValueError("Metadata key must be a non-empty string")
        
        self.metadata[key] = value
        self.touch()
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value."""
        return self.metadata.get(key, default)
    
    def remove_metadata(self, key: str) -> None:
        """Remove metadata key."""
        self.metadata.pop(key, None)
        self.touch()


@dataclass
class AuditableEntity(IdentityEntity, ABC):
    """Base entity with audit trail support."""
    
    created_by: UUID | None = None
    updated_by: UUID | None = None
    version: int = 1
    
    def update_audit_info(self, updated_by: UUID) -> None:
        """Update audit information."""
        self.updated_by = updated_by
        self.version += 1
        self.touch()


@dataclass
class ExpirableEntity(IdentityEntity, ABC):
    """Base entity with expiration support."""
    
    expires_at: datetime | None = None
    
    def is_expired(self) -> bool:
        """Check if entity has expired."""
        if not self.expires_at:
            return False
        return datetime.now(UTC) > self.expires_at
    
    def extend_expiry(self, additional_seconds: int) -> None:
        """Extend expiry time."""
        if not self.expires_at:
            raise ValueError("Cannot extend expiry on non-expiring entity")
        
        from datetime import timedelta
        self.expires_at += timedelta(seconds=additional_seconds)
        self.touch()


class SecurityValidationMixin:
    """Mixin for security-related validation."""
    
    @staticmethod
    def validate_hash(hash_value: str, field_name: str = "hash") -> None:
        """Validate hash format."""
        if not hash_value:
            raise ValueError(f"{field_name} is required")
        
        if not isinstance(hash_value, str):
            raise ValueError(f"{field_name} must be a string")
        
        # Basic hash format validation (hex string)
        if not all(c in '0123456789abcdef' for c in hash_value.lower()):
            raise ValueError(f"{field_name} must be a valid hex string")
    
    @staticmethod
    def validate_token_format(token: str, field_name: str = "token") -> None:
        """Validate token format."""
        if not token:
            raise ValueError(f"{field_name} is required")
        
        if len(token) < 16:
            raise ValueError(f"{field_name} must be at least 16 characters")
        
        if len(token) > 512:
            raise ValueError(f"{field_name} cannot exceed 512 characters")


class RiskAssessmentMixin:
    """Mixin for risk assessment functionality."""
    
    def calculate_base_risk(self, factors: dict[str, float]) -> float:
        """Calculate base risk score from factors."""
        if not factors:
            return 0.0
        
        # Weighted average of risk factors
        total_weight = sum(factors.values())
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(factor * weight for factor, weight in factors.items())
        return min(weighted_sum / total_weight, 1.0)
    
    def normalize_risk_score(self, score: float) -> float:
        """Normalize risk score to 0.0-1.0 range."""
        return max(0.0, min(1.0, score))
