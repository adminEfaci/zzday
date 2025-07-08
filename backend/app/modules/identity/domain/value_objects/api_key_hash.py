"""
API Key Hash Value Object

Immutable representation of hashed API keys for secure storage.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .base import ValueObject


class APIKeyType(Enum):
    """Types of API keys."""
    
    PERSONAL = "personal"  # User's personal API key
    SERVICE = "service"  # Service-to-service key
    APPLICATION = "application"  # Third-party application key
    WEBHOOK = "webhook"  # Webhook signing key
    TEMPORARY = "temporary"  # Short-lived keys
    MASTER = "master"  # Master/admin key (high privilege)


class APIKeyScope(Enum):
    """API key permission scopes."""
    
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    CUSTOM = "custom"


@dataclass(frozen=True)
class APIKeyHash(ValueObject):
    """
    Value object representing a hashed API key.
    
    Stores the hash and metadata for API keys, never the plain text.
    Supports key prefixes for identification without exposing the full key.
    """
    
    key_hash: str
    key_prefix: str  # First few characters for identification
    key_type: APIKeyType
    algorithm: str = "sha256"
    salt: str | None = None
    created_at: datetime | None = None
    
    def __post_init__(self):
        """Validate API key hash."""
        if not self.key_hash:
            raise ValueError("Key hash is required")
        
        if not self.key_prefix or len(self.key_prefix) < 4:
            raise ValueError("Key prefix must be at least 4 characters")
        
        if len(self.key_prefix) > 12:
            raise ValueError("Key prefix too long (max 12 characters)")
        
        # Validate hash format
        if self.algorithm == "sha256" and len(self.key_hash) != 64:
            raise ValueError("Invalid SHA256 hash length")
        
        # Validate prefix format (should be alphanumeric)
        if not self.key_prefix.replace('-', '').replace('_', '').isalnum():
            raise ValueError("Key prefix must be alphanumeric (with optional hyphens/underscores)")
        
        # Ensure created_at is timezone-aware if provided
        if self.created_at and self.created_at.tzinfo is None:
            object.__setattr__(self, 'created_at', self.created_at.replace(tzinfo=UTC))
    
    @classmethod
    def generate_api_key(
        cls,
        key_type: APIKeyType,
        prefix: str | None = None,
        length: int = 32
    ) -> tuple['APIKeyHash', str]:
        """
        Generate a new API key.
        
        Returns tuple of (APIKeyHash object, plain text key).
        Plain text key should be shown once and never stored.
        """
        # Generate key prefix based on type if not provided
        if not prefix:
            prefix_map = {
                APIKeyType.PERSONAL: "pk",
                APIKeyType.SERVICE: "sk",
                APIKeyType.APPLICATION: "ak",
                APIKeyType.WEBHOOK: "whk",
                APIKeyType.TEMPORARY: "tk",
                APIKeyType.MASTER: "mk"
            }
            prefix = prefix_map.get(key_type, "key")
        
        # Generate random key
        random_part = secrets.token_urlsafe(length)
        
        # Create full key with prefix
        full_key = f"{prefix}_{random_part}"
        
        # Generate salt for additional security
        salt = secrets.token_hex(16)
        
        # Hash the key with salt
        key_hash = cls._hash_key(full_key, salt)
        
        # Extract prefix for identification (first part before first 8 chars of random)
        display_prefix = f"{prefix}_{random_part[:8]}"
        
        api_key_hash = cls(
            key_hash=key_hash,
            key_prefix=display_prefix,
            key_type=key_type,
            salt=salt,
            created_at=datetime.now(UTC)
        )
        
        return api_key_hash, full_key
    
    @classmethod
    def from_plain_key(
        cls,
        plain_key: str,
        key_type: APIKeyType,
        salt: str | None = None
    ) -> 'APIKeyHash':
        """
        Create APIKeyHash from plain text key (for verification).
        
        Used when verifying an incoming API key.
        """
        # Extract prefix
        parts = plain_key.split('_', 2)
        if len(parts) < 2:
            raise ValueError("Invalid API key format")
        
        prefix = parts[0]
        key_start = parts[1][:8] if len(parts[1]) >= 8 else parts[1]
        display_prefix = f"{prefix}_{key_start}"
        
        # Hash the key
        key_hash = cls._hash_key(plain_key, salt) if salt else hashlib.sha256(plain_key.encode()).hexdigest()
        
        return cls(
            key_hash=key_hash,
            key_prefix=display_prefix,
            key_type=key_type,
            salt=salt
        )
    
    @staticmethod
    def _hash_key(key: str, salt: str) -> str:
        """Hash API key with salt using HMAC."""
        return hmac.new(
            salt.encode(),
            key.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_key(self, plain_key: str) -> bool:
        """Verify a plain text key against this hash."""
        if self.salt:
            # Use HMAC with salt
            test_hash = self._hash_key(plain_key, self.salt)
        else:
            # Simple hash (legacy support)
            test_hash = hashlib.sha256(plain_key.encode()).hexdigest()
        
        return secrets.compare_digest(self.key_hash, test_hash)
    
    @property
    def is_service_key(self) -> bool:
        """Check if this is a service-to-service key."""
        return self.key_type in [APIKeyType.SERVICE, APIKeyType.MASTER]
    
    @property
    def is_user_key(self) -> bool:
        """Check if this is a user-specific key."""
        return self.key_type == APIKeyType.PERSONAL
    
    @property
    def is_high_privilege(self) -> bool:
        """Check if this is a high-privilege key."""
        return self.key_type in [APIKeyType.MASTER, APIKeyType.SERVICE]
    
    def requires_rotation(self, max_age_days: int = 365) -> bool:
        """
        Check if key should be rotated based on age.
        
        Different key types have different rotation requirements.
        """
        if not self.created_at:
            return True  # No creation date, should rotate
        
        age = datetime.now(UTC) - self.created_at
        
        # Different rotation periods for different key types
        rotation_periods = {
            APIKeyType.TEMPORARY: 7,  # Weekly
            APIKeyType.PERSONAL: 365,  # Yearly
            APIKeyType.SERVICE: 90,  # Quarterly
            APIKeyType.APPLICATION: 180,  # Semi-annually
            APIKeyType.WEBHOOK: 365,  # Yearly
            APIKeyType.MASTER: 30  # Monthly (high security)
        }
        
        max_days = rotation_periods.get(self.key_type, max_age_days)
        return age.days >= max_days
    
    def get_display_format(self) -> str:
        """Get display format showing only prefix."""
        return f"{self.key_prefix}...{self.key_hash[-4:]}"
    
    def get_fingerprint(self) -> str:
        """Get fingerprint for tracking."""
        # Use first and last 4 chars of hash
        return f"{self.key_hash[:4]}...{self.key_hash[-4:]}"
    
    def to_audit_entry(self) -> dict[str, Any]:
        """Create audit log entry."""
        entry = {
            'key_prefix': self.key_prefix,
            'key_type': self.key_type.value,
            'fingerprint': self.get_fingerprint(),
            'algorithm': self.algorithm,
            'has_salt': self.salt is not None
        }
        
        if self.created_at:
            entry['created_at'] = self.created_at.isoformat()
            entry['age_days'] = (datetime.now(UTC) - self.created_at).days
            entry['requires_rotation'] = self.requires_rotation()
        
        return entry
    
    def matches_prefix(self, prefix: str) -> bool:
        """Check if this key matches a given prefix."""
        return self.key_prefix.startswith(prefix)
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        return f"APIKey({self.get_display_format()})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        age_str = ""
        if self.created_at:
            age_days = (datetime.now(UTC) - self.created_at).days
            age_str = f", age={age_days}d"
        
        return f"APIKeyHash(type={self.key_type.value}, prefix={self.key_prefix}{age_str})"