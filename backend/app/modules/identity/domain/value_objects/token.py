"""
Token Value Object

Immutable representation of authentication/authorization tokens.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.domain.base import ValueObject


class TokenType(Enum):
    """Types of tokens."""
    
    ACCESS = "access"
    REFRESH = "refresh"
    ID = "id"
    SESSION = "session"
    API_KEY = "api_key"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION = "email_verification"
    MFA = "mfa"
    CHALLENGE = "challenge"
    DEVICE_REGISTRATION = "device_registration"
    DELEGATION = "delegation"
    IMPERSONATION = "impersonation"
    SERVICE = "service"


class TokenFormat(Enum):
    """Token format types."""
    
    OPAQUE = "opaque"  # Random string
    JWT = "jwt"  # JSON Web Token
    PASETO = "paseto"  # Platform-Agnostic Security Tokens
    MACAROON = "macaroon"  # Macaroon tokens


@dataclass(frozen=True)
class Token(ValueObject):
    """
    Value object representing a security token.
    
    Encapsulates token value, type, and metadata for various authentication
    and authorization scenarios.
    """
    
    value: str
    token_type: TokenType
    token_format: TokenFormat
    issued_at: datetime
    expires_at: datetime | None = None
    issuer: str | None = None
    subject: str | None = None  # User ID or entity the token represents
    audience: str | None = None  # Intended recipient
    scope: str | None = None  # Space-delimited scopes
    claims: dict[str, Any] = None
    id: UUID | None = None  # Add id field for compatibility
    
    def __post_init__(self):
        """Validate token."""
        if not self.value or not self.value.strip():
            raise ValueError("Token value is required")
        
        # Validate token format
        if self.token_format == TokenFormat.OPAQUE:
            # Opaque tokens should be sufficiently random
            if len(self.value) < 32:
                raise ValueError("Opaque tokens must be at least 32 characters")
        elif self.token_format == TokenFormat.JWT:
            # Basic JWT validation (three parts separated by dots)
            parts = self.value.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
        
        # Ensure issued_at is timezone-aware
        if self.issued_at.tzinfo is None:
            object.__setattr__(self, 'issued_at', self.issued_at.replace(tzinfo=UTC))
        
        # Validate expiration
        if self.expires_at:
            if self.expires_at.tzinfo is None:
                object.__setattr__(self, 'expires_at', self.expires_at.replace(tzinfo=UTC))
            if self.expires_at <= self.issued_at:
                raise ValueError("Token expiration must be after issuance")
        
        # Initialize claims if not provided
        if self.claims is None:
            object.__setattr__(self, 'claims', {})
    
    @classmethod
    def generate(
        cls,
        token_type: TokenType,
        subject: str | None = None,
        expires_in: timedelta | None = None,
        issuer: str | None = None,
        length: int = 32
    ) -> 'Token':
        """Generate a new token (shorthand for generate_opaque)."""
        return cls.generate_opaque(
            token_type=token_type,
            subject=subject,
            expires_in=expires_in,
            issuer=issuer,
            length=length
        )
    
    @classmethod
    def generate_opaque(
        cls,
        token_type: TokenType,
        subject: str | None = None,
        expires_in: timedelta | None = None,
        issuer: str | None = None,
        length: int = 32
    ) -> 'Token':
        """Generate a new opaque (random) token."""
        # Generate cryptographically secure random token
        token_value = secrets.token_urlsafe(length)
        
        issued_at = datetime.now(UTC)
        expires_at = issued_at + expires_in if expires_in else None
        
        return cls(
            value=token_value,
            token_type=token_type,
            token_format=TokenFormat.OPAQUE,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=issuer,
            subject=subject
        )
    
    @classmethod
    def from_jwt_claims(
        cls,
        jwt_value: str,
        token_type: TokenType,
        claims: dict[str, Any]
    ) -> 'Token':
        """Create Token from JWT value and decoded claims."""
        # Standard JWT claims
        issued_at = datetime.fromtimestamp(
            claims.get('iat', datetime.now(UTC).timestamp()),
            tz=UTC
        )
        expires_at = datetime.fromtimestamp(claims['exp'], tz=UTC) if 'exp' in claims else None
        
        return cls(
            value=jwt_value,
            token_type=token_type,
            token_format=TokenFormat.JWT,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer=claims.get('iss'),
            subject=claims.get('sub'),
            audience=claims.get('aud'),
            scope=claims.get('scope'),
            claims={k: v for k, v in claims.items() if k not in ['iat', 'exp', 'iss', 'sub', 'aud', 'scope']}
        )
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False  # No expiration
        return datetime.now(UTC) > self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if token is currently active (issued and not expired)."""
        now = datetime.now(UTC)
        if now < self.issued_at:
            return False  # Not yet valid
        return not self.is_expired
    
    @property
    def time_to_expiry(self) -> timedelta | None:
        """Get time remaining until expiration."""
        if not self.expires_at:
            return None
        
        remaining = self.expires_at - datetime.now(UTC)
        return remaining if remaining > timedelta() else timedelta()
    
    @property
    def lifetime(self) -> timedelta | None:
        """Get total token lifetime."""
        if not self.expires_at:
            return None
        return self.expires_at - self.issued_at
    
    @property
    def age(self) -> timedelta:
        """Get token age since issuance."""
        return datetime.now(UTC) - self.issued_at
    
    @property
    def is_short_lived(self) -> bool:
        """Check if token is short-lived (less than 1 hour lifetime)."""
        lifetime = self.lifetime
        return lifetime is not None and lifetime < timedelta(hours=1)
    
    @property
    def is_long_lived(self) -> bool:
        """Check if token is long-lived (more than 24 hours lifetime)."""
        lifetime = self.lifetime
        return lifetime is not None and lifetime > timedelta(days=1)
    
    @property
    def requires_refresh(self, threshold: float = 0.8) -> bool:
        """
        Check if token should be refreshed.
        
        Returns True if more than threshold (default 80%) of lifetime has passed.
        """
        if not self.expires_at or self.is_expired:
            return True
        
        lifetime = self.lifetime
        if not lifetime:
            return False
        
        age = self.age
        return (age.total_seconds() / lifetime.total_seconds()) > threshold
    
    def get_scopes(self) -> list[str]:
        """Get list of scopes from space-delimited string."""
        if not self.scope:
            return []
        return self.scope.split()
    
    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope."""
        return scope in self.get_scopes()
    
    def get_fingerprint(self) -> str:
        """
        Generate a fingerprint of the token for tracking/logging.
        
        Never logs the actual token value.
        """
        # Create a hash of the token for safe logging
        hash_input = f"{self.token_type.value}:{self.value}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def mask_value(self, visible_chars: int = 4) -> str:
        """Get masked token value for display."""
        if len(self.value) <= visible_chars * 2:
            return '*' * len(self.value)
        
        return f"{self.value[:visible_chars]}...{self.value[-visible_chars:]}"
    
    def to_audit_entry(self) -> dict[str, Any]:
        """Create audit log entry (without sensitive data)."""
        return {
            'token_fingerprint': self.get_fingerprint(),
            'token_type': self.token_type.value,
            'token_format': self.token_format.value,
            'issued_at': self.issued_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'issuer': self.issuer,
            'subject': self.subject,
            'audience': self.audience,
            'scopes': self.get_scopes(),
            'is_expired': self.is_expired,
            'is_active': self.is_active,
            'age_seconds': int(self.age.total_seconds())
        }
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        return f"Token(type={self.token_type.value}, fingerprint={self.get_fingerprint()[:8]}...)"
    
    def __repr__(self) -> str:
        """Debug representation (safe for logging)."""
        status = "active" if self.is_active else "expired" if self.is_expired else "not-yet-valid"
        return f"Token(type={self.token_type.value}, status={status}, format={self.token_format.value})"
