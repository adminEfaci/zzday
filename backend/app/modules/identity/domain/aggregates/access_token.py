"""
Access Token Aggregate

Represents an OAuth 2.0 access token aggregate.
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from ..enums import TokenStatus, RefreshStrategy
from ..events import TokenFamilyRevoked, TokenIssued, TokenRefreshed, TokenRevoked
from ..entities.shared.base_entity import ExpirableEntity, SecurityValidationMixin


@dataclass
class TokenFamily:
    """Token family for tracking related tokens."""
    
    family_id: UUID
    root_token_id: UUID
    created_at: datetime
    status: TokenStatus = TokenStatus.ACTIVE
    member_count: int = 0
    last_refresh_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    
    def is_active(self) -> bool:
        """Check if family is active."""
        return self.status == TokenStatus.ACTIVE and (
            self.revoked_at is None or datetime.now(UTC) < self.revoked_at
        )
    
    def revoke(self, reason: str) -> None:
        """Revoke the entire token family."""
        self.status = TokenStatus.REVOKED
        self.revoked_at = datetime.now(UTC)
        self.revocation_reason = reason


@dataclass
class AccessToken(ExpirableAggregate, SecurityValidationMixin):
    """Access token aggregate for OAuth 2.0 authentication."""
    
    # REQUIRED FIELDS (no defaults) - MUST come first
    id: UUID
    user_id: UUID
    token_hash: str  # Store only the hash
    scopes: list[str]
    expires_at: datetime

    # OPTIONAL FIELDS (with defaults) - come after required fields
    client_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    revoked_at: datetime | None = None
    refresh_token_hash: str | None = None
    refresh_token_expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Enhanced refresh logic fields
    status: TokenStatus = TokenStatus.ACTIVE
    refresh_strategy: RefreshStrategy = RefreshStrategy.ROTATE
    token_family: TokenFamily | None = None
    parent_token_id: UUID | None = None  # For tracking token chains
    refresh_count: int = 0
    max_refresh_count: int = 10  # Limit refresh cycles

    # Token rotation and family tracking
    family_id: UUID | None = None
    generation: int = 1  # Token generation in family
    last_refreshed_at: datetime | None = None
    next_rotation_at: datetime | None = None

    # Security features
    rotation_jitter: int = 300  # Random seconds added to rotation time
    require_proof_of_possession: bool = False
    bound_client_certificate: str | None = None

    # Usage tracking for refresh decisions
    usage_count: int = 0
    last_used_at: datetime | None = None
    suspicious_activity_score: float = 0.0

    def _validate_entity(self) -> None:
        """Validate access token business rules."""
        # Validate token hash
        self.validate_hash(self.token_hash, "token_hash")

        if not self.scopes:
            raise ValueError("At least one scope is required")

        if self.expires_at <= self.created_at:
            raise ValueError("Token expiry must be after creation time")

        # Validate refresh token hash if present
        if self.refresh_token_hash:
            self.validate_hash(self.refresh_token_hash, "refresh_token_hash")

        # Ensure scopes list has no duplicates
        self.scopes = list(set(self.scopes))
        
        # Validate refresh strategy constraints
        if self.refresh_strategy == RefreshStrategy.FAMILY and not self.family_id:
            self.family_id = uuid4()

    @classmethod
    def create(
        cls,
        user_id: UUID,
        scopes: list[str],
        client_id: str | None = None,
        access_token_ttl: int = 3600,  # 1 hour default
        refresh_token_ttl: int | None = None  # 30 days default if enabled
    ) -> tuple['AccessToken', str, str | None]:
        """Create a new access token and return aggregate, raw token, and raw refresh token."""
        # Generate tokens
        raw_access_token = cls._generate_token()
        access_token_hash = cls._hash_token(raw_access_token)

        raw_refresh_token = None
        refresh_token_hash = None
        refresh_token_expires_at = None

        if refresh_token_ttl:
            raw_refresh_token = cls._generate_token()
            refresh_token_hash = cls._hash_token(raw_refresh_token)
            refresh_token_expires_at = datetime.now(UTC) + timedelta(seconds=refresh_token_ttl)

        token = cls(
            id=uuid4(),
            user_id=user_id,
            token_hash=access_token_hash,
            scopes=scopes,
            expires_at=datetime.now(UTC) + timedelta(seconds=access_token_ttl),
            client_id=client_id,
            refresh_token_hash=refresh_token_hash,
            refresh_token_expires_at=refresh_token_expires_at,
            created_at=datetime.now(UTC)
        )

        # Add token issued event
        token.add_domain_event(TokenIssued(
            token_id=token.id,
            user_id=user_id,
            token_type="access",
            scopes=scopes,
            client_id=client_id,
            expires_at=token.expires_at
        ))

        return token, raw_access_token, raw_refresh_token

    @staticmethod
    def _generate_token() -> str:
        """Generate a secure token."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def verify_token(self, raw_token: str) -> bool:
        """Verify if provided token matches."""
        return self._hash_token(raw_token) == self.token_hash

    def verify_refresh_token(self, raw_refresh_token: str) -> bool:
        """Verify if provided refresh token matches."""
        if not self.refresh_token_hash:
            return False
        return self._hash_token(raw_refresh_token) == self.refresh_token_hash

    def is_expired(self) -> bool:
        """Check if access token is expired."""
        if self.revoked_at:
            return True
        return datetime.now(UTC) > self.expires_at

    def is_refresh_token_expired(self) -> bool:
        """Check if refresh token is expired."""
        if not self.refresh_token_expires_at:
            return True
        if self.revoked_at:
            return True
        return datetime.now(UTC) > self.refresh_token_expires_at

    def has_scope(self, scope: str) -> bool:
        """Check if token has specific scope."""
        if self.is_expired():
            return False

        # Check for exact scope
        if scope in self.scopes:
            return True

        # Check for wildcard scopes
        for token_scope in self.scopes:
            if self._matches_scope_pattern(scope, token_scope):
                return True

        return False

    def _matches_scope_pattern(self, requested_scope: str, granted_scope: str) -> bool:
        """Check if requested scope matches granted scope pattern."""
        if granted_scope == "*":
            return True

        if "*" not in granted_scope:
            return requested_scope == granted_scope

        # Handle patterns like "read:*" or "*:user"
        pattern_parts = granted_scope.split("*")

        if len(pattern_parts) == 2:
            prefix, suffix = pattern_parts
            return requested_scope.startswith(prefix) and requested_scope.endswith(suffix)

        return False

    def revoke(self, revoked_by: UUID | None = None, reason: str = "user_revoked") -> None:
        """Revoke the access token."""
        if self.revoked_at:
            return  # Already revoked

        self.revoked_at = datetime.now(UTC)

        self.add_domain_event(TokenRevoked(
            user_id=self.user_id,
            token_id=self.id,
            token_type="access",
            revoked_by=revoked_by,
            revocation_reason=reason
        ))

    def refresh(self, new_ttl: int = 3600, refresh_ttl: int | None = None) -> tuple['AccessToken', str, str | None]:
        """Create a new access token from refresh token with enhanced refresh logic."""
        if not self.can_refresh():
            raise ValueError("Token cannot be refreshed")

        if self.refresh_count >= self.max_refresh_count:
            raise ValueError(f"Maximum refresh count ({self.max_refresh_count}) exceeded")

        # Apply refresh strategy
        if self.refresh_strategy == RefreshStrategy.ROTATE:
            return self._refresh_with_rotation(new_ttl, refresh_ttl)
        if self.refresh_strategy == RefreshStrategy.REUSE:
            return self._refresh_with_reuse(new_ttl)
        if self.refresh_strategy == RefreshStrategy.FAMILY:
            return self._refresh_with_family_tracking(new_ttl, refresh_ttl)
        # Default to rotation
        return self._refresh_with_rotation(new_ttl, refresh_ttl)

    def _refresh_with_rotation(self, new_ttl: int, refresh_ttl: int | None) -> tuple['AccessToken', str, str | None]:
        """Refresh token with rotation strategy."""
        # Generate new tokens
        raw_access_token = self._generate_token()
        access_token_hash = self._hash_token(raw_access_token)

        raw_refresh_token = None
        refresh_token_hash = None
        refresh_token_expires_at = None

        if refresh_ttl:
            raw_refresh_token = self._generate_token()
            refresh_token_hash = self._hash_token(raw_refresh_token)
            refresh_token_expires_at = datetime.now(UTC) + timedelta(seconds=refresh_ttl)

        # Create new token
        new_token = AccessToken(
            id=uuid4(),
            user_id=self.user_id,
            token_hash=access_token_hash,
            scopes=self.scopes.copy(),
            expires_at=datetime.now(UTC) + timedelta(seconds=new_ttl),
            client_id=self.client_id,
            refresh_token_hash=refresh_token_hash,
            refresh_token_expires_at=refresh_token_expires_at,
            status=TokenStatus.ACTIVE,
            refresh_strategy=self.refresh_strategy,
            parent_token_id=self.id,
            refresh_count=self.refresh_count + 1,
            family_id=self.family_id or uuid4(),
            generation=self.generation + 1,
            last_refreshed_at=datetime.now(UTC),
            metadata=self.metadata.copy()
        )

        # Add refresh event
        new_token.add_domain_event(TokenRefreshed(
            token_id=new_token.id,
            user_id=self.user_id,
            old_token_id=self.id,
            refresh_strategy=self.refresh_strategy.value,
            generation=new_token.generation
        ))

        # Revoke old token
        self.status = TokenStatus.REVOKED
        self.revoked_at = datetime.now(UTC)

        return new_token, raw_access_token, raw_refresh_token

    def _refresh_with_reuse(self, new_ttl: int) -> tuple['AccessToken', str, str | None]:
        """Refresh token with reuse strategy (keep same refresh token)."""
        raw_access_token = self._generate_token()
        access_token_hash = self._hash_token(raw_access_token)

        new_token = AccessToken(
            id=uuid4(),
            user_id=self.user_id,
            token_hash=access_token_hash,
            scopes=self.scopes.copy(),
            expires_at=datetime.now(UTC) + timedelta(seconds=new_ttl),
            client_id=self.client_id,
            refresh_token_hash=self.refresh_token_hash,  # Reuse same refresh token
            refresh_token_expires_at=self.refresh_token_expires_at,
            status=TokenStatus.ACTIVE,
            refresh_strategy=self.refresh_strategy,
            parent_token_id=self.id,
            refresh_count=self.refresh_count + 1,
            family_id=self.family_id or uuid4(),
            generation=self.generation + 1,
            last_refreshed_at=datetime.now(UTC),
            metadata=self.metadata.copy()
        )

        new_token.add_domain_event(TokenRefreshed(
            token_id=new_token.id,
            user_id=self.user_id,
            old_token_id=self.id,
            refresh_strategy=self.refresh_strategy.value,
            generation=new_token.generation
        ))

        self.status = TokenStatus.REVOKED
        self.revoked_at = datetime.now(UTC)

        return new_token, raw_access_token, None  # No new refresh token

    def _refresh_with_family_tracking(self, new_ttl: int, refresh_ttl: int | None) -> tuple['AccessToken', str, str | None]:
        """Refresh token with family tracking for automatic revocation."""
        # Ensure family exists
        if not self.token_family:
            self.token_family = TokenFamily(
                family_id=self.family_id or uuid4(),
                root_token_id=self.id,
                created_at=self.created_at,
                status=TokenStatus.ACTIVE,
                member_count=1
            )
            self.family_id = self.token_family.family_id

        # Check family status
        if not self.token_family.is_active():
            raise ValueError("Token family has been revoked")

        # Generate new tokens
        raw_access_token = self._generate_token()
        access_token_hash = self._hash_token(raw_access_token)

        raw_refresh_token = None
        refresh_token_hash = None
        refresh_token_expires_at = None

        if refresh_ttl:
            raw_refresh_token = self._generate_token()
            refresh_token_hash = self._hash_token(raw_refresh_token)
            refresh_token_expires_at = datetime.now(UTC) + timedelta(seconds=refresh_ttl)

        # Create new token in same family
        new_token = AccessToken(
            id=uuid4(),
            user_id=self.user_id,
            token_hash=access_token_hash,
            scopes=self.scopes.copy(),
            expires_at=datetime.now(UTC) + timedelta(seconds=new_ttl),
            client_id=self.client_id,
            refresh_token_hash=refresh_token_hash,
            refresh_token_expires_at=refresh_token_expires_at,
            status=TokenStatus.ACTIVE,
            refresh_strategy=self.refresh_strategy,
            token_family=self.token_family,
            parent_token_id=self.id,
            refresh_count=self.refresh_count + 1,
            family_id=self.family_id,
            generation=self.generation + 1,
            last_refreshed_at=datetime.now(UTC),
            metadata=self.metadata.copy()
        )
        
        # Update family
        self.token_family.member_count += 1
        self.token_family.last_refresh_at = datetime.now(UTC)
        
        new_token.add_domain_event(TokenRefreshed(
            token_id=new_token.id,
            user_id=self.user_id,
            old_token_id=self.id,
            refresh_strategy=self.refresh_strategy.value,
            generation=new_token.generation
        ))
        
        self.status = TokenStatus.REVOKED
        self.revoked_at = datetime.now(UTC)
        
        return new_token, raw_access_token, raw_refresh_token
    
    def can_refresh(self) -> bool:
        """Check if token can be refreshed."""
        if not self.refresh_token_hash:
            return False
        
        if self.is_refresh_token_expired():
            return False
        
        if self.status != TokenStatus.ACTIVE:
            return False
        
        if self.refresh_count >= self.max_refresh_count:
            return False
        
        # Check family status if using family strategy
        if self.refresh_strategy == RefreshStrategy.FAMILY and self.token_family:
            if not self.token_family.is_active():
                return False
        
        return True
    
    def should_refresh(self) -> bool:
        """Check if token should be refreshed based on expiry and rotation schedule."""
        if not self.can_refresh():
            return False
        
        # Check if access token is close to expiry
        remaining = self.get_time_until_expiry()
        if remaining <= timedelta(minutes=5):  # Refresh 5 minutes before expiry
            return True
        
        # Check if scheduled rotation is due
        return bool(self.next_rotation_at and datetime.now(UTC) >= self.next_rotation_at)
    
    def revoke_family(self, reason: str = "security_incident") -> None:
        """Revoke entire token family."""
        if self.token_family:
            self.token_family.revoke(reason)
            
            self.add_domain_event(TokenFamilyRevoked(
                family_id=self.family_id,
                user_id=self.user_id,
                revocation_reason=reason,
                member_count=self.token_family.member_count
            ))
    
    def detect_suspicious_refresh_pattern(self, recent_refreshes: list[datetime]) -> bool:
        """Detect suspicious refresh patterns that might indicate token theft."""
        if len(recent_refreshes) < 2:
            return False
        
        # Check for rapid successive refreshes (possible replay attack)
        rapid_refreshes = 0
        for i in range(1, len(recent_refreshes)):
            time_diff = (recent_refreshes[i] - recent_refreshes[i-1]).total_seconds()
            if time_diff < 60:  # Less than 1 minute between refreshes
                rapid_refreshes += 1
        
        if rapid_refreshes >= 3:
            self.suspicious_activity_score += 0.5
            return True
        
        # Check for impossible refresh timing
        if len(recent_refreshes) >= 5:
            time_span = (recent_refreshes[-1] - recent_refreshes[0]).total_seconds()
            if time_span < 300:  # 5 refreshes in less than 5 minutes
                self.suspicious_activity_score += 0.3
                return True
        
        return False
    
    def record_usage(self) -> None:
        """Record token usage for analytics and refresh decisions."""
        self.usage_count += 1
        self.last_used_at = datetime.now(UTC)
        
        # Schedule next rotation with jitter if not already scheduled
        if not self.next_rotation_at and self.refresh_strategy == RefreshStrategy.ROTATE:
            base_rotation_time = self.expires_at - timedelta(minutes=10)
            jitter_seconds = secrets.randbelow(self.rotation_jitter)
            self.next_rotation_at = base_rotation_time + timedelta(seconds=jitter_seconds)
    
    def extend_expiry(self, additional_seconds: int) -> None:
        """Extend token expiry time."""
        if self.status != TokenStatus.ACTIVE:
            raise ValueError("Cannot extend inactive token")
        
        self.expires_at += timedelta(seconds=additional_seconds)
        
        # Update rotation schedule if applicable
        if self.next_rotation_at:
            self.next_rotation_at += timedelta(seconds=additional_seconds)
    
    def suspend(self, reason: str, duration: timedelta | None = None) -> None:
        """Suspend token temporarily."""
        self.status = TokenStatus.SUSPENDED
        self.metadata["suspension_reason"] = reason
        self.metadata["suspended_at"] = datetime.now(UTC).isoformat()
        
        if duration:
            resume_at = datetime.now(UTC) + duration
            self.metadata["resume_at"] = resume_at.isoformat()
    
    def resume(self) -> None:
        """Resume suspended token."""
        if self.status != TokenStatus.SUSPENDED:
            raise ValueError("Token is not suspended")
        
        # Check if suspension period has passed
        if "resume_at" in self.metadata:
            resume_at = datetime.fromisoformat(self.metadata["resume_at"])
            if datetime.now(UTC) < resume_at:
                raise ValueError("Suspension period has not ended")
        
        self.status = TokenStatus.ACTIVE
        self.metadata["resumed_at"] = datetime.now(UTC).isoformat()
        
        # Clear suspension metadata
        self.metadata.pop("suspension_reason", None)
        self.metadata.pop("suspended_at", None)
        self.metadata.pop("resume_at", None)
    
    def validate_proof_of_possession(self, client_certificate: str) -> bool:
        """Validate proof of possession for certificate-bound tokens."""
        if not self.require_proof_of_possession:
            return True
        
        if not self.bound_client_certificate:
            return False
        
        return self.bound_client_certificate == client_certificate
    
    def get_refresh_history(self) -> dict[str, Any]:
        """Get refresh history and family information."""
        return {
            "token_id": str(self.id),
            "family_id": str(self.family_id) if self.family_id else None,
            "generation": self.generation,
            "refresh_count": self.refresh_count,
            "max_refresh_count": self.max_refresh_count,
            "refresh_strategy": self.refresh_strategy.value,
            "parent_token_id": str(self.parent_token_id) if self.parent_token_id else None,
            "last_refreshed_at": self.last_refreshed_at.isoformat() if self.last_refreshed_at else None,
            "next_rotation_at": self.next_rotation_at.isoformat() if self.next_rotation_at else None,
            "family_status": self.token_family.status.value if self.token_family else "no_family",
            "family_member_count": self.token_family.member_count if self.token_family else 0,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "suspicious_activity_score": round(self.suspicious_activity_score, 3)
        }
    
    def get_time_until_expiry(self) -> timedelta:
        """Get time remaining until token expires."""
        if self.is_expired():
            return timedelta(0)
        
        return self.expires_at - datetime.now(UTC)
    
    def get_token_info(self) -> dict[str, Any]:
        """Get token information for display."""
        return {
            "id": str(self.id),
            "scopes": self.scopes,
            "client_id": self.client_id,
            "expires_at": self.expires_at.isoformat(),
            "expires_in": int(self.get_time_until_expiry().total_seconds()),
            "is_expired": self.is_expired(),
            "has_refresh_token": bool(self.refresh_token_hash),
            "refresh_token_expires_at": self.refresh_token_expires_at.isoformat() if self.refresh_token_expires_at else None
        }
    
    def to_oauth_response(self, access_token: str, refresh_token: str | None = None) -> dict[str, Any]:
        """Convert to OAuth 2.0 token response format."""
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": int(self.get_time_until_expiry().total_seconds()),
            "scope": " ".join(self.scopes)
        }
        
        if refresh_token:
            response["refresh_token"] = refresh_token
        
        return response
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        base_dict = {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "token_hash": self.token_hash,
            "scopes": self.scopes,
            "client_id": self.client_id,
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "refresh_token_hash": self.refresh_token_hash,
            "refresh_token_expires_at": self.refresh_token_expires_at.isoformat() if self.refresh_token_expires_at else None,
            "metadata": self.metadata
        }
        
        # Add enhanced refresh logic fields
        base_dict.update({
            "status": self.status.value,
            "refresh_strategy": self.refresh_strategy.value,
            "parent_token_id": str(self.parent_token_id) if self.parent_token_id else None,
            "refresh_count": self.refresh_count,
            "max_refresh_count": self.max_refresh_count,
            "family_id": str(self.family_id) if self.family_id else None,
            "generation": self.generation,
            "last_refreshed_at": self.last_refreshed_at.isoformat() if self.last_refreshed_at else None,
            "next_rotation_at": self.next_rotation_at.isoformat() if self.next_rotation_at else None,
            "rotation_jitter": self.rotation_jitter,
            "require_proof_of_possession": self.require_proof_of_possession,
            "bound_client_certificate": self.bound_client_certificate,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "suspicious_activity_score": round(self.suspicious_activity_score, 3),
            "token_family": {
                "family_id": str(self.token_family.family_id),
                "root_token_id": str(self.token_family.root_token_id),
                "created_at": self.token_family.created_at.isoformat(),
                "status": self.token_family.status.value,
                "member_count": self.token_family.member_count,
                "last_refresh_at": self.token_family.last_refresh_at.isoformat() if self.token_family.last_refresh_at else None,
                "revoked_at": self.token_family.revoked_at.isoformat() if self.token_family.revoked_at else None,
                "revocation_reason": self.token_family.revocation_reason
            } if self.token_family else None
        })
        
        return base_dict