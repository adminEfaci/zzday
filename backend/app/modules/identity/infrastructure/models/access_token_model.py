"""
Access Token Model

SQLModel definition for access token persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.modules.identity.domain.entities.admin.access_token import (
    AccessToken,
    RefreshStrategy,
    TokenStatus,
)


class AccessTokenModel(SQLModel, table=True):
    """Access token persistence model."""
    
    __tablename__ = "access_tokens"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    session_id: UUID | None = Field(default=None, index=True)
    
    # Token data
    token_hash: str = Field(index=True)
    scopes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    client_id: str | None = Field(default=None, index=True)
    
    # Refresh token
    refresh_token_hash: str | None = Field(default=None, index=True)
    refresh_token_expires_at: datetime | None = Field(default=None)
    
    # Status and strategy
    status: str = Field(default=TokenStatus.ACTIVE.value, index=True)
    refresh_strategy: str = Field(default=RefreshStrategy.ROTATE.value)
    
    # Token family tracking
    family_id: UUID | None = Field(default=None, index=True)
    parent_token_id: UUID | None = Field(default=None)
    generation: int = Field(default=1)
    refresh_count: int = Field(default=0)
    max_refresh_count: int = Field(default=10)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    expires_at: datetime = Field(index=True)
    revoked_at: datetime | None = Field(default=None)
    last_refreshed_at: datetime | None = Field(default=None)
    next_rotation_at: datetime | None = Field(default=None)
    
    # Usage tracking
    usage_count: int = Field(default=0)
    last_used_at: datetime | None = Field(default=None)
    suspicious_activity_score: float = Field(default=0.0)
    
    # Security features
    rotation_jitter: int = Field(default=300)
    require_proof_of_possession: bool = Field(default=False)
    bound_client_certificate: str | None = Field(default=None)
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Flags
    is_valid: bool = Field(default=True, index=True)
    
    @classmethod
    def from_domain(cls, token: AccessToken) -> "AccessTokenModel":
        """Create model from domain entity."""
        return cls(
            id=token.id,
            user_id=token.user_id,
            token_hash=token.token_hash,
            scopes=token.scopes[:],  # Copy list
            client_id=token.client_id,
            created_at=token.created_at,
            expires_at=token.expires_at,
            revoked_at=token.revoked_at,
            refresh_token_hash=token.refresh_token_hash,
            refresh_token_expires_at=token.refresh_token_expires_at,
            metadata=token.metadata.copy(),
            status=token.status.value if isinstance(token.status, TokenStatus) else token.status,
            refresh_strategy=token.refresh_strategy.value if isinstance(token.refresh_strategy, RefreshStrategy) else token.refresh_strategy,
            family_id=token.family_id,
            parent_token_id=token.parent_token_id,
            generation=token.generation,
            refresh_count=token.refresh_count,
            max_refresh_count=token.max_refresh_count,
            last_refreshed_at=token.last_refreshed_at,
            next_rotation_at=token.next_rotation_at,
            rotation_jitter=token.rotation_jitter,
            require_proof_of_possession=token.require_proof_of_possession,
            bound_client_certificate=token.bound_client_certificate,
            usage_count=token.usage_count,
            last_used_at=token.last_used_at,
            suspicious_activity_score=token.suspicious_activity_score,
            is_valid=token.status == TokenStatus.ACTIVE and token.revoked_at is None
        )
    
    def to_domain(self) -> AccessToken:
        """Convert to domain entity."""
        # Reconstruct enums
        status = TokenStatus(self.status) if self.status else TokenStatus.ACTIVE
        refresh_strategy = RefreshStrategy(self.refresh_strategy) if self.refresh_strategy else RefreshStrategy.ROTATE
        
        # Create token instance
        token = AccessToken(
            id=self.id,
            user_id=self.user_id,
            token_hash=self.token_hash,
            scopes=self.scopes[:],  # Copy list
            expires_at=self.expires_at,
            client_id=self.client_id,
            created_at=self.created_at,
            revoked_at=self.revoked_at,
            refresh_token_hash=self.refresh_token_hash,
            refresh_token_expires_at=self.refresh_token_expires_at,
            metadata=self.metadata.copy() if self.metadata else {},
            status=status,
            refresh_strategy=refresh_strategy,
            family_id=self.family_id,
            parent_token_id=self.parent_token_id,
            generation=self.generation,
            refresh_count=self.refresh_count,
            max_refresh_count=self.max_refresh_count,
            last_refreshed_at=self.last_refreshed_at,
            next_rotation_at=self.next_rotation_at,
            rotation_jitter=self.rotation_jitter,
            require_proof_of_possession=self.require_proof_of_possession,
            bound_client_certificate=self.bound_client_certificate,
            usage_count=self.usage_count,
            last_used_at=self.last_used_at,
            suspicious_activity_score=self.suspicious_activity_score
        )
        
        return token