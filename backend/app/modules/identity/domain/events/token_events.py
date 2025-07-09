"""Token-related domain events."""

from datetime import datetime
from uuid import UUID

from .base import IdentityDomainEvent


class TokenIssued(IdentityDomainEvent):
    """Event raised when an access token is issued."""
    token_id: UUID
    user_id: UUID
    token_type: str
    scopes: list[str]
    client_id: str | None = None
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenRefreshed(IdentityDomainEvent):
    """Event raised when a token is refreshed."""
    token_id: UUID
    user_id: UUID
    old_token_id: UUID
    refresh_strategy: str
    generation: int

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenRevoked(IdentityDomainEvent):
    """Event raised when a token is revoked."""
    user_id: UUID
    token_id: UUID
    token_type: str
    revoked_by: UUID | None = None
    revocation_reason: str = "user_revoked"

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenFamilyRevoked(IdentityDomainEvent):
    """Event raised when an entire token family is revoked."""
    family_id: UUID
    user_id: UUID
    revocation_reason: str
    member_count: int

    def get_aggregate_id(self) -> str:
        return str(self.family_id)