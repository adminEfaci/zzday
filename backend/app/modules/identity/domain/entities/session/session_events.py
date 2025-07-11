"""
Session Entity Events

Domain events related to session lifecycle and token management.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from ...events import IdentityDomainEvent


# Session Lifecycle Events
class SessionCreated(IdentityDomainEvent):
    """Event raised when a new session is created."""
    session_id: UUID
    user_id: UUID
    ip_address: str
    user_agent: str
    device_info: dict[str, Any]
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionExpired(IdentityDomainEvent):
    """Event raised when a session expires."""
    session_id: UUID
    user_id: UUID
    expired_at: datetime
    reason: str = Field(default="timeout")
    automatic_cleanup: bool = Field(default=True)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionRevoked(IdentityDomainEvent):
    """Event raised when a session is manually revoked."""
    session_id: UUID
    user_id: UUID
    revoked_by: UUID | None = None
    reason: str = Field(default="user_logout")
    revoke_all_sessions: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionSuspended(IdentityDomainEvent):
    """Event raised when session is suspended."""
    session_id: UUID
    user_id: UUID
    reason: str
    suspended_until: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionResumed(IdentityDomainEvent):
    """Event raised when session is resumed."""
    session_id: UUID
    user_id: UUID

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# Token Events
class TokenRefreshed(IdentityDomainEvent):
    """Event raised when refresh token is used to obtain new access token."""
    user_id: UUID
    session_id: UUID
    old_token_id: UUID
    new_token_id: UUID
    ip_address: str
    user_agent: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class TokenRevoked(IdentityDomainEvent):
    """Event raised when a token is revoked."""
    user_id: UUID
    token_id: UUID
    token_type: str  # access, refresh
    revoked_by: UUID | None
    revocation_reason: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# Authentication Events
class SessionMFACompleted(IdentityDomainEvent):
    """Event raised when MFA is completed for a session."""
    session_id: UUID
    user_id: UUID
    completion_time: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionPrivilegeElevated(IdentityDomainEvent):
    """Event raised when session privileges are elevated."""
    session_id: UUID
    user_id: UUID
    reason: str
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# Security Events
class SessionSecurityEvent(IdentityDomainEvent):
    """Event raised for session security incidents."""
    session_id: UUID
    user_id: UUID
    event_type: str
    risk_level: str
    details: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionLocationChanged(IdentityDomainEvent):
    """Event raised when session location changes significantly."""
    session_id: UUID
    user_id: UUID
    old_location: str | None
    new_location: str
    distance_km: float | None = None
    flagged_as_suspicious: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionRiskScoreChanged(IdentityDomainEvent):
    """Event raised when session risk score changes significantly."""
    session_id: UUID
    user_id: UUID
    old_risk_score: float
    new_risk_score: float
    trigger_event: str
    automatic_action_taken: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# Export all events
__all__ = [
    'SessionCreated',
    'SessionExpired',
    'SessionRevoked',
    'SessionSuspended', 
    'SessionResumed',
    'TokenRefreshed',
    'TokenRevoked',
    'SessionMFACompleted',
    'SessionPrivilegeElevated',
    'SessionSecurityEvent',
    'SessionLocationChanged',
    'SessionRiskScoreChanged'
]