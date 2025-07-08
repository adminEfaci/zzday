"""
Session Model

SQLModel definition for session persistence.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from sqlmodel import Field, SQLModel, Column, JSON
from app.modules.identity.domain.entities.session.session import Session
from app.modules.identity.domain.entities.session.session_enums import SessionStatus, SessionType
from app.modules.identity.domain.value_objects.token import Token, TokenType
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.user_agent import UserAgent
from app.modules.identity.domain.value_objects.device_fingerprint import DeviceFingerprint
from app.modules.identity.domain.value_objects.geolocation import Geolocation


class SessionModel(SQLModel, table=True):
    """Session persistence model."""
    
    __tablename__ = "sessions"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    session_type: str = Field(index=True)
    status: str = Field(index=True)
    
    # Tokens
    access_token: str = Field(index=True)
    refresh_token: str | None = Field(default=None, index=True)
    
    # Device info
    ip_address: str | None = Field(default=None, index=True)
    user_agent: str | None = Field(default=None)
    device_fingerprint: str | None = Field(default=None, index=True)
    
    # Location (stored as JSON)
    geolocation: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    
    # Session properties
    is_trusted: bool = Field(default=False)
    requires_mfa: bool = Field(default=False)
    mfa_completed: bool = Field(default=False)
    
    # Activity tracking
    last_activity_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    last_refresh_at: datetime | None = Field(default=None)
    activity_count: int = Field(default=0)
    
    # Flags and metadata
    flags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Security
    risk_score: float = Field(default=0.0)
    security_events: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    expires_at: datetime | None = Field(default=None, index=True)
    
    @classmethod
    def from_domain(cls, session: Session) -> "SessionModel":
        """Create model from domain entity."""
        return cls(
            id=session.id,
            user_id=session.user_id,
            session_type=session.session_type.value if isinstance(session.session_type, SessionType) else session.session_type,
            status=session.status.value if isinstance(session.status, SessionStatus) else session.status,
            access_token=session.access_token.value if isinstance(session.access_token, Token) else session.access_token,
            refresh_token=session.refresh_token.value if session.refresh_token and isinstance(session.refresh_token, Token) else session.refresh_token,
            ip_address=session.ip_address.value if session.ip_address and isinstance(session.ip_address, IpAddress) else session.ip_address,
            user_agent=session.user_agent.value if session.user_agent and isinstance(session.user_agent, UserAgent) else session.user_agent,
            device_fingerprint=session.device_fingerprint.value if session.device_fingerprint and isinstance(session.device_fingerprint, DeviceFingerprint) else session.device_fingerprint,
            geolocation=session.geolocation.to_dict() if session.geolocation and isinstance(session.geolocation, Geolocation) else session.geolocation,
            is_trusted=session.is_trusted,
            requires_mfa=session.requires_mfa,
            mfa_completed=session.mfa_completed,
            last_activity_at=session.last_activity_at,
            last_refresh_at=session.last_refresh_at,
            activity_count=session.activity_count,
            flags=list(session.flags),
            metadata=session.metadata,
            risk_score=session.risk_score,
            security_events=session.security_events,
            created_at=session.created_at,
            expires_at=session._calculate_expiry() if hasattr(session, '_calculate_expiry') else None,
        )
    
    def to_domain(self) -> Session:
        """Convert to domain entity."""
        # Reconstruct value objects
        access_token = Token(value=self.access_token, token_type=TokenType.ACCESS) if self.access_token else None
        refresh_token = Token(value=self.refresh_token, token_type=TokenType.REFRESH) if self.refresh_token else None
        ip_address = IpAddress(self.ip_address) if self.ip_address else None
        user_agent = UserAgent(self.user_agent) if self.user_agent else None
        device_fingerprint = DeviceFingerprint(self.device_fingerprint) if self.device_fingerprint else None
        
        # Handle Geolocation
        geolocation = None
        if self.geolocation:
            try:
                geolocation = Geolocation(**self.geolocation)
            except:
                geolocation = self.geolocation
        
        # Handle enums
        session_type = SessionType(self.session_type) if self.session_type else SessionType.WEB
        status = SessionStatus(self.status) if self.status else SessionStatus.ACTIVE
        
        # Create session instance
        session = Session(
            id=self.id,
            user_id=self.user_id,
            session_type=session_type,
            status=status,
            access_token=access_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            geolocation=geolocation,
            is_trusted=self.is_trusted,
            requires_mfa=self.requires_mfa,
            mfa_completed=self.mfa_completed,
            last_activity_at=self.last_activity_at,
            last_refresh_at=self.last_refresh_at,
            activity_count=self.activity_count,
            flags=set(self.flags) if self.flags else set(),
            metadata=self.metadata or {},
            risk_score=self.risk_score,
            security_events=self.security_events or [],
            created_at=self.created_at,
        )
        
        return session