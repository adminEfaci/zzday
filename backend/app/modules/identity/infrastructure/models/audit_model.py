"""
Audit Models

SQLModel definitions for login attempts and security events persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel, Text


class LoginAttemptModel(SQLModel, table=True):
    """Login attempt persistence model."""
    
    __tablename__ = "login_attempts"
    
    # Identity
    id: UUID = Field(primary_key=True)
    email: str = Field(index=True)
    user_id: UUID | None = Field(default=None, index=True)
    session_id: UUID | None = Field(default=None, index=True)
    
    # Attempt details
    success: bool = Field(index=True)
    failure_reason: str | None = Field(default=None, index=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    
    # IP and device info
    ip_address: str = Field(index=True)
    user_agent: str | None = Field(default=None)
    device_fingerprint: str | None = Field(default=None, index=True)
    mfa_used: bool = Field(default=False)
    
    # Location info
    country: str | None = Field(default=None, index=True)
    city: str | None = Field(default=None)
    latitude: float | None = Field(default=None)
    longitude: float | None = Field(default=None)
    isp: str | None = Field(default=None)
    organization: str | None = Field(default=None)
    
    # Risk assessment
    risk_score: float = Field(default=0.0, index=True)
    risk_indicators: list[str] = Field(default=[], sa_column=Column(JSON))
    risk_breakdown: dict[str, float] = Field(default={}, sa_column=Column(JSON))
    
    # Behavioral analysis
    login_velocity: int = Field(default=0)
    unique_ips_used: int = Field(default=0)
    failed_attempts_24h: int = Field(default=0)
    last_successful_login: datetime | None = Field(default=None)
    typical_login_hours: list[int] = Field(default=[], sa_column=Column(JSON))
    
    # Device and location trust
    device_trust_score: float = Field(default=0.0)
    location_trust_score: float = Field(default=0.0)
    is_known_device: bool = Field(default=False)
    is_known_location: bool = Field(default=False)
    
    # Attack patterns
    is_distributed_attack: bool = Field(default=False)
    attack_pattern: str | None = Field(default=None)
    credential_stuffing_score: float = Field(default=0.0)
    
    # ML features
    ml_risk_score: float | None = Field(default=None)
    ml_confidence: float | None = Field(default=None)
    ml_features: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    class Config:
        """SQLModel configuration."""
        validate_assignment = True


class SecurityEventModel(SQLModel, table=True):
    """Security event persistence model."""
    
    __tablename__ = "security_events"
    
    # Identity
    id: UUID = Field(primary_key=True)
    event_type: str = Field(index=True)
    risk_level: str = Field(index=True)
    status: str = Field(index=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    
    # User and session info
    user_id: UUID | None = Field(default=None, index=True)
    session_id: UUID | None = Field(default=None, index=True)
    device_id: UUID | None = Field(default=None, index=True)
    
    # IP and device info
    ip_address: str | None = Field(default=None, index=True)
    user_agent: str | None = Field(default=None)
    
    # Event details
    description: str = Field(sa_column=Column(Text))
    details: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    affected_resources: list[str] = Field(default=[], sa_column=Column(JSON))
    
    # Location info
    country: str | None = Field(default=None, index=True)
    city: str | None = Field(default=None)
    latitude: float | None = Field(default=None)
    longitude: float | None = Field(default=None)
    
    # Investigation and response
    investigated_by: UUID | None = Field(default=None)
    investigation_notes: list[dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    resolved_at: datetime | None = Field(default=None)
    resolved_by: UUID | None = Field(default=None)
    resolution: str | None = Field(default=None, sa_column=Column(Text))
    false_positive_reason: str | None = Field(default=None)
    
    # Correlation
    correlation_id: str | None = Field(default=None, index=True)
    related_event_ids: list[str] = Field(default=[], sa_column=Column(JSON))
    attack_pattern: str | None = Field(default=None, index=True)
    
    # Metadata
    source_system: str = Field(default="identity", index=True)
    alert_sent: bool = Field(default=False)
    auto_mitigated: bool = Field(default=False)
    requires_review: bool = Field(default=True, index=True)
    severity_score: float = Field(default=0.0)
    response_priority: int = Field(default=5)
    
    # Timestamps and metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    class Config:
        """SQLModel configuration."""
        validate_assignment = True


# Indexes and constraints would be added in migrations
# Example indexes:
# - login_attempts: (email, timestamp DESC)
# - login_attempts: (ip_address, timestamp DESC)
# - login_attempts: (user_id, timestamp DESC)
# - login_attempts: (risk_score DESC, timestamp DESC) WHERE success = false
# - security_events: (user_id, timestamp DESC)
# - security_events: (event_type, timestamp DESC)
# - security_events: (risk_level, status, timestamp DESC)
# - security_events: (correlation_id) WHERE correlation_id IS NOT NULL