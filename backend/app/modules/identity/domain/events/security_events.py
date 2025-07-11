"""Security-related domain events."""

from datetime import datetime
from typing import Any
from uuid import UUID

from .base import IdentityDomainEvent


class SecurityAlertRaised(IdentityDomainEvent):
    """Event raised when a security alert is triggered."""
    alert_id: UUID
    user_id: UUID | None = None
    alert_type: str
    severity: str
    description: str
    source: str
    metadata: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.alert_id)


class SuspiciousActivityDetected(IdentityDomainEvent):
    """Event raised when suspicious activity is detected."""
    activity_id: UUID
    user_id: UUID | None = None
    activity_type: str
    risk_score: float
    description: str
    source_ip: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.activity_id)


class IPAllowlisted(IdentityDomainEvent):
    """Event raised when IP is added to allowlist."""
    ip_address: str
    added_by: UUID
    reason: str | None = None
    expires_at: datetime | None = None

    def get_aggregate_id(self) -> str:
        return self.ip_address


class IPBlocklisted(IdentityDomainEvent):
    """Event raised when IP is blocklisted."""
    ip_address: str
    blocked_by: UUID | None = None
    reason: str
    blocked_at: datetime
    expires_at: datetime | None = None
    automatic_block: bool = False

    def get_aggregate_id(self) -> str:
        return self.ip_address


class AuditLogCreated(IdentityDomainEvent):
    """Event raised when an audit log entry is created."""
    audit_id: UUID
    user_id: UUID | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    result: str  # success, failure, partial
    details: dict[str, Any]
    ip_address: str | None = None
    user_agent: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.audit_id)


class ComplianceViolationDetected(IdentityDomainEvent):
    """Event raised when a compliance violation is detected."""
    violation_id: UUID
    user_id: UUID | None = None
    violation_type: str
    regulation: str  # GDPR, HIPAA, SOX, etc.
    severity: str
    description: str
    affected_data: dict[str, Any]
    remediation_required: bool = True

    def get_aggregate_id(self) -> str:
        return str(self.violation_id)