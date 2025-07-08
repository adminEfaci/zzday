"""GraphQL unions for audit module."""


import strawberry

from .types.audit_entry_type import AuditEntryType
from .types.audit_report_type import AuditReportType
from .types.compliance_type import ComplianceReportType, ComplianceViolationType


@strawberry.type
class SecurityEventType:
    """Type for security-related audit events."""

    id: strawberry.ID
    event_type: str
    severity: str
    description: str
    detected_at: str
    source_ip: str
    user_agent: str
    risk_score: float


@strawberry.type
class SystemEventType:
    """Type for system-related audit events."""

    id: strawberry.ID
    event_type: str
    system_component: str
    description: str
    occurred_at: str
    impact_level: str
    duration_ms: int


@strawberry.type
class UserActivityType:
    """Type for user activity events."""

    id: strawberry.ID
    user_id: strawberry.ID
    activity_type: str
    description: str
    occurred_at: str
    session_id: str
    ip_address: str


# Union types for polymorphic responses
AuditEventUnion = strawberry.union(
    "AuditEventUnion",
    (AuditEntryType, SecurityEventType, SystemEventType, UserActivityType),
)

ReportContentUnion = strawberry.union(
    "ReportContentUnion", (AuditReportType, ComplianceReportType)
)


@strawberry.type
class AuditSearchHit:
    """Type for search hit content."""

    id: strawberry.ID
    content_type: str
    title: str
    snippet: str
    score: float
    highlighted_fields: list[str]


SearchResultUnion = strawberry.union(
    "SearchResultUnion", (AuditEntryType, AuditSearchHit, ComplianceViolationType)
)
