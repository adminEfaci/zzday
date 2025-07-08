"""Audit domain events.

This module defines domain events emitted by the audit module,
enabling event-driven integration with other modules.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import DomainEvent
from app.core.errors import ValidationError
from app.core.events.types import EventMetadata
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity


class AuditLogCreated(DomainEvent):
    """
    Event emitted when a new audit log is created.

    This event signals the creation of a new audit log aggregate,
    which can contain multiple audit entries.

    Attributes:
        audit_log_id: ID of the created audit log
        title: Title of the audit log
        description: Description of the log purpose
        retention_policy: Applied retention policy
        created_by: User who created the log
    """

    def __init__(
        self,
        audit_log_id: UUID,
        title: str,
        description: str | None = None,
        retention_policy: str | None = None,
        created_by: UUID | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        """Initialize audit log created event."""
        super().__init__(metadata=metadata, **kwargs)
        self.audit_log_id = audit_log_id
        self.title = title
        self.description = description
        self.retention_policy = retention_policy
        self.created_by = created_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.audit_log_id:
            raise ValidationError("audit_log_id is required")
        if not self.title:
            raise ValidationError("title is required")


class AuditSessionStarted(DomainEvent):
    """
    Event emitted when an audit session is started.

    Audit sessions group related audit entries together,
    providing context for a series of related actions.

    Attributes:
        session_id: ID of the audit session
        user_id: User who started the session
        session_type: Type of session (e.g., 'user_activity', 'batch_operation')
        correlation_id: Correlation ID for tracking
        parent_session_id: Parent session for nested sessions
        context: Additional session context
    """

    def __init__(
        self,
        session_id: UUID,
        user_id: UUID | None,
        session_type: str,
        correlation_id: str,
        parent_session_id: UUID | None = None,
        context: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        """Initialize audit session started event."""
        super().__init__(metadata=metadata, **kwargs)
        self.session_id = session_id
        self.user_id = user_id
        self.session_type = session_type
        self.correlation_id = correlation_id
        self.parent_session_id = parent_session_id
        self.context = context or {}

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.session_id:
            raise ValidationError("session_id is required")
        if not self.session_type:
            raise ValidationError("session_type is required")
        if not self.correlation_id:
            raise ValidationError("correlation_id is required")


class AuditEntryRecorded(DomainEvent):
    """
    Event emitted when an audit entry is recorded.

    This is the core audit event, capturing individual
    auditable actions in the system.

    Attributes:
        entry_id: ID of the audit entry
        user_id: User who performed the action
        action_type: Type of action performed
        resource_type: Type of resource affected
        resource_id: ID of the resource
        severity: Severity level of the event
        category: Category of the event
        outcome: Outcome of the action
        session_id: Associated session ID
        correlation_id: Correlation ID
    """

    def __init__(
        self,
        entry_id: UUID,
        user_id: UUID | None,
        action_type: str,
        resource_type: str,
        resource_id: str,
        severity: str,
        category: str,
        outcome: str = "success",
        session_id: UUID | None = None,
        correlation_id: str | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        """Initialize audit entry recorded event."""
        super().__init__(metadata=metadata, **kwargs)
        self.entry_id = entry_id
        self.user_id = user_id
        self.action_type = action_type
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.severity = severity
        self.category = category
        self.outcome = outcome
        self.session_id = session_id
        self.correlation_id = correlation_id

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.entry_id:
            raise ValidationError("entry_id is required")
        if not self.action_type:
            raise ValidationError("action_type is required")
        if not self.resource_type:
            raise ValidationError("resource_type is required")
        if not self.resource_id:
            raise ValidationError("resource_id is required")
        if not self.severity:
            raise ValidationError("severity is required")
        if not self.category:
            raise ValidationError("category is required")

        # Validate outcome
        valid_outcomes = {"success", "failure", "partial"}
        if self.outcome not in valid_outcomes:
            raise ValidationError(
                f"outcome must be one of: {', '.join(valid_outcomes)}"
            )


class AuditReportGenerated(DomainEvent):
    """
    Event emitted when an audit report is generated.

    This event signals the completion of audit report generation,
    which may trigger notifications or further processing.

    Attributes:
        report_id: ID of the generated report
        report_type: Type of report
        title: Report title
        time_range_start: Start of report period
        time_range_end: End of report period
        total_entries: Total entries in report
        critical_findings: Whether critical findings exist
        generated_by: User who generated report
        file_path: Path to generated file
    """

    def __init__(
        self,
        report_id: UUID,
        report_type: str,
        title: str,
        time_range_start: datetime,
        time_range_end: datetime,
        total_entries: int,
        critical_findings: bool,
        generated_by: UUID,
        file_path: str | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        """Initialize audit report generated event."""
        super().__init__(metadata=metadata, **kwargs)
        self.report_id = report_id
        self.report_type = report_type
        self.title = title
        self.time_range_start = time_range_start
        self.time_range_end = time_range_end
        self.total_entries = total_entries
        self.critical_findings = critical_findings
        self.generated_by = generated_by
        self.file_path = file_path

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.report_id:
            raise ValidationError("report_id is required")
        if not self.report_type:
            raise ValidationError("report_type is required")
        if not self.title:
            raise ValidationError("title is required")
        if not self.time_range_start:
            raise ValidationError("time_range_start is required")
        if not self.time_range_end:
            raise ValidationError("time_range_end is required")
        if self.total_entries < 0:
            raise ValidationError("total_entries cannot be negative")
        if not self.generated_by:
            raise ValidationError("generated_by is required")


class AuditArchived(DomainEvent):
    """
    Event emitted when audit records are archived.

    This event signals that audit records have been moved
    to archival storage based on retention policies.

    Attributes:
        archive_id: ID of the archive operation
        archived_count: Number of records archived
        time_range_start: Start of archived period
        time_range_end: End of archived period
        archive_location: Location of archived data
        retention_policy: Applied retention policy
        compressed_size_bytes: Size after compression
    """

    def __init__(
        self,
        archive_id: UUID,
        archived_count: int,
        time_range_start: datetime,
        time_range_end: datetime,
        archive_location: str,
        retention_policy: str,
        compressed_size_bytes: int | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        """Initialize audit archived event."""
        super().__init__(metadata=metadata, **kwargs)
        self.archive_id = archive_id
        self.archived_count = archived_count
        self.time_range_start = time_range_start
        self.time_range_end = time_range_end
        self.archive_location = archive_location
        self.retention_policy = retention_policy
        self.compressed_size_bytes = compressed_size_bytes

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.archive_id:
            raise ValidationError("archive_id is required")
        if self.archived_count < 0:
            raise ValidationError("archived_count cannot be negative")
        if not self.time_range_start:
            raise ValidationError("time_range_start is required")
        if not self.time_range_end:
            raise ValidationError("time_range_end is required")
        if not self.archive_location:
            raise ValidationError("archive_location is required")
        if not self.retention_policy:
            raise ValidationError("retention_policy is required")


@dataclass(frozen=True)
class AuditDomainEvent(DomainEvent):
    """Base class for all audit domain events."""
    
    audit_entry_id: UUID
    correlation_id: str | None = None


@dataclass(frozen=True)
class AuditEntryCreated(AuditDomainEvent):
    """Event raised when an audit entry is created."""
    
    user_id: UUID | None
    action_type: str
    resource_type: str
    resource_id: str
    severity: AuditSeverity
    category: AuditCategory
    outcome: str
    risk_score: int
    session_id: UUID | None
    created_at: datetime


@dataclass(frozen=True)
class AuditEntryFailed(AuditDomainEvent):
    """Event raised when an audit entry represents a failed action."""
    
    user_id: UUID | None
    action_type: str
    resource_type: str
    resource_id: str
    error_details: dict[str, Any] | None
    created_at: datetime


@dataclass(frozen=True)
class HighRiskAuditDetected(AuditDomainEvent):
    """Event raised when a high-risk audit entry is detected."""
    
    user_id: UUID | None
    action_type: str
    resource_type: str
    resource_id: str
    risk_score: int
    severity: AuditSeverity
    outcome: str
    requires_investigation: bool
    created_at: datetime


@dataclass(frozen=True)
class IntegrityViolationDetected(AuditDomainEvent):
    """Event raised when audit entry integrity violation is detected."""
    
    expected_hash: str
    actual_hash: str
    violation_type: str
    detected_at: datetime


@dataclass(frozen=True)
class AuditReportGenerated(DomainEvent):
    """Event raised when an audit report is generated."""
    
    report_id: UUID
    report_type: str
    generated_by: UUID
    total_entries: int
    time_range_start: datetime
    time_range_end: datetime
    has_critical_findings: bool
    generation_duration_seconds: float | None
    created_at: datetime


@dataclass(frozen=True)
class AuditReportFailed(DomainEvent):
    """Event raised when audit report generation fails."""
    
    report_id: UUID
    report_type: str
    generated_by: UUID
    error_message: str
    failure_reason: str
    created_at: datetime


@dataclass(frozen=True)
class CriticalFindingDetected(DomainEvent):
    """Event raised when a critical finding is detected in a report."""
    
    report_id: UUID
    finding_title: str
    finding_description: str
    affected_count: int
    severity: AuditSeverity
    recommendation: str | None
    detected_at: datetime


# Register events with the event factory
from app.core.events.types import EventFactory

EventFactory.register_event_type(AuditLogCreated)
EventFactory.register_event_type(AuditSessionStarted)
EventFactory.register_event_type(AuditEntryRecorded)
EventFactory.register_event_type(AuditReportGenerated)
EventFactory.register_event_type(AuditArchived)


__all__ = [
    "AuditArchived",
    "AuditDomainEvent",
    "AuditEntryCreated",
    "AuditEntryFailed",
    "AuditEntryRecorded",
    "AuditLogCreated",
    "AuditReportFailed",
    "AuditReportGenerated",
    "AuditSessionStarted",
    "CriticalFindingDetected",
    "HighRiskAuditDetected",
    "IntegrityViolationDetected",
]
