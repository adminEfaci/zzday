"""Audit domain layer.

This layer contains the core business logic for audit trail management,
including aggregates, entities, value objects, events, and domain services.
All components follow pure Python principles without framework dependencies.
"""

# Import key domain components for easier access
from .aggregates.audit_log import AuditLog
from .aggregates.audit_session import AuditSession
from .entities.audit_entry import AuditEntry
from .entities.audit_filter import AuditFilter
from .entities.audit_report import AuditReport
from .enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
    RetentionPolicy,
)
from .errors.audit_errors import (
    AuditArchiveError,
    AuditNotFoundError,
    AuditRetentionError,
    InvalidAuditQueryError,
)
from .events.audit_events import (
    AuditArchived,
    AuditEntryRecorded,
    AuditLogCreated,
    AuditReportGenerated,
    AuditSessionStarted,
)
from .interfaces.ports import IIdentityPort, INotificationPort
from .interfaces.services import (
    IAuditDomainService,
    IAuditRetentionService,
    IAuditValidationService,
)
from .value_objects.audit_action import AuditAction
from .value_objects.audit_context import AuditContext
from .value_objects.audit_metadata import AuditMetadata
from .value_objects.resource_identifier import ResourceIdentifier
from .value_objects.time_range import TimeRange

__all__ = [
    # Value Objects
    "AuditAction",
    # Errors
    "AuditArchiveError",
    # Events
    "AuditArchived",
    # Enums
    "AuditCategory",
    "AuditContext",
    # Entities
    "AuditEntry",
    "AuditEntryRecorded",
    "AuditFilter",
    # Aggregates
    "AuditLog",
    "AuditLogCreated",
    "AuditMetadata",
    "AuditNotFoundError",
    "AuditReport",
    "AuditReportGenerated",
    "AuditRetentionError",
    "AuditSession",
    "AuditSessionStarted",
    "AuditSeverity",
    "AuditStatus",
    # Interfaces - Services
    "IAuditDomainService",
    "IAuditRetentionService",
    "IAuditValidationService",
    # Interfaces - Ports
    "IIdentityPort",
    "INotificationPort",
    "InvalidAuditQueryError",
    "ResourceIdentifier",
    "RetentionPolicy",
    "TimeRange",
]
