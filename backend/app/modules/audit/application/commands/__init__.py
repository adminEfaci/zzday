"""Audit application commands.

This module contains all commands for the audit module,
implementing the write side of CQRS pattern.
"""

from .archive_audit_log_command import (
    ArchiveAuditLogCommand,
    ArchiveAuditLogCommandHandler,
)
from .create_audit_session_command import (
    CreateAuditSessionCommand,
    CreateAuditSessionCommandHandler,
)
from .generate_audit_report_command import (
    GenerateAuditReportCommand,
    GenerateAuditReportCommandHandler,
)
from .record_audit_entry_command import (
    RecordAuditEntryCommand,
    RecordAuditEntryCommandHandler,
)
from .update_retention_policy_command import (
    UpdateRetentionPolicyCommand,
    UpdateRetentionPolicyCommandHandler,
)

__all__ = [
    "ArchiveAuditLogCommand",
    "ArchiveAuditLogCommandHandler",
    "CreateAuditSessionCommand",
    "CreateAuditSessionCommandHandler",
    "GenerateAuditReportCommand",
    "GenerateAuditReportCommandHandler",
    # Commands
    "RecordAuditEntryCommand",
    # Handlers
    "RecordAuditEntryCommandHandler",
    "UpdateRetentionPolicyCommand",
    "UpdateRetentionPolicyCommandHandler",
]
