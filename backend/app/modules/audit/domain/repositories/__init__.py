"""Audit domain repositories."""

from .audit_entry_repository import IAuditEntryRepository
from .audit_report_repository import IAuditReportRepository

__all__ = [
    "IAuditEntryRepository",
    "IAuditReportRepository",
]
