"""Audit domain interfaces."""

# Repository interfaces
from .repositories import (
    IAuditEntryRepository,
    IAuditReportRepository,
)

# Service interfaces  
from .services import (
    IAuditIntegrityService,
    IAuditRetentionService,
    IComplianceService,
)

__all__ = [
    # Repository interfaces
    "IAuditEntryRepository",
    # Service interfaces
    "IAuditIntegrityService",
    "IAuditReportRepository",
    "IAuditRetentionService",
    "IComplianceService",
]
