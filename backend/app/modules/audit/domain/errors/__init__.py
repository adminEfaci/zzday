"""Audit domain errors."""

from .audit_errors import (
    AuditArchiveError,
    AuditComplianceError,
    AuditDomainError,
    AuditExportError,
    AuditFilterError,
    AuditImmutabilityError,
    AuditIntegrityError,
    AuditNotFoundError,
    AuditPermissionError,
    AuditReportError,
    AuditRetentionError,
    AuditSessionError,
    InvalidAuditQueryError,
)

__all__ = [
    "AuditArchiveError",
    "AuditComplianceError",
    "AuditDomainError",
    "AuditExportError",
    "AuditFilterError",
    "AuditImmutabilityError",
    "AuditIntegrityError",
    "AuditNotFoundError",
    "AuditPermissionError",
    "AuditReportError",
    "AuditRetentionError",
    "AuditSessionError",
    "InvalidAuditQueryError",
]
