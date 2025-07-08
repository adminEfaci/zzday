"""Audit domain-specific errors.

This module defines custom exceptions for the audit domain,
providing clear error semantics and rich error information.
"""

from typing import Any
from uuid import UUID

from app.core.errors import DomainError


class AuditDomainError(DomainError):
    """Base class for all audit domain errors."""

    default_code = "AUDIT_DOMAIN_ERROR"

    def __init__(self, message: str, **kwargs):
        """Initialize audit domain error."""
        super().__init__(message, **kwargs)


class AuditNotFoundError(AuditDomainError):
    """Raised when an audit record cannot be found."""

    default_code = "AUDIT_NOT_FOUND"

    def __init__(
        self,
        audit_id: UUID | None = None,
        criteria: dict[str, Any] | None = None,
        **kwargs,
    ):
        """
        Initialize audit not found error.

        Args:
            audit_id: ID of the audit record that was not found
            criteria: Search criteria that yielded no results
            **kwargs: Additional error context
        """
        if audit_id:
            message = f"Audit record not found: {audit_id}"
            details = {"audit_id": str(audit_id)}
        elif criteria:
            message = "No audit records found matching criteria"
            details = {"criteria": criteria}
        else:
            message = "Audit record not found"
            details = {}

        super().__init__(
            message=message,
            details=details,
            user_message="The requested audit record was not found",
            **kwargs,
        )


class InvalidAuditQueryError(AuditDomainError):
    """Raised when an audit query is invalid or malformed."""

    default_code = "INVALID_AUDIT_QUERY"

    def __init__(
        self,
        message: str,
        query_type: str | None = None,
        invalid_fields: list[str] | None = None,
        **kwargs,
    ):
        """
        Initialize invalid audit query error.

        Args:
            message: Error message
            query_type: Type of query that failed
            invalid_fields: List of invalid field names
            **kwargs: Additional error context
        """
        details = {}
        if query_type:
            details["query_type"] = query_type
        if invalid_fields:
            details["invalid_fields"] = invalid_fields

        super().__init__(
            message=message,
            details=details,
            user_message="The audit query contains invalid parameters",
            recovery_hint="Check the query syntax and field names",
            **kwargs,
        )


class AuditRetentionError(AuditDomainError):
    """Raised when there's an error with audit retention policy."""

    default_code = "AUDIT_RETENTION_ERROR"

    def __init__(
        self,
        message: str,
        policy: str | None = None,
        affected_count: int | None = None,
        **kwargs,
    ):
        """
        Initialize audit retention error.

        Args:
            message: Error message
            policy: Retention policy that caused the error
            affected_count: Number of records affected
            **kwargs: Additional error context
        """
        details = {}
        if policy:
            details["policy"] = policy
        if affected_count is not None:
            details["affected_count"] = affected_count

        super().__init__(
            message=message,
            details=details,
            user_message="Unable to apply retention policy to audit records",
            **kwargs,
        )


class AuditArchiveError(AuditDomainError):
    """Raised when there's an error archiving audit records."""

    default_code = "AUDIT_ARCHIVE_ERROR"

    def __init__(
        self,
        message: str,
        archive_operation: str | None = None,
        failed_records: list[UUID] | None = None,
        **kwargs,
    ):
        """
        Initialize audit archive error.

        Args:
            message: Error message
            archive_operation: Type of archive operation that failed
            failed_records: List of record IDs that failed to archive
            **kwargs: Additional error context
        """
        details = {}
        if archive_operation:
            details["operation"] = archive_operation
        if failed_records:
            details["failed_records"] = [str(rid) for rid in failed_records]
            details["failed_count"] = len(failed_records)

        super().__init__(
            message=message,
            details=details,
            user_message="Failed to archive audit records",
            recovery_hint="Check archive storage availability and permissions",
            **kwargs,
        )


class AuditImmutabilityError(AuditDomainError):
    """Raised when attempting to modify an immutable audit record."""

    default_code = "AUDIT_IMMUTABILITY_VIOLATION"

    def __init__(self, audit_id: UUID, attempted_operation: str, **kwargs):
        """
        Initialize audit immutability error.

        Args:
            audit_id: ID of the audit record
            attempted_operation: Operation that was attempted
            **kwargs: Additional error context
        """
        message = f"Cannot modify immutable audit record {audit_id}"

        super().__init__(
            message=message,
            details={
                "audit_id": str(audit_id),
                "attempted_operation": attempted_operation,
            },
            user_message="Audit records cannot be modified once created",
            **kwargs,
        )


class AuditSessionError(AuditDomainError):
    """Raised when there's an error with audit session management."""

    default_code = "AUDIT_SESSION_ERROR"

    def __init__(
        self,
        message: str,
        session_id: UUID | None = None,
        session_status: str | None = None,
        **kwargs,
    ):
        """
        Initialize audit session error.

        Args:
            message: Error message
            session_id: ID of the affected session
            session_status: Current status of the session
            **kwargs: Additional error context
        """
        details = {}
        if session_id:
            details["session_id"] = str(session_id)
        if session_status:
            details["session_status"] = session_status

        super().__init__(
            message=message,
            details=details,
            user_message="Audit session operation failed",
            **kwargs,
        )


class AuditReportError(AuditDomainError):
    """Raised when there's an error generating audit reports."""

    default_code = "AUDIT_REPORT_ERROR"

    def __init__(
        self,
        message: str,
        report_type: str | None = None,
        time_range: str | None = None,
        **kwargs,
    ):
        """
        Initialize audit report error.

        Args:
            message: Error message
            report_type: Type of report that failed
            time_range: Time range for the report
            **kwargs: Additional error context
        """
        details = {}
        if report_type:
            details["report_type"] = report_type
        if time_range:
            details["time_range"] = time_range

        super().__init__(
            message=message,
            details=details,
            user_message="Failed to generate audit report",
            recovery_hint="Check report parameters and try a smaller time range",
            **kwargs,
        )


class AuditIntegrityError(AuditDomainError):
    """Raised when audit record integrity is compromised."""

    default_code = "AUDIT_INTEGRITY_ERROR"

    def __init__(
        self,
        message: str,
        audit_id: UUID | None = None,
        integrity_check: str | None = None,
        expected_hash: str | None = None,
        actual_hash: str | None = None,
        **kwargs,
    ):
        """
        Initialize audit integrity error.

        Args:
            message: Error message
            audit_id: ID of the compromised audit record
            integrity_check: Type of integrity check that failed
            expected_hash: Expected hash value
            actual_hash: Actual hash value
            **kwargs: Additional error context
        """
        details = {}
        if audit_id:
            details["audit_id"] = str(audit_id)
        if integrity_check:
            details["integrity_check"] = integrity_check
        if expected_hash:
            details["expected_hash"] = expected_hash
        if actual_hash:
            details["actual_hash"] = actual_hash

        super().__init__(
            message=message,
            details=details,
            user_message="Audit record integrity check failed",
            recovery_hint="Verify audit record authenticity and check for tampering",
            **kwargs,
        )


class AuditComplianceError(AuditDomainError):
    """Raised when audit operations violate compliance requirements."""

    default_code = "AUDIT_COMPLIANCE_ERROR"

    def __init__(
        self,
        message: str,
        regulation: str | None = None,
        violation_type: str | None = None,
        required_action: str | None = None,
        **kwargs,
    ):
        """
        Initialize audit compliance error.

        Args:
            message: Error message
            regulation: Compliance regulation that was violated
            violation_type: Type of compliance violation
            required_action: Action required to resolve the violation
            **kwargs: Additional error context
        """
        details = {}
        if regulation:
            details["regulation"] = regulation
        if violation_type:
            details["violation_type"] = violation_type
        if required_action:
            details["required_action"] = required_action

        super().__init__(
            message=message,
            details=details,
            user_message="Operation violates compliance requirements",
            recovery_hint=required_action or "Review compliance policies and requirements",
            **kwargs,
        )


class AuditExportError(AuditDomainError):
    """Raised when audit data export operations fail."""

    default_code = "AUDIT_EXPORT_ERROR"

    def __init__(
        self,
        message: str,
        export_format: str | None = None,
        record_count: int | None = None,
        export_size: int | None = None,
        **kwargs,
    ):
        """
        Initialize audit export error.

        Args:
            message: Error message
            export_format: Format of the export that failed
            record_count: Number of records being exported
            export_size: Size of the export in bytes
            **kwargs: Additional error context
        """
        details = {}
        if export_format:
            details["export_format"] = export_format
        if record_count is not None:
            details["record_count"] = record_count
        if export_size is not None:
            details["export_size"] = export_size

        super().__init__(
            message=message,
            details=details,
            user_message="Failed to export audit data",
            recovery_hint="Check export parameters and available storage space",
            **kwargs,
        )


class AuditFilterError(AuditDomainError):
    """Raised when audit filter operations are invalid."""

    default_code = "AUDIT_FILTER_ERROR"

    def __init__(
        self,
        message: str,
        filter_type: str | None = None,
        invalid_criteria: dict[str, Any] | None = None,
        **kwargs,
    ):
        """
        Initialize audit filter error.

        Args:
            message: Error message
            filter_type: Type of filter that caused the error
            invalid_criteria: Invalid filter criteria
            **kwargs: Additional error context
        """
        details = {}
        if filter_type:
            details["filter_type"] = filter_type
        if invalid_criteria:
            details["invalid_criteria"] = invalid_criteria

        super().__init__(
            message=message,
            details=details,
            user_message="Invalid audit filter criteria",
            recovery_hint="Check filter syntax and supported field names",
            **kwargs,
        )


class AuditPermissionError(AuditDomainError):
    """Raised when user lacks permission for audit operations."""

    default_code = "AUDIT_PERMISSION_ERROR"

    def __init__(
        self,
        message: str,
        user_id: UUID | None = None,
        required_permission: str | None = None,
        operation: str | None = None,
        **kwargs,
    ):
        """
        Initialize audit permission error.

        Args:
            message: Error message
            user_id: ID of the user lacking permission
            required_permission: Permission required for the operation
            operation: Operation that was attempted
            **kwargs: Additional error context
        """
        details = {}
        if user_id:
            details["user_id"] = str(user_id)
        if required_permission:
            details["required_permission"] = required_permission
        if operation:
            details["operation"] = operation

        super().__init__(
            message=message,
            details=details,
            user_message="Insufficient permissions for audit operation",
            recovery_hint="Contact administrator to request required permissions",
            **kwargs,
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
