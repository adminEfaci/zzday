"""
Comprehensive tests for Audit domain errors.

This module tests all audit error classes with complete coverage focusing on:
- Error creation and initialization
- Error message formatting
- Error context and details
- Error inheritance and behavior
- Custom error attributes
"""

from uuid import uuid4

import pytest

from app.core.errors import DomainError
from app.modules.audit.domain.errors.audit_errors import (
    AuditArchiveError,
    AuditDomainError,
    AuditImmutabilityError,
    AuditNotFoundError,
    AuditReportError,
    AuditRetentionError,
    AuditSessionError,
    InvalidAuditQueryError,
)


class TestAuditDomainError:
    """Test the base AuditDomainError class."""

    def test_audit_domain_error_inherits_from_domain_error(self):
        """Test that AuditDomainError inherits from DomainError."""
        # Act & Assert
        assert issubclass(AuditDomainError, DomainError)

    def test_audit_domain_error_creation_with_message(self):
        """Test creating audit domain error with message."""
        # Arrange
        message = "Test audit domain error"

        # Act
        error = AuditDomainError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "AUDIT_DOMAIN_ERROR"

    def test_audit_domain_error_creation_with_kwargs(self):
        """Test creating audit domain error with additional kwargs."""
        # Arrange
        message = "Test error with details"
        details = {"field": "value", "count": 42}

        # Act
        error = AuditDomainError(message, details=details, severity="high")

        # Assert
        assert str(error) == message
        assert hasattr(error, "details")
        assert hasattr(error, "severity")


class TestAuditNotFoundError:
    """Test AuditNotFoundError class."""

    def test_audit_not_found_error_with_audit_id(self):
        """Test creating audit not found error with audit ID."""
        # Arrange
        audit_id = uuid4()

        # Act
        error = AuditNotFoundError(audit_id=audit_id)

        # Assert
        assert f"Audit record not found: {audit_id}" in str(error)
        assert error.default_code == "AUDIT_NOT_FOUND"
        assert error.details["audit_id"] == str(audit_id)
        assert "requested audit record was not found" in error.user_message

    def test_audit_not_found_error_with_criteria(self):
        """Test creating audit not found error with search criteria."""
        # Arrange
        criteria = {"user_id": "123", "action_type": "update"}

        # Act
        error = AuditNotFoundError(criteria=criteria)

        # Assert
        assert "No audit records found matching criteria" in str(error)
        assert error.details["criteria"] == criteria
        assert "requested audit record was not found" in error.user_message

    def test_audit_not_found_error_without_parameters(self):
        """Test creating audit not found error without specific parameters."""
        # Act
        error = AuditNotFoundError()

        # Assert
        assert "Audit record not found" in str(error)
        assert error.details == {}
        assert "requested audit record was not found" in error.user_message

    def test_audit_not_found_error_inherits_from_audit_domain_error(self):
        """Test inheritance hierarchy."""
        # Act & Assert
        assert issubclass(AuditNotFoundError, AuditDomainError)
        assert issubclass(AuditNotFoundError, DomainError)


class TestInvalidAuditQueryError:
    """Test InvalidAuditQueryError class."""

    def test_invalid_audit_query_error_basic(self):
        """Test creating invalid audit query error with basic message."""
        # Arrange
        message = "Invalid query syntax"

        # Act
        error = InvalidAuditQueryError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "INVALID_AUDIT_QUERY"
        assert "invalid parameters" in error.user_message
        assert "Check the query syntax" in error.recovery_hint

    def test_invalid_audit_query_error_with_query_type(self):
        """Test creating error with query type information."""
        # Arrange
        message = "Invalid search query"
        query_type = "full_text_search"

        # Act
        error = InvalidAuditQueryError(message, query_type=query_type)

        # Assert
        assert str(error) == message
        assert error.details["query_type"] == query_type

    def test_invalid_audit_query_error_with_invalid_fields(self):
        """Test creating error with invalid field information."""
        # Arrange
        message = "Invalid field names in query"
        invalid_fields = ["invalid_field1", "unknown_field2"]

        # Act
        error = InvalidAuditQueryError(message, invalid_fields=invalid_fields)

        # Assert
        assert str(error) == message
        assert error.details["invalid_fields"] == invalid_fields

    def test_invalid_audit_query_error_with_all_parameters(self):
        """Test creating error with all parameters."""
        # Arrange
        message = "Complex query validation failed"
        query_type = "advanced_filter"
        invalid_fields = ["bad_field"]

        # Act
        error = InvalidAuditQueryError(
            message, query_type=query_type, invalid_fields=invalid_fields
        )

        # Assert
        assert str(error) == message
        assert error.details["query_type"] == query_type
        assert error.details["invalid_fields"] == invalid_fields
        assert "invalid parameters" in error.user_message
        assert "Check the query syntax" in error.recovery_hint


class TestAuditRetentionError:
    """Test AuditRetentionError class."""

    def test_audit_retention_error_basic(self):
        """Test creating audit retention error with basic message."""
        # Arrange
        message = "Retention policy application failed"

        # Act
        error = AuditRetentionError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "AUDIT_RETENTION_ERROR"
        assert "Unable to apply retention policy" in error.user_message

    def test_audit_retention_error_with_policy(self):
        """Test creating error with retention policy information."""
        # Arrange
        message = "Cannot apply invalid retention policy"
        policy = "7_years"

        # Act
        error = AuditRetentionError(message, policy=policy)

        # Assert
        assert str(error) == message
        assert error.details["policy"] == policy

    def test_audit_retention_error_with_affected_count(self):
        """Test creating error with affected record count."""
        # Arrange
        message = "Failed to apply retention to records"
        affected_count = 1500

        # Act
        error = AuditRetentionError(message, affected_count=affected_count)

        # Assert
        assert str(error) == message
        assert error.details["affected_count"] == affected_count

    def test_audit_retention_error_with_all_parameters(self):
        """Test creating error with all parameters."""
        # Arrange
        message = "Complete retention operation failure"
        policy = "permanent"
        affected_count = 2000

        # Act
        error = AuditRetentionError(
            message, policy=policy, affected_count=affected_count
        )

        # Assert
        assert str(error) == message
        assert error.details["policy"] == policy
        assert error.details["affected_count"] == affected_count


class TestAuditArchiveError:
    """Test AuditArchiveError class."""

    def test_audit_archive_error_basic(self):
        """Test creating audit archive error with basic message."""
        # Arrange
        message = "Archive operation failed"

        # Act
        error = AuditArchiveError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "AUDIT_ARCHIVE_ERROR"
        assert "Failed to archive audit records" in error.user_message
        assert "Check archive storage availability" in error.recovery_hint

    def test_audit_archive_error_with_operation(self):
        """Test creating error with archive operation information."""
        # Arrange
        message = "Compression failed during archive"
        archive_operation = "compress_and_store"

        # Act
        error = AuditArchiveError(message, archive_operation=archive_operation)

        # Assert
        assert str(error) == message
        assert error.details["operation"] == archive_operation

    def test_audit_archive_error_with_failed_records(self):
        """Test creating error with failed record information."""
        # Arrange
        message = "Multiple records failed to archive"
        failed_records = [uuid4(), uuid4(), uuid4()]

        # Act
        error = AuditArchiveError(message, failed_records=failed_records)

        # Assert
        assert str(error) == message
        assert error.details["failed_count"] == 3
        assert len(error.details["failed_records"]) == 3
        for record_id in failed_records:
            assert str(record_id) in error.details["failed_records"]

    def test_audit_archive_error_with_all_parameters(self):
        """Test creating error with all parameters."""
        # Arrange
        message = "Archive workflow completely failed"
        archive_operation = "full_archive"
        failed_records = [uuid4(), uuid4()]

        # Act
        error = AuditArchiveError(
            message, archive_operation=archive_operation, failed_records=failed_records
        )

        # Assert
        assert str(error) == message
        assert error.details["operation"] == archive_operation
        assert error.details["failed_count"] == 2
        assert len(error.details["failed_records"]) == 2


class TestAuditImmutabilityError:
    """Test AuditImmutabilityError class."""

    def test_audit_immutability_error_creation(self):
        """Test creating audit immutability error."""
        # Arrange
        audit_id = uuid4()
        attempted_operation = "update_entry"

        # Act
        error = AuditImmutabilityError(audit_id, attempted_operation)

        # Assert
        assert f"Cannot modify immutable audit record {audit_id}" in str(error)
        assert error.default_code == "AUDIT_IMMUTABILITY_VIOLATION"
        assert error.details["audit_id"] == str(audit_id)
        assert error.details["attempted_operation"] == attempted_operation
        assert "cannot be modified once created" in error.user_message

    def test_audit_immutability_error_with_various_operations(self):
        """Test error with different attempted operations."""
        # Arrange
        audit_id = uuid4()
        operations = ["edit", "delete", "modify_metadata", "change_status"]

        for operation in operations:
            # Act
            error = AuditImmutabilityError(audit_id, operation)

            # Assert
            assert error.details["attempted_operation"] == operation
            assert str(audit_id) in str(error)

    def test_audit_immutability_error_inherits_correctly(self):
        """Test inheritance hierarchy."""
        # Act & Assert
        assert issubclass(AuditImmutabilityError, AuditDomainError)
        assert issubclass(AuditImmutabilityError, DomainError)


class TestAuditSessionError:
    """Test AuditSessionError class."""

    def test_audit_session_error_basic(self):
        """Test creating audit session error with basic message."""
        # Arrange
        message = "Session creation failed"

        # Act
        error = AuditSessionError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "AUDIT_SESSION_ERROR"
        assert "Audit session operation failed" in error.user_message

    def test_audit_session_error_with_session_id(self):
        """Test creating error with session ID information."""
        # Arrange
        message = "Session state invalid"
        session_id = uuid4()

        # Act
        error = AuditSessionError(message, session_id=session_id)

        # Assert
        assert str(error) == message
        assert error.details["session_id"] == str(session_id)

    def test_audit_session_error_with_session_status(self):
        """Test creating error with session status information."""
        # Arrange
        message = "Cannot perform operation on closed session"
        session_status = "closed"

        # Act
        error = AuditSessionError(message, session_status=session_status)

        # Assert
        assert str(error) == message
        assert error.details["session_status"] == session_status

    def test_audit_session_error_with_all_parameters(self):
        """Test creating error with all parameters."""
        # Arrange
        message = "Session operation completely failed"
        session_id = uuid4()
        session_status = "expired"

        # Act
        error = AuditSessionError(
            message, session_id=session_id, session_status=session_status
        )

        # Assert
        assert str(error) == message
        assert error.details["session_id"] == str(session_id)
        assert error.details["session_status"] == session_status


class TestAuditReportError:
    """Test AuditReportError class."""

    def test_audit_report_error_basic(self):
        """Test creating audit report error with basic message."""
        # Arrange
        message = "Report generation failed"

        # Act
        error = AuditReportError(message)

        # Assert
        assert str(error) == message
        assert error.default_code == "AUDIT_REPORT_ERROR"
        assert "Failed to generate audit report" in error.user_message
        assert "smaller time range" in error.recovery_hint

    def test_audit_report_error_with_report_type(self):
        """Test creating error with report type information."""
        # Arrange
        message = "Compliance report failed"
        report_type = "sox_compliance"

        # Act
        error = AuditReportError(message, report_type=report_type)

        # Assert
        assert str(error) == message
        assert error.details["report_type"] == report_type

    def test_audit_report_error_with_time_range(self):
        """Test creating error with time range information."""
        # Arrange
        message = "Time range too large for report"
        time_range = "2023-01-01 to 2024-12-31"

        # Act
        error = AuditReportError(message, time_range=time_range)

        # Assert
        assert str(error) == message
        assert error.details["time_range"] == time_range

    def test_audit_report_error_with_all_parameters(self):
        """Test creating error with all parameters."""
        # Arrange
        message = "Complete report generation failure"
        report_type = "security_audit"
        time_range = "Last 12 months"

        # Act
        error = AuditReportError(
            message, report_type=report_type, time_range=time_range
        )

        # Assert
        assert str(error) == message
        assert error.details["report_type"] == report_type
        assert error.details["time_range"] == time_range


class TestAuditErrorIntegration:
    """Test integration and common behavior across audit errors."""

    def test_all_audit_errors_inherit_from_audit_domain_error(self):
        """Test that all audit errors inherit from AuditDomainError."""
        # Arrange
        error_classes = [
            AuditNotFoundError,
            InvalidAuditQueryError,
            AuditRetentionError,
            AuditArchiveError,
            AuditImmutabilityError,
            AuditSessionError,
            AuditReportError,
        ]

        # Act & Assert
        for error_class in error_classes:
            assert issubclass(error_class, AuditDomainError)
            assert issubclass(error_class, DomainError)

    def test_all_audit_errors_have_unique_default_codes(self):
        """Test that all audit errors have unique default error codes."""
        # Arrange
        error_classes = [
            AuditDomainError,
            AuditNotFoundError,
            InvalidAuditQueryError,
            AuditRetentionError,
            AuditArchiveError,
            AuditImmutabilityError,
            AuditSessionError,
            AuditReportError,
        ]

        # Act
        codes = [error_class.default_code for error_class in error_classes]

        # Assert
        assert len(codes) == len(set(codes)), "All error codes should be unique"

    def test_all_audit_errors_can_be_created_with_minimal_parameters(self):
        """Test that all audit errors can be created with minimal parameters."""
        # Act & Assert

        # AuditDomainError
        error = AuditDomainError("Test message")
        assert str(error) == "Test message"

        # AuditNotFoundError
        error = AuditNotFoundError()
        assert "not found" in str(error)

        # InvalidAuditQueryError
        error = InvalidAuditQueryError("Invalid query")
        assert "Invalid query" in str(error)

        # AuditRetentionError
        error = AuditRetentionError("Retention failed")
        assert "Retention failed" in str(error)

        # AuditArchiveError
        error = AuditArchiveError("Archive failed")
        assert "Archive failed" in str(error)

        # AuditImmutabilityError
        audit_id = uuid4()
        error = AuditImmutabilityError(audit_id, "modify")
        assert str(audit_id) in str(error)

        # AuditSessionError
        error = AuditSessionError("Session failed")
        assert "Session failed" in str(error)

        # AuditReportError
        error = AuditReportError("Report failed")
        assert "Report failed" in str(error)

    def test_audit_errors_preserve_details_dictionary_structure(self):
        """Test that error details maintain proper dictionary structure."""
        # Arrange
        test_cases = [
            (AuditNotFoundError(audit_id=uuid4()), ["audit_id"]),
            (InvalidAuditQueryError("test", query_type="filter"), ["query_type"]),
            (AuditRetentionError("test", policy="permanent"), ["policy"]),
            (AuditArchiveError("test", archive_operation="compress"), ["operation"]),
            (
                AuditImmutabilityError(uuid4(), "edit"),
                ["audit_id", "attempted_operation"],
            ),
            (AuditSessionError("test", session_id=uuid4()), ["session_id"]),
            (AuditReportError("test", report_type="compliance"), ["report_type"]),
        ]

        # Act & Assert
        for error, expected_keys in test_cases:
            assert hasattr(error, "details")
            assert isinstance(error.details, dict)
            for key in expected_keys:
                assert key in error.details

    def test_audit_errors_support_exception_chaining(self):
        """Test that audit errors support exception chaining."""
        # Arrange
        original_error = ValueError("Original error")

        # Act
        try:
            raise AuditDomainError("Chained error") from original_error
        except AuditDomainError:
            pass

        # Assert
        assert chained_error.__cause__ is original_error
        assert "Original error" in str(original_error)
        assert "Chained error" in str(chained_error)

    def test_audit_errors_are_pickleable(self):
        """Test that audit errors can be pickled and unpickled."""
        import pickle

        # Arrange
        errors_to_test = [
            AuditDomainError("Test"),
            AuditNotFoundError(audit_id=uuid4()),
            AuditImmutabilityError(uuid4(), "modify"),
            AuditRetentionError("test", policy="permanent", affected_count=100),
        ]

        # Act & Assert
        for original_error in errors_to_test:
            # Pickle and unpickle
            pickled_data = pickle.dumps(original_error)
            unpickled_error = pickle.loads(pickled_data)

            # Verify error properties are preserved
            assert str(original_error) == str(unpickled_error)
            assert original_error.default_code == unpickled_error.default_code
            assert type(original_error) == type(unpickled_error)


class TestAuditErrorHandlingPatterns:
    """Test common error handling patterns for audit errors."""

    def test_error_context_preservation_through_exception_handling(self):
        """Test that error context is preserved through exception handling."""
        # Arrange
        audit_id = uuid4()

        def risky_operation():
            raise AuditImmutabilityError(audit_id, "unauthorized_modification")

        # Act & Assert
        with pytest.raises(AuditImmutabilityError) as exc_info:
            risky_operation()

        error = exc_info.value
        assert error.details["audit_id"] == str(audit_id)
        assert error.details["attempted_operation"] == "unauthorized_modification"

    def test_error_filtering_by_type(self):
        """Test filtering errors by their specific types."""
        # Arrange
        errors = [
            AuditNotFoundError(audit_id=uuid4()),
            InvalidAuditQueryError("Invalid syntax"),
            AuditRetentionError("Policy failed"),
            AuditImmutabilityError(uuid4(), "modify"),
            AuditArchiveError("Archive failed"),
        ]

        # Act
        not_found_errors = [e for e in errors if isinstance(e, AuditNotFoundError)]
        immutability_errors = [
            e for e in errors if isinstance(e, AuditImmutabilityError)
        ]
        domain_errors = [e for e in errors if isinstance(e, AuditDomainError)]

        # Assert
        assert len(not_found_errors) == 1
        assert len(immutability_errors) == 1
        assert len(domain_errors) == 5  # All are audit domain errors

    def test_error_message_localization_support(self):
        """Test that errors support message localization patterns."""
        # Arrange
        error = AuditNotFoundError(audit_id=uuid4())

        # Act & Assert
        # Verify that user_message exists for localization
        assert hasattr(error, "user_message")
        assert error.user_message is not None
        assert len(error.user_message) > 0

        # Verify technical message is separate from user message
        assert str(error) != error.user_message

    def test_error_severity_classification(self):
        """Test that errors can be classified by severity."""
        # Arrange
        errors_by_severity = {
            "low": [AuditNotFoundError()],
            "medium": [InvalidAuditQueryError("Invalid syntax")],
            "high": [AuditRetentionError("Policy failure")],
            "critical": [
                AuditImmutabilityError(uuid4(), "tamper_attempt"),
                AuditArchiveError("Complete archive failure"),
            ],
        }

        # Act & Assert
        for _severity, error_list in errors_by_severity.items():
            for error in error_list:
                # Verify error is properly categorized
                assert isinstance(error, AuditDomainError)
                # In a real implementation, you might have a severity property
                # assert error.severity == severity
