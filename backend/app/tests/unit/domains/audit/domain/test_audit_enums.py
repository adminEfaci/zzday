"""
Comprehensive tests for Audit domain enumerations.

This module tests all audit enums with complete coverage focusing on:
- Enum value validation and creation
- String conversion and parsing
- Comparison operations
- Business logic methods
- Edge cases and error handling
"""

import pytest

from app.modules.audit.domain.enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
    RetentionPolicy,
)


class TestAuditSeverity:
    """Test AuditSeverity enumeration."""

    def test_audit_severity_values(self):
        """Test that audit severity values are correctly defined."""
        # Assert
        assert AuditSeverity.LOW.value == "low"
        assert AuditSeverity.MEDIUM.value == "medium"
        assert AuditSeverity.HIGH.value == "high"
        assert AuditSeverity.CRITICAL.value == "critical"

    def test_audit_severity_from_string_valid(self):
        """Test creating audit severity from valid string values."""
        # Act & Assert
        assert AuditSeverity.from_string("low") == AuditSeverity.LOW
        assert AuditSeverity.from_string("medium") == AuditSeverity.MEDIUM
        assert AuditSeverity.from_string("high") == AuditSeverity.HIGH
        assert AuditSeverity.from_string("critical") == AuditSeverity.CRITICAL

    def test_audit_severity_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        # Act & Assert
        assert AuditSeverity.from_string("LOW") == AuditSeverity.LOW
        assert AuditSeverity.from_string("Medium") == AuditSeverity.MEDIUM
        assert AuditSeverity.from_string("HIGH") == AuditSeverity.HIGH
        assert AuditSeverity.from_string("CRITICAL") == AuditSeverity.CRITICAL

    def test_audit_severity_from_string_invalid_raises_error(self):
        """Test that invalid string raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid audit severity: invalid"):
            AuditSeverity.from_string("invalid")

        with pytest.raises(ValueError, match="Invalid audit severity: extreme"):
            AuditSeverity.from_string("extreme")

    def test_audit_severity_str_representation(self):
        """Test string representation of audit severity."""
        # Act & Assert
        assert str(AuditSeverity.LOW) == "low"
        assert str(AuditSeverity.MEDIUM) == "medium"
        assert str(AuditSeverity.HIGH) == "high"
        assert str(AuditSeverity.CRITICAL) == "critical"

    def test_audit_severity_comparison_less_than(self):
        """Test severity comparison using less than operator."""
        # Act & Assert
        assert AuditSeverity.LOW < AuditSeverity.MEDIUM
        assert AuditSeverity.MEDIUM < AuditSeverity.HIGH
        assert AuditSeverity.HIGH < AuditSeverity.CRITICAL

        # Test transitivity
        assert AuditSeverity.LOW < AuditSeverity.HIGH
        assert AuditSeverity.LOW < AuditSeverity.CRITICAL
        assert AuditSeverity.MEDIUM < AuditSeverity.CRITICAL

    def test_audit_severity_comparison_not_less_than(self):
        """Test severity comparison negative cases."""
        # Act & Assert
        assert not (AuditSeverity.MEDIUM < AuditSeverity.LOW)
        assert not (AuditSeverity.HIGH < AuditSeverity.MEDIUM)
        assert not (AuditSeverity.CRITICAL < AuditSeverity.HIGH)
        assert not (AuditSeverity.LOW < AuditSeverity.LOW)  # Equal values

    def test_audit_severity_comparison_equal(self):
        """Test severity equality comparison."""
        # Act & Assert
        assert AuditSeverity.LOW == AuditSeverity.LOW
        assert AuditSeverity.MEDIUM == AuditSeverity.MEDIUM
        assert AuditSeverity.HIGH == AuditSeverity.HIGH
        assert AuditSeverity.CRITICAL == AuditSeverity.CRITICAL

        # Test inequality
        assert AuditSeverity.LOW != AuditSeverity.MEDIUM
        assert AuditSeverity.HIGH != AuditSeverity.CRITICAL

    def test_audit_severity_ordering(self):
        """Test complete severity ordering."""
        # Arrange
        severities = [
            AuditSeverity.CRITICAL,
            AuditSeverity.LOW,
            AuditSeverity.HIGH,
            AuditSeverity.MEDIUM,
        ]

        # Act
        sorted_severities = sorted(severities)

        # Assert
        expected_order = [
            AuditSeverity.LOW,
            AuditSeverity.MEDIUM,
            AuditSeverity.HIGH,
            AuditSeverity.CRITICAL,
        ]
        assert sorted_severities == expected_order


class TestAuditCategory:
    """Test AuditCategory enumeration."""

    def test_audit_category_values(self):
        """Test that audit category values are correctly defined."""
        # Assert
        assert AuditCategory.AUTHENTICATION.value == "authentication"
        assert AuditCategory.AUTHORIZATION.value == "authorization"
        assert AuditCategory.DATA_ACCESS.value == "data_access"
        assert AuditCategory.CONFIGURATION.value == "configuration"
        assert AuditCategory.SYSTEM.value == "system"
        assert AuditCategory.SECURITY.value == "security"
        assert AuditCategory.COMPLIANCE.value == "compliance"
        assert AuditCategory.INTEGRATION.value == "integration"

    def test_audit_category_from_string_valid(self):
        """Test creating audit category from valid string values."""
        # Act & Assert
        assert (
            AuditCategory.from_string("authentication") == AuditCategory.AUTHENTICATION
        )
        assert AuditCategory.from_string("authorization") == AuditCategory.AUTHORIZATION
        assert AuditCategory.from_string("data_access") == AuditCategory.DATA_ACCESS
        assert AuditCategory.from_string("configuration") == AuditCategory.CONFIGURATION
        assert AuditCategory.from_string("system") == AuditCategory.SYSTEM
        assert AuditCategory.from_string("security") == AuditCategory.SECURITY
        assert AuditCategory.from_string("compliance") == AuditCategory.COMPLIANCE
        assert AuditCategory.from_string("integration") == AuditCategory.INTEGRATION

    def test_audit_category_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        # Act & Assert
        assert (
            AuditCategory.from_string("AUTHENTICATION") == AuditCategory.AUTHENTICATION
        )
        assert AuditCategory.from_string("Authorization") == AuditCategory.AUTHORIZATION
        assert AuditCategory.from_string("DATA_ACCESS") == AuditCategory.DATA_ACCESS
        assert AuditCategory.from_string("System") == AuditCategory.SYSTEM

    def test_audit_category_from_string_invalid_raises_error(self):
        """Test that invalid string raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid audit category: invalid"):
            AuditCategory.from_string("invalid")

        with pytest.raises(ValueError, match="Invalid audit category: unknown"):
            AuditCategory.from_string("unknown")

    def test_audit_category_str_representation(self):
        """Test string representation of audit category."""
        # Act & Assert
        assert str(AuditCategory.AUTHENTICATION) == "authentication"
        assert str(AuditCategory.AUTHORIZATION) == "authorization"
        assert str(AuditCategory.DATA_ACCESS) == "data_access"
        assert str(AuditCategory.CONFIGURATION) == "configuration"
        assert str(AuditCategory.SYSTEM) == "system"
        assert str(AuditCategory.SECURITY) == "security"
        assert str(AuditCategory.COMPLIANCE) == "compliance"
        assert str(AuditCategory.INTEGRATION) == "integration"

    def test_audit_category_equality(self):
        """Test category equality comparison."""
        # Act & Assert
        assert AuditCategory.AUTHENTICATION == AuditCategory.AUTHENTICATION
        assert AuditCategory.SECURITY == AuditCategory.SECURITY

        # Test inequality
        assert AuditCategory.AUTHENTICATION != AuditCategory.AUTHORIZATION
        assert AuditCategory.SECURITY != AuditCategory.COMPLIANCE


class TestRetentionPolicy:
    """Test RetentionPolicy enumeration."""

    def test_retention_policy_values(self):
        """Test that retention policy values are correctly defined."""
        # Assert
        assert RetentionPolicy.DAYS_30.label == "30_days"
        assert RetentionPolicy.DAYS_30.days == 30

        assert RetentionPolicy.DAYS_90.label == "90_days"
        assert RetentionPolicy.DAYS_90.days == 90

        assert RetentionPolicy.YEARS_1.label == "1_year"
        assert RetentionPolicy.YEARS_1.days == 365

        assert RetentionPolicy.YEARS_7.label == "7_years"
        assert RetentionPolicy.YEARS_7.days == 2555

        assert RetentionPolicy.PERMANENT.label == "permanent"
        assert RetentionPolicy.PERMANENT.days == -1

    def test_retention_policy_from_string_by_label(self):
        """Test creating retention policy from label string."""
        # Act & Assert
        assert RetentionPolicy.from_string("30_days") == RetentionPolicy.DAYS_30
        assert RetentionPolicy.from_string("90_days") == RetentionPolicy.DAYS_90
        assert RetentionPolicy.from_string("1_year") == RetentionPolicy.YEARS_1
        assert RetentionPolicy.from_string("7_years") == RetentionPolicy.YEARS_7
        assert RetentionPolicy.from_string("permanent") == RetentionPolicy.PERMANENT

    def test_retention_policy_from_string_by_name(self):
        """Test creating retention policy from enum name."""
        # Act & Assert
        assert RetentionPolicy.from_string("DAYS_30") == RetentionPolicy.DAYS_30
        assert RetentionPolicy.from_string("DAYS_90") == RetentionPolicy.DAYS_90
        assert RetentionPolicy.from_string("YEARS_1") == RetentionPolicy.YEARS_1
        assert RetentionPolicy.from_string("YEARS_7") == RetentionPolicy.YEARS_7
        assert RetentionPolicy.from_string("PERMANENT") == RetentionPolicy.PERMANENT

    def test_retention_policy_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        # Act & Assert
        assert RetentionPolicy.from_string("days_30") == RetentionPolicy.DAYS_30
        assert RetentionPolicy.from_string("PERMANENT") == RetentionPolicy.PERMANENT
        assert RetentionPolicy.from_string("Years_7") == RetentionPolicy.YEARS_7

    def test_retention_policy_from_string_invalid_raises_error(self):
        """Test that invalid string raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid retention policy: invalid"):
            RetentionPolicy.from_string("invalid")

        with pytest.raises(ValueError, match="Invalid retention policy: 60_days"):
            RetentionPolicy.from_string("60_days")

    def test_retention_policy_str_representation(self):
        """Test string representation of retention policy."""
        # Act & Assert
        assert str(RetentionPolicy.DAYS_30) == "30_days"
        assert str(RetentionPolicy.DAYS_90) == "90_days"
        assert str(RetentionPolicy.YEARS_1) == "1_year"
        assert str(RetentionPolicy.YEARS_7) == "7_years"
        assert str(RetentionPolicy.PERMANENT) == "permanent"

    def test_retention_policy_is_permanent(self):
        """Test permanent policy detection."""
        # Act & Assert
        assert RetentionPolicy.PERMANENT.is_permanent()

        # Test non-permanent policies
        assert not RetentionPolicy.DAYS_30.is_permanent()
        assert not RetentionPolicy.DAYS_90.is_permanent()
        assert not RetentionPolicy.YEARS_1.is_permanent()
        assert not RetentionPolicy.YEARS_7.is_permanent()

    def test_retention_policy_get_retention_days(self):
        """Test retention days retrieval."""
        # Act & Assert
        assert RetentionPolicy.DAYS_30.get_retention_days() == 30
        assert RetentionPolicy.DAYS_90.get_retention_days() == 90
        assert RetentionPolicy.YEARS_1.get_retention_days() == 365
        assert RetentionPolicy.YEARS_7.get_retention_days() == 2555
        assert RetentionPolicy.PERMANENT.get_retention_days() == -1

    def test_retention_policy_equality(self):
        """Test retention policy equality."""
        # Act & Assert
        assert RetentionPolicy.DAYS_30 == RetentionPolicy.DAYS_30
        assert RetentionPolicy.PERMANENT == RetentionPolicy.PERMANENT

        # Test inequality
        assert RetentionPolicy.DAYS_30 != RetentionPolicy.DAYS_90
        assert RetentionPolicy.YEARS_1 != RetentionPolicy.PERMANENT


class TestAuditStatus:
    """Test AuditStatus enumeration."""

    def test_audit_status_values(self):
        """Test that audit status values are correctly defined."""
        # Assert
        assert AuditStatus.ACTIVE.value == "active"
        assert AuditStatus.ARCHIVED.value == "archived"
        assert AuditStatus.DELETED.value == "deleted"
        assert AuditStatus.PENDING_ARCHIVE.value == "pending_archive"
        assert AuditStatus.PENDING_DELETE.value == "pending_delete"

    def test_audit_status_from_string_valid(self):
        """Test creating audit status from valid string values."""
        # Act & Assert
        assert AuditStatus.from_string("active") == AuditStatus.ACTIVE
        assert AuditStatus.from_string("archived") == AuditStatus.ARCHIVED
        assert AuditStatus.from_string("deleted") == AuditStatus.DELETED
        assert AuditStatus.from_string("pending_archive") == AuditStatus.PENDING_ARCHIVE
        assert AuditStatus.from_string("pending_delete") == AuditStatus.PENDING_DELETE

    def test_audit_status_from_string_case_insensitive(self):
        """Test that from_string is case insensitive."""
        # Act & Assert
        assert AuditStatus.from_string("ACTIVE") == AuditStatus.ACTIVE
        assert AuditStatus.from_string("Archived") == AuditStatus.ARCHIVED
        assert AuditStatus.from_string("PENDING_ARCHIVE") == AuditStatus.PENDING_ARCHIVE

    def test_audit_status_from_string_invalid_raises_error(self):
        """Test that invalid string raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid audit status: invalid"):
            AuditStatus.from_string("invalid")

        with pytest.raises(ValueError, match="Invalid audit status: processing"):
            AuditStatus.from_string("processing")

    def test_audit_status_str_representation(self):
        """Test string representation of audit status."""
        # Act & Assert
        assert str(AuditStatus.ACTIVE) == "active"
        assert str(AuditStatus.ARCHIVED) == "archived"
        assert str(AuditStatus.DELETED) == "deleted"
        assert str(AuditStatus.PENDING_ARCHIVE) == "pending_archive"
        assert str(AuditStatus.PENDING_DELETE) == "pending_delete"

    def test_audit_status_is_active(self):
        """Test active status detection."""
        # Act & Assert
        assert AuditStatus.ACTIVE.is_active()

        # Test non-active statuses
        assert not AuditStatus.ARCHIVED.is_active()
        assert not AuditStatus.DELETED.is_active()
        assert not AuditStatus.PENDING_ARCHIVE.is_active()
        assert not AuditStatus.PENDING_DELETE.is_active()

    def test_audit_status_is_archived(self):
        """Test archived status detection."""
        # Act & Assert
        assert AuditStatus.ARCHIVED.is_archived()
        assert AuditStatus.PENDING_ARCHIVE.is_archived()

        # Test non-archived statuses
        assert not AuditStatus.ACTIVE.is_archived()
        assert not AuditStatus.DELETED.is_archived()
        assert not AuditStatus.PENDING_DELETE.is_archived()

    def test_audit_status_is_deleted(self):
        """Test deleted status detection."""
        # Act & Assert
        assert AuditStatus.DELETED.is_deleted()
        assert AuditStatus.PENDING_DELETE.is_deleted()

        # Test non-deleted statuses
        assert not AuditStatus.ACTIVE.is_deleted()
        assert not AuditStatus.ARCHIVED.is_deleted()
        assert not AuditStatus.PENDING_ARCHIVE.is_deleted()

    def test_audit_status_can_transition_to_from_active(self):
        """Test valid transitions from ACTIVE status."""
        # Act & Assert
        assert AuditStatus.ACTIVE.can_transition_to(AuditStatus.PENDING_ARCHIVE)
        assert AuditStatus.ACTIVE.can_transition_to(AuditStatus.PENDING_DELETE)

        # Invalid transitions
        assert not AuditStatus.ACTIVE.can_transition_to(AuditStatus.ARCHIVED)
        assert not AuditStatus.ACTIVE.can_transition_to(AuditStatus.DELETED)
        assert not AuditStatus.ACTIVE.can_transition_to(AuditStatus.ACTIVE)

    def test_audit_status_can_transition_to_from_pending_archive(self):
        """Test valid transitions from PENDING_ARCHIVE status."""
        # Act & Assert
        assert AuditStatus.PENDING_ARCHIVE.can_transition_to(AuditStatus.ARCHIVED)
        assert AuditStatus.PENDING_ARCHIVE.can_transition_to(AuditStatus.ACTIVE)

        # Invalid transitions
        assert not AuditStatus.PENDING_ARCHIVE.can_transition_to(AuditStatus.DELETED)
        assert not AuditStatus.PENDING_ARCHIVE.can_transition_to(
            AuditStatus.PENDING_DELETE
        )
        assert not AuditStatus.PENDING_ARCHIVE.can_transition_to(
            AuditStatus.PENDING_ARCHIVE
        )

    def test_audit_status_can_transition_to_from_pending_delete(self):
        """Test valid transitions from PENDING_DELETE status."""
        # Act & Assert
        assert AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.DELETED)
        assert AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.ACTIVE)

        # Invalid transitions
        assert not AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.ARCHIVED)
        assert not AuditStatus.PENDING_DELETE.can_transition_to(
            AuditStatus.PENDING_ARCHIVE
        )
        assert not AuditStatus.PENDING_DELETE.can_transition_to(
            AuditStatus.PENDING_DELETE
        )

    def test_audit_status_can_transition_to_from_archived(self):
        """Test valid transitions from ARCHIVED status."""
        # Act & Assert
        assert AuditStatus.ARCHIVED.can_transition_to(AuditStatus.PENDING_DELETE)

        # Invalid transitions
        assert not AuditStatus.ARCHIVED.can_transition_to(AuditStatus.ACTIVE)
        assert not AuditStatus.ARCHIVED.can_transition_to(AuditStatus.PENDING_ARCHIVE)
        assert not AuditStatus.ARCHIVED.can_transition_to(AuditStatus.DELETED)
        assert not AuditStatus.ARCHIVED.can_transition_to(AuditStatus.ARCHIVED)

    def test_audit_status_can_transition_to_from_deleted(self):
        """Test valid transitions from DELETED status."""
        # Act & Assert - No valid transitions from DELETED
        assert not AuditStatus.DELETED.can_transition_to(AuditStatus.ACTIVE)
        assert not AuditStatus.DELETED.can_transition_to(AuditStatus.ARCHIVED)
        assert not AuditStatus.DELETED.can_transition_to(AuditStatus.PENDING_ARCHIVE)
        assert not AuditStatus.DELETED.can_transition_to(AuditStatus.PENDING_DELETE)
        assert not AuditStatus.DELETED.can_transition_to(AuditStatus.DELETED)

    def test_audit_status_complete_transition_workflow(self):
        """Test complete status transition workflow."""
        # Test normal archive workflow
        assert AuditStatus.ACTIVE.can_transition_to(AuditStatus.PENDING_ARCHIVE)
        assert AuditStatus.PENDING_ARCHIVE.can_transition_to(AuditStatus.ARCHIVED)
        assert AuditStatus.ARCHIVED.can_transition_to(AuditStatus.PENDING_DELETE)
        assert AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.DELETED)

        # Test direct delete workflow
        assert AuditStatus.ACTIVE.can_transition_to(AuditStatus.PENDING_DELETE)
        assert AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.DELETED)

        # Test cancellation workflows
        assert AuditStatus.PENDING_ARCHIVE.can_transition_to(AuditStatus.ACTIVE)
        assert AuditStatus.PENDING_DELETE.can_transition_to(AuditStatus.ACTIVE)


class TestEnumIntegration:
    """Test integration between different audit enums."""

    def test_enum_combinations_in_audit_context(self):
        """Test that enums work together in audit contexts."""
        # Arrange - Create combinations that would be used together
        high_security_config = {
            "severity": AuditSeverity.HIGH,
            "category": AuditCategory.SECURITY,
            "retention": RetentionPolicy.YEARS_7,
            "status": AuditStatus.ACTIVE,
        }

        compliance_config = {
            "severity": AuditSeverity.CRITICAL,
            "category": AuditCategory.COMPLIANCE,
            "retention": RetentionPolicy.PERMANENT,
            "status": AuditStatus.ACTIVE,
        }

        # Act & Assert - Verify enum combinations work as expected
        assert high_security_config["severity"] > AuditSeverity.MEDIUM
        assert high_security_config["category"] == AuditCategory.SECURITY
        assert not high_security_config["retention"].is_permanent()
        assert high_security_config["status"].is_active()

        assert compliance_config["severity"] > high_security_config["severity"]
        assert compliance_config["category"] == AuditCategory.COMPLIANCE
        assert compliance_config["retention"].is_permanent()
        assert compliance_config["status"].is_active()

    def test_enum_string_conversions_consistency(self):
        """Test that all enums have consistent string conversion behavior."""
        # Arrange
        enums_to_test = [
            (AuditSeverity.HIGH, "high"),
            (AuditCategory.SECURITY, "security"),
            (RetentionPolicy.YEARS_7, "7_years"),
            (AuditStatus.ACTIVE, "active"),
        ]

        # Act & Assert
        for enum_value, expected_string in enums_to_test:
            assert str(enum_value) == expected_string

    def test_enum_from_string_consistency(self):
        """Test that all enums support from_string method consistently."""
        # Act & Assert
        assert AuditSeverity.from_string("critical") == AuditSeverity.CRITICAL
        assert AuditCategory.from_string("compliance") == AuditCategory.COMPLIANCE
        assert RetentionPolicy.from_string("permanent") == RetentionPolicy.PERMANENT
        assert AuditStatus.from_string("archived") == AuditStatus.ARCHIVED


class TestEnumEdgeCases:
    """Test edge cases and error conditions for all enums."""

    @pytest.mark.parametrize(
        ("enum_class", "invalid_value"),
        [
            (AuditSeverity, ""),
            (AuditSeverity, "   "),
            (AuditSeverity, "extreme"),
            (AuditCategory, "unknown"),
            (AuditCategory, "user_access"),
            (RetentionPolicy, "forever"),
            (RetentionPolicy, "2_years"),
            (AuditStatus, "processing"),
            (AuditStatus, "suspended"),
        ],
    )
    def test_enum_from_string_with_invalid_values(self, enum_class, invalid_value):
        """Test that all enums properly handle invalid string values."""
        # Act & Assert
        with pytest.raises(ValueError):
            enum_class.from_string(invalid_value)

    def test_enum_values_are_hashable(self):
        """Test that all enum values can be used as dictionary keys."""
        # Act
        enum_dict = {
            AuditSeverity.HIGH: "high_severity",
            AuditCategory.SECURITY: "security_category",
            RetentionPolicy.PERMANENT: "permanent_retention",
            AuditStatus.ACTIVE: "active_status",
        }

        # Assert
        assert enum_dict[AuditSeverity.HIGH] == "high_severity"
        assert enum_dict[AuditCategory.SECURITY] == "security_category"
        assert enum_dict[RetentionPolicy.PERMANENT] == "permanent_retention"
        assert enum_dict[AuditStatus.ACTIVE] == "active_status"

    def test_enum_values_are_comparable_to_themselves(self):
        """Test that enum values can be compared to themselves."""
        # Act & Assert
        assert AuditSeverity.HIGH == AuditSeverity.HIGH
        assert AuditCategory.SECURITY == AuditCategory.SECURITY
        assert RetentionPolicy.PERMANENT == RetentionPolicy.PERMANENT
        assert AuditStatus.ACTIVE == AuditStatus.ACTIVE

        # Test inequality
        assert AuditSeverity.HIGH != AuditSeverity.LOW
        assert AuditCategory.SECURITY != AuditCategory.COMPLIANCE
        assert RetentionPolicy.PERMANENT != RetentionPolicy.DAYS_30
        assert AuditStatus.ACTIVE != AuditStatus.DELETED

    def test_enum_membership(self):
        """Test enum membership operations."""
        # Act & Assert
        assert AuditSeverity.HIGH in AuditSeverity
        assert AuditCategory.SECURITY in AuditCategory
        assert RetentionPolicy.PERMANENT in RetentionPolicy
        assert AuditStatus.ACTIVE in AuditStatus

    def test_enum_iteration(self):
        """Test that all enums can be iterated."""
        # Act
        severity_values = list(AuditSeverity)
        category_values = list(AuditCategory)
        retention_values = list(RetentionPolicy)
        status_values = list(AuditStatus)

        # Assert
        assert len(severity_values) == 4
        assert len(category_values) == 8
        assert len(retention_values) == 5
        assert len(status_values) == 5

        # Verify specific values are present
        assert AuditSeverity.CRITICAL in severity_values
        assert AuditCategory.COMPLIANCE in category_values
        assert RetentionPolicy.PERMANENT in retention_values
        assert AuditStatus.DELETED in status_values
