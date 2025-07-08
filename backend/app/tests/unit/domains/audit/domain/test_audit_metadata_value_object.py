"""
Comprehensive tests for AuditMetadata value object.

This module tests the AuditMetadata value object with complete coverage focusing on:
- Value object immutability
- Tag validation and normalization
- Data classification validation
- Compliance flag management
- Metadata merging and manipulation
- Factory methods for common scenarios
"""

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata


class TestAuditMetadataCreation:
    """Test audit metadata creation and initialization."""

    def test_create_audit_metadata_with_all_fields(self):
        """Test creating audit metadata with all fields."""
        # Arrange
        tags = ["security", "authentication", "login"]
        business_context = {
            "department": "IT",
            "cost_center": "CC-001",
            "project": "USER_AUTH",
        }
        compliance_flags = {"gdpr": True, "sox": False, "hipaa": True}
        custom_fields = {
            "priority": "high",
            "reviewer": "security_team",
            "ticket_id": "SEC-12345",
        }

        # Act
        metadata = AuditMetadata(
            tags=tags,
            business_context=business_context,
            compliance_flags=compliance_flags,
            data_classification="confidential",
            retention_override="permanent",
            custom_fields=custom_fields,
        )

        # Assert
        assert metadata.tags == ["security", "authentication", "login"]
        assert metadata.business_context["department"] == "IT"
        assert metadata.business_context["cost_center"] == "CC-001"
        assert metadata.business_context["project"] == "USER_AUTH"
        assert metadata.compliance_flags["gdpr"] is True
        assert metadata.compliance_flags["sox"] is False
        assert metadata.compliance_flags["hipaa"] is True
        assert metadata.data_classification == "confidential"
        assert metadata.retention_override == "permanent"
        assert metadata.custom_fields["priority"] == "high"
        assert metadata.custom_fields["reviewer"] == "security_team"
        assert metadata.custom_fields["ticket_id"] == "SEC-12345"

    def test_create_audit_metadata_with_minimal_fields(self):
        """Test creating audit metadata with minimal fields."""
        # Act
        metadata = AuditMetadata()

        # Assert
        assert metadata.tags == []
        assert metadata.business_context == {}
        assert metadata.compliance_flags == {}
        assert metadata.data_classification == "internal"  # Default
        assert metadata.retention_override is None
        assert metadata.custom_fields == {}

    def test_create_audit_metadata_with_custom_classification(self):
        """Test creating audit metadata with custom data classification."""
        # Act
        metadata = AuditMetadata(data_classification="restricted")

        # Assert
        assert metadata.data_classification == "restricted"

    def test_create_audit_metadata_normalizes_classification(self):
        """Test that data classification is normalized to lowercase."""
        # Act
        metadata = AuditMetadata(data_classification="  CONFIDENTIAL  ")

        # Assert
        assert metadata.data_classification == "confidential"

    @pytest.mark.parametrize("invalid_classification", ["invalid", "secret", "", "   "])
    def test_create_audit_metadata_with_invalid_classification_raises_error(
        self, invalid_classification
    ):
        """Test that invalid data classification raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid data classification"):
            AuditMetadata(data_classification=invalid_classification)

    @pytest.mark.parametrize(
        "valid_classification",
        ["public", "internal", "confidential", "restricted", "PUBLIC", "INTERNAL"],
    )
    def test_create_audit_metadata_with_valid_classifications(
        self, valid_classification
    ):
        """Test creating metadata with all valid classifications."""
        # Act
        metadata = AuditMetadata(data_classification=valid_classification)

        # Assert
        assert metadata.data_classification == valid_classification.lower()


class TestAuditMetadataImmutability:
    """Test audit metadata value object immutability."""

    def test_audit_metadata_is_frozen_after_creation(self):
        """Test that audit metadata is immutable after creation."""
        # Arrange
        metadata = AuditMetadata(tags=["test"], data_classification="confidential")

        # Act & Assert - Attempting to modify should raise an error
        with pytest.raises(AttributeError):
            metadata.tags.append("new_tag")

        with pytest.raises(AttributeError):
            metadata.data_classification = "public"

        with pytest.raises(AttributeError):
            metadata.new_field = "value"

    def test_nested_data_is_copied_not_referenced(self):
        """Test that nested data structures are copied, not referenced."""
        # Arrange
        original_context = {"key": "value"}
        original_flags = {"gdpr": True}
        original_custom = {"field": "value"}

        metadata = AuditMetadata(
            business_context=original_context,
            compliance_flags=original_flags,
            custom_fields=original_custom,
        )

        # Act - Modify original data
        original_context["key"] = "modified"
        original_flags["gdpr"] = False
        original_custom["field"] = "modified"

        # Assert - Metadata should remain unchanged
        assert metadata.business_context["key"] == "value"
        assert metadata.compliance_flags["gdpr"] is True
        assert metadata.custom_fields["field"] == "value"


class TestAuditMetadataTagValidation:
    """Test tag validation and normalization."""

    def test_create_metadata_with_valid_tags(self):
        """Test creating metadata with valid tags."""
        # Arrange
        tags = ["security", "authentication", "user-management", "api_access"]

        # Act
        metadata = AuditMetadata(tags=tags)

        # Assert
        assert metadata.tags == [
            "security",
            "authentication",
            "user-management",
            "api_access",
        ]

    def test_create_metadata_normalizes_tags(self):
        """Test that tags are normalized to lowercase and trimmed."""
        # Arrange
        tags = ["  SECURITY  ", "Authentication", "USER_Management"]

        # Act
        metadata = AuditMetadata(tags=tags)

        # Assert
        assert metadata.tags == ["security", "authentication", "user_management"]

    def test_create_metadata_removes_duplicate_tags(self):
        """Test that duplicate tags are removed."""
        # Arrange
        tags = ["security", "SECURITY", "authentication", "security", "data"]

        # Act
        metadata = AuditMetadata(tags=tags)

        # Assert
        assert metadata.tags == ["security", "authentication", "data"]
        assert len(metadata.tags) == 3

    def test_create_metadata_removes_empty_tags(self):
        """Test that empty tags are removed."""
        # Arrange
        tags = ["security", "", "   ", "authentication", None]

        # Act
        metadata = AuditMetadata(tags=[t for t in tags if t is not None])

        # Assert
        assert metadata.tags == ["security", "authentication"]

    def test_create_metadata_with_non_string_tags_raises_error(self):
        """Test that non-string tags raise ValidationError."""
        # Arrange
        tags = ["security", 123, "authentication"]

        # Act & Assert
        with pytest.raises(ValidationError, match="Each tag must be a string"):
            AuditMetadata(tags=tags)

    def test_create_metadata_with_non_list_tags_raises_error(self):
        """Test that non-list tags raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Tags must be a list"):
            AuditMetadata(tags="not_a_list")

    def test_create_metadata_with_too_long_tag_raises_error(self):
        """Test that tags exceeding length limit raise ValidationError."""
        # Arrange
        long_tag = "A" * 51  # Exceeds 50 character limit
        tags = ["security", long_tag]

        # Act & Assert
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            AuditMetadata(tags=tags)


class TestAuditMetadataTagQueries:
    """Test tag query and manipulation methods."""

    @pytest.fixture
    def sample_metadata(self):
        """Create sample metadata with tags for testing."""
        return AuditMetadata(
            tags=["security", "authentication", "user", "api"],
            data_classification="confidential",
        )

    def test_has_tag(self, sample_metadata):
        """Test tag presence checking."""
        # Assert
        assert sample_metadata.has_tag("security")
        assert sample_metadata.has_tag("SECURITY")  # Case insensitive
        assert sample_metadata.has_tag("authentication")
        assert not sample_metadata.has_tag("nonexistent")
        assert not sample_metadata.has_tag("authorization")

    def test_has_any_tag(self, sample_metadata):
        """Test checking for any of multiple tags."""
        # Assert
        assert sample_metadata.has_any_tag(["security", "nonexistent"])
        assert sample_metadata.has_any_tag(
            ["SECURITY", "NONEXISTENT"]
        )  # Case insensitive
        assert sample_metadata.has_any_tag(["authentication", "authorization"])
        assert not sample_metadata.has_any_tag(["nonexistent", "missing"])

    def test_has_all_tags(self, sample_metadata):
        """Test checking for all of multiple tags."""
        # Assert
        assert sample_metadata.has_all_tags(["security", "authentication"])
        assert sample_metadata.has_all_tags(["SECURITY", "USER"])  # Case insensitive
        assert sample_metadata.has_all_tags(["api"])  # Single tag
        assert not sample_metadata.has_all_tags(["security", "nonexistent"])
        assert not sample_metadata.has_all_tags(["nonexistent", "missing"])

    def test_with_tag(self, sample_metadata):
        """Test adding a tag to metadata."""
        # Act
        new_metadata = sample_metadata.with_tag("compliance")

        # Assert
        assert new_metadata.has_tag("compliance")
        assert new_metadata.has_tag("security")  # Original tags preserved
        assert not sample_metadata.has_tag("compliance")  # Original unchanged

        # Verify all original tags are preserved
        for tag in sample_metadata.tags:
            assert new_metadata.has_tag(tag)

    def test_with_tag_duplicate_ignored(self, sample_metadata):
        """Test that adding duplicate tag is ignored."""
        # Act
        new_metadata = sample_metadata.with_tag("security")

        # Assert
        assert len(new_metadata.tags) == len(sample_metadata.tags)
        assert new_metadata.tags == sample_metadata.tags

    def test_with_tag_case_insensitive_duplicate(self, sample_metadata):
        """Test that adding tag with different case is treated as duplicate."""
        # Act
        new_metadata = sample_metadata.with_tag("SECURITY")

        # Assert
        assert len(new_metadata.tags) == len(sample_metadata.tags)
        assert new_metadata.tags == sample_metadata.tags


class TestAuditMetadataComplianceFlags:
    """Test compliance flag management."""

    def test_is_compliant_with(self):
        """Test compliance checking."""
        # Arrange
        metadata = AuditMetadata(
            compliance_flags={"gdpr": True, "sox": False, "hipaa": True}
        )

        # Assert
        assert metadata.is_compliant_with("gdpr")
        assert metadata.is_compliant_with("GDPR")  # Case insensitive
        assert not metadata.is_compliant_with("sox")
        assert metadata.is_compliant_with("hipaa")
        assert not metadata.is_compliant_with("nonexistent")  # Default False

    def test_with_compliance_flag(self):
        """Test adding/updating compliance flags."""
        # Arrange
        metadata = AuditMetadata(compliance_flags={"gdpr": True})

        # Act
        new_metadata = metadata.with_compliance_flag("sox", True)
        updated_metadata = new_metadata.with_compliance_flag("gdpr", False)

        # Assert
        assert new_metadata.is_compliant_with("sox")
        assert new_metadata.is_compliant_with("gdpr")  # Original preserved

        assert updated_metadata.is_compliant_with("sox")
        assert not updated_metadata.is_compliant_with("gdpr")  # Updated

        # Original should remain unchanged
        assert metadata.is_compliant_with("gdpr")
        assert not metadata.is_compliant_with("sox")

    def test_with_compliance_flag_case_insensitive(self):
        """Test that compliance flag keys are case insensitive."""
        # Arrange
        metadata = AuditMetadata()

        # Act
        new_metadata = metadata.with_compliance_flag("GDPR", True)

        # Assert
        assert new_metadata.is_compliant_with("gdpr")
        assert new_metadata.is_compliant_with("GDPR")


class TestAuditMetadataDataClassification:
    """Test data classification validation and features."""

    @pytest.mark.parametrize(
        ("classification", "expected_encryption"),
        [
            ("public", False),
            ("internal", False),
            ("confidential", True),
            ("restricted", True),
        ],
    )
    def test_requires_encryption(self, classification, expected_encryption):
        """Test encryption requirement based on classification."""
        # Arrange
        metadata = AuditMetadata(data_classification=classification)

        # Act & Assert
        assert metadata.requires_encryption() == expected_encryption

    @pytest.mark.parametrize(
        ("classification", "expected_restricted"),
        [
            ("public", False),
            ("internal", False),
            ("confidential", False),
            ("restricted", True),
        ],
    )
    def test_requires_restricted_access(self, classification, expected_restricted):
        """Test restricted access requirement based on classification."""
        # Arrange
        metadata = AuditMetadata(data_classification=classification)

        # Act & Assert
        assert metadata.requires_restricted_access() == expected_restricted


class TestAuditMetadataMerging:
    """Test metadata merging functionality."""

    def test_merge_with_tags(self):
        """Test merging metadata with different tags."""
        # Arrange
        metadata1 = AuditMetadata(
            tags=["security", "authentication"], data_classification="internal"
        )
        metadata2 = AuditMetadata(
            tags=["compliance", "audit"], data_classification="confidential"
        )

        # Act
        merged = metadata1.merge_with(metadata2)

        # Assert
        expected_tags = ["security", "authentication", "compliance", "audit"]
        assert len(merged.tags) == 4
        for tag in expected_tags:
            assert merged.has_tag(tag)

    def test_merge_with_business_context(self):
        """Test merging business context."""
        # Arrange
        metadata1 = AuditMetadata(
            business_context={"department": "IT", "project": "AUTH"}
        )
        metadata2 = AuditMetadata(
            business_context={"cost_center": "CC-001", "department": "Security"}
        )

        # Act
        merged = metadata1.merge_with(metadata2)

        # Assert
        assert merged.business_context["department"] == "Security"  # metadata2 wins
        assert merged.business_context["project"] == "AUTH"  # metadata1 preserved
        assert merged.business_context["cost_center"] == "CC-001"  # metadata2 added

    def test_merge_with_compliance_flags(self):
        """Test merging compliance flags."""
        # Arrange
        metadata1 = AuditMetadata(compliance_flags={"gdpr": True, "sox": False})
        metadata2 = AuditMetadata(compliance_flags={"hipaa": True, "sox": True})

        # Act
        merged = metadata1.merge_with(metadata2)

        # Assert
        assert merged.compliance_flags["gdpr"] is True  # metadata1 preserved
        assert merged.compliance_flags["sox"] is True  # metadata2 wins
        assert merged.compliance_flags["hipaa"] is True  # metadata2 added

    def test_merge_with_custom_fields(self):
        """Test merging custom fields."""
        # Arrange
        metadata1 = AuditMetadata(
            custom_fields={"priority": "medium", "reviewer": "team1"}
        )
        metadata2 = AuditMetadata(
            custom_fields={"ticket_id": "SEC-123", "priority": "high"}
        )

        # Act
        merged = metadata1.merge_with(metadata2)

        # Assert
        assert merged.custom_fields["priority"] == "high"  # metadata2 wins
        assert merged.custom_fields["reviewer"] == "team1"  # metadata1 preserved
        assert merged.custom_fields["ticket_id"] == "SEC-123"  # metadata2 added

    def test_merge_with_data_classification_priority(self):
        """Test that more restrictive classification is preserved."""
        # Arrange
        test_cases = [
            ("public", "internal", "internal"),
            ("internal", "confidential", "confidential"),
            ("confidential", "restricted", "restricted"),
            ("public", "restricted", "restricted"),
            ("confidential", "public", "confidential"),
        ]

        for class1, class2, expected in test_cases:
            metadata1 = AuditMetadata(data_classification=class1)
            metadata2 = AuditMetadata(data_classification=class2)

            # Act
            merged = metadata1.merge_with(metadata2)

            # Assert
            assert (
                merged.data_classification == expected
            ), f"Merging {class1} with {class2} should result in {expected}"

    def test_merge_with_retention_override(self):
        """Test merging retention override."""
        # Arrange
        metadata1 = AuditMetadata(retention_override=None)
        metadata2 = AuditMetadata(retention_override="permanent")
        metadata3 = AuditMetadata(retention_override="7_years")

        # Act & Assert
        # metadata2's override should be used when metadata1 has none
        merged1 = metadata1.merge_with(metadata2)
        assert merged1.retention_override == "permanent"

        # metadata3's override should be used when metadata2 already has one
        merged2 = metadata2.merge_with(metadata3)
        assert merged2.retention_override == "7_years"


class TestAuditMetadataStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_minimal(self):
        """Test string representation with minimal data."""
        # Arrange
        metadata = AuditMetadata()

        # Act
        string_repr = str(metadata)

        # Assert
        assert "classification=internal" in string_repr
        assert "AuditMetadata(" in string_repr

    def test_str_representation_with_tags(self):
        """Test string representation with tags."""
        # Arrange
        metadata = AuditMetadata(
            tags=["security", "compliance"], data_classification="confidential"
        )

        # Act
        string_repr = str(metadata)

        # Assert
        assert "classification=confidential" in string_repr
        assert "tags=security,compliance" in string_repr

    def test_str_representation_with_compliance(self):
        """Test string representation with compliance flags."""
        # Arrange
        metadata = AuditMetadata(
            compliance_flags={"gdpr": True, "sox": False, "hipaa": True},
            data_classification="restricted",
        )

        # Act
        string_repr = str(metadata)

        # Assert
        assert "classification=restricted" in string_repr
        assert "compliance=" in string_repr
        # Should only show compliant regulations
        assert "gdpr" in string_repr
        assert "hipaa" in string_repr
        assert "sox" not in string_repr  # False, so shouldn't appear


class TestAuditMetadataFactoryMethods:
    """Test factory methods for common metadata scenarios."""

    def test_create_default(self):
        """Test default metadata factory method."""
        # Act
        metadata = AuditMetadata.create_default()

        # Assert
        assert metadata.tags == []
        assert metadata.business_context == {}
        assert metadata.compliance_flags == {}
        assert metadata.data_classification == "internal"
        assert metadata.retention_override is None
        assert metadata.custom_fields == {}

    @pytest.mark.parametrize(
        ("severity", "expected_classification", "expected_tags"),
        [
            ("low", "confidential", ["security", "low"]),
            ("medium", "confidential", ["security", "medium"]),
            ("high", "confidential", ["security", "high"]),
            ("critical", "restricted", ["security", "critical"]),
        ],
    )
    def test_create_for_security_event(
        self, severity, expected_classification, expected_tags
    ):
        """Test security event metadata factory method."""
        # Act
        metadata = AuditMetadata.create_for_security_event(severity)

        # Assert
        assert metadata.data_classification == expected_classification
        assert metadata.tags == expected_tags
        assert metadata.compliance_flags == {}

    def test_create_for_security_event_with_compliance(self):
        """Test security event metadata with compliance regulations."""
        # Act
        metadata = AuditMetadata.create_for_security_event(
            severity="high", compliance_regulations=["gdpr", "sox"]
        )

        # Assert
        assert metadata.data_classification == "confidential"
        assert metadata.tags == ["security", "high"]
        assert metadata.compliance_flags["gdpr"] is True
        assert metadata.compliance_flags["sox"] is True


class TestAuditMetadataClassificationConstants:
    """Test data classification constants."""

    def test_classification_constants(self):
        """Test that classification constants are properly defined."""
        # Assert
        assert AuditMetadata.CLASSIFICATION_PUBLIC == "public"
        assert AuditMetadata.CLASSIFICATION_INTERNAL == "internal"
        assert AuditMetadata.CLASSIFICATION_CONFIDENTIAL == "confidential"
        assert AuditMetadata.CLASSIFICATION_RESTRICTED == "restricted"

    def test_create_metadata_with_constants(self):
        """Test creating metadata using predefined constants."""
        # Act
        metadata = AuditMetadata(
            data_classification=AuditMetadata.CLASSIFICATION_RESTRICTED
        )

        # Assert
        assert metadata.data_classification == "restricted"
        assert metadata.requires_encryption()
        assert metadata.requires_restricted_access()


class TestAuditMetadataEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_metadata_with_empty_nested_objects(self):
        """Test creating metadata with empty nested objects."""
        # Act
        metadata = AuditMetadata(
            tags=[], business_context={}, compliance_flags={}, custom_fields={}
        )

        # Assert
        assert metadata.tags == []
        assert metadata.business_context == {}
        assert metadata.compliance_flags == {}
        assert metadata.custom_fields == {}

    def test_merge_with_empty_metadata(self):
        """Test merging with empty metadata."""
        # Arrange
        metadata = AuditMetadata(tags=["security"], data_classification="confidential")
        empty_metadata = AuditMetadata()

        # Act
        merged = metadata.merge_with(empty_metadata)

        # Assert
        assert merged.tags == ["security"]
        assert merged.data_classification == "confidential"  # More restrictive

    def test_compliance_with_case_variations(self):
        """Test compliance checking with various case combinations."""
        # Arrange
        metadata = AuditMetadata(
            compliance_flags={"gdpr": True, "SOX": True, "HiPaA": True}
        )

        # Act & Assert
        assert metadata.is_compliant_with("gdpr")
        assert metadata.is_compliant_with("GDPR")
        assert metadata.is_compliant_with("sox")
        assert metadata.is_compliant_with("SOX")
        assert metadata.is_compliant_with("hipaa")
        assert metadata.is_compliant_with("HIPAA")
        assert metadata.is_compliant_with("HiPaA")

    def test_tag_operations_with_unicode(self):
        """Test tag operations with unicode characters."""
        # Act
        metadata = AuditMetadata(tags=["sécurité", "données", "🔒"])
        new_metadata = metadata.with_tag("conformité")

        # Assert
        assert metadata.has_tag("sécurité")
        assert metadata.has_tag("🔒")
        assert new_metadata.has_tag("conformité")
        assert new_metadata.has_tag("sécurité")
