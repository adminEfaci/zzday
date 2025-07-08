"""
Comprehensive tests for ResourceIdentifier value object.

This module tests the ResourceIdentifier value object with complete coverage focusing on:
- Value object immutability
- Resource identification and validation
- Hierarchical resource relationships
- UUID vs string-based identifiers
- Factory methods for common resource types
- Display and audit string representations
"""

from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)


class TestResourceIdentifierCreation:
    """Test resource identifier creation and initialization."""

    def test_create_resource_identifier_with_all_fields(self):
        """Test creating resource identifier with all fields."""
        # Arrange
        resource_type = "user"
        resource_id = str(uuid4())
        resource_name = "John Doe"
        parent_type = "organization"
        parent_id = str(uuid4())
        attributes = {
            "department": "Engineering",
            "role": "Senior Developer",
            "active": True,
        }

        # Act
        resource = ResourceIdentifier(
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            parent_type=parent_type,
            parent_id=parent_id,
            attributes=attributes,
        )

        # Assert
        assert resource.resource_type == "user"
        assert resource.resource_id == resource_id
        assert resource.resource_name == "John Doe"
        assert resource.parent_type == "organization"
        assert resource.parent_id == parent_id
        assert resource.attributes["department"] == "Engineering"
        assert resource.attributes["role"] == "Senior Developer"
        assert resource.attributes["active"] is True

    def test_create_resource_identifier_with_minimal_fields(self):
        """Test creating resource identifier with minimal required fields."""
        # Act
        resource = ResourceIdentifier(resource_type="document", resource_id="DOC-12345")

        # Assert
        assert resource.resource_type == "document"
        assert resource.resource_id == "DOC-12345"
        assert resource.resource_name is None
        assert resource.parent_type is None
        assert resource.parent_id is None
        assert resource.attributes == {}

    def test_create_resource_identifier_normalizes_type(self):
        """Test that resource type is normalized to lowercase."""
        # Act
        resource = ResourceIdentifier(resource_type="  USER  ", resource_id="user-123")

        # Assert
        assert resource.resource_type == "user"

    def test_create_resource_identifier_trims_whitespace(self):
        """Test that resource fields are trimmed."""
        # Act
        resource = ResourceIdentifier(
            resource_type="  user  ",
            resource_id="  user-123  ",
            resource_name="  John Doe  ",
        )

        # Assert
        assert resource.resource_type == "user"
        assert resource.resource_id == "user-123"
        assert resource.resource_name == "John Doe"

    def test_create_resource_identifier_converts_id_to_string(self):
        """Test that resource ID is converted to string."""
        # Arrange
        uuid_id = uuid4()

        # Act
        resource = ResourceIdentifier(
            resource_type="user", resource_id=uuid_id  # Pass UUID object
        )

        # Assert
        assert resource.resource_id == str(uuid_id)
        assert isinstance(resource.resource_id, str)

    @pytest.mark.parametrize(
        ("invalid_field", "field_value"),
        [
            ("resource_type", ""),
            ("resource_type", "   "),
            ("resource_type", None),
            ("resource_id", ""),
            ("resource_id", "   "),
            ("resource_id", None),
        ],
    )
    def test_create_resource_identifier_with_invalid_fields_raises_error(
        self, invalid_field, field_value
    ):
        """Test that invalid required fields raise ValidationError."""
        # Arrange
        fields = {"resource_type": "user", "resource_id": "user-123"}
        fields[invalid_field] = field_value

        # Act & Assert
        with pytest.raises(ValidationError):
            ResourceIdentifier(**fields)


class TestResourceIdentifierHierarchy:
    """Test hierarchical resource relationships."""

    def test_create_hierarchical_resource_valid(self):
        """Test creating hierarchical resource with valid parent."""
        # Act
        resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="comment-123",
            parent_type="post",
            parent_id="post-456",
        )

        # Assert
        assert resource.is_hierarchical()
        assert resource.parent_type == "post"
        assert resource.parent_id == "post-456"

    def test_create_hierarchical_resource_missing_parent_type_raises_error(self):
        """Test that missing parent_type raises ValidationError."""
        # Act & Assert
        with pytest.raises(
            ValidationError, match="Both parent_type and parent_id must be provided"
        ):
            ResourceIdentifier(
                resource_type="comment",
                resource_id="comment-123",
                parent_id="post-456"
                # Missing parent_type
            )

    def test_create_hierarchical_resource_missing_parent_id_raises_error(self):
        """Test that missing parent_id raises ValidationError."""
        # Act & Assert
        with pytest.raises(
            ValidationError, match="Both parent_type and parent_id must be provided"
        ):
            ResourceIdentifier(
                resource_type="comment",
                resource_id="comment-123",
                parent_type="post"
                # Missing parent_id
            )

    def test_create_flat_resource_is_not_hierarchical(self):
        """Test that flat resource is not considered hierarchical."""
        # Act
        resource = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Assert
        assert not resource.is_hierarchical()


class TestResourceIdentifierImmutability:
    """Test resource identifier value object immutability."""

    def test_resource_identifier_is_frozen_after_creation(self):
        """Test that resource identifier is immutable after creation."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123", attributes={"role": "admin"}
        )

        # Act & Assert - Attempting to modify should raise an error
        with pytest.raises(AttributeError):
            resource.resource_type = "admin"

        with pytest.raises(AttributeError):
            resource.resource_id = "admin-456"

        with pytest.raises(AttributeError):
            resource.new_field = "value"

    def test_attributes_are_copied_not_referenced(self):
        """Test that attributes dict is copied, not referenced."""
        # Arrange
        original_attributes = {"role": "user", "active": True}
        resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123", attributes=original_attributes
        )

        # Act - Modify original attributes
        original_attributes["role"] = "admin"
        original_attributes["new_field"] = "new_value"

        # Assert - Resource attributes should remain unchanged
        assert resource.attributes["role"] == "user"
        assert resource.attributes["active"] is True
        assert "new_field" not in resource.attributes


class TestResourceIdentifierPaths:
    """Test resource path generation methods."""

    def test_get_full_path_flat_resource(self):
        """Test full path for flat resource."""
        # Arrange
        resource = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Act
        full_path = resource.get_full_path()

        # Assert
        assert full_path == "user/user-123"

    def test_get_full_path_hierarchical_resource(self):
        """Test full path for hierarchical resource."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="comment-789",
            parent_type="post",
            parent_id="post-456",
        )

        # Act
        full_path = resource.get_full_path()

        # Assert
        assert full_path == "post/post-456/comment/comment-789"

    def test_get_display_name_with_name(self):
        """Test display name when resource name is provided."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123", resource_name="John Doe"
        )

        # Act
        display_name = resource.get_display_name()

        # Assert
        assert display_name == "John Doe (user:user-123)"

    def test_get_display_name_without_name(self):
        """Test display name when resource name is not provided."""
        # Arrange
        resource = ResourceIdentifier(resource_type="document", resource_id="doc-456")

        # Act
        display_name = resource.get_display_name()

        # Assert
        assert display_name == "document:doc-456"


class TestResourceIdentifierUUIDDetection:
    """Test UUID-based identifier detection."""

    def test_is_uuid_based_with_valid_uuid(self):
        """Test UUID detection with valid UUID."""
        # Arrange
        uuid_id = uuid4()
        resource = ResourceIdentifier(resource_type="user", resource_id=str(uuid_id))

        # Act & Assert
        assert resource.is_uuid_based()

    def test_is_uuid_based_with_string_id(self):
        """Test UUID detection with string-based ID."""
        # Arrange
        resource = ResourceIdentifier(resource_type="document", resource_id="DOC-12345")

        # Act & Assert
        assert not resource.is_uuid_based()

    def test_is_uuid_based_with_numeric_string(self):
        """Test UUID detection with numeric string."""
        # Arrange
        resource = ResourceIdentifier(resource_type="order", resource_id="123456")

        # Act & Assert
        assert not resource.is_uuid_based()


class TestResourceIdentifierMatching:
    """Test resource matching methods."""

    def test_matches_type_correct_type(self):
        """Test type matching with correct type."""
        # Arrange
        resource = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Act & Assert
        assert resource.matches_type("user")
        assert resource.matches_type("USER")  # Case insensitive

    def test_matches_type_incorrect_type(self):
        """Test type matching with incorrect type."""
        # Arrange
        resource = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Act & Assert
        assert not resource.matches_type("document")
        assert not resource.matches_type("admin")


class TestResourceIdentifierImmutableMethods:
    """Test immutable modification methods."""

    def test_with_name(self):
        """Test creating new resource with name."""
        # Arrange
        original_resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123"
        )

        # Act
        named_resource = original_resource.with_name("Jane Smith")

        # Assert
        assert named_resource.resource_name == "Jane Smith"
        assert named_resource.resource_type == "user"
        assert named_resource.resource_id == "user-123"

        # Original should remain unchanged
        assert original_resource.resource_name is None

    def test_with_name_preserves_all_fields(self):
        """Test that with_name preserves all other fields."""
        # Arrange
        original_resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="comment-123",
            parent_type="post",
            parent_id="post-456",
            attributes={"timestamp": "2024-01-01"},
        )

        # Act
        named_resource = original_resource.with_name("Important Comment")

        # Assert
        assert named_resource.resource_name == "Important Comment"
        assert named_resource.parent_type == "post"
        assert named_resource.parent_id == "post-456"
        assert named_resource.attributes["timestamp"] == "2024-01-01"

    def test_with_attribute(self):
        """Test creating new resource with additional attribute."""
        # Arrange
        original_resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123", attributes={"role": "user"}
        )

        # Act
        enhanced_resource = original_resource.with_attribute(
            "department", "Engineering"
        )

        # Assert
        assert enhanced_resource.attributes["role"] == "user"
        assert enhanced_resource.attributes["department"] == "Engineering"

        # Original should remain unchanged
        assert "department" not in original_resource.attributes

    def test_with_attribute_overwrites_existing(self):
        """Test that with_attribute overwrites existing attributes."""
        # Arrange
        original_resource = ResourceIdentifier(
            resource_type="user",
            resource_id="user-123",
            attributes={"role": "user", "active": True},
        )

        # Act
        updated_resource = original_resource.with_attribute("role", "admin")

        # Assert
        assert updated_resource.attributes["role"] == "admin"
        assert updated_resource.attributes["active"] is True

        # Original should remain unchanged
        assert original_resource.attributes["role"] == "user"


class TestResourceIdentifierStringRepresentations:
    """Test string representation methods."""

    def test_str_representation_flat_resource(self):
        """Test string representation for flat resource."""
        # Arrange
        resource = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Act
        string_repr = str(resource)

        # Assert
        assert string_repr == "user/user-123"

    def test_str_representation_hierarchical_resource(self):
        """Test string representation for hierarchical resource."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="comment-789",
            parent_type="post",
            parent_id="post-456",
        )

        # Act
        string_repr = str(resource)

        # Assert
        assert string_repr == "post/post-456/comment/comment-789"

    def test_to_audit_string_minimal(self):
        """Test audit string representation with minimal data."""
        # Arrange
        resource = ResourceIdentifier(resource_type="document", resource_id="doc-123")

        # Act
        audit_string = resource.to_audit_string()

        # Assert
        assert "type=document" in audit_string
        assert "id=doc-123" in audit_string

    def test_to_audit_string_with_name(self):
        """Test audit string representation with name."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="user", resource_id="user-123", resource_name="John Doe"
        )

        # Act
        audit_string = resource.to_audit_string()

        # Assert
        assert "type=user" in audit_string
        assert "id=user-123" in audit_string
        assert "name=John Doe" in audit_string

    def test_to_audit_string_hierarchical(self):
        """Test audit string representation for hierarchical resource."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="comment-123",
            resource_name="Important Comment",
            parent_type="post",
            parent_id="post-456",
        )

        # Act
        audit_string = resource.to_audit_string()

        # Assert
        assert "type=comment" in audit_string
        assert "id=comment-123" in audit_string
        assert "name=Important Comment" in audit_string
        assert "parent=post:post-456" in audit_string

    def test_to_audit_string_with_attributes(self):
        """Test audit string representation with attributes."""
        # Arrange
        resource = ResourceIdentifier(
            resource_type="user",
            resource_id="user-123",
            attributes={"role": "admin", "department": "IT", "active": True},
        )

        # Act
        audit_string = resource.to_audit_string()

        # Assert
        assert "type=user" in audit_string
        assert "id=user-123" in audit_string
        assert "role=admin" in audit_string
        assert "department=IT" in audit_string
        assert "active=True" in audit_string


class TestResourceIdentifierFactoryMethods:
    """Test factory methods for common resource types."""

    def test_create_for_user_with_username(self):
        """Test user resource factory method with username."""
        # Arrange
        user_id = uuid4()
        username = "john.doe"

        # Act
        resource = ResourceIdentifier.create_for_user(user_id, username)

        # Assert
        assert resource.resource_type == "user"
        assert resource.resource_id == str(user_id)
        assert resource.resource_name == username
        assert not resource.is_hierarchical()

    def test_create_for_user_without_username(self):
        """Test user resource factory method without username."""
        # Arrange
        user_id = uuid4()

        # Act
        resource = ResourceIdentifier.create_for_user(user_id)

        # Assert
        assert resource.resource_type == "user"
        assert resource.resource_id == str(user_id)
        assert resource.resource_name is None
        assert resource.is_uuid_based()

    def test_create_for_aggregate_with_name(self):
        """Test aggregate resource factory method with name."""
        # Arrange
        aggregate_id = uuid4()

        # Act
        resource = ResourceIdentifier.create_for_aggregate(
            aggregate_type="order",
            aggregate_id=aggregate_id,
            name="Customer Order #12345",
        )

        # Assert
        assert resource.resource_type == "order"
        assert resource.resource_id == str(aggregate_id)
        assert resource.resource_name == "Customer Order #12345"
        assert resource.attributes["aggregate"] is True
        assert resource.is_uuid_based()

    def test_create_for_aggregate_without_name(self):
        """Test aggregate resource factory method without name."""
        # Arrange
        aggregate_id = uuid4()

        # Act
        resource = ResourceIdentifier.create_for_aggregate(
            aggregate_type="payment", aggregate_id=aggregate_id
        )

        # Assert
        assert resource.resource_type == "payment"
        assert resource.resource_id == str(aggregate_id)
        assert resource.resource_name is None
        assert resource.attributes["aggregate"] is True

    def test_create_hierarchical_factory_method(self):
        """Test hierarchical resource factory method."""
        # Arrange
        parent_resource = ResourceIdentifier(
            resource_type="blog", resource_id="blog-123", resource_name="Tech Blog"
        )

        # Act
        child_resource = ResourceIdentifier.create_hierarchical(
            resource_type="post",
            resource_id="post-456",
            parent_identifier=parent_resource,
            resource_name="Introduction to Python",
        )

        # Assert
        assert child_resource.resource_type == "post"
        assert child_resource.resource_id == "post-456"
        assert child_resource.resource_name == "Introduction to Python"
        assert child_resource.parent_type == "blog"
        assert child_resource.parent_id == "blog-123"
        assert child_resource.is_hierarchical()

        # Test full path
        expected_path = "blog/blog-123/post/post-456"
        assert child_resource.get_full_path() == expected_path


class TestResourceIdentifierEquality:
    """Test equality and comparison of resource identifiers."""

    def test_resource_identifiers_equal_when_same_values(self):
        """Test that resource identifiers with same values are equal."""
        # Arrange
        resource1 = ResourceIdentifier(
            resource_type="user",
            resource_id="user-123",
            resource_name="John Doe",
            attributes={"role": "admin"},
        )

        resource2 = ResourceIdentifier(
            resource_type="user",
            resource_id="user-123",
            resource_name="John Doe",
            attributes={"role": "admin"},
        )

        # Act & Assert
        assert resource1 == resource2
        assert hash(resource1) == hash(resource2)

    def test_resource_identifiers_not_equal_when_different_values(self):
        """Test that resource identifiers with different values are not equal."""
        # Arrange
        resource1 = ResourceIdentifier(resource_type="user", resource_id="user-123")

        resource2 = ResourceIdentifier(resource_type="user", resource_id="user-456")

        # Act & Assert
        assert resource1 != resource2
        assert hash(resource1) != hash(resource2)

    def test_resource_identifiers_equal_ignoring_case_differences(self):
        """Test that identifiers are equal after case normalization."""
        # Arrange
        resource1 = ResourceIdentifier(resource_type="USER", resource_id="user-123")

        resource2 = ResourceIdentifier(resource_type="user", resource_id="user-123")

        # Act & Assert
        assert resource1 == resource2


class TestResourceIdentifierEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_resource_with_unicode_characters(self):
        """Test creating resource with unicode characters."""
        # Act
        resource = ResourceIdentifier(
            resource_type="utilisateur",
            resource_id="utilisateur-123",
            resource_name="José María García 🇪🇸",
            attributes={"département": "développement"},
        )

        # Assert
        assert resource.resource_type == "utilisateur"
        assert resource.resource_name == "José María García 🇪🇸"
        assert resource.attributes["département"] == "développement"

    def test_create_resource_with_very_long_fields(self):
        """Test creating resource with very long field values."""
        # Arrange
        long_name = "A" * 1000
        long_id = "ID-" + "B" * 500

        # Act
        resource = ResourceIdentifier(
            resource_type="document", resource_id=long_id, resource_name=long_name
        )

        # Assert
        assert resource.resource_name == long_name
        assert resource.resource_id == long_id
        assert len(resource.resource_name) == 1000
        assert len(resource.resource_id) == 503

    def test_create_resource_with_special_characters(self):
        """Test creating resource with special characters."""
        # Act
        resource = ResourceIdentifier(
            resource_type="api_endpoint",
            resource_id="/api/v1/users/{id}",
            resource_name="User API Endpoint @#$%^&*()",
            attributes={"method": "GET", "auth": "required"},
        )

        # Assert
        assert resource.resource_id == "/api/v1/users/{id}"
        assert "@#$%^&*()" in resource.resource_name
        assert resource.attributes["method"] == "GET"

    def test_create_resource_with_complex_attributes(self):
        """Test creating resource with complex nested attributes."""
        # Arrange
        complex_attributes = {
            "metadata": {
                "created_by": "system",
                "tags": ["important", "urgent"],
                "permissions": {"read": True, "write": False},
            },
            "stats": {"views": 1250, "downloads": 89},
        }

        # Act
        resource = ResourceIdentifier(
            resource_type="document",
            resource_id="doc-complex-123",
            attributes=complex_attributes,
        )

        # Assert
        assert resource.attributes["metadata"]["created_by"] == "system"
        assert resource.attributes["metadata"]["tags"] == ["important", "urgent"]
        assert resource.attributes["metadata"]["permissions"]["read"] is True
        assert resource.attributes["stats"]["views"] == 1250
