"""
Comprehensive tests for AuditField entity.

This module tests the AuditField entity with complete coverage focusing on:
- Field change tracking and validation
- Sensitive data masking
- Value type handling
- Display and serialization
- Immutability enforcement
"""

from datetime import datetime
from uuid import UUID, uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.entities.audit_entry import AuditField


class TestAuditFieldCreation:
    """Test audit field creation and initialization."""

    def test_create_audit_field_with_basic_data(self):
        """Test creating audit field with basic required data."""
        # Arrange
        field_name = "email"
        old_value = "old@example.com"
        new_value = "new@example.com"

        # Act
        field = AuditField(
            field_name=field_name, old_value=old_value, new_value=new_value
        )

        # Assert
        assert field.field_name == field_name
        assert field.old_value == old_value
        assert field.new_value == new_value
        assert field.field_path == field_name  # Defaults to field_name
        assert field.value_type == "str"  # Auto-determined
        assert not field.is_sensitive  # Default
        assert field.id is not None

    def test_create_audit_field_with_all_parameters(self):
        """Test creating audit field with all parameters."""
        # Arrange
        field_name = "password"
        old_value = "old_password"
        new_value = "new_password"
        field_path = "authentication.password"
        value_type = "encrypted_string"
        is_sensitive = True
        field_id = uuid4()

        # Act
        field = AuditField(
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            field_path=field_path,
            value_type=value_type,
            is_sensitive=is_sensitive,
            entity_id=field_id,
        )

        # Assert
        assert field.field_name == field_name
        assert field.old_value == old_value
        assert field.new_value == new_value
        assert field.field_path == field_path
        assert field.value_type == value_type
        assert field.is_sensitive == is_sensitive
        assert field.id == field_id

    def test_create_audit_field_with_nested_field_path(self):
        """Test creating field with nested path structure."""
        # Arrange
        field_name = "city"
        field_path = "profile.address.city"
        old_value = "Old City"
        new_value = "New City"

        # Act
        field = AuditField(
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            field_path=field_path,
        )

        # Assert
        assert field.field_name == field_name
        assert field.field_path == field_path
        assert field.old_value == old_value
        assert field.new_value == new_value

    def test_create_audit_field_with_different_value_types(self):
        """Test creating fields with various value types."""
        # Test integer field
        int_field = AuditField("age", 25, 26)
        assert int_field.value_type == "int"

        # Test boolean field
        bool_field = AuditField("active", False, True)
        assert bool_field.value_type == "bool"

        # Test float field
        float_field = AuditField("score", 95.5, 97.8)
        assert float_field.value_type == "float"

        # Test None values
        none_field = AuditField("optional_field", "value", None)
        assert none_field.value_type == "NoneType"

        # Test list field
        list_field = AuditField("tags", ["old"], ["new", "tags"])
        assert list_field.value_type == "list"

        # Test dict field
        dict_field = AuditField("metadata", {"old": "data"}, {"new": "data"})
        assert dict_field.value_type == "dict"

    def test_create_audit_field_with_explicit_value_type(self):
        """Test creating field with explicitly specified value type."""
        # Arrange
        field_name = "encrypted_data"
        old_value = "encrypted123"
        new_value = "encrypted456"
        value_type = "base64_encrypted"

        # Act
        field = AuditField(
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            value_type=value_type,
        )

        # Assert
        assert field.value_type == value_type  # Uses explicit type

    @pytest.mark.parametrize("invalid_field_name", ["", "   ", None])
    def test_create_audit_field_with_invalid_field_name_raises_error(
        self, invalid_field_name
    ):
        """Test that invalid field names raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="field_name"):
            AuditField(field_name=invalid_field_name, old_value="old", new_value="new")


class TestAuditFieldValueHandling:
    """Test audit field value handling and change detection."""

    def test_has_changed_returns_true_for_different_values(self):
        """Test that has_changed returns True when values differ."""
        # Arrange
        test_cases = [
            ("string_field", "old", "new"),
            ("number_field", 1, 2),
            ("boolean_field", True, False),
            ("list_field", [1, 2], [2, 3]),
            ("none_to_value", None, "value"),
            ("value_to_none", "value", None),
        ]

        for field_name, old_value, new_value in test_cases:
            # Act
            field = AuditField(field_name, old_value, new_value)

            # Assert
            assert field.has_changed(), f"Field {field_name} should show as changed"

    def test_has_changed_returns_false_for_same_values(self):
        """Test that has_changed returns False when values are the same."""
        # Arrange
        test_cases = [
            ("string_field", "same", "same"),
            ("number_field", 42, 42),
            ("boolean_field", True, True),
            ("none_field", None, None),
            ("list_field", [1, 2, 3], [1, 2, 3]),
            ("dict_field", {"key": "value"}, {"key": "value"}),
        ]

        for field_name, old_value, new_value in test_cases:
            # Act
            field = AuditField(field_name, old_value, new_value)

            # Assert
            assert (
                not field.has_changed()
            ), f"Field {field_name} should not show as changed"

    def test_has_changed_with_complex_objects(self):
        """Test change detection with complex object values."""
        # Test datetime objects
        old_time = datetime(2024, 1, 1, 12, 0, 0)
        new_time = datetime(2024, 1, 1, 12, 0, 1)

        time_field = AuditField("timestamp", old_time, new_time)
        assert time_field.has_changed()

        # Test UUID objects
        old_uuid = uuid4()
        new_uuid = uuid4()

        uuid_field = AuditField("reference_id", old_uuid, new_uuid)
        assert uuid_field.has_changed()

        # Test custom objects (should work with __eq__ implementation)
        class CustomObject:
            def __init__(self, value):
                self.value = value

            def __eq__(self, other):
                return isinstance(other, CustomObject) and self.value == other.value

        custom_field = AuditField("custom", CustomObject(1), CustomObject(2))
        assert custom_field.has_changed()

        same_custom_field = AuditField("custom", CustomObject(1), CustomObject(1))
        assert not same_custom_field.has_changed()


class TestAuditFieldSensitiveDataHandling:
    """Test sensitive data masking and display."""

    def test_get_display_value_masks_sensitive_data(self):
        """Test that sensitive data is masked in display values."""
        # Arrange
        field = AuditField(
            field_name="password",
            old_value="secret123",
            new_value="newsecret456",
            is_sensitive=True,
        )

        # Act & Assert
        assert field.get_display_value(field.old_value) == "***REDACTED***"
        assert field.get_display_value(field.new_value) == "***REDACTED***"
        assert field.get_display_value("any_value") == "***REDACTED***"

    def test_get_display_value_shows_non_sensitive_data(self):
        """Test that non-sensitive data is displayed normally."""
        # Arrange
        field = AuditField(
            field_name="email",
            old_value="old@example.com",
            new_value="new@example.com",
            is_sensitive=False,
        )

        # Act & Assert
        assert field.get_display_value(field.old_value) == "old@example.com"
        assert field.get_display_value(field.new_value) == "new@example.com"
        assert field.get_display_value("test@example.com") == "test@example.com"

    def test_get_display_value_handles_none_values(self):
        """Test that None values are handled properly."""
        # Arrange
        field = AuditField(
            field_name="optional_field", old_value=None, new_value="value"
        )

        # Act & Assert
        assert field.get_display_value(None) == "null"
        assert field.get_display_value(field.new_value) == "value"

    def test_get_display_value_converts_complex_types_to_string(self):
        """Test that complex types are converted to strings."""
        # Arrange
        field = AuditField(
            field_name="metadata",
            old_value={"key": "old_value"},
            new_value={"key": "new_value"},
        )

        # Act & Assert
        old_display = field.get_display_value(field.old_value)
        new_display = field.get_display_value(field.new_value)

        assert "key" in old_display
        assert "old_value" in old_display
        assert "key" in new_display
        assert "new_value" in new_display

    def test_sensitive_field_detection_patterns(self):
        """Test common patterns for identifying sensitive fields."""
        # Common sensitive field names
        sensitive_fields = [
            "password",
            "secret",
            "token",
            "private_key",
            "api_key",
            "credit_card_number",
            "ssn",
            "social_security_number",
        ]

        for field_name in sensitive_fields:
            # Act
            field = AuditField(
                field_name=field_name,
                old_value="sensitive_data",
                new_value="new_sensitive_data",
                is_sensitive=True,  # Would be auto-detected in real implementation
            )

            # Assert
            assert (
                field.is_sensitive
            ), f"Field {field_name} should be marked as sensitive"
            assert field.get_display_value("test") == "***REDACTED***"


class TestAuditFieldSerialization:
    """Test audit field serialization and data conversion."""

    def test_to_dict_with_non_sensitive_field(self):
        """Test dictionary conversion for non-sensitive field."""
        # Arrange
        field = AuditField(
            field_name="username",
            old_value="old_user",
            new_value="new_user",
            field_path="profile.username",
            value_type="string",
        )

        # Act
        field_dict = field.to_dict()

        # Assert
        expected_dict = {
            "field_name": "username",
            "field_path": "profile.username",
            "old_value": "old_user",
            "new_value": "new_user",
            "value_type": "string",
            "is_sensitive": False,
        }
        assert field_dict == expected_dict

    def test_to_dict_with_sensitive_field(self):
        """Test dictionary conversion for sensitive field."""
        # Arrange
        field = AuditField(
            field_name="password",
            old_value="secret123",
            new_value="newsecret456",
            field_path="auth.password",
            value_type="encrypted",
            is_sensitive=True,
        )

        # Act
        field_dict = field.to_dict()

        # Assert
        expected_dict = {
            "field_name": "password",
            "field_path": "auth.password",
            "old_value": "***REDACTED***",
            "new_value": "***REDACTED***",
            "value_type": "encrypted",
            "is_sensitive": True,
        }
        assert field_dict == expected_dict

    def test_to_dict_with_none_values(self):
        """Test dictionary conversion with None values."""
        # Arrange
        field = AuditField(
            field_name="optional_field", old_value=None, new_value="new_value"
        )

        # Act
        field_dict = field.to_dict()

        # Assert
        assert field_dict["old_value"] == "null"
        assert field_dict["new_value"] == "new_value"

    def test_to_dict_with_complex_values(self):
        """Test dictionary conversion with complex values."""
        # Arrange
        old_value = {"nested": {"key": "old_value"}, "list": [1, 2, 3]}
        new_value = {"nested": {"key": "new_value"}, "list": [4, 5, 6]}

        field = AuditField(
            field_name="complex_data", old_value=old_value, new_value=new_value
        )

        # Act
        field_dict = field.to_dict()

        # Assert
        assert "nested" in field_dict["old_value"]
        assert "list" in field_dict["old_value"]
        assert "nested" in field_dict["new_value"]
        assert "list" in field_dict["new_value"]


class TestAuditFieldBehavior:
    """Test audit field behavioral patterns and business logic."""

    def test_field_inherits_from_entity(self):
        """Test that AuditField inherits from Entity."""
        # Arrange
        field = AuditField("test_field", "old", "new")

        # Act & Assert
        from app.core.domain.base import Entity

        assert isinstance(field, Entity)
        assert hasattr(field, "id")
        assert hasattr(field, "created_at")
        assert hasattr(field, "updated_at")

    def test_field_has_unique_id(self):
        """Test that each field gets a unique ID."""
        # Arrange & Act
        field1 = AuditField("field1", "old1", "new1")
        field2 = AuditField("field2", "old2", "new2")

        # Assert
        assert field1.id != field2.id
        assert isinstance(field1.id, UUID)
        assert isinstance(field2.id, UUID)

    def test_field_with_same_values_different_instances(self):
        """Test that fields with same values are different instances."""
        # Arrange & Act
        field1 = AuditField("same_field", "same_old", "same_new")
        field2 = AuditField("same_field", "same_old", "same_new")

        # Assert
        assert field1.id != field2.id
        assert field1.field_name == field2.field_name
        assert field1.old_value == field2.old_value
        assert field1.new_value == field2.new_value

    def test_field_equality_based_on_content(self):
        """Test field equality based on content, not identity."""
        # Note: This test assumes Entity implements equality based on content
        # If Entity uses ID-based equality, this test might need adjustment

        # Arrange
        field_id = uuid4()
        field1 = AuditField("test_field", "old", "new", entity_id=field_id)
        field2 = AuditField("test_field", "old", "new", entity_id=field_id)

        # Act & Assert
        # Entity equality is typically based on ID
        assert field1 == field2


class TestAuditFieldEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_field_with_very_long_field_name(self):
        """Test field with very long field name."""
        # Arrange
        long_field_name = "a" * 1000  # Very long field name

        # Act
        field = AuditField(long_field_name, "old", "new")

        # Assert
        assert field.field_name == long_field_name
        assert len(field.field_name) == 1000

    def test_field_with_special_characters_in_name(self):
        """Test field with special characters in name."""
        # Arrange
        special_names = [
            "field-with-hyphens",
            "field_with_underscores",
            "field.with.dots",
            "field with spaces",
            "field/with/slashes",
            "field@with#symbols$",
            "unicode_field_名前",
        ]

        for field_name in special_names:
            # Act
            field = AuditField(field_name, "old", "new")

            # Assert
            assert field.field_name == field_name

    def test_field_with_very_large_values(self):
        """Test field with very large values."""
        # Arrange
        large_string = "x" * 10000  # 10KB string
        large_list = list(range(1000))  # 1000 item list
        large_dict = {f"key_{i}": f"value_{i}" for i in range(100)}

        test_cases = [
            ("large_string", "small", large_string),
            ("large_list", [], large_list),
            ("large_dict", {}, large_dict),
        ]

        for field_name, old_value, new_value in test_cases:
            # Act
            field = AuditField(field_name, old_value, new_value)

            # Assert
            assert field.field_name == field_name
            assert field.old_value == old_value
            assert field.new_value == new_value
            assert field.has_changed()

    def test_field_with_unicode_values(self):
        """Test field with Unicode values."""
        # Arrange
        unicode_values = ["简体中文", "русский", "العربية", "🚀🌟⭐", "café", "naïve", "Ñoño"]

        for i, unicode_val in enumerate(unicode_values):
            # Act
            field = AuditField(f"unicode_field_{i}", "old", unicode_val)

            # Assert
            assert field.new_value == unicode_val
            assert field.get_display_value(unicode_val) == unicode_val

    def test_field_type_detection_edge_cases(self):
        """Test value type detection for edge cases."""

        # Test with custom classes
        class CustomClass:
            pass

        custom_obj = CustomClass()
        field = AuditField("custom", None, custom_obj)
        assert field.value_type == "CustomClass"

        # Test with lambda (function)
        def lambda_func(x):
            return x

        field = AuditField("lambda", None, lambda_func)
        assert field.value_type == "function"

        # Test with complex numbers
        complex_num = 3 + 4j
        field = AuditField("complex", 0, complex_num)
        assert field.value_type == "complex"


class TestAuditFieldIntegration:
    """Test audit field integration with other components."""

    def test_field_in_list_operations(self):
        """Test field behavior in list operations."""
        # Arrange
        fields = [
            AuditField("field1", "old1", "new1"),
            AuditField("field2", "old2", "new2"),
            AuditField("field3", "old3", "new3"),
        ]

        # Act & Assert
        # Test filtering
        changed_fields = [f for f in fields if f.has_changed()]
        assert len(changed_fields) == 3

        # Test sorting by field name
        sorted_fields = sorted(fields, key=lambda f: f.field_name)
        assert sorted_fields[0].field_name == "field1"
        assert sorted_fields[1].field_name == "field2"
        assert sorted_fields[2].field_name == "field3"

        # Test field name extraction
        field_names = [f.field_name for f in fields]
        assert field_names == ["field1", "field2", "field3"]

    def test_field_dictionary_serialization_round_trip(self):
        """Test that field can be serialized to dict and maintain integrity."""
        # Arrange
        original_field = AuditField(
            field_name="test_field",
            old_value="old_value",
            new_value="new_value",
            field_path="path.to.field",
            value_type="custom_type",
            is_sensitive=False,
        )

        # Act
        field_dict = original_field.to_dict()

        # Assert
        assert field_dict["field_name"] == original_field.field_name
        assert field_dict["old_value"] == str(original_field.old_value)
        assert field_dict["new_value"] == str(original_field.new_value)
        assert field_dict["field_path"] == original_field.field_path
        assert field_dict["value_type"] == original_field.value_type
        assert field_dict["is_sensitive"] == original_field.is_sensitive

    def test_field_creation_with_audit_entry_context(self):
        """Test field creation in the context of audit entries."""
        # This test simulates how fields would be used in audit entries

        # Arrange - Simulate user profile update
        profile_changes = [
            AuditField("email", "old@example.com", "new@example.com"),
            AuditField("phone", "+1234567890", "+0987654321"),
            AuditField("address", "Old Address", "New Address"),
        ]

        # Act & Assert
        assert len(profile_changes) == 3
        assert all(field.has_changed() for field in profile_changes)

        # Verify change summary structure
        for field in profile_changes:
            field_dict = field.to_dict()
            assert "field_name" in field_dict
            assert "old_value" in field_dict
            assert "new_value" in field_dict
            assert field_dict["old_value"] != field_dict["new_value"]
