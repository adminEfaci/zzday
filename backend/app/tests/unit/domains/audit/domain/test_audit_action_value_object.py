"""
Comprehensive tests for AuditAction value object.

This module tests the AuditAction value object with complete coverage focusing on:
- Value object immutability
- Action type validation and categorization
- Factory methods for common actions
- Severity hint determination
- String representations
"""

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.value_objects.audit_action import AuditAction


class TestAuditActionCreation:
    """Test audit action creation and initialization."""

    def test_create_audit_action_with_all_fields(self):
        """Test creating audit action with all fields."""
        # Act
        action = AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description="User updated their profile information",
        )

        # Assert
        assert action.action_type == "update"
        assert action.resource_type == "user"
        assert action.operation == "update_profile"
        assert action.description == "User updated their profile information"

    def test_create_audit_action_without_description(self):
        """Test creating audit action without explicit description."""
        # Act
        action = AuditAction(
            action_type="create", resource_type="order", operation="place_order"
        )

        # Assert
        assert action.description == "create order via place_order"  # Auto-generated

    def test_create_audit_action_normalizes_case(self):
        """Test that action creation normalizes case."""
        # Act
        action = AuditAction(
            action_type="CREATE", resource_type="USER", operation="REGISTER"
        )

        # Assert
        assert action.action_type == "create"
        assert action.resource_type == "user"
        assert action.operation == "register"

    def test_create_audit_action_trims_whitespace(self):
        """Test that action creation trims whitespace."""
        # Act
        action = AuditAction(
            action_type="  update  ",
            resource_type="  user  ",
            operation="  update_profile  ",
            description="  User updated profile  ",
        )

        # Assert
        assert action.action_type == "update"
        assert action.resource_type == "user"
        assert action.operation == "update_profile"
        assert action.description == "User updated profile"

    @pytest.mark.parametrize(
        ("invalid_field", "field_value"),
        [
            ("action_type", ""),
            ("action_type", "   "),
            ("action_type", None),
            ("resource_type", ""),
            ("resource_type", "   "),
            ("resource_type", None),
            ("operation", ""),
            ("operation", "   "),
            ("operation", None),
        ],
    )
    def test_create_audit_action_with_invalid_fields_raises_error(
        self, invalid_field, field_value
    ):
        """Test that invalid required fields raise ValidationError."""
        # Arrange
        fields = {
            "action_type": "update",
            "resource_type": "user",
            "operation": "update_profile",
        }
        fields[invalid_field] = field_value

        # Act & Assert
        with pytest.raises(ValidationError):
            AuditAction(**fields)


class TestAuditActionImmutability:
    """Test audit action value object immutability."""

    def test_audit_action_is_frozen_after_creation(self):
        """Test that audit action is immutable after creation."""
        # Arrange
        action = AuditAction(
            action_type="read", resource_type="document", operation="view"
        )

        # Act & Assert - Attempting to modify should raise an error
        with pytest.raises(AttributeError):
            action.action_type = "write"

        with pytest.raises(AttributeError):
            action.new_field = "value"


class TestAuditActionClassification:
    """Test action type classification methods."""

    @pytest.mark.parametrize(
        ("action_type", "expected_read"),
        [
            ("read", True),
            ("view", True),
            ("list", True),
            ("search", True),
            ("export", True),
            ("create", False),
            ("update", False),
            ("delete", False),
        ],
    )
    def test_is_read_action(self, action_type, expected_read):
        """Test read action classification."""
        # Arrange
        action = AuditAction(
            action_type=action_type, resource_type="user", operation="test_operation"
        )

        # Act & Assert
        assert action.is_read_action() == expected_read

    @pytest.mark.parametrize(
        ("action_type", "expected_write"),
        [
            ("create", True),
            ("update", True),
            ("delete", True),
            ("import", True),
            ("restore", True),
            ("read", False),
            ("view", False),
            ("list", False),
            ("search", False),
        ],
    )
    def test_is_write_action(self, action_type, expected_write):
        """Test write action classification."""
        # Arrange
        action = AuditAction(
            action_type=action_type, resource_type="user", operation="test_operation"
        )

        # Act & Assert
        assert action.is_write_action() == expected_write

    @pytest.mark.parametrize(
        ("operation", "expected_auth"),
        [
            ("login", True),
            ("logout", True),
            ("password_change", True),
            ("password_reset", True),
            ("mfa_enable", True),
            ("mfa_disable", True),
            ("create_user", False),
            ("update_profile", False),
            ("view_document", False),
        ],
    )
    def test_is_auth_action(self, operation, expected_auth):
        """Test authentication action classification."""
        # Arrange
        action = AuditAction(
            action_type="execute", resource_type="session", operation=operation
        )

        # Act & Assert
        assert action.is_auth_action() == expected_auth


class TestAuditActionSeverityHints:
    """Test severity hint determination."""

    @pytest.mark.parametrize(
        ("action_type", "operation", "expected_severity"),
        [
            ("delete", "delete_user", "high"),
            ("login", "authenticate", "medium"),
            ("logout", "terminate_session", "medium"),
            ("password_change", "update_password", "medium"),
            ("create", "create_user", "medium"),
            ("update", "update_profile", "medium"),
            ("read", "view_document", "low"),
            ("view", "list_users", "low"),
            ("search", "find_records", "low"),
        ],
    )
    def test_get_severity_hint(self, action_type, operation, expected_severity):
        """Test severity hint determination based on action type and operation."""
        # Arrange
        action = AuditAction(
            action_type=action_type, resource_type="user", operation=operation
        )

        # Act & Assert
        assert action.get_severity_hint() == expected_severity


class TestAuditActionStringRepresentation:
    """Test string representation methods."""

    def test_str_representation(self):
        """Test string representation of audit action."""
        # Arrange
        action = AuditAction(
            action_type="update", resource_type="user", operation="update_profile"
        )

        # Act
        string_repr = str(action)

        # Assert
        assert string_repr == "update:user:update_profile"

    def test_action_with_complex_operation_string(self):
        """Test string representation with complex operation."""
        # Arrange
        action = AuditAction(
            action_type="execute",
            resource_type="financial_report",
            operation="generate_quarterly_compliance_report",
        )

        # Act
        string_repr = str(action)

        # Assert
        assert (
            string_repr
            == "execute:financial_report:generate_quarterly_compliance_report"
        )


class TestAuditActionFactoryMethods:
    """Test factory methods for common audit actions."""

    def test_create_login_action_default(self):
        """Test login action factory method with defaults."""
        # Act
        action = AuditAction.create_login_action()

        # Assert
        assert action.action_type == "login"
        assert action.resource_type == "session"
        assert action.operation == "login"
        assert action.description == "User logged in"
        assert action.is_auth_action()

    def test_create_login_action_custom_resource_type(self):
        """Test login action factory method with custom resource type."""
        # Act
        action = AuditAction.create_login_action(resource_type="authentication")

        # Assert
        assert action.action_type == "login"
        assert action.resource_type == "authentication"
        assert action.operation == "login"
        assert action.description == "User logged in"

    def test_create_logout_action_default(self):
        """Test logout action factory method with defaults."""
        # Act
        action = AuditAction.create_logout_action()

        # Assert
        assert action.action_type == "logout"
        assert action.resource_type == "session"
        assert action.operation == "logout"
        assert action.description == "User logged out"
        assert action.is_auth_action()

    def test_create_logout_action_custom_resource_type(self):
        """Test logout action factory method with custom resource type."""
        # Act
        action = AuditAction.create_logout_action(resource_type="user_session")

        # Assert
        assert action.action_type == "logout"
        assert action.resource_type == "user_session"
        assert action.operation == "logout"
        assert action.description == "User logged out"

    @pytest.mark.parametrize(
        ("action_type", "resource_type", "expected_operation", "expected_description"),
        [
            ("create", "user", "create_user", "Create user"),
            ("read", "document", "read_document", "Read document"),
            ("update", "profile", "update_profile", "Update profile"),
            ("delete", "order", "delete_order", "Delete order"),
        ],
    )
    def test_create_crud_action_without_name(
        self, action_type, resource_type, expected_operation, expected_description
    ):
        """Test CRUD action factory method without resource name."""
        # Act
        action = AuditAction.create_crud_action(
            action_type=action_type, resource_type=resource_type
        )

        # Assert
        assert action.action_type == action_type
        assert action.resource_type == resource_type
        assert action.operation == expected_operation
        assert action.description == expected_description

    def test_create_crud_action_with_name(self):
        """Test CRUD action factory method with resource name."""
        # Act
        action = AuditAction.create_crud_action(
            action_type="update", resource_type="user", resource_name="User Profile"
        )

        # Assert
        assert action.action_type == "update"
        assert action.resource_type == "user"
        assert action.operation == "update_user"
        assert action.description == "Update User Profile"


class TestAuditActionEquality:
    """Test equality and comparison of audit actions."""

    def test_audit_actions_equal_when_same_values(self):
        """Test that audit actions with same values are equal."""
        # Arrange
        action1 = AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description="Profile updated",
        )

        action2 = AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description="Profile updated",
        )

        # Act & Assert
        assert action1 == action2
        assert hash(action1) == hash(action2)

    def test_audit_actions_not_equal_when_different_values(self):
        """Test that audit actions with different values are not equal."""
        # Arrange
        action1 = AuditAction(
            action_type="update", resource_type="user", operation="update_profile"
        )

        action2 = AuditAction(
            action_type="create", resource_type="user", operation="create_user"
        )

        # Act & Assert
        assert action1 != action2
        assert hash(action1) != hash(action2)

    def test_audit_actions_equal_ignoring_case_differences(self):
        """Test that actions are equal after case normalization."""
        # Arrange
        action1 = AuditAction(
            action_type="UPDATE", resource_type="USER", operation="UPDATE_PROFILE"
        )

        action2 = AuditAction(
            action_type="update", resource_type="user", operation="update_profile"
        )

        # Act & Assert
        assert action1 == action2


class TestAuditActionValidation:
    """Test validation of audit action components."""

    def test_action_type_constants(self):
        """Test that action type constants are properly defined."""
        # Assert
        assert AuditAction.ACTION_CREATE == "create"
        assert AuditAction.ACTION_READ == "read"
        assert AuditAction.ACTION_UPDATE == "update"
        assert AuditAction.ACTION_DELETE == "delete"
        assert AuditAction.ACTION_EXECUTE == "execute"
        assert AuditAction.ACTION_LOGIN == "login"
        assert AuditAction.ACTION_LOGOUT == "logout"
        assert AuditAction.ACTION_EXPORT == "export"
        assert AuditAction.ACTION_IMPORT == "import"

    def test_create_action_with_constants(self):
        """Test creating actions using predefined constants."""
        # Act
        action = AuditAction(
            action_type=AuditAction.ACTION_DELETE,
            resource_type="user",
            operation="deactivate_account",
        )

        # Assert
        assert action.action_type == "delete"
        assert action.is_write_action()
        assert action.get_severity_hint() == "high"


class TestAuditActionEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_action_with_unicode_characters(self):
        """Test creating action with unicode characters."""
        # Act
        action = AuditAction(
            action_type="créer",
            resource_type="utilisateur",
            operation="créer_profil",
            description="Créer un nouveau profil utilisateur",
        )

        # Assert
        assert action.action_type == "créer"
        assert action.resource_type == "utilisateur"
        assert action.operation == "créer_profil"
        assert action.description == "Créer un nouveau profil utilisateur"

    def test_create_action_with_very_long_fields(self):
        """Test creating action with very long field values."""
        # Arrange
        long_description = "A" * 1000  # Very long description

        # Act
        action = AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description=long_description,
        )

        # Assert
        assert action.description == long_description
        assert len(action.description) == 1000

    def test_create_action_with_special_characters(self):
        """Test creating action with special characters."""
        # Act
        action = AuditAction(
            action_type="update",
            resource_type="api_endpoint",
            operation="modify_webhook_url",
            description="Updated webhook URL with special chars: @#$%^&*()",
        )

        # Assert
        assert action.resource_type == "api_endpoint"
        assert action.operation == "modify_webhook_url"
        assert "@#$%^&*()" in action.description

    def test_multiple_action_creation_performance(self):
        """Test creating multiple actions for performance validation."""
        import time

        # Arrange
        start_time = time.perf_counter()
        actions = []

        # Act - Create 1000 actions
        for i in range(1000):
            action = AuditAction(
                action_type="read",
                resource_type="document",
                operation=f"view_document_{i}",
                description=f"View document {i}",
            )
            actions.append(action)

        end_time = time.perf_counter()
        duration = end_time - start_time

        # Assert
        assert len(actions) == 1000
        assert duration < 1.0  # Should create 1000 actions in under 1 second

        # Verify all actions are properly created
        for i, action in enumerate(actions):
            assert action.action_type == "read"
            assert action.resource_type == "document"
            assert action.operation == f"view_document_{i}"
            assert action.description == f"View document {i}"
