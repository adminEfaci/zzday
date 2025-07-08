"""
Comprehensive tests for AuditEntry entity.

This module tests the AuditEntry entity with complete coverage focusing on:
- Immutability enforcement after creation
- Field-level change tracking
- Auto-determination of severity and category
- Business rule validation
- System vs user action differentiation
"""

from uuid import uuid4

import pytest

from app.core.errors import DomainError, ValidationError
from app.modules.audit.domain.entities.audit_entry import AuditEntry, AuditField
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)


class TestAuditEntryCreation:
    """Test audit entry creation and initialization."""

    @pytest.fixture
    def sample_action(self):
        """Create sample audit action."""
        return AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description="User updated their profile",
        )

    @pytest.fixture
    def sample_resource(self):
        """Create sample resource identifier."""
        return ResourceIdentifier(
            resource_type="user", resource_id=str(uuid4()), resource_name="John Doe"
        )

    @pytest.fixture
    def sample_context(self):
        """Create sample audit context."""
        return AuditContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 Test Browser",
            request_id=str(uuid4()),
            environment="test",
        )

    def test_create_audit_entry_with_user_action(
        self, sample_action, sample_resource, sample_context
    ):
        """Test creating audit entry with user-initiated action."""
        # Arrange
        user_id = uuid4()
        metadata = AuditMetadata(tags=["profile", "update"])

        # Act
        entry = AuditEntry(
            user_id=user_id,
            action=sample_action,
            resource=sample_resource,
            context=sample_context,
            metadata=metadata,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.DATA_ACCESS,
            outcome="success",
            duration_ms=150,
        )

        # Assert
        assert entry.user_id == user_id
        assert entry.action == sample_action
        assert entry.resource == sample_resource
        assert entry.context == sample_context
        assert entry.metadata == metadata
        assert entry.severity == AuditSeverity.MEDIUM
        assert entry.category == AuditCategory.DATA_ACCESS
        assert entry.outcome == "success"
        assert entry.duration_ms == 150
        assert entry.correlation_id is not None
        assert not entry.is_system_action()
        assert entry.is_successful()
        assert not entry.is_failed()
        assert not entry.is_partial()

    def test_create_audit_entry_with_system_action(
        self, sample_action, sample_resource, sample_context
    ):
        """Test creating audit entry with system-initiated action."""
        # Act
        entry = AuditEntry(
            user_id=None,  # System action
            action=sample_action,
            resource=sample_resource,
            context=sample_context,
        )

        # Assert
        assert entry.user_id is None
        assert entry.is_system_action()
        assert entry.outcome == "success"  # Default outcome

    def test_create_audit_entry_with_minimal_data(
        self, sample_action, sample_resource, sample_context
    ):
        """Test creating audit entry with minimal required data."""
        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=sample_action,
            resource=sample_resource,
            context=sample_context,
        )

        # Assert
        assert entry.metadata is not None  # Should create default metadata
        assert entry.severity is not None  # Should auto-determine
        assert entry.category is not None  # Should auto-determine
        assert entry.outcome == "success"  # Default outcome
        assert entry.error_details is None
        assert entry.duration_ms is None
        assert len(entry.changes) == 0
        assert entry.correlation_id is not None
        assert entry.session_id is None

    def test_create_audit_entry_with_failure_outcome_requires_error_details(
        self, sample_action, sample_resource, sample_context
    ):
        """Test that failure outcome requires error details."""
        # Act & Assert
        with pytest.raises(
            DomainError, match="Error details are required for failed actions"
        ):
            AuditEntry(
                user_id=uuid4(),
                action=sample_action,
                resource=sample_resource,
                context=sample_context,
                outcome="failure"
                # Missing error_details
            )

    def test_create_audit_entry_with_failure_and_error_details(
        self, sample_action, sample_resource, sample_context
    ):
        """Test creating audit entry with failure outcome and error details."""
        # Arrange
        error_details = {
            "error_code": "VALIDATION_ERROR",
            "error_message": "Invalid email format",
            "field": "email",
        }

        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=sample_action,
            resource=sample_resource,
            context=sample_context,
            outcome="failure",
            error_details=error_details,
        )

        # Assert
        assert entry.outcome == "failure"
        assert entry.error_details == error_details
        assert entry.is_failed()
        assert not entry.is_successful()

    @pytest.mark.parametrize(
        "invalid_outcome", ["invalid", "complete", "FAILURE", ""]  # Wrong case
    )
    def test_create_audit_entry_with_invalid_outcome_raises_error(
        self, sample_action, sample_resource, sample_context, invalid_outcome
    ):
        """Test that invalid outcomes raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid outcome"):
            AuditEntry(
                user_id=uuid4(),
                action=sample_action,
                resource=sample_resource,
                context=sample_context,
                outcome=invalid_outcome,
            )

    @pytest.mark.parametrize(
        ("outcome", "expected_success", "expected_failure", "expected_partial"),
        [
            ("success", True, False, False),
            ("failure", False, True, False),
            ("partial", False, False, True),
            ("SUCCESS", True, False, False),  # Should normalize case
            ("PARTIAL", False, False, True),
        ],
    )
    def test_outcome_validation_and_normalization(
        self,
        sample_action,
        sample_resource,
        sample_context,
        outcome,
        expected_success,
        expected_failure,
        expected_partial,
    ):
        """Test outcome validation and normalization."""
        # Arrange
        error_details = {"error": "test"} if outcome.lower() == "failure" else None

        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=sample_action,
            resource=sample_resource,
            context=sample_context,
            outcome=outcome,
            error_details=error_details,
        )

        # Assert
        assert entry.outcome == outcome.lower()
        assert entry.is_successful() == expected_success
        assert entry.is_failed() == expected_failure
        assert entry.is_partial() == expected_partial


class TestAuditEntryFieldChanges:
    """Test field-level change tracking in audit entries."""

    @pytest.fixture
    def update_action(self):
        """Create update action for testing changes."""
        return AuditAction(
            action_type="update",
            resource_type="user",
            operation="update_profile",
            description="User profile updated",
        )

    @pytest.fixture
    def read_action(self):
        """Create read action that shouldn't allow changes."""
        return AuditAction(
            action_type="read",
            resource_type="user",
            operation="view_profile",
            description="User profile viewed",
        )

    @pytest.fixture
    def sample_resource(self):
        """Create sample resource."""
        return ResourceIdentifier("user", str(uuid4()))

    @pytest.fixture
    def sample_context(self):
        """Create sample context."""
        return AuditContext()

    def test_create_audit_entry_with_field_changes(
        self, update_action, sample_resource, sample_context
    ):
        """Test creating audit entry with field-level changes."""
        # Arrange
        changes = [
            AuditField(
                field_name="email",
                old_value="old@example.com",
                new_value="new@example.com",
                field_path="profile.email",
            ),
            AuditField(
                field_name="phone",
                old_value="+1234567890",
                new_value="+0987654321",
                field_path="profile.phone",
            ),
        ]

        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=update_action,
            resource=sample_resource,
            context=sample_context,
            changes=changes,
        )

        # Assert
        assert entry.has_changes()
        assert len(entry.changes) == 2
        assert entry.get_changed_fields() == ["email", "phone"]

        change_summary = entry.get_change_summary()
        assert change_summary["email"]["old_value"] == "old@example.com"
        assert change_summary["email"]["new_value"] == "new@example.com"
        assert change_summary["phone"]["old_value"] == "+1234567890"
        assert change_summary["phone"]["new_value"] == "+0987654321"

    def test_create_audit_entry_changes_only_allowed_for_write_actions(
        self, read_action, sample_resource, sample_context
    ):
        """Test that changes can only be specified for write actions."""
        # Arrange
        changes = [
            AuditField(
                field_name="email",
                old_value="old@example.com",
                new_value="new@example.com",
            )
        ]

        # Act & Assert
        with pytest.raises(
            DomainError, match="Changes can only be specified for write actions"
        ):
            AuditEntry(
                user_id=uuid4(),
                action=read_action,
                resource=sample_resource,
                context=sample_context,
                changes=changes,
            )

    def test_audit_entry_without_changes(
        self, update_action, sample_resource, sample_context
    ):
        """Test audit entry without field changes."""
        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=update_action,
            resource=sample_resource,
            context=sample_context,
        )

        # Assert
        assert not entry.has_changes()
        assert len(entry.changes) == 0
        assert entry.get_changed_fields() == []
        assert entry.get_change_summary() == {}


class TestAuditEntryAutoSeverityDetermination:
    """Test automatic severity determination based on action and outcome."""

    @pytest.fixture
    def sample_resource(self):
        """Create sample resource."""
        return ResourceIdentifier("user", str(uuid4()))

    @pytest.fixture
    def sample_context(self):
        """Create sample context."""
        return AuditContext()

    @pytest.mark.parametrize(
        ("action_type", "operation", "outcome", "expected_severity"),
        [
            ("delete", "delete_user", "failure", AuditSeverity.HIGH),
            ("login", "authenticate", "failure", AuditSeverity.HIGH),
            ("update", "update_profile", "failure", AuditSeverity.MEDIUM),
            ("create", "create_user", "success", AuditSeverity.MEDIUM),
            ("read", "view_profile", "success", AuditSeverity.LOW),
        ],
    )
    def test_auto_determine_severity_based_on_action_and_outcome(
        self,
        sample_resource,
        sample_context,
        action_type,
        operation,
        outcome,
        expected_severity,
    ):
        """Test automatic severity determination."""
        # Arrange
        action = AuditAction(
            action_type=action_type,
            resource_type="user",
            operation=operation,
            description=f"Test {action_type} action",
        )

        error_details = {"error": "test"} if outcome == "failure" else None

        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=action,
            resource=sample_resource,
            context=sample_context,
            outcome=outcome,
            error_details=error_details
            # Don't specify severity - let it auto-determine
        )

        # Assert
        assert entry.severity == expected_severity


class TestAuditEntryAutoCategoryDetermination:
    """Test automatic category determination based on action."""

    @pytest.fixture
    def sample_resource(self):
        """Create sample resource."""
        return ResourceIdentifier("user", str(uuid4()))

    @pytest.fixture
    def sample_context(self):
        """Create sample context."""
        return AuditContext()

    @pytest.mark.parametrize(
        ("action_type", "operation", "expected_category"),
        [
            ("login", "login", AuditCategory.AUTHENTICATION),
            ("logout", "logout", AuditCategory.AUTHENTICATION),
            ("update", "change_password", AuditCategory.AUTHORIZATION),
            ("update", "assign_role", AuditCategory.AUTHORIZATION),
            ("read", "view_document", AuditCategory.DATA_ACCESS),
            ("create", "create_user", AuditCategory.DATA_ACCESS),
        ],
    )
    def test_auto_determine_category_based_on_action(
        self, sample_resource, sample_context, action_type, operation, expected_category
    ):
        """Test automatic category determination."""
        # Arrange
        action = AuditAction(
            action_type=action_type,
            resource_type="user",
            operation=operation,
            description=f"Test {action_type} action",
        )

        # Act
        entry = AuditEntry(
            user_id=uuid4(),
            action=action,
            resource=sample_resource,
            context=sample_context
            # Don't specify category - let it auto-determine
        )

        # Assert
        assert entry.category == expected_category

    @pytest.mark.parametrize(
        ("resource_type", "expected_category"),
        [
            ("configuration", AuditCategory.CONFIGURATION),
            ("setting", AuditCategory.CONFIGURATION),
            ("preference", AuditCategory.CONFIGURATION),
            ("integration", AuditCategory.INTEGRATION),
            ("webhook", AuditCategory.INTEGRATION),
            ("api", AuditCategory.INTEGRATION),
        ],
    )
    def test_auto_determine_category_based_on_resource_type(
        self, sample_context, resource_type, expected_category
    ):
        """Test category determination based on resource type."""
        # Arrange
        action = AuditAction(
            action_type="update",
            resource_type=resource_type,
            operation="modify",
            description="Test action",
        )

        resource = ResourceIdentifier(resource_type, str(uuid4()))

        # Act
        entry = AuditEntry(
            user_id=uuid4(), action=action, resource=resource, context=sample_context
        )

        # Assert
        assert entry.category == expected_category


class TestAuditEntryImmutability:
    """Test immutability enforcement in audit entries."""

    def test_audit_entry_is_immutable_after_creation(self):
        """Test that audit entries become immutable after creation."""
        # Arrange
        action = AuditAction("create", "user", "register", "User registration")
        resource = ResourceIdentifier("user", str(uuid4()))
        context = AuditContext()

        # Act
        entry = AuditEntry(
            user_id=uuid4(), action=action, resource=resource, context=context
        )

        # Assert - Entry should be immutable
        with pytest.raises(DomainError, match="immutable"):
            entry.mark_modified()

        # Verify the entry has immutable flag set
        assert hasattr(entry, "_immutable")
        assert entry._immutable is True

    def test_audit_entry_validation_prevents_modification(self):
        """Test that validation prevents modification of immutable entries."""
        # Arrange
        action = AuditAction("update", "document", "edit", "Document edited")
        resource = ResourceIdentifier("document", str(uuid4()))
        context = AuditContext()

        # Act
        entry = AuditEntry(
            user_id=uuid4(), action=action, resource=resource, context=context
        )

        # Assert - _validate_entity should prevent modification
        with pytest.raises(DomainError, match="immutable"):
            entry._validate_entity()


class TestAuditEntryQueryMethods:
    """Test query and matching methods in audit entries."""

    @pytest.fixture
    def sample_entry(self):
        """Create sample audit entry for testing."""
        action = AuditAction("update", "user", "profile_update", "Profile updated")
        resource = ResourceIdentifier("user", str(uuid4()), "John Doe")
        context = AuditContext(session_id="sess-123")

        return AuditEntry(
            user_id=uuid4(),
            action=action,
            resource=resource,
            context=context,
            severity=AuditSeverity.HIGH,
            session_id=uuid4(),
        )

    def test_matches_user(self, sample_entry):
        """Test user matching functionality."""
        # Assert
        assert sample_entry.matches_user(sample_entry.user_id)
        assert not sample_entry.matches_user(uuid4())

    def test_matches_resource(self, sample_entry):
        """Test resource matching functionality."""
        # Assert
        assert sample_entry.matches_resource("user")
        assert sample_entry.matches_resource("user", sample_entry.resource.resource_id)
        assert not sample_entry.matches_resource("order")
        assert not sample_entry.matches_resource("user", "different-id")

    def test_matches_session(self, sample_entry):
        """Test session matching functionality."""
        # Assert
        assert sample_entry.matches_session(sample_entry.session_id)
        assert not sample_entry.matches_session(uuid4())

    def test_is_high_severity(self, sample_entry):
        """Test high severity detection."""
        # Assert
        assert sample_entry.is_high_severity()

        # Test with low severity
        low_severity_entry = AuditEntry(
            user_id=uuid4(),
            action=AuditAction("read", "document", "view", "Document viewed"),
            resource=ResourceIdentifier("document", str(uuid4())),
            context=AuditContext(),
            severity=AuditSeverity.LOW,
        )
        assert not low_severity_entry.is_high_severity()


class TestAuditEntryStringRepresentation:
    """Test string representation and logging methods."""

    def test_to_log_string_with_user_action(self):
        """Test log string representation for user action."""
        # Arrange
        user_id = uuid4()
        action = AuditAction("create", "order", "place_order", "Order placed")
        resource = ResourceIdentifier("order", "ORD-123", "Test Order")
        context = AuditContext()

        entry = AuditEntry(
            user_id=user_id,
            action=action,
            resource=resource,
            context=context,
            severity=AuditSeverity.MEDIUM,
        )

        # Act
        log_string = entry.to_log_string()

        # Assert
        assert str(user_id) in log_string
        assert "create:order:place_order" in log_string
        assert "type=order, id=ORD-123" in log_string
        assert "Severity=medium" in log_string

    def test_to_log_string_with_system_action(self):
        """Test log string representation for system action."""
        # Arrange
        action = AuditAction("execute", "cleanup", "purge_old_data", "System cleanup")
        resource = ResourceIdentifier("system", "cleanup-job-1")
        context = AuditContext()

        entry = AuditEntry(
            user_id=None,  # System action
            action=action,
            resource=resource,
            context=context,
            outcome="success",
        )

        # Act
        log_string = entry.to_log_string()

        # Assert
        assert "User=SYSTEM" in log_string
        assert "execute:cleanup:purge_old_data" in log_string

    def test_to_log_string_with_failure_outcome(self):
        """Test log string representation with failure outcome."""
        # Arrange
        action = AuditAction("delete", "user", "deactivate", "User deactivation")
        resource = ResourceIdentifier("user", str(uuid4()))
        context = AuditContext()

        entry = AuditEntry(
            user_id=uuid4(),
            action=action,
            resource=resource,
            context=context,
            outcome="failure",
            error_details={"error": "User not found"},
        )

        # Act
        log_string = entry.to_log_string()

        # Assert
        assert "[FAILURE]" in log_string


class TestAuditEntryDictSerialization:
    """Test dictionary serialization of audit entries."""

    def test_to_dict_complete_entry(self):
        """Test dictionary serialization with all fields."""
        # Arrange
        user_id = uuid4()
        session_id = uuid4()
        action = AuditAction("update", "profile", "change_email", "Email changed")
        resource = ResourceIdentifier("user", str(uuid4()), "John Doe")
        context = AuditContext(ip_address="192.168.1.1")
        metadata = AuditMetadata(tags=["profile", "email"])

        changes = [
            AuditField(
                field_name="email",
                old_value="old@example.com",
                new_value="new@example.com",
            )
        ]

        entry = AuditEntry(
            user_id=user_id,
            action=action,
            resource=resource,
            context=context,
            metadata=metadata,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.DATA_ACCESS,
            outcome="success",
            duration_ms=250,
            changes=changes,
            session_id=session_id,
        )

        # Act
        entry_dict = entry.to_dict()

        # Assert
        assert entry_dict["user_id"] == str(user_id)
        assert entry_dict["action"] == action.to_dict()
        assert entry_dict["resource"] == resource.to_dict()
        assert entry_dict["context"] == context.to_dict()
        assert entry_dict["metadata"] == metadata.to_dict()
        assert entry_dict["severity"] == "medium"
        assert entry_dict["category"] == "data_access"
        assert entry_dict["outcome"] == "success"
        assert entry_dict["duration_ms"] == 250
        assert len(entry_dict["changes"]) == 1
        assert entry_dict["session_id"] == str(session_id)
        assert entry_dict["correlation_id"] is not None

    def test_to_dict_system_entry(self):
        """Test dictionary serialization for system entry."""
        # Arrange
        action = AuditAction("execute", "maintenance", "backup", "System backup")
        resource = ResourceIdentifier("system", "backup-001")
        context = AuditContext()

        entry = AuditEntry(
            user_id=None,  # System action
            action=action,
            resource=resource,
            context=context,
        )

        # Act
        entry_dict = entry.to_dict()

        # Assert
        assert entry_dict["user_id"] is None
        assert entry_dict["session_id"] is None
        assert entry_dict["changes"] == []
        assert entry_dict["error_details"] is None


class TestAuditField:
    """Test AuditField entity for field-level changes."""

    def test_create_audit_field_with_all_data(self):
        """Test creating audit field with complete data."""
        # Act
        field = AuditField(
            field_name="email",
            old_value="old@example.com",
            new_value="new@example.com",
            field_path="user.profile.email",
            value_type="string",
            is_sensitive=False,
        )

        # Assert
        assert field.field_name == "email"
        assert field.old_value == "old@example.com"
        assert field.new_value == "new@example.com"
        assert field.field_path == "user.profile.email"
        assert field.value_type == "string"
        assert not field.is_sensitive
        assert field.has_changed()

    def test_create_audit_field_with_minimal_data(self):
        """Test creating audit field with minimal data."""
        # Act
        field = AuditField(
            field_name="status", old_value="active", new_value="inactive"
        )

        # Assert
        assert field.field_name == "status"
        assert field.field_path == "status"  # Should default to field_name
        assert field.value_type == "str"  # Should auto-determine from new_value type
        assert not field.is_sensitive  # Default

    def test_audit_field_sensitive_data_masking(self):
        """Test that sensitive field data is masked in display."""
        # Arrange
        field = AuditField(
            field_name="password",
            old_value="old_password",
            new_value="new_password",
            is_sensitive=True,
        )

        # Act & Assert
        assert field.get_display_value("secret_value") == "***REDACTED***"
        assert field.get_display_value(None) == "null"

        # Non-sensitive field should show actual value
        non_sensitive = AuditField(
            field_name="name", old_value="John", new_value="Jane", is_sensitive=False
        )
        assert non_sensitive.get_display_value("actual_value") == "actual_value"

    def test_audit_field_has_changed(self):
        """Test change detection in audit fields."""
        # Different values
        changed_field = AuditField(
            field_name="email", old_value="old@example.com", new_value="new@example.com"
        )
        assert changed_field.has_changed()

        # Same values
        unchanged_field = AuditField(
            field_name="email",
            old_value="same@example.com",
            new_value="same@example.com",
        )
        assert not unchanged_field.has_changed()

    def test_audit_field_to_dict_masks_sensitive_data(self):
        """Test that dictionary representation masks sensitive data."""
        # Arrange
        sensitive_field = AuditField(
            field_name="password",
            old_value="old_password",
            new_value="new_password",
            is_sensitive=True,
        )

        # Act
        field_dict = sensitive_field.to_dict()

        # Assert
        assert field_dict["old_value"] == "***REDACTED***"
        assert field_dict["new_value"] == "***REDACTED***"
        assert field_dict["is_sensitive"] is True

    @pytest.mark.parametrize("field_name", ["", "   ", None])
    def test_audit_field_invalid_field_name_raises_error(self, field_name):
        """Test that invalid field names raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="field_name"):
            AuditField(field_name=field_name, old_value="old", new_value="new")
