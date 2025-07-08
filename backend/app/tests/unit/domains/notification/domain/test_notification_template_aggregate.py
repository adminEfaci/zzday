"""Comprehensive tests for NotificationTemplate aggregate.

This module provides complete test coverage for the NotificationTemplate aggregate,
including multi-channel support, variable substitution, template versioning,
and lifecycle management.
"""


import pytest

from app.core.errors import ValidationError
from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.enums import (
    NotificationChannel,
    TemplateType,
    VariableType,
)
from app.modules.notification.domain.errors import (
    InvalidTemplateError,
    TemplateVariableError,
)
from app.modules.notification.domain.events import (
    TemplateCreated,
    TemplateDeleted,
    TemplateUpdated,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    TemplateVariable,
)


class TestNotificationTemplateCreation:
    """Test suite for NotificationTemplate creation and initialization."""

    def test_basic_template_creation(self, sample_user_id):
        """Test creating a basic notification template."""
        template = NotificationTemplate(
            name="Welcome Email",
            template_type=TemplateType.TRANSACTIONAL,
            created_by=sample_user_id,
            description="Welcome email for new users",
            tags=["welcome", "onboarding"],
        )

        assert template.name == "Welcome Email"
        assert template.template_type == TemplateType.TRANSACTIONAL
        assert template.created_by == sample_user_id
        assert template.description == "Welcome email for new users"
        assert template.tags == ["welcome", "onboarding"]
        assert template.version == 1
        assert template.is_active is True
        assert template.is_default is False
        assert template.usage_count == 0
        assert len(template.channel_contents) == 0
        assert len(template.variables) == 0
        assert len(template.required_channels) == 0

    def test_template_creation_with_minimal_fields(self, sample_user_id):
        """Test creating template with minimal required fields."""
        template = NotificationTemplate(
            name="Minimal Template",
            template_type=TemplateType.SYSTEM,
            created_by=sample_user_id,
        )

        assert template.name == "Minimal Template"
        assert template.template_type == TemplateType.SYSTEM
        assert template.created_by == sample_user_id
        assert template.description is None
        assert template.tags == []

    def test_template_creation_emits_event(self, sample_user_id):
        """Test that template creation emits TemplateCreated event."""
        template = NotificationTemplate(
            name="Test Template",
            template_type=TemplateType.ALERT,
            created_by=sample_user_id,
        )

        events = template.get_uncommitted_events()
        assert len(events) == 1

        event = events[0]
        assert isinstance(event, TemplateCreated)
        assert event.template_id == template.id
        assert event.name == "Test Template"
        assert event.template_type == TemplateType.ALERT
        assert event.created_by == sample_user_id
        assert event.is_active is True

    def test_template_name_validation_empty_fails(self, sample_user_id):
        """Test that empty template name fails validation."""
        with pytest.raises(ValidationError, match="Template name is required"):
            NotificationTemplate(
                name="",
                template_type=TemplateType.TRANSACTIONAL,
                created_by=sample_user_id,
            )

    def test_template_name_validation_whitespace_only_fails(self, sample_user_id):
        """Test that whitespace-only template name fails validation."""
        with pytest.raises(ValidationError, match="Template name is required"):
            NotificationTemplate(
                name="   ",
                template_type=TemplateType.TRANSACTIONAL,
                created_by=sample_user_id,
            )

    def test_template_name_validation_too_long_fails(self, sample_user_id):
        """Test that overly long template name fails validation."""
        long_name = "A" * 101  # Exceeds 100 character limit

        with pytest.raises(
            ValidationError, match="Template name cannot exceed 100 characters"
        ):
            NotificationTemplate(
                name=long_name,
                template_type=TemplateType.TRANSACTIONAL,
                created_by=sample_user_id,
            )

    def test_template_name_trimming(self, sample_user_id):
        """Test that template name is trimmed of whitespace."""
        template = NotificationTemplate(
            name="  Trimmed Name  ",
            template_type=TemplateType.TRANSACTIONAL,
            created_by=sample_user_id,
        )

        assert template.name == "Trimmed Name"


class TestNotificationTemplateChannelContent:
    """Test suite for template channel content management."""

    def test_add_email_channel_content(self, email_template, sample_user_id):
        """Test adding email channel content."""
        content = NotificationContent(
            subject="Welcome {{user_name}}",
            body="Hello {{user_name}}, welcome to our platform!",
            html_body="<h1>Welcome {{user_name}}!</h1>",
            variables={"user_name": "John"},
        )

        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        assert NotificationChannel.EMAIL in email_template.channel_contents
        stored_content = email_template.channel_contents[NotificationChannel.EMAIL]
        assert stored_content.subject == "Welcome {{user_name}}"
        assert stored_content.body == "Hello {{user_name}}, welcome to our platform!"

        # Check that variable was auto-created
        assert "user_name" in email_template.variables

    def test_add_sms_channel_content(self, email_template, sample_user_id):
        """Test adding SMS channel content."""
        content = NotificationContent(
            body="Welcome {{user_name}}! Your code: {{code}}",
            variables={"user_name": "John", "code": "123456"},
        )

        email_template.add_channel_content(
            NotificationChannel.SMS, content, sample_user_id
        )

        assert NotificationChannel.SMS in email_template.channel_contents
        stored_content = email_template.channel_contents[NotificationChannel.SMS]
        assert stored_content.body == "Welcome {{user_name}}! Your code: {{code}}"

        # Check that variables were auto-created
        assert "user_name" in email_template.variables
        assert "code" in email_template.variables

    def test_add_push_channel_content(self, email_template, sample_user_id):
        """Test adding push notification channel content."""
        content = NotificationContent(
            subject="Alert from {{app_name}}",
            body="{{message}}",
            variables={"app_name": "MyApp", "message": "Important update"},
        )

        email_template.add_channel_content(
            NotificationChannel.PUSH, content, sample_user_id
        )

        assert NotificationChannel.PUSH in email_template.channel_contents
        stored_content = email_template.channel_contents[NotificationChannel.PUSH]
        assert stored_content.subject == "Alert from {{app_name}}"
        assert stored_content.body == "{{message}}"

    def test_add_in_app_channel_content(self, email_template, sample_user_id):
        """Test adding in-app notification channel content."""
        content = NotificationContent(
            subject="System Notification",
            body="{{notification_text}}",
            html_body="<div class='alert'>{{notification_text}}</div>",
            variables={"notification_text": "System maintenance scheduled"},
        )

        email_template.add_channel_content(
            NotificationChannel.IN_APP, content, sample_user_id
        )

        assert NotificationChannel.IN_APP in email_template.channel_contents
        stored_content = email_template.channel_contents[NotificationChannel.IN_APP]
        assert (
            stored_content.html_body == "<div class='alert'>{{notification_text}}</div>"
        )

    def test_update_existing_channel_content(self, email_template, sample_user_id):
        """Test updating existing channel content."""
        # Add initial content
        initial_content = NotificationContent(
            subject="Initial Subject", body="Initial body"
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, initial_content, sample_user_id
        )
        initial_version = email_template.version

        # Update content
        updated_content = NotificationContent(
            subject="Updated Subject",
            body="Updated body with {{variable}}",
            variables={"variable": "value"},
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, updated_content, sample_user_id
        )

        # Verify update
        stored_content = email_template.channel_contents[NotificationChannel.EMAIL]
        assert stored_content.subject == "Updated Subject"
        assert stored_content.body == "Updated body with {{variable}}"
        assert email_template.version == initial_version + 1

    def test_email_content_validation_requires_subject(
        self, email_template, sample_user_id
    ):
        """Test that email content requires a subject."""
        content = NotificationContent(body="Email body without subject")

        with pytest.raises(
            InvalidTemplateError, match="Email templates require a subject"
        ):
            email_template.add_channel_content(
                NotificationChannel.EMAIL, content, sample_user_id
            )

    def test_sms_content_length_validation(self, email_template, sample_user_id):
        """Test SMS content length validation."""
        long_body = "A" * 1601  # Exceeds 1600 character limit
        content = NotificationContent(body=long_body)

        with pytest.raises(
            InvalidTemplateError,
            match="SMS template body cannot exceed 1600 characters",
        ):
            email_template.add_channel_content(
                NotificationChannel.SMS, content, sample_user_id
            )

    def test_push_content_title_length_validation(self, email_template, sample_user_id):
        """Test push notification title length validation."""
        long_title = "A" * 66  # Exceeds 65 character limit
        content = NotificationContent(subject=long_title, body="Push body")

        with pytest.raises(
            InvalidTemplateError,
            match="Push notification title cannot exceed 65 characters",
        ):
            email_template.add_channel_content(
                NotificationChannel.PUSH, content, sample_user_id
            )

    def test_push_content_body_length_validation(self, email_template, sample_user_id):
        """Test push notification body length validation."""
        long_body = "A" * 241  # Exceeds 240 character limit
        content = NotificationContent(subject="Push Title", body=long_body)

        with pytest.raises(
            InvalidTemplateError,
            match="Push notification body cannot exceed 240 characters",
        ):
            email_template.add_channel_content(
                NotificationChannel.PUSH, content, sample_user_id
            )

    def test_remove_channel_content(self, multi_channel_template, sample_user_id):
        """Test removing channel content."""
        assert NotificationChannel.SMS in multi_channel_template.channel_contents
        initial_version = multi_channel_template.version

        multi_channel_template.remove_channel_content(
            NotificationChannel.SMS, sample_user_id
        )

        assert NotificationChannel.SMS not in multi_channel_template.channel_contents
        assert multi_channel_template.version == initial_version + 1

    def test_remove_nonexistent_channel_content_fails(
        self, email_template, sample_user_id
    ):
        """Test removing nonexistent channel content fails."""
        with pytest.raises(ValidationError, match="No content found for channel"):
            email_template.remove_channel_content(
                NotificationChannel.SMS, sample_user_id
            )

    def test_remove_required_channel_content_fails(
        self, multi_channel_template, sample_user_id
    ):
        """Test removing required channel content fails."""
        # Set email as required
        multi_channel_template.set_required_channels(
            [NotificationChannel.EMAIL], sample_user_id
        )

        with pytest.raises(ValidationError, match="Cannot remove required channel"):
            multi_channel_template.remove_channel_content(
                NotificationChannel.EMAIL, sample_user_id
            )

    def test_add_channel_content_emits_event(self, email_template, sample_user_id):
        """Test that adding channel content emits TemplateUpdated event."""
        content = NotificationContent(subject="New Content", body="New body")

        email_template.clear_events()  # Clear creation event
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        events = email_template.get_uncommitted_events()
        assert len(events) == 1

        event = events[0]
        assert isinstance(event, TemplateUpdated)
        assert event.template_id == email_template.id
        assert event.updated_by == sample_user_id
        assert event.changes["channel"] == "email"
        assert event.changes["action"] == "added"


class TestNotificationTemplateVariables:
    """Test suite for template variable management."""

    def test_define_string_variable(self, email_template, sample_user_id):
        """Test defining a string variable."""
        variable = TemplateVariable(
            name="user_name",
            var_type=VariableType.STRING,
            required=True,
            description="User's full name",
        )

        email_template.define_variable(variable, sample_user_id)

        assert "user_name" in email_template.variables
        stored_var = email_template.variables["user_name"]
        assert stored_var.name == "user_name"
        assert stored_var.var_type == VariableType.STRING
        assert stored_var.required is True
        assert stored_var.description == "User's full name"

    def test_define_currency_variable_with_default(
        self, email_template, sample_user_id
    ):
        """Test defining a currency variable with default value."""
        variable = TemplateVariable(
            name="discount",
            var_type=VariableType.CURRENCY,
            required=False,
            default_value=0.0,
            description="Discount amount",
            validation_rules={"min_value": 0, "max_value": 1000},
        )

        email_template.define_variable(variable, sample_user_id)

        stored_var = email_template.variables["discount"]
        assert stored_var.var_type == VariableType.CURRENCY
        assert stored_var.default_value == 0.0
        assert stored_var.validation_rules["max_value"] == 1000

    def test_define_date_variable_with_pattern(self, email_template, sample_user_id):
        """Test defining a date variable with format pattern."""
        variable = TemplateVariable(
            name="event_date",
            var_type=VariableType.DATE,
            required=True,
            description="Event date",
            format_pattern="{:%B %d, %Y}",
        )

        email_template.define_variable(variable, sample_user_id)

        stored_var = email_template.variables["event_date"]
        assert stored_var.var_type == VariableType.DATE
        assert stored_var.format_pattern == "{:%B %d, %Y}"

    def test_update_existing_variable(self, email_template, sample_user_id):
        """Test updating an existing variable definition."""
        # Define initial variable
        initial_var = TemplateVariable(
            name="amount", var_type=VariableType.NUMBER, required=True
        )
        email_template.define_variable(initial_var, sample_user_id)
        initial_version = email_template.version

        # Update variable
        updated_var = TemplateVariable(
            name="amount",
            var_type=VariableType.CURRENCY,
            required=False,
            default_value=0.0,
            description="Updated amount field",
        )
        email_template.define_variable(updated_var, sample_user_id)

        # Verify update
        stored_var = email_template.variables["amount"]
        assert stored_var.var_type == VariableType.CURRENCY
        assert stored_var.default_value == 0.0
        assert stored_var.description == "Updated amount field"
        assert email_template.version == initial_version + 1

    def test_remove_variable(self, email_template, sample_user_id):
        """Test removing a variable definition."""
        # Define variable
        variable = TemplateVariable(
            name="temp_var", var_type=VariableType.STRING, required=False
        )
        email_template.define_variable(variable, sample_user_id)
        assert "temp_var" in email_template.variables

        initial_version = email_template.version

        # Remove variable
        email_template.remove_variable("temp_var", sample_user_id)

        assert "temp_var" not in email_template.variables
        assert email_template.version == initial_version + 1

    def test_remove_nonexistent_variable_fails(self, email_template, sample_user_id):
        """Test removing nonexistent variable fails."""
        with pytest.raises(ValidationError, match="Variable nonexistent not found"):
            email_template.remove_variable("nonexistent", sample_user_id)

    def test_remove_variable_used_in_content_fails(
        self, email_template, sample_user_id
    ):
        """Test removing variable used in content fails."""
        # Add content with variable
        content = NotificationContent(
            subject="Hello {{user_name}}", body="Welcome {{user_name}}"
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Try to remove the variable
        with pytest.raises(ValidationError, match="Cannot remove variable user_name"):
            email_template.remove_variable("user_name", sample_user_id)

    def test_auto_create_variables_from_content(self, email_template, sample_user_id):
        """Test that variables are auto-created from content."""
        content = NotificationContent(
            subject="{{title}} for {{user_name}}",
            body="Hello {{user_name}}, your {{item_type}} is ready!",
        )

        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Check that all variables were auto-created
        expected_vars = ["title", "user_name", "item_type"]
        for var_name in expected_vars:
            assert var_name in email_template.variables
            var = email_template.variables[var_name]
            assert var.var_type == VariableType.STRING
            assert var.required is True

    def test_define_variable_emits_event(self, email_template, sample_user_id):
        """Test that defining variable emits TemplateUpdated event."""
        variable = TemplateVariable(
            name="test_var", var_type=VariableType.STRING, required=True
        )

        email_template.clear_events()
        email_template.define_variable(variable, sample_user_id)

        events = email_template.get_uncommitted_events()
        assert len(events) == 1

        event = events[0]
        assert isinstance(event, TemplateUpdated)
        assert event.changes["variable"] == "test_var"
        assert event.changes["action"] == "defined"
        assert event.changes["type"] == "string"


class TestNotificationTemplateValidation:
    """Test suite for template variable validation."""

    def test_validate_variables_success(self, email_template, sample_user_id):
        """Test successful variable validation."""
        # Define variables
        variables = [
            TemplateVariable("user_name", VariableType.STRING, required=True),
            TemplateVariable("age", VariableType.NUMBER, required=True),
            TemplateVariable(
                "discount", VariableType.CURRENCY, required=False, default_value=0.0
            ),
        ]

        for var in variables:
            email_template.define_variable(var, sample_user_id)

        # Valid variable values
        provided_vars = {"user_name": "John Doe", "age": 25, "discount": 15.99}

        # Should not raise exception
        email_template.validate_variables(provided_vars)

    def test_validate_variables_missing_required_fails(
        self, email_template, sample_user_id
    ):
        """Test validation fails for missing required variables."""
        # Define required variable
        variable = TemplateVariable("user_name", VariableType.STRING, required=True)
        email_template.define_variable(variable, sample_user_id)

        # Missing required variable
        provided_vars = {"other_var": "value"}

        with pytest.raises(TemplateVariableError) as exc_info:
            email_template.validate_variables(provided_vars)

        error = exc_info.value
        assert "user_name" in error.missing_variables
        assert error.template_id == email_template.id

    def test_validate_variables_with_defaults_success(
        self, email_template, sample_user_id
    ):
        """Test validation succeeds with default values."""
        # Define variable with default
        variable = TemplateVariable(
            "greeting", VariableType.STRING, required=True, default_value="Hello"
        )
        email_template.define_variable(variable, sample_user_id)

        # Don't provide the variable (should use default)
        provided_vars = {}

        # Should not raise exception
        email_template.validate_variables(provided_vars)

    def test_validate_variables_invalid_type_fails(
        self, email_template, sample_user_id
    ):
        """Test validation fails for invalid variable types."""
        # Define number variable
        variable = TemplateVariable("age", VariableType.NUMBER, required=True)
        email_template.define_variable(variable, sample_user_id)

        # Provide string value for number variable
        provided_vars = {"age": "not a number"}

        with pytest.raises(TemplateVariableError) as exc_info:
            email_template.validate_variables(provided_vars)

        error = exc_info.value
        assert "age" in error.invalid_variables
        assert "Invalid value for number type" in error.invalid_variables["age"]

    def test_validate_variables_with_validation_rules(
        self, email_template, sample_user_id
    ):
        """Test validation with custom validation rules."""
        # Define variable with validation rules
        variable = TemplateVariable(
            "code",
            VariableType.STRING,
            required=True,
            validation_rules={"min_length": 6, "max_length": 6, "pattern": r"^\d{6}$"},
        )
        email_template.define_variable(variable, sample_user_id)

        # Valid code
        email_template.validate_variables({"code": "123456"})

        # Invalid codes
        invalid_codes = ["12345", "1234567", "abc123"]
        for invalid_code in invalid_codes:
            with pytest.raises(TemplateVariableError):
                email_template.validate_variables({"code": invalid_code})


class TestNotificationTemplateRendering:
    """Test suite for template content rendering."""

    def test_render_email_content(self, email_template, sample_user_id):
        """Test rendering email content with variables."""
        # Add content with variables
        content = NotificationContent(
            subject="Welcome {{user_name}} to {{platform_name}}",
            body="Hello {{user_name}},\n\nWelcome to {{platform_name}}! Your balance is {{balance}}.",
            html_body="<h1>Welcome {{user_name}}!</h1><p>Balance: {{balance}}</p>",
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Define variables
        variables = [
            TemplateVariable("user_name", VariableType.STRING, required=True),
            TemplateVariable("platform_name", VariableType.STRING, required=True),
            TemplateVariable("balance", VariableType.CURRENCY, required=True),
        ]
        for var in variables:
            email_template.define_variable(var, sample_user_id)

        # Render content
        rendered = email_template.render_for_channel(
            NotificationChannel.EMAIL,
            {"user_name": "John Doe", "platform_name": "MyApp", "balance": 1234.56},
        )

        assert rendered.subject == "Welcome John Doe to MyApp"
        assert "Welcome to MyApp!" in rendered.body
        assert "$1,234.56" in rendered.body
        assert "<h1>Welcome John Doe!</h1>" in rendered.html_body

    def test_render_sms_content(self, email_template, sample_user_id):
        """Test rendering SMS content with variables."""
        content = NotificationContent(
            body="Your verification code is {{code}}. Expires in {{expiry_minutes}} minutes."
        )
        email_template.add_channel_content(
            NotificationChannel.SMS, content, sample_user_id
        )

        # Define variables
        variables = [
            TemplateVariable("code", VariableType.STRING, required=True),
            TemplateVariable("expiry_minutes", VariableType.NUMBER, required=True),
        ]
        for var in variables:
            email_template.define_variable(var, sample_user_id)

        rendered = email_template.render_for_channel(
            NotificationChannel.SMS, {"code": "123456", "expiry_minutes": 5}
        )

        assert (
            rendered.body == "Your verification code is 123456. Expires in 5 minutes."
        )

    def test_render_with_default_values(self, email_template, sample_user_id):
        """Test rendering with default variable values."""
        content = NotificationContent(
            subject="{{greeting}} {{user_name}}!",
            body="{{greeting}} {{user_name}}, welcome to {{platform_name}}!",
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Define variables with defaults
        variables = [
            TemplateVariable(
                "greeting", VariableType.STRING, required=False, default_value="Hello"
            ),
            TemplateVariable("user_name", VariableType.STRING, required=True),
            TemplateVariable(
                "platform_name",
                VariableType.STRING,
                required=False,
                default_value="Our Platform",
            ),
        ]
        for var in variables:
            email_template.define_variable(var, sample_user_id)

        rendered = email_template.render_for_channel(
            NotificationChannel.EMAIL,
            {"user_name": "Alice"},  # Only provide required variable
        )

        assert rendered.subject == "Hello Alice!"
        assert rendered.body == "Hello Alice, welcome to Our Platform!"

    def test_render_formatted_values(self, email_template, sample_user_id):
        """Test rendering with formatted variable values."""
        content = NotificationContent(
            body="Your order total is {{amount}}. Due date: {{due_date}}."
        )
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Define variables with formatting
        variables = [
            TemplateVariable("amount", VariableType.CURRENCY, required=True),
            TemplateVariable("due_date", VariableType.DATE, required=True),
        ]
        for var in variables:
            email_template.define_variable(var, sample_user_id)

        rendered = email_template.render_for_channel(
            NotificationChannel.EMAIL,
            {"amount": 99.99, "due_date": "2023-12-25T00:00:00Z"},
        )

        assert "$99.99" in rendered.body
        assert "2023-12-25" in rendered.body

    def test_render_nonexistent_channel_fails(self, email_template):
        """Test rendering nonexistent channel fails."""
        with pytest.raises(
            InvalidTemplateError, match="No content defined for channel"
        ):
            email_template.render_for_channel(NotificationChannel.SMS, {})

    def test_render_with_validation_errors_fails(self, email_template, sample_user_id):
        """Test rendering with validation errors fails."""
        content = NotificationContent(body="Hello {{user_name}}")
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        # Missing required variable
        with pytest.raises(TemplateVariableError):
            email_template.render_for_channel(NotificationChannel.EMAIL, {})


class TestNotificationTemplateVersioning:
    """Test suite for template versioning and lifecycle."""

    def test_version_increments_on_changes(self, email_template, sample_user_id):
        """Test that version increments on template changes."""
        initial_version = email_template.version

        # Add content
        content = NotificationContent(subject="Test", body="Test body")
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )
        assert email_template.version == initial_version + 1

        # Define variable
        variable = TemplateVariable("test_var", VariableType.STRING, required=True)
        email_template.define_variable(variable, sample_user_id)
        assert email_template.version == initial_version + 2

        # Set required channels
        email_template.set_required_channels(
            [NotificationChannel.EMAIL], sample_user_id
        )
        assert email_template.version == initial_version + 3

    def test_version_history_tracking(self, email_template, sample_user_id):
        """Test that version history is tracked."""
        initial_history_length = len(email_template.version_history)

        # Make changes
        content = NotificationContent(subject="Test", body="Test body")
        email_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        variable = TemplateVariable("test_var", VariableType.STRING, required=True)
        email_template.define_variable(variable, sample_user_id)

        # Check history
        assert len(email_template.version_history) == initial_history_length + 2

        latest_entry = email_template.version_history[-1]
        assert latest_entry["version"] == email_template.version
        assert latest_entry["updated_by"] == str(sample_user_id)
        assert "defined variable test_var" in latest_entry["description"]
        assert "updated_at" in latest_entry

    def test_version_history_limit(self, email_template, sample_user_id):
        """Test that version history is limited to 50 entries."""
        # Make 55 changes to exceed limit
        for i in range(55):
            variable = TemplateVariable(f"var_{i}", VariableType.STRING, required=False)
            email_template.define_variable(variable, sample_user_id)

        # History should be limited to 50
        assert len(email_template.version_history) == 50

        # Should contain the latest 50 versions
        versions = [entry["version"] for entry in email_template.version_history]
        expected_versions = list(
            range(email_template.version - 49, email_template.version + 1)
        )
        assert versions == expected_versions

    def test_activate_template(self, inactive_template, sample_user_id):
        """Test activating an inactive template."""
        # Add content first
        content = NotificationContent(subject="Test", body="Test body")
        inactive_template.add_channel_content(
            NotificationChannel.EMAIL, content, sample_user_id
        )

        assert inactive_template.is_active is False
        initial_version = inactive_template.version

        inactive_template.activate(sample_user_id)

        assert inactive_template.is_active is True
        assert inactive_template.version == initial_version + 1

    def test_activate_template_without_content_fails(
        self, inactive_template, sample_user_id
    ):
        """Test activating template without content fails."""
        with pytest.raises(
            InvalidTemplateError,
            match="Cannot activate template without any channel content",
        ):
            inactive_template.activate(sample_user_id)

    def test_deactivate_template(self, email_template, sample_user_id):
        """Test deactivating an active template."""
        assert email_template.is_active is True
        initial_version = email_template.version

        email_template.deactivate(sample_user_id, "No longer needed")

        assert email_template.is_active is False
        assert email_template.version == initial_version + 1

    def test_set_as_default_template(self, email_template, sample_user_id):
        """Test setting template as default."""
        assert email_template.is_default is False
        initial_version = email_template.version

        email_template.set_as_default(sample_user_id)

        assert email_template.is_default is True
        assert email_template.version == initial_version + 1

    def test_set_inactive_template_as_default_fails(
        self, inactive_template, sample_user_id
    ):
        """Test setting inactive template as default fails."""
        with pytest.raises(
            ValidationError, match="Cannot set inactive template as default"
        ):
            inactive_template.set_as_default(sample_user_id)


class TestNotificationTemplateRequiredChannels:
    """Test suite for required channel management."""

    def test_set_required_channels(self, multi_channel_template, sample_user_id):
        """Test setting required channels."""
        required_channels = [NotificationChannel.EMAIL, NotificationChannel.SMS]
        multi_channel_template.set_required_channels(required_channels, sample_user_id)

        assert multi_channel_template.required_channels == set(required_channels)

    def test_set_required_channels_without_content_fails(
        self, email_template, sample_user_id
    ):
        """Test setting required channel without content fails."""
        with pytest.raises(
            ValidationError, match="Cannot require channel sms without content"
        ):
            email_template.set_required_channels(
                [NotificationChannel.SMS], sample_user_id
            )

    def test_remove_required_channel_content_blocked(
        self, multi_channel_template, sample_user_id
    ):
        """Test that required channel content cannot be removed."""
        # Set email as required
        multi_channel_template.set_required_channels(
            [NotificationChannel.EMAIL], sample_user_id
        )

        # Try to remove required channel
        with pytest.raises(ValidationError, match="Cannot remove required channel"):
            multi_channel_template.remove_channel_content(
                NotificationChannel.EMAIL, sample_user_id
            )


class TestNotificationTemplateUsageTracking:
    """Test suite for template usage tracking."""

    def test_mark_as_used(self, email_template):
        """Test marking template as used."""
        initial_count = email_template.usage_count
        assert email_template.last_used_at is None

        email_template.mark_as_used()

        assert email_template.usage_count == initial_count + 1
        assert email_template.last_used_at is not None

    def test_multiple_uses_increment_count(self, email_template):
        """Test multiple uses increment count."""
        initial_count = email_template.usage_count

        for _i in range(5):
            email_template.mark_as_used()

        assert email_template.usage_count == initial_count + 5

    def test_get_usage_stats(self, email_template):
        """Test getting usage statistics."""
        email_template.mark_as_used()

        stats = email_template.get_usage_stats()

        assert stats["usage_count"] == 1
        assert stats["last_used_at"] is not None
        assert stats["version"] == email_template.version
        assert stats["channel_count"] >= 0
        assert stats["variable_count"] >= 0
        assert stats["is_active"] == email_template.is_active
        assert stats["is_default"] == email_template.is_default


class TestNotificationTemplateMetadata:
    """Test suite for template metadata management."""

    def test_add_metadata(self, email_template):
        """Test adding metadata to template."""
        email_template.add_metadata("category", "user_onboarding")
        email_template.add_metadata("priority", "high")

        assert hasattr(email_template, "metadata")
        assert email_template.metadata["category"] == "user_onboarding"
        assert email_template.metadata["priority"] == "high"

    def test_add_tag(self, email_template):
        """Test adding tags to template."""
        initial_tags = len(email_template.tags)

        email_template.add_tag("important")
        email_template.add_tag("customer-facing")

        assert len(email_template.tags) == initial_tags + 2
        assert "important" in email_template.tags
        assert "customer-facing" in email_template.tags

    def test_add_duplicate_tag_ignored(self, email_template):
        """Test adding duplicate tag is ignored."""
        email_template.add_tag("existing")
        initial_count = len(email_template.tags)

        email_template.add_tag("existing")

        assert len(email_template.tags) == initial_count

    def test_remove_tag(self, email_template):
        """Test removing tag from template."""
        email_template.add_tag("removeme")
        assert "removeme" in email_template.tags

        email_template.remove_tag("removeme")

        assert "removeme" not in email_template.tags

    def test_remove_nonexistent_tag_ignored(self, email_template):
        """Test removing nonexistent tag is ignored."""
        initial_tags = email_template.tags.copy()

        email_template.remove_tag("nonexistent")

        assert email_template.tags == initial_tags


class TestNotificationTemplateDeletion:
    """Test suite for template deletion."""

    def test_delete_template(self, email_template, sample_user_id):
        """Test soft deleting template."""
        assert email_template.is_active is True

        email_template.delete(sample_user_id, "No longer needed")

        assert email_template.is_active is False
        assert hasattr(email_template, "metadata")
        assert email_template.metadata["deleted"] is True
        assert email_template.metadata["deleted_by"] == str(sample_user_id)
        assert "deleted_at" in email_template.metadata
        assert email_template.metadata["deletion_reason"] == "No longer needed"

    def test_delete_template_emits_event(self, email_template, sample_user_id):
        """Test that template deletion emits event."""
        email_template.clear_events()
        email_template.delete(sample_user_id, "Testing deletion")

        events = email_template.get_uncommitted_events()
        assert len(events) == 1

        event = events[0]
        assert isinstance(event, TemplateDeleted)
        assert event.template_id == email_template.id
        assert event.deleted_by == sample_user_id
        assert event.reason == "Testing deletion"


class TestNotificationTemplateUtilities:
    """Test suite for template utility methods."""

    def test_get_supported_channels(self, multi_channel_template):
        """Test getting supported channels."""
        channels = multi_channel_template.get_supported_channels()

        expected_channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
            NotificationChannel.IN_APP,
        ]

        for channel in expected_channels:
            assert channel in channels

    def test_export_template(self, multi_channel_template):
        """Test exporting template configuration."""
        export_data = multi_channel_template.export()

        assert export_data["name"] == multi_channel_template.name
        assert (
            export_data["template_type"] == multi_channel_template.template_type.value
        )
        assert export_data["version"] == multi_channel_template.version
        assert export_data["is_active"] == multi_channel_template.is_active
        assert "channels" in export_data
        assert "variables" in export_data
        assert "created_at" in export_data
        assert "updated_at" in export_data

        # Check channels export
        for channel in multi_channel_template.channel_contents:
            assert channel.value in export_data["channels"]

    def test_string_representation(self, multi_channel_template):
        """Test string representation of template."""
        str_repr = str(multi_channel_template)

        assert multi_channel_template.name in str_repr
        assert multi_channel_template.template_type.value in str_repr
        assert f"v{multi_channel_template.version}" in str_repr
        assert "Channels:" in str_repr
