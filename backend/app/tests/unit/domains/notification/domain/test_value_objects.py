"""Comprehensive tests for notification domain value objects.

This module tests all value objects in the notification domain including:
- NotificationContent with variable substitution and channel optimization
- RecipientAddress with channel-specific validation
- ChannelConfig with provider-specific settings
- NotificationPriorityValue with escalation rules
- DeliveryStatusValue with retry logic
- TemplateVariable with type validation and formatting
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    VariableType,
)
from app.modules.notification.domain.value_objects import (
    ChannelConfig,
    DeliveryStatusValue,
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
    TemplateVariable,
)


class TestNotificationContent:
    """Test suite for NotificationContent value object."""

    def test_basic_content_creation(self):
        """Test basic content creation with all fields."""
        content = NotificationContent(
            subject="Test Subject",
            body="Test body content",
            html_body="<p>Test body content</p>",
            variables={"user": "John", "amount": 100},
            attachments=[{"filename": "test.pdf", "size": 1024}],
            metadata={"campaign": "welcome"},
        )

        assert content.subject == "Test Subject"
        assert content.body == "Test body content"
        assert content.html_body == "<p>Test body content</p>"
        assert content.variables == {"user": "John", "amount": 100}
        assert len(content.attachments) == 1
        assert content.metadata == {"campaign": "welcome"}

    def test_content_creation_with_minimal_fields(self):
        """Test content creation with only required fields."""
        content = NotificationContent(body="Just a body")

        assert content.subject is None
        assert content.body == "Just a body"
        assert content.html_body is None
        assert content.variables == {}
        assert content.attachments == []
        assert content.metadata == {}

    def test_content_validation_empty_body_fails(self):
        """Test that empty body raises validation error."""
        with pytest.raises(ValidationError, match="body"):
            NotificationContent(body="")

    def test_content_validation_none_body_fails(self):
        """Test that None body raises validation error."""
        with pytest.raises(ValidationError):
            NotificationContent(body=None)

    def test_subject_length_validation(self):
        """Test subject length validation."""
        long_subject = "A" * 201  # Exceeds 200 character limit

        with pytest.raises(
            ValidationError, match="Subject cannot exceed 200 characters"
        ):
            NotificationContent(subject=long_subject, body="Test body")

    def test_body_length_validation(self):
        """Test body length validation."""
        long_body = "A" * 100001  # Exceeds 100KB limit

        with pytest.raises(ValidationError, match="Body cannot exceed 100KB"):
            NotificationContent(body=long_body)

    def test_html_body_length_validation(self):
        """Test HTML body length validation."""
        long_html = "<p>" + "A" * 500000 + "</p>"  # Exceeds 500KB limit

        with pytest.raises(ValidationError, match="HTML body cannot exceed 500KB"):
            NotificationContent(body="Test body", html_body=long_html)

    def test_attachment_validation_requires_filename(self):
        """Test that attachments must have filename."""
        with pytest.raises(ValidationError, match="Attachment must have a filename"):
            NotificationContent(
                body="Test body", attachments=[{"size": 1024}]  # Missing filename
            )

    def test_attachment_size_validation(self):
        """Test attachment size validation."""
        large_attachment = {
            "filename": "large.pdf",
            "size": 11485760,  # 11MB, exceeds 10MB limit
        }

        with pytest.raises(ValidationError, match="exceeds 10MB limit"):
            NotificationContent(body="Test body", attachments=[large_attachment])

    def test_attachment_validation_non_dict_fails(self):
        """Test that non-dict attachments fail validation."""
        with pytest.raises(
            ValidationError, match="Each attachment must be a dictionary"
        ):
            NotificationContent(body="Test body", attachments=["invalid_attachment"])

    def test_variable_substitution_simple(self):
        """Test simple variable substitution."""
        content = NotificationContent(
            subject="Hello {{name}}",
            body="Welcome {{name}}, you have {{count}} messages.",
            variables={"existing": "value"},
        )

        rendered = content.render({"name": "John", "count": 5})

        assert rendered.subject == "Hello John"
        assert rendered.body == "Welcome John, you have 5 messages."

    def test_variable_substitution_html(self):
        """Test variable substitution in HTML content."""
        content = NotificationContent(
            body="Plain text",
            html_body="<h1>Hello {{name}}</h1><p>Balance: ${{balance}}</p>",
        )

        rendered = content.render({"name": "Alice", "balance": 1250.50})

        assert rendered.html_body == "<h1>Hello Alice</h1><p>Balance: $1250.5</p>"

    def test_variable_substitution_merges_variables(self):
        """Test that render merges template variables with provided variables."""
        content = NotificationContent(
            body="{{greeting}} {{name}}, {{message}}",
            variables={"greeting": "Hello", "message": "Welcome back!"},
        )

        rendered = content.render({"name": "Bob"})

        assert rendered.body == "Hello Bob, Welcome back!"

    def test_variable_substitution_overrides_instance_variables(self):
        """Test that provided variables override instance variables."""
        content = NotificationContent(
            body="{{message}}", variables={"message": "Default message"}
        )

        rendered = content.render({"message": "Override message"})

        assert rendered.body == "Override message"

    def test_extract_variables_from_all_content(self):
        """Test extracting variable names from all content fields."""
        content = NotificationContent(
            subject="{{title}} - {{date}}",
            body="Hello {{name}}, {{message}}",
            html_body="<p>{{name}}</p><p>{{extra_var}}</p>",
        )

        variables = content.extract_variables()

        expected = ["date", "extra_var", "message", "name", "title"]
        assert variables == expected

    def test_extract_variables_no_subject(self):
        """Test extracting variables when subject is None."""
        content = NotificationContent(body="Hello {{name}}, {{message}}")

        variables = content.extract_variables()

        assert variables == ["message", "name"]

    def test_extract_variables_empty_content(self):
        """Test extracting variables from empty content."""
        content = NotificationContent(body="No variables here")

        variables = content.extract_variables()

        assert variables == []

    def test_extract_variables_complex_patterns(self):
        """Test extracting variables with complex patterns."""
        content = NotificationContent(
            body="{{user_name}} has {{item_count}} items. Total: {{total_amount}}"
        )

        variables = content.extract_variables()

        assert variables == ["item_count", "total_amount", "user_name"]

    def test_for_channel_sms_truncation(self):
        """Test content optimization for SMS channel."""
        content = NotificationContent(
            subject="Long subject that will be ignored",
            body="This is a very long SMS message that exceeds the 160 character limit and should be truncated to fit within the SMS constraints properly.",
        )

        sms_content = content.for_channel(NotificationChannel.SMS)

        assert sms_content.subject is None
        assert len(sms_content.body) == 160
        assert sms_content.body.endswith("...")  # Should be truncated

    def test_for_channel_push_truncation(self):
        """Test content optimization for push notifications."""
        content = NotificationContent(
            subject="Push notification title",
            body="This is a long push notification body that needs to be truncated to fit the push notification constraints properly and not exceed limits.",
        )

        push_content = content.for_channel(NotificationChannel.PUSH)

        assert push_content.subject == "Push notification title"
        assert len(push_content.body) <= 100

    def test_for_channel_email_preserves_all(self):
        """Test that email channel preserves all content."""
        content = NotificationContent(
            subject="Email subject",
            body="Email body",
            html_body="<p>Email HTML</p>",
            attachments=[{"filename": "doc.pdf"}],
            metadata={"type": "newsletter"},
        )

        email_content = content.for_channel(NotificationChannel.EMAIL)

        assert email_content.subject == content.subject
        assert email_content.body == content.body
        assert email_content.html_body == content.html_body
        assert email_content.attachments == content.attachments
        assert email_content.metadata == content.metadata

    def test_for_channel_in_app_removes_attachments(self):
        """Test that in-app channel removes attachments."""
        content = NotificationContent(
            subject="In-app notification",
            body="Body text",
            html_body="<p>HTML content</p>",
            attachments=[{"filename": "doc.pdf"}],
            metadata={"campaign": "promo"},
        )

        in_app_content = content.for_channel(NotificationChannel.IN_APP)

        assert in_app_content.subject == "In-app notification"
        assert in_app_content.body == "Body text"
        assert in_app_content.html_body == "<p>HTML content</p>"
        assert in_app_content.attachments == []  # Removed
        assert in_app_content.metadata == {"campaign": "promo"}

    def test_content_immutability(self):
        """Test that NotificationContent is immutable."""
        content = NotificationContent(subject="Original", body="Original body")

        # Attempting to modify should fail
        with pytest.raises(AttributeError):
            content.subject = "Modified"

    def test_string_representation_with_subject(self):
        """Test string representation when subject is present."""
        content = NotificationContent(
            subject="This is a very long subject that should be truncated",
            body="Body content",
        )

        str_repr = str(content)
        assert str_repr.startswith("Subject:")
        assert len(str_repr) <= 60  # Should be truncated

    def test_string_representation_without_subject(self):
        """Test string representation when subject is None."""
        content = NotificationContent(
            body="This is a very long body that should be truncated for display purposes"
        )

        str_repr = str(content)
        assert str_repr.startswith("Body:")
        assert len(str_repr) <= 60  # Should be truncated


class TestRecipientAddress:
    """Test suite for RecipientAddress value object."""

    def test_email_address_creation(self):
        """Test creating valid email recipient address."""
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="john.doe@example.com",
            display_name="John Doe",
        )

        assert address.channel == NotificationChannel.EMAIL
        assert address.address == "john.doe@example.com"
        assert address.display_name == "John Doe"

    def test_email_address_normalization(self):
        """Test email address normalization to lowercase."""
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL, address="JOHN.DOE@EXAMPLE.COM"
        )

        assert address.address == "john.doe@example.com"

    @pytest.mark.parametrize(
        "invalid_email",
        [
            "invalid-email",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@example",
            "",
        ],
    )
    def test_email_address_validation_fails(self, invalid_email):
        """Test invalid email addresses are rejected."""
        with pytest.raises(ValidationError, match="Invalid email address"):
            RecipientAddress(channel=NotificationChannel.EMAIL, address=invalid_email)

    def test_sms_address_creation(self):
        """Test creating valid SMS recipient address."""
        address = RecipientAddress(
            channel=NotificationChannel.SMS, address="+1234567890"
        )

        assert address.channel == NotificationChannel.SMS
        assert address.address == "+1234567890"

    def test_sms_address_normalization(self):
        """Test SMS address normalization."""
        address = RecipientAddress(
            channel=NotificationChannel.SMS, address="(123) 456-7890"
        )

        assert address.address == "+1234567890"

    def test_sms_address_adds_plus_prefix(self):
        """Test SMS address adds + prefix if missing."""
        address = RecipientAddress(
            channel=NotificationChannel.SMS, address="1234567890"
        )

        assert address.address == "+1234567890"

    @pytest.mark.parametrize(
        "invalid_phone",
        [
            "123",  # Too short
            "abc123",  # Contains letters
            "+123456789012345678",  # Too long
            "",
        ],
    )
    def test_sms_address_validation_fails(self, invalid_phone):
        """Test invalid phone numbers are rejected."""
        with pytest.raises(ValidationError, match="Invalid phone number"):
            RecipientAddress(channel=NotificationChannel.SMS, address=invalid_phone)

    def test_push_address_creation(self):
        """Test creating valid push notification address."""
        token = "device_token_abc123xyz789device_token_abc123xyz789"
        address = RecipientAddress(channel=NotificationChannel.PUSH, address=token)

        assert address.channel == NotificationChannel.PUSH
        assert address.address == token

    def test_push_address_validation_fails_short_token(self):
        """Test push address validation fails for short tokens."""
        with pytest.raises(ValidationError, match="Invalid device token"):
            RecipientAddress(channel=NotificationChannel.PUSH, address="short_token")

    def test_in_app_address_creation(self):
        """Test creating valid in-app recipient address."""
        user_id = str(uuid4())
        address = RecipientAddress(
            channel=NotificationChannel.IN_APP,
            address=user_id,
            display_name="User Name",
        )

        assert address.channel == NotificationChannel.IN_APP
        assert address.address == user_id
        assert address.display_name == "User Name"

    def test_in_app_address_validation_fails_invalid_uuid(self):
        """Test in-app address validation fails for invalid UUID."""
        with pytest.raises(
            ValidationError, match="In-app address must be a valid UUID"
        ):
            RecipientAddress(channel=NotificationChannel.IN_APP, address="not-a-uuid")

    def test_empty_address_fails(self):
        """Test that empty address fails validation."""
        with pytest.raises(ValidationError, match="Address cannot be empty"):
            RecipientAddress(channel=NotificationChannel.EMAIL, address="")

    def test_none_address_fails(self):
        """Test that None address fails validation."""
        with pytest.raises(ValidationError, match="Address cannot be empty"):
            RecipientAddress(channel=NotificationChannel.EMAIL, address=None)

    def test_display_name_trimming(self):
        """Test display name is trimmed of whitespace."""
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="test@example.com",
            display_name="  John Doe  ",
        )

        assert address.display_name == "John Doe"

    def test_string_representation_with_display_name(self):
        """Test string representation with display name."""
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="john@example.com",
            display_name="John Doe",
        )

        assert str(address) == "John Doe <john@example.com>"

    def test_string_representation_without_display_name(self):
        """Test string representation without display name."""
        address = RecipientAddress(
            channel=NotificationChannel.SMS, address="+1234567890"
        )

        assert str(address) == "+1234567890"

    def test_recipient_address_immutability(self):
        """Test that RecipientAddress is immutable."""
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL, address="test@example.com"
        )

        with pytest.raises(AttributeError):
            address.address = "modified@example.com"


class TestChannelConfig:
    """Test suite for ChannelConfig value object."""

    def test_email_config_creation(self):
        """Test creating valid email channel configuration."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            settings={"from_email": "noreply@example.com", "from_name": "Test App"},
            credentials={"api_key": "encrypted_key"},
            rate_limits={"per_second": 100},
            features=["templates", "tracking"],
        )

        assert config.channel == NotificationChannel.EMAIL
        assert config.provider == "sendgrid"
        assert config.settings["from_email"] == "noreply@example.com"
        assert "templates" in config.features

    def test_email_config_validation_missing_from_email(self):
        """Test email config validation fails without from_email."""
        with pytest.raises(
            ValidationError, match="Email config missing required setting: from_email"
        ):
            ChannelConfig(
                channel=NotificationChannel.EMAIL,
                provider="sendgrid",
                settings={"from_name": "Test App"},  # Missing from_email
            )

    def test_email_config_validation_missing_from_name(self):
        """Test email config validation fails without from_name."""
        with pytest.raises(
            ValidationError, match="Email config missing required setting: from_name"
        ):
            ChannelConfig(
                channel=NotificationChannel.EMAIL,
                provider="sendgrid",
                settings={"from_email": "noreply@example.com"},  # Missing from_name
            )

    def test_email_config_validation_invalid_from_email(self):
        """Test email config validation fails with invalid from_email."""
        with pytest.raises(ValidationError, match="Invalid from_email"):
            ChannelConfig(
                channel=NotificationChannel.EMAIL,
                provider="sendgrid",
                settings={"from_email": "invalid-email", "from_name": "Test App"},
            )

    def test_sms_config_creation(self):
        """Test creating valid SMS channel configuration."""
        config = ChannelConfig(
            channel=NotificationChannel.SMS,
            provider="twilio",
            settings={"from_number": "+1234567890"},
            credentials={"account_sid": "sid", "auth_token": "token"},
        )

        assert config.channel == NotificationChannel.SMS
        assert config.provider == "twilio"
        assert config.settings["from_number"] == "+1234567890"

    def test_sms_config_validation_missing_from_number(self):
        """Test SMS config validation fails without from_number."""
        with pytest.raises(
            ValidationError, match="SMS config missing required setting: from_number"
        ):
            ChannelConfig(
                channel=NotificationChannel.SMS,
                provider="twilio",
                settings={},  # Missing from_number
            )

    def test_push_config_creation(self):
        """Test creating valid push notification configuration."""
        config = ChannelConfig(
            channel=NotificationChannel.PUSH,
            provider="firebase",
            settings={"project_id": "test-project"},
            credentials={"private_key": "encrypted_key"},
        )

        assert config.channel == NotificationChannel.PUSH
        assert config.provider == "firebase"
        assert config.settings["project_id"] == "test-project"

    def test_push_config_validation_firebase_missing_project_id(self):
        """Test Firebase push config validation fails without project_id."""
        with pytest.raises(
            ValidationError,
            match="Firebase config missing required setting: project_id",
        ):
            ChannelConfig(
                channel=NotificationChannel.PUSH,
                provider="firebase",
                settings={},  # Missing project_id
            )

    def test_provider_name_normalization(self):
        """Test provider name is normalized to lowercase."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="SendGrid",
            settings={"from_email": "test@example.com", "from_name": "Test"},
        )

        assert config.provider == "sendgrid"

    def test_empty_provider_fails(self):
        """Test that empty provider name fails validation."""
        with pytest.raises(ValidationError, match="Provider name is required"):
            ChannelConfig(
                channel=NotificationChannel.EMAIL,
                provider="",
                settings={"from_email": "test@example.com", "from_name": "Test"},
            )

    def test_get_rate_limit(self):
        """Test getting rate limit for specific type."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            settings={"from_email": "test@example.com", "from_name": "Test"},
            rate_limits={"per_second": 100, "per_minute": 6000},
        )

        assert config.get_rate_limit("per_second") == 100
        assert config.get_rate_limit("per_minute") == 6000
        assert config.get_rate_limit("per_hour") is None

    def test_has_feature(self):
        """Test checking if feature is enabled."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            settings={"from_email": "test@example.com", "from_name": "Test"},
            features=["templates", "tracking", "webhooks"],
        )

        assert config.has_feature("templates") is True
        assert config.has_feature("tracking") is True
        assert config.has_feature("analytics") is False

    def test_string_representation(self):
        """Test string representation of channel config."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            settings={"from_email": "test@example.com", "from_name": "Test"},
        )

        assert str(config) == "email via sendgrid"

    def test_config_immutability(self):
        """Test that ChannelConfig is immutable."""
        config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            settings={"from_email": "test@example.com", "from_name": "Test"},
        )

        with pytest.raises(AttributeError):
            config.provider = "modified"


class TestNotificationPriorityValue:
    """Test suite for NotificationPriorityValue value object."""

    def test_basic_priority_creation(self):
        """Test creating basic priority value."""
        priority = NotificationPriorityValue(
            level=NotificationPriority.HIGH, reason="Critical system alert"
        )

        assert priority.level == NotificationPriority.HIGH
        assert priority.reason == "Critical system alert"
        assert priority.expires_at is None
        assert priority.escalation_rules == {}

    def test_priority_with_expiration(self):
        """Test priority with expiration time."""
        expires_at = datetime.utcnow() + timedelta(hours=1)
        priority = NotificationPriorityValue(
            level=NotificationPriority.URGENT, expires_at=expires_at
        )

        assert priority.expires_at == expires_at

    def test_priority_expiration_validation_past_time_fails(self):
        """Test that past expiration time fails validation."""
        past_time = datetime.utcnow() - timedelta(hours=1)

        with pytest.raises(
            ValidationError, match="Priority expiration must be in the future"
        ):
            NotificationPriorityValue(
                level=NotificationPriority.HIGH, expires_at=past_time
            )

    def test_priority_with_escalation_rules(self):
        """Test priority with escalation rules."""
        escalation_rules = {
            "escalate_after_minutes": 30,
            "escalate_to": NotificationPriority.URGENT.value,
        }

        priority = NotificationPriorityValue(
            level=NotificationPriority.HIGH, escalation_rules=escalation_rules
        )

        assert priority.escalation_rules == escalation_rules

    def test_should_escalate_with_rules(self):
        """Test escalation check with rules."""
        priority = NotificationPriorityValue(
            level=NotificationPriority.NORMAL,
            escalation_rules={"escalate_after_minutes": 30},
        )

        # Current implementation returns False - would need creation time for proper implementation
        result = priority.should_escalate(datetime.utcnow())
        assert result is False

    def test_should_escalate_without_rules(self):
        """Test escalation check without rules returns False."""
        priority = NotificationPriorityValue(level=NotificationPriority.NORMAL)

        result = priority.should_escalate(datetime.utcnow())
        assert result is False

    def test_get_next_level_escalation(self):
        """Test getting next priority level for escalation."""
        test_cases = [
            (NotificationPriority.LOW, NotificationPriority.NORMAL),
            (NotificationPriority.NORMAL, NotificationPriority.HIGH),
            (NotificationPriority.HIGH, NotificationPriority.URGENT),
            (NotificationPriority.URGENT, None),
        ]

        for current, expected_next in test_cases:
            priority = NotificationPriorityValue(level=current)
            assert priority.get_next_level() == expected_next

    def test_string_representation(self):
        """Test string representation of priority."""
        priority = NotificationPriorityValue(level=NotificationPriority.HIGH)
        assert str(priority) == "high priority"

    def test_priority_immutability(self):
        """Test that NotificationPriorityValue is immutable."""
        priority = NotificationPriorityValue(level=NotificationPriority.NORMAL)

        with pytest.raises(AttributeError):
            priority.level = NotificationPriority.HIGH


class TestDeliveryStatusValue:
    """Test suite for DeliveryStatusValue value object."""

    def test_basic_status_creation(self):
        """Test creating basic delivery status."""
        timestamp = datetime.utcnow()
        status = DeliveryStatusValue(
            status=DeliveryStatus.SENT,
            timestamp=timestamp,
            details="Message sent successfully",
        )

        assert status.status == DeliveryStatus.SENT
        assert status.timestamp == timestamp
        assert status.details == "Message sent successfully"
        assert status.retry_count == 0

    def test_status_with_provider_info(self):
        """Test status with provider information."""
        status = DeliveryStatusValue(
            status=DeliveryStatus.DELIVERED,
            timestamp=datetime.utcnow(),
            provider_message_id="msg_123",
            provider_status="delivered",
            retry_count=1,
        )

        assert status.provider_message_id == "msg_123"
        assert status.provider_status == "delivered"
        assert status.retry_count == 1

    def test_status_with_error_info(self):
        """Test status with error information."""
        status = DeliveryStatusValue(
            status=DeliveryStatus.FAILED,
            timestamp=datetime.utcnow(),
            details="SMTP server timeout",
            error_code="SMTP_TIMEOUT",
            retry_count=2,
        )

        assert status.error_code == "SMTP_TIMEOUT"
        assert status.details == "SMTP server timeout"
        assert status.retry_count == 2

    def test_retry_count_validation_negative_fails(self):
        """Test that negative retry count fails validation."""
        with pytest.raises(ValidationError, match="Retry count cannot be negative"):
            DeliveryStatusValue(
                status=DeliveryStatus.FAILED,
                timestamp=datetime.utcnow(),
                retry_count=-1,
            )

    def test_retry_count_validation_excessive_fails(self):
        """Test that excessive retry count fails validation."""
        with pytest.raises(ValidationError, match="Retry count exceeds maximum limit"):
            DeliveryStatusValue(
                status=DeliveryStatus.FAILED,
                timestamp=datetime.utcnow(),
                retry_count=101,
            )

    def test_can_retry_with_retryable_status(self):
        """Test can_retry with retryable status."""
        status = DeliveryStatusValue(
            status=DeliveryStatus.FAILED, timestamp=datetime.utcnow(), retry_count=2
        )

        assert status.can_retry(max_retries=5) is True
        assert status.can_retry(max_retries=2) is False
        assert status.can_retry(max_retries=1) is False

    def test_can_retry_with_non_retryable_status(self):
        """Test can_retry with non-retryable status."""
        status = DeliveryStatusValue(
            status=DeliveryStatus.DELIVERED, timestamp=datetime.utcnow(), retry_count=0
        )

        assert status.can_retry(max_retries=5) is False

    def test_with_retry_creates_new_status(self):
        """Test creating new status for retry attempt."""
        original = DeliveryStatusValue(
            status=DeliveryStatus.FAILED, timestamp=datetime.utcnow(), retry_count=1
        )

        retry_status = original.with_retry()

        assert retry_status.status == DeliveryStatus.QUEUED
        assert retry_status.retry_count == 2
        assert "Retry attempt 2" in retry_status.details
        assert retry_status.timestamp > original.timestamp

    def test_string_representation(self):
        """Test string representation of delivery status."""
        timestamp = datetime.utcnow()
        status = DeliveryStatusValue(status=DeliveryStatus.SENT, timestamp=timestamp)

        expected = f"sent at {timestamp.isoformat()}"
        assert str(status) == expected

    def test_status_immutability(self):
        """Test that DeliveryStatusValue is immutable."""
        status = DeliveryStatusValue(
            status=DeliveryStatus.SENT, timestamp=datetime.utcnow()
        )

        with pytest.raises(AttributeError):
            status.status = DeliveryStatus.DELIVERED


class TestTemplateVariable:
    """Test suite for TemplateVariable value object."""

    def test_basic_variable_creation(self):
        """Test creating basic template variable."""
        variable = TemplateVariable(
            name="user_name",
            var_type=VariableType.STRING,
            required=True,
            description="User's full name",
        )

        assert variable.name == "user_name"
        assert variable.var_type == VariableType.STRING
        assert variable.required is True
        assert variable.description == "User's full name"
        assert variable.default_value is None

    def test_variable_with_default_value(self):
        """Test variable with default value."""
        variable = TemplateVariable(
            name="discount",
            var_type=VariableType.CURRENCY,
            required=False,
            default_value=0.0,
            description="Discount amount",
        )

        assert variable.default_value == 0.0
        assert variable.required is False

    def test_variable_with_validation_rules(self):
        """Test variable with validation rules."""
        validation_rules = {
            "min_length": 6,
            "max_length": 20,
            "pattern": r"^[A-Za-z0-9]+$",
        }

        variable = TemplateVariable(
            name="username",
            var_type=VariableType.STRING,
            validation_rules=validation_rules,
        )

        assert variable.validation_rules == validation_rules

    def test_variable_with_format_pattern(self):
        """Test variable with format pattern."""
        variable = TemplateVariable(
            name="amount", var_type=VariableType.CURRENCY, format_pattern="${:.2f}"
        )

        assert variable.format_pattern == "${:.2f}"

    def test_variable_name_validation_empty_fails(self):
        """Test that empty variable name fails validation."""
        with pytest.raises(ValidationError):
            TemplateVariable(name="", var_type=VariableType.STRING)

    def test_variable_name_validation_invalid_format_fails(self):
        """Test that invalid variable name format fails validation."""
        invalid_names = ["123invalid", "user-name", "user name", "user.name"]

        for invalid_name in invalid_names:
            with pytest.raises(ValidationError, match="Invalid variable name"):
                TemplateVariable(name=invalid_name, var_type=VariableType.STRING)

    def test_variable_name_validation_valid_formats(self):
        """Test valid variable name formats."""
        valid_names = ["user_name", "userName", "USER_NAME", "user123", "name1"]

        for valid_name in valid_names:
            variable = TemplateVariable(name=valid_name, var_type=VariableType.STRING)
            assert variable.name == valid_name

    def test_default_value_type_validation_fails(self):
        """Test that default value type mismatch fails validation."""
        with pytest.raises(ValidationError, match="Default value does not match type"):
            TemplateVariable(
                name="count", var_type=VariableType.NUMBER, default_value="not a number"
            )

    @pytest.mark.parametrize(
        ("var_type", "valid_values", "invalid_values"),
        [
            (VariableType.STRING, ["hello", "world"], [123, True, None]),
            (VariableType.NUMBER, [123, 45.67, 0], ["string", True, None]),
            (VariableType.BOOLEAN, [True, False], ["true", 1, None]),
            (
                VariableType.URL,
                ["https://example.com", "http://test.org"],
                ["not_url", "ftp://invalid", None],
            ),
            (
                VariableType.EMAIL,
                ["test@example.com", "user@domain.org"],
                ["invalid_email", "@domain.com", None],
            ),
            (VariableType.CURRENCY, [19.99, 100.0, 0.01], ["not_currency", True, None]),
        ],
    )
    def test_validate_value_type_checking(self, var_type, valid_values, invalid_values):
        """Test value validation for different variable types."""
        variable = TemplateVariable(name="test_var", var_type=var_type, required=True)

        # Test valid values
        for valid_value in valid_values:
            assert variable.validate_value(valid_value) is True

        # Test invalid values
        for invalid_value in invalid_values:
            assert variable.validate_value(invalid_value) is False

    def test_validate_value_required_field(self):
        """Test validation of required vs optional fields."""
        required_var = TemplateVariable(
            name="required_field", var_type=VariableType.STRING, required=True
        )

        optional_var = TemplateVariable(
            name="optional_field", var_type=VariableType.STRING, required=False
        )

        optional_with_default = TemplateVariable(
            name="optional_with_default",
            var_type=VariableType.STRING,
            required=True,
            default_value="default",
        )

        # None value tests
        assert required_var.validate_value(None) is False
        assert optional_var.validate_value(None) is True
        assert optional_with_default.validate_value(None) is True

    def test_validate_value_with_validation_rules(self):
        """Test validation with custom validation rules."""
        variable = TemplateVariable(
            name="code",
            var_type=VariableType.STRING,
            validation_rules={"min_length": 6, "max_length": 10, "pattern": r"^\d+$"},
        )

        # Valid values
        assert variable.validate_value("123456") is True
        assert variable.validate_value("1234567890") is True

        # Invalid values
        assert variable.validate_value("12345") is False  # Too short
        assert variable.validate_value("12345678901") is False  # Too long
        assert variable.validate_value("abc123") is False  # Invalid pattern

    def test_validate_value_numeric_range_rules(self):
        """Test validation with numeric range rules."""
        variable = TemplateVariable(
            name="rating",
            var_type=VariableType.NUMBER,
            validation_rules={"min_value": 1, "max_value": 5},
        )

        # Valid values
        assert variable.validate_value(1) is True
        assert variable.validate_value(3.5) is True
        assert variable.validate_value(5) is True

        # Invalid values
        assert variable.validate_value(0) is False  # Too low
        assert variable.validate_value(6) is False  # Too high

    def test_format_value_with_default(self):
        """Test value formatting with default value."""
        variable = TemplateVariable(
            name="greeting", var_type=VariableType.STRING, default_value="Hello"
        )

        assert variable.format_value(None) == "Hello"
        assert variable.format_value("Hi") == "Hi"

    def test_format_value_with_custom_pattern(self):
        """Test value formatting with custom format pattern."""
        variable = TemplateVariable(
            name="discount",
            var_type=VariableType.CURRENCY,
            format_pattern="Discount: ${:.2f}",
        )

        assert variable.format_value(25.5) == "Discount: $25.50"

    def test_format_value_currency_default(self):
        """Test default currency formatting."""
        variable = TemplateVariable(name="price", var_type=VariableType.CURRENCY)

        assert variable.format_value(1234.56) == "$1,234.56"
        assert variable.format_value(0) == "$0.00"

    def test_format_value_date_default(self):
        """Test default date formatting."""
        variable = TemplateVariable(name="date", var_type=VariableType.DATE)

        assert variable.format_value("2023-12-25T12:00:00Z") == "2023-12-25"
        assert variable.format_value("2023-12-25") == "2023-12-25"

    def test_format_value_datetime_default(self):
        """Test default datetime formatting."""
        variable = TemplateVariable(name="timestamp", var_type=VariableType.DATETIME)

        result = variable.format_value("2023-12-25T12:00:00Z")
        assert result == "2023-12-25 12:00:00 UTC"

    def test_format_value_fallback_to_string(self):
        """Test formatting falls back to string conversion."""
        variable = TemplateVariable(name="generic", var_type=VariableType.STRING)

        assert variable.format_value(123) == "123"
        assert variable.format_value(True) == "True"

    def test_string_representation(self):
        """Test string representation of template variable."""
        variable = TemplateVariable(name="user_name", var_type=VariableType.STRING)

        assert str(variable) == "user_name (string)"

    def test_variable_immutability(self):
        """Test that TemplateVariable is immutable."""
        variable = TemplateVariable(name="test_var", var_type=VariableType.STRING)

        with pytest.raises(AttributeError):
            variable.name = "modified"
