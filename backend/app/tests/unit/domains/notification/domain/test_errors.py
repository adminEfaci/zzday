"""Comprehensive tests for notification domain errors.

This module provides complete test coverage for all custom exception classes
in the notification domain, including error handling, error contexts, and
proper error inheritance.
"""

from uuid import uuid4

import pytest

from app.modules.notification.domain.errors import (
    BatchProcessingError,
    ChannelNotConfiguredError,
    DeliveryFailedError,
    DuplicateNotificationError,
    InvalidChannelError,
    InvalidPriorityError,
    InvalidTemplateError,
    NotificationError,
    NotificationExpiredError,
    NotificationNotFoundError,
    RateLimitExceededError,
    RecipientBlockedError,
    RecipientNotFoundError,
    ScheduleError,
    TemplateNotFoundError,
    TemplateRenderError,
    TemplateVariableError,
)


class TestNotificationError:
    """Test suite for base NotificationError."""

    def test_basic_error_creation(self):
        """Test creating basic notification domain error."""
        error = NotificationError("Test error message")

        assert str(error) == "Test error message"
        assert error.default_code == "NOTIFICATION_ERROR"

    def test_error_inheritance(self):
        """Test that domain error inherits from Exception."""
        error = NotificationError("Test")

        assert isinstance(error, Exception)
        assert isinstance(error, NotificationError)


class TestNotificationNotFoundError:
    """Test suite for NotificationNotFoundError."""

    def test_notification_not_found_error(self):
        """Test notification not found error creation."""
        notification_id = uuid4()
        error = NotificationNotFoundError(notification_id)

        assert "Notification" in str(error)
        assert str(notification_id) in str(error)


class TestTemplateNotFoundError:
    """Test suite for TemplateNotFoundError."""

    def test_template_not_found_error(self):
        """Test template not found error creation."""
        template_id = uuid4()
        error = TemplateNotFoundError(template_id)

        assert "NotificationTemplate" in str(error) or "Template" in str(error)
        assert str(template_id) in str(error)


class TestInvalidTemplateError:
    """Test suite for InvalidTemplateError."""

    def test_invalid_template_error_with_id(self):
        """Test invalid template error with template ID."""
        template_id = uuid4()
        error = InvalidTemplateError(
            template_id=template_id, reason="Missing required field"
        )

        assert error.default_code == "INVALID_TEMPLATE"
        assert "Invalid template" in str(error)
        assert "Missing required field" in str(error)
        assert error.details["template_id"] == str(template_id)
        assert error.details["reason"] == "Missing required field"

    def test_invalid_template_error_with_name(self):
        """Test invalid template error with template name."""
        error = InvalidTemplateError(
            template_name="Welcome Email", reason="Invalid syntax"
        )

        assert "Welcome Email" in str(error)
        assert "Invalid syntax" in str(error)
        assert error.details["template_name"] == "Welcome Email"

    def test_invalid_template_error_minimal(self):
        """Test invalid template error with minimal info."""
        error = InvalidTemplateError()

        assert "Template validation failed" in str(error)
        assert error.details["reason"] == "Template validation failed"


class TestDeliveryFailedError:
    """Test suite for DeliveryFailedError."""

    def test_delivery_failed_error_creation(self):
        """Test delivery failed error creation."""
        notification_id = uuid4()
        error = DeliveryFailedError(
            notification_id=notification_id,
            channel="email",
            reason="SMTP server unavailable",
            provider_error="Connection timeout",
            is_permanent=False,
        )

        assert error.default_code == "DELIVERY_FAILED"
        assert str(notification_id) in str(error)
        assert "email" in str(error)
        assert "SMTP server unavailable" in str(error)
        assert error.details["notification_id"] == str(notification_id)
        assert error.details["channel"] == "email"
        assert error.details["provider_error"] == "Connection timeout"
        assert error.details["is_permanent"] is False
        assert error.retryable is True

    def test_delivery_failed_permanent_error(self):
        """Test permanent delivery failure."""
        notification_id = uuid4()
        error = DeliveryFailedError(
            notification_id=notification_id,
            channel="email",
            reason="Invalid recipient address",
            is_permanent=True,
        )

        assert error.details["is_permanent"] is True
        assert error.retryable is False

    def test_delivery_failed_user_message(self):
        """Test delivery failed error includes user message."""
        notification_id = uuid4()
        error = DeliveryFailedError(
            notification_id=notification_id, channel="sms", reason="Network error"
        )

        assert hasattr(error, "user_message")
        assert "Failed to send notification" in error.user_message


class TestChannelNotConfiguredError:
    """Test suite for ChannelNotConfiguredError."""

    def test_channel_not_configured_error(self):
        """Test channel not configured error."""
        error = ChannelNotConfiguredError(
            channel="sms", reason="Missing API credentials"
        )

        assert error.default_code == "CHANNEL_NOT_CONFIGURED"
        assert "sms" in str(error)
        assert "Missing API credentials" in str(error)
        assert error.details["channel"] == "sms"
        assert error.details["reason"] == "Missing API credentials"

    def test_channel_not_configured_without_reason(self):
        """Test channel not configured error without reason."""
        error = ChannelNotConfiguredError(channel="push")

        assert "push" in str(error)
        assert error.details["reason"] is None


class TestRecipientNotFoundError:
    """Test suite for RecipientNotFoundError."""

    def test_recipient_not_found_with_id(self):
        """Test recipient not found with ID."""
        recipient_id = uuid4()
        error = RecipientNotFoundError(recipient_id=recipient_id)

        assert "Recipient" in str(error)
        assert str(recipient_id) in str(error)

    def test_recipient_not_found_with_address(self):
        """Test recipient not found with address."""
        error = RecipientNotFoundError(recipient_address="test@example.com")

        assert "Recipient" in str(error)
        assert "test@example.com" in str(error)


class TestRecipientBlockedError:
    """Test suite for RecipientBlockedError."""

    def test_recipient_blocked_error(self):
        """Test recipient blocked error creation."""
        recipient_id = uuid4()
        error = RecipientBlockedError(
            recipient_id=recipient_id,
            recipient_address="blocked@example.com",
            block_reason="Hard bounce",
        )

        assert error.default_code == "RECIPIENT_BLOCKED"
        assert "blocked@example.com" in str(error)
        assert "Hard bounce" in str(error)
        assert error.details["recipient_id"] == str(recipient_id)
        assert error.details["recipient_address"] == "blocked@example.com"
        assert error.details["block_reason"] == "Hard bounce"


class TestTemplateVariableError:
    """Test suite for TemplateVariableError."""

    def test_template_variable_error_missing_only(self):
        """Test template variable error with missing variables."""
        template_id = uuid4()
        missing_vars = ["user_name", "order_id"]

        error = TemplateVariableError(
            template_id=template_id, missing_variables=missing_vars
        )

        assert error.default_code == "TEMPLATE_VARIABLE_ERROR"
        assert "Missing variables" in str(error)
        assert "user_name" in str(error)
        assert "order_id" in str(error)
        assert error.details["missing_variables"] == missing_vars
        assert error.details["invalid_variables"] is None

    def test_template_variable_error_invalid_only(self):
        """Test template variable error with invalid variables."""
        template_id = uuid4()
        invalid_vars = {"email": "Invalid format", "age": "Must be numeric"}

        error = TemplateVariableError(
            template_id=template_id, invalid_variables=invalid_vars
        )

        assert "Invalid variables" in str(error)
        assert "email: Invalid format" in str(error)
        assert error.details["invalid_variables"] == invalid_vars
        assert error.details["missing_variables"] is None

    def test_template_variable_error_both(self):
        """Test template variable error with both missing and invalid."""
        template_id = uuid4()
        missing_vars = ["name"]
        invalid_vars = {"age": "Invalid"}

        error = TemplateVariableError(
            template_id=template_id,
            missing_variables=missing_vars,
            invalid_variables=invalid_vars,
        )

        error_str = str(error)
        assert "Missing variables" in error_str
        assert "Invalid variables" in error_str
        assert error.details["missing_variables"] == missing_vars
        assert error.details["invalid_variables"] == invalid_vars


class TestBatchProcessingError:
    """Test suite for BatchProcessingError."""

    def test_batch_processing_error(self):
        """Test batch processing error creation."""
        batch_id = uuid4()
        error = BatchProcessingError(
            batch_id=batch_id,
            total_notifications=100,
            failed_count=5,
            reason="Provider rate limit exceeded",
        )

        assert error.default_code == "BATCH_PROCESSING_ERROR"
        assert str(batch_id) in str(error)
        assert "5/100" in str(error)
        assert "Provider rate limit exceeded" in str(error)
        assert error.details["batch_id"] == str(batch_id)
        assert error.details["total_notifications"] == 100
        assert error.details["failed_count"] == 5
        assert error.details["success_count"] == 95
        assert error.details["reason"] == "Provider rate limit exceeded"


class TestScheduleError:
    """Test suite for ScheduleError."""

    def test_schedule_error_with_id(self):
        """Test schedule error with schedule ID."""
        schedule_id = uuid4()
        error = ScheduleError(schedule_id=schedule_id, reason="Invalid schedule time")

        assert error.default_code == "SCHEDULE_ERROR"
        assert str(schedule_id) in str(error)
        assert "Invalid schedule time" in str(error)
        assert error.details["schedule_id"] == str(schedule_id)
        assert error.details["reason"] == "Invalid schedule time"

    def test_schedule_error_without_id(self):
        """Test schedule error without schedule ID."""
        error = ScheduleError(reason="Scheduling conflict")

        assert "Notification scheduling error" in str(error)
        assert "Scheduling conflict" in str(error)
        assert error.details["schedule_id"] is None


class TestRateLimitExceededError:
    """Test suite for RateLimitExceededError."""

    def test_rate_limit_exceeded_error(self):
        """Test rate limit exceeded error creation."""
        error = RateLimitExceededError(
            channel="email", limit=100, window="minute", retry_after=60
        )

        assert error.default_code == "RATE_LIMIT_EXCEEDED"
        assert "Rate limit exceeded for email" in str(error)
        assert "100 per minute" in str(error)
        assert error.details["channel"] == "email"
        assert error.details["limit"] == 100
        assert error.details["window"] == "minute"
        assert error.details["retry_after"] == 60
        assert error.retryable is True

    def test_rate_limit_exceeded_without_retry_after(self):
        """Test rate limit exceeded without retry_after."""
        error = RateLimitExceededError(channel="sms", limit=10, window="second")

        assert error.details["retry_after"] is None
        assert "Wait 60 seconds" in error.recovery_hint


class TestDuplicateNotificationError:
    """Test suite for DuplicateNotificationError."""

    def test_duplicate_notification_error(self):
        """Test duplicate notification error creation."""
        existing_id = uuid4()
        error = DuplicateNotificationError(
            idempotency_key="unique-key-123", existing_notification_id=existing_id
        )

        assert error.default_code == "DUPLICATE_NOTIFICATION"
        assert "unique-key-123" in str(error)
        assert "already exists" in str(error)
        assert error.details["idempotency_key"] == "unique-key-123"
        assert error.details["existing_notification_id"] == str(existing_id)


class TestInvalidChannelError:
    """Test suite for InvalidChannelError."""

    def test_invalid_channel_error(self):
        """Test invalid channel error creation."""
        error = InvalidChannelError(
            channel="webhook", available_channels=["email", "sms", "push", "in_app"]
        )

        assert error.default_code == "INVALID_CHANNEL"
        assert "webhook" in str(error)
        assert "email, sms, push, in_app" in str(error)
        assert error.details["invalid_channel"] == "webhook"
        assert error.details["available_channels"] == ["email", "sms", "push", "in_app"]


class TestTemplateRenderError:
    """Test suite for TemplateRenderError."""

    def test_template_render_error(self):
        """Test template render error creation."""
        template_id = uuid4()
        error = TemplateRenderError(
            template_id=template_id, render_error="Undefined variable 'missing_var'"
        )

        assert error.default_code == "TEMPLATE_RENDER_ERROR"
        assert "Failed to render template" in str(error)
        assert "Undefined variable 'missing_var'" in str(error)
        assert error.details["template_id"] == str(template_id)
        assert error.details["render_error"] == "Undefined variable 'missing_var'"


class TestInvalidPriorityError:
    """Test suite for InvalidPriorityError."""

    def test_invalid_priority_error(self):
        """Test invalid priority error creation."""
        error = InvalidPriorityError(
            priority="super_urgent",
            valid_priorities=["low", "normal", "high", "urgent"],
        )

        assert error.default_code == "INVALID_PRIORITY"
        assert "super_urgent" in str(error)
        assert "low, normal, high, urgent" in str(error)
        assert error.details["invalid_priority"] == "super_urgent"
        assert error.details["valid_priorities"] == ["low", "normal", "high", "urgent"]


class TestNotificationExpiredError:
    """Test suite for NotificationExpiredError."""

    def test_notification_expired_error(self):
        """Test notification expired error creation."""
        notification_id = uuid4()
        expired_at = "2023-12-25T12:00:00Z"

        error = NotificationExpiredError(
            notification_id=notification_id, expired_at=expired_at
        )

        assert error.default_code == "NOTIFICATION_EXPIRED"
        assert str(notification_id) in str(error)
        assert expired_at in str(error)
        assert "has expired" in str(error)
        assert error.details["notification_id"] == str(notification_id)
        assert error.details["expired_at"] == expired_at


class TestErrorInheritance:
    """Test suite for error class inheritance."""

    def test_all_errors_inherit_from_base(self):
        """Test that all domain errors inherit from NotificationError."""
        base_error_classes = [
            InvalidTemplateError,
            DeliveryFailedError,
            ChannelNotConfiguredError,
            RecipientBlockedError,
            TemplateVariableError,
            BatchProcessingError,
            ScheduleError,
            RateLimitExceededError,
            DuplicateNotificationError,
            InvalidChannelError,
            TemplateRenderError,
            InvalidPriorityError,
            NotificationExpiredError,
        ]

        for error_class in base_error_classes:
            if error_class == TemplateVariableError:
                # TemplateVariableError inherits from InvalidTemplateError
                error = error_class(template_id=uuid4())
            elif error_class == TemplateRenderError:
                # TemplateRenderError inherits from InvalidTemplateError
                error = error_class(template_id=uuid4(), render_error="Test")
            elif error_class == DeliveryFailedError:
                error = error_class(
                    notification_id=uuid4(), channel="email", reason="Test"
                )
            elif error_class == RecipientBlockedError:
                error = error_class(
                    recipient_id=uuid4(),
                    recipient_address="test@example.com",
                    block_reason="Test",
                )
            elif error_class == BatchProcessingError:
                error = error_class(
                    batch_id=uuid4(),
                    total_notifications=10,
                    failed_count=1,
                    reason="Test",
                )
            elif error_class == RateLimitExceededError:
                error = error_class(channel="email", limit=100, window="minute")
            elif error_class == DuplicateNotificationError:
                error = error_class(
                    idempotency_key="test", existing_notification_id=uuid4()
                )
            elif error_class == InvalidChannelError:
                error = error_class(channel="invalid", available_channels=["email"])
            elif error_class == InvalidPriorityError:
                error = error_class(priority="invalid", valid_priorities=["normal"])
            elif error_class == NotificationExpiredError:
                error = error_class(
                    notification_id=uuid4(), expired_at="2023-12-25T12:00:00Z"
                )
            else:
                error = error_class("Test message")

            assert isinstance(error, NotificationError)
            assert isinstance(error, Exception)

    def test_not_found_errors_inheritance(self):
        """Test that NotFound errors inherit properly."""
        # These inherit from NotFoundError, not NotificationError directly
        not_found_classes = [
            NotificationNotFoundError,
            TemplateNotFoundError,
            RecipientNotFoundError,
        ]

        for error_class in not_found_classes:
            if error_class == RecipientNotFoundError:
                error = error_class(recipient_id=uuid4())
            else:
                error = error_class(uuid4())

            assert isinstance(error, Exception)

    def test_all_errors_are_exceptions(self):
        """Test that all errors can be raised and caught."""
        error_classes = [
            NotificationError,
            NotificationNotFoundError,
            TemplateNotFoundError,
            InvalidTemplateError,
            DeliveryFailedError,
            ChannelNotConfiguredError,
            RecipientNotFoundError,
            RecipientBlockedError,
            TemplateVariableError,
            BatchProcessingError,
            ScheduleError,
            RateLimitExceededError,
            DuplicateNotificationError,
            InvalidChannelError,
            TemplateRenderError,
            InvalidPriorityError,
            NotificationExpiredError,
        ]

        for error_class in error_classes:
            # Test that errors can be raised and caught
            with pytest.raises(error_class):
                if error_class in [NotificationNotFoundError, TemplateNotFoundError]:
                    raise error_class(uuid4())
                if error_class == RecipientNotFoundError:
                    raise error_class(recipient_id=uuid4())
                if error_class == InvalidTemplateError:
                    raise error_class()
                if error_class == DeliveryFailedError:
                    raise error_class(
                        notification_id=uuid4(), channel="email", reason="Test"
                    )
                if error_class == RecipientBlockedError:
                    raise error_class(
                        recipient_id=uuid4(),
                        recipient_address="test@example.com",
                        block_reason="Test",
                    )
                if error_class == TemplateVariableError:
                    raise error_class(template_id=uuid4())
                if error_class == BatchProcessingError:
                    raise error_class(
                        batch_id=uuid4(),
                        total_notifications=10,
                        failed_count=1,
                        reason="Test",
                    )
                if error_class == RateLimitExceededError:
                    raise error_class(channel="email", limit=100, window="minute")
                if error_class == DuplicateNotificationError:
                    raise error_class(
                        idempotency_key="test", existing_notification_id=uuid4()
                    )
                if error_class == InvalidChannelError:
                    raise error_class(channel="invalid", available_channels=["email"])
                if error_class == TemplateRenderError:
                    raise error_class(template_id=uuid4(), render_error="Test")
                if error_class == InvalidPriorityError:
                    raise error_class(priority="invalid", valid_priorities=["normal"])
                if error_class == NotificationExpiredError:
                    raise error_class(
                        notification_id=uuid4(), expired_at="2023-12-25T12:00:00Z"
                    )
                raise error_class("Test error")

            # Test that they can be caught as base exception
            with pytest.raises(Exception):
                if error_class in [NotificationNotFoundError, TemplateNotFoundError]:
                    raise error_class(uuid4())
                if error_class == RecipientNotFoundError:
                    raise error_class(recipient_id=uuid4())
                if error_class == InvalidTemplateError:
                    raise error_class()
                if error_class == DeliveryFailedError:
                    raise error_class(
                        notification_id=uuid4(), channel="email", reason="Test"
                    )
                if error_class == RecipientBlockedError:
                    raise error_class(
                        recipient_id=uuid4(),
                        recipient_address="test@example.com",
                        block_reason="Test",
                    )
                if error_class == TemplateVariableError:
                    raise error_class(template_id=uuid4())
                if error_class == BatchProcessingError:
                    raise error_class(
                        batch_id=uuid4(),
                        total_notifications=10,
                        failed_count=1,
                        reason="Test",
                    )
                if error_class == RateLimitExceededError:
                    raise error_class(channel="email", limit=100, window="minute")
                if error_class == DuplicateNotificationError:
                    raise error_class(
                        idempotency_key="test", existing_notification_id=uuid4()
                    )
                if error_class == InvalidChannelError:
                    raise error_class(channel="invalid", available_channels=["email"])
                if error_class == TemplateRenderError:
                    raise error_class(template_id=uuid4(), render_error="Test")
                if error_class == InvalidPriorityError:
                    raise error_class(priority="invalid", valid_priorities=["normal"])
                if error_class == NotificationExpiredError:
                    raise error_class(
                        notification_id=uuid4(), expired_at="2023-12-25T12:00:00Z"
                    )
                raise error_class("Test error")


class TestErrorDetails:
    """Test suite for error details and context."""

    def test_error_details_accessibility(self):
        """Test that error details are accessible."""
        template_id = uuid4()
        error = InvalidTemplateError(
            template_id=template_id,
            template_name="Test Template",
            reason="Invalid structure",
        )

        assert hasattr(error, "details")
        assert error.details["template_id"] == str(template_id)
        assert error.details["template_name"] == "Test Template"
        assert error.details["reason"] == "Invalid structure"

    def test_user_messages_and_recovery_hints(self):
        """Test that errors provide user messages and recovery hints."""
        # Test delivery error
        delivery_error = DeliveryFailedError(
            notification_id=uuid4(), channel="email", reason="SMTP error"
        )

        assert hasattr(delivery_error, "user_message")
        assert hasattr(delivery_error, "recovery_hint")
        assert "Failed to send notification" in delivery_error.user_message

        # Test rate limit error
        rate_limit_error = RateLimitExceededError(
            channel="sms", limit=10, window="minute"
        )

        assert "Too many notifications" in rate_limit_error.user_message
        assert "Wait" in rate_limit_error.recovery_hint
