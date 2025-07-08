"""Comprehensive tests for notification domain enums.

This module provides complete test coverage for all notification domain enums
including channel capabilities, priority processing, status transitions,
template types, and variable validation.
"""

import pytest

from app.modules.notification.domain.enums import (
    BatchStatus,
    ChannelStatus,
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    RecipientStatus,
    ScheduleStatus,
    TemplateType,
    VariableType,
)


class TestNotificationChannel:
    """Test suite for NotificationChannel enum."""

    def test_all_channels_exist(self):
        """Test that all expected channels are defined."""
        expected_channels = ["email", "sms", "push", "in_app"]
        actual_channels = [channel.value for channel in NotificationChannel]

        for expected in expected_channels:
            assert expected in actual_channels

    def test_is_external_channels(self):
        """Test external channel identification."""
        external_channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
        ]

        for channel in external_channels:
            assert channel.is_external() is True

        # In-app should not be external
        assert NotificationChannel.IN_APP.is_external() is False

    def test_requires_address_channels(self):
        """Test channels that require recipient address."""
        address_required_channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
        ]

        for channel in address_required_channels:
            assert channel.requires_address() is True

        # In-app may not require traditional address
        assert NotificationChannel.IN_APP.requires_address() is False

    def test_supports_rich_content_channels(self):
        """Test channels that support rich HTML content."""
        rich_content_channels = [NotificationChannel.EMAIL, NotificationChannel.IN_APP]

        for channel in rich_content_channels:
            assert channel.supports_rich_content() is True

        # SMS and Push don't support rich content
        assert NotificationChannel.SMS.supports_rich_content() is False
        assert NotificationChannel.PUSH.supports_rich_content() is False

    def test_supports_attachments_channels(self):
        """Test channels that support file attachments."""
        # Only email supports attachments
        assert NotificationChannel.EMAIL.supports_attachments() is True

        # All other channels don't support attachments
        other_channels = [
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
            NotificationChannel.IN_APP,
        ]

        for channel in other_channels:
            assert channel.supports_attachments() is False

    def test_max_content_length_constraints(self):
        """Test maximum content length for each channel."""
        content_limits = {
            NotificationChannel.SMS: 160,
            NotificationChannel.PUSH: 256,
            NotificationChannel.EMAIL: 100000,
            NotificationChannel.IN_APP: 100000,
        }

        for channel, expected_limit in content_limits.items():
            assert channel.max_content_length() == expected_limit


class TestNotificationPriority:
    """Test suite for NotificationPriority enum."""

    def test_all_priorities_exist(self):
        """Test that all expected priorities are defined."""
        expected_priorities = ["low", "normal", "high", "urgent"]
        actual_priorities = [priority.value for priority in NotificationPriority]

        for expected in expected_priorities:
            assert expected in actual_priorities

    def test_processing_weight_ordering(self):
        """Test that processing weights are properly ordered."""
        weights = {
            NotificationPriority.LOW: 1,
            NotificationPriority.NORMAL: 5,
            NotificationPriority.HIGH: 10,
            NotificationPriority.URGENT: 100,
        }

        for priority, expected_weight in weights.items():
            assert priority.processing_weight() == expected_weight

        # Verify ordering is correct
        assert (
            NotificationPriority.LOW.processing_weight()
            < NotificationPriority.NORMAL.processing_weight()
        )
        assert (
            NotificationPriority.NORMAL.processing_weight()
            < NotificationPriority.HIGH.processing_weight()
        )
        assert (
            NotificationPriority.HIGH.processing_weight()
            < NotificationPriority.URGENT.processing_weight()
        )

    def test_max_retry_attempts(self):
        """Test maximum retry attempts for each priority."""
        retry_attempts = {
            NotificationPriority.LOW: 1,
            NotificationPriority.NORMAL: 3,
            NotificationPriority.HIGH: 5,
            NotificationPriority.URGENT: 10,
        }

        for priority, expected_attempts in retry_attempts.items():
            assert priority.max_retry_attempts() == expected_attempts

    def test_retry_delay_seconds(self):
        """Test retry delay intervals for each priority."""
        retry_delays = {
            NotificationPriority.LOW: 3600,  # 1 hour
            NotificationPriority.NORMAL: 900,  # 15 minutes
            NotificationPriority.HIGH: 300,  # 5 minutes
            NotificationPriority.URGENT: 60,  # 1 minute
        }

        for priority, expected_delay in retry_delays.items():
            assert priority.retry_delay_seconds() == expected_delay

        # Verify higher priority has shorter delays
        assert (
            NotificationPriority.URGENT.retry_delay_seconds()
            < NotificationPriority.HIGH.retry_delay_seconds()
        )
        assert (
            NotificationPriority.HIGH.retry_delay_seconds()
            < NotificationPriority.NORMAL.retry_delay_seconds()
        )
        assert (
            NotificationPriority.NORMAL.retry_delay_seconds()
            < NotificationPriority.LOW.retry_delay_seconds()
        )


class TestDeliveryStatus:
    """Test suite for DeliveryStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses are defined."""
        expected_statuses = [
            "pending",
            "queued",
            "sending",
            "sent",
            "delivered",
            "failed",
            "bounced",
            "read",
            "cancelled",
        ]
        actual_statuses = [status.value for status in DeliveryStatus]

        for expected in expected_statuses:
            assert expected in actual_statuses

    def test_is_final_statuses(self):
        """Test identification of final statuses."""
        final_statuses = [
            DeliveryStatus.DELIVERED,
            DeliveryStatus.FAILED,
            DeliveryStatus.BOUNCED,
            DeliveryStatus.READ,
            DeliveryStatus.CANCELLED,
        ]

        for status in final_statuses:
            assert status.is_final() is True

        # Non-final statuses
        non_final_statuses = [
            DeliveryStatus.PENDING,
            DeliveryStatus.QUEUED,
            DeliveryStatus.SENDING,
            DeliveryStatus.SENT,
        ]

        for status in non_final_statuses:
            assert status.is_final() is False

    def test_is_successful_statuses(self):
        """Test identification of successful statuses."""
        successful_statuses = [DeliveryStatus.DELIVERED, DeliveryStatus.READ]

        for status in successful_statuses:
            assert status.is_successful() is True

        # Non-successful statuses
        non_successful_statuses = [
            DeliveryStatus.PENDING,
            DeliveryStatus.QUEUED,
            DeliveryStatus.SENDING,
            DeliveryStatus.SENT,
            DeliveryStatus.FAILED,
            DeliveryStatus.BOUNCED,
            DeliveryStatus.CANCELLED,
        ]

        for status in non_successful_statuses:
            assert status.is_successful() is False

    def test_is_retryable_statuses(self):
        """Test identification of retryable statuses."""
        retryable_statuses = [DeliveryStatus.FAILED, DeliveryStatus.BOUNCED]

        for status in retryable_statuses:
            assert status.is_retryable() is True

        # Non-retryable statuses
        non_retryable_statuses = [
            DeliveryStatus.PENDING,
            DeliveryStatus.QUEUED,
            DeliveryStatus.SENDING,
            DeliveryStatus.SENT,
            DeliveryStatus.DELIVERED,
            DeliveryStatus.READ,
            DeliveryStatus.CANCELLED,
        ]

        for status in non_retryable_statuses:
            assert status.is_retryable() is False

    def test_status_transitions(self):
        """Test valid status transitions."""
        valid_transitions = {
            DeliveryStatus.PENDING: [DeliveryStatus.QUEUED, DeliveryStatus.CANCELLED],
            DeliveryStatus.QUEUED: [DeliveryStatus.SENDING, DeliveryStatus.CANCELLED],
            DeliveryStatus.SENDING: [DeliveryStatus.SENT, DeliveryStatus.FAILED],
            DeliveryStatus.SENT: [
                DeliveryStatus.DELIVERED,
                DeliveryStatus.BOUNCED,
                DeliveryStatus.FAILED,
            ],
            DeliveryStatus.DELIVERED: [DeliveryStatus.READ],
            DeliveryStatus.FAILED: [DeliveryStatus.QUEUED],  # For retry
            DeliveryStatus.BOUNCED: [],
            DeliveryStatus.READ: [],
            DeliveryStatus.CANCELLED: [],
        }

        for current_status, allowed_next_statuses in valid_transitions.items():
            for next_status in allowed_next_statuses:
                assert current_status.can_transition_to(next_status) is True

        # Test some invalid transitions
        assert (
            DeliveryStatus.DELIVERED.can_transition_to(DeliveryStatus.PENDING) is False
        )
        assert (
            DeliveryStatus.CANCELLED.can_transition_to(DeliveryStatus.QUEUED) is False
        )
        assert DeliveryStatus.READ.can_transition_to(DeliveryStatus.SENT) is False


class TestTemplateType:
    """Test suite for TemplateType enum."""

    def test_all_template_types_exist(self):
        """Test that all expected template types are defined."""
        expected_types = ["transactional", "marketing", "system", "alert"]
        actual_types = [template_type.value for template_type in TemplateType]

        for expected in expected_types:
            assert expected in actual_types

    def test_requires_unsubscribe(self):
        """Test which template types require unsubscribe option."""
        # Only marketing requires unsubscribe
        assert TemplateType.MARKETING.requires_unsubscribe() is True

        # All others don't require unsubscribe
        other_types = [
            TemplateType.TRANSACTIONAL,
            TemplateType.SYSTEM,
            TemplateType.ALERT,
        ]

        for template_type in other_types:
            assert template_type.requires_unsubscribe() is False

    def test_allows_batching(self):
        """Test which template types allow batching."""
        batching_allowed = [TemplateType.MARKETING, TemplateType.SYSTEM]

        for template_type in batching_allowed:
            assert template_type.allows_batching() is True

        # Transactional and alert don't allow batching
        no_batching = [TemplateType.TRANSACTIONAL, TemplateType.ALERT]

        for template_type in no_batching:
            assert template_type.allows_batching() is False

    def test_default_priority(self):
        """Test default priority for each template type."""
        expected_priorities = {
            TemplateType.TRANSACTIONAL: NotificationPriority.HIGH,
            TemplateType.MARKETING: NotificationPriority.LOW,
            TemplateType.SYSTEM: NotificationPriority.NORMAL,
            TemplateType.ALERT: NotificationPriority.URGENT,
        }

        for template_type, expected_priority in expected_priorities.items():
            assert template_type.default_priority() == expected_priority

    def test_retention_days(self):
        """Test retention period for each template type."""
        expected_retention = {
            TemplateType.TRANSACTIONAL: 365,  # 1 year
            TemplateType.MARKETING: 90,  # 3 months
            TemplateType.SYSTEM: 180,  # 6 months
            TemplateType.ALERT: 30,  # 1 month
        }

        for template_type, expected_days in expected_retention.items():
            assert template_type.retention_days() == expected_days


class TestBatchStatus:
    """Test suite for BatchStatus enum."""

    def test_all_batch_statuses_exist(self):
        """Test that all expected batch statuses are defined."""
        expected_statuses = [
            "created",
            "processing",
            "completed",
            "failed",
            "partial",
            "cancelled",
        ]
        actual_statuses = [status.value for status in BatchStatus]

        for expected in expected_statuses:
            assert expected in actual_statuses

    def test_is_final_batch_statuses(self):
        """Test identification of final batch statuses."""
        final_statuses = [
            BatchStatus.COMPLETED,
            BatchStatus.FAILED,
            BatchStatus.CANCELLED,
        ]

        for status in final_statuses:
            assert status.is_final() is True

        # Non-final statuses
        non_final_statuses = [
            BatchStatus.CREATED,
            BatchStatus.PROCESSING,
            BatchStatus.PARTIAL,
        ]

        for status in non_final_statuses:
            assert status.is_final() is False

    def test_can_add_notifications(self):
        """Test when notifications can be added to batch."""
        # Only CREATED status allows adding notifications
        assert BatchStatus.CREATED.can_add_notifications() is True

        # All other statuses don't allow adding
        other_statuses = [
            BatchStatus.PROCESSING,
            BatchStatus.COMPLETED,
            BatchStatus.FAILED,
            BatchStatus.PARTIAL,
            BatchStatus.CANCELLED,
        ]

        for status in other_statuses:
            assert status.can_add_notifications() is False


class TestChannelStatus:
    """Test suite for ChannelStatus enum."""

    def test_all_channel_statuses_exist(self):
        """Test that all expected channel statuses are defined."""
        expected_statuses = ["active", "inactive", "suspended", "configuring", "error"]
        actual_statuses = [status.value for status in ChannelStatus]

        for expected in expected_statuses:
            assert expected in actual_statuses

    def test_is_operational(self):
        """Test operational channel status identification."""
        # Only ACTIVE is operational
        assert ChannelStatus.ACTIVE.is_operational() is True

        # All others are not operational
        non_operational = [
            ChannelStatus.INACTIVE,
            ChannelStatus.SUSPENDED,
            ChannelStatus.CONFIGURING,
            ChannelStatus.ERROR,
        ]

        for status in non_operational:
            assert status.is_operational() is False


class TestRecipientStatus:
    """Test suite for RecipientStatus enum."""

    def test_all_recipient_statuses_exist(self):
        """Test that all expected recipient statuses are defined."""
        expected_statuses = [
            "active",
            "unsubscribed",
            "bounced",
            "complained",
            "suppressed",
        ]
        actual_statuses = [status.value for status in RecipientStatus]

        for expected in expected_statuses:
            assert expected in actual_statuses

    def test_can_receive_notifications(self):
        """Test which recipient statuses can receive notifications."""
        # Only ACTIVE can receive notifications
        assert RecipientStatus.ACTIVE.can_receive_notifications() is True

        # All others cannot
        blocked_statuses = [
            RecipientStatus.UNSUBSCRIBED,
            RecipientStatus.BOUNCED,
            RecipientStatus.COMPLAINED,
            RecipientStatus.SUPPRESSED,
        ]

        for status in blocked_statuses:
            assert status.can_receive_notifications() is False

    def test_is_permanently_blocked(self):
        """Test permanently blocked recipient statuses."""
        permanently_blocked = [RecipientStatus.COMPLAINED, RecipientStatus.SUPPRESSED]

        for status in permanently_blocked:
            assert status.is_permanently_blocked() is True

        # Others are not permanently blocked
        not_permanently_blocked = [
            RecipientStatus.ACTIVE,
            RecipientStatus.UNSUBSCRIBED,
            RecipientStatus.BOUNCED,
        ]

        for status in not_permanently_blocked:
            assert status.is_permanently_blocked() is False


class TestScheduleStatus:
    """Test suite for ScheduleStatus enum."""

    def test_all_schedule_statuses_exist(self):
        """Test that all expected schedule statuses are defined."""
        expected_statuses = ["active", "paused", "completed", "cancelled", "expired"]
        actual_statuses = [status.value for status in ScheduleStatus]

        for expected in expected_statuses:
            assert expected in actual_statuses

    def test_is_executable(self):
        """Test which schedule statuses are executable."""
        # Only ACTIVE is executable
        assert ScheduleStatus.ACTIVE.is_executable() is True

        # All others are not executable
        non_executable = [
            ScheduleStatus.PAUSED,
            ScheduleStatus.COMPLETED,
            ScheduleStatus.CANCELLED,
            ScheduleStatus.EXPIRED,
        ]

        for status in non_executable:
            assert status.is_executable() is False

    def test_is_final_schedule_status(self):
        """Test identification of final schedule statuses."""
        final_statuses = [
            ScheduleStatus.COMPLETED,
            ScheduleStatus.CANCELLED,
            ScheduleStatus.EXPIRED,
        ]

        for status in final_statuses:
            assert status.is_final() is True

        # Non-final statuses
        non_final_statuses = [ScheduleStatus.ACTIVE, ScheduleStatus.PAUSED]

        for status in non_final_statuses:
            assert status.is_final() is False


class TestVariableType:
    """Test suite for VariableType enum."""

    def test_all_variable_types_exist(self):
        """Test that all expected variable types are defined."""
        expected_types = [
            "string",
            "number",
            "date",
            "datetime",
            "boolean",
            "url",
            "email",
            "currency",
        ]
        actual_types = [var_type.value for var_type in VariableType]

        for expected in expected_types:
            assert expected in actual_types

    @pytest.mark.parametrize(
        ("var_type", "valid_values", "invalid_values"),
        [
            (VariableType.STRING, ["hello", "world", ""], [123, True, None]),
            (VariableType.NUMBER, [123, 45.67, 0, -10], ["123", True, None]),
            (VariableType.BOOLEAN, [True, False], ["true", 1, 0, None]),
            (VariableType.DATE, ["2023-12-25", "2024-01-01"], [123, True, None]),
            (VariableType.DATETIME, ["2023-12-25T12:00:00Z"], [123, True, None]),
            (
                VariableType.URL,
                ["https://example.com", "http://test.org"],
                ["not_a_url", "ftp://invalid", 123, None],
            ),
            (
                VariableType.EMAIL,
                ["test@example.com", "user@domain.org"],
                ["invalid_email", "no_at_symbol.com", 123, None],
            ),
            (VariableType.CURRENCY, [19.99, 100.0, 0.01, 0], ["19.99", True, None]),
        ],
    )
    def test_variable_type_validation(self, var_type, valid_values, invalid_values):
        """Test value validation for different variable types."""
        # Test valid values
        for valid_value in valid_values:
            assert (
                var_type.validate_value(valid_value) is True
            ), f"Expected {valid_value} to be valid for {var_type.value}"

        # Test invalid values
        for invalid_value in invalid_values:
            assert (
                var_type.validate_value(invalid_value) is False
            ), f"Expected {invalid_value} to be invalid for {var_type.value}"

    def test_string_type_validation(self):
        """Test string type validation specifics."""
        var_type = VariableType.STRING

        # Valid strings
        assert var_type.validate_value("hello") is True
        assert var_type.validate_value("") is True
        assert var_type.validate_value("123") is True

        # Invalid types
        assert var_type.validate_value(123) is False
        assert var_type.validate_value(True) is False
        assert var_type.validate_value(None) is False

    def test_number_type_validation(self):
        """Test number type validation specifics."""
        var_type = VariableType.NUMBER

        # Valid numbers
        assert var_type.validate_value(123) is True
        assert var_type.validate_value(45.67) is True
        assert var_type.validate_value(0) is True
        assert var_type.validate_value(-10) is True

        # Invalid types
        assert var_type.validate_value("123") is False
        assert var_type.validate_value(True) is False
        assert var_type.validate_value(None) is False

    def test_url_type_validation(self):
        """Test URL type validation specifics."""
        var_type = VariableType.URL

        # Valid URLs
        valid_urls = [
            "https://example.com",
            "http://test.org",
            "https://api.service.com/endpoint",
            "http://localhost:8080",
        ]

        for url in valid_urls:
            assert var_type.validate_value(url) is True

        # Invalid URLs
        invalid_urls = ["not_a_url", "ftp://example.com", "example.com", "", 123, None]

        for url in invalid_urls:
            assert var_type.validate_value(url) is False

    def test_email_type_validation(self):
        """Test email type validation specifics."""
        var_type = VariableType.EMAIL

        # Valid emails
        valid_emails = [
            "test@example.com",
            "user@domain.org",
            "user.name@company.co.uk",
            "test+tag@example.com",
        ]

        for email in valid_emails:
            assert var_type.validate_value(email) is True

        # Invalid emails (basic validation)
        invalid_emails = [
            "invalid_email",
            "no_at_symbol.com",
            "@domain.com",
            "user@",
            "",
            123,
            None,
        ]

        for email in invalid_emails:
            assert var_type.validate_value(email) is False

    def test_currency_type_validation(self):
        """Test currency type validation specifics."""
        var_type = VariableType.CURRENCY

        # Valid currency values
        assert var_type.validate_value(19.99) is True
        assert var_type.validate_value(100) is True
        assert var_type.validate_value(0) is True
        assert var_type.validate_value(0.01) is True

        # Invalid currency values
        assert var_type.validate_value("19.99") is False
        assert var_type.validate_value(True) is False
        assert var_type.validate_value(None) is False

    def test_boolean_type_validation(self):
        """Test boolean type validation specifics."""
        var_type = VariableType.BOOLEAN

        # Valid booleans
        assert var_type.validate_value(True) is True
        assert var_type.validate_value(False) is True

        # Invalid booleans
        assert var_type.validate_value("true") is False
        assert var_type.validate_value(1) is False
        assert var_type.validate_value(0) is False
        assert var_type.validate_value(None) is False

    def test_date_and_datetime_validation(self):
        """Test date and datetime type validation."""
        date_type = VariableType.DATE
        datetime_type = VariableType.DATETIME

        # Valid date/datetime strings
        assert date_type.validate_value("2023-12-25") is True
        assert datetime_type.validate_value("2023-12-25T12:00:00Z") is True

        # Invalid values
        assert date_type.validate_value(123) is False
        assert datetime_type.validate_value(True) is False
        assert date_type.validate_value(None) is False
        assert datetime_type.validate_value(None) is False
