"""Comprehensive tests for Notification entity.

This module provides complete test coverage for the Notification entity,
including lifecycle management, status transitions, retry logic,
and multi-channel delivery tracking.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
)
from app.modules.notification.domain.errors import (
    InvalidChannelError,
    NotificationExpiredError,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
)


class TestNotificationCreation:
    """Test suite for Notification entity creation and initialization."""

    def test_basic_notification_creation(self, sample_recipient_id):
        """Test creating a basic notification."""
        content = NotificationContent(
            subject="Test Subject", body="Test notification body"
        )
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL, address="test@example.com"
        )

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
        )

        assert notification.recipient_id == sample_recipient_id
        assert notification.channel == NotificationChannel.EMAIL
        assert notification.content.subject == "Test Subject"
        assert notification.content.body == "Test notification body"
        assert notification.recipient_address.address == "test@example.com"
        assert notification.template_id is None
        assert notification.priority.level == NotificationPriority.NORMAL
        assert notification.expires_at is None
        assert notification.idempotency_key is None
        assert notification.metadata == {}

    def test_notification_creation_with_all_fields(
        self, sample_recipient_id, sample_template_id
    ):
        """Test creating notification with all optional fields."""
        content = NotificationContent(
            subject="Complete Notification",
            body="This is a complete notification with all fields",
            html_body="<p>HTML version</p>",
            variables={"user": "John"},
            metadata={"test": True},
        )
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="john@example.com",
            display_name="John Doe",
        )
        priority = NotificationPriorityValue(
            level=NotificationPriority.HIGH, reason="Important notification"
        )
        expires_at = datetime.utcnow() + timedelta(hours=24)

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            template_id=sample_template_id,
            priority=priority,
            expires_at=expires_at,
            idempotency_key="unique-key-123",
            metadata={"campaign": "welcome", "version": "2.0"},
        )

        assert notification.template_id == sample_template_id
        assert notification.priority.level == NotificationPriority.HIGH
        assert notification.priority.reason == "Important notification"
        assert notification.expires_at == expires_at
        assert notification.idempotency_key == "unique-key-123"
        assert notification.metadata["campaign"] == "welcome"
        assert notification.metadata["version"] == "2.0"

    def test_notification_initial_status(self, basic_notification):
        """Test that new notification has correct initial status."""
        assert notification.current_status == DeliveryStatus.PENDING
        assert len(notification.status_history) == 1

        initial_status = notification.status_history[0]
        assert initial_status.status == DeliveryStatus.PENDING
        assert initial_status.details == "Notification created"
        assert initial_status.timestamp == notification.created_at

    def test_notification_retry_settings(self, basic_notification):
        """Test notification retry settings based on priority."""
        assert notification.retry_count == 0
        assert (
            notification.max_retries == notification.priority.level.max_retry_attempts()
        )
        assert notification.next_retry_at is None

    def test_notification_timestamps_initialization(self, basic_notification):
        """Test notification timestamp initialization."""
        assert notification.scheduled_for is None
        assert notification.sent_at is None
        assert notification.delivered_at is None
        assert notification.read_at is None
        assert notification.failed_at is None

    def test_notification_provider_tracking_initialization(self, basic_notification):
        """Test notification provider tracking initialization."""
        assert notification.provider is None
        assert notification.provider_message_id is None
        assert notification.provider_response is None


class TestNotificationValidation:
    """Test suite for notification validation during creation."""

    def test_validation_empty_recipient_id_fails(self):
        """Test that empty recipient ID fails validation."""
        content = NotificationContent(body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        with pytest.raises(ValidationError, match="Recipient ID is required"):
            Notification(
                recipient_id=None,
                channel=NotificationChannel.EMAIL,
                content=content,
                recipient_address=address,
            )

    def test_validation_invalid_channel_fails(self, sample_recipient_id):
        """Test that invalid channel fails validation."""
        content = NotificationContent(body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        with pytest.raises(InvalidChannelError):
            Notification(
                recipient_id=sample_recipient_id,
                channel="invalid_channel",  # Invalid channel type
                content=content,
                recipient_address=address,
            )

    def test_validation_invalid_content_fails(self, sample_recipient_id):
        """Test that invalid content fails validation."""
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        with pytest.raises(
            ValidationError, match="Content must be a NotificationContent instance"
        ):
            Notification(
                recipient_id=sample_recipient_id,
                channel=NotificationChannel.EMAIL,
                content="invalid_content",  # Should be NotificationContent
                recipient_address=address,
            )

    def test_validation_email_without_subject_fails(self, sample_recipient_id):
        """Test that email notification without subject fails validation."""
        content = NotificationContent(body="Email body without subject")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        with pytest.raises(
            ValidationError, match="Email notifications require a subject"
        ):
            Notification(
                recipient_id=sample_recipient_id,
                channel=NotificationChannel.EMAIL,
                content=content,
                recipient_address=address,
            )

    def test_validation_mismatched_channel_address_fails(self, sample_recipient_id):
        """Test that mismatched channel and address fails validation."""
        content = NotificationContent(body="Test")
        sms_address = RecipientAddress(NotificationChannel.SMS, "+1234567890")

        with pytest.raises(
            ValidationError, match="Recipient address channel sms does not match"
        ):
            Notification(
                recipient_id=sample_recipient_id,
                channel=NotificationChannel.EMAIL,  # Email channel
                content=content,
                recipient_address=sms_address,  # SMS address
            )

    def test_validation_invalid_recipient_address_fails(self, sample_recipient_id):
        """Test that invalid recipient address fails validation."""
        content = NotificationContent(body="Test")

        with pytest.raises(
            ValidationError,
            match="Recipient address must be a RecipientAddress instance",
        ):
            Notification(
                recipient_id=sample_recipient_id,
                channel=NotificationChannel.EMAIL,
                content=content,
                recipient_address="invalid_address",  # Should be RecipientAddress
            )


class TestNotificationContentOptimization:
    """Test suite for channel-specific content optimization."""

    def test_email_content_preserved(self, sample_recipient_id):
        """Test that email content is preserved as-is."""
        original_content = NotificationContent(
            subject="Email Subject",
            body="Email body content",
            html_body="<p>HTML content</p>",
            attachments=[{"filename": "doc.pdf"}],
        )
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=original_content,
            recipient_address=address,
        )

        assert notification.content.subject == "Email Subject"
        assert notification.content.body == "Email body content"
        assert notification.content.html_body == "<p>HTML content</p>"
        assert len(notification.content.attachments) == 1

    def test_sms_content_optimization(self, sample_recipient_id):
        """Test that SMS content is optimized for channel."""
        long_content = NotificationContent(
            subject="SMS Subject (will be ignored)",
            body="This is a very long SMS message " * 10,  # Very long
            html_body="<p>HTML (will be ignored)</p>",
        )
        address = RecipientAddress(NotificationChannel.SMS, "+1234567890")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.SMS,
            content=long_content,
            recipient_address=address,
        )

        # SMS should be optimized
        assert notification.content.subject is None
        assert len(notification.content.body) <= 160
        assert notification.content.html_body is None

    def test_push_content_optimization(self, sample_recipient_id):
        """Test that push notification content is optimized."""
        long_content = NotificationContent(
            subject="Push Notification Title",
            body="This is a very long push notification body " * 5,  # Very long
            html_body="<p>HTML (will be ignored)</p>",
        )
        address = RecipientAddress(NotificationChannel.PUSH, "device_token_123")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.PUSH,
            content=long_content,
            recipient_address=address,
        )

        # Push should be optimized
        assert notification.content.subject == "Push Notification Title"
        assert len(notification.content.body) <= 100
        assert notification.content.html_body is None

    def test_in_app_content_optimization(self, sample_recipient_id):
        """Test that in-app content removes attachments."""
        content = NotificationContent(
            subject="In-App Notification",
            body="In-app body",
            html_body="<p>Rich content</p>",
            attachments=[{"filename": "doc.pdf"}],
        )
        address = RecipientAddress(NotificationChannel.IN_APP, str(uuid4()))

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.IN_APP,
            content=content,
            recipient_address=address,
        )

        # In-app should remove attachments but keep other content
        assert notification.content.subject == "In-App Notification"
        assert notification.content.body == "In-app body"
        assert notification.content.html_body == "<p>Rich content</p>"
        assert notification.content.attachments == []


class TestNotificationProperties:
    """Test suite for notification computed properties."""

    def test_current_status_property(self, basic_notification):
        """Test current_status property reflects latest status."""
        assert notification.current_status == DeliveryStatus.PENDING

        notification.update_status(DeliveryStatus.QUEUED)
        assert notification.current_status == DeliveryStatus.QUEUED

        notification.update_status(DeliveryStatus.SENT)
        assert notification.current_status == DeliveryStatus.SENT

    def test_is_final_property(self, basic_notification):
        """Test is_final property for different statuses."""
        # Initial status is not final
        assert notification.is_final is False

        # In-progress statuses are not final
        for status in [
            DeliveryStatus.QUEUED,
            DeliveryStatus.SENDING,
            DeliveryStatus.SENT,
        ]:
            notification.update_status(status)
            assert notification.is_final is False

        # Final statuses
        for status in [
            DeliveryStatus.DELIVERED,
            DeliveryStatus.FAILED,
            DeliveryStatus.CANCELLED,
            DeliveryStatus.READ,
        ]:
            notification.update_status(status)
            assert notification.is_final is True

    def test_is_successful_property(self, basic_notification):
        """Test is_successful property for different statuses."""
        # Non-successful statuses
        for status in [
            DeliveryStatus.PENDING,
            DeliveryStatus.QUEUED,
            DeliveryStatus.FAILED,
            DeliveryStatus.CANCELLED,
        ]:
            notification.update_status(status)
            assert notification.is_successful is False

        # Successful statuses
        for status in [DeliveryStatus.DELIVERED, DeliveryStatus.READ]:
            notification.update_status(status)
            assert notification.is_successful is True

    def test_is_expired_property_no_expiration(self, basic_notification):
        """Test is_expired property when no expiration is set."""
        assert notification.expires_at is None
        assert notification.is_expired is False

    def test_is_expired_property_future_expiration(self, sample_recipient_id):
        """Test is_expired property with future expiration."""
        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )

        assert notification.is_expired is False

    def test_is_expired_property_past_expiration(self, sample_recipient_id):
        """Test is_expired property with past expiration."""
        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        assert notification.is_expired is True

    def test_can_retry_property(self, failed_notification):
        """Test can_retry property logic."""
        # Failed notification should be retryable if under max retries
        assert failed_notification.can_retry is True

        # Exceed max retries
        failed_notification.retry_count = failed_notification.max_retries
        assert failed_notification.can_retry is False

        # Reset retry count but make it expired
        failed_notification.retry_count = 0
        failed_notification.expires_at = datetime.utcnow() - timedelta(hours=1)
        assert failed_notification.can_retry is False

    def test_can_retry_property_non_retryable_status(self, basic_notification):
        """Test can_retry property with non-retryable status."""
        notification.update_status(DeliveryStatus.DELIVERED)
        assert notification.can_retry is False

        notification.update_status(DeliveryStatus.CANCELLED)
        assert notification.can_retry is False


class TestNotificationStatusUpdates:
    """Test suite for notification status update logic."""

    def test_update_status_basic(self, basic_notification):
        """Test basic status update."""
        initial_history_length = len(notification.status_history)

        notification.update_status(
            DeliveryStatus.QUEUED,
            details="Added to queue",
            provider_message_id="msg_123",
        )

        assert notification.current_status == DeliveryStatus.QUEUED
        assert len(notification.status_history) == initial_history_length + 1
        assert notification.provider_message_id == "msg_123"

        latest_status = notification.status_history[-1]
        assert latest_status.status == DeliveryStatus.QUEUED
        assert latest_status.details == "Added to queue"
        assert latest_status.provider_message_id == "msg_123"

    def test_update_status_with_provider_info(self, basic_notification):
        """Test status update with provider information."""
        notification.update_status(
            DeliveryStatus.SENT,
            details="Sent via SendGrid",
            provider_message_id="sg_123456",
            provider_status="accepted",
            error_code=None,
        )

        latest_status = notification.status_history[-1]
        assert latest_status.provider_message_id == "sg_123456"
        assert latest_status.provider_status == "accepted"
        assert latest_status.error_code is None

    def test_update_status_with_error_info(self, basic_notification):
        """Test status update with error information."""
        notification.update_status(
            DeliveryStatus.FAILED,
            details="SMTP server unavailable",
            error_code="SMTP_503",
        )

        latest_status = notification.status_history[-1]
        assert latest_status.status == DeliveryStatus.FAILED
        assert latest_status.details == "SMTP server unavailable"
        assert latest_status.error_code == "SMTP_503"

    def test_update_status_invalid_transition_fails(self, basic_notification):
        """Test that invalid status transitions fail."""
        # Try to go from PENDING to DELIVERED (invalid)
        with pytest.raises(
            ValidationError, match="Cannot transition from pending to delivered"
        ):
            notification.update_status(DeliveryStatus.DELIVERED)

    def test_update_status_expired_notification_fails(self, expired_notification):
        """Test that updating expired notification fails."""
        with pytest.raises(NotificationExpiredError):
            expired_notification.update_status(DeliveryStatus.QUEUED)

    def test_update_status_timestamps(self, basic_notification):
        """Test that status updates set appropriate timestamps."""
        start_time = datetime.utcnow()

        # Test SENT timestamp
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)
        notification.update_status(DeliveryStatus.SENT)

        assert notification.sent_at is not None
        assert notification.sent_at >= start_time

        # Test DELIVERED timestamp
        notification.update_status(DeliveryStatus.DELIVERED)
        assert notification.delivered_at is not None
        assert notification.delivered_at >= notification.sent_at

        # Test READ timestamp
        notification.update_status(DeliveryStatus.READ)
        assert notification.read_at is not None
        assert notification.read_at >= notification.delivered_at

    def test_update_status_failed_timestamp(self, basic_notification):
        """Test FAILED status sets failed_at timestamp."""
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.FAILED, error_code="TEST_ERROR")

        assert notification.failed_at is not None
        assert notification.current_status == DeliveryStatus.FAILED


class TestNotificationScheduling:
    """Test suite for notification scheduling functionality."""

    def test_schedule_notification(self, basic_notification):
        """Test scheduling notification for future delivery."""
        future_time = datetime.utcnow() + timedelta(hours=2)

        notification.schedule(future_time)

        assert notification.scheduled_for == future_time

    def test_schedule_notification_invalid_status_fails(self, basic_notification):
        """Test scheduling notification in invalid status fails."""
        notification.update_status(DeliveryStatus.QUEUED)
        future_time = datetime.utcnow() + timedelta(hours=2)

        with pytest.raises(
            ValidationError, match="Cannot schedule notification in queued status"
        ):
            notification.schedule(future_time)

    def test_schedule_notification_past_time_fails(self, basic_notification):
        """Test scheduling notification in the past fails."""
        past_time = datetime.utcnow() - timedelta(hours=1)

        with pytest.raises(
            ValidationError, match="Scheduled time must be in the future"
        ):
            notification.schedule(past_time)

    def test_schedule_notification_after_expiration_fails(self, sample_recipient_id):
        """Test scheduling notification after expiration fails."""
        expires_at = datetime.utcnow() + timedelta(hours=1)
        scheduled_for = datetime.utcnow() + timedelta(hours=2)

        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            expires_at=expires_at,
        )

        with pytest.raises(
            ValidationError, match="Cannot schedule notification after expiration"
        ):
            notification.schedule(scheduled_for)


class TestNotificationRetryLogic:
    """Test suite for notification retry functionality."""

    def test_mark_for_retry_basic(self, failed_notification):
        """Test basic retry marking."""
        initial_retry_count = failed_notification.retry_count

        failed_notification.mark_for_retry()

        assert failed_notification.retry_count == initial_retry_count + 1
        assert failed_notification.next_retry_at is not None
        assert failed_notification.current_status == DeliveryStatus.QUEUED

    def test_mark_for_retry_custom_delay(self, failed_notification):
        """Test retry marking with custom delay."""
        start_time = datetime.utcnow()
        custom_delay = 300  # 5 minutes

        failed_notification.mark_for_retry(delay_seconds=custom_delay)

        expected_time = start_time + timedelta(seconds=custom_delay)
        time_diff = abs(
            (failed_notification.next_retry_at - expected_time).total_seconds()
        )
        assert time_diff < 5  # Within 5 seconds tolerance

    def test_mark_for_retry_exponential_backoff(self, failed_notification):
        """Test retry marking with exponential backoff."""
        # First retry
        failed_notification.mark_for_retry(delay_seconds=60)
        first_retry_time = failed_notification.next_retry_at

        # Update to failed again
        failed_notification.update_status(DeliveryStatus.FAILED)

        # Second retry
        failed_notification.mark_for_retry(delay_seconds=60)
        second_retry_time = failed_notification.next_retry_at

        # Second retry should have longer delay due to backoff
        time_diff = (second_retry_time - first_retry_time).total_seconds()
        assert time_diff > 60  # Should be more than base delay due to backoff

    def test_mark_for_retry_max_delay_cap(self, failed_notification):
        """Test retry marking has maximum delay cap."""
        # Simulate many retries to test max delay cap
        failed_notification.retry_count = 10  # High retry count for large backoff

        start_time = datetime.utcnow()
        failed_notification.mark_for_retry(delay_seconds=60)

        # Even with high retry count, delay should be capped at 1 hour
        max_expected_time = start_time + timedelta(hours=1, seconds=10)
        assert failed_notification.next_retry_at <= max_expected_time

    def test_mark_for_retry_not_allowed_fails(self, basic_notification):
        """Test retry marking fails when not allowed."""
        # Successful notification cannot be retried
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENT)
        notification.update_status(DeliveryStatus.DELIVERED)

        with pytest.raises(ValidationError, match="Notification cannot be retried"):
            notification.mark_for_retry()

    def test_mark_for_retry_emits_status_update(self, failed_notification):
        """Test retry marking updates status history."""
        initial_history_length = len(failed_notification.status_history)

        failed_notification.mark_for_retry()

        assert len(failed_notification.status_history) == initial_history_length + 1
        latest_status = failed_notification.status_history[-1]
        assert "retry" in latest_status.details.lower()


class TestNotificationProviderInfo:
    """Test suite for provider information management."""

    def test_set_provider_info_basic(self, basic_notification):
        """Test setting basic provider information."""
        notification.set_provider_info("sendgrid")

        assert notification.provider == "sendgrid"
        assert notification.provider_response is None

    def test_set_provider_info_with_response(self, basic_notification):
        """Test setting provider information with response."""
        provider_response = {
            "message_id": "msg_123",
            "status": "accepted",
            "recipients": ["test@example.com"],
        }

        notification.set_provider_info("sendgrid", provider_response)

        assert notification.provider == "sendgrid"
        assert notification.provider_response == provider_response


class TestNotificationCancellation:
    """Test suite for notification cancellation."""

    def test_cancel_notification(self, basic_notification):
        """Test canceling a notification."""
        notification.cancel("User requested cancellation")

        assert notification.current_status == DeliveryStatus.CANCELLED
        latest_status = notification.status_history[-1]
        assert latest_status.details == "User requested cancellation"

    def test_cancel_notification_without_reason(self, basic_notification):
        """Test canceling notification without specific reason."""
        notification.cancel()

        assert notification.current_status == DeliveryStatus.CANCELLED
        latest_status = notification.status_history[-1]
        assert latest_status.details == "Notification cancelled"

    def test_cancel_final_notification_fails(self, basic_notification):
        """Test canceling final notification fails."""
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENT)
        notification.update_status(DeliveryStatus.DELIVERED)

        with pytest.raises(
            ValidationError, match="Cannot cancel notification in delivered status"
        ):
            notification.cancel()


class TestNotificationMetadata:
    """Test suite for notification metadata management."""

    def test_add_metadata(self, basic_notification):
        """Test adding metadata to notification."""
        notification.add_metadata("tracking_id", "track_123")
        notification.add_metadata("campaign", "welcome_series")

        assert notification.metadata["tracking_id"] == "track_123"
        assert notification.metadata["campaign"] == "welcome_series"

    def test_metadata_persistence(self, basic_notification):
        """Test that metadata persists through status changes."""
        notification.add_metadata("persistent_data", "important_value")

        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENT)

        assert notification.metadata["persistent_data"] == "important_value"


class TestNotificationDurationCalculations:
    """Test suite for notification duration calculations."""

    def test_get_delivery_duration(self, basic_notification):
        """Test calculating delivery duration."""
        # Initially no duration
        assert notification.get_delivery_duration() is None

        # Set sent timestamp
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)
        notification.update_status(DeliveryStatus.SENT)

        # Set delivered timestamp after a delay
        import time

        time.sleep(0.01)  # Small delay
        notification.update_status(DeliveryStatus.DELIVERED)

        duration = notification.get_delivery_duration()
        assert duration is not None
        assert duration.total_seconds() > 0
        assert duration == notification.delivered_at - notification.sent_at

    def test_get_delivery_duration_incomplete(self, basic_notification):
        """Test delivery duration calculation when incomplete."""
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENT)
        # No delivered timestamp

        assert notification.get_delivery_duration() is None

    def test_get_processing_duration_success(self, basic_notification):
        """Test calculating processing duration for successful delivery."""
        import time

        time.sleep(0.01)  # Small delay

        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENT)
        notification.update_status(DeliveryStatus.DELIVERED)

        duration = notification.get_processing_duration()
        assert duration is not None
        assert duration.total_seconds() > 0
        assert duration == notification.delivered_at - notification.created_at

    def test_get_processing_duration_failure(self, basic_notification):
        """Test calculating processing duration for failed delivery."""
        import time

        time.sleep(0.01)  # Small delay

        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.FAILED)

        duration = notification.get_processing_duration()
        assert duration is not None
        assert duration.total_seconds() > 0
        assert duration == notification.failed_at - notification.created_at

    def test_get_processing_duration_incomplete(self, basic_notification):
        """Test processing duration calculation when incomplete."""
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)
        # Still in progress

        assert notification.get_processing_duration() is None


class TestNotificationDeliverySummary:
    """Test suite for notification delivery summary generation."""

    def test_delivery_summary_complete(self, basic_notification):
        """Test delivery summary for complete notification lifecycle."""
        # Complete the lifecycle
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)
        notification.update_status(DeliveryStatus.SENT)
        notification.update_status(DeliveryStatus.DELIVERED)
        notification.update_status(DeliveryStatus.READ)

        notification.set_provider_info("sendgrid", {"message_id": "msg_123"})

        summary = notification.to_delivery_summary()

        assert summary["notification_id"] == str(notification.id)
        assert summary["recipient_id"] == str(notification.recipient_id)
        assert summary["channel"] == notification.channel.value
        assert summary["status"] == "read"
        assert summary["created_at"] is not None
        assert summary["sent_at"] is not None
        assert summary["delivered_at"] is not None
        assert summary["read_at"] is not None
        assert summary["failed_at"] is None
        assert summary["retry_count"] == 0
        assert summary["provider"] == "sendgrid"
        assert summary["provider_message_id"] is not None
        assert summary["delivery_duration_seconds"] is not None
        assert summary["processing_duration_seconds"] is not None

    def test_delivery_summary_failed(self, failed_notification):
        """Test delivery summary for failed notification."""
        summary = failed_notification.to_delivery_summary()

        assert summary["status"] == "failed"
        assert summary["failed_at"] is not None
        assert summary["delivered_at"] is None
        assert summary["read_at"] is None
        assert summary["delivery_duration_seconds"] is None
        assert summary["processing_duration_seconds"] is not None

    def test_delivery_summary_in_progress(self, basic_notification):
        """Test delivery summary for in-progress notification."""
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)

        summary = notification.to_delivery_summary()

        assert summary["status"] == "sending"
        assert summary["sent_at"] is None
        assert summary["delivered_at"] is None
        assert summary["failed_at"] is None
        assert summary["delivery_duration_seconds"] is None
        assert summary["processing_duration_seconds"] is None


class TestNotificationStringRepresentation:
    """Test suite for notification string representation."""

    def test_string_representation(self, basic_notification):
        """Test notification string representation."""
        str_repr = str(notification)

        assert str(notification.id) in str_repr
        assert notification.recipient_address.address in str_repr
        assert notification.channel.value in str_repr
        assert notification.current_status.value in str_repr

    def test_string_representation_with_display_name(self, sample_recipient_id):
        """Test string representation with recipient display name."""
        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(
            channel=NotificationChannel.EMAIL,
            address="john@example.com",
            display_name="John Doe",
        )

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
        )

        str_repr = str(notification)
        assert "John Doe" in str_repr or "john@example.com" in str_repr


class TestNotificationChannelSpecificBehavior:
    """Test suite for channel-specific notification behavior."""

    @pytest.mark.parametrize(
        ("channel", "address_value"),
        [
            (NotificationChannel.EMAIL, "test@example.com"),
            (NotificationChannel.SMS, "+1234567890"),
            (NotificationChannel.PUSH, "device_token_abc123xyz789"),
            (NotificationChannel.IN_APP, str(uuid4())),
        ],
    )
    def test_notification_creation_all_channels(
        self, sample_recipient_id, channel, address_value
    ):
        """Test notification creation for all supported channels."""
        content = NotificationContent(
            subject="Test"
            if channel in [NotificationChannel.EMAIL, NotificationChannel.PUSH]
            else None,
            body="Test notification body",
        )
        address = RecipientAddress(channel=channel, address=address_value)

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=channel,
            content=content,
            recipient_address=address,
        )

        assert notification.channel == channel
        assert notification.recipient_address.channel == channel
        assert notification.recipient_address.address == address_value
        assert notification.current_status == DeliveryStatus.PENDING

    def test_email_notification_max_retries(self, sample_recipient_id):
        """Test email notification retry settings."""
        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")
        priority = NotificationPriorityValue(level=NotificationPriority.HIGH)

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            priority=priority,
        )

        assert (
            notification.max_retries == NotificationPriority.HIGH.max_retry_attempts()
        )

    def test_sms_notification_urgency(self, sample_recipient_id):
        """Test SMS notification with urgent priority."""
        content = NotificationContent(body="Urgent SMS")
        address = RecipientAddress(NotificationChannel.SMS, "+1234567890")
        priority = NotificationPriorityValue(level=NotificationPriority.URGENT)

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.SMS,
            content=content,
            recipient_address=address,
            priority=priority,
        )

        assert notification.priority.level == NotificationPriority.URGENT
        assert (
            notification.max_retries == NotificationPriority.URGENT.max_retry_attempts()
        )

    def test_push_notification_short_expiry(self, sample_recipient_id):
        """Test push notification with short expiry."""
        content = NotificationContent(subject="Push", body="Push body")
        address = RecipientAddress(NotificationChannel.PUSH, "device_token_123")
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.PUSH,
            content=content,
            recipient_address=address,
            expires_at=expires_at,
        )

        assert notification.expires_at == expires_at
        time_until_expiry = notification.expires_at - datetime.utcnow()
        assert time_until_expiry.total_seconds() <= 30 * 60  # 30 minutes


class TestNotificationComplexScenarios:
    """Test suite for complex notification scenarios."""

    def test_notification_full_lifecycle_success(self, basic_notification):
        """Test complete successful notification lifecycle."""
        # Queue the notification
        notification.update_status(DeliveryStatus.QUEUED, details="Added to send queue")
        assert notification.current_status == DeliveryStatus.QUEUED

        # Start sending
        notification.update_status(
            DeliveryStatus.SENDING,
            details="Sending via provider",
            provider_message_id="provider_123",
        )
        assert notification.current_status == DeliveryStatus.SENDING
        assert notification.provider_message_id == "provider_123"

        # Successfully sent
        notification.update_status(
            DeliveryStatus.SENT, details="Successfully sent to provider"
        )
        assert notification.current_status == DeliveryStatus.SENT
        assert notification.sent_at is not None

        # Delivered to recipient
        notification.update_status(
            DeliveryStatus.DELIVERED,
            details="Delivered to recipient",
            provider_status="delivered",
        )
        assert notification.current_status == DeliveryStatus.DELIVERED
        assert notification.delivered_at is not None
        assert notification.is_successful is True

        # Read by recipient
        notification.update_status(DeliveryStatus.READ, details="Opened by recipient")
        assert notification.current_status == DeliveryStatus.READ
        assert notification.read_at is not None

        # Verify full history
        assert len(notification.status_history) == 6  # Including initial PENDING

        # Verify durations
        assert notification.get_delivery_duration() is not None
        assert notification.get_processing_duration() is not None

    def test_notification_failure_and_retry_cycle(self, basic_notification):
        """Test notification failure and retry cycle."""
        # Queue and attempt send
        notification.update_status(DeliveryStatus.QUEUED)
        notification.update_status(DeliveryStatus.SENDING)

        # First failure
        notification.update_status(
            DeliveryStatus.FAILED,
            details="SMTP server timeout",
            error_code="SMTP_TIMEOUT",
        )
        assert notification.failed_at is not None

        # Mark for retry
        notification.mark_for_retry()
        assert notification.retry_count == 1
        assert notification.current_status == DeliveryStatus.QUEUED
        assert notification.next_retry_at is not None

        # Second attempt
        notification.update_status(DeliveryStatus.SENDING)
        notification.update_status(
            DeliveryStatus.FAILED,
            details="Recipient mailbox full",
            error_code="MAILBOX_FULL",
        )

        # Second retry
        notification.mark_for_retry()
        assert notification.retry_count == 2

        # Third attempt succeeds
        notification.update_status(DeliveryStatus.SENDING)
        notification.update_status(DeliveryStatus.SENT)
        notification.update_status(DeliveryStatus.DELIVERED)

        assert notification.is_successful is True
        assert notification.retry_count == 2

        # Verify comprehensive status history
        statuses = [status.status for status in notification.status_history]
        expected_pattern = [
            DeliveryStatus.PENDING,
            DeliveryStatus.QUEUED,
            DeliveryStatus.SENDING,
            DeliveryStatus.FAILED,
            DeliveryStatus.QUEUED,  # First retry
            DeliveryStatus.SENDING,
            DeliveryStatus.FAILED,
            DeliveryStatus.QUEUED,  # Second retry
            DeliveryStatus.SENDING,
            DeliveryStatus.SENT,
            DeliveryStatus.DELIVERED,
        ]
        assert statuses == expected_pattern

    def test_notification_expiry_during_processing(self, sample_recipient_id):
        """Test notification expiring during processing."""
        content = NotificationContent(subject="Test", body="Test")
        address = RecipientAddress(NotificationChannel.EMAIL, "test@example.com")

        # Create with very short expiry
        notification = Notification(
            recipient_id=sample_recipient_id,
            channel=NotificationChannel.EMAIL,
            content=content,
            recipient_address=address,
            expires_at=datetime.utcnow() + timedelta(milliseconds=100),
        )

        # Queue immediately
        notification.update_status(DeliveryStatus.QUEUED)

        # Wait for expiry
        import time

        time.sleep(0.2)

        # Attempt to process expired notification
        with pytest.raises(NotificationExpiredError):
            notification.update_status(DeliveryStatus.SENDING)
