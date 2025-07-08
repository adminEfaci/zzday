"""Comprehensive tests for NotificationBatch aggregate.

This module provides complete test coverage for the NotificationBatch aggregate,
including batch creation, notification management, processing workflows,
and performance optimization.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.notification.domain.aggregates.notification_batch import (
    NotificationBatch,
)
from app.modules.notification.domain.enums import (
    BatchStatus,
    NotificationChannel,
    NotificationPriority,
)
from app.modules.notification.domain.errors import InvalidBatchStateError
from app.modules.notification.domain.events import BatchCreated, BatchProcessed


class TestNotificationBatchCreation:
    """Test suite for NotificationBatch creation and initialization."""

    def test_basic_batch_creation(self):
        """Test creating a basic notification batch."""
        batch = NotificationBatch(
            name="Marketing Campaign Batch",
            description="Monthly newsletter batch",
            metadata={"campaign_id": "camp_001", "type": "newsletter"},
        )

        assert batch.name == "Marketing Campaign Batch"
        assert batch.description == "Monthly newsletter batch"
        assert batch.metadata["campaign_id"] == "camp_001"
        assert batch.metadata["type"] == "newsletter"
        assert batch.status == BatchStatus.CREATED
        assert batch.notifications == []
        assert batch.total_count == 0
        assert batch.processed_count == 0
        assert batch.successful_count == 0
        assert batch.failed_count == 0
        assert batch.scheduled_for is None
        assert batch.started_at is None
        assert batch.completed_at is None
        assert batch.processing_duration is None

    def test_batch_creation_with_minimal_fields(self):
        """Test creating batch with minimal required fields."""
        batch = NotificationBatch(name="Minimal Batch")

        assert batch.name == "Minimal Batch"
        assert batch.description is None
        assert batch.metadata == {}
        assert batch.status == BatchStatus.CREATED

    def test_batch_creation_with_scheduling(self):
        """Test creating batch with scheduling."""
        scheduled_for = datetime.utcnow() + timedelta(hours=2)

        batch = NotificationBatch(
            name="Scheduled Batch",
            scheduled_for=scheduled_for,
            metadata={"schedule_type": "delayed"},
        )

        assert batch.scheduled_for == scheduled_for
        assert batch.metadata["schedule_type"] == "delayed"

    def test_batch_creation_emits_event(self):
        """Test that batch creation emits BatchCreated event."""
        created_by = uuid4()
        batch = NotificationBatch(
            name="Event Test Batch", created_by=created_by, metadata={"test": True}
        )

        events = batch.get_uncommitted_events()
        assert len(events) == 1

        event = events[0]
        assert isinstance(event, BatchCreated)
        assert event.batch_id == batch.id
        assert event.name == "Event Test Batch"
        assert event.created_by == created_by
        assert event.total_recipients == 0  # No notifications added yet

    def test_batch_name_validation_empty_fails(self):
        """Test that empty batch name fails validation."""
        with pytest.raises(ValidationError, match="Batch name is required"):
            NotificationBatch(name="")

    def test_batch_name_validation_whitespace_only_fails(self):
        """Test that whitespace-only batch name fails validation."""
        with pytest.raises(ValidationError, match="Batch name is required"):
            NotificationBatch(name="   ")

    def test_batch_name_validation_too_long_fails(self):
        """Test that overly long batch name fails validation."""
        long_name = "A" * 201  # Exceeds 200 character limit

        with pytest.raises(
            ValidationError, match="Batch name cannot exceed 200 characters"
        ):
            NotificationBatch(name=long_name)

    def test_batch_name_trimming(self):
        """Test that batch name is trimmed of whitespace."""
        batch = NotificationBatch(name="  Trimmed Batch Name  ")
        assert batch.name == "Trimmed Batch Name"


class TestNotificationBatchNotificationManagement:
    """Test suite for managing notifications within a batch."""

    def test_add_notification_basic(self, notification_batch):
        """Test adding a basic notification to batch."""
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "template_id": uuid4(),
            "content": {"subject": "Test Subject", "body": "Test body content"},
            "recipient_address": "test@example.com",
            "priority": NotificationPriority.NORMAL,
            "metadata": {"test": True},
        }

        initial_count = notification_batch.total_count
        notification_batch.add_notification(notification_data)

        assert notification_batch.total_count == initial_count + 1
        assert len(notification_batch.notifications) == initial_count + 1

        added_notification = notification_batch.notifications[-1]
        assert added_notification["recipient_id"] == notification_data["recipient_id"]
        assert added_notification["channel"] == notification_data["channel"]
        assert added_notification["template_id"] == notification_data["template_id"]
        assert added_notification["priority"] == notification_data["priority"]

    def test_add_notification_with_variables(self, notification_batch):
        """Test adding notification with template variables."""
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "template_id": uuid4(),
            "content": {
                "subject": "Welcome {{user_name}}",
                "body": "Hello {{user_name}}, welcome to {{platform_name}}!",
            },
            "recipient_address": "user@example.com",
            "variables": {"user_name": "John Doe", "platform_name": "TestApp"},
            "metadata": {"template_variables": True},
        }

        notification_batch.add_notification(notification_data)

        added_notification = notification_batch.notifications[-1]
        assert added_notification["variables"]["user_name"] == "John Doe"
        assert added_notification["variables"]["platform_name"] == "TestApp"

    def test_add_notification_with_scheduling(self, notification_batch):
        """Test adding notification with individual scheduling."""
        deliver_at = datetime.utcnow() + timedelta(hours=1)
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.SMS,
            "content": {"body": "SMS content"},
            "recipient_address": "+1234567890",
            "deliver_at": deliver_at,
            "expires_at": datetime.utcnow() + timedelta(hours=24),
        }

        notification_batch.add_notification(notification_data)

        added_notification = notification_batch.notifications[-1]
        assert added_notification["deliver_at"] == deliver_at
        assert added_notification["expires_at"] is not None

    def test_add_notification_to_processing_batch_fails(self, processing_batch):
        """Test that adding notification to processing batch fails."""
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }

        with pytest.raises(
            InvalidBatchStateError,
            match="Cannot add notifications to batch in PROCESSING status",
        ):
            processing_batch.add_notification(notification_data)

    def test_add_multiple_notifications_bulk(self, notification_batch):
        """Test adding multiple notifications in bulk."""
        notifications_data = []
        recipients = [uuid4() for _ in range(5)]

        for i, recipient_id in enumerate(recipients):
            notification_data = {
                "recipient_id": recipient_id,
                "channel": NotificationChannel.EMAIL,
                "content": {
                    "subject": f"Bulk notification {i+1}",
                    "body": f"This is bulk notification number {i+1}",
                },
                "recipient_address": f"user{i+1}@example.com",
                "variables": {"sequence_number": i + 1},
                "metadata": {"bulk_position": i + 1},
            }
            notifications_data.append(notification_data)

        initial_count = notification_batch.total_count
        notification_batch.add_notifications_bulk(notifications_data)

        assert notification_batch.total_count == initial_count + 5
        assert len(notification_batch.notifications) == initial_count + 5

        # Verify all notifications were added correctly
        for i, notification in enumerate(notification_batch.notifications[-5:]):
            assert notification["variables"]["sequence_number"] == i + 1
            assert notification["metadata"]["bulk_position"] == i + 1

    def test_remove_notification(self, notification_batch):
        """Test removing a notification from batch."""
        # Add a notification first
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }
        notification_batch.add_notification(notification_data)
        initial_count = notification_batch.total_count

        # Remove the notification
        notification_id = notification_batch.notifications[-1]["notification_id"]
        notification_batch.remove_notification(notification_id)

        assert notification_batch.total_count == initial_count - 1
        assert len(notification_batch.notifications) == initial_count - 1

        # Verify notification is not in the list
        notification_ids = [
            n["notification_id"] for n in notification_batch.notifications
        ]
        assert notification_id not in notification_ids

    def test_remove_nonexistent_notification_fails(self, notification_batch):
        """Test removing nonexistent notification fails."""
        nonexistent_id = uuid4()

        with pytest.raises(ValidationError, match="Notification not found in batch"):
            notification_batch.remove_notification(nonexistent_id)

    def test_remove_notification_from_processing_batch_fails(self, processing_batch):
        """Test removing notification from processing batch fails."""
        # Assuming processing batch has notifications
        if processing_batch.notifications:
            notification_id = processing_batch.notifications[0]["notification_id"]

            with pytest.raises(
                InvalidBatchStateError,
                match="Cannot remove notifications from batch in PROCESSING status",
            ):
                processing_batch.remove_notification(notification_id)

    def test_get_notifications_by_channel(self, notification_batch):
        """Test filtering notifications by channel."""
        # Add notifications for different channels
        channels_and_addresses = [
            (NotificationChannel.EMAIL, "user1@example.com"),
            (NotificationChannel.EMAIL, "user2@example.com"),
            (NotificationChannel.SMS, "+1234567890"),
            (NotificationChannel.SMS, "+0987654321"),
            (NotificationChannel.PUSH, "device_token_1"),
        ]

        for channel, address in channels_and_addresses:
            notification_data = {
                "recipient_id": uuid4(),
                "channel": channel,
                "content": {"subject": "Test", "body": "Test"}
                if channel == NotificationChannel.EMAIL
                else {"body": "Test"},
                "recipient_address": address,
            }
            notification_batch.add_notification(notification_data)

        # Filter by email
        email_notifications = notification_batch.get_notifications_by_channel(
            NotificationChannel.EMAIL
        )
        assert len(email_notifications) == 2
        assert all(
            n["channel"] == NotificationChannel.EMAIL for n in email_notifications
        )

        # Filter by SMS
        sms_notifications = notification_batch.get_notifications_by_channel(
            NotificationChannel.SMS
        )
        assert len(sms_notifications) == 2
        assert all(n["channel"] == NotificationChannel.SMS for n in sms_notifications)

        # Filter by push
        push_notifications = notification_batch.get_notifications_by_channel(
            NotificationChannel.PUSH
        )
        assert len(push_notifications) == 1
        assert all(n["channel"] == NotificationChannel.PUSH for n in push_notifications)

    def test_get_notifications_by_priority(self, notification_batch):
        """Test filtering notifications by priority."""
        # Add notifications with different priorities
        priorities = [
            NotificationPriority.LOW,
            NotificationPriority.NORMAL,
            NotificationPriority.NORMAL,
            NotificationPriority.HIGH,
            NotificationPriority.URGENT,
        ]

        for i, priority in enumerate(priorities):
            notification_data = {
                "recipient_id": uuid4(),
                "channel": NotificationChannel.EMAIL,
                "content": {"subject": f"Test {i}", "body": f"Test {i}"},
                "recipient_address": f"user{i}@example.com",
                "priority": priority,
            }
            notification_batch.add_notification(notification_data)

        # Filter by priority
        high_priority = notification_batch.get_notifications_by_priority(
            NotificationPriority.HIGH
        )
        assert len(high_priority) == 1

        normal_priority = notification_batch.get_notifications_by_priority(
            NotificationPriority.NORMAL
        )
        assert len(normal_priority) == 2


class TestNotificationBatchProcessing:
    """Test suite for batch processing workflows."""

    def test_start_processing_basic(self, notification_batch):
        """Test starting batch processing."""
        # Add some notifications first
        for i in range(3):
            notification_data = {
                "recipient_id": uuid4(),
                "channel": NotificationChannel.EMAIL,
                "content": {"subject": f"Test {i}", "body": f"Test {i}"},
                "recipient_address": f"user{i}@example.com",
            }
            notification_batch.add_notification(notification_data)

        assert notification_batch.status == BatchStatus.CREATED
        assert notification_batch.started_at is None

        notification_batch.start_processing()

        assert notification_batch.status == BatchStatus.PROCESSING
        assert notification_batch.started_at is not None
        assert notification_batch.started_at <= datetime.utcnow()

    def test_start_processing_empty_batch_fails(self, notification_batch):
        """Test starting processing on empty batch fails."""
        assert notification_batch.total_count == 0

        with pytest.raises(
            InvalidBatchStateError, match="Cannot start processing empty batch"
        ):
            notification_batch.start_processing()

    def test_start_processing_already_processing_fails(self, processing_batch):
        """Test starting processing on already processing batch fails."""
        with pytest.raises(
            InvalidBatchStateError, match="Batch is already in PROCESSING status"
        ):
            processing_batch.start_processing()

    def test_mark_notification_processed_success(self, processing_batch):
        """Test marking individual notification as successfully processed."""
        if processing_batch.notifications:
            notification_id = processing_batch.notifications[0]["notification_id"]
            initial_successful = processing_batch.successful_count
            initial_processed = processing_batch.processed_count

            processing_batch.mark_notification_processed(
                notification_id,
                success=True,
                details="Successfully sent via email provider",
            )

            assert processing_batch.successful_count == initial_successful + 1
            assert processing_batch.processed_count == initial_processed + 1

    def test_mark_notification_processed_failure(self, processing_batch):
        """Test marking individual notification as failed."""
        if processing_batch.notifications:
            notification_id = processing_batch.notifications[0]["notification_id"]
            initial_failed = processing_batch.failed_count
            initial_processed = processing_batch.processed_count

            processing_batch.mark_notification_processed(
                notification_id,
                success=False,
                details="SMTP server unavailable",
                error_code="SMTP_503",
            )

            assert processing_batch.failed_count == initial_failed + 1
            assert processing_batch.processed_count == initial_processed + 1

    def test_mark_notification_processed_nonexistent_fails(self, processing_batch):
        """Test marking nonexistent notification as processed fails."""
        nonexistent_id = uuid4()

        with pytest.raises(ValidationError, match="Notification not found in batch"):
            processing_batch.mark_notification_processed(nonexistent_id, success=True)

    def test_mark_notification_processed_not_processing_fails(self, notification_batch):
        """Test marking notification processed on non-processing batch fails."""
        # Add a notification
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }
        notification_batch.add_notification(notification_data)
        notification_id = notification_batch.notifications[0]["notification_id"]

        with pytest.raises(
            InvalidBatchStateError,
            match="Can only mark notifications processed for batches in PROCESSING status",
        ):
            notification_batch.mark_notification_processed(
                notification_id, success=True
            )

    def test_complete_processing_success(self, processing_batch):
        """Test completing batch processing successfully."""
        # Mark all notifications as processed
        for notification in processing_batch.notifications:
            processing_batch.mark_notification_processed(
                notification["notification_id"],
                success=True,
                details="Successfully processed",
            )

        assert processing_batch.processed_count == processing_batch.total_count
        assert processing_batch.completed_at is None

        processing_batch.complete_processing()

        assert processing_batch.status == BatchStatus.COMPLETED
        assert processing_batch.completed_at is not None
        assert processing_batch.processing_duration is not None
        assert processing_batch.processing_duration.total_seconds() > 0

    def test_complete_processing_partial(self, processing_batch):
        """Test completing batch processing with partial results."""
        # Mark some notifications as successful, some as failed
        notifications = processing_batch.notifications
        for i, notification in enumerate(notifications):
            success = i % 2 == 0  # Alternate success/failure
            processing_batch.mark_notification_processed(
                notification["notification_id"],
                success=success,
                details="Processed" if success else "Failed",
                error_code=None if success else "TEST_ERROR",
            )

        processing_batch.complete_processing()

        assert processing_batch.status == BatchStatus.PARTIAL
        assert processing_batch.successful_count > 0
        assert processing_batch.failed_count > 0
        assert (
            processing_batch.successful_count + processing_batch.failed_count
            == processing_batch.total_count
        )

    def test_complete_processing_all_failed(self, processing_batch):
        """Test completing batch processing with all failures."""
        # Mark all notifications as failed
        for notification in processing_batch.notifications:
            processing_batch.mark_notification_processed(
                notification["notification_id"],
                success=False,
                details="Processing failed",
                error_code="BATCH_ERROR",
            )

        processing_batch.complete_processing()

        assert processing_batch.status == BatchStatus.FAILED
        assert processing_batch.failed_count == processing_batch.total_count
        assert processing_batch.successful_count == 0

    def test_complete_processing_incomplete_fails(self, processing_batch):
        """Test completing processing with incomplete notifications fails."""
        # Only process some notifications
        if processing_batch.notifications:
            processing_batch.mark_notification_processed(
                processing_batch.notifications[0]["notification_id"], success=True
            )

        with pytest.raises(
            InvalidBatchStateError,
            match="Cannot complete processing with unprocessed notifications",
        ):
            processing_batch.complete_processing()

    def test_mark_batch_failed(self, processing_batch):
        """Test marking entire batch as failed."""
        reason = "Provider service unavailable"

        processing_batch.mark_failed(reason)

        assert processing_batch.status == BatchStatus.FAILED
        assert processing_batch.completed_at is not None
        assert processing_batch.processing_duration is not None
        assert hasattr(processing_batch, "failure_reason")
        assert processing_batch.failure_reason == reason

    def test_mark_batch_failed_not_processing_fails(self, notification_batch):
        """Test marking non-processing batch as failed fails."""
        with pytest.raises(
            InvalidBatchStateError, match="Can only mark processing batches as failed"
        ):
            notification_batch.mark_failed("Test failure")

    def test_cancel_batch_processing(self, processing_batch):
        """Test canceling batch processing."""
        reason = "User requested cancellation"

        processing_batch.cancel_processing(reason)

        assert processing_batch.status == BatchStatus.CANCELLED
        assert processing_batch.completed_at is not None
        assert hasattr(processing_batch, "cancellation_reason")
        assert processing_batch.cancellation_reason == reason

    def test_cancel_batch_not_processing_fails(self, notification_batch):
        """Test canceling non-processing batch fails."""
        with pytest.raises(
            InvalidBatchStateError, match="Can only cancel processing batches"
        ):
            notification_batch.cancel_processing("Test cancellation")


class TestNotificationBatchScheduling:
    """Test suite for batch scheduling functionality."""

    def test_schedule_batch(self, notification_batch):
        """Test scheduling a batch for future processing."""
        # Add notifications first
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }
        notification_batch.add_notification(notification_data)

        scheduled_for = datetime.utcnow() + timedelta(hours=2)
        notification_batch.schedule_processing(scheduled_for)

        assert notification_batch.scheduled_for == scheduled_for
        assert (
            notification_batch.status == BatchStatus.CREATED
        )  # Should remain in created status

    def test_schedule_batch_past_time_fails(self, notification_batch):
        """Test scheduling batch for past time fails."""
        past_time = datetime.utcnow() - timedelta(hours=1)

        with pytest.raises(
            ValidationError, match="Cannot schedule batch for past time"
        ):
            notification_batch.schedule_processing(past_time)

    def test_schedule_empty_batch_fails(self, notification_batch):
        """Test scheduling empty batch fails."""
        future_time = datetime.utcnow() + timedelta(hours=1)

        with pytest.raises(InvalidBatchStateError, match="Cannot schedule empty batch"):
            notification_batch.schedule_processing(future_time)

    def test_schedule_processing_batch_fails(self, processing_batch):
        """Test scheduling already processing batch fails."""
        future_time = datetime.utcnow() + timedelta(hours=1)

        with pytest.raises(
            InvalidBatchStateError,
            match="Cannot schedule batch that is already processing",
        ):
            processing_batch.schedule_processing(future_time)

    def test_reschedule_batch(self, notification_batch):
        """Test rescheduling a batch."""
        # Add notification and schedule
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }
        notification_batch.add_notification(notification_data)

        initial_time = datetime.utcnow() + timedelta(hours=1)
        notification_batch.schedule_processing(initial_time)
        assert notification_batch.scheduled_for == initial_time

        # Reschedule
        new_time = datetime.utcnow() + timedelta(hours=3)
        notification_batch.schedule_processing(new_time)
        assert notification_batch.scheduled_for == new_time

    def test_unschedule_batch(self, notification_batch):
        """Test unscheduling a batch."""
        # Add notification and schedule
        notification_data = {
            "recipient_id": uuid4(),
            "channel": NotificationChannel.EMAIL,
            "content": {"subject": "Test", "body": "Test"},
            "recipient_address": "test@example.com",
        }
        notification_batch.add_notification(notification_data)

        scheduled_time = datetime.utcnow() + timedelta(hours=1)
        notification_batch.schedule_processing(scheduled_time)
        assert notification_batch.scheduled_for == scheduled_time

        # Unschedule
        notification_batch.unschedule_processing()
        assert notification_batch.scheduled_for is None


class TestNotificationBatchStatistics:
    """Test suite for batch statistics and reporting."""

    def test_get_processing_statistics_empty(self, notification_batch):
        """Test getting statistics for empty batch."""
        stats = notification_batch.get_processing_statistics()

        assert stats["total_count"] == 0
        assert stats["processed_count"] == 0
        assert stats["successful_count"] == 0
        assert stats["failed_count"] == 0
        assert stats["success_rate"] == 0.0
        assert stats["failure_rate"] == 0.0
        assert stats["processing_progress"] == 0.0

    def test_get_processing_statistics_partial(self, processing_batch):
        """Test getting statistics for partially processed batch."""
        # Process some notifications
        notifications = processing_batch.notifications
        processed_count = min(3, len(notifications))

        for i in range(processed_count):
            success = i % 2 == 0  # Alternate success/failure
            processing_batch.mark_notification_processed(
                notifications[i]["notification_id"],
                success=success,
                details="Processed",
            )

        stats = processing_batch.get_processing_statistics()

        assert stats["total_count"] == len(notifications)
        assert stats["processed_count"] == processed_count
        assert (
            stats["processing_progress"] == (processed_count / len(notifications)) * 100
        )

        if processed_count > 0:
            expected_success_rate = (stats["successful_count"] / processed_count) * 100
            assert stats["success_rate"] == expected_success_rate

    def test_get_processing_statistics_completed(self, processing_batch):
        """Test getting statistics for completed batch."""
        # Process all notifications
        successful = 0
        for i, notification in enumerate(processing_batch.notifications):
            success = i % 3 != 0  # 2/3 success rate
            if success:
                successful += 1

            processing_batch.mark_notification_processed(
                notification["notification_id"], success=success, details="Processed"
            )

        processing_batch.complete_processing()
        stats = processing_batch.get_processing_statistics()

        assert stats["total_count"] == len(processing_batch.notifications)
        assert stats["processed_count"] == len(processing_batch.notifications)
        assert stats["successful_count"] == successful
        assert stats["failed_count"] == len(processing_batch.notifications) - successful
        assert stats["processing_progress"] == 100.0
        assert (
            stats["success_rate"]
            == (successful / len(processing_batch.notifications)) * 100
        )
        assert stats["processing_duration_seconds"] > 0

    def test_get_channel_distribution(self, notification_batch):
        """Test getting channel distribution statistics."""
        # Add notifications for different channels
        channel_counts = {
            NotificationChannel.EMAIL: 5,
            NotificationChannel.SMS: 3,
            NotificationChannel.PUSH: 2,
        }

        for channel, count in channel_counts.items():
            for i in range(count):
                notification_data = {
                    "recipient_id": uuid4(),
                    "channel": channel,
                    "content": {"subject": "Test", "body": "Test"}
                    if channel == NotificationChannel.EMAIL
                    else {"body": "Test"},
                    "recipient_address": f"recipient{i}@example.com"
                    if channel == NotificationChannel.EMAIL
                    else f"+12345678{i:02d}",
                }
                notification_batch.add_notification(notification_data)

        distribution = notification_batch.get_channel_distribution()

        for channel, expected_count in channel_counts.items():
            assert distribution[channel.value] == expected_count

        # Verify percentages
        total = sum(channel_counts.values())
        for channel, count in channel_counts.items():
            expected_percentage = (count / total) * 100
            assert (
                abs(distribution[f"{channel.value}_percentage"] - expected_percentage)
                < 0.01
            )

    def test_get_priority_distribution(self, notification_batch):
        """Test getting priority distribution statistics."""
        # Add notifications with different priorities
        priority_counts = {
            NotificationPriority.LOW: 2,
            NotificationPriority.NORMAL: 5,
            NotificationPriority.HIGH: 2,
            NotificationPriority.URGENT: 1,
        }

        for priority, count in priority_counts.items():
            for i in range(count):
                notification_data = {
                    "recipient_id": uuid4(),
                    "channel": NotificationChannel.EMAIL,
                    "content": {"subject": f"Test {priority.value}", "body": "Test"},
                    "recipient_address": f"user{i}@example.com",
                    "priority": priority,
                }
                notification_batch.add_notification(notification_data)

        distribution = notification_batch.get_priority_distribution()

        for priority, expected_count in priority_counts.items():
            assert distribution[priority.value] == expected_count

    def test_estimate_processing_time(self, notification_batch):
        """Test estimating batch processing time."""
        # Add notifications
        for i in range(100):
            notification_data = {
                "recipient_id": uuid4(),
                "channel": NotificationChannel.EMAIL,
                "content": {"subject": f"Test {i}", "body": "Test"},
                "recipient_address": f"user{i}@example.com",
            }
            notification_batch.add_notification(notification_data)

        # Estimate with default rate
        estimate = notification_batch.estimate_processing_time()
        assert estimate > 0

        # Estimate with custom rate
        custom_estimate = notification_batch.estimate_processing_time(
            notifications_per_second=50
        )
        assert custom_estimate > 0
        assert custom_estimate != estimate  # Should be different with different rate

    def test_get_failure_analysis(self, processing_batch):
        """Test getting failure analysis."""
        # Process notifications with various failures
        error_codes = ["SMTP_TIMEOUT", "INVALID_EMAIL", "SMTP_TIMEOUT", "RATE_LIMIT"]

        for i, notification in enumerate(processing_batch.notifications[:4]):
            processing_batch.mark_notification_processed(
                notification["notification_id"],
                success=False,
                details=f"Failed with {error_codes[i]}",
                error_code=error_codes[i],
            )

        analysis = processing_batch.get_failure_analysis()

        assert "SMTP_TIMEOUT" in analysis["error_codes"]
        assert analysis["error_codes"]["SMTP_TIMEOUT"] == 2
        assert analysis["error_codes"]["INVALID_EMAIL"] == 1
        assert analysis["error_codes"]["RATE_LIMIT"] == 1
        assert analysis["total_failures"] == 4


class TestNotificationBatchMetadata:
    """Test suite for batch metadata management."""

    def test_add_metadata(self, notification_batch):
        """Test adding metadata to batch."""
        notification_batch.add_metadata("campaign_type", "promotional")
        notification_batch.add_metadata("target_audience", "premium_users")

        assert notification_batch.metadata["campaign_type"] == "promotional"
        assert notification_batch.metadata["target_audience"] == "premium_users"

    def test_update_metadata(self, notification_batch):
        """Test updating existing metadata."""
        notification_batch.add_metadata("version", "1.0")
        assert notification_batch.metadata["version"] == "1.0"

        notification_batch.add_metadata("version", "1.1")
        assert notification_batch.metadata["version"] == "1.1"

    def test_remove_metadata(self, notification_batch):
        """Test removing metadata from batch."""
        notification_batch.add_metadata("temporary", "value")
        assert "temporary" in notification_batch.metadata

        notification_batch.remove_metadata("temporary")
        assert "temporary" not in notification_batch.metadata

    def test_remove_nonexistent_metadata_ignored(self, notification_batch):
        """Test removing nonexistent metadata is ignored."""
        # Should not raise error
        notification_batch.remove_metadata("nonexistent")


class TestNotificationBatchEvents:
    """Test suite for batch-related events."""

    def test_batch_created_event_content(self, sample_user_id):
        """Test BatchCreated event contains correct information."""
        template_id = uuid4()
        batch = NotificationBatch(
            name="Event Test Batch",
            template_id=template_id,
            created_by=sample_user_id,
            scheduled_for=datetime.utcnow() + timedelta(hours=1),
            metadata={"test_event": True},
        )

        # Add notifications to set up channels
        for channel in [NotificationChannel.EMAIL, NotificationChannel.SMS]:
            notification_data = {
                "recipient_id": uuid4(),
                "channel": channel,
                "template_id": template_id,
                "content": {"subject": "Test", "body": "Test"}
                if channel == NotificationChannel.EMAIL
                else {"body": "Test"},
                "recipient_address": "test@example.com"
                if channel == NotificationChannel.EMAIL
                else "+1234567890",
            }
            batch.add_notification(notification_data)

        events = batch.get_uncommitted_events()
        creation_event = next((e for e in events if isinstance(e, BatchCreated)), None)

        assert creation_event is not None
        assert creation_event.batch_id == batch.id
        assert creation_event.template_id == template_id
        assert creation_event.total_recipients == 2
        assert creation_event.channels == [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
        ]
        assert creation_event.created_by == sample_user_id
        assert creation_event.scheduled_for is not None

    def test_batch_processed_event_emission(self, processing_batch):
        """Test that BatchProcessed event is emitted on completion."""
        start_time = datetime.utcnow()

        # Process all notifications
        for notification in processing_batch.notifications:
            processing_batch.mark_notification_processed(
                notification["notification_id"],
                success=True,
                details="Successfully processed",
            )

        processing_batch.clear_events()  # Clear previous events
        processing_batch.complete_processing()

        events = processing_batch.get_uncommitted_events()
        processed_event = next(
            (e for e in events if isinstance(e, BatchProcessed)), None
        )

        assert processed_event is not None
        assert processed_event.batch_id == processing_batch.id
        assert processed_event.total_notifications == processing_batch.total_count
        assert processed_event.successful_count == processing_batch.successful_count
        assert processed_event.failed_count == processing_batch.failed_count
        assert processed_event.processing_time_seconds > 0
        assert processed_event.completed_at >= start_time


class TestNotificationBatchComplexScenarios:
    """Test suite for complex batch processing scenarios."""

    def test_large_batch_processing_simulation(self):
        """Test processing a large batch with mixed results."""
        batch = NotificationBatch(
            name="Large Batch Test",
            description="Simulating large batch processing",
            metadata={"size": "large", "test": True},
        )

        # Add 1000 notifications across different channels
        channels = [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
        ]

        for i in range(1000):
            channel = channels[i % 3]
            notification_data = {
                "recipient_id": uuid4(),
                "channel": channel,
                "content": {
                    "subject": f"Large batch notification {i}"
                    if channel == NotificationChannel.EMAIL
                    else None,
                    "body": f"This is notification {i} in the large batch",
                },
                "recipient_address": f"user{i}@example.com"
                if channel == NotificationChannel.EMAIL
                else f"+1234567{i:03d}",
                "priority": NotificationPriority.NORMAL,
                "metadata": {"batch_position": i},
            }

            # Add in smaller chunks to avoid memory issues
            if i % 100 == 0:
                notifications_chunk = []
            notifications_chunk.append(notification_data)

            if i % 100 == 99 or i == 999:
                batch.add_notifications_bulk(notifications_chunk)

        assert batch.total_count == 1000

        # Start processing
        batch.start_processing()
        assert batch.status == BatchStatus.PROCESSING

        # Simulate processing with various outcomes
        success_count = 0
        failure_count = 0

        for i, notification in enumerate(batch.notifications):
            # Simulate 95% success rate
            success = i % 20 != 0  # 19/20 success rate

            batch.mark_notification_processed(
                notification["notification_id"],
                success=success,
                details="Processed successfully" if success else "Processing failed",
                error_code=None if success else f"ERROR_{i % 5}",
            )

            if success:
                success_count += 1
            else:
                failure_count += 1

        # Complete processing
        batch.complete_processing()

        assert batch.status == BatchStatus.PARTIAL  # Some failures
        assert batch.successful_count == success_count
        assert batch.failed_count == failure_count
        assert batch.processed_count == 1000

        # Verify statistics
        stats = batch.get_processing_statistics()
        assert stats["success_rate"] == 95.0  # 19/20 = 95%
        assert stats["processing_progress"] == 100.0

        # Verify channel distribution
        distribution = batch.get_channel_distribution()
        expected_per_channel = 1000 // 3
        for channel in channels:
            # Allow for rounding differences
            assert abs(distribution[channel.value] - expected_per_channel) <= 1

    def test_scheduled_batch_workflow(self):
        """Test complete scheduled batch workflow."""
        batch = NotificationBatch(
            name="Scheduled Marketing Campaign",
            description="Scheduled batch for marketing campaign",
            metadata={"campaign_id": "camp_202312", "type": "marketing"},
        )

        # Add notifications
        for i in range(50):
            notification_data = {
                "recipient_id": uuid4(),
                "channel": NotificationChannel.EMAIL,
                "template_id": uuid4(),
                "content": {
                    "subject": f"Marketing email {i}",
                    "body": f"This is marketing email {i}",
                },
                "recipient_address": f"customer{i}@example.com",
                "priority": NotificationPriority.LOW,
                "variables": {
                    "customer_name": f"Customer {i}",
                    "offer_code": f"SAVE{i:02d}",
                },
            }
            batch.add_notification(notification_data)

        # Schedule for future
        scheduled_time = datetime.utcnow() + timedelta(hours=2)
        batch.schedule_processing(scheduled_time)

        assert batch.scheduled_for == scheduled_time
        assert batch.status == BatchStatus.CREATED

        # Simulate scheduler picking up the batch
        # (In real system, this would be done by a scheduler service)

        # Start processing when scheduled time arrives
        batch.start_processing()
        assert batch.status == BatchStatus.PROCESSING

        # Process all notifications successfully
        for notification in batch.notifications:
            batch.mark_notification_processed(
                notification["notification_id"],
                success=True,
                details="Marketing email sent successfully",
            )

        # Complete processing
        batch.complete_processing()

        assert batch.status == BatchStatus.COMPLETED
        assert batch.successful_count == 50
        assert batch.failed_count == 0

        # Verify final statistics
        stats = batch.get_processing_statistics()
        assert stats["success_rate"] == 100.0
        assert stats["failure_rate"] == 0.0

    def test_batch_failure_recovery_workflow(self):
        """Test batch failure and recovery workflow."""
        batch = NotificationBatch(
            name="Failure Recovery Test",
            description="Testing batch failure and recovery",
        )

        # Add notifications
        for i in range(20):
            notification_data = {
                "recipient_id": uuid4(),
                "channel": NotificationChannel.EMAIL,
                "content": {"subject": f"Test {i}", "body": f"Test {i}"},
                "recipient_address": f"user{i}@example.com",
            }
            batch.add_notification(notification_data)

        # Start processing
        batch.start_processing()

        # Process a few notifications successfully
        for i in range(5):
            batch.mark_notification_processed(
                batch.notifications[i]["notification_id"],
                success=True,
                details="Processed successfully",
            )

        # Simulate system failure
        batch.mark_failed("Email provider service unavailable")

        assert batch.status == BatchStatus.FAILED
        assert batch.successful_count == 5
        assert batch.processed_count == 5
        assert batch.failed_count == 0  # These are unprocessed, not failed

        # Verify failure reason is recorded
        assert hasattr(batch, "failure_reason")
        assert batch.failure_reason == "Email provider service unavailable"
