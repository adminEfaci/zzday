"""Comprehensive tests for notification domain events.

This module tests all domain events emitted by the notification module,
including event validation, payload verification, and event-driven workflows.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.core.events.types import EventMetadata
from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
    TemplateType,
)
from app.modules.notification.domain.events import (  # Batch processing events; Channel management events; Notification lifecycle events; Recipient management events; Template management events
    BatchCreated,
    BatchProcessed,
    ChannelConfigured,
    ChannelDisabled,
    NotificationCreated,
    NotificationDelivered,
    NotificationFailed,
    NotificationRead,
    NotificationScheduled,
    NotificationSent,
    RecipientResubscribed,
    RecipientUnsubscribed,
    TemplateCreated,
    TemplateDeleted,
    TemplateUpdated,
)


class TestNotificationLifecycleEvents:
    """Test suite for notification lifecycle events."""

    def test_notification_created_event_basic(self):
        """Test creating a basic NotificationCreated event."""
        notification_id = uuid4()
        recipient_id = uuid4()

        event = NotificationCreated(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.NORMAL,
        )

        assert event.notification_id == notification_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.EMAIL
        assert event.template_id is None
        assert event.priority == NotificationPriority.NORMAL
        assert event.scheduled_for is None
        assert event.event_type == "NotificationCreated"
        assert event.occurred_at is not None

    def test_notification_created_event_with_template_and_schedule(self):
        """Test NotificationCreated event with template and scheduling."""
        notification_id = uuid4()
        recipient_id = uuid4()
        template_id = uuid4()
        scheduled_for = datetime.utcnow() + timedelta(hours=1)

        metadata = EventMetadata(
            correlation_id=str(uuid4()),
            source_service="notification_service",
            user_id=str(uuid4()),
        )

        event = NotificationCreated(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.PUSH,
            template_id=template_id,
            priority=NotificationPriority.URGENT,
            scheduled_for=scheduled_for,
            metadata=metadata,
        )

        assert event.template_id == template_id
        assert event.priority == NotificationPriority.URGENT
        assert event.scheduled_for == scheduled_for
        assert event.metadata == metadata

    def test_notification_created_event_validation(self):
        """Test NotificationCreated event validation."""
        # Test missing notification_id
        with pytest.raises(ValueError, match="notification_id is required"):
            NotificationCreated(
                notification_id=None,
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
            )

        # Test missing recipient_id
        with pytest.raises(ValueError, match="recipient_id is required"):
            NotificationCreated(
                notification_id=uuid4(),
                recipient_id=None,
                channel=NotificationChannel.EMAIL,
            )

        # Test invalid channel
        with pytest.raises(
            ValueError, match="channel must be a NotificationChannel enum"
        ):
            NotificationCreated(
                notification_id=uuid4(), recipient_id=uuid4(), channel="invalid_channel"
            )

        # Test invalid priority
        with pytest.raises(
            ValueError, match="priority must be a NotificationPriority enum"
        ):
            NotificationCreated(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                priority="invalid_priority",
            )

    def test_notification_sent_event_basic(self):
        """Test creating a basic NotificationSent event."""
        notification_id = uuid4()
        recipient_id = uuid4()
        sent_at = datetime.utcnow()

        event = NotificationSent(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.SMS,
            provider="twilio",
            provider_message_id="sms_123456",
            sent_at=sent_at,
        )

        assert event.notification_id == notification_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.SMS
        assert event.provider == "twilio"
        assert event.provider_message_id == "sms_123456"
        assert event.sent_at == sent_at

    def test_notification_sent_event_auto_timestamp(self):
        """Test NotificationSent event auto-generates timestamp."""
        before_creation = datetime.utcnow()

        event = NotificationSent(
            notification_id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
        )

        after_creation = datetime.utcnow()

        assert before_creation <= event.sent_at <= after_creation

    def test_notification_sent_event_validation(self):
        """Test NotificationSent event validation."""
        # Test missing provider
        with pytest.raises(ValueError, match="provider is required"):
            NotificationSent(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                provider="",
            )

    def test_notification_delivered_event(self):
        """Test NotificationDelivered event."""
        notification_id = uuid4()
        recipient_id = uuid4()
        delivered_at = datetime.utcnow()
        provider_confirmation = {
            "delivery_status": "delivered",
            "delivered_timestamp": "2023-12-25T10:30:00Z",
            "delivery_attempts": 1,
        }

        event = NotificationDelivered(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.PUSH,
            delivered_at=delivered_at,
            provider_confirmation=provider_confirmation,
        )

        assert event.notification_id == notification_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.PUSH
        assert event.delivered_at == delivered_at
        assert event.provider_confirmation == provider_confirmation

    def test_notification_failed_event_basic(self):
        """Test basic NotificationFailed event."""
        notification_id = uuid4()
        recipient_id = uuid4()
        failed_at = datetime.utcnow()

        event = NotificationFailed(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            error_code="SMTP_TIMEOUT",
            error_message="SMTP server connection timeout",
            is_permanent=False,
            retry_count=1,
            will_retry=True,
            failed_at=failed_at,
        )

        assert event.notification_id == notification_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.EMAIL
        assert event.error_code == "SMTP_TIMEOUT"
        assert event.error_message == "SMTP server connection timeout"
        assert event.is_permanent is False
        assert event.retry_count == 1
        assert event.will_retry is True
        assert event.failed_at == failed_at

    def test_notification_failed_event_permanent_failure(self):
        """Test NotificationFailed event with permanent failure."""
        event = NotificationFailed(
            notification_id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.EMAIL,
            error_code="INVALID_EMAIL",
            error_message="Invalid email address format",
            is_permanent=True,
            retry_count=0,
            will_retry=False,  # Should be overridden to False
        )

        assert event.is_permanent is True
        assert event.will_retry is False  # Should be False for permanent failures

    def test_notification_failed_event_validation(self):
        """Test NotificationFailed event validation."""
        # Test missing error_code
        with pytest.raises(ValueError, match="error_code is required"):
            NotificationFailed(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                error_code="",
                error_message="Some error",
            )

        # Test missing error_message
        with pytest.raises(ValueError, match="error_message is required"):
            NotificationFailed(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                error_code="ERROR_CODE",
                error_message="",
            )

    def test_notification_read_event(self):
        """Test NotificationRead event."""
        notification_id = uuid4()
        recipient_id = uuid4()
        read_at = datetime.utcnow()
        client_info = {
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
            "ip_address": "192.168.1.100",
            "platform": "ios",
            "app_version": "2.1.0",
        }

        event = NotificationRead(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.IN_APP,
            read_at=read_at,
            client_info=client_info,
        )

        assert event.notification_id == notification_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.IN_APP
        assert event.read_at == read_at
        assert event.client_info == client_info

    def test_notification_scheduled_event(self):
        """Test NotificationScheduled event."""
        notification_id = uuid4()
        schedule_id = uuid4()
        recipient_id = uuid4()
        scheduled_for = datetime.utcnow() + timedelta(hours=24)

        event = NotificationScheduled(
            notification_id=notification_id,
            schedule_id=schedule_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            scheduled_for=scheduled_for,
            recurrence_rule="FREQ=DAILY;COUNT=5",
        )

        assert event.notification_id == notification_id
        assert event.schedule_id == schedule_id
        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.EMAIL
        assert event.scheduled_for == scheduled_for
        assert event.recurrence_rule == "FREQ=DAILY;COUNT=5"

    def test_notification_scheduled_event_validation(self):
        """Test NotificationScheduled event validation."""
        # Test missing schedule_id
        with pytest.raises(ValueError, match="schedule_id is required"):
            NotificationScheduled(
                notification_id=uuid4(),
                schedule_id=None,
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                scheduled_for=datetime.utcnow() + timedelta(hours=1),
            )

        # Test missing scheduled_for
        with pytest.raises(ValueError, match="scheduled_for is required"):
            NotificationScheduled(
                notification_id=uuid4(),
                schedule_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
                scheduled_for=None,
            )


class TestTemplateManagementEvents:
    """Test suite for template management events."""

    def test_template_created_event(self):
        """Test TemplateCreated event."""
        template_id = uuid4()
        created_by = uuid4()
        channels = [NotificationChannel.EMAIL, NotificationChannel.SMS]

        event = TemplateCreated(
            template_id=template_id,
            name="Welcome Email Template",
            template_type=TemplateType.TRANSACTIONAL,
            channels=channels,
            created_by=created_by,
            is_active=True,
        )

        assert event.template_id == template_id
        assert event.name == "Welcome Email Template"
        assert event.template_type == TemplateType.TRANSACTIONAL
        assert event.channels == channels
        assert event.created_by == created_by
        assert event.is_active is True

    def test_template_created_event_validation(self):
        """Test TemplateCreated event validation."""
        # Test missing template_id
        with pytest.raises(ValueError, match="template_id is required"):
            TemplateCreated(
                template_id=None,
                name="Test Template",
                template_type=TemplateType.TRANSACTIONAL,
                channels=[NotificationChannel.EMAIL],
                created_by=uuid4(),
            )

        # Test missing name
        with pytest.raises(ValueError, match="name is required"):
            TemplateCreated(
                template_id=uuid4(),
                name="",
                template_type=TemplateType.TRANSACTIONAL,
                channels=[NotificationChannel.EMAIL],
                created_by=uuid4(),
            )

        # Test invalid template_type
        with pytest.raises(
            ValueError, match="template_type must be a TemplateType enum"
        ):
            TemplateCreated(
                template_id=uuid4(),
                name="Test Template",
                template_type="invalid_type",
                channels=[NotificationChannel.EMAIL],
                created_by=uuid4(),
            )

        # Test empty channels
        with pytest.raises(ValueError, match="channels list cannot be empty"):
            TemplateCreated(
                template_id=uuid4(),
                name="Test Template",
                template_type=TemplateType.TRANSACTIONAL,
                channels=[],
                created_by=uuid4(),
            )

        # Test invalid channels
        with pytest.raises(
            ValueError, match="all channels must be NotificationChannel enums"
        ):
            TemplateCreated(
                template_id=uuid4(),
                name="Test Template",
                template_type=TemplateType.TRANSACTIONAL,
                channels=["invalid_channel"],
                created_by=uuid4(),
            )

    def test_template_updated_event(self):
        """Test TemplateUpdated event."""
        template_id = uuid4()
        updated_by = uuid4()
        changes = {
            "channel": "email",
            "action": "updated",
            "variable": "user_name",
            "old_value": "string",
            "new_value": "formatted_string",
        }

        event = TemplateUpdated(
            template_id=template_id, updated_by=updated_by, changes=changes, version=3
        )

        assert event.template_id == template_id
        assert event.updated_by == updated_by
        assert event.changes == changes
        assert event.version == 3

    def test_template_updated_event_validation(self):
        """Test TemplateUpdated event validation."""
        # Test invalid version
        with pytest.raises(ValueError, match="version must be positive"):
            TemplateUpdated(
                template_id=uuid4(),
                updated_by=uuid4(),
                changes={"action": "update"},
                version=0,
            )

        # Test empty changes
        with pytest.raises(ValueError, match="changes cannot be empty"):
            TemplateUpdated(
                template_id=uuid4(), updated_by=uuid4(), changes={}, version=2
            )

    def test_template_deleted_event(self):
        """Test TemplateDeleted event."""
        template_id = uuid4()
        deleted_by = uuid4()
        reason = "Template no longer needed"

        event = TemplateDeleted(
            template_id=template_id, deleted_by=deleted_by, reason=reason
        )

        assert event.template_id == template_id
        assert event.deleted_by == deleted_by
        assert event.reason == reason

    def test_template_deleted_event_validation(self):
        """Test TemplateDeleted event validation."""
        # Test missing deleted_by
        with pytest.raises(ValueError, match="deleted_by is required"):
            TemplateDeleted(
                template_id=uuid4(), deleted_by=None, reason="Test deletion"
            )


class TestBatchProcessingEvents:
    """Test suite for batch processing events."""

    def test_batch_created_event(self):
        """Test BatchCreated event."""
        batch_id = uuid4()
        template_id = uuid4()
        created_by = uuid4()
        scheduled_for = datetime.utcnow() + timedelta(hours=2)
        channels = [NotificationChannel.EMAIL, NotificationChannel.SMS]

        event = BatchCreated(
            batch_id=batch_id,
            template_id=template_id,
            total_recipients=150,
            channels=channels,
            created_by=created_by,
            scheduled_for=scheduled_for,
        )

        assert event.batch_id == batch_id
        assert event.template_id == template_id
        assert event.total_recipients == 150
        assert event.channels == channels
        assert event.created_by == created_by
        assert event.scheduled_for == scheduled_for

    def test_batch_created_event_validation(self):
        """Test BatchCreated event validation."""
        # Test invalid total_recipients
        with pytest.raises(ValueError, match="total_recipients must be at least 1"):
            BatchCreated(
                batch_id=uuid4(),
                template_id=uuid4(),
                total_recipients=0,
                channels=[NotificationChannel.EMAIL],
                created_by=uuid4(),
            )

    def test_batch_processed_event(self):
        """Test BatchProcessed event."""
        batch_id = uuid4()
        completed_at = datetime.utcnow()

        event = BatchProcessed(
            batch_id=batch_id,
            total_notifications=100,
            successful_count=95,
            failed_count=5,
            processing_time_seconds=45.7,
            completed_at=completed_at,
        )

        assert event.batch_id == batch_id
        assert event.total_notifications == 100
        assert event.successful_count == 95
        assert event.failed_count == 5
        assert event.processing_time_seconds == 45.7
        assert event.completed_at == completed_at

    def test_batch_processed_event_validation(self):
        """Test BatchProcessed event validation."""
        # Test count mismatch
        with pytest.raises(
            ValueError,
            match="successful_count \\+ failed_count must equal total_notifications",
        ):
            BatchProcessed(
                batch_id=uuid4(),
                total_notifications=100,
                successful_count=60,
                failed_count=30,  # 60 + 30 = 90, not 100
                processing_time_seconds=30.0,
            )

        # Test negative processing time
        with pytest.raises(
            ValueError, match="processing_time_seconds cannot be negative"
        ):
            BatchProcessed(
                batch_id=uuid4(),
                total_notifications=50,
                successful_count=50,
                failed_count=0,
                processing_time_seconds=-5.0,
            )


class TestRecipientManagementEvents:
    """Test suite for recipient management events."""

    def test_recipient_unsubscribed_event_all_channels(self):
        """Test RecipientUnsubscribed event for all channels."""
        recipient_id = uuid4()
        unsubscribed_at = datetime.utcnow()

        event = RecipientUnsubscribed(
            recipient_id=recipient_id,
            channel=None,  # All channels
            template_type=None,  # All types
            reason="User requested global unsubscribe",
            unsubscribed_at=unsubscribed_at,
        )

        assert event.recipient_id == recipient_id
        assert event.channel is None
        assert event.template_type is None
        assert event.reason == "User requested global unsubscribe"
        assert event.unsubscribed_at == unsubscribed_at

    def test_recipient_unsubscribed_event_specific_channel(self):
        """Test RecipientUnsubscribed event for specific channel."""
        recipient_id = uuid4()

        event = RecipientUnsubscribed(
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            template_type=TemplateType.MARKETING,
            reason="Unsubscribed from marketing emails",
        )

        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.EMAIL
        assert event.template_type == TemplateType.MARKETING
        assert event.reason == "Unsubscribed from marketing emails"

    def test_recipient_unsubscribed_event_validation(self):
        """Test RecipientUnsubscribed event validation."""
        # Test invalid channel
        with pytest.raises(
            ValueError, match="channel must be a NotificationChannel enum"
        ):
            RecipientUnsubscribed(recipient_id=uuid4(), channel="invalid_channel")

        # Test invalid template_type
        with pytest.raises(
            ValueError, match="template_type must be a TemplateType enum"
        ):
            RecipientUnsubscribed(recipient_id=uuid4(), template_type="invalid_type")

    def test_recipient_resubscribed_event(self):
        """Test RecipientResubscribed event."""
        recipient_id = uuid4()
        resubscribed_at = datetime.utcnow()

        event = RecipientResubscribed(
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            template_type=TemplateType.MARKETING,
            resubscribed_at=resubscribed_at,
        )

        assert event.recipient_id == recipient_id
        assert event.channel == NotificationChannel.EMAIL
        assert event.template_type == TemplateType.MARKETING
        assert event.resubscribed_at == resubscribed_at


class TestChannelManagementEvents:
    """Test suite for channel management events."""

    def test_channel_configured_event(self):
        """Test ChannelConfigured event."""
        configured_by = uuid4()

        event = ChannelConfigured(
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            configured_by=configured_by,
            is_active=True,
        )

        assert event.channel == NotificationChannel.EMAIL
        assert event.provider == "sendgrid"
        assert event.configured_by == configured_by
        assert event.is_active is True

    def test_channel_configured_event_validation(self):
        """Test ChannelConfigured event validation."""
        # Test missing provider
        with pytest.raises(ValueError, match="provider is required"):
            ChannelConfigured(
                channel=NotificationChannel.EMAIL, provider="", configured_by=uuid4()
            )

        # Test invalid channel
        with pytest.raises(
            ValueError, match="channel must be a NotificationChannel enum"
        ):
            ChannelConfigured(
                channel="invalid_channel", provider="sendgrid", configured_by=uuid4()
            )

    def test_channel_disabled_event(self):
        """Test ChannelDisabled event."""
        disabled_by = uuid4()
        reason = "Provider API key expired"

        event = ChannelDisabled(
            channel=NotificationChannel.SMS, disabled_by=disabled_by, reason=reason
        )

        assert event.channel == NotificationChannel.SMS
        assert event.disabled_by == disabled_by
        assert event.reason == reason

    def test_channel_disabled_event_validation(self):
        """Test ChannelDisabled event validation."""
        # Test missing disabled_by
        with pytest.raises(ValueError, match="disabled_by is required"):
            ChannelDisabled(
                channel=NotificationChannel.SMS, disabled_by=None, reason="Test reason"
            )


class TestEventMetadataAndSerialization:
    """Test suite for event metadata and serialization."""

    def test_event_with_custom_metadata(self):
        """Test event with custom metadata."""
        correlation_id = str(uuid4())
        metadata = EventMetadata(
            correlation_id=correlation_id,
            source_service="notification_api",
            user_id=str(uuid4()),
            tenant_id="tenant_123",
            request_id=str(uuid4()),
            custom_data={"api_version": "v2", "client_type": "mobile"},
        )

        event = NotificationCreated(
            notification_id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.PUSH,
            metadata=metadata,
        )

        assert event.metadata.correlation_id == correlation_id
        assert event.metadata.source_service == "notification_api"
        assert event.metadata.custom_data["api_version"] == "v2"
        assert event.metadata.custom_data["client_type"] == "mobile"

    def test_event_auto_metadata_generation(self):
        """Test that events auto-generate required metadata."""
        event = NotificationSent(
            notification_id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
        )

        # Events should have basic metadata
        assert event.event_id is not None
        assert event.event_type == "NotificationSent"
        assert event.occurred_at is not None
        assert event.schema_version is not None

    def test_event_validation_edge_cases(self):
        """Test event validation edge cases."""
        # Test very long strings (should be handled gracefully)
        long_string = "A" * 1000

        event = NotificationFailed(
            notification_id=uuid4(),
            recipient_id=uuid4(),
            channel=NotificationChannel.EMAIL,
            error_code="LONG_ERROR",
            error_message=long_string,  # Very long error message
        )

        assert len(event.error_message) == 1000

        # Test special characters in strings
        special_chars = "Test with émojis 🚀 and special chars: <>&'\"àáâãäåæçèéêë"

        event = TemplateCreated(
            template_id=uuid4(),
            name=special_chars,
            template_type=TemplateType.TRANSACTIONAL,
            channels=[NotificationChannel.EMAIL],
            created_by=uuid4(),
        )

        assert event.name == special_chars

    def test_event_timestamp_consistency(self):
        """Test event timestamp consistency."""
        before_events = datetime.utcnow()

        # Create multiple events in sequence
        events = []
        for i in range(5):
            event = NotificationCreated(
                notification_id=uuid4(),
                recipient_id=uuid4(),
                channel=NotificationChannel.EMAIL,
            )
            events.append(event)

        after_events = datetime.utcnow()

        # All events should have timestamps within the test window
        for event in events:
            assert before_events <= event.occurred_at <= after_events

        # Events should have chronological ordering (or very close)
        for i in range(1, len(events)):
            assert events[i].occurred_at >= events[i - 1].occurred_at


class TestEventDrivenWorkflows:
    """Test suite for event-driven workflow scenarios."""

    def test_notification_lifecycle_event_sequence(self):
        """Test complete notification lifecycle event sequence."""
        notification_id = uuid4()
        recipient_id = uuid4()
        template_id = uuid4()

        # 1. Notification created
        created_event = NotificationCreated(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            template_id=template_id,
            priority=NotificationPriority.HIGH,
        )

        # 2. Notification sent
        sent_event = NotificationSent(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            provider="sendgrid",
            provider_message_id="sg_123456",
        )

        # 3. Notification delivered
        delivered_event = NotificationDelivered(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            provider_confirmation={"status": "delivered"},
        )

        # 4. Notification read
        read_event = NotificationRead(
            notification_id=notification_id,
            recipient_id=recipient_id,
            channel=NotificationChannel.EMAIL,
            client_info={"platform": "web"},
        )

        event_sequence = [created_event, sent_event, delivered_event, read_event]

        # Verify event sequence consistency
        assert all(event.notification_id == notification_id for event in event_sequence)
        assert all(event.recipient_id == recipient_id for event in event_sequence)
        assert all(
            event.channel == NotificationChannel.EMAIL for event in event_sequence
        )

        # Verify chronological ordering
        for i in range(1, len(event_sequence)):
            assert event_sequence[i].occurred_at >= event_sequence[i - 1].occurred_at

    def test_template_evolution_event_sequence(self):
        """Test template evolution through events."""
        template_id = uuid4()
        user_id = uuid4()

        # 1. Template created
        created_event = TemplateCreated(
            template_id=template_id,
            name="Evolution Test Template",
            template_type=TemplateType.TRANSACTIONAL,
            channels=[NotificationChannel.EMAIL],
            created_by=user_id,
        )

        # 2. Template updated - add SMS channel
        update1_event = TemplateUpdated(
            template_id=template_id,
            updated_by=user_id,
            changes={"channel": "sms", "action": "added"},
            version=2,
        )

        # 3. Template updated - add variable
        update2_event = TemplateUpdated(
            template_id=template_id,
            updated_by=user_id,
            changes={"variable": "user_name", "action": "defined", "type": "string"},
            version=3,
        )

        # 4. Template updated - modify content
        update3_event = TemplateUpdated(
            template_id=template_id,
            updated_by=user_id,
            changes={"channel": "email", "action": "updated", "field": "subject"},
            version=4,
        )

        # 5. Template deleted
        deleted_event = TemplateDeleted(
            template_id=template_id, deleted_by=user_id, reason="No longer needed"
        )

        evolution_events = [
            created_event,
            update1_event,
            update2_event,
            update3_event,
            deleted_event,
        ]

        # Verify template evolution consistency
        assert all(
            event.template_id == template_id
            for event in evolution_events
            if hasattr(event, "template_id")
        )
        assert all(
            event.updated_by == user_id
            for event in evolution_events
            if hasattr(event, "updated_by")
        )
        assert all(
            event.deleted_by == user_id
            for event in evolution_events
            if hasattr(event, "deleted_by")
        )

        # Verify version progression
        update_events = [update1_event, update2_event, update3_event]
        for i, event in enumerate(update_events, 2):
            assert event.version == i

    def test_batch_processing_event_workflow(self):
        """Test batch processing event workflow."""
        batch_id = uuid4()
        template_id = uuid4()
        created_by = uuid4()

        # 1. Batch created
        created_event = BatchCreated(
            batch_id=batch_id,
            template_id=template_id,
            total_recipients=1000,
            channels=[NotificationChannel.EMAIL, NotificationChannel.SMS],
            created_by=created_by,
            scheduled_for=datetime.utcnow() + timedelta(hours=1),
        )

        # 2. Individual notifications created (simulate with events)
        notification_events = []
        for i in range(5):  # Sample of notifications
            notification_id = uuid4()
            recipient_id = uuid4()

            notification_created = NotificationCreated(
                notification_id=notification_id,
                recipient_id=recipient_id,
                channel=NotificationChannel.EMAIL,
                template_id=template_id,
                metadata=EventMetadata(
                    correlation_id=str(batch_id),  # Link to batch
                    custom_data={"batch_id": str(batch_id), "batch_position": i},
                ),
            )
            notification_events.append(notification_created)

        # 3. Batch processed
        processed_event = BatchProcessed(
            batch_id=batch_id,
            total_notifications=1000,
            successful_count=980,
            failed_count=20,
            processing_time_seconds=125.5,
        )

        # Verify batch workflow consistency
        assert created_event.batch_id == batch_id
        assert created_event.template_id == template_id
        assert processed_event.batch_id == batch_id

        # Verify notification events are linked to batch
        for notification_event in notification_events:
            assert notification_event.template_id == template_id
            assert notification_event.metadata.correlation_id == str(batch_id)
            assert notification_event.metadata.custom_data["batch_id"] == str(batch_id)

        # Verify processing results
        assert processed_event.successful_count + processed_event.failed_count == 1000
        assert processed_event.processing_time_seconds > 0
