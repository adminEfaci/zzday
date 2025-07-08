"""Notification domain events.

This module contains all domain events emitted by the notification module,
enabling event-driven communication with other modules.
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.core.events.types import DomainEvent, EventMetadata
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    TemplateType,
)


class NotificationCreated(DomainEvent):
    """Emitted when a new notification is created."""

    def __init__(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        template_id: UUID | None = None,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        scheduled_for: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.template_id = template_id
        self.priority = priority
        self.scheduled_for = scheduled_for

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not isinstance(self.priority, NotificationPriority):
            raise ValueError("priority must be a NotificationPriority enum")


class NotificationSent(DomainEvent):
    """Emitted when a notification is successfully sent to provider."""

    def __init__(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        provider: str,
        provider_message_id: str | None = None,
        sent_at: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.provider = provider
        self.provider_message_id = provider_message_id
        self.sent_at = sent_at or datetime.utcnow()

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not self.provider:
            raise ValueError("provider is required")


class NotificationDelivered(DomainEvent):
    """Emitted when a notification is confirmed delivered."""

    def __init__(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        delivered_at: datetime | None = None,
        provider_confirmation: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.delivered_at = delivered_at or datetime.utcnow()
        self.provider_confirmation = provider_confirmation or {}

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")


class NotificationFailed(DomainEvent):
    """Emitted when notification delivery fails."""

    def __init__(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        error_code: str,
        error_message: str,
        is_permanent: bool = False,
        retry_count: int = 0,
        will_retry: bool = True,
        failed_at: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.error_code = error_code
        self.error_message = error_message
        self.is_permanent = is_permanent
        self.retry_count = retry_count
        self.will_retry = will_retry and not is_permanent
        self.failed_at = failed_at or datetime.utcnow()

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not self.error_code:
            raise ValueError("error_code is required")
        if not self.error_message:
            raise ValueError("error_message is required")


class NotificationRead(DomainEvent):
    """Emitted when a notification is read by recipient."""

    def __init__(
        self,
        notification_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        read_at: datetime | None = None,
        client_info: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.read_at = read_at or datetime.utcnow()
        self.client_info = client_info or {}

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")


class NotificationScheduled(DomainEvent):
    """Emitted when a notification is scheduled for future delivery."""

    def __init__(
        self,
        notification_id: UUID,
        schedule_id: UUID,
        recipient_id: UUID,
        channel: NotificationChannel,
        scheduled_for: datetime,
        recurrence_rule: str | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.notification_id = notification_id
        self.schedule_id = schedule_id
        self.recipient_id = recipient_id
        self.channel = channel
        self.scheduled_for = scheduled_for
        self.recurrence_rule = recurrence_rule

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.notification_id:
            raise ValueError("notification_id is required")
        if not self.schedule_id:
            raise ValueError("schedule_id is required")
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not self.scheduled_for:
            raise ValueError("scheduled_for is required")


class TemplateCreated(DomainEvent):
    """Emitted when a notification template is created."""

    def __init__(
        self,
        template_id: UUID,
        name: str,
        template_type: TemplateType,
        channels: list[NotificationChannel],
        created_by: UUID,
        is_active: bool = True,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.template_id = template_id
        self.name = name
        self.template_type = template_type
        self.channels = channels
        self.created_by = created_by
        self.is_active = is_active

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.template_id:
            raise ValueError("template_id is required")
        if not self.name:
            raise ValueError("name is required")
        if not isinstance(self.template_type, TemplateType):
            raise ValueError("template_type must be a TemplateType enum")
        if not self.channels:
            raise ValueError("channels list cannot be empty")
        if not all(isinstance(ch, NotificationChannel) for ch in self.channels):
            raise ValueError("all channels must be NotificationChannel enums")
        if not self.created_by:
            raise ValueError("created_by is required")


class TemplateUpdated(DomainEvent):
    """Emitted when a notification template is updated."""

    def __init__(
        self,
        template_id: UUID,
        updated_by: UUID,
        changes: dict[str, Any],
        version: int,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.template_id = template_id
        self.updated_by = updated_by
        self.changes = changes
        self.version = version

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.template_id:
            raise ValueError("template_id is required")
        if not self.updated_by:
            raise ValueError("updated_by is required")
        if not self.changes:
            raise ValueError("changes cannot be empty")
        if self.version < 1:
            raise ValueError("version must be positive")


class TemplateDeleted(DomainEvent):
    """Emitted when a notification template is deleted."""

    def __init__(
        self,
        template_id: UUID,
        deleted_by: UUID,
        reason: str | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.template_id = template_id
        self.deleted_by = deleted_by
        self.reason = reason

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.template_id:
            raise ValueError("template_id is required")
        if not self.deleted_by:
            raise ValueError("deleted_by is required")


class BatchCreated(DomainEvent):
    """Emitted when a notification batch is created."""

    def __init__(
        self,
        batch_id: UUID,
        template_id: UUID,
        total_recipients: int,
        channels: list[NotificationChannel],
        created_by: UUID,
        scheduled_for: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.batch_id = batch_id
        self.template_id = template_id
        self.total_recipients = total_recipients
        self.channels = channels
        self.created_by = created_by
        self.scheduled_for = scheduled_for

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.batch_id:
            raise ValueError("batch_id is required")
        if not self.template_id:
            raise ValueError("template_id is required")
        if self.total_recipients < 1:
            raise ValueError("total_recipients must be at least 1")
        if not self.channels:
            raise ValueError("channels list cannot be empty")
        if not all(isinstance(ch, NotificationChannel) for ch in self.channels):
            raise ValueError("all channels must be NotificationChannel enums")
        if not self.created_by:
            raise ValueError("created_by is required")


class BatchProcessed(DomainEvent):
    """Emitted when a notification batch processing is completed."""

    def __init__(
        self,
        batch_id: UUID,
        total_notifications: int,
        successful_count: int,
        failed_count: int,
        processing_time_seconds: float,
        completed_at: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.batch_id = batch_id
        self.total_notifications = total_notifications
        self.successful_count = successful_count
        self.failed_count = failed_count
        self.processing_time_seconds = processing_time_seconds
        self.completed_at = completed_at or datetime.utcnow()

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.batch_id:
            raise ValueError("batch_id is required")
        if self.total_notifications < 0:
            raise ValueError("total_notifications cannot be negative")
        if self.successful_count < 0:
            raise ValueError("successful_count cannot be negative")
        if self.failed_count < 0:
            raise ValueError("failed_count cannot be negative")
        if self.successful_count + self.failed_count != self.total_notifications:
            raise ValueError(
                "successful_count + failed_count must equal total_notifications"
            )
        if self.processing_time_seconds < 0:
            raise ValueError("processing_time_seconds cannot be negative")


class RecipientUnsubscribed(DomainEvent):
    """Emitted when a recipient unsubscribes from notifications."""

    def __init__(
        self,
        recipient_id: UUID,
        channel: NotificationChannel | None = None,
        template_type: TemplateType | None = None,
        reason: str | None = None,
        unsubscribed_at: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.recipient_id = recipient_id
        self.channel = channel  # None means all channels
        self.template_type = template_type  # None means all types
        self.reason = reason
        self.unsubscribed_at = unsubscribed_at or datetime.utcnow()

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if self.channel and not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if self.template_type and not isinstance(self.template_type, TemplateType):
            raise ValueError("template_type must be a TemplateType enum")


class RecipientResubscribed(DomainEvent):
    """Emitted when a recipient resubscribes to notifications."""

    def __init__(
        self,
        recipient_id: UUID,
        channel: NotificationChannel | None = None,
        template_type: TemplateType | None = None,
        resubscribed_at: datetime | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.recipient_id = recipient_id
        self.channel = channel  # None means all channels
        self.template_type = template_type  # None means all types
        self.resubscribed_at = resubscribed_at or datetime.utcnow()

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.recipient_id:
            raise ValueError("recipient_id is required")
        if self.channel and not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if self.template_type and not isinstance(self.template_type, TemplateType):
            raise ValueError("template_type must be a TemplateType enum")


class ChannelConfigured(DomainEvent):
    """Emitted when a notification channel is configured."""

    def __init__(
        self,
        channel: NotificationChannel,
        provider: str,
        configured_by: UUID,
        is_active: bool = True,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.channel = channel
        self.provider = provider
        self.configured_by = configured_by
        self.is_active = is_active

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not self.provider:
            raise ValueError("provider is required")
        if not self.configured_by:
            raise ValueError("configured_by is required")


class ChannelDisabled(DomainEvent):
    """Emitted when a notification channel is disabled."""

    def __init__(
        self,
        channel: NotificationChannel,
        disabled_by: UUID,
        reason: str | None = None,
        metadata: EventMetadata | None = None,
        **kwargs,
    ):
        super().__init__(metadata=metadata, **kwargs)
        self.channel = channel
        self.disabled_by = disabled_by
        self.reason = reason

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError("channel must be a NotificationChannel enum")
        if not self.disabled_by:
            raise ValueError("disabled_by is required")


# Register all events with the event factory
from app.core.events.types import EventFactory

# Notification lifecycle events
EventFactory.register_event_type(NotificationCreated)
EventFactory.register_event_type(NotificationSent)
EventFactory.register_event_type(NotificationDelivered)
EventFactory.register_event_type(NotificationFailed)
EventFactory.register_event_type(NotificationRead)
EventFactory.register_event_type(NotificationScheduled)

# Template management events
EventFactory.register_event_type(TemplateCreated)
EventFactory.register_event_type(TemplateUpdated)
EventFactory.register_event_type(TemplateDeleted)

# Batch processing events
EventFactory.register_event_type(BatchCreated)
EventFactory.register_event_type(BatchProcessed)

# Recipient management events
EventFactory.register_event_type(RecipientUnsubscribed)
EventFactory.register_event_type(RecipientResubscribed)

# Channel management events
EventFactory.register_event_type(ChannelConfigured)
EventFactory.register_event_type(ChannelDisabled)


# Export all events
__all__ = [
    # Batch processing
    "BatchCreated",
    "BatchProcessed",
    # Channel management
    "ChannelConfigured",
    "ChannelDisabled",
    # Notification lifecycle
    "NotificationCreated",
    "NotificationDelivered",
    "NotificationFailed",
    "NotificationRead",
    "NotificationScheduled",
    "NotificationSent",
    "RecipientResubscribed",
    # Recipient management
    "RecipientUnsubscribed",
    # Template management
    "TemplateCreated",
    "TemplateDeleted",
    "TemplateUpdated",
]
