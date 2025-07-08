"""Notification entity representing an individual notification instance.

This entity manages the lifecycle of a single notification, tracking its
delivery status, content, and processing history.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import ValidationError
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
    DeliveryStatusValue,
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
)

# Constants
MAX_RETRY_DELAY_SECONDS = 3600  # 1 hour


class Notification(Entity):
    """Individual notification instance with delivery tracking.

    This entity represents a single notification that will be or has been
    delivered to a recipient through a specific channel. It tracks the
    complete lifecycle from creation through delivery or failure.
    """

    def __init__(
        self,
        recipient_id: UUID,
        channel: NotificationChannel,
        content: NotificationContent,
        recipient_address: RecipientAddress,
        template_id: UUID | None = None,
        priority: NotificationPriorityValue | None = None,
        expires_at: datetime | None = None,
        idempotency_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize notification entity.

        Args:
            recipient_id: ID of the recipient user
            channel: Delivery channel
            content: Notification content
            recipient_address: Channel-specific recipient address
            template_id: ID of template used (if any)
            priority: Notification priority
            expires_at: When notification expires
            idempotency_key: Key for duplicate prevention
            metadata: Additional notification metadata
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Required fields
        self.recipient_id = self._validate_recipient_id(recipient_id)
        self.channel = self._validate_channel(channel)
        self.content = self._validate_content(content)
        self.recipient_address = self._validate_recipient_address(
            recipient_address, channel
        )

        # Optional fields
        self.template_id = template_id
        self.priority = priority or NotificationPriorityValue(
            level=NotificationPriority.NORMAL
        )
        self.expires_at = expires_at
        self.idempotency_key = idempotency_key
        self.metadata = metadata or {}

        # Delivery tracking
        self.status_history: list[DeliveryStatusValue] = [
            DeliveryStatusValue(
                status=DeliveryStatus.PENDING,
                timestamp=self.created_at,
                details="Notification created",
            )
        ]

        # Processing fields
        self.scheduled_for: datetime | None = None
        self.sent_at: datetime | None = None
        self.delivered_at: datetime | None = None
        self.read_at: datetime | None = None
        self.failed_at: datetime | None = None

        # Provider tracking
        self.provider: str | None = None
        self.provider_message_id: str | None = None
        self.provider_response: dict[str, Any] | None = None

        # Retry tracking
        self.retry_count: int = 0
        self.max_retries: int = self.priority.level.max_retry_attempts()
        self.next_retry_at: datetime | None = None

    def _validate_recipient_id(self, recipient_id: UUID) -> UUID:
        """Validate recipient ID."""
        if not recipient_id:
            raise ValidationError("Recipient ID is required")
        return recipient_id

    def _validate_channel(self, channel: NotificationChannel) -> NotificationChannel:
        """Validate notification channel."""
        if not isinstance(channel, NotificationChannel):
            raise InvalidChannelError(
                channel=str(channel),
                available_channels=[ch.value for ch in NotificationChannel],
            )
        return channel

    def _validate_content(self, content: NotificationContent) -> NotificationContent:
        """Validate notification content."""
        if not isinstance(content, NotificationContent):
            raise ValidationError("Content must be a NotificationContent instance")

        # Validate content for channel
        if self.channel == NotificationChannel.EMAIL and not content.subject:
            raise ValidationError("Email notifications require a subject")

        # Get channel-optimized content
        return content.for_channel(self.channel)

    def _validate_recipient_address(
        self, address: RecipientAddress, channel: NotificationChannel
    ) -> RecipientAddress:
        """Validate recipient address matches channel."""
        if not isinstance(address, RecipientAddress):
            raise ValidationError(
                "Recipient address must be a RecipientAddress instance"
            )

        if address.channel != channel:
            raise ValidationError(
                f"Recipient address channel {address.channel.value} "
                f"does not match notification channel {channel.value}"
            )

        return address

    @property
    def current_status(self) -> DeliveryStatus:
        """Get current delivery status."""
        return (
            self.status_history[-1].status
            if self.status_history
            else DeliveryStatus.PENDING
        )

    @property
    def is_final(self) -> bool:
        """Check if notification is in final state."""
        return self.current_status.is_final()

    @property
    def is_successful(self) -> bool:
        """Check if notification was successfully delivered."""
        return self.current_status.is_successful()

    @property
    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def can_retry(self) -> bool:
        """Check if notification can be retried."""
        return (
            self.current_status.is_retryable()
            and self.retry_count < self.max_retries
            and not self.is_expired
        )

    def update_status(
        self,
        new_status: DeliveryStatus,
        details: str | None = None,
        provider_message_id: str | None = None,
        provider_status: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Update notification delivery status.

        Args:
            new_status: New delivery status
            details: Human-readable status details
            provider_message_id: Message ID from provider
            provider_status: Raw status from provider
            error_code: Error code if failed

        Raises:
            ValidationError: If status transition is invalid
        """
        current_status = self.current_status

        # Validate status transition
        if not current_status.can_transition_to(new_status):
            raise ValidationError(
                f"Cannot transition from {current_status.value} to {new_status.value}"
            )

        # Check expiration for non-final statuses
        if not new_status.is_final() and self.is_expired:
            raise NotificationExpiredError(
                notification_id=self.id, expired_at=self.expires_at.isoformat()
            )

        # Create new status value
        status_value = DeliveryStatusValue(
            status=new_status,
            timestamp=datetime.utcnow(),
            details=details,
            provider_message_id=provider_message_id or self.provider_message_id,
            provider_status=provider_status,
            error_code=error_code,
            retry_count=self.retry_count,
        )

        # Add to history
        self.status_history.append(status_value)

        # Update provider message ID if provided
        if provider_message_id:
            self.provider_message_id = provider_message_id

        # Update timestamps based on status
        if new_status == DeliveryStatus.SENT:
            self.sent_at = status_value.timestamp
        elif new_status == DeliveryStatus.DELIVERED:
            self.delivered_at = status_value.timestamp
        elif new_status == DeliveryStatus.READ:
            self.read_at = status_value.timestamp
        elif new_status == DeliveryStatus.FAILED:
            self.failed_at = status_value.timestamp

        self.mark_modified()

    def schedule(self, scheduled_for: datetime) -> None:
        """Schedule notification for future delivery.

        Args:
            scheduled_for: When to deliver the notification

        Raises:
            ValidationError: If scheduling is invalid
        """
        if self.current_status != DeliveryStatus.PENDING:
            raise ValidationError(
                f"Cannot schedule notification in {self.current_status.value} status"
            )

        if scheduled_for <= datetime.utcnow():
            raise ValidationError("Scheduled time must be in the future")

        if self.expires_at and scheduled_for > self.expires_at:
            raise ValidationError("Cannot schedule notification after expiration")

        self.scheduled_for = scheduled_for
        self.mark_modified()

    def mark_for_retry(self, delay_seconds: int | None = None) -> None:
        """Mark notification for retry.

        Args:
            delay_seconds: Delay before retry (uses priority default if not specified)

        Raises:
            ValidationError: If retry is not allowed
        """
        if not self.can_retry:
            raise ValidationError("Notification cannot be retried")

        # Use priority-based delay if not specified
        if delay_seconds is None:
            delay_seconds = self.priority.level.retry_delay_seconds()

        # Calculate exponential backoff
        backoff_multiplier = 2**self.retry_count
        actual_delay = min(delay_seconds * backoff_multiplier, MAX_RETRY_DELAY_SECONDS)

        self.retry_count += 1
        self.next_retry_at = datetime.utcnow() + timedelta(seconds=actual_delay)

        # Update status to queued for retry
        self.update_status(
            DeliveryStatus.QUEUED,
            details=f"Scheduled for retry #{self.retry_count} at {self.next_retry_at.isoformat()}",
        )

    def set_provider_info(
        self, provider: str, provider_response: dict[str, Any] | None = None
    ) -> None:
        """Set provider information.

        Args:
            provider: Provider name
            provider_response: Raw response from provider
        """
        self.provider = provider
        if provider_response:
            self.provider_response = provider_response
        self.mark_modified()

    def cancel(self, reason: str | None = None) -> None:
        """Cancel notification.

        Args:
            reason: Cancellation reason

        Raises:
            ValidationError: If notification cannot be cancelled
        """
        if self.is_final:
            raise ValidationError(
                f"Cannot cancel notification in {self.current_status.value} status"
            )

        self.update_status(
            DeliveryStatus.CANCELLED, details=reason or "Notification cancelled"
        )

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to notification.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
        self.mark_modified()

    def get_delivery_duration(self) -> timedelta | None:
        """Get time taken for delivery."""
        if self.sent_at and self.delivered_at:
            return self.delivered_at - self.sent_at
        return None

    def get_processing_duration(self) -> timedelta | None:
        """Get total processing time."""
        if self.delivered_at:
            return self.delivered_at - self.created_at
        if self.failed_at:
            return self.failed_at - self.created_at
        return None

    def to_delivery_summary(self) -> dict[str, Any]:
        """Get delivery summary for reporting."""
        return {
            "notification_id": str(self.id),
            "recipient_id": str(self.recipient_id),
            "channel": self.channel.value,
            "status": self.current_status.value,
            "created_at": self.created_at.isoformat(),
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "delivered_at": self.delivered_at.isoformat()
            if self.delivered_at
            else None,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
            "retry_count": self.retry_count,
            "provider": self.provider,
            "provider_message_id": self.provider_message_id,
            "delivery_duration_seconds": (
                self.get_delivery_duration().total_seconds()
                if self.get_delivery_duration()
                else None
            ),
            "processing_duration_seconds": (
                self.get_processing_duration().total_seconds()
                if self.get_processing_duration()
                else None
            ),
        }

    def __str__(self) -> str:
        """String representation."""
        return (
            f"Notification({self.id}) to {self.recipient_address} "
            f"via {self.channel.value} - {self.current_status.value}"
        )
