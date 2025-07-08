"""Notification domain enums.

This module contains all enumeration types used in the notification domain,
providing type-safe constants for notification channels, priorities, statuses,
and template types.
"""

from enum import Enum
from typing import Any


class NotificationChannel(Enum):
    """Available notification delivery channels."""

    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"

    def is_external(self) -> bool:
        """Check if this is an external channel requiring third-party integration."""
        return self in [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
        ]

    def requires_address(self) -> bool:
        """Check if this channel requires a recipient address."""
        return self in [
            NotificationChannel.EMAIL,
            NotificationChannel.SMS,
            NotificationChannel.PUSH,
        ]

    def supports_rich_content(self) -> bool:
        """Check if this channel supports rich HTML content."""
        return self in [NotificationChannel.EMAIL, NotificationChannel.IN_APP]

    def supports_attachments(self) -> bool:
        """Check if this channel supports file attachments."""
        return self == NotificationChannel.EMAIL

    def max_content_length(self) -> int:
        """Get maximum content length for this channel."""
        if self == NotificationChannel.SMS:
            return 160  # Standard SMS length
        if self == NotificationChannel.PUSH:
            return 256  # Typical push notification limit
        return 100000  # 100KB for email and in-app


class NotificationPriority(Enum):
    """Notification priority levels for processing and delivery."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

    def processing_weight(self) -> int:
        """Get processing weight for queue prioritization."""
        weights = {
            NotificationPriority.LOW: 1,
            NotificationPriority.NORMAL: 5,
            NotificationPriority.HIGH: 10,
            NotificationPriority.URGENT: 100,
        }
        return weights[self]

    def max_retry_attempts(self) -> int:
        """Get maximum retry attempts based on priority."""
        attempts = {
            NotificationPriority.LOW: 1,
            NotificationPriority.NORMAL: 3,
            NotificationPriority.HIGH: 5,
            NotificationPriority.URGENT: 10,
        }
        return attempts[self]

    def retry_delay_seconds(self) -> int:
        """Get retry delay in seconds based on priority."""
        delays = {
            NotificationPriority.LOW: 3600,  # 1 hour
            NotificationPriority.NORMAL: 900,  # 15 minutes
            NotificationPriority.HIGH: 300,  # 5 minutes
            NotificationPriority.URGENT: 60,  # 1 minute
        }
        return delays[self]


class DeliveryStatus(Enum):
    """Notification delivery status tracking."""

    PENDING = "pending"
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"
    READ = "read"
    CANCELLED = "cancelled"

    def is_final(self) -> bool:
        """Check if this is a final status (no further processing needed)."""
        return self in [
            DeliveryStatus.DELIVERED,
            DeliveryStatus.FAILED,
            DeliveryStatus.BOUNCED,
            DeliveryStatus.READ,
            DeliveryStatus.CANCELLED,
        ]

    def is_successful(self) -> bool:
        """Check if this status indicates successful delivery."""
        return self in [DeliveryStatus.DELIVERED, DeliveryStatus.READ]

    def is_retryable(self) -> bool:
        """Check if notifications with this status can be retried."""
        return self in [DeliveryStatus.FAILED, DeliveryStatus.BOUNCED]

    def can_transition_to(self, new_status: "DeliveryStatus") -> bool:
        """Check if transition to new status is valid."""
        valid_transitions: dict[DeliveryStatus, list[DeliveryStatus]] = {
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
        return new_status in valid_transitions.get(self, [])


class TemplateType(Enum):
    """Notification template types for categorization and processing rules."""

    TRANSACTIONAL = "transactional"
    MARKETING = "marketing"
    SYSTEM = "system"
    ALERT = "alert"

    def requires_unsubscribe(self) -> bool:
        """Check if this template type requires unsubscribe option."""
        return self == TemplateType.MARKETING

    def allows_batching(self) -> bool:
        """Check if notifications of this type can be batched."""
        return self in [TemplateType.MARKETING, TemplateType.SYSTEM]

    def default_priority(self) -> NotificationPriority:
        """Get default priority for this template type."""
        priorities = {
            TemplateType.TRANSACTIONAL: NotificationPriority.HIGH,
            TemplateType.MARKETING: NotificationPriority.LOW,
            TemplateType.SYSTEM: NotificationPriority.NORMAL,
            TemplateType.ALERT: NotificationPriority.URGENT,
        }
        return priorities[self]

    def retention_days(self) -> int:
        """Get retention period in days for notifications of this type."""
        retention = {
            TemplateType.TRANSACTIONAL: 365,  # 1 year
            TemplateType.MARKETING: 90,  # 3 months
            TemplateType.SYSTEM: 180,  # 6 months
            TemplateType.ALERT: 30,  # 1 month
        }
        return retention[self]


class BatchStatus(Enum):
    """Notification batch processing status."""

    CREATED = "created"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"

    def is_final(self) -> bool:
        """Check if this is a final batch status."""
        return self in [
            BatchStatus.COMPLETED,
            BatchStatus.FAILED,
            BatchStatus.CANCELLED,
        ]

    def can_add_notifications(self) -> bool:
        """Check if notifications can still be added to batch."""
        return self == BatchStatus.CREATED


class ChannelStatus(Enum):
    """Notification channel configuration status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    CONFIGURING = "configuring"
    ERROR = "error"

    def is_operational(self) -> bool:
        """Check if channel is operational for sending."""
        return self == ChannelStatus.ACTIVE


class RecipientStatus(Enum):
    """Recipient status for notification delivery."""

    ACTIVE = "active"
    UNSUBSCRIBED = "unsubscribed"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    SUPPRESSED = "suppressed"

    def can_receive_notifications(self) -> bool:
        """Check if recipient can receive notifications."""
        return self == RecipientStatus.ACTIVE

    def is_permanently_blocked(self) -> bool:
        """Check if recipient is permanently blocked."""
        return self in [RecipientStatus.COMPLAINED, RecipientStatus.SUPPRESSED]


class ScheduleStatus(Enum):
    """Notification schedule status."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

    def is_executable(self) -> bool:
        """Check if schedule can be executed."""
        return self == ScheduleStatus.ACTIVE

    def is_final(self) -> bool:
        """Check if this is a final schedule status."""
        return self in [
            ScheduleStatus.COMPLETED,
            ScheduleStatus.CANCELLED,
            ScheduleStatus.EXPIRED,
        ]


class VariableType(Enum):
    """Template variable types for validation and formatting."""

    STRING = "string"
    NUMBER = "number"
    DATE = "date"
    DATETIME = "datetime"
    BOOLEAN = "boolean"
    URL = "url"
    EMAIL = "email"
    CURRENCY = "currency"

    def validate_value(self, value: Any) -> bool:
        """Basic validation for variable values."""
        if self == VariableType.STRING:
            return isinstance(value, str)
        if self == VariableType.NUMBER:
            return isinstance(value, int | float)
        if self == VariableType.BOOLEAN:
            return isinstance(value, bool)
        if self in [VariableType.DATE, VariableType.DATETIME]:
            return isinstance(value, str)  # Should be ISO format
        if self == VariableType.URL:
            return isinstance(value, str) and (
                str(value).startswith("http://") or str(value).startswith("https://")
            )
        if self == VariableType.EMAIL:
            return isinstance(value, str) and "@" in str(value)
        if self == VariableType.CURRENCY:
            return isinstance(value, int | float)
        return False


# Export all enums
__all__: list[str] = [
    "BatchStatus",
    "ChannelStatus",
    "DeliveryStatus",
    "NotificationChannel",
    "NotificationPriority",
    "RecipientStatus",
    "ScheduleStatus",
    "TemplateType",
    "VariableType",
]
