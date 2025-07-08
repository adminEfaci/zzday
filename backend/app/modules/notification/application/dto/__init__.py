"""Notification application DTOs.

This module contains Data Transfer Objects used in the notification application layer
for transferring data between layers and external systems.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.modules.notification.domain.enums import (
    BatchStatus,
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    TemplateType,
)


@dataclass(frozen=True)
class NotificationRequestDTO:
    """DTO for notification request."""

    recipient_id: UUID
    channel: NotificationChannel
    template_id: UUID | None = None
    template_code: str | None = None
    variables: dict[str, Any] = field(default_factory=dict)

    # Optional fields
    priority: NotificationPriority = NotificationPriority.NORMAL
    scheduled_for: datetime | None = None
    expires_at: datetime | None = None
    idempotency_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Direct content (used when not using template)
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None
    attachments: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """Validate that either template or direct content is provided."""
        if not (self.template_id or self.template_code) and not self.body:
            raise ValueError(
                "Either template (ID or code) or direct content (body) must be provided"
            )


@dataclass(frozen=True)
class NotificationResponseDTO:
    """DTO for notification response."""

    notification_id: UUID
    status: DeliveryStatus
    channel: NotificationChannel
    recipient_id: UUID
    created_at: datetime
    scheduled_for: datetime | None = None
    sent_at: datetime | None = None
    delivered_at: datetime | None = None
    provider_message_id: str | None = None

    @classmethod
    def from_notification(cls, notification: Any) -> "NotificationResponseDTO":
        """Create DTO from notification entity."""
        return cls(
            notification_id=notification.id,
            status=notification.current_status,
            channel=notification.channel,
            recipient_id=notification.recipient_id,
            created_at=notification.created_at,
            scheduled_for=notification.scheduled_for,
            sent_at=notification.sent_at,
            delivered_at=notification.delivered_at,
            provider_message_id=notification.provider_message_id,
        )


@dataclass(frozen=True)
class TemplateDTO:
    """DTO for notification template."""

    template_id: UUID
    code: str
    name: str
    description: str | None
    template_type: TemplateType
    channel: NotificationChannel

    # Template content
    subject_template: str | None
    body_template: str
    html_template: str | None

    # Variables
    variables: list[dict[str, Any]]  # List of variable definitions

    # Settings
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    # Optional metadata
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RecipientPreferencesDTO:
    """DTO for recipient notification preferences."""

    recipient_id: UUID
    preferences: dict[NotificationChannel, dict[str, Any]]

    # Channel-specific settings
    email_enabled: bool = True
    sms_enabled: bool = True
    push_enabled: bool = True
    in_app_enabled: bool = True

    # Type-specific settings
    marketing_enabled: bool = True
    transactional_enabled: bool = True
    system_enabled: bool = True
    alert_enabled: bool = True

    # Delivery preferences
    quiet_hours_enabled: bool = False
    quiet_hours_start: str | None = None  # HH:MM format
    quiet_hours_end: str | None = None  # HH:MM format
    timezone: str = "UTC"

    # Contact information
    email_addresses: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    device_tokens: list[str] = field(default_factory=list)

    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class DeliveryReportDTO:
    """DTO for notification delivery report."""

    notification_id: UUID
    channel: NotificationChannel
    status: DeliveryStatus

    # Timeline
    created_at: datetime
    queued_at: datetime | None
    sent_at: datetime | None
    delivered_at: datetime | None
    read_at: datetime | None
    failed_at: datetime | None

    # Provider information
    provider: str | None
    provider_message_id: str | None
    provider_status: str | None

    # Delivery details
    retry_count: int
    error_code: str | None
    error_message: str | None

    # Performance metrics
    delivery_duration_seconds: float | None
    processing_duration_seconds: float | None

    # Status history
    status_history: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class BatchStatusDTO:
    """DTO for notification batch status."""

    batch_id: UUID
    status: BatchStatus
    total_notifications: int

    # Processing stats
    pending_count: int
    sent_count: int
    delivered_count: int
    failed_count: int

    # Timeline
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    # Performance metrics
    processing_duration_seconds: float | None
    average_delivery_time_seconds: float | None

    # Error information
    error_summary: dict[str, int] = field(default_factory=dict)  # Error code -> count

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_notifications == 0:
            return 0.0
        return self.delivered_count / self.total_notifications

    @property
    def is_complete(self) -> bool:
        """Check if batch processing is complete."""
        return self.status.is_final()


@dataclass(frozen=True)
class NotificationHistoryDTO:
    """DTO for notification history query results."""

    notifications: list[NotificationResponseDTO]
    total_count: int
    page: int
    page_size: int

    # Filters applied
    recipient_id: UUID | None = None
    channel: NotificationChannel | None = None
    status: DeliveryStatus | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None

    @property
    def total_pages(self) -> int:
        """Calculate total pages."""
        return (self.total_count + self.page_size - 1) // self.page_size

    @property
    def has_next(self) -> bool:
        """Check if there's a next page."""
        return self.page < self.total_pages

    @property
    def has_previous(self) -> bool:
        """Check if there's a previous page."""
        return self.page > 1


@dataclass(frozen=True)
class ChannelStatusDTO:
    """DTO for notification channel status."""

    channel: NotificationChannel
    is_active: bool
    provider: str

    # Health metrics
    health_status: str  # "healthy", "degraded", "unhealthy"
    last_check_at: datetime
    uptime_percentage: float

    # Performance metrics
    average_delivery_time_seconds: float
    success_rate: float

    # Rate limiting
    rate_limit: int | None
    rate_limit_window: str | None
    current_usage: int

    # Configuration
    features: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScheduledNotificationDTO:
    """DTO for scheduled notification."""

    schedule_id: UUID
    notification_request: NotificationRequestDTO
    scheduled_for: datetime

    # Recurrence settings
    is_recurring: bool = False
    recurrence_pattern: str | None = None  # "daily", "weekly", "monthly"
    recurrence_interval: int | None = None
    recurrence_end_date: datetime | None = None

    # Status
    is_active: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    run_count: int = 0

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: UUID | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# Export all DTOs
__all__ = [
    "BatchStatusDTO",
    "ChannelStatusDTO",
    "DeliveryReportDTO",
    "NotificationHistoryDTO",
    "NotificationRequestDTO",
    "NotificationResponseDTO",
    "RecipientPreferencesDTO",
    "ScheduledNotificationDTO",
    "TemplateDTO",
]
