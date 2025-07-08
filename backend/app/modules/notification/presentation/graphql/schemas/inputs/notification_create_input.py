"""Notification creation input types.

This module contains GraphQL input types for creating and managing notifications.
"""

from datetime import datetime

import strawberry

from ..enums import NotificationChannelEnum, NotificationPriorityEnum


@strawberry.input
class NotificationAttachmentInput:
    """GraphQL input for notification attachments."""

    filename: str
    content_type: str
    content: str  # Base64 encoded content
    inline: bool = False


@strawberry.input
class NotificationMetadataInput:
    """GraphQL input for notification metadata."""

    key: str
    value: str


@strawberry.input
class NotificationCreateInput:
    """GraphQL input for creating notifications."""

    # Required fields
    recipient_id: strawberry.ID
    channel: NotificationChannelEnum

    # Template or direct content
    template_id: strawberry.ID | None = None
    template_code: str | None = None
    template_variables: dict[str, str] | None = None

    # Direct content (when not using template)
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None
    attachments: list[NotificationAttachmentInput] | None = None

    # Settings
    priority: NotificationPriorityEnum = NotificationPriorityEnum.NORMAL
    scheduled_for: datetime | None = None
    expires_at: datetime | None = None

    # Tracking and identification
    idempotency_key: str | None = None
    campaign_id: strawberry.ID | None = None
    batch_id: strawberry.ID | None = None

    # Metadata
    metadata: list[NotificationMetadataInput] | None = None

    # Delivery options
    track_opens: bool = True
    track_clicks: bool = True
    allow_unsubscribe: bool = True

    # Retry configuration
    max_retries: int = 3
    retry_delay_seconds: int | None = None


@strawberry.input
class NotificationUpdateInput:
    """GraphQL input for updating notifications."""

    # Fields that can be updated before sending
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None
    scheduled_for: datetime | None = None
    expires_at: datetime | None = None
    priority: NotificationPriorityEnum | None = None

    # Metadata updates
    metadata: list[NotificationMetadataInput] | None = None

    # Template variable updates
    template_variables: dict[str, str] | None = None


@strawberry.input
class NotificationScheduleInput:
    """GraphQL input for scheduling notifications."""

    # Notification template
    notification_template: NotificationCreateInput

    # Schedule configuration
    scheduled_for: datetime
    timezone: str = "UTC"

    # Recurring schedule
    is_recurring: bool = False
    recurrence_pattern: str | None = None  # "daily", "weekly", "monthly"
    recurrence_interval: int = 1
    recurrence_end_date: datetime | None = None

    # Schedule metadata
    name: str
    description: str | None = None
    is_active: bool = True

    # Execution limits
    max_executions: int | None = None

    # Error handling
    continue_on_error: bool = True
    max_consecutive_failures: int = 5


@strawberry.input
class NotificationBatchInput:
    """GraphQL input for creating notification batches."""

    # Batch configuration
    name: str | None = None
    description: str | None = None

    # Notification template
    template_id: strawberry.ID
    channel: NotificationChannelEnum
    priority: NotificationPriorityEnum = NotificationPriorityEnum.NORMAL

    # Recipients (list of recipient IDs)
    recipient_ids: list[strawberry.ID]

    # Template variables per recipient
    recipient_variables: dict[str, dict[str, str]] | None = None

    # Batch settings
    batch_size: int = 100
    send_rate_per_minute: int | None = None

    # Scheduling
    scheduled_for: datetime | None = None

    # Campaign association
    campaign_id: strawberry.ID | None = None

    # Tracking
    track_opens: bool = True
    track_clicks: bool = True


@strawberry.input
class NotificationRetryInput:
    """GraphQL input for retrying failed notifications."""

    notification_ids: list[strawberry.ID]

    # Retry configuration
    force_retry: bool = False  # Retry even if max retries reached
    reset_retry_count: bool = False
    new_channel: NotificationChannelEnum | None = None

    # Updated content (optional)
    updated_template_variables: dict[str, str] | None = None
    updated_subject: str | None = None
    updated_body: str | None = None


@strawberry.input
class NotificationCancelInput:
    """GraphQL input for cancelling notifications."""

    notification_ids: list[strawberry.ID]

    # Cancellation reason
    reason: str | None = None

    # Batch cancellation options
    cancel_batch: bool = False  # Cancel entire batch if notification is part of one

    # Force cancellation
    force_cancel: bool = False  # Cancel even if already sending


@strawberry.input
class NotificationSearchInput:
    """GraphQL input for searching notifications."""

    # Text search
    query: str | None = None

    # Filters
    recipient_ids: list[strawberry.ID] | None = None
    channels: list[NotificationChannelEnum] | None = None
    statuses: list[str] | None = None  # DeliveryStatusEnum values
    priorities: list[NotificationPriorityEnum] | None = None
    template_ids: list[strawberry.ID] | None = None
    campaign_ids: list[strawberry.ID] | None = None

    # Date filters
    created_after: datetime | None = None
    created_before: datetime | None = None
    sent_after: datetime | None = None
    sent_before: datetime | None = None
    delivered_after: datetime | None = None
    delivered_before: datetime | None = None

    # Metadata filters
    metadata_filters: list[NotificationMetadataInput] | None = None

    # Tags and segmentation
    tags: list[str] | None = None

    # Performance filters
    min_delivery_time_seconds: float | None = None
    max_delivery_time_seconds: float | None = None
    has_opened: bool | None = None
    has_clicked: bool | None = None

    # Pagination and sorting
    limit: int = 50
    offset: int = 0
    sort_by: str = "created_at"
    sort_direction: str = "desc"


@strawberry.input
class NotificationTestInput:
    """GraphQL input for testing notifications."""

    # Test configuration
    test_recipient: str  # Email, phone, etc.
    channel: NotificationChannelEnum

    # Content to test
    template_id: strawberry.ID | None = None
    template_variables: dict[str, str] | None = None

    # Direct content
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None

    # Test options
    send_actual_notification: bool = False  # If false, just validate/preview
    track_delivery: bool = True


@strawberry.input
class NotificationPreviewInput:
    """GraphQL input for previewing notifications."""

    # Template or direct content
    template_id: strawberry.ID | None = None
    template_variables: dict[str, str] | None = None

    # Direct content
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None

    # Channel for preview formatting
    channel: NotificationChannelEnum

    # Preview options
    include_tracking_pixels: bool = False
    include_unsubscribe_link: bool = True

    # Sample recipient data for variable substitution
    sample_recipient_data: dict[str, str] | None = None
