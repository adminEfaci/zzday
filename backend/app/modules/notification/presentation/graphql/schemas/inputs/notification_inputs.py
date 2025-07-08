"""
Notification GraphQL Input Types

Input types for notification operations including creation, updates, filtering,
and bulk operations.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from ..types.notification_type import (
    NotificationCategoryType,
    NotificationPriorityType,
    NotificationStatusType,
)
from ..types.recipient_type import ContactMethodType


@strawberry.input
class PaginationInput:
    """Pagination parameters for list queries."""

    page: int | None = strawberry.field(description="Page number (1-based)", default=1)

    page_size: int | None = strawberry.field(
        description="Number of items per page (max 100)", default=20
    )

    sort_by: str | None = strawberry.field(
        description="Field to sort by", default="created_at"
    )

    sort_order: str | None = strawberry.field(
        description="Sort order (asc, desc)", default="desc"
    )


@strawberry.input
class DateRangeInput:
    """Date range filter input."""

    start_date: datetime | None = strawberry.field(
        description="Start date for filtering"
    )

    end_date: datetime | None = strawberry.field(description="End date for filtering")


@strawberry.input
class NotificationContentInput:
    """Input for notification content."""

    subject: str | None = strawberry.field(description="Notification subject/title")

    body: str = strawberry.field(description="Main notification content")

    html_body: str | None = strawberry.field(
        description="HTML version of content (for email)"
    )

    short_text: str | None = strawberry.field(
        description="Short version for SMS/push (under 160 chars)"
    )

    rich_content: str | None = strawberry.field(
        description="Rich content for in-app notifications (JSON)"
    )

    attachments: list[str] | None = strawberry.field(
        description="List of attachment URLs"
    )

    action_url: str | None = strawberry.field(
        description="Primary action URL for the notification"
    )

    action_text: str | None = strawberry.field(
        description="Text for the primary action button"
    )

    metadata: str | None = strawberry.field(
        description="Additional metadata as JSON string"
    )


@strawberry.input
class NotificationSchedulingInput:
    """Input for notification scheduling."""

    send_at: datetime | None = strawberry.field(
        description="Specific time to send notification"
    )

    timezone: str | None = strawberry.field(
        description="Timezone for scheduling (e.g., 'America/New_York')"
    )

    batch_size: int | None = strawberry.field(
        description="Number of notifications to send per batch"
    )

    batch_interval: int | None = strawberry.field(
        description="Interval between batches in seconds"
    )

    retry_config: str | None = strawberry.field(
        description="Retry configuration as JSON"
    )


@strawberry.input
class NotificationCreateInput:
    """Input for creating a new notification."""

    title: str = strawberry.field(description="Notification title/name")

    category: NotificationCategoryType = strawberry.field(
        description="Notification category"
    )

    priority: NotificationPriorityType = strawberry.field(
        description="Notification priority level"
    )

    content: NotificationContentInput = strawberry.field(
        description="Notification content"
    )

    # Template and variables
    template_id: UUID | None = strawberry.field(
        description="Template to use for this notification"
    )

    variables: str | None = strawberry.field(
        description="Template variables as JSON string"
    )

    # Recipients and channels
    channels: list[ContactMethodType] = strawberry.field(
        description="Channels to send notification through"
    )

    recipient_ids: list[UUID] = strawberry.field(description="Recipient IDs")

    recipient_group_ids: list[UUID] | None = strawberry.field(
        description="Recipient group IDs"
    )

    # Scheduling
    scheduling: NotificationSchedulingInput | None = strawberry.field(
        description="Scheduling configuration"
    )

    # Campaign association
    campaign_id: UUID | None = strawberry.field(description="Associated campaign ID")

    # Metadata
    tags: list[str] | None = strawberry.field(
        description="Tags for organization and filtering"
    )

    external_id: str | None = strawberry.field(description="External system identifier")

    correlation_id: str | None = strawberry.field(
        description="Correlation ID for tracking across systems"
    )


@strawberry.input
class NotificationUpdateInput:
    """Input for updating an existing notification."""

    title: str | None = strawberry.field(description="Notification title/name")

    category: NotificationCategoryType | None = strawberry.field(
        description="Notification category"
    )

    priority: NotificationPriorityType | None = strawberry.field(
        description="Notification priority level"
    )

    content: NotificationContentInput | None = strawberry.field(
        description="Notification content"
    )

    status: NotificationStatusType | None = strawberry.field(
        description="Notification status"
    )

    # Scheduling
    scheduling: NotificationSchedulingInput | None = strawberry.field(
        description="Scheduling configuration"
    )

    # Metadata
    tags: list[str] | None = strawberry.field(
        description="Tags for organization and filtering"
    )


@strawberry.input
class NotificationFilterInput:
    """Filter input for notification queries."""

    # Status filtering
    status: list[NotificationStatusType] | None = strawberry.field(
        description="Filter by notification status"
    )

    priority: list[NotificationPriorityType] | None = strawberry.field(
        description="Filter by priority level"
    )

    category: list[NotificationCategoryType] | None = strawberry.field(
        description="Filter by category"
    )

    # Channel filtering
    channels: list[ContactMethodType] | None = strawberry.field(
        description="Filter by channels used"
    )

    # Date filtering
    created_after: datetime | None = strawberry.field(
        description="Filter notifications created after this date"
    )

    created_before: datetime | None = strawberry.field(
        description="Filter notifications created before this date"
    )

    sent_after: datetime | None = strawberry.field(
        description="Filter notifications sent after this date"
    )

    sent_before: datetime | None = strawberry.field(
        description="Filter notifications sent before this date"
    )

    # Relationships
    template_id: UUID | None = strawberry.field(description="Filter by template used")

    campaign_id: UUID | None = strawberry.field(description="Filter by campaign")

    created_by: UUID | None = strawberry.field(description="Filter by creator")

    # Recipient filtering
    recipient_id: UUID | None = strawberry.field(
        description="Filter by specific recipient"
    )

    recipient_group_id: UUID | None = strawberry.field(
        description="Filter by recipient group"
    )

    # Content filtering
    has_attachments: bool | None = strawberry.field(
        description="Filter notifications with/without attachments"
    )

    # Tags and metadata
    tags: list[str] | None = strawberry.field(description="Filter by tags (OR logic)")

    tags_all: list[str] | None = strawberry.field(
        description="Filter by tags (AND logic - must have all)"
    )

    external_id: str | None = strawberry.field(description="Filter by external ID")

    correlation_id: str | None = strawberry.field(
        description="Filter by correlation ID"
    )

    # Text search
    search_query: str | None = strawberry.field(
        description="Search in title and content"
    )


@strawberry.input
class BulkNotificationCreateInput:
    """Input for creating notifications in bulk."""

    # Common properties for all notifications
    category: NotificationCategoryType = strawberry.field(
        description="Category for all notifications"
    )

    priority: NotificationPriorityType = strawberry.field(
        description="Priority for all notifications"
    )

    template_id: UUID = strawberry.field(
        description="Template to use for all notifications"
    )

    channels: list[ContactMethodType] = strawberry.field(
        description="Channels for delivery"
    )

    # Recipient configuration
    recipient_ids: list[UUID] | None = strawberry.field(
        description="Individual recipient IDs"
    )

    recipient_group_ids: list[UUID] | None = strawberry.field(
        description="Recipient group IDs"
    )

    # Per-notification data
    notifications_data: list[str] = strawberry.field(
        description="Array of JSON objects with per-notification data (variables, etc.)"
    )

    # Scheduling
    scheduling: NotificationSchedulingInput | None = strawberry.field(
        description="Scheduling configuration"
    )

    # Campaign association
    campaign_id: UUID | None = strawberry.field(description="Associated campaign ID")

    # Metadata
    tags: list[str] | None = strawberry.field(description="Tags for all notifications")


@strawberry.input
class NotificationPreferencesInput:
    """Input for updating notification preferences."""

    recipient_id: UUID = strawberry.field(description="Recipient ID")

    channel_preferences: list[str] = strawberry.field(
        description="Channel preferences as JSON array"
    )

    category_preferences: list[str] | None = strawberry.field(
        description="Category preferences"
    )

    frequency_preference: str | None = strawberry.field(
        description="Frequency preference (immediate, daily, weekly, etc.)"
    )

    quiet_hours: str | None = strawberry.field(
        description="Quiet hours configuration (JSON)"
    )

    timezone: str | None = strawberry.field(
        description="User's timezone for scheduling"
    )


@strawberry.input
class NotificationResendInput:
    """Input for resending failed notifications."""

    notification_id: UUID = strawberry.field(description="Notification to resend")

    recipient_ids: list[UUID] | None = strawberry.field(
        description="Specific recipients to resend to (optional - defaults to failed recipients)"
    )

    channels: list[ContactMethodType] | None = strawberry.field(
        description="Specific channels to resend through (optional)"
    )

    force_resend: bool | None = strawberry.field(
        description="Force resend even to successful recipients", default=False
    )


@strawberry.input
class NotificationCancelInput:
    """Input for canceling scheduled notifications."""

    notification_ids: list[UUID] = strawberry.field(
        description="Notification IDs to cancel"
    )

    reason: str | None = strawberry.field(description="Reason for cancellation")
