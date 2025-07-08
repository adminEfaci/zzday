"""
Notification GraphQL Types

Comprehensive GraphQL types for the notification system with full support for
multi-channel notifications, delivery tracking, and analytics.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from .channel_type import NotificationChannelType
from .delivery_type import DeliveryLogType
from .recipient_type import RecipientType


@strawberry.enum
class NotificationPriorityType(str):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


@strawberry.enum
class NotificationStatusType(str):
    """Notification processing status."""

    DRAFT = "draft"
    QUEUED = "queued"
    PROCESSING = "processing"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


@strawberry.enum
class NotificationCategoryType(str):
    """Notification categories for organization."""

    SYSTEM = "system"
    MARKETING = "marketing"
    TRANSACTIONAL = "transactional"
    ALERT = "alert"
    REMINDER = "reminder"
    UPDATE = "update"
    SECURITY = "security"
    BILLING = "billing"


@strawberry.type
class NotificationContentType:
    """Structured notification content for multi-channel delivery."""

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


@strawberry.type
class NotificationVariablesType:
    """Variables available for template substitution."""

    user_variables: str | None = strawberry.field(
        description="User-specific variables (JSON)"
    )

    system_variables: str | None = strawberry.field(
        description="System-generated variables (JSON)"
    )

    custom_variables: str | None = strawberry.field(
        description="Custom variables passed with notification (JSON)"
    )


@strawberry.type
class NotificationSchedulingType:
    """Notification scheduling configuration."""

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


@strawberry.type
class NotificationAnalyticsType:
    """Analytics and metrics for notifications."""

    total_sent: int = strawberry.field(description="Total notifications sent")

    total_delivered: int = strawberry.field(description="Total notifications delivered")

    total_failed: int = strawberry.field(description="Total notifications failed")

    total_bounced: int = strawberry.field(description="Total notifications bounced")

    total_clicked: int = strawberry.field(description="Total notifications clicked")

    total_opened: int = strawberry.field(description="Total notifications opened")

    delivery_rate: float = strawberry.field(
        description="Delivery success rate (0.0 - 1.0)"
    )

    open_rate: float = strawberry.field(
        description="Open rate for email notifications (0.0 - 1.0)"
    )

    click_rate: float = strawberry.field(description="Click-through rate (0.0 - 1.0)")

    bounce_rate: float = strawberry.field(description="Bounce rate (0.0 - 1.0)")

    avg_delivery_time: float | None = strawberry.field(
        description="Average delivery time in seconds"
    )

    channel_breakdown: str | None = strawberry.field(
        description="Per-channel analytics (JSON)"
    )


@strawberry.type
class NotificationType:
    """Core notification type with comprehensive fields."""

    id: UUID = strawberry.field(description="Unique notification identifier")

    title: str = strawberry.field(description="Notification title/name")

    category: NotificationCategoryType = strawberry.field(
        description="Notification category"
    )

    priority: NotificationPriorityType = strawberry.field(
        description="Notification priority level"
    )

    status: NotificationStatusType = strawberry.field(
        description="Current notification status"
    )

    content: NotificationContentType = strawberry.field(
        description="Notification content for all channels"
    )

    # Template and variables
    template_id: UUID | None = strawberry.field(
        description="Template used for this notification"
    )

    variables: NotificationVariablesType | None = strawberry.field(
        description="Variables for template substitution"
    )

    # Recipients and channels
    channels: list[NotificationChannelType] = strawberry.field(
        description="Channels to send notification through"
    )

    recipients: list[RecipientType] = strawberry.field(
        description="Notification recipients"
    )

    recipient_count: int = strawberry.field(description="Total number of recipients")

    # Scheduling
    scheduling: NotificationSchedulingType | None = strawberry.field(
        description="Scheduling configuration"
    )

    # Tracking and analytics
    delivery_logs: list[DeliveryLogType] = strawberry.field(
        description="Delivery logs for this notification"
    )

    analytics: NotificationAnalyticsType | None = strawberry.field(
        description="Analytics and metrics"
    )

    # Campaign association
    campaign_id: UUID | None = strawberry.field(description="Associated campaign ID")

    # Metadata and tracking
    tags: list[str] = strawberry.field(
        description="Tags for organization and filtering"
    )

    external_id: str | None = strawberry.field(description="External system identifier")

    source: str = strawberry.field(
        description="Source system or service that created notification"
    )

    correlation_id: str | None = strawberry.field(
        description="Correlation ID for tracking across systems"
    )

    # Audit fields
    created_by: UUID = strawberry.field(description="User who created the notification")

    created_at: datetime = strawberry.field(
        description="When the notification was created"
    )

    updated_at: datetime = strawberry.field(
        description="When the notification was last updated"
    )

    sent_at: datetime | None = strawberry.field(
        description="When the notification was sent"
    )

    completed_at: datetime | None = strawberry.field(
        description="When all deliveries were completed"
    )


@strawberry.type
class NotificationBatchType:
    """Batch notification for bulk operations."""

    id: UUID = strawberry.field(description="Unique batch identifier")

    name: str = strawberry.field(description="Batch name")

    description: str | None = strawberry.field(description="Batch description")

    notifications: list[NotificationType] = strawberry.field(
        description="Notifications in this batch"
    )

    total_notifications: int = strawberry.field(
        description="Total number of notifications in batch"
    )

    status: NotificationStatusType = strawberry.field(
        description="Overall batch status"
    )

    progress: float = strawberry.field(
        description="Batch completion progress (0.0 - 1.0)"
    )

    analytics: NotificationAnalyticsType = strawberry.field(
        description="Aggregated analytics for the batch"
    )

    created_at: datetime = strawberry.field(description="When the batch was created")

    started_at: datetime | None = strawberry.field(
        description="When batch processing started"
    )

    completed_at: datetime | None = strawberry.field(
        description="When batch processing completed"
    )


@strawberry.type
class NotificationListType:
    """Paginated list of notifications."""

    items: list[NotificationType] = strawberry.field(
        description="Notifications in this page"
    )

    total_count: int = strawberry.field(description="Total number of notifications")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class NotificationSummaryType:
    """Summary statistics for notifications."""

    total_notifications: int = strawberry.field(
        description="Total number of notifications"
    )

    by_status: str = strawberry.field(description="Count by status (JSON object)")

    by_priority: str = strawberry.field(description="Count by priority (JSON object)")

    by_category: str = strawberry.field(description="Count by category (JSON object)")

    by_channel: str = strawberry.field(description="Count by channel (JSON object)")

    today_count: int = strawberry.field(description="Notifications created today")

    week_count: int = strawberry.field(description="Notifications created this week")

    month_count: int = strawberry.field(description="Notifications created this month")

    avg_delivery_time: float | None = strawberry.field(
        description="Average delivery time in seconds"
    )

    success_rate: float = strawberry.field(
        description="Overall success rate (0.0 - 1.0)"
    )
