"""
Delivery GraphQL Types

Types for tracking notification delivery status, analytics, and performance metrics.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from .recipient_type import ContactMethodType


@strawberry.enum
class DeliveryStatusType(str):
    """Delivery status for individual notifications."""

    QUEUED = "queued"
    PROCESSING = "processing"
    SENT = "sent"
    DELIVERED = "delivered"
    OPENED = "opened"
    CLICKED = "clicked"
    BOUNCED = "bounced"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    UNSUBSCRIBED = "unsubscribed"


@strawberry.enum
class DeliveryFailureReasonType(str):
    """Common delivery failure reasons."""

    INVALID_EMAIL = "invalid_email"
    INVALID_PHONE = "invalid_phone"
    BOUNCED = "bounced"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    BLOCKED_CONTENT = "blocked_content"
    RECIPIENT_UNSUBSCRIBED = "recipient_unsubscribed"
    RECIPIENT_BLOCKED = "recipient_blocked"
    CHANNEL_ERROR = "channel_error"
    UNKNOWN = "unknown"


@strawberry.type
class DeliveryAttemptType:
    """Individual delivery attempt information."""

    attempt_number: int = strawberry.field(description="Attempt number (1-based)")

    status: DeliveryStatusType = strawberry.field(description="Status of this attempt")

    attempted_at: datetime = strawberry.field(description="When this attempt was made")

    completed_at: datetime | None = strawberry.field(
        description="When this attempt completed"
    )

    response_time: float | None = strawberry.field(
        description="Response time in milliseconds"
    )

    error_message: str | None = strawberry.field(
        description="Error message if attempt failed"
    )

    failure_reason: DeliveryFailureReasonType | None = strawberry.field(
        description="Specific failure reason"
    )

    provider_response: str | None = strawberry.field(
        description="Raw provider response"
    )

    provider_message_id: str | None = strawberry.field(
        description="Provider's message ID"
    )

    metadata: str | None = strawberry.field(
        description="Additional attempt metadata (JSON)"
    )


@strawberry.type
class DeliveryEventType:
    """Individual delivery event (opened, clicked, etc.)."""

    id: UUID = strawberry.field(description="Event identifier")

    event_type: str = strawberry.field(
        description="Type of event (opened, clicked, bounced, etc.)"
    )

    occurred_at: datetime = strawberry.field(description="When the event occurred")

    user_agent: str | None = strawberry.field(
        description="User agent that triggered the event"
    )

    ip_address: str | None = strawberry.field(
        description="IP address that triggered the event"
    )

    location: str | None = strawberry.field(description="Geographic location (JSON)")

    device_info: str | None = strawberry.field(description="Device information (JSON)")

    url: str | None = strawberry.field(description="URL clicked (for click events)")

    metadata: str | None = strawberry.field(
        description="Additional event metadata (JSON)"
    )


@strawberry.type
class DeliveryLogType:
    """Comprehensive delivery log for a notification to a specific recipient."""

    id: UUID = strawberry.field(description="Unique delivery log identifier")

    notification_id: UUID = strawberry.field(description="Associated notification ID")

    recipient_id: UUID = strawberry.field(description="Recipient ID")

    channel_id: UUID = strawberry.field(description="Channel used for delivery")

    channel_type: ContactMethodType = strawberry.field(
        description="Type of channel used"
    )

    # Current status
    status: DeliveryStatusType = strawberry.field(description="Current delivery status")

    final_status: bool = strawberry.field(
        description="Whether this is the final status"
    )

    # Delivery details
    recipient_address: str = strawberry.field(
        description="Recipient address (email, phone, etc.)"
    )

    content_hash: str | None = strawberry.field(
        description="Hash of delivered content for verification"
    )

    # Timing information
    queued_at: datetime = strawberry.field(description="When delivery was queued")

    sent_at: datetime | None = strawberry.field(description="When delivery was sent")

    delivered_at: datetime | None = strawberry.field(
        description="When delivery was confirmed"
    )

    opened_at: datetime | None = strawberry.field(
        description="When notification was first opened"
    )

    clicked_at: datetime | None = strawberry.field(
        description="When notification was first clicked"
    )

    failed_at: datetime | None = strawberry.field(
        description="When delivery failed (if applicable)"
    )

    # Performance metrics
    delivery_duration: float | None = strawberry.field(
        description="Time from queue to delivery in seconds"
    )

    total_attempts: int = strawberry.field(
        description="Total number of delivery attempts"
    )

    # Provider information
    provider_name: str = strawberry.field(description="Name of the delivery provider")

    provider_message_id: str | None = strawberry.field(
        description="Provider's unique message identifier"
    )

    provider_response: str | None = strawberry.field(
        description="Raw provider response"
    )

    # Failure information
    failure_reason: DeliveryFailureReasonType | None = strawberry.field(
        description="Reason for delivery failure"
    )

    error_message: str | None = strawberry.field(description="Detailed error message")

    retry_count: int = strawberry.field(description="Number of retry attempts")

    next_retry_at: datetime | None = strawberry.field(
        description="When next retry is scheduled"
    )

    # Detailed tracking
    delivery_attempts: list[DeliveryAttemptType] = strawberry.field(
        description="Detailed delivery attempts"
    )

    events: list[DeliveryEventType] = strawberry.field(
        description="Delivery events (opens, clicks, etc.)"
    )

    # Analytics data
    open_count: int = strawberry.field(
        description="Number of times notification was opened"
    )

    click_count: int = strawberry.field(
        description="Number of times links were clicked"
    )

    last_opened: datetime | None = strawberry.field(
        description="Last time notification was opened"
    )

    last_clicked: datetime | None = strawberry.field(
        description="Last time a link was clicked"
    )

    # Cost tracking
    delivery_cost: float | None = strawberry.field(description="Cost of this delivery")

    cost_currency: str | None = strawberry.field(
        description="Currency for delivery cost"
    )

    # Metadata
    tags: list[str] = strawberry.field(description="Tags for categorization")

    metadata: str | None = strawberry.field(
        description="Additional delivery metadata (JSON)"
    )


@strawberry.type
class DeliveryAnalyticsType:
    """Delivery analytics and metrics."""

    total_deliveries: int = strawberry.field(description="Total number of deliveries")

    successful_deliveries: int = strawberry.field(
        description="Number of successful deliveries"
    )

    failed_deliveries: int = strawberry.field(description="Number of failed deliveries")

    pending_deliveries: int = strawberry.field(
        description="Number of pending deliveries"
    )

    # Rates
    delivery_rate: float = strawberry.field(
        description="Delivery success rate (0.0 - 1.0)"
    )

    open_rate: float = strawberry.field(description="Open rate (0.0 - 1.0)")

    click_rate: float = strawberry.field(description="Click-through rate (0.0 - 1.0)")

    bounce_rate: float = strawberry.field(description="Bounce rate (0.0 - 1.0)")

    unsubscribe_rate: float = strawberry.field(
        description="Unsubscribe rate (0.0 - 1.0)"
    )

    # Timing metrics
    avg_delivery_time: float | None = strawberry.field(
        description="Average delivery time in seconds"
    )

    median_delivery_time: float | None = strawberry.field(
        description="Median delivery time in seconds"
    )

    fastest_delivery: float | None = strawberry.field(
        description="Fastest delivery time in seconds"
    )

    slowest_delivery: float | None = strawberry.field(
        description="Slowest delivery time in seconds"
    )

    # Breakdown by channel
    by_channel: str = strawberry.field(description="Delivery metrics by channel (JSON)")

    by_status: str = strawberry.field(description="Count by delivery status (JSON)")

    by_failure_reason: str = strawberry.field(
        description="Count by failure reason (JSON)"
    )

    # Time series data
    hourly_volume: str = strawberry.field(description="Hourly delivery volume (JSON)")

    daily_volume: str = strawberry.field(description="Daily delivery volume (JSON)")

    # Cost analytics
    total_cost: float | None = strawberry.field(description="Total delivery cost")

    avg_cost_per_delivery: float | None = strawberry.field(
        description="Average cost per delivery"
    )

    cost_by_channel: str | None = strawberry.field(
        description="Cost breakdown by channel (JSON)"
    )


@strawberry.type
class DeliveryListType:
    """Paginated list of delivery logs."""

    items: list[DeliveryLogType] = strawberry.field(
        description="Delivery logs in this page"
    )

    total_count: int = strawberry.field(description="Total number of delivery logs")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class DeliveryReportType:
    """Comprehensive delivery report."""

    id: UUID = strawberry.field(description="Report identifier")

    name: str = strawberry.field(description="Report name")

    description: str | None = strawberry.field(description="Report description")

    # Report parameters
    start_date: datetime = strawberry.field(description="Report start date")

    end_date: datetime = strawberry.field(description="Report end date")

    filters: str | None = strawberry.field(description="Applied filters (JSON)")

    # Analytics
    analytics: DeliveryAnalyticsType = strawberry.field(
        description="Delivery analytics for this report"
    )

    # Detailed breakdowns
    top_performing_channels: str = strawberry.field(
        description="Top performing channels (JSON)"
    )

    worst_performing_channels: str = strawberry.field(
        description="Worst performing channels (JSON)"
    )

    engagement_trends: str = strawberry.field(
        description="Engagement trends over time (JSON)"
    )

    failure_analysis: str = strawberry.field(
        description="Detailed failure analysis (JSON)"
    )

    # Report metadata
    generated_at: datetime = strawberry.field(
        description="When the report was generated"
    )

    generated_by: UUID = strawberry.field(description="User who generated the report")
