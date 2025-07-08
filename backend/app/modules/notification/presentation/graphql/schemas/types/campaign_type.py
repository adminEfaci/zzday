"""
Campaign GraphQL Types

Types for notification campaigns including A/B testing, scheduling,
and campaign analytics.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from .notification_type import NotificationCategoryType, NotificationPriorityType
from .recipient_type import ContactMethodType


@strawberry.enum
class CampaignStatusType(str):
    """Campaign status."""

    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@strawberry.enum
class CampaignTypeEnum(str):
    """Campaign types."""

    ONE_TIME = "one_time"
    RECURRING = "recurring"
    DRIP = "drip"
    AB_TEST = "ab_test"
    TRIGGERED = "triggered"
    TRANSACTIONAL = "transactional"


@strawberry.enum
class ABTestStatusType(str):
    """A/B test status."""

    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    WINNER_SELECTED = "winner_selected"


@strawberry.type
class CampaignScheduleType:
    """Campaign scheduling configuration."""

    start_date: datetime | None = strawberry.field(
        description="Campaign start date and time"
    )

    end_date: datetime | None = strawberry.field(
        description="Campaign end date and time"
    )

    timezone: str = strawberry.field(
        description="Timezone for scheduling", default="UTC"
    )

    # Recurring configuration
    is_recurring: bool = strawberry.field(
        description="Whether this is a recurring campaign"
    )

    recurrence_pattern: str | None = strawberry.field(
        description="Recurrence pattern (cron expression or JSON)"
    )

    recurrence_end: datetime | None = strawberry.field(
        description="When recurrence should end"
    )

    max_occurrences: int | None = strawberry.field(
        description="Maximum number of recurrences"
    )

    # Delivery optimization
    optimize_send_time: bool = strawberry.field(
        description="Whether to optimize send time for each recipient"
    )

    respect_quiet_hours: bool = strawberry.field(
        description="Whether to respect recipient quiet hours"
    )

    batch_size: int | None = strawberry.field(
        description="Number of notifications per batch"
    )

    batch_interval: int | None = strawberry.field(
        description="Interval between batches in minutes"
    )


@strawberry.type
class ABTestVariantType:
    """A/B test variant definition."""

    id: UUID = strawberry.field(description="Variant identifier")

    name: str = strawberry.field(
        description="Variant name (e.g., 'Control', 'Variant A')"
    )

    description: str | None = strawberry.field(description="Variant description")

    template_id: UUID = strawberry.field(description="Template used for this variant")

    traffic_percentage: float = strawberry.field(
        description="Percentage of traffic allocated to this variant (0.0 - 1.0)"
    )

    variables: str | None = strawberry.field(
        description="Template variables specific to this variant (JSON)"
    )

    # Performance metrics
    recipients_count: int = strawberry.field(
        description="Number of recipients assigned to this variant"
    )

    sent_count: int = strawberry.field(description="Number of notifications sent")

    delivered_count: int = strawberry.field(description="Number delivered successfully")

    opened_count: int = strawberry.field(description="Number opened")

    clicked_count: int = strawberry.field(description="Number clicked")

    conversion_count: int = strawberry.field(description="Number of conversions")

    # Calculated rates
    delivery_rate: float = strawberry.field(description="Delivery rate (0.0 - 1.0)")

    open_rate: float = strawberry.field(description="Open rate (0.0 - 1.0)")

    click_rate: float = strawberry.field(description="Click-through rate (0.0 - 1.0)")

    conversion_rate: float = strawberry.field(description="Conversion rate (0.0 - 1.0)")

    is_winner: bool = strawberry.field(description="Whether this variant is the winner")

    confidence_level: float | None = strawberry.field(
        description="Statistical confidence level (0.0 - 1.0)"
    )


@strawberry.type
class ABTestConfigType:
    """A/B test configuration."""

    test_name: str = strawberry.field(description="Name of the A/B test")

    description: str | None = strawberry.field(
        description="Test description and hypothesis"
    )

    status: ABTestStatusType = strawberry.field(description="Current test status")

    variants: list[ABTestVariantType] = strawberry.field(description="Test variants")

    # Test configuration
    test_duration: int | None = strawberry.field(description="Test duration in hours")

    minimum_sample_size: int = strawberry.field(
        description="Minimum sample size per variant"
    )

    confidence_threshold: float = strawberry.field(
        description="Required confidence level for significance", default=0.95
    )

    success_metric: str = strawberry.field(
        description="Primary success metric (opens, clicks, conversions)"
    )

    # Auto-optimization
    auto_select_winner: bool = strawberry.field(
        description="Whether to automatically select winner"
    )

    auto_send_winner: bool = strawberry.field(
        description="Whether to automatically send to remaining recipients"
    )

    # Results
    winner_variant_id: UUID | None = strawberry.field(
        description="ID of winning variant (if determined)"
    )

    winner_selected_at: datetime | None = strawberry.field(
        description="When winner was selected"
    )

    statistical_significance: float | None = strawberry.field(
        description="Current statistical significance"
    )


@strawberry.type
class CampaignTargetingType:
    """Campaign targeting and segmentation."""

    # Recipient targeting
    recipient_groups: list[UUID] = strawberry.field(
        description="Recipient group IDs to target"
    )

    individual_recipients: list[UUID] = strawberry.field(
        description="Individual recipient IDs to include"
    )

    excluded_recipients: list[UUID] = strawberry.field(
        description="Recipients to exclude"
    )

    # Filtering criteria
    filters: str | None = strawberry.field(
        description="Advanced filtering criteria (JSON)"
    )

    # Channel targeting
    preferred_channels: list[ContactMethodType] = strawberry.field(
        description="Preferred channels for delivery"
    )

    fallback_channels: list[ContactMethodType] = strawberry.field(
        description="Fallback channels if preferred not available"
    )

    # Estimated reach
    estimated_recipients: int = strawberry.field(
        description="Estimated number of recipients"
    )

    actual_recipients: int | None = strawberry.field(
        description="Actual number of recipients (after campaign runs)"
    )


@strawberry.type
class CampaignAnalyticsType:
    """Comprehensive campaign analytics."""

    # Basic metrics
    total_recipients: int = strawberry.field(description="Total number of recipients")

    total_sent: int = strawberry.field(description="Total notifications sent")

    total_delivered: int = strawberry.field(description="Total notifications delivered")

    total_failed: int = strawberry.field(description="Total failed deliveries")

    total_opened: int = strawberry.field(description="Total opens")

    total_clicked: int = strawberry.field(description="Total clicks")

    total_unsubscribed: int = strawberry.field(description="Total unsubscribes")

    total_bounced: int = strawberry.field(description="Total bounces")

    # Calculated rates
    delivery_rate: float = strawberry.field(
        description="Delivery success rate (0.0 - 1.0)"
    )

    open_rate: float = strawberry.field(description="Open rate (0.0 - 1.0)")

    click_rate: float = strawberry.field(description="Click-through rate (0.0 - 1.0)")

    unsubscribe_rate: float = strawberry.field(
        description="Unsubscribe rate (0.0 - 1.0)"
    )

    bounce_rate: float = strawberry.field(description="Bounce rate (0.0 - 1.0)")

    # Engagement metrics
    unique_opens: int = strawberry.field(
        description="Number of unique recipients who opened"
    )

    unique_clicks: int = strawberry.field(
        description="Number of unique recipients who clicked"
    )

    avg_time_to_open: float | None = strawberry.field(
        description="Average time to first open in hours"
    )

    avg_time_to_click: float | None = strawberry.field(
        description="Average time to first click in hours"
    )

    # Channel breakdown
    by_channel: str = strawberry.field(
        description="Performance breakdown by channel (JSON)"
    )

    # Time-based analytics
    engagement_over_time: str = strawberry.field(
        description="Engagement metrics over time (JSON)"
    )

    delivery_timeline: str = strawberry.field(
        description="Delivery timeline data (JSON)"
    )

    # Geographic data
    by_country: str | None = strawberry.field(
        description="Performance by country (JSON)"
    )

    by_timezone: str | None = strawberry.field(
        description="Performance by timezone (JSON)"
    )

    # Device/client data
    by_device: str | None = strawberry.field(
        description="Opens/clicks by device type (JSON)"
    )

    by_client: str | None = strawberry.field(description="Opens by email client (JSON)")


@strawberry.type
class NotificationCampaignType:
    """Comprehensive notification campaign."""

    id: UUID = strawberry.field(description="Unique campaign identifier")

    name: str = strawberry.field(description="Campaign name")

    description: str | None = strawberry.field(description="Campaign description")

    type: CampaignTypeEnum = strawberry.field(description="Campaign type")

    status: CampaignStatusType = strawberry.field(description="Current campaign status")

    category: NotificationCategoryType = strawberry.field(
        description="Campaign category"
    )

    priority: NotificationPriorityType = strawberry.field(
        description="Campaign priority"
    )

    # Template and content
    template_id: UUID | None = strawberry.field(
        description="Primary template for the campaign"
    )

    # Targeting and segmentation
    targeting: CampaignTargetingType = strawberry.field(
        description="Campaign targeting configuration"
    )

    # Scheduling
    schedule: CampaignScheduleType = strawberry.field(
        description="Campaign scheduling configuration"
    )

    # A/B testing
    ab_test: ABTestConfigType | None = strawberry.field(
        description="A/B test configuration (if applicable)"
    )

    # Analytics and performance
    analytics: CampaignAnalyticsType | None = strawberry.field(
        description="Campaign performance analytics"
    )

    # Progress tracking
    progress_percentage: float = strawberry.field(
        description="Campaign completion percentage (0.0 - 1.0)"
    )

    estimated_completion: datetime | None = strawberry.field(
        description="Estimated completion time"
    )

    # Organization
    tags: list[str] = strawberry.field(description="Tags for organization")

    folder: str | None = strawberry.field(description="Folder/category path")

    # Budget and costs
    budget: float | None = strawberry.field(description="Campaign budget")

    estimated_cost: float | None = strawberry.field(
        description="Estimated campaign cost"
    )

    actual_cost: float | None = strawberry.field(description="Actual campaign cost")

    # Audit fields
    created_by: UUID = strawberry.field(description="User who created the campaign")

    created_at: datetime = strawberry.field(description="When the campaign was created")

    updated_by: UUID | None = strawberry.field(
        description="User who last updated the campaign"
    )

    updated_at: datetime = strawberry.field(
        description="When the campaign was last updated"
    )

    started_at: datetime | None = strawberry.field(
        description="When the campaign was started"
    )

    completed_at: datetime | None = strawberry.field(
        description="When the campaign was completed"
    )


@strawberry.type
class CampaignListType:
    """Paginated list of campaigns."""

    items: list[NotificationCampaignType] = strawberry.field(
        description="Campaigns in this page"
    )

    total_count: int = strawberry.field(description="Total number of campaigns")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class CampaignSummaryType:
    """Summary statistics for campaigns."""

    total_campaigns: int = strawberry.field(description="Total number of campaigns")

    active_campaigns: int = strawberry.field(description="Number of active campaigns")

    by_status: str = strawberry.field(description="Count by status (JSON object)")

    by_type: str = strawberry.field(description="Count by type (JSON object)")

    by_category: str = strawberry.field(description="Count by category (JSON object)")

    total_recipients_today: int = strawberry.field(
        description="Total recipients reached today"
    )

    total_cost_this_month: float | None = strawberry.field(
        description="Total campaign costs this month"
    )

    avg_delivery_rate: float = strawberry.field(
        description="Average delivery rate across all campaigns (0.0 - 1.0)"
    )

    avg_engagement_rate: float = strawberry.field(
        description="Average engagement rate across all campaigns (0.0 - 1.0)"
    )

    most_successful_campaigns: list[NotificationCampaignType] = strawberry.field(
        description="Most successful campaigns by engagement"
    )
