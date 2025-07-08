"""Campaign input types.

This module contains GraphQL input types for managing notification campaigns.
"""

from datetime import datetime
from typing import Any

import strawberry

from ..enums import CampaignStatusEnum, NotificationChannelEnum, TemplateTypeEnum


@strawberry.input
class CampaignRecipientInput:
    """GraphQL input for campaign recipients."""

    recipient_id: strawberry.ID

    # Personalization variables
    variables: dict[str, str] | None = None

    # Segmentation
    segments: list[str] | None = None
    tags: list[str] | None = None

    # Override default settings
    preferred_channel: NotificationChannelEnum | None = None
    scheduled_for: datetime | None = None


@strawberry.input
class CampaignScheduleInput:
    """GraphQL input for campaign scheduling."""

    # Basic scheduling
    scheduled_at: datetime | None = None
    timezone: str = "UTC"

    # Recurring campaigns
    is_recurring: bool = False
    recurrence_pattern: str | None = None  # "daily", "weekly", "monthly"
    recurrence_interval: int = 1
    recurrence_end_date: datetime | None = None

    # Send window optimization
    send_window_start: str | None = None  # HH:MM format
    send_window_end: str | None = None  # HH:MM format
    respect_quiet_hours: bool = True
    optimize_send_time: bool = False

    # Throttling and rate limiting
    max_send_rate_per_minute: int | None = None
    max_send_rate_per_hour: int | None = None
    batch_size: int = 100

    # Delivery window
    max_delivery_window_hours: int | None = None
    abort_if_not_sent_by: datetime | None = None


@strawberry.input
class CampaignSegmentInput:
    """GraphQL input for campaign audience segments."""

    name: str
    description: str | None = None

    # Segmentation criteria
    criteria: dict[str, Any]

    # Exclusion criteria
    exclusion_criteria: dict[str, Any] | None = None

    # Dynamic segment settings
    is_dynamic: bool = True
    refresh_before_send: bool = True

    # Size estimation
    estimate_size: bool = True


@strawberry.input
class CampaignABTestInput:
    """GraphQL input for A/B testing configuration."""

    enabled: bool = True

    # Test configuration
    test_name: str
    test_description: str | None = None

    # Traffic split
    control_percentage: int = 50
    variant_percentage: int = 50

    # Templates for each variant
    control_template_id: strawberry.ID
    variant_template_id: strawberry.ID

    # Test parameters
    primary_metric: str = "open_rate"  # "open_rate", "click_rate", "conversion_rate"
    secondary_metrics: list[str] | None = None

    # Statistical significance
    minimum_confidence: float = 95.0
    minimum_sample_size: int = 100
    maximum_test_duration_hours: int | None = None

    # Auto-winner selection
    auto_select_winner: bool = False
    winner_selection_criteria: str = "statistical_significance"

    # Fallback settings
    fallback_to_control_on_error: bool = True


@strawberry.input
class CampaignCreateInput:
    """GraphQL input for creating campaigns."""

    # Basic information
    name: str
    description: str | None = None

    # Campaign configuration
    campaign_type: TemplateTypeEnum
    channel: NotificationChannelEnum

    # Templates
    template_id: strawberry.ID
    fallback_template_id: strawberry.ID | None = None

    # Audience
    segments: list[CampaignSegmentInput] | None = None
    recipient_list: list[CampaignRecipientInput] | None = None

    # Scheduling
    schedule: CampaignScheduleInput

    # A/B Testing
    ab_test: CampaignABTestInput | None = None

    # Campaign settings
    track_opens: bool = True
    track_clicks: bool = True
    track_conversions: bool = False
    allow_unsubscribe: bool = True

    # Content personalization
    default_variables: dict[str, str] | None = None

    # Tags and categorization
    tags: list[str] | None = None
    category: str | None = None

    # Performance goals
    target_open_rate: float | None = None
    target_click_rate: float | None = None
    target_conversion_rate: float | None = None

    # Start as draft
    start_as_draft: bool = True


@strawberry.input
class CampaignUpdateInput:
    """GraphQL input for updating campaigns."""

    # Basic information
    name: str | None = None
    description: str | None = None

    # Templates (only if campaign hasn't started)
    template_id: strawberry.ID | None = None
    fallback_template_id: strawberry.ID | None = None

    # Audience updates (only if campaign hasn't started)
    segments: list[CampaignSegmentInput] | None = None

    # Scheduling updates
    schedule: CampaignScheduleInput | None = None

    # Settings
    track_opens: bool | None = None
    track_clicks: bool | None = None
    track_conversions: bool | None = None
    allow_unsubscribe: bool | None = None

    # Tags and categorization
    tags: list[str] | None = None
    category: str | None = None

    # Performance goals
    target_open_rate: float | None = None
    target_click_rate: float | None = None
    target_conversion_rate: float | None = None

    # Status changes
    is_active: bool | None = None


@strawberry.input
class CampaignActionInput:
    """GraphQL input for campaign actions."""

    campaign_id: strawberry.ID
    action: str  # "start", "pause", "resume", "cancel", "duplicate"

    # Action-specific parameters
    reason: str | None = None

    # For duplication
    new_campaign_name: str | None = None

    # Force action (bypass validation)
    force: bool = False

    # Scheduling for start action
    start_immediately: bool = True
    scheduled_start_time: datetime | None = None


@strawberry.input
class CampaignBulkActionInput:
    """GraphQL input for bulk campaign actions."""

    campaign_ids: list[strawberry.ID]
    action: str  # "start", "pause", "cancel", "tag", "categorize"

    # Action-specific parameters
    tags_to_add: list[str] | None = None
    tags_to_remove: list[str] | None = None
    new_category: str | None = None
    new_status: CampaignStatusEnum | None = None

    # Execution options
    continue_on_error: bool = True
    execute_in_sequence: bool = False

    # Confirmation
    confirm_destructive_actions: bool = False

    # Reason for bulk action
    reason: str | None = None


@strawberry.input
class CampaignSearchInput:
    """GraphQL input for searching campaigns."""

    # Text search
    query: str | None = None

    # Filters
    campaign_types: list[TemplateTypeEnum] | None = None
    channels: list[NotificationChannelEnum] | None = None
    statuses: list[CampaignStatusEnum] | None = None
    tags: list[str] | None = None
    categories: list[str] | None = None

    # Creator filters
    created_by: list[strawberry.ID] | None = None

    # Date filters
    created_after: datetime | None = None
    created_before: datetime | None = None
    scheduled_after: datetime | None = None
    scheduled_before: datetime | None = None
    completed_after: datetime | None = None
    completed_before: datetime | None = None

    # Performance filters
    min_recipients: int | None = None
    max_recipients: int | None = None
    min_open_rate: float | None = None
    min_click_rate: float | None = None
    min_conversion_rate: float | None = None

    # Template filters
    template_ids: list[strawberry.ID] | None = None

    # A/B test filters
    has_ab_test: bool | None = None
    ab_test_completed: bool | None = None

    # Pagination and sorting
    limit: int = 50
    offset: int = 0
    sort_by: str = "created_at"
    sort_direction: str = "desc"


@strawberry.input
class CampaignCloneInput:
    """GraphQL input for cloning campaigns."""

    source_campaign_id: strawberry.ID

    # New campaign details
    new_name: str
    new_description: str | None = None

    # What to clone
    clone_audience: bool = True
    clone_schedule: bool = False  # Usually want to set new schedule
    clone_ab_test: bool = True
    clone_settings: bool = True
    clone_tags: bool = True

    # Modifications
    new_template_id: strawberry.ID | None = None
    new_channel: NotificationChannelEnum | None = None
    new_schedule: CampaignScheduleInput | None = None

    # Start as draft
    start_as_draft: bool = True


@strawberry.input
class CampaignPreviewInput:
    """GraphQL input for previewing campaigns."""

    campaign_id: strawberry.ID

    # Preview options
    estimate_audience_size: bool = True
    estimate_cost: bool = True
    estimate_duration: bool = True
    validate_configuration: bool = True

    # Sample preview
    generate_sample_notifications: bool = True
    sample_count: int = 5

    # Test audience
    test_audience_size: int | None = None

    # Validation options
    check_template_variables: bool = True
    check_recipient_preferences: bool = True
    check_channel_capacity: bool = True


@strawberry.input
class CampaignReportInput:
    """GraphQL input for generating campaign reports."""

    campaign_ids: list[strawberry.ID]

    # Report type
    report_type: str = "performance"  # "performance", "detailed", "comparison"

    # Report options
    include_engagement_metrics: bool = True
    include_delivery_metrics: bool = True
    include_revenue_metrics: bool = False
    include_audience_breakdown: bool = True
    include_time_series: bool = True

    # Comparison options (for comparison reports)
    compare_with_previous: bool = False
    compare_with_benchmark: bool = False

    # Export options
    format: str = "json"  # "json", "pdf", "csv", "xlsx"
    include_charts: bool = False

    # Delivery
    email_to: list[str] | None = None
    generate_summary: bool = True


@strawberry.input
class CampaignOptimizationInput:
    """GraphQL input for campaign optimization suggestions."""

    campaign_id: strawberry.ID

    # Optimization areas
    optimize_send_time: bool = True
    optimize_audience: bool = True
    optimize_content: bool = True
    optimize_frequency: bool = True

    # Analysis options
    analyze_historical_performance: bool = True
    analyze_competitor_benchmarks: bool = False
    analyze_industry_trends: bool = False

    # Recommendation preferences
    conservative_recommendations: bool = False
    include_ab_test_suggestions: bool = True
    max_recommendations: int = 10
