"""Analytics GraphQL types.

This module contains GraphQL type definitions for notification analytics and reporting.
"""

from datetime import datetime
from typing import Any

import strawberry

from ..enums import (
    AnalyticsTimeframeEnum,
    CampaignStatusEnum,
    NotificationChannelEnum,
    TemplateTypeEnum,
)

# Constants
MIN_DATA_POINTS_FOR_GROWTH = 2
ANALYTICS_REFRESH_THRESHOLD_SECONDS = 3600  # 1 hour


@strawberry.type
class TimeSeriesDataPoint:
    """GraphQL type for time series data points."""

    timestamp: datetime
    value: float
    label: str | None = None

    # Additional dimensions
    dimensions: dict[str, str] = strawberry.field(default_factory=dict)


@strawberry.type
class TimeSeriesData:
    """GraphQL type for time series data."""

    metric_name: str
    timeframe: AnalyticsTimeframeEnum
    start_date: datetime
    end_date: datetime

    # Data points
    data_points: list[TimeSeriesDataPoint] = strawberry.field(default_factory=list)

    # Summary statistics
    total: float = 0.0
    average: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0

    # Trend analysis
    trend_direction: str = "stable"  # "up", "down", "stable"
    trend_percentage: float | None = None

    @strawberry.field
    def growth_rate(self) -> float | None:
        """Calculate growth rate between first and last data points."""
        if len(self.data_points) < MIN_DATA_POINTS_FOR_GROWTH:
            return None

        first_value = self.data_points[0].value
        last_value = self.data_points[-1].value

        if first_value == 0:
            return None

        return ((last_value - first_value) / first_value) * 100


@strawberry.type
class MetricsSummary:
    """GraphQL type for metrics summary."""

    period_start: datetime
    period_end: datetime

    # Volume metrics
    total_notifications: int
    total_sent: int
    total_delivered: int
    total_failed: int
    total_bounced: int

    # Engagement metrics
    total_opens: int = 0
    total_clicks: int = 0
    unique_opens: int = 0
    unique_clicks: int = 0
    total_conversions: int = 0

    # Performance metrics
    average_delivery_time_seconds: float = 0.0
    success_rate: float = 0.0
    open_rate: float = 0.0
    click_rate: float = 0.0
    conversion_rate: float = 0.0
    bounce_rate: float = 0.0

    # Comparison with previous period
    previous_period_start: datetime | None = None
    previous_period_end: datetime | None = None

    # Growth metrics (vs previous period)
    notifications_growth: float | None = None
    delivery_rate_change: float | None = None
    engagement_rate_change: float | None = None

    @strawberry.field
    def engagement_rate(self) -> float:
        """Calculate overall engagement rate."""
        if self.total_delivered == 0:
            return 0.0

        engaged = self.unique_opens + self.unique_clicks
        return (engaged / self.total_delivered) * 100


@strawberry.type
class ChannelMetrics:
    """GraphQL type for channel-specific metrics."""

    channel: NotificationChannelEnum
    timeframe: AnalyticsTimeframeEnum

    # Volume
    notifications_sent: int
    notifications_delivered: int
    notifications_failed: int

    # Performance
    delivery_rate: float
    average_delivery_time_seconds: float

    # Channel-specific metrics
    opens: int | None = None
    clicks: int | None = None
    bounces: int | None = None
    complaints: int | None = None

    # Cost metrics
    total_cost: float | None = None
    cost_per_notification: float | None = None
    cost_per_delivery: float | None = None

    # Provider metrics
    provider_success_rate: float | None = None
    provider_response_time_ms: float | None = None

    @strawberry.field
    def efficiency_score(self) -> float:
        """Calculate channel efficiency score (0-100)."""
        # Weighted score based on delivery rate, speed, and cost
        delivery_score = self.delivery_rate

        # Speed score (assume < 5 seconds is optimal)
        speed_score = max(0, 100 - (self.average_delivery_time_seconds / 5) * 10)
        speed_score = min(100, speed_score)

        # Cost score (if available)
        cost_score = 50  # Default neutral score

        # Weighted average
        return delivery_score * 0.5 + speed_score * 0.3 + cost_score * 0.2


@strawberry.type
class TemplateMetrics:
    """GraphQL type for template-specific metrics."""

    template_id: strawberry.ID
    template_name: str
    template_type: TemplateTypeEnum
    channel: NotificationChannelEnum

    # Usage metrics
    total_usage: int
    recent_usage: int  # Last 30 days

    # Performance metrics
    delivery_rate: float
    open_rate: float | None = None
    click_rate: float | None = None
    conversion_rate: float | None = None
    unsubscribe_rate: float | None = None

    # Engagement trends
    engagement_trend: str = "stable"  # "improving", "declining", "stable"
    performance_score: float = 0.0  # 0-100 score

    # A/B test results (if applicable)
    ab_test_winner: bool | None = None
    ab_test_lift: float | None = None

    # Comparison metrics
    industry_benchmark_open_rate: float | None = None
    industry_benchmark_click_rate: float | None = None

    @strawberry.field
    def performance_vs_benchmark(self) -> float | None:
        """Calculate performance vs industry benchmark."""
        if not self.industry_benchmark_open_rate or not self.open_rate:
            return None

        return (
            (self.open_rate - self.industry_benchmark_open_rate)
            / self.industry_benchmark_open_rate
        ) * 100


@strawberry.type
class CampaignMetrics:
    """GraphQL type for campaign-specific metrics."""

    campaign_id: strawberry.ID
    campaign_name: str
    campaign_status: CampaignStatusEnum

    # Volume metrics
    total_recipients: int
    sent_count: int
    delivered_count: int
    failed_count: int

    # Engagement metrics
    opens: int = 0
    clicks: int = 0
    conversions: int = 0
    unsubscribes: int = 0

    # Calculated rates
    delivery_rate: float = 0.0
    open_rate: float = 0.0
    click_rate: float = 0.0
    conversion_rate: float = 0.0
    unsubscribe_rate: float = 0.0

    # Revenue metrics
    total_revenue: float | None = None
    revenue_per_recipient: float | None = None
    return_on_investment: float | None = None

    # Timing metrics
    campaign_duration_hours: float | None = None
    time_to_peak_engagement_hours: float | None = None

    # Goal achievement
    target_open_rate: float | None = None
    target_click_rate: float | None = None
    open_rate_achievement: float | None = None  # Percentage of goal achieved
    click_rate_achievement: float | None = None

    @strawberry.field
    def roi_percentage(self) -> float | None:
        """Calculate ROI percentage."""
        if not self.return_on_investment:
            return None
        return self.return_on_investment * 100


@strawberry.type
class DeliveryMetrics:
    """GraphQL type for delivery performance metrics."""

    timeframe: AnalyticsTimeframeEnum

    # Volume metrics
    total_notifications: int
    successful_deliveries: int
    failed_deliveries: int
    pending_deliveries: int

    # Performance metrics
    overall_success_rate: float
    average_delivery_time_seconds: float
    median_delivery_time_seconds: float
    p95_delivery_time_seconds: float
    p99_delivery_time_seconds: float

    # Error analysis
    top_error_types: list[dict[str, Any]] = strawberry.field(default_factory=list)
    error_rate_by_channel: dict[str, float] = strawberry.field(default_factory=dict)

    # Provider performance
    provider_success_rates: dict[str, float] = strawberry.field(default_factory=dict)
    provider_avg_response_times: dict[str, float] = strawberry.field(
        default_factory=dict
    )

    # Retry metrics
    total_retries: int = 0
    successful_retries: int = 0
    max_retries_reached: int = 0

    @strawberry.field
    def retry_success_rate(self) -> float:
        """Calculate retry success rate."""
        if self.total_retries == 0:
            return 0.0
        return (self.successful_retries / self.total_retries) * 100


@strawberry.type
class EngagementMetrics:
    """GraphQL type for engagement metrics."""

    timeframe: AnalyticsTimeframeEnum

    # Open metrics
    total_opens: int
    unique_opens: int
    open_rate: float

    # Click metrics
    total_clicks: int
    unique_clicks: int
    click_rate: float
    click_to_open_rate: float

    # Time-based engagement
    opens_by_hour: list[TimeSeriesDataPoint] = strawberry.field(default_factory=list)
    clicks_by_hour: list[TimeSeriesDataPoint] = strawberry.field(default_factory=list)

    # Device/platform breakdown
    opens_by_device: dict[str, int] = strawberry.field(default_factory=dict)
    clicks_by_device: dict[str, int] = strawberry.field(default_factory=dict)

    # Geographic breakdown
    opens_by_country: dict[str, int] = strawberry.field(default_factory=dict)
    clicks_by_country: dict[str, int] = strawberry.field(default_factory=dict)

    # Engagement patterns
    peak_engagement_hour: int | None = None
    peak_engagement_day: str | None = None
    average_time_to_open_minutes: float | None = None
    average_time_to_click_minutes: float | None = None


@strawberry.type
class RevenueMetrics:
    """GraphQL type for revenue and conversion metrics."""

    timeframe: AnalyticsTimeframeEnum

    # Revenue totals
    total_revenue: float
    revenue_from_email: float = 0.0
    revenue_from_sms: float = 0.0
    revenue_from_push: float = 0.0

    # Conversion metrics
    total_conversions: int
    conversion_rate: float
    average_order_value: float

    # Attribution
    first_click_revenue: float = 0.0
    last_click_revenue: float = 0.0

    # Time to conversion
    average_time_to_conversion_hours: float | None = None
    median_time_to_conversion_hours: float | None = None

    # Goals and targets
    revenue_target: float | None = None
    conversion_target: float | None = None
    target_achievement_percentage: float | None = None


@strawberry.type
class AnalyticsType:
    """GraphQL type for comprehensive analytics."""

    # Time period
    start_date: datetime
    end_date: datetime
    timezone: str = "UTC"

    # Summary metrics
    summary: MetricsSummary

    # Channel performance
    channel_metrics: list[ChannelMetrics] = strawberry.field(default_factory=list)

    # Template performance
    template_metrics: list[TemplateMetrics] = strawberry.field(default_factory=list)

    # Campaign performance
    campaign_metrics: list[CampaignMetrics] = strawberry.field(default_factory=list)

    # Delivery performance
    delivery_metrics: DeliveryMetrics

    # Engagement analysis
    engagement_metrics: EngagementMetrics

    # Revenue analysis
    revenue_metrics: RevenueMetrics | None = None

    # Trends and forecasting
    trends: list[TimeSeriesData] = strawberry.field(default_factory=list)

    # Insights and recommendations
    insights: list[str] = strawberry.field(default_factory=list)
    recommendations: list[str] = strawberry.field(default_factory=list)

    @strawberry.field
    def top_performing_templates(self, limit: int = 5) -> list[TemplateMetrics]:
        """Get top performing templates by engagement."""
        return sorted(
            self.template_metrics, key=lambda t: t.performance_score, reverse=True
        )[:limit]

    @strawberry.field
    def top_performing_channels(self) -> list[ChannelMetrics]:
        """Get channels ranked by efficiency score."""
        return sorted(
            self.channel_metrics, key=lambda c: c.efficiency_score(), reverse=True
        )

    @strawberry.field
    def engagement_trend_direction(self) -> str:
        """Determine overall engagement trend."""
        engagement_trend = next(
            (t for t in self.trends if t.metric_name == "engagement_rate"), None
        )
        return engagement_trend.trend_direction if engagement_trend else "stable"


@strawberry.type
class AnalyticsReport:
    """GraphQL type for analytics reports."""

    id: strawberry.ID
    name: str
    description: str | None = None

    # Report configuration
    report_type: str  # "summary", "detailed", "campaign", "channel"
    timeframe: AnalyticsTimeframeEnum
    filters: dict[str, Any] = strawberry.field(default_factory=dict)

    # Analytics data
    analytics: AnalyticsType

    # Report metadata
    generated_at: datetime
    generated_by: strawberry.ID | None = None

    # Sharing and export
    is_public: bool = False
    export_url: str | None = None
    expires_at: datetime | None = None

    @strawberry.field
    def can_refresh(self) -> bool:
        """Check if report can be refreshed with current data."""
        # Allow refresh if generated more than 1 hour ago
        time_diff = datetime.utcnow() - self.generated_at
        return time_diff.total_seconds() > ANALYTICS_REFRESH_THRESHOLD_SECONDS
