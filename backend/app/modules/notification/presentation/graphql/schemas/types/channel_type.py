"""
Channel GraphQL Types

Types for notification channels including email, SMS, push notifications,
webhooks, and other delivery methods.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from .recipient_type import ContactMethodType


@strawberry.enum
class ChannelStatusType(str):
    """Channel operational status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"


@strawberry.enum
class ChannelProviderType(str):
    """Supported channel providers."""

    # Email providers
    RESEND = "resend"
    SENDGRID = "sendgrid"
    MAILGUN = "mailgun"
    SES = "ses"

    # SMS providers
    TWILIO = "twilio"
    VONAGE = "vonage"

    # Push providers
    FCM = "fcm"
    APNS = "apns"

    # Other
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    INTERNAL = "internal"


@strawberry.type
class ChannelConfigType:
    """Channel configuration settings."""

    api_key: str | None = strawberry.field(
        description="API key or access token (masked for security)"
    )

    endpoint_url: str | None = strawberry.field(description="Custom endpoint URL")

    from_address: str | None = strawberry.field(
        description="Default from address for email channels"
    )

    from_name: str | None = strawberry.field(
        description="Default from name for email channels"
    )

    webhook_url: str | None = strawberry.field(
        description="Webhook URL for webhook channels"
    )

    rate_limit: int | None = strawberry.field(description="Rate limit per minute")

    daily_quota: int | None = strawberry.field(description="Daily sending quota")

    retry_attempts: int = strawberry.field(
        description="Number of retry attempts for failed deliveries", default=3
    )

    retry_delay: int = strawberry.field(
        description="Delay between retries in seconds", default=30
    )

    timeout: int = strawberry.field(
        description="Request timeout in seconds", default=30
    )

    custom_headers: str | None = strawberry.field(
        description="Custom headers for requests (JSON)"
    )

    encryption_enabled: bool = strawberry.field(
        description="Whether encryption is enabled", default=True
    )

    metadata: str | None = strawberry.field(
        description="Additional configuration metadata (JSON)"
    )


@strawberry.type
class ChannelCapabilitiesType:
    """Channel capabilities and supported features."""

    supports_html: bool = strawberry.field(
        description="Whether channel supports HTML content"
    )

    supports_attachments: bool = strawberry.field(
        description="Whether channel supports file attachments"
    )

    supports_templates: bool = strawberry.field(
        description="Whether channel supports templates"
    )

    supports_tracking: bool = strawberry.field(
        description="Whether channel supports delivery tracking"
    )

    supports_rich_content: bool = strawberry.field(
        description="Whether channel supports rich content (images, links)"
    )

    max_content_length: int | None = strawberry.field(
        description="Maximum content length in characters"
    )

    max_subject_length: int | None = strawberry.field(
        description="Maximum subject length in characters"
    )

    max_attachment_size: int | None = strawberry.field(
        description="Maximum attachment size in bytes"
    )

    supported_formats: list[str] = strawberry.field(
        description="Supported content formats (text, html, markdown)"
    )


@strawberry.type
class ChannelHealthType:
    """Channel health and performance metrics."""

    status: ChannelStatusType = strawberry.field(description="Current channel status")

    last_success: datetime | None = strawberry.field(
        description="Last successful delivery"
    )

    last_failure: datetime | None = strawberry.field(description="Last failed delivery")

    success_rate: float = strawberry.field(
        description="Success rate over last 24 hours (0.0 - 1.0)"
    )

    avg_delivery_time: float | None = strawberry.field(
        description="Average delivery time in seconds"
    )

    current_queue_size: int = strawberry.field(
        description="Current number of queued messages"
    )

    quota_used: int = strawberry.field(description="Quota used today")

    quota_remaining: int | None = strawberry.field(
        description="Remaining quota for today"
    )

    error_count: int = strawberry.field(description="Error count in last 24 hours")

    last_error: str | None = strawberry.field(description="Last error message")


@strawberry.type
class ChannelAnalyticsType:
    """Channel analytics and performance data."""

    total_sent: int = strawberry.field(
        description="Total messages sent through this channel"
    )

    total_delivered: int = strawberry.field(description="Total messages delivered")

    total_failed: int = strawberry.field(description="Total messages failed")

    total_bounced: int = strawberry.field(description="Total messages bounced")

    delivery_rate: float = strawberry.field(
        description="Overall delivery rate (0.0 - 1.0)"
    )

    bounce_rate: float = strawberry.field(description="Overall bounce rate (0.0 - 1.0)")

    avg_cost_per_message: float | None = strawberry.field(
        description="Average cost per message"
    )

    daily_volume: str = strawberry.field(
        description="Daily message volume (JSON array)"
    )

    hourly_volume: str = strawberry.field(
        description="Hourly message volume for today (JSON array)"
    )

    top_failure_reasons: str = strawberry.field(
        description="Top failure reasons (JSON array)"
    )


@strawberry.type
class NotificationChannelType:
    """Comprehensive notification channel configuration."""

    id: UUID = strawberry.field(description="Unique channel identifier")

    name: str = strawberry.field(description="Channel name")

    description: str | None = strawberry.field(description="Channel description")

    type: ContactMethodType = strawberry.field(
        description="Channel type (email, sms, push, etc.)"
    )

    provider: ChannelProviderType = strawberry.field(description="Channel provider")

    status: ChannelStatusType = strawberry.field(description="Current channel status")

    enabled: bool = strawberry.field(description="Whether channel is enabled")

    priority: int = strawberry.field(
        description="Channel priority (lower numbers = higher priority)"
    )

    # Configuration
    config: ChannelConfigType = strawberry.field(
        description="Channel configuration settings"
    )

    capabilities: ChannelCapabilitiesType = strawberry.field(
        description="Channel capabilities and features"
    )

    # Health and monitoring
    health: ChannelHealthType = strawberry.field(description="Channel health status")

    analytics: ChannelAnalyticsType = strawberry.field(
        description="Channel analytics and metrics"
    )

    # Fallback configuration
    fallback_channel_id: UUID | None = strawberry.field(
        description="Fallback channel for failures"
    )

    fallback_enabled: bool = strawberry.field(description="Whether fallback is enabled")

    # Environment and access
    environment: str = strawberry.field(
        description="Environment (dev, staging, prod)", default="prod"
    )

    tags: list[str] = strawberry.field(description="Tags for organization")

    # Audit fields
    created_by: UUID = strawberry.field(description="User who created the channel")

    created_at: datetime = strawberry.field(description="When the channel was created")

    updated_at: datetime = strawberry.field(
        description="When the channel was last updated"
    )

    last_used: datetime | None = strawberry.field(
        description="When the channel was last used"
    )


@strawberry.type
class ChannelTestResultType:
    """Result of channel testing."""

    success: bool = strawberry.field(description="Whether the test was successful")

    response_time: float = strawberry.field(description="Response time in milliseconds")

    status_code: int | None = strawberry.field(
        description="HTTP status code if applicable"
    )

    message: str = strawberry.field(description="Test result message")

    error_details: str | None = strawberry.field(
        description="Error details if test failed"
    )

    tested_at: datetime = strawberry.field(description="When the test was performed")


@strawberry.type
class ChannelListType:
    """Paginated list of channels."""

    items: list[NotificationChannelType] = strawberry.field(
        description="Channels in this page"
    )

    total_count: int = strawberry.field(description="Total number of channels")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class ChannelSummaryType:
    """Summary statistics for channels."""

    total_channels: int = strawberry.field(description="Total number of channels")

    active_channels: int = strawberry.field(description="Number of active channels")

    by_type: str = strawberry.field(description="Count by channel type (JSON object)")

    by_provider: str = strawberry.field(description="Count by provider (JSON object)")

    by_status: str = strawberry.field(description="Count by status (JSON object)")

    total_volume_today: int = strawberry.field(
        description="Total messages sent today across all channels"
    )

    avg_success_rate: float = strawberry.field(
        description="Average success rate across all channels (0.0 - 1.0)"
    )

    channels_with_errors: int = strawberry.field(
        description="Number of channels with recent errors"
    )
