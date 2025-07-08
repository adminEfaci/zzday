"""GraphQL types for Email service entities.

This module provides GraphQL type definitions for email service integration,
including email sending, templates, and analytics.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import EmailProviderEnum


@strawberry.type
class EmailAddress:
    """GraphQL type for email addresses."""

    email: str
    name: str | None = None

    @strawberry.field
    def display_name(self) -> str:
        """Get display name for email address."""
        if self.name:
            return f"{self.name} <{self.email}>"
        return self.email


@strawberry.type
class EmailAttachment:
    """GraphQL type for email attachments."""

    filename: str
    content_type: str
    size_bytes: int
    content: str | None = None  # Base64 encoded content
    url: str | None = None  # URL to attachment content

    # Metadata
    disposition: str = "attachment"  # "attachment", "inline"
    content_id: str | None = None  # For inline images

    @strawberry.field
    def size_mb(self) -> float:
        """Get attachment size in MB."""
        return self.size_bytes / (1024 * 1024)


@strawberry.type
class EmailTemplate:
    """GraphQL type for email templates."""

    template_id: UUID
    integration_id: UUID

    # Template details
    name: str
    description: str | None = None
    subject: str
    html_content: str | None = None
    text_content: str | None = None

    # Template variables
    variables: list[str] = strawberry.field(default_factory=list)
    variable_descriptions: dict[str, str] = strawberry.field(default_factory=dict)

    # Categories and tags
    category: str | None = None
    tags: list[str] = strawberry.field(default_factory=list)

    # Status
    is_active: bool = True
    version: str = "1.0"

    # Usage statistics
    total_sends: int = 0
    total_opens: int = 0
    total_clicks: int = 0

    # Timestamps
    created_at: datetime
    updated_at: datetime
    last_used: datetime | None = None

    @strawberry.field
    def open_rate(self) -> float:
        """Calculate email open rate."""
        if self.total_sends == 0:
            return 0.0
        return (self.total_opens / self.total_sends) * 100

    @strawberry.field
    def click_rate(self) -> float:
        """Calculate email click rate."""
        if self.total_sends == 0:
            return 0.0
        return (self.total_clicks / self.total_sends) * 100


@strawberry.type
class EmailCampaign:
    """GraphQL type for email campaigns."""

    campaign_id: UUID
    integration_id: UUID
    template_id: UUID

    # Campaign details
    name: str
    description: str | None = None

    # Recipients
    total_recipients: int = 0
    sent_count: int = 0
    delivered_count: int = 0
    failed_count: int = 0

    # Engagement metrics
    opened_count: int = 0
    clicked_count: int = 0
    unsubscribed_count: int = 0
    bounced_count: int = 0

    # Status
    status: str = "draft"  # "draft", "scheduled", "sending", "sent", "cancelled"

    # Scheduling
    scheduled_at: datetime | None = None
    send_immediately: bool = False

    # Timestamps
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @strawberry.field
    def delivery_rate(self) -> float:
        """Calculate delivery rate."""
        if self.sent_count == 0:
            return 0.0
        return (self.delivered_count / self.sent_count) * 100

    @strawberry.field
    def open_rate(self) -> float:
        """Calculate open rate."""
        if self.delivered_count == 0:
            return 0.0
        return (self.opened_count / self.delivered_count) * 100

    @strawberry.field
    def click_rate(self) -> float:
        """Calculate click rate."""
        if self.delivered_count == 0:
            return 0.0
        return (self.clicked_count / self.delivered_count) * 100


@strawberry.type
class EmailEvent:
    """GraphQL type for email events."""

    event_id: UUID
    email_id: UUID

    # Event details
    event_type: str  # "sent", "delivered", "opened", "clicked", "bounced", "spam", "unsubscribed"
    timestamp: datetime

    # Event data
    data: dict[str, Any] = strawberry.field(default_factory=dict)

    # Location and device info
    ip_address: str | None = None
    user_agent: str | None = None
    location: str | None = None

    # Additional context
    link_url: str | None = None  # For click events
    reason: str | None = None  # For bounce/spam events


@strawberry.type
class EmailMetrics:
    """GraphQL type for email metrics."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # Volume metrics
    total_sent: int = 0
    total_delivered: int = 0
    total_bounced: int = 0
    total_opened: int = 0
    total_clicked: int = 0
    total_unsubscribed: int = 0
    total_spam_reports: int = 0

    # Rate metrics
    delivery_rate: float = 0.0
    bounce_rate: float = 0.0
    open_rate: float = 0.0
    click_rate: float = 0.0
    unsubscribe_rate: float = 0.0
    spam_rate: float = 0.0

    # Engagement metrics
    unique_opens: int = 0
    unique_clicks: int = 0
    average_time_to_open_minutes: float = 0.0

    # Top performing content
    top_templates: list[dict[str, Any]] = strawberry.field(default_factory=list)
    top_campaigns: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Trends
    volume_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)
    engagement_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Reputation metrics
    reputation_score: float = 100.0
    domain_reputation: str = "good"  # "excellent", "good", "fair", "poor"
    ip_reputation: str = "good"


@strawberry.type
class Email:
    """GraphQL type for individual emails."""

    email_id: UUID
    integration_id: UUID

    # Email details
    to_addresses: list[EmailAddress] = strawberry.field(default_factory=list)
    from_address: EmailAddress
    reply_to: EmailAddress | None = None
    cc_addresses: list[EmailAddress] = strawberry.field(default_factory=list)
    bcc_addresses: list[EmailAddress] = strawberry.field(default_factory=list)

    # Content
    subject: str
    html_content: str | None = None
    text_content: str | None = None

    # Attachments
    attachments: list[EmailAttachment] = strawberry.field(default_factory=list)

    # Metadata
    template_id: UUID | None = None
    campaign_id: UUID | None = None
    tags: list[str] = strawberry.field(default_factory=list)
    custom_data: dict[str, Any] = strawberry.field(default_factory=dict)

    # Status
    status: str = "draft"  # "draft", "queued", "sending", "sent", "delivered", "failed"
    priority: str = "normal"  # "low", "normal", "high"

    # Provider details
    provider_message_id: str | None = None
    provider_data: dict[str, Any] = strawberry.field(default_factory=dict)

    # Events
    events: list[EmailEvent] = strawberry.field(default_factory=list)

    # Tracking
    track_opens: bool = True
    track_clicks: bool = True

    # Timestamps
    created_at: datetime
    updated_at: datetime
    sent_at: datetime | None = None
    delivered_at: datetime | None = None
    first_opened_at: datetime | None = None

    @strawberry.field
    def is_delivered(self) -> bool:
        """Check if email was delivered."""
        return any(event.event_type == "delivered" for event in self.events)

    @strawberry.field
    def is_opened(self) -> bool:
        """Check if email was opened."""
        return any(event.event_type == "opened" for event in self.events)

    @strawberry.field
    def is_clicked(self) -> bool:
        """Check if email had clicks."""
        return any(event.event_type == "clicked" for event in self.events)

    @strawberry.field
    def total_attachments_size_mb(self) -> float:
        """Calculate total size of attachments in MB."""
        total_bytes = sum(attachment.size_bytes for attachment in self.attachments)
        return total_bytes / (1024 * 1024)


@strawberry.type
class EmailServiceType:
    """GraphQL type for email service management."""

    integration_id: UUID
    provider: EmailProviderEnum

    # Service status
    is_active: bool = True
    is_healthy: bool = True
    last_health_check: datetime | None = None

    # Configuration
    sending_domain: str
    from_name: str
    reply_to_email: str

    # Rate limiting
    rate_limit_per_hour: int = 1000
    current_hour_sent: int = 0
    rate_limit_remaining: int = 1000

    # Recent activity
    recent_emails: list[Email] = strawberry.field(default_factory=list)
    recent_campaigns: list[EmailCampaign] = strawberry.field(default_factory=list)

    # Templates
    templates: list[EmailTemplate] = strawberry.field(default_factory=list)

    # Metrics
    daily_metrics: EmailMetrics
    monthly_metrics: EmailMetrics

    # Quotas and limits
    monthly_quota: int | None = None
    monthly_sent: int = 0
    daily_quota: int | None = None
    daily_sent: int = 0

    # Reputation
    domain_reputation_score: float = 100.0
    ip_reputation_score: float = 100.0

    # Last sync information
    last_sync: datetime | None = None
    sync_status: str = "idle"  # "idle", "syncing", "error"

    @strawberry.field
    def monthly_quota_usage(self) -> float:
        """Calculate monthly quota usage percentage."""
        if not self.monthly_quota:
            return 0.0
        return (self.monthly_sent / self.monthly_quota) * 100

    @strawberry.field
    def daily_quota_usage(self) -> float:
        """Calculate daily quota usage percentage."""
        if not self.daily_quota:
            return 0.0
        return (self.daily_sent / self.daily_quota) * 100

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if email service requires attention."""
        return (
            not self.is_healthy
            or self.domain_reputation_score < 80
            or self.ip_reputation_score < 80
            or (self.monthly_quota and self.monthly_quota_usage() > 90)
        )


@strawberry.type
class EmailServiceError:
    """GraphQL type for email service errors."""

    success: bool = False
    message: str
    error_code: str

    # Email-specific details
    email_id: UUID | None = None
    template_id: UUID | None = None
    campaign_id: UUID | None = None

    # Provider details
    provider: EmailProviderEnum | None = None
    provider_error_code: str | None = None
    provider_error_message: str | None = None

    # Content validation errors
    validation_errors: list[str] = strawberry.field(default_factory=list)

    # Delivery errors
    recipient_errors: dict[str, str] = strawberry.field(default_factory=dict)

    # Recovery information
    is_retryable: bool = True
    retry_after: int | None = None

    # Timestamps
    occurred_at: datetime


__all__ = [
    "Email",
    "EmailAddress",
    "EmailAttachment",
    "EmailCampaign",
    "EmailEvent",
    "EmailMetrics",
    "EmailServiceError",
    "EmailServiceType",
    "EmailTemplate",
]
