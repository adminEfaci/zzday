"""
Recipient GraphQL Types

Types for notification recipients with multi-channel contact information
and preference management.
"""

from datetime import datetime
from uuid import UUID

import strawberry


@strawberry.enum
class RecipientStatusType(str):
    """Recipient status for notifications."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    BOUNCED = "bounced"
    UNSUBSCRIBED = "unsubscribed"
    BLOCKED = "blocked"
    PENDING_VERIFICATION = "pending_verification"


@strawberry.enum
class ContactMethodType(str):
    """Available contact methods."""

    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    WEBHOOK = "webhook"
    IN_APP = "in_app"
    VOICE = "voice"
    SLACK = "slack"
    TEAMS = "teams"


@strawberry.type
class ContactInfoType:
    """Contact information for a specific channel."""

    method: ContactMethodType = strawberry.field(description="Contact method type")

    value: str = strawberry.field(description="Contact value (email, phone, etc.)")

    verified: bool = strawberry.field(
        description="Whether this contact method is verified"
    )

    primary: bool = strawberry.field(
        description="Whether this is the primary contact for this method"
    )

    metadata: str | None = strawberry.field(
        description="Additional metadata for this contact method (JSON)"
    )

    created_at: datetime = strawberry.field(description="When this contact was added")

    verified_at: datetime | None = strawberry.field(
        description="When this contact was verified"
    )


@strawberry.type
class NotificationPreferenceType:
    """Individual notification preferences."""

    channel: ContactMethodType = strawberry.field(description="Notification channel")

    enabled: bool = strawberry.field(
        description="Whether notifications are enabled for this channel"
    )

    categories: list[str] = strawberry.field(
        description="Allowed notification categories"
    )

    frequency: str = strawberry.field(
        description="Notification frequency (immediate, daily, weekly, etc.)"
    )

    quiet_hours: str | None = strawberry.field(
        description="Quiet hours configuration (JSON)"
    )

    timezone: str | None = strawberry.field(
        description="User's timezone for scheduling"
    )


@strawberry.type
class RecipientGroupType:
    """Group of recipients for bulk operations."""

    id: UUID = strawberry.field(description="Group identifier")

    name: str = strawberry.field(description="Group name")

    description: str | None = strawberry.field(description="Group description")

    tags: list[str] = strawberry.field(description="Tags for group organization")

    recipient_count: int = strawberry.field(
        description="Number of recipients in this group"
    )

    created_at: datetime = strawberry.field(description="When the group was created")

    updated_at: datetime = strawberry.field(
        description="When the group was last updated"
    )


@strawberry.type
class RecipientType:
    """Comprehensive recipient information."""

    id: UUID = strawberry.field(description="Unique recipient identifier")

    user_id: UUID | None = strawberry.field(
        description="Associated user ID if recipient is a registered user"
    )

    name: str | None = strawberry.field(description="Recipient's display name")

    first_name: str | None = strawberry.field(description="Recipient's first name")

    last_name: str | None = strawberry.field(description="Recipient's last name")

    # Contact information
    contact_info: list[ContactInfoType] = strawberry.field(
        description="All contact methods for this recipient"
    )

    primary_email: str | None = strawberry.field(description="Primary email address")

    primary_phone: str | None = strawberry.field(description="Primary phone number")

    # Status and preferences
    status: RecipientStatusType = strawberry.field(description="Recipient status")

    preferences: list[NotificationPreferenceType] = strawberry.field(
        description="Notification preferences per channel"
    )

    # Grouping and segmentation
    groups: list[RecipientGroupType] = strawberry.field(
        description="Groups this recipient belongs to"
    )

    tags: list[str] = strawberry.field(description="Tags for recipient segmentation")

    custom_fields: str | None = strawberry.field(
        description="Custom recipient fields (JSON)"
    )

    # Analytics and tracking
    total_notifications_sent: int = strawberry.field(
        description="Total notifications sent to this recipient"
    )

    total_notifications_delivered: int = strawberry.field(
        description="Total notifications delivered"
    )

    total_notifications_clicked: int = strawberry.field(
        description="Total notifications clicked"
    )

    last_notification_sent: datetime | None = strawberry.field(
        description="When the last notification was sent"
    )

    last_notification_opened: datetime | None = strawberry.field(
        description="When the last notification was opened"
    )

    last_notification_clicked: datetime | None = strawberry.field(
        description="When the last notification was clicked"
    )

    engagement_score: float | None = strawberry.field(
        description="Engagement score (0.0 - 1.0)"
    )

    # Audit fields
    created_at: datetime = strawberry.field(
        description="When the recipient was created"
    )

    updated_at: datetime = strawberry.field(
        description="When the recipient was last updated"
    )

    last_seen: datetime | None = strawberry.field(
        description="When the recipient was last seen/active"
    )


@strawberry.type
class RecipientListType:
    """Paginated list of recipients."""

    items: list[RecipientType] = strawberry.field(description="Recipients in this page")

    total_count: int = strawberry.field(description="Total number of recipients")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class RecipientSummaryType:
    """Summary statistics for recipients."""

    total_recipients: int = strawberry.field(description="Total number of recipients")

    by_status: str = strawberry.field(description="Count by status (JSON object)")

    by_channel: str = strawberry.field(
        description="Count by preferred channel (JSON object)"
    )

    verified_emails: int = strawberry.field(
        description="Number of verified email addresses"
    )

    verified_phones: int = strawberry.field(
        description="Number of verified phone numbers"
    )

    active_recipients: int = strawberry.field(description="Number of active recipients")

    engagement_rate: float = strawberry.field(
        description="Overall engagement rate (0.0 - 1.0)"
    )

    top_groups: list[RecipientGroupType] = strawberry.field(
        description="Top recipient groups by size"
    )
