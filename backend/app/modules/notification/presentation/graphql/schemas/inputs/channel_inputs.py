"""
Channel GraphQL Input Types

Input types for notification channel operations including configuration,
testing, and management.
"""

from uuid import UUID

import strawberry

from ..types.channel_type import ChannelProviderType, ChannelStatusType
from ..types.recipient_type import ContactMethodType


@strawberry.input
class ChannelConfigInput:
    """Input for channel configuration settings."""

    api_key: str | None = strawberry.field(description="API key or access token")

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

    retry_attempts: int | None = strawberry.field(
        description="Number of retry attempts for failed deliveries", default=3
    )

    retry_delay: int | None = strawberry.field(
        description="Delay between retries in seconds", default=30
    )

    timeout: int | None = strawberry.field(
        description="Request timeout in seconds", default=30
    )

    custom_headers: str | None = strawberry.field(
        description="Custom headers for requests (JSON)"
    )

    encryption_enabled: bool | None = strawberry.field(
        description="Whether encryption is enabled", default=True
    )

    metadata: str | None = strawberry.field(
        description="Additional configuration metadata (JSON)"
    )


@strawberry.input
class ChannelCreateInput:
    """Input for creating a new notification channel."""

    name: str = strawberry.field(description="Channel name")

    description: str | None = strawberry.field(description="Channel description")

    type: ContactMethodType = strawberry.field(
        description="Channel type (email, sms, push, etc.)"
    )

    provider: ChannelProviderType = strawberry.field(description="Channel provider")

    enabled: bool | None = strawberry.field(
        description="Whether channel is enabled", default=True
    )

    priority: int | None = strawberry.field(
        description="Channel priority (lower numbers = higher priority)", default=100
    )

    config: ChannelConfigInput = strawberry.field(
        description="Channel configuration settings"
    )

    fallback_channel_id: UUID | None = strawberry.field(
        description="Fallback channel for failures"
    )

    fallback_enabled: bool | None = strawberry.field(
        description="Whether fallback is enabled", default=False
    )

    environment: str | None = strawberry.field(
        description="Environment (dev, staging, prod)", default="prod"
    )

    tags: list[str] | None = strawberry.field(description="Tags for organization")


@strawberry.input
class ChannelUpdateInput:
    """Input for updating an existing channel."""

    name: str | None = strawberry.field(description="Channel name")

    description: str | None = strawberry.field(description="Channel description")

    status: ChannelStatusType | None = strawberry.field(description="Channel status")

    enabled: bool | None = strawberry.field(description="Whether channel is enabled")

    priority: int | None = strawberry.field(
        description="Channel priority (lower numbers = higher priority)"
    )

    config: ChannelConfigInput | None = strawberry.field(
        description="Channel configuration settings"
    )

    fallback_channel_id: UUID | None = strawberry.field(
        description="Fallback channel for failures"
    )

    fallback_enabled: bool | None = strawberry.field(
        description="Whether fallback is enabled"
    )

    tags: list[str] | None = strawberry.field(description="Tags for organization")


@strawberry.input
class ChannelFilterInput:
    """Filter input for channel queries."""

    type: list[ContactMethodType] | None = strawberry.field(
        description="Filter by channel type"
    )

    provider: list[ChannelProviderType] | None = strawberry.field(
        description="Filter by provider"
    )

    status: list[ChannelStatusType] | None = strawberry.field(
        description="Filter by status"
    )

    enabled: bool | None = strawberry.field(
        description="Filter by enabled/disabled channels"
    )

    environment: list[str] | None = strawberry.field(
        description="Filter by environment"
    )

    tags: list[str] | None = strawberry.field(description="Filter by tags (OR logic)")

    tags_all: list[str] | None = strawberry.field(
        description="Filter by tags (AND logic - must have all)"
    )

    has_fallback: bool | None = strawberry.field(
        description="Filter channels with/without fallback configuration"
    )

    created_by: UUID | None = strawberry.field(description="Filter by creator")

    search_query: str | None = strawberry.field(
        description="Search in channel name and description"
    )


@strawberry.input
class ChannelTestInput:
    """Input for testing channel connectivity."""

    channel_id: UUID = strawberry.field(description="Channel to test")

    test_recipient: str = strawberry.field(
        description="Test recipient address (email, phone, etc.)"
    )

    test_message: str | None = strawberry.field(
        description="Test message content",
        default="Test message from notification system",
    )

    test_subject: str | None = strawberry.field(
        description="Test message subject (for email)", default="Test Notification"
    )

    include_metadata: bool | None = strawberry.field(
        description="Include detailed test metadata", default=True
    )


@strawberry.input
class BulkChannelUpdateInput:
    """Input for bulk channel operations."""

    channel_ids: list[UUID] = strawberry.field(description="Channel IDs to update")

    status: ChannelStatusType | None = strawberry.field(
        description="New status for all channels"
    )

    enabled: bool | None = strawberry.field(description="Enable/disable all channels")

    tags_to_add: list[str] | None = strawberry.field(
        description="Tags to add to all channels"
    )

    tags_to_remove: list[str] | None = strawberry.field(
        description="Tags to remove from all channels"
    )

    environment: str | None = strawberry.field(
        description="Update environment for all channels"
    )
