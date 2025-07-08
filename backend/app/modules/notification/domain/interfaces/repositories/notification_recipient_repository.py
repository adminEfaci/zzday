"""Notification Recipient Repository Interface.

Domain contract for notification recipient data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.notification.domain.entities.notification_recipient import (
    NotificationRecipient,
)
from app.modules.notification.domain.enums import NotificationChannel, RecipientStatus


class INotificationRecipientRepository(
    ISpecificationRepository[NotificationRecipient, UUID], ABC
):
    """Repository interface for NotificationRecipient entity operations."""

    @abstractmethod
    async def find_by_user_id(self, user_id: UUID) -> NotificationRecipient | None:
        """Find recipient by user ID."""

    @abstractmethod
    async def find_by_email(self, email: str) -> NotificationRecipient | None:
        """Find recipient by email address."""

    @abstractmethod
    async def find_by_phone_number(
        self, phone_number: str
    ) -> NotificationRecipient | None:
        """Find recipient by phone number."""

    @abstractmethod
    async def find_by_device_token(
        self, device_token: str, channel: NotificationChannel
    ) -> NotificationRecipient | None:
        """Find recipient by device token for push notifications."""

    @abstractmethod
    async def find_by_status(
        self, status: RecipientStatus, limit: int | None = None, offset: int = 0
    ) -> list[NotificationRecipient]:
        """Find recipients by status."""

    @abstractmethod
    async def find_active_recipients(
        self, limit: int | None = None, offset: int = 0
    ) -> list[NotificationRecipient]:
        """Find active recipients."""

    @abstractmethod
    async def find_opted_out_recipients(
        self,
        channel: NotificationChannel | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Find recipients who have opted out."""

    @abstractmethod
    async def find_bounced_recipients(
        self,
        channel: NotificationChannel | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Find recipients with bounced notifications."""

    @abstractmethod
    async def find_recipients_by_preference(
        self,
        channel: NotificationChannel,
        enabled: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Find recipients by channel preference."""

    @abstractmethod
    async def find_recipients_by_timezone(
        self, timezone: str, limit: int | None = None, offset: int = 0
    ) -> list[NotificationRecipient]:
        """Find recipients in a specific timezone."""

    @abstractmethod
    async def find_recipients_by_language(
        self, language: str, limit: int | None = None, offset: int = 0
    ) -> list[NotificationRecipient]:
        """Find recipients with a specific language preference."""

    @abstractmethod
    async def find_recipients_with_tags(
        self,
        tags: list[str],
        match_all: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Find recipients by tags."""

    @abstractmethod
    async def find_inactive_recipients(
        self, inactive_days: int = 90, limit: int | None = None, offset: int = 0
    ) -> list[NotificationRecipient]:
        """Find recipients inactive for specified days."""

    @abstractmethod
    async def find_recipients_by_engagement_score(
        self,
        min_score: float,
        max_score: float | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Find recipients by engagement score range."""

    @abstractmethod
    async def search_recipients(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationRecipient]:
        """Search recipients by text query."""

    @abstractmethod
    async def email_exists(
        self, email: str, exclude_recipient_id: UUID | None = None
    ) -> bool:
        """Check if email address exists."""

    @abstractmethod
    async def phone_exists(
        self, phone_number: str, exclude_recipient_id: UUID | None = None
    ) -> bool:
        """Check if phone number exists."""

    @abstractmethod
    async def device_token_exists(
        self,
        device_token: str,
        channel: NotificationChannel,
        exclude_recipient_id: UUID | None = None,
    ) -> bool:
        """Check if device token exists for channel."""

    @abstractmethod
    async def get_recipient_statistics(
        self, recipient_id: UUID
    ) -> dict[str, Any] | None:
        """Get statistics for a specific recipient."""

    @abstractmethod
    async def get_system_recipient_statistics(self) -> dict[str, Any]:
        """Get system-wide recipient statistics."""

    @abstractmethod
    async def count_recipients_by_status(self) -> dict[RecipientStatus, int]:
        """Count recipients grouped by status."""

    @abstractmethod
    async def count_recipients_by_channel_preference(
        self,
    ) -> dict[NotificationChannel, int]:
        """Count recipients grouped by channel preferences."""

    @abstractmethod
    async def count_recipients_by_timezone(self) -> dict[str, int]:
        """Count recipients grouped by timezone."""

    @abstractmethod
    async def count_recipients_by_language(self) -> dict[str, int]:
        """Count recipients grouped by language."""

    @abstractmethod
    async def get_engagement_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get recipient engagement statistics."""

    @abstractmethod
    async def get_opt_out_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get opt-out statistics by channel."""

    @abstractmethod
    async def get_bounce_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get bounce statistics by channel."""

    @abstractmethod
    async def get_most_engaged_recipients(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get most engaged recipients."""

    @abstractmethod
    async def get_least_engaged_recipients(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get least engaged recipients."""

    @abstractmethod
    async def get_recipients_needing_attention(self) -> list[NotificationRecipient]:
        """Get recipients that need administrative attention."""

    @abstractmethod
    async def bulk_update_preferences(
        self, recipient_ids: list[UUID], preferences: dict[NotificationChannel, bool]
    ) -> int:
        """Bulk update channel preferences."""

    @abstractmethod
    async def bulk_add_tags(self, recipient_ids: list[UUID], tags: list[str]) -> int:
        """Bulk add tags to recipients."""

    @abstractmethod
    async def bulk_remove_tags(self, recipient_ids: list[UUID], tags: list[str]) -> int:
        """Bulk remove tags from recipients."""

    @abstractmethod
    async def bulk_update_status(
        self,
        recipient_ids: list[UUID],
        status: RecipientStatus,
        reason: str | None = None,
    ) -> int:
        """Bulk update recipient status."""

    @abstractmethod
    async def cleanup_inactive_recipients(
        self, inactive_days: int = 365, dry_run: bool = True
    ) -> int:
        """Clean up long-inactive recipients."""

    @abstractmethod
    async def merge_duplicate_recipients(
        self, primary_recipient_id: UUID, duplicate_recipient_ids: list[UUID]
    ) -> NotificationRecipient:
        """Merge duplicate recipient records."""

    @abstractmethod
    async def detect_duplicate_recipients(
        self, similarity_threshold: float = 0.9
    ) -> list[list[NotificationRecipient]]:
        """Detect potentially duplicate recipients."""

    @abstractmethod
    async def validate_contact_information(self, recipient_id: UUID) -> dict[str, Any]:
        """Validate recipient contact information."""

    @abstractmethod
    async def update_engagement_scores(self, batch_size: int = 1000) -> int:
        """Update engagement scores for all recipients."""

    @abstractmethod
    async def export_recipient_data(
        self, recipient_id: UUID, include_statistics: bool = True
    ) -> dict[str, Any]:
        """Export complete recipient data."""

    @abstractmethod
    async def import_recipients(
        self,
        recipient_data: list[dict[str, Any]],
        created_by: UUID,
        overwrite_existing: bool = False,
    ) -> list[NotificationRecipient]:
        """Import recipients from data."""

    @abstractmethod
    async def get_recipient_health_report(self) -> dict[str, Any]:
        """Get health report for recipient management."""

    @abstractmethod
    async def detect_recipient_anomalies(
        self, time_window_days: int = 7, threshold_factor: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalous recipient patterns."""
