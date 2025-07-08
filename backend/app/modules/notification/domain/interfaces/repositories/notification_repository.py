"""Notification Repository Interface.

Domain contract for notification data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
    NotificationStatus,
)


class INotificationRepository(ISpecificationRepository[Notification, UUID], ABC):
    """Repository interface for Notification entity operations."""

    @abstractmethod
    async def find_by_recipient_id(
        self, recipient_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by recipient ID."""

    @abstractmethod
    async def find_by_batch_id(
        self, batch_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by batch ID."""

    @abstractmethod
    async def find_by_template_id(
        self, template_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by template ID."""

    @abstractmethod
    async def find_by_channel(
        self, channel: NotificationChannel, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by channel."""

    @abstractmethod
    async def find_by_status(
        self, status: NotificationStatus, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by status."""

    @abstractmethod
    async def find_by_priority(
        self, priority: NotificationPriority, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by priority."""

    @abstractmethod
    async def find_pending_notifications(
        self,
        channel: NotificationChannel | None = None,
        priority: NotificationPriority | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find pending notifications ready for delivery."""

    @abstractmethod
    async def find_scheduled_notifications(
        self,
        scheduled_before: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find scheduled notifications ready for processing."""

    @abstractmethod
    async def find_failed_notifications(
        self,
        since: datetime | None = None,
        max_retry_count: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find failed notifications that may need retry."""

    @abstractmethod
    async def find_delivered_notifications(
        self,
        since: datetime | None = None,
        recipient_id: UUID | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find successfully delivered notifications."""

    @abstractmethod
    async def find_read_notifications(
        self,
        recipient_id: UUID,
        since: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find notifications that have been read."""

    @abstractmethod
    async def find_unread_notifications(
        self, recipient_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find unread notifications for a recipient."""

    @abstractmethod
    async def find_expired_notifications(
        self,
        expired_before: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Find expired notifications."""

    @abstractmethod
    async def find_notifications_by_correlation_id(
        self, correlation_id: str, limit: int | None = None, offset: int = 0
    ) -> list[Notification]:
        """Find notifications by correlation ID."""

    @abstractmethod
    async def find_notifications_by_external_id(
        self, external_id: str, channel: NotificationChannel | None = None
    ) -> list[Notification]:
        """Find notifications by external provider ID."""

    @abstractmethod
    async def search_notifications(
        self,
        query: str,
        recipient_id: UUID | None = None,
        channel: NotificationChannel | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Notification]:
        """Search notifications by text content."""

    @abstractmethod
    async def get_notification_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get notification statistics."""

    @abstractmethod
    async def get_recipient_statistics(
        self, recipient_id: UUID, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get notification statistics for a recipient."""

    @abstractmethod
    async def get_channel_statistics(
        self, channel: NotificationChannel, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get statistics for a specific channel."""

    @abstractmethod
    async def count_notifications_by_status(
        self, since: datetime | None = None, channel: NotificationChannel | None = None
    ) -> dict[NotificationStatus, int]:
        """Count notifications grouped by status."""

    @abstractmethod
    async def count_notifications_by_channel(
        self, since: datetime | None = None, status: NotificationStatus | None = None
    ) -> dict[NotificationChannel, int]:
        """Count notifications grouped by channel."""

    @abstractmethod
    async def count_notifications_by_priority(
        self, since: datetime | None = None, channel: NotificationChannel | None = None
    ) -> dict[NotificationPriority, int]:
        """Count notifications grouped by priority."""

    @abstractmethod
    async def count_unread_notifications(self, recipient_id: UUID) -> int:
        """Count unread notifications for a recipient."""

    @abstractmethod
    async def get_delivery_rate(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get delivery success rate as percentage."""

    @abstractmethod
    async def get_read_rate(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get read rate as percentage of delivered notifications."""

    @abstractmethod
    async def get_average_delivery_time(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get average delivery time in seconds."""

    @abstractmethod
    async def get_most_active_recipients(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[tuple[UUID, int]]:
        """Get most active recipients by notification count."""

    @abstractmethod
    async def get_most_used_templates(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[tuple[UUID, int]]:
        """Get most used templates by notification count."""

    @abstractmethod
    async def get_error_patterns(
        self,
        since: datetime | None = None,
        channel: NotificationChannel | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get common error patterns in failed notifications."""

    @abstractmethod
    async def get_delivery_timeline(
        self,
        resolution_hours: int = 1,
        since: datetime | None = None,
        channel: NotificationChannel | None = None,
    ) -> dict[datetime, dict[str, int]]:
        """Get delivery statistics over time."""

    @abstractmethod
    async def bulk_mark_as_read(
        self, notification_ids: list[UUID], read_at: datetime | None = None
    ) -> int:
        """Bulk mark notifications as read."""

    @abstractmethod
    async def bulk_update_status(
        self,
        notification_ids: list[UUID],
        status: NotificationStatus,
        error_message: str | None = None,
    ) -> int:
        """Bulk update notification status."""

    @abstractmethod
    async def cleanup_old_notifications(
        self,
        older_than_days: int = 90,
        keep_unread: bool = True,
        batch_size: int = 1000,
    ) -> int:
        """Clean up old notifications."""

    @abstractmethod
    async def cleanup_delivered_notifications(
        self,
        older_than_days: int = 30,
        exclude_channels: list[NotificationChannel] | None = None,
        batch_size: int = 1000,
    ) -> int:
        """Clean up old delivered notifications."""

    @abstractmethod
    async def retry_failed_notifications(
        self, max_retry_count: int = 3, batch_size: int = 100
    ) -> int:
        """Retry failed notifications that haven't exceeded retry limit."""

    @abstractmethod
    async def archive_old_notifications(
        self, older_than_days: int = 365, batch_size: int = 1000
    ) -> int:
        """Archive old notifications to reduce storage."""

    @abstractmethod
    async def detect_delivery_anomalies(
        self, time_window_hours: int = 24, threshold_factor: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalous delivery patterns."""

    @abstractmethod
    async def get_notification_health_report(self) -> dict[str, Any]:
        """Get comprehensive health report for notifications."""

    @abstractmethod
    async def export_notification_data(
        self,
        recipient_id: UUID,
        since: datetime | None = None,
        include_content: bool = False,
    ) -> dict[str, Any]:
        """Export notification data for a recipient."""
