"""Notification Batch Repository Interface.

Domain contract for notification batch data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.notification.domain.aggregates.notification_batch import (
    NotificationBatch,
)
from app.modules.notification.domain.enums import BatchStatus, NotificationChannel


class INotificationBatchRepository(
    ISpecificationRepository[NotificationBatch, UUID], ABC
):
    """Repository interface for NotificationBatch aggregate operations."""

    @abstractmethod
    async def find_by_name(self, name: str) -> NotificationBatch | None:
        """Find batch by name."""

    @abstractmethod
    async def find_by_created_by(
        self, created_by: UUID, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find batches created by a specific user."""

    @abstractmethod
    async def find_by_status(
        self, status: BatchStatus, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find batches by status."""

    @abstractmethod
    async def find_by_template_id(
        self, template_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find batches using a specific template."""

    @abstractmethod
    async def find_by_channel(
        self, channel: NotificationChannel, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find batches for a specific channel."""

    @abstractmethod
    async def find_pending_batches(
        self, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find batches pending execution."""

    @abstractmethod
    async def find_scheduled_batches(
        self,
        scheduled_before: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationBatch]:
        """Find scheduled batches ready for processing."""

    @abstractmethod
    async def find_processing_batches(
        self, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find currently processing batches."""

    @abstractmethod
    async def find_completed_batches(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find completed batches."""

    @abstractmethod
    async def find_failed_batches(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find failed batches."""

    @abstractmethod
    async def find_stalled_batches(
        self,
        stalled_threshold_minutes: int = 60,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationBatch]:
        """Find batches that appear to be stalled."""

    @abstractmethod
    async def find_large_batches(
        self, min_size: int = 10000, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find large batches by recipient count."""

    @abstractmethod
    async def find_batches_by_tags(
        self,
        tags: list[str],
        match_all: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationBatch]:
        """Find batches by tags."""

    @abstractmethod
    async def find_recent_batches(
        self, since: datetime, limit: int | None = None, offset: int = 0
    ) -> list[NotificationBatch]:
        """Find recently created batches."""

    @abstractmethod
    async def search_batches(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[NotificationBatch]:
        """Search batches by text query."""

    @abstractmethod
    async def get_batch_statistics(self, batch_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific batch."""

    @abstractmethod
    async def get_system_batch_statistics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get system-wide batch statistics."""

    @abstractmethod
    async def count_batches_by_status(
        self, since: datetime | None = None
    ) -> dict[BatchStatus, int]:
        """Count batches grouped by status."""

    @abstractmethod
    async def count_batches_by_channel(
        self, since: datetime | None = None
    ) -> dict[NotificationChannel, int]:
        """Count batches grouped by channel."""

    @abstractmethod
    async def count_batches_by_user(
        self, since: datetime | None = None, limit: int = 10
    ) -> dict[UUID, int]:
        """Count batches grouped by creating user."""

    @abstractmethod
    async def get_average_batch_size(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get average batch size by recipient count."""

    @abstractmethod
    async def get_average_processing_time(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get average batch processing time in minutes."""

    @abstractmethod
    async def get_batch_success_rate(
        self, channel: NotificationChannel | None = None, since: datetime | None = None
    ) -> float:
        """Get batch completion success rate as percentage."""

    @abstractmethod
    async def get_processing_timeline(
        self,
        resolution_hours: int = 1,
        since: datetime | None = None,
        channel: NotificationChannel | None = None,
    ) -> dict[datetime, dict[str, int]]:
        """Get batch processing statistics over time."""

    @abstractmethod
    async def get_most_used_templates(
        self, since: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get most frequently used templates in batches."""

    @abstractmethod
    async def get_batch_size_distribution(
        self, since: datetime | None = None
    ) -> dict[str, int]:
        """Get distribution of batch sizes."""

    @abstractmethod
    async def get_processing_time_distribution(
        self, since: datetime | None = None
    ) -> dict[str, int]:
        """Get distribution of processing times."""

    @abstractmethod
    async def find_duplicate_batches(
        self, similarity_threshold: float = 0.9, time_window_hours: int = 24
    ) -> list[list[NotificationBatch]]:
        """Find potentially duplicate batches."""

    @abstractmethod
    async def cleanup_old_batches(
        self, older_than_days: int = 90, keep_failed: bool = True, batch_size: int = 100
    ) -> int:
        """Clean up old completed batches."""

    @abstractmethod
    async def retry_failed_batches(
        self, max_retry_count: int = 3, batch_limit: int = 10
    ) -> int:
        """Retry failed batches that haven't exceeded retry limit."""

    @abstractmethod
    async def cancel_stalled_batches(self, stalled_threshold_hours: int = 24) -> int:
        """Cancel batches that have been processing too long."""

    @abstractmethod
    async def archive_completed_batches(
        self, older_than_days: int = 30, batch_size: int = 100
    ) -> int:
        """Archive old completed batches."""

    @abstractmethod
    async def get_batch_health_report(self) -> dict[str, Any]:
        """Get health report for batch processing."""

    @abstractmethod
    async def detect_batch_anomalies(
        self, time_window_hours: int = 24, threshold_factor: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalous batch processing patterns."""

    @abstractmethod
    async def optimize_batch_scheduling(
        self, look_ahead_hours: int = 24
    ) -> dict[str, Any]:
        """Optimize batch scheduling and return recommendations."""

    @abstractmethod
    async def export_batch_data(
        self, batch_id: UUID, include_notifications: bool = False
    ) -> dict[str, Any]:
        """Export complete batch data."""

    @abstractmethod
    async def get_batch_performance_metrics(
        self, since: datetime | None = None
    ) -> dict[str, Any]:
        """Get performance metrics for batch processing."""
