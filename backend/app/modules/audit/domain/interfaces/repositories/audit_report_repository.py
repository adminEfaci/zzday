"""Audit Report Repository Interface.

Domain contract for audit report data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.audit.domain.entities.audit_report import AuditReport
from app.modules.audit.domain.value_objects.time_range import TimeRange


class IAuditReportRepository(ISpecificationRepository[AuditReport, UUID], ABC):
    """Repository interface for AuditReport entity operations."""

    @abstractmethod
    async def find_by_name(self, name: str) -> AuditReport | None:
        """Find audit report by name."""

    @abstractmethod
    async def find_by_created_by(
        self, created_by: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports created by a specific user."""

    @abstractmethod
    async def find_by_report_type(
        self, report_type: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports by report type."""

    @abstractmethod
    async def find_by_status(
        self, status: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports by status."""

    @abstractmethod
    async def find_scheduled_reports(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports with scheduled execution."""

    @abstractmethod
    async def find_reports_due_for_generation(
        self, up_to_time: datetime | None = None
    ) -> list[AuditReport]:
        """Find reports that are due for generation."""

    @abstractmethod
    async def find_recent_reports(
        self, since: datetime, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find recently created reports."""

    @abstractmethod
    async def find_reports_by_time_range(
        self, time_range: TimeRange, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports covering a specific time range."""

    @abstractmethod
    async def find_failed_reports(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports that failed to generate."""

    @abstractmethod
    async def find_large_reports(
        self,
        min_size_bytes: int = 10485760,  # 10MB
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditReport]:
        """Find large reports by file size."""

    @abstractmethod
    async def find_reports_with_long_generation_time(
        self, min_duration_minutes: int = 30, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find reports with long generation times."""

    @abstractmethod
    async def find_archived_reports(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find archived reports."""

    @abstractmethod
    async def find_reports_by_tags(
        self,
        tags: list[str],
        match_all: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditReport]:
        """Find reports by tags."""

    @abstractmethod
    async def search_reports(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditReport]:
        """Search reports by text query."""

    @abstractmethod
    async def get_report_statistics(self, report_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific report."""

    @abstractmethod
    async def get_user_report_summary(
        self, user_id: UUID, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get report summary for a user."""

    @abstractmethod
    async def get_system_report_statistics(
        self, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get system-wide report statistics."""

    @abstractmethod
    async def count_reports_by_type(
        self, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Count reports grouped by type."""

    @abstractmethod
    async def count_reports_by_status(
        self, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Count reports grouped by status."""

    @abstractmethod
    async def count_reports_by_user(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> dict[UUID, int]:
        """Count reports grouped by creating user."""

    @abstractmethod
    async def get_average_generation_time(
        self, report_type: str | None = None, time_range: TimeRange | None = None
    ) -> float:
        """Get average report generation time in minutes."""

    @abstractmethod
    async def get_generation_time_distribution(
        self, report_type: str | None = None, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Get distribution of report generation times."""

    @abstractmethod
    async def get_storage_usage_by_report_type(self) -> dict[str, dict[str, Any]]:
        """Get storage usage statistics by report type."""

    @abstractmethod
    async def find_duplicate_reports(
        self, similarity_threshold: float = 0.9
    ) -> list[list[AuditReport]]:
        """Find potentially duplicate reports."""

    @abstractmethod
    async def cleanup_old_reports(
        self,
        older_than_days: int = 365,
        keep_scheduled: bool = True,
        archive_before_delete: bool = True,
    ) -> int:
        """Clean up old reports."""

    @abstractmethod
    async def archive_completed_reports(
        self, older_than_days: int = 90, compression_enabled: bool = True
    ) -> int:
        """Archive completed reports."""

    @abstractmethod
    async def optimize_report_storage(self) -> dict[str, Any]:
        """Optimize report storage and return statistics."""

    @abstractmethod
    async def validate_report_integrity(self, report_id: UUID) -> dict[str, Any]:
        """Validate the integrity of a report."""

    @abstractmethod
    async def get_report_performance_metrics(
        self, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get performance metrics for report generation."""

    @abstractmethod
    async def find_reports_needing_refresh(
        self, max_age_hours: int = 24
    ) -> list[AuditReport]:
        """Find reports that need to be refreshed."""

    @abstractmethod
    async def get_report_access_log(
        self, report_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Get access log for a report."""

    @abstractmethod
    async def get_most_accessed_reports(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get most frequently accessed reports."""

    @abstractmethod
    async def export_report_metadata(
        self, report_ids: list[UUID] | None = None
    ) -> dict[str, Any]:
        """Export report metadata for backup or migration."""
