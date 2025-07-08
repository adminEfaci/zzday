"""Audit Log Repository Interface.

Domain contract for audit log data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditStatus, RetentionPolicy
from app.modules.audit.domain.value_objects.time_range import TimeRange


class IAuditLogRepository(ISpecificationRepository[AuditLog, UUID], ABC):
    """Repository interface for AuditLog aggregate operations."""

    @abstractmethod
    async def find_by_title(self, title: str) -> AuditLog | None:
        """Find audit log by title."""

    @abstractmethod
    async def find_by_status(self, status: AuditStatus) -> list[AuditLog]:
        """Find audit logs by status."""

    @abstractmethod
    async def find_by_retention_policy(self, policy: RetentionPolicy) -> list[AuditLog]:
        """Find audit logs by retention policy."""

    @abstractmethod
    async def find_active_logs(self) -> list[AuditLog]:
        """Find all active audit logs."""

    @abstractmethod
    async def find_active(self) -> AuditLog | None:
        """Find the currently active audit log."""

    @abstractmethod
    async def find_full_logs(self, max_entries: int | None = None) -> list[AuditLog]:
        """Find audit logs that are at or near capacity."""

    @abstractmethod
    async def find_expired_logs(self) -> list[AuditLog]:
        """Find audit logs that have exceeded their retention period."""

    @abstractmethod
    async def find_logs_for_archival(
        self, min_age_days: int = 30, min_entries: int = 1000
    ) -> list[AuditLog]:
        """Find logs ready for archival."""

    @abstractmethod
    async def find_logs_by_time_range(
        self, time_range: TimeRange, include_archived: bool = False
    ) -> list[AuditLog]:
        """Find logs with entries in the specified time range."""

    @abstractmethod
    async def find_logs_by_owner(self, owner_id: UUID) -> list[AuditLog]:
        """Find logs created by a specific user."""

    @abstractmethod
    async def get_log_statistics(self, log_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific log."""

    @abstractmethod
    async def get_system_statistics(self) -> dict[str, Any]:
        """Get system-wide audit log statistics."""

    @abstractmethod
    async def get_statistics(self) -> dict[str, Any]:
        """Get overall audit statistics."""

    @abstractmethod
    async def search_logs(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditLog]:
        """Search audit logs by text query."""

    @abstractmethod
    async def find_logs_with_entries_by_filter(
        self, entry_filter: AuditFilter, limit: int | None = None, offset: int = 0
    ) -> list[AuditLog]:
        """Find logs containing entries matching the filter."""

    @abstractmethod
    async def count_logs_by_status(self) -> dict[AuditStatus, int]:
        """Count logs grouped by status."""

    @abstractmethod
    async def count_logs_by_retention_policy(self) -> dict[RetentionPolicy, int]:
        """Count logs grouped by retention policy."""

    @abstractmethod
    async def find_logs_needing_attention(self) -> list[AuditLog]:
        """Find logs that need administrative attention."""

    @abstractmethod
    async def get_storage_usage_by_log(self) -> dict[UUID, dict[str, Any]]:
        """Get storage usage statistics by log."""

    @abstractmethod
    async def find_recently_modified_logs(
        self, since: datetime, limit: int | None = None
    ) -> list[AuditLog]:
        """Find logs modified since a specific time."""

    @abstractmethod
    async def cleanup_empty_logs(self, max_age_days: int = 7) -> int:
        """Clean up empty logs older than specified days."""

    @abstractmethod
    async def archive_completed_logs(
        self, archive_location_template: str, compression_enabled: bool = True
    ) -> list[UUID]:
        """Archive logs marked for archival."""

    @abstractmethod
    async def restore_archived_log(
        self, log_id: UUID, archive_location: str
    ) -> AuditLog | None:
        """Restore an archived log."""

    @abstractmethod
    async def validate_log_integrity(self, log_id: UUID) -> dict[str, Any]:
        """Validate the integrity of a log and its entries."""

    @abstractmethod
    async def get_retention_summary(self) -> dict[str, Any]:
        """Get summary of retention policies and their impact."""

    @abstractmethod
    async def find_logs_by_health_status(
        self,
        include_healthy: bool = True,
        include_warnings: bool = True,
        include_errors: bool = True,
    ) -> list[AuditLog]:
        """Find logs by their health status."""
