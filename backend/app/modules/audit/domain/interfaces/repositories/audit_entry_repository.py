"""Audit Entry Repository Interface.

Domain contract for audit entry data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)
from app.modules.audit.domain.value_objects.time_range import TimeRange


class IAuditEntryRepository(ISpecificationRepository[AuditEntry, UUID], ABC):
    """Repository interface for AuditEntry entity operations."""

    @abstractmethod
    async def find_by_log_id(
        self, log_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by log ID."""

    @abstractmethod
    async def find_by_user_id(
        self, user_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by user ID."""

    @abstractmethod
    async def find_by_session_id(
        self, session_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by session ID."""

    @abstractmethod
    async def find_by_correlation_id(
        self, correlation_id: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by correlation ID."""

    @abstractmethod
    async def find_by_resource(
        self, resource: ResourceIdentifier, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries for a specific resource."""

    @abstractmethod
    async def find_by_resource_type(
        self, resource_type: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by resource type."""

    @abstractmethod
    async def find_by_action_type(
        self, action_type: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by action type."""

    @abstractmethod
    async def find_by_severity(
        self, severity: AuditSeverity, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by severity level."""

    @abstractmethod
    async def find_by_category(
        self, category: AuditCategory, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by category."""

    @abstractmethod
    async def find_by_outcome(
        self, outcome: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries by outcome."""

    @abstractmethod
    async def find_by_time_range(
        self, time_range: TimeRange, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find audit entries within a time range."""

    @abstractmethod
    async def find_by_filter(self, audit_filter: AuditFilter) -> list[AuditEntry]:
        """Find audit entries matching complex filter criteria."""

    @abstractmethod
    async def find_failed_operations(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find failed operations."""

    @abstractmethod
    async def find_high_severity_entries(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find high severity audit entries."""

    @abstractmethod
    async def find_suspicious_activities(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find potentially suspicious activities."""

    @abstractmethod
    async def find_entries_with_errors(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find entries with error details."""

    @abstractmethod
    async def find_long_running_operations(
        self,
        min_duration_ms: int = 5000,
        since: datetime | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Find long-running operations."""

    @abstractmethod
    async def search_entries(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Search audit entries by text query."""

    @abstractmethod
    async def get_entry_statistics(
        self, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get statistics about audit entries."""

    @abstractmethod
    async def get_activity_timeline(
        self,
        resource: ResourceIdentifier | None = None,
        user_id: UUID | None = None,
        time_range: TimeRange | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """Get activity timeline for a resource or user."""

    @abstractmethod
    async def get_user_activity_summary(
        self, user_id: UUID, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get activity summary for a user."""

    @abstractmethod
    async def get_resource_activity_summary(
        self, resource: ResourceIdentifier, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get activity summary for a resource."""

    @abstractmethod
    async def count_entries_by_log(self) -> dict[UUID, int]:
        """Count entries grouped by log ID."""

    @abstractmethod
    async def count_entries_by_user(
        self, time_range: TimeRange | None = None
    ) -> dict[UUID, int]:
        """Count entries grouped by user ID."""

    @abstractmethod
    async def count_entries_by_severity(
        self, time_range: TimeRange | None = None
    ) -> dict[AuditSeverity, int]:
        """Count entries grouped by severity."""

    @abstractmethod
    async def count_entries_by_category(
        self, time_range: TimeRange | None = None
    ) -> dict[AuditCategory, int]:
        """Count entries grouped by category."""

    @abstractmethod
    async def count_entries_by_outcome(
        self, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Count entries grouped by outcome."""

    @abstractmethod
    async def get_most_active_users(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> list[tuple[UUID, int]]:
        """Get most active users by entry count."""

    @abstractmethod
    async def get_most_accessed_resources(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> list[tuple[ResourceIdentifier, int]]:
        """Get most accessed resources by entry count."""

    @abstractmethod
    async def get_error_patterns(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get common error patterns."""

    @abstractmethod
    async def bulk_create_entries(self, entries: list[AuditEntry]) -> list[AuditEntry]:
        """Bulk create audit entries efficiently."""

    @abstractmethod
    async def archive_old_entries(
        self, older_than: datetime, batch_size: int = 1000
    ) -> int:
        """Archive old entries to reduce storage."""

    @abstractmethod
    async def delete_archived_entries(
        self, older_than: datetime, batch_size: int = 1000
    ) -> int:
        """Delete entries that have been archived."""

    @abstractmethod
    async def validate_entry_integrity(self, entry_id: UUID) -> dict[str, Any]:
        """Validate the integrity of an audit entry."""

    @abstractmethod
    async def detect_anomalies(
        self, time_range: TimeRange | None = None, threshold_factor: float = 2.0
    ) -> list[dict[str, Any]]:
        """Detect anomalous patterns in audit entries."""
