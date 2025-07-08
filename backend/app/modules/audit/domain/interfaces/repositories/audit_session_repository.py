"""Audit Session Repository Interface.

Domain contract for audit session data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.repositories.base import ISpecificationRepository
from app.modules.audit.domain.aggregates.audit_session import AuditSession
from app.modules.audit.domain.value_objects.time_range import TimeRange


class IAuditSessionRepository(ISpecificationRepository[AuditSession, UUID], ABC):
    """Repository interface for AuditSession aggregate operations."""

    @abstractmethod
    async def find_by_user_id(
        self, user_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find audit sessions by user ID."""

    @abstractmethod
    async def find_by_correlation_id(self, correlation_id: str) -> AuditSession | None:
        """Find audit session by correlation ID."""

    @abstractmethod
    async def find_active_user_session(self, user_id: UUID) -> AuditSession | None:
        """Find the active session for a specific user."""

    @abstractmethod
    async def find_active_sessions(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find currently active audit sessions."""

    @abstractmethod
    async def find_completed_sessions(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find completed audit sessions."""

    @abstractmethod
    async def find_failed_sessions(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find failed audit sessions."""

    @abstractmethod
    async def find_sessions_by_time_range(
        self, time_range: TimeRange, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions within a time range."""

    @abstractmethod
    async def find_long_running_sessions(
        self, min_duration_minutes: int = 60, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find long-running audit sessions."""

    @abstractmethod
    async def find_sessions_with_errors(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions that encountered errors."""

    @abstractmethod
    async def find_sessions_by_entry_count(
        self,
        min_entries: int,
        max_entries: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditSession]:
        """Find sessions by entry count range."""

    @abstractmethod
    async def find_orphaned_sessions(
        self, older_than_hours: int = 24
    ) -> list[AuditSession]:
        """Find sessions that appear to be orphaned."""

    @abstractmethod
    async def get_session_statistics(self, session_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific session."""

    @abstractmethod
    async def get_user_session_summary(
        self, user_id: UUID, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get session summary for a user."""

    @abstractmethod
    async def get_system_session_statistics(
        self, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get system-wide session statistics."""

    @abstractmethod
    async def count_sessions_by_status(
        self, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Count sessions grouped by status."""

    @abstractmethod
    async def count_sessions_by_user(
        self, time_range: TimeRange | None = None, limit: int = 10
    ) -> dict[UUID, int]:
        """Count sessions grouped by user."""

    @abstractmethod
    async def get_average_session_duration(
        self, time_range: TimeRange | None = None
    ) -> float:
        """Get average session duration in minutes."""

    @abstractmethod
    async def get_session_duration_distribution(
        self, time_range: TimeRange | None = None
    ) -> dict[str, int]:
        """Get distribution of session durations."""

    @abstractmethod
    async def find_concurrent_sessions(
        self, time_point: datetime, limit: int | None = None
    ) -> list[AuditSession]:
        """Find sessions that were active at a specific time."""

    @abstractmethod
    async def get_peak_concurrent_sessions(
        self, time_range: TimeRange, resolution_minutes: int = 60
    ) -> dict[datetime, int]:
        """Get peak concurrent session counts over time."""

    @abstractmethod
    async def cleanup_old_sessions(
        self, older_than_days: int = 90, keep_failed: bool = True
    ) -> int:
        """Clean up old completed sessions."""

    @abstractmethod
    async def force_complete_stale_sessions(
        self, stale_threshold_hours: int = 24
    ) -> int:
        """Force completion of stale active sessions."""

    @abstractmethod
    async def get_session_health_report(self) -> dict[str, Any]:
        """Get health report for audit sessions."""

    @abstractmethod
    async def export_session_data(
        self, session_id: UUID, include_entries: bool = True
    ) -> dict[str, Any]:
        """Export complete session data."""

    @abstractmethod
    async def search_sessions(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditSession]:
        """Search sessions by text query."""

    @abstractmethod
    async def find_sessions_by_ip_address(
        self, ip_address: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions by IP address."""

    @abstractmethod
    async def find_sessions_by_user_agent(
        self, user_agent_pattern: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions by user agent pattern."""

    @abstractmethod
    async def detect_suspicious_sessions(
        self, time_range: TimeRange | None = None, anomaly_threshold: float = 2.0
    ) -> list[AuditSession]:
        """Detect potentially suspicious session patterns."""

    @abstractmethod
    async def get_session_performance_metrics(
        self, time_range: TimeRange | None = None
    ) -> dict[str, Any]:
        """Get performance metrics for sessions."""
