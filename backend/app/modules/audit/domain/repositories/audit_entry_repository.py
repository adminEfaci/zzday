"""
Audit Entry Repository Interface

Repository interface for audit entry persistence operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.specifications.audit_specifications import Specification


class IAuditEntryRepository(ABC):
    """Repository interface for audit entry operations."""

    @abstractmethod
    async def save(self, audit_entry: AuditEntry) -> None:
        """Save an audit entry."""

    @abstractmethod
    async def find_by_id(self, audit_id: UUID) -> AuditEntry | None:
        """Find an audit entry by ID."""

    @abstractmethod
    async def find_by_filter(self, audit_filter: AuditFilter) -> list[AuditEntry]:
        """Find audit entries matching the filter criteria."""

    @abstractmethod
    async def find_by_specification(self, spec: Specification) -> list[AuditEntry]:
        """Find audit entries matching the specification."""

    @abstractmethod
    async def find_by_user(self, user_id: UUID, limit: int = 100) -> list[AuditEntry]:
        """Find audit entries for a specific user."""

    @abstractmethod
    async def find_by_date_range(
        self, start_date: datetime, end_date: datetime, limit: int = 1000
    ) -> list[AuditEntry]:
        """Find audit entries within a date range."""

    @abstractmethod
    async def count_by_filter(self, audit_filter: AuditFilter) -> int:
        """Count audit entries matching the filter criteria."""

    @abstractmethod
    async def delete_by_ids(self, audit_ids: list[UUID]) -> int:
        """Delete audit entries by IDs. Returns count of deleted entries."""

    @abstractmethod
    async def archive_by_filter(self, audit_filter: AuditFilter) -> int:
        """Archive audit entries matching the filter. Returns count of archived entries."""

    @abstractmethod
    async def exists(self, audit_id: UUID) -> bool:
        """Check if an audit entry exists."""
