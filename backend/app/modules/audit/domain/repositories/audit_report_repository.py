"""
Audit Report Repository Interface

Repository interface for audit report persistence operations.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.modules.audit.domain.entities.audit_report import AuditReport


class IAuditReportRepository(ABC):
    """Repository interface for audit report operations."""

    @abstractmethod
    async def save(self, report: AuditReport) -> None:
        """Save an audit report."""

    @abstractmethod
    async def find_by_id(self, report_id: UUID) -> AuditReport | None:
        """Find an audit report by ID."""

    @abstractmethod
    async def find_by_type(self, report_type: str, limit: int = 50) -> list[AuditReport]:
        """Find audit reports by type."""

    @abstractmethod
    async def find_by_generator(self, generated_by: UUID, limit: int = 50) -> list[AuditReport]:
        """Find audit reports by generator user."""

    @abstractmethod
    async def find_recent(self, days: int = 30, limit: int = 50) -> list[AuditReport]:
        """Find recent audit reports."""

    @abstractmethod
    async def delete(self, report_id: UUID) -> bool:
        """Delete an audit report. Returns True if deleted."""

    @abstractmethod
    async def exists(self, report_id: UUID) -> bool:
        """Check if an audit report exists."""
