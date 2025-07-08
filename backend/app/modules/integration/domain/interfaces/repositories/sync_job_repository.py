"""Sync job repository interface."""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.modules.integration.domain.entities import SyncJob
from app.modules.integration.domain.enums import SyncDirection, SyncStatus


class ISyncJobRepository(ABC):
    """Repository interface for SyncJob entity operations."""

    @abstractmethod
    async def get_by_id(self, job_id: UUID) -> SyncJob | None:
        """Get a sync job by its ID.

        Args:
            job_id: The unique identifier of the sync job

        Returns:
            SyncJob | None: The sync job if found, None otherwise
        """

    @abstractmethod
    async def get_by_integration_id(
        self,
        integration_id: UUID,
        status: SyncStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SyncJob]:
        """Get sync jobs for an integration.

        Args:
            integration_id: The integration identifier
            status: Optional status filter
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip

        Returns:
            list[SyncJob]: List of sync jobs
        """

    @abstractmethod
    async def get_active_jobs(self, tenant_id: UUID) -> list[SyncJob]:
        """Get all active sync jobs for a tenant.

        Args:
            tenant_id: The tenant identifier

        Returns:
            list[SyncJob]: List of active sync jobs
        """

    @abstractmethod
    async def get_by_status(
        self, tenant_id: UUID, status: SyncStatus, limit: int = 100, offset: int = 0
    ) -> list[SyncJob]:
        """Get sync jobs by status.

        Args:
            tenant_id: The tenant identifier
            status: The sync status to filter by
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip

        Returns:
            list[SyncJob]: List of sync jobs with the specified status
        """

    @abstractmethod
    async def save(self, sync_job: SyncJob) -> SyncJob:
        """Save a sync job (create or update).

        Args:
            sync_job: The sync job to save

        Returns:
            SyncJob: The saved sync job
        """

    @abstractmethod
    async def delete(self, job_id: UUID) -> bool:
        """Delete a sync job.

        Args:
            job_id: The unique identifier of the sync job

        Returns:
            bool: True if deleted successfully, False otherwise
        """

    @abstractmethod
    async def exists(self, job_id: UUID) -> bool:
        """Check if a sync job exists.

        Args:
            job_id: The unique identifier of the sync job

        Returns:
            bool: True if exists, False otherwise
        """

    @abstractmethod
    async def update_status(
        self,
        job_id: UUID,
        status: SyncStatus,
        error_message: str | None = None,
        progress: int | None = None,
    ) -> bool:
        """Update the status of a sync job.

        Args:
            job_id: The unique identifier of the sync job
            status: The new status
            error_message: Optional error message if status is error
            progress: Optional progress percentage (0-100)

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def update_progress(
        self, job_id: UUID, progress: int, items_processed: int, items_total: int
    ) -> bool:
        """Update the progress of a sync job.

        Args:
            job_id: The unique identifier of the sync job
            progress: Progress percentage (0-100)
            items_processed: Number of items processed
            items_total: Total number of items to process

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def complete_job(
        self,
        job_id: UUID,
        items_synced: int,
        items_failed: int,
        sync_summary: dict[str, Any],
    ) -> bool:
        """Mark a sync job as completed.

        Args:
            job_id: The unique identifier of the sync job
            items_synced: Number of items successfully synced
            items_failed: Number of items that failed to sync
            sync_summary: Summary of the sync operation

        Returns:
            bool: True if completed successfully, False otherwise
        """

    @abstractmethod
    async def get_job_history(
        self, integration_id: UUID, days_back: int = 30, limit: int = 100
    ) -> list[SyncJob]:
        """Get sync job history for an integration.

        Args:
            integration_id: The integration identifier
            days_back: Number of days to look back
            limit: Maximum number of jobs to return

        Returns:
            list[SyncJob]: List of historical sync jobs
        """

    @abstractmethod
    async def cleanup_old_jobs(self, days_to_keep: int = 90) -> int:
        """Clean up old sync jobs.

        Args:
            days_to_keep: Number of days to keep jobs

        Returns:
            int: Number of jobs deleted
        """

    @abstractmethod
    async def get_last_successful_job(
        self, integration_id: UUID, direction: SyncDirection | None = None
    ) -> SyncJob | None:
        """Get the last successful sync job for an integration.

        Args:
            integration_id: The integration identifier
            direction: Optional sync direction filter

        Returns:
            SyncJob | None: The last successful sync job if found
        """
