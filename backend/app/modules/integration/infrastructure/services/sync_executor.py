"""Sync job executor service.

This module provides execution logic for synchronization jobs.
"""

import asyncio
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from app.core.errors import IntegrationError
from app.modules.integration.domain.entities import SyncJob
from app.modules.integration.domain.enums import SyncDirection, SyncStatus
from app.modules.integration.infrastructure.http_clients import RestApiClient
from app.modules.integration.infrastructure.repositories import (
    IntegrationRepository,
    MappingRepository,
    SyncJobRepository,
)
from app.modules.integration.infrastructure.services import DataTransformationService

logger = logging.getLogger(__name__)


class SyncExecutorService:
    """Service for executing synchronization jobs."""

    def __init__(
        self,
        sync_job_repo: SyncJobRepository,
        mapping_repo: MappingRepository,
        integration_repo: IntegrationRepository,
        transformation_service: DataTransformationService,
        progress_callback: Callable | None = None,
        error_callback: Callable | None = None,
    ):
        """Initialize sync executor."""
        self.sync_job_repo = sync_job_repo
        self.mapping_repo = mapping_repo
        self.integration_repo = integration_repo
        self.transformation_service = transformation_service
        self.progress_callback = progress_callback
        self.error_callback = error_callback

        # Active jobs tracking
        self._active_jobs: dict[UUID, asyncio.Task] = {}

    async def execute_sync_job(
        self, sync_job: SyncJob, api_client: RestApiClient
    ) -> dict[str, Any]:
        """Execute a synchronization job.

        Args:
            sync_job: Sync job to execute
            api_client: Configured API client

        Returns:
            Execution result summary
        """
        job_id = sync_job.id

        try:
            # Update job status to running
            sync_job.start()
            await self.sync_job_repo.save(sync_job)

            # Get mappings
            mappings = await self.mapping_repo.find_by_ids(sync_job.mapping_ids)
            if not mappings:
                raise IntegrationError("No mappings found for sync job")

            # Execute based on direction
            if sync_job.direction == SyncDirection.IMPORT:
                result = await self._execute_import(sync_job, api_client, mappings)
            elif sync_job.direction == SyncDirection.EXPORT:
                result = await self._execute_export(sync_job, api_client, mappings)
            else:  # BIDIRECTIONAL
                import_result = await self._execute_import(
                    sync_job, api_client, mappings
                )
                export_result = await self._execute_export(
                    sync_job, api_client, mappings
                )
                result = {"import": import_result, "export": export_result}

            # Mark job as completed
            sync_job.complete(result)
            await self.sync_job_repo.save(sync_job)

            return result

        except Exception as e:
            logger.error(f"Sync job {job_id} failed: {e}", exc_info=True)

            # Mark job as failed
            sync_job.fail(str(e))
            await self.sync_job_repo.save(sync_job)

            if self.error_callback:
                await self.error_callback(sync_job, e)

            raise

        finally:
            # Remove from active jobs
            self._active_jobs.pop(job_id, None)

    async def _execute_import(
        self, sync_job: SyncJob, api_client: RestApiClient, mappings: list[Any]
    ) -> dict[str, Any]:
        """Execute import synchronization."""
        total_processed = 0
        total_failed = 0
        total_skipped = 0

        # Get data from API
        endpoint = sync_job.parameters.get("import_endpoint", "/data")
        filters = sync_job.filters or {}

        # Paginate through results
        page = 1
        while True:
            # Fetch page
            response = await api_client.get(
                endpoint, params={**filters, "page": page, "per_page": 100}
            )

            records = response.get("data", [])
            if not records:
                break

            # Process records
            for record in records:
                try:
                    # Transform data
                    await self.transformation_service.transform_record(
                        record, mappings, direction="import"
                    )

                    # Save transformed data (implementation specific)
                    # await self._save_imported_record(transformed)

                    total_processed += 1

                except Exception as e:
                    logger.exception(f"Failed to process record: {e}")
                    total_failed += 1

                # Update progress
                if self.progress_callback:
                    await self.progress_callback(
                        sync_job.id, total_processed, total_failed, total_skipped
                    )

            page += 1

            # Check if job was cancelled
            if await self._is_job_cancelled(sync_job.id):
                break

        return {
            "processed": total_processed,
            "failed": total_failed,
            "skipped": total_skipped,
        }

    async def _execute_export(
        self, sync_job: SyncJob, api_client: RestApiClient, mappings: list[Any]
    ) -> dict[str, Any]:
        """Execute export synchronization."""
        # Similar to import but in reverse
        # Implementation depends on specific requirements
        return {"processed": 0, "failed": 0, "skipped": 0}

    async def _is_job_cancelled(self, job_id: UUID) -> bool:
        """Check if job was cancelled."""
        job = await self.sync_job_repo.find_by_id(job_id)
        return job and job.sync_status.status == SyncStatus.CANCELLED

    async def start_background_job(self, sync_job_id: UUID) -> None:
        """Start sync job in background."""
        sync_job = await self.sync_job_repo.find_by_id(sync_job_id)
        if not sync_job:
            raise IntegrationError(f"Sync job {sync_job_id} not found")

        # Get integration and API client
        integration = await self.integration_repo.find_by_id(sync_job.integration_id)
        if not integration:
            raise IntegrationError("Integration not found")

        # Create API client (simplified)
        api_client = RestApiClient(
            base_url=integration.api_endpoint.base_url,
            # Add auth and other config
        )

        # Create background task
        task = asyncio.create_task(self.execute_sync_job(sync_job, api_client))
        self._active_jobs[sync_job_id] = task

    async def cancel_job(self, job_id: UUID) -> bool:
        """Cancel a running sync job."""
        # Cancel task if running
        task = self._active_jobs.get(job_id)
        if task and not task.done():
            task.cancel()

        # Update job status
        job = await self.sync_job_repo.find_by_id(job_id)
        if job and job.sync_status.status == SyncStatus.RUNNING:
            job.cancel()
            await self.sync_job_repo.save(job)
            return True

        return False

    def get_active_jobs(self) -> list[UUID]:
        """Get list of active job IDs."""
        return list(self._active_jobs.keys())
