"""Get sync status query and handler.

This module provides the query and handler for retrieving
synchronization status and progress information.
"""

from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import SyncStatusDTO
from typing import Any

logger = get_logger(__name__)


class GetSyncStatusQuery(Query):
    """Query to get synchronization status."""

    def __init__(
        self,
        sync_job_id: UUID | None = None,
        integration_id: UUID | None = None,
        mapping_id: UUID | None = None,
        include_details: bool = False,
    ):
        """Initialize get sync status query.

        Args:
            sync_job_id: ID of specific sync job
            integration_id: ID of integration (for latest sync status)
            mapping_id: ID of mapping (for latest sync status)
            include_details: Include detailed sync information
        """
        super().__init__()

        self.sync_job_id = sync_job_id
        self.integration_id = integration_id
        self.mapping_id = mapping_id
        self.include_details = include_details

        # Set cache key based on parameters
        if sync_job_id:
            self.cache_key = f"sync_status:job:{sync_job_id}"
        elif integration_id and mapping_id:
            self.cache_key = (
                f"sync_status:integration:{integration_id}:mapping:{mapping_id}"
            )
        elif integration_id:
            self.cache_key = f"sync_status:integration:{integration_id}"

        self.cache_ttl = 30  # 30 seconds for active sync status

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        if not any([self.sync_job_id, self.integration_id]):
            raise ValidationError(
                "Either sync_job_id or integration_id must be provided"
            )


class GetSyncStatusQueryHandler(QueryHandler[GetSyncStatusQuery, SyncStatusDTO]):
    """Handler for getting sync status."""

    def __init__(
        self,
        sync_job_repository: Any,
        integration_repository: Any,
        mapping_repository: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            sync_job_repository: Repository for sync job data
            integration_repository: Repository for integration data
            mapping_repository: Repository for mapping data
        """
        super().__init__()
        self._sync_job_repository = sync_job_repository
        self._integration_repository = integration_repository
        self._mapping_repository = mapping_repository

    async def handle(self, query: GetSyncStatusQuery) -> SyncStatusDTO:
        """Handle get sync status query.

        Args:
            query: Get sync status query

        Returns:
            SyncStatusDTO: Sync status information

        Raises:
            NotFoundError: If sync job or integration not found
        """
        logger.debug(
            "Getting sync status",
            sync_job_id=query.sync_job_id,
            integration_id=query.integration_id,
            mapping_id=query.mapping_id,
        )

        sync_job = None

        if query.sync_job_id:
            # Get specific sync job
            sync_job = await self._sync_job_repository.get_by_id(query.sync_job_id)
            if not sync_job:
                raise NotFoundError(f"Sync job not found: {query.sync_job_id}")
        else:
            # Get latest sync job for integration/mapping
            if query.mapping_id:
                sync_job = await self._sync_job_repository.get_latest_by_mapping_id(
                    query.mapping_id
                )
            else:
                sync_job = await self._sync_job_repository.get_latest_by_integration_id(
                    query.integration_id
                )

            if not sync_job:
                # If no sync jobs found, create a placeholder status
                if query.integration_id:
                    integration = await self._integration_repository.get_by_id(
                        query.integration_id
                    )
                    if not integration:
                        raise NotFoundError(
                            f"Integration not found: {query.integration_id}"
                        )

                # Return empty status
                from datetime import datetime

                from app.modules.integration.domain.enums import (
                    SyncDirection,
                    SyncStatus,
                )

                return SyncStatusDTO(
                    sync_job_id=UUID("00000000-0000-0000-0000-000000000000"),
                    integration_id=query.integration_id,
                    status=SyncStatus.PENDING,
                    direction=SyncDirection.BIDIRECTIONAL,
                    started_at=datetime.utcnow(),
                    completed_at=None,
                    duration_seconds=None,
                    total_records=0,
                    processed_records=0,
                    failed_records=0,
                    skipped_records=0,
                    error_message="No sync jobs found",
                    progress_percentage=0.0,
                    estimated_completion=None,
                )

        # Create status DTO
        status_dto = SyncStatusDTO.from_domain(sync_job)

        # Add detailed information if requested
        if query.include_details:
            enriched_data = status_dto.to_dict()

            # Add sync job details
            enriched_data["sync_job_details"] = {
                "batch_size": sync_job.batch_size,
                "filters": sync_job.filters,
                "options": sync_job.options,
                "created_by": str(sync_job.created_by),
                "created_at": sync_job.created_at.isoformat(),
            }

            # Add error details if available
            if sync_job.error_message:
                enriched_data["error_details"] = {
                    "message": sync_job.error_message,
                    "occurred_at": sync_job.updated_at.isoformat()
                    if sync_job.updated_at
                    else None,
                }

            # Add mapping information
            if sync_job.mapping_id:
                mapping = await self._mapping_repository.get_by_id(sync_job.mapping_id)
                if mapping:
                    enriched_data["mapping_details"] = {
                        "name": mapping.name,
                        "source_entity": mapping.source_entity,
                        "target_entity": mapping.target_entity,
                    }

        return status_dto

    @property
    def query_type(self) -> type[GetSyncStatusQuery]:
        """Get query type this handler processes."""
        return GetSyncStatusQuery
