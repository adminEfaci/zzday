"""Start sync command and handler.

This module provides the command and handler for starting data synchronization
between systems with proper validation and error handling.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import SyncJobDTO
from app.modules.integration.domain.entities import SyncJob
from app.modules.integration.domain.enums import SyncDirection

logger = get_logger(__name__)


class StartSyncCommand(Command):
    """Command to start data synchronization."""

    def __init__(
        self,
        integration_id: UUID,
        mapping_id: UUID,
        direction: SyncDirection,
        batch_size: int = 100,
        filters: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
        scheduled_at: datetime | None = None,
    ):
        """Initialize start sync command.

        Args:
            integration_id: ID of integration
            mapping_id: ID of mapping configuration
            direction: Sync direction
            batch_size: Number of records per batch
            filters: Optional filters for data selection
            options: Additional sync options
            scheduled_at: Optional scheduled execution time
        """
        super().__init__()

        self.integration_id = integration_id
        self.mapping_id = mapping_id
        self.direction = direction
        self.batch_size = batch_size
        self.filters = filters or {}
        self.options = options or {}
        self.scheduled_at = scheduled_at

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.mapping_id:
            raise ValidationError("mapping_id is required")

        if not isinstance(self.direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")

        if self.batch_size < 1 or self.batch_size > 10000:
            raise ValidationError("batch_size must be between 1 and 10000")

        if self.scheduled_at and self.scheduled_at < datetime.utcnow():
            raise ValidationError("scheduled_at must be in the future")


class StartSyncCommandHandler(CommandHandler[StartSyncCommand, SyncJobDTO]):
    """Handler for starting data synchronization."""

    def __init__(
        self,
        integration_repository: Any,
        mapping_repository: Any,
        sync_job_repository: Any,
        sync_service: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integrations
            mapping_repository: Repository for mappings
            sync_job_repository: Repository for sync jobs
            sync_service: Service for sync operations
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._integration_repository = integration_repository
        self._mapping_repository = mapping_repository
        self._sync_job_repository = sync_job_repository
        self._sync_service = sync_service
        self._event_publisher = event_publisher

    async def handle(self, command: StartSyncCommand) -> SyncJobDTO:
        """Handle start sync command.

        Args:
            command: Start sync command

        Returns:
            SyncJobDTO: Created sync job

        Raises:
            NotFoundError: If integration or mapping not found
            ValidationError: If sync cannot be started
            DomainError: If domain rules violated
        """
        logger.info(
            "Starting sync job",
            integration_id=command.integration_id,
            mapping_id=command.mapping_id,
            direction=command.direction.value,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(
            command.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {command.integration_id}")

        # Validate integration can sync
        if not integration.can_sync:
            raise ValidationError(
                f"Integration cannot sync. Status: {integration.status.value}, "
                f"Active: {integration.is_active}, Connected: {integration.is_connected}"
            )

        # Get mapping
        mapping = await self._mapping_repository.get_by_id(command.mapping_id)
        if not mapping:
            raise NotFoundError(f"Mapping not found: {command.mapping_id}")

        # Validate mapping belongs to integration
        if mapping.integration_id != integration.id:
            raise ValidationError("Mapping does not belong to this integration")

        # Validate mapping is active
        if not mapping.is_active:
            raise ValidationError("Mapping is not active")

        # Validate sync direction
        if (
            command.direction == SyncDirection.IMPORT
            and not command.direction.allows_import
        ):
            raise ValidationError("Import not allowed for this mapping")

        if (
            command.direction == SyncDirection.EXPORT
            and not command.direction.allows_export
        ):
            raise ValidationError("Export not allowed for this mapping")

        # Check for existing active sync jobs
        active_jobs = await self._sync_job_repository.count_active_jobs(
            integration_id=integration.id, mapping_id=mapping.id
        )
        if active_jobs > 0:
            raise ValidationError(
                f"Cannot start sync: {active_jobs} active sync jobs already running"
            )

        # Create sync job
        sync_job = SyncJob(
            integration_id=integration.id,
            mapping_id=mapping.id,
            direction=command.direction,
            batch_size=command.batch_size,
            filters=command.filters,
            options=command.options,
            scheduled_at=command.scheduled_at,
            created_by=command.user_id or integration.owner_id,
        )

        # Save sync job
        await self._sync_job_repository.save(sync_job)

        # Add to integration
        integration.add_sync_job(sync_job.id)
        await self._integration_repository.save(integration)

        # Start sync if not scheduled
        if not command.scheduled_at:
            try:
                await self._sync_service.start_sync(sync_job)
                sync_job.start()
                await self._sync_job_repository.save(sync_job)
            except Exception as e:
                logger.exception(
                    "Failed to start sync job", sync_job_id=sync_job.id, error=str(e)
                )
                sync_job.fail(str(e))
                await self._sync_job_repository.save(sync_job)
                raise

        # Publish events
        for event in sync_job.collect_events():
            await self._event_publisher.publish(event)

        logger.info(
            "Sync job created successfully",
            sync_job_id=sync_job.id,
            status=sync_job.status.value,
        )

        return SyncJobDTO.from_domain(sync_job)

    @property
    def command_type(self) -> type[StartSyncCommand]:
        """Get command type this handler processes."""
        return StartSyncCommand
