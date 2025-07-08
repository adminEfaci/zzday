"""Disconnect integration command and handler.

This module provides the command and handler for disconnecting integrations
from external systems with proper cleanup.
"""

from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import IntegrationDetailDTO

logger = get_logger(__name__)


class DisconnectIntegrationCommand(Command):
    """Command to disconnect an integration from external system."""

    def __init__(
        self, integration_id: UUID, reason: str | None = None, force: bool = False
    ):
        """Initialize disconnect integration command.

        Args:
            integration_id: ID of integration to disconnect
            reason: Reason for disconnection
            force: Force disconnection even if sync jobs are running
        """
        super().__init__()

        self.integration_id = integration_id
        self.reason = reason
        self.force = force

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")


class DisconnectIntegrationCommandHandler(
    CommandHandler[DisconnectIntegrationCommand, IntegrationDetailDTO]
):
    """Handler for disconnecting integrations."""

    def __init__(
        self,
        integration_repository: Any,
        sync_job_repository: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integration persistence
            sync_job_repository: Repository for sync job persistence
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._integration_repository = integration_repository
        self._sync_job_repository = sync_job_repository
        self._event_publisher = event_publisher

    async def handle(
        self, command: DisconnectIntegrationCommand
    ) -> IntegrationDetailDTO:
        """Handle disconnect integration command.

        Args:
            command: Disconnect integration command

        Returns:
            IntegrationDetailDTO: Disconnected integration details

        Raises:
            NotFoundError: If integration not found
            ValidationError: If cannot disconnect due to active operations
        """
        logger.info(
            "Disconnecting integration",
            integration_id=command.integration_id,
            reason=command.reason,
            force=command.force,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(
            command.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {command.integration_id}")

        # Check for active sync jobs if not forcing
        if not command.force:
            active_jobs = await self._sync_job_repository.count_active_jobs(
                integration_id=integration.id
            )
            if active_jobs > 0:
                raise ValidationError(
                    f"Cannot disconnect integration with {active_jobs} active sync jobs. "
                    "Use force=True to disconnect anyway."
                )

        # Disconnect integration
        integration.disconnect(user_id=command.user_id, reason=command.reason)

        # Cancel any active sync jobs if forcing
        if command.force:
            active_jobs = await self._sync_job_repository.get_active_jobs(
                integration_id=integration.id
            )
            for job in active_jobs:
                job.cancel(reason="Integration disconnected")
                await self._sync_job_repository.save(job)

        # Save changes
        await self._integration_repository.save(integration)

        # Publish events
        for event in integration.collect_events():
            await self._event_publisher.publish(event)

        logger.info(
            "Integration disconnected successfully",
            integration_id=integration.id,
            system_name=integration.system_name,
        )

        return IntegrationDetailDTO.from_domain(integration)

    @property
    def command_type(self) -> type[DisconnectIntegrationCommand]:
        """Get command type this handler processes."""
        return DisconnectIntegrationCommand
