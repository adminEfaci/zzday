"""Connect integration command and handler.

This module provides the command and handler for connecting integrations
to external systems with proper authentication and validation.
"""

from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import DomainError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import IntegrationDetailDTO
from app.modules.integration.domain.errors import (
    AuthenticationError,
    ConnectionFailedError,
)

logger = get_logger(__name__)


class ConnectIntegrationCommand(Command):
    """Command to connect an integration to external system."""

    def __init__(
        self,
        integration_id: UUID,
        credential_id: UUID,
        test_connection: bool = True,
        connection_options: dict[str, Any] | None = None,
    ):
        """Initialize connect integration command.

        Args:
            integration_id: ID of integration to connect
            credential_id: ID of credential to use
            test_connection: Whether to test connection before establishing
            connection_options: Additional connection options
        """
        super().__init__()

        self.integration_id = integration_id
        self.credential_id = credential_id
        self.test_connection = test_connection
        self.connection_options = connection_options or {}

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.credential_id:
            raise ValidationError("credential_id is required")


class ConnectIntegrationCommandHandler(
    CommandHandler[ConnectIntegrationCommand, IntegrationDetailDTO]
):
    """Handler for connecting integrations."""

    def __init__(
        self,
        integration_repository: Any,
        credential_repository: Any,
        connection_service: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integration persistence
            credential_repository: Repository for credential persistence
            connection_service: Service for testing connections
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._integration_repository = integration_repository
        self._credential_repository = credential_repository
        self._connection_service = connection_service
        self._event_publisher = event_publisher

    async def handle(self, command: ConnectIntegrationCommand) -> IntegrationDetailDTO:
        """Handle connect integration command.

        Args:
            command: Connect integration command

        Returns:
            IntegrationDetailDTO: Connected integration details

        Raises:
            NotFoundError: If integration or credential not found
            ConnectionFailedError: If connection fails
            AuthenticationError: If authentication fails
        """
        logger.info(
            "Connecting integration",
            integration_id=command.integration_id,
            credential_id=command.credential_id,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(
            command.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {command.integration_id}")

        # Get credential
        credential = await self._credential_repository.get_by_id(command.credential_id)
        if not credential:
            raise NotFoundError(f"Credential not found: {command.credential_id}")

        # Validate credential belongs to integration
        if credential.integration_id != integration.id:
            raise ValidationError("Credential does not belong to this integration")

        # Validate credential is active and valid
        if not credential.is_active:
            raise ValidationError("Credential is not active")

        if not credential.is_valid:
            raise ValidationError("Credential is not valid")

        # Test connection if requested
        if command.test_connection:
            try:
                await self._connection_service.test_connection(
                    integration=integration,
                    credential=credential,
                    options=command.connection_options,
                )
            except Exception as e:
                logger.exception(
                    "Connection test failed",
                    integration_id=integration.id,
                    error=str(e),
                )
                if "auth" in str(e).lower():
                    raise AuthenticationError(f"Authentication failed: {e!s}")
                raise ConnectionFailedError(f"Connection failed: {e!s}")

        # Connect integration
        try:
            integration.connect(
                credential_id=credential.id, test_connection=command.test_connection
            )

            # Update credential usage
            credential.record_usage()

            # Save changes
            await self._integration_repository.save(integration)
            await self._credential_repository.save(credential)

            # Publish events
            for event in integration.collect_events():
                await self._event_publisher.publish(event)

            logger.info(
                "Integration connected successfully",
                integration_id=integration.id,
                system_name=integration.system_name,
            )

            return IntegrationDetailDTO.from_domain(integration)

        except DomainError as e:
            logger.exception(
                "Failed to connect integration",
                integration_id=integration.id,
                error=str(e),
            )
            raise
        except Exception as e:
            logger.exception(
                "Unexpected error connecting integration",
                integration_id=integration.id,
                error=str(e),
            )
            raise ConnectionFailedError(f"Failed to connect integration: {e!s}")

    @property
    def command_type(self) -> type[ConnectIntegrationCommand]:
        """Get command type this handler processes."""
        return ConnectIntegrationCommand
