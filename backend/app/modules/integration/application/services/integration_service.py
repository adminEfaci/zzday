"""Integration application service.

This module provides the main application service for integration operations,
orchestrating domain logic and handling business workflows.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ApplicationError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import IntegrationDetailDTO
from app.modules.integration.domain.aggregates import Integration
from app.modules.integration.domain.entities import ApiCredential
from app.modules.integration.domain.enums import AuthType, IntegrationType
from app.modules.integration.domain.errors import ConnectionFailedError
from app.modules.integration.domain.value_objects import ApiEndpoint, RateLimitConfig

logger = get_logger(__name__)


class IntegrationService:
    """Application service for integration management."""

    def __init__(
        self,
        integration_repository: Any,
        credential_repository: Any,
        mapping_repository: Any,
        connection_service: Any,
        auth_service: Any,
        encryption_service: Any,
        rate_limiter: Any,
        event_publisher: Any,
    ):
        """Initialize integration service.

        Args:
            integration_repository: Repository for integration persistence
            credential_repository: Repository for credential persistence
            mapping_repository: Repository for mapping persistence
            connection_service: Service for testing connections
            auth_service: Service for authentication operations
            encryption_service: Service for credential encryption
            rate_limiter: Service for rate limiting
            event_publisher: Event publisher for domain events
        """
        self._integration_repository = integration_repository
        self._credential_repository = credential_repository
        self._mapping_repository = mapping_repository
        self._connection_service = connection_service
        self._auth_service = auth_service
        self._encryption_service = encryption_service
        self._rate_limiter = rate_limiter
        self._event_publisher = event_publisher

    async def create_integration(
        self,
        name: str,
        integration_type: IntegrationType,
        system_name: str,
        api_base_url: str,
        owner_id: UUID,
        description: str | None = None,
        api_version: str | None = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        rate_limit_requests: int | None = None,
        rate_limit_period: int | None = None,
        capabilities: list[str] | None = None,
        configuration: dict[str, Any] | None = None,
    ) -> IntegrationDetailDTO:
        """Create a new integration.

        Args:
            name: Integration name
            integration_type: Type of integration
            system_name: External system name
            api_base_url: Base URL for API
            owner_id: Owner user ID
            description: Optional description
            api_version: Optional API version
            timeout_seconds: Request timeout
            max_retries: Maximum retry attempts
            rate_limit_requests: Rate limit requests per period
            rate_limit_period: Rate limit period in seconds
            capabilities: List of capabilities
            configuration: Additional configuration

        Returns:
            IntegrationDetailDTO: Created integration

        Raises:
            ValidationError: If input validation fails
            ApplicationError: If creation fails
        """
        logger.info(
            "Creating integration",
            name=name,
            system_name=system_name,
            integration_type=integration_type.value,
        )

        try:
            # Create API endpoint
            api_endpoint = ApiEndpoint(
                base_url=api_base_url,
                version=api_version,
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
            )

            # Create rate limit config if specified
            rate_limit = None
            if rate_limit_requests and rate_limit_period:
                rate_limit = RateLimitConfig(
                    requests_per_period=rate_limit_requests,
                    period_seconds=rate_limit_period,
                )

            # Create integration
            integration = Integration(
                name=name,
                integration_type=integration_type,
                system_name=system_name,
                api_endpoint=api_endpoint,
                owner_id=owner_id,
                description=description,
                rate_limit=rate_limit,
                capabilities=capabilities,
                configuration=configuration or {},
            )

            # Save integration
            await self._integration_repository.save(integration)

            # Publish events
            for event in integration.collect_events():
                await self._event_publisher.publish(event)

            logger.info(
                "Integration created successfully",
                integration_id=integration.id,
                name=integration.name,
            )

            return IntegrationDetailDTO.from_domain(integration)

        except Exception as e:
            logger.exception("Failed to create integration", name=name, error=str(e))
            raise ApplicationError(f"Failed to create integration: {e!s}")

    async def update_integration_configuration(
        self, integration_id: UUID, updates: dict[str, Any], updated_by: UUID
    ) -> IntegrationDetailDTO:
        """Update integration configuration.

        Args:
            integration_id: Integration ID
            updates: Configuration updates
            updated_by: User making updates

        Returns:
            IntegrationDetailDTO: Updated integration

        Raises:
            NotFoundError: If integration not found
            ValidationError: If updates are invalid
        """
        logger.info(
            "Updating integration configuration",
            integration_id=integration_id,
            updated_by=updated_by,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Update configuration
        integration.update_configuration(updates, updated_by)

        # Save changes
        await self._integration_repository.save(integration)

        # Publish events
        for event in integration.collect_events():
            await self._event_publisher.publish(event)

        logger.info("Integration configuration updated", integration_id=integration.id)

        return IntegrationDetailDTO.from_domain(integration)

    async def test_integration_connection(
        self,
        integration_id: UUID,
        credential_id: UUID,
        test_options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Test integration connection.

        Args:
            integration_id: Integration ID
            credential_id: Credential ID
            test_options: Optional test options

        Returns:
            dict[str, Any]: Test results

        Raises:
            NotFoundError: If integration or credential not found
            ConnectionFailedError: If connection test fails
        """
        logger.info(
            "Testing integration connection",
            integration_id=integration_id,
            credential_id=credential_id,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Get credential
        credential = await self._credential_repository.get_by_id(credential_id)
        if not credential:
            raise NotFoundError(f"Credential not found: {credential_id}")

        # Validate credential belongs to integration
        if credential.integration_id != integration.id:
            raise ValidationError("Credential does not belong to this integration")

        try:
            # Test connection
            test_result = await self._connection_service.test_connection(
                integration=integration,
                credential=credential,
                options=test_options or {},
            )

            logger.info(
                "Connection test completed",
                integration_id=integration.id,
                success=test_result.get("success", False),
            )

            return test_result

        except Exception as e:
            logger.exception(
                "Connection test failed", integration_id=integration.id, error=str(e)
            )
            raise ConnectionFailedError(f"Connection test failed: {e!s}")

    async def add_credential(
        self,
        integration_id: UUID,
        name: str,
        auth_type: AuthType,
        credentials: dict[str, Any],
        created_by: UUID,
        expires_at: datetime | None = None,
    ) -> UUID:
        """Add credential to integration.

        Args:
            integration_id: Integration ID
            name: Credential name
            auth_type: Authentication type
            credentials: Credential data
            created_by: User creating credential
            expires_at: Optional expiration time

        Returns:
            UUID: Created credential ID

        Raises:
            NotFoundError: If integration not found
            ValidationError: If credential data invalid
        """
        logger.info(
            "Adding credential to integration",
            integration_id=integration_id,
            name=name,
            auth_type=auth_type.value,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Encrypt credential data
        encrypted_data = await self._encryption_service.encrypt(credentials)

        # Create credential
        credential = ApiCredential(
            integration_id=integration.id,
            name=name,
            auth_type=auth_type,
            encrypted_data=encrypted_data,
            expires_at=expires_at,
            created_by=created_by,
        )

        # Save credential
        await self._credential_repository.save(credential)

        # Add to integration
        integration.add_credential(credential.id)
        await self._integration_repository.save(integration)

        logger.info(
            "Credential added successfully",
            integration_id=integration.id,
            credential_id=credential.id,
        )

        return credential.id

    async def activate_integration(self, integration_id: UUID) -> IntegrationDetailDTO:
        """Activate an integration.

        Args:
            integration_id: Integration ID

        Returns:
            IntegrationDetailDTO: Updated integration

        Raises:
            NotFoundError: If integration not found
        """
        logger.info("Activating integration", integration_id=integration_id)

        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        integration.activate()
        await self._integration_repository.save(integration)

        logger.info("Integration activated", integration_id=integration.id)

        return IntegrationDetailDTO.from_domain(integration)

    async def deactivate_integration(
        self, integration_id: UUID
    ) -> IntegrationDetailDTO:
        """Deactivate an integration.

        Args:
            integration_id: Integration ID

        Returns:
            IntegrationDetailDTO: Updated integration

        Raises:
            NotFoundError: If integration not found
        """
        logger.info("Deactivating integration", integration_id=integration_id)

        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        integration.deactivate()
        await self._integration_repository.save(integration)

        # Publish events
        for event in integration.collect_events():
            await self._event_publisher.publish(event)

        logger.info("Integration deactivated", integration_id=integration.id)

        return IntegrationDetailDTO.from_domain(integration)

    async def delete_integration(self, integration_id: UUID) -> None:
        """Delete an integration.

        Args:
            integration_id: Integration ID

        Raises:
            NotFoundError: If integration not found
            ValidationError: If integration cannot be deleted
        """
        logger.info("Deleting integration", integration_id=integration_id)

        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        # Check if integration can be deleted
        if integration.is_connected:
            raise ValidationError(
                "Cannot delete connected integration. Disconnect first."
            )

        # Delete related entities
        credentials = await self._credential_repository.get_by_integration_id(
            integration.id
        )
        for credential in credentials:
            await self._credential_repository.delete(credential.id)

        mappings = await self._mapping_repository.get_by_integration_id(integration.id)
        for mapping in mappings:
            await self._mapping_repository.delete(mapping.id)

        # Delete integration
        await self._integration_repository.delete(integration.id)

        logger.info("Integration deleted", integration_id=integration_id)
