"""Integration repository interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.modules.integration.domain.aggregates import Integration
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType


class IIntegrationRepository(ABC):
    """Repository interface for Integration aggregate operations."""

    @abstractmethod
    async def get_by_id(self, integration_id: UUID) -> Integration | None:
        """Get an integration by its ID.

        Args:
            integration_id: The unique identifier of the integration

        Returns:
            Integration | None: The integration if found, None otherwise
        """

    @abstractmethod
    async def get_by_tenant_id(
        self, tenant_id: UUID, include_inactive: bool = False
    ) -> list[Integration]:
        """Get all integrations for a tenant.

        Args:
            tenant_id: The tenant identifier
            include_inactive: Whether to include inactive integrations

        Returns:
            list[Integration]: List of integrations for the tenant
        """

    @abstractmethod
    async def get_by_type(
        self, tenant_id: UUID, integration_type: IntegrationType
    ) -> list[Integration]:
        """Get integrations by type for a tenant.

        Args:
            tenant_id: The tenant identifier
            integration_type: The type of integration

        Returns:
            list[Integration]: List of integrations matching the type
        """

    @abstractmethod
    async def get_by_status(
        self, tenant_id: UUID, status: ConnectionStatus
    ) -> list[Integration]:
        """Get integrations by connection status.

        Args:
            tenant_id: The tenant identifier
            status: The connection status to filter by

        Returns:
            list[Integration]: List of integrations with the specified status
        """

    @abstractmethod
    async def save(self, integration: Integration) -> Integration:
        """Save an integration (create or update).

        Args:
            integration: The integration to save

        Returns:
            Integration: The saved integration
        """

    @abstractmethod
    async def delete(self, integration_id: UUID) -> bool:
        """Delete an integration.

        Args:
            integration_id: The unique identifier of the integration

        Returns:
            bool: True if deleted successfully, False otherwise
        """

    @abstractmethod
    async def exists(self, integration_id: UUID) -> bool:
        """Check if an integration exists.

        Args:
            integration_id: The unique identifier of the integration

        Returns:
            bool: True if exists, False otherwise
        """

    @abstractmethod
    async def find_by_external_id(
        self, tenant_id: UUID, external_id: str
    ) -> Integration | None:
        """Find an integration by its external system ID.

        Args:
            tenant_id: The tenant identifier
            external_id: The ID in the external system

        Returns:
            Integration | None: The integration if found, None otherwise
        """

    @abstractmethod
    async def update_status(
        self,
        integration_id: UUID,
        status: ConnectionStatus,
        error_message: str | None = None,
    ) -> bool:
        """Update the connection status of an integration.

        Args:
            integration_id: The unique identifier of the integration
            status: The new connection status
            error_message: Optional error message if status is error

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def update_last_sync(
        self, integration_id: UUID, last_sync_at: datetime
    ) -> bool:
        """Update the last sync timestamp for an integration.

        Args:
            integration_id: The unique identifier of the integration
            last_sync_at: The timestamp of the last successful sync

        Returns:
            bool: True if updated successfully, False otherwise
        """
