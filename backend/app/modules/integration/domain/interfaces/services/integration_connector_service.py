"""
Integration Connector Service Interface

Port for managing integration connectors including registration,
configuration, health monitoring, and lifecycle management.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.integration.domain.aggregates.integration import Integration
    from app.modules.integration.domain.enums import IntegrationType, IntegrationStatus


class IIntegrationConnectorService(ABC):
    """Port for integration connector management operations."""
    
    @abstractmethod
    async def register_connector(
        self,
        name: str,
        integration_type: "IntegrationType",
        config: dict[str, Any],
        metadata: dict[str, Any] | None = None
    ) -> "Integration":
        """
        Register a new integration connector.
        
        Args:
            name: Unique name for the integration
            integration_type: Type of integration
            config: Connector configuration
            metadata: Optional metadata
            
        Returns:
            Created Integration aggregate
            
        Raises:
            DuplicateIntegrationError: If name already exists
            InvalidConfigurationError: If config is invalid
            UnsupportedIntegrationTypeError: If type not supported
        """
        ...
    
    @abstractmethod
    async def configure_connector(
        self,
        integration_id: UUID,
        config: dict[str, Any],
        validate: bool = True
    ) -> None:
        """
        Update connector configuration.
        
        Args:
            integration_id: ID of integration
            config: New configuration
            validate: Whether to validate config
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            InvalidConfigurationError: If config is invalid
            IntegrationActiveError: If integration is active
        """
        ...
    
    @abstractmethod
    async def validate_configuration(
        self,
        integration_type: "IntegrationType",
        config: dict[str, Any]
    ) -> tuple[bool, list[str]]:
        """
        Validate configuration for integration type.
        
        Args:
            integration_type: Type of integration
            config: Configuration to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        ...
    
    @abstractmethod
    async def activate_connector(
        self,
        integration_id: UUID,
        test_connection: bool = True
    ) -> None:
        """
        Activate an integration connector.
        
        Args:
            integration_id: ID of integration
            test_connection: Whether to test before activating
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            ConnectionTestFailedError: If connection test fails
            MissingRequiredConfigError: If required config missing
        """
        ...
    
    @abstractmethod
    async def deactivate_connector(
        self,
        integration_id: UUID,
        reason: str | None = None
    ) -> None:
        """
        Deactivate an integration connector.
        
        Args:
            integration_id: ID of integration
            reason: Optional deactivation reason
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            IntegrationNotActiveError: If already inactive
        """
        ...
    
    @abstractmethod
    async def test_connection(
        self,
        integration_id: UUID
    ) -> tuple[bool, dict[str, Any]]:
        """
        Test integration connection.
        
        Args:
            integration_id: ID of integration
            
        Returns:
            Tuple of (success, test_results)
        """
        ...
    
    @abstractmethod
    async def check_health(
        self,
        integration_id: UUID
    ) -> dict[str, Any]:
        """
        Check health status of integration.
        
        Args:
            integration_id: ID of integration
            
        Returns:
            Health status details
        """
        ...
    
    @abstractmethod
    async def rotate_credentials(
        self,
        integration_id: UUID,
        new_credentials: dict[str, Any]
    ) -> None:
        """
        Rotate integration credentials.
        
        Args:
            integration_id: ID of integration
            new_credentials: New credentials
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            InvalidCredentialsError: If credentials are invalid
        """
        ...
    
    @abstractmethod
    async def get_connector_capabilities(
        self,
        integration_type: "IntegrationType"
    ) -> dict[str, Any]:
        """
        Get capabilities of an integration type.
        
        Args:
            integration_type: Type of integration
            
        Returns:
            Dictionary of capabilities
        """
        ...
    
    @abstractmethod
    async def migrate_connector(
        self,
        integration_id: UUID,
        to_version: str
    ) -> None:
        """
        Migrate connector to new version.
        
        Args:
            integration_id: ID of integration
            to_version: Target version
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            IncompatibleVersionError: If migration not possible
            MigrationFailedError: If migration fails
        """
        ...