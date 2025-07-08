"""Mapping repository interface."""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.modules.integration.domain.entities import IntegrationMapping
from app.modules.integration.domain.enums import EntityType


class IMappingRepository(ABC):
    """Repository interface for IntegrationMapping entity operations."""

    @abstractmethod
    async def get_by_id(self, mapping_id: UUID) -> IntegrationMapping | None:
        """Get a mapping by its ID.

        Args:
            mapping_id: The unique identifier of the mapping

        Returns:
            IntegrationMapping | None: The mapping if found, None otherwise
        """

    @abstractmethod
    async def get_by_integration_id(
        self, integration_id: UUID, entity_type: EntityType | None = None
    ) -> list[IntegrationMapping]:
        """Get all mappings for an integration.

        Args:
            integration_id: The integration identifier
            entity_type: Optional entity type filter

        Returns:
            list[IntegrationMapping]: List of mappings
        """

    @abstractmethod
    async def get_by_entity_type(
        self, tenant_id: UUID, entity_type: EntityType
    ) -> list[IntegrationMapping]:
        """Get mappings by entity type.

        Args:
            tenant_id: The tenant identifier
            entity_type: The entity type to filter by

        Returns:
            list[IntegrationMapping]: List of mappings for the entity type
        """

    @abstractmethod
    async def get_active_mappings(
        self, integration_id: UUID
    ) -> list[IntegrationMapping]:
        """Get all active mappings for an integration.

        Args:
            integration_id: The integration identifier

        Returns:
            list[IntegrationMapping]: List of active mappings
        """

    @abstractmethod
    async def save(self, mapping: IntegrationMapping) -> IntegrationMapping:
        """Save a mapping (create or update).

        Args:
            mapping: The mapping to save

        Returns:
            IntegrationMapping: The saved mapping
        """

    @abstractmethod
    async def delete(self, mapping_id: UUID) -> bool:
        """Delete a mapping.

        Args:
            mapping_id: The unique identifier of the mapping

        Returns:
            bool: True if deleted successfully, False otherwise
        """

    @abstractmethod
    async def exists(self, mapping_id: UUID) -> bool:
        """Check if a mapping exists.

        Args:
            mapping_id: The unique identifier of the mapping

        Returns:
            bool: True if exists, False otherwise
        """

    @abstractmethod
    async def find_mapping(
        self, integration_id: UUID, source_field: str, target_field: str
    ) -> IntegrationMapping | None:
        """Find a specific field mapping.

        Args:
            integration_id: The integration identifier
            source_field: The source field name
            target_field: The target field name

        Returns:
            IntegrationMapping | None: The mapping if found, None otherwise
        """

    @abstractmethod
    async def get_mapping_rules(self, mapping_id: UUID) -> dict[str, Any]:
        """Get the mapping rules for a mapping.

        Args:
            mapping_id: The unique identifier of the mapping

        Returns:
            dict[str, Any]: The mapping rules configuration
        """

    @abstractmethod
    async def update_mapping_rules(
        self, mapping_id: UUID, rules: dict[str, Any]
    ) -> bool:
        """Update the mapping rules for a mapping.

        Args:
            mapping_id: The unique identifier of the mapping
            rules: The new mapping rules

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def validate_mapping(self, mapping_id: UUID) -> dict[str, Any]:
        """Validate a mapping configuration.

        Args:
            mapping_id: The unique identifier of the mapping

        Returns:
            dict[str, Any]: Validation results with any errors or warnings
        """

    @abstractmethod
    async def get_transformation_history(
        self, mapping_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Get transformation history for a mapping.

        Args:
            mapping_id: The unique identifier of the mapping
            limit: Maximum number of transformations to return
            offset: Number of transformations to skip

        Returns:
            list[dict[str, Any]]: List of transformation records
        """

    @abstractmethod
    async def bulk_create_mappings(
        self, mappings: list[IntegrationMapping]
    ) -> list[IntegrationMapping]:
        """Create multiple mappings in bulk.

        Args:
            mappings: List of mappings to create

        Returns:
            list[IntegrationMapping]: List of created mappings
        """
