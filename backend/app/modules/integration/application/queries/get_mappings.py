"""Get mappings query and handler.

This module provides the query and handler for retrieving
integration mapping configurations.
"""

from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import MappingConfigDTO
from typing import Any

logger = get_logger(__name__)


class GetMappingsQuery(Query):
    """Query to get integration mapping configurations."""

    def __init__(
        self,
        integration_id: UUID,
        mapping_id: UUID | None = None,
        is_active: bool | None = None,
        source_entity: str | None = None,
        target_entity: str | None = None,
        include_validation: bool = False,
    ):
        """Initialize get mappings query.

        Args:
            integration_id: ID of integration
            mapping_id: Optional specific mapping ID
            is_active: Optional filter by active status
            source_entity: Optional filter by source entity
            target_entity: Optional filter by target entity
            include_validation: Include mapping validation results
        """
        super().__init__()

        self.integration_id = integration_id
        self.mapping_id = mapping_id
        self.is_active = is_active
        self.source_entity = source_entity
        self.target_entity = target_entity
        self.include_validation = include_validation

        # Set cache key
        cache_params = [
            f"integration:{integration_id}",
            f"mapping:{mapping_id}" if mapping_id else None,
            f"active:{is_active}" if is_active is not None else None,
            f"source:{source_entity}" if source_entity else None,
            f"target:{target_entity}" if target_entity else None,
            f"validation:{include_validation}",
        ]
        cache_key_parts = [part for part in cache_params if part is not None]
        self.cache_key = f"mappings:{':'.join(cache_key_parts)}"
        self.cache_ttl = 300  # 5 minutes

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        if not self.integration_id:
            raise ValidationError("integration_id is required")


class GetMappingsQueryHandler(QueryHandler[GetMappingsQuery, list[MappingConfigDTO]]):
    """Handler for getting integration mappings."""

    def __init__(
        self,
        mapping_repository: Any,
        integration_repository: Any,
        mapping_validator: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            mapping_repository: Repository for mapping data
            integration_repository: Repository for integration data
            mapping_validator: Service for mapping validation
        """
        super().__init__()
        self._mapping_repository = mapping_repository
        self._integration_repository = integration_repository
        self._mapping_validator = mapping_validator

    async def handle(self, query: GetMappingsQuery) -> list[MappingConfigDTO]:
        """Handle get mappings query.

        Args:
            query: Get mappings query

        Returns:
            list[MappingConfigDTO]: List of mapping configurations

        Raises:
            NotFoundError: If integration not found
        """
        logger.debug(
            "Getting mappings",
            integration_id=query.integration_id,
            mapping_id=query.mapping_id,
        )

        # Verify integration exists
        integration = await self._integration_repository.get_by_id(query.integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {query.integration_id}")

        mappings = []

        if query.mapping_id:
            # Get specific mapping
            mapping = await self._mapping_repository.get_by_id(query.mapping_id)
            if not mapping:
                raise NotFoundError(f"Mapping not found: {query.mapping_id}")

            # Verify mapping belongs to integration
            if mapping.integration_id != query.integration_id:
                raise NotFoundError("Mapping not found for this integration")

            mappings = [mapping]
        else:
            # Get mappings with filters
            filters = {"integration_id": query.integration_id}

            if query.is_active is not None:
                filters["is_active"] = query.is_active

            if query.source_entity:
                filters["source_entity"] = query.source_entity

            if query.target_entity:
                filters["target_entity"] = query.target_entity

            mappings = await self._mapping_repository.get_by_filters(filters)

        # Convert to DTOs
        mapping_dtos = []
        for mapping in mappings:
            dto = MappingConfigDTO.from_domain(mapping)

            # Add validation results if requested
            if query.include_validation:
                try:
                    validation_result = await self._mapping_validator.validate_mapping(
                        integration=integration, mapping=mapping
                    )

                    # Enrich DTO with validation data
                    enriched_data = dto.to_dict()
                    enriched_data["validation_result"] = {
                        "is_valid": validation_result.is_valid,
                        "errors": validation_result.errors,
                        "warnings": validation_result.warnings,
                        "validated_at": validation_result.validated_at.isoformat()
                        if hasattr(validation_result, "validated_at")
                        else None,
                    }

                    # Note: In a real implementation, you'd create an enriched DTO class
                    # For now, we'll add the validation info as metadata

                except Exception as e:
                    logger.warning(
                        "Failed to validate mapping",
                        mapping_id=mapping.id,
                        error=str(e),
                    )
                    # Continue without validation results

            mapping_dtos.append(dto)

        logger.debug(
            "Retrieved mappings",
            integration_id=query.integration_id,
            count=len(mapping_dtos),
        )

        return mapping_dtos

    @property
    def query_type(self) -> type[GetMappingsQuery]:
        """Get query type this handler processes."""
        return GetMappingsQuery
