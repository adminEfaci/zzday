"""List integrations query and handler.

This module provides the query and handler for retrieving
a paginated list of integrations with filtering and sorting.
"""

from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import IntegrationListItemDTO
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType
from typing import Any

logger = get_logger(__name__)


class ListIntegrationsQuery(Query):
    """Query to list integrations with filtering and pagination."""

    def __init__(
        self,
        owner_id: UUID | None = None,
        integration_type: IntegrationType | None = None,
        status: ConnectionStatus | None = None,
        is_active: bool | None = None,
        is_healthy: bool | None = None,
        search_term: str | None = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_direction: str = "desc",
    ):
        """Initialize list integrations query.

        Args:
            owner_id: Optional filter by owner
            integration_type: Optional filter by integration type
            status: Optional filter by connection status
            is_active: Optional filter by active status
            is_healthy: Optional filter by health status
            search_term: Optional search term for name/system
            page: Page number (1-based)
            page_size: Number of items per page
            sort_by: Field to sort by
            sort_direction: Sort direction (asc/desc)
        """
        super().__init__()

        self.owner_id = owner_id
        self.integration_type = integration_type
        self.status = status
        self.is_active = is_active
        self.is_healthy = is_healthy
        self.search_term = search_term.strip() if search_term else None

        # Set pagination parameters
        self.set_pagination(page, page_size, sort_by, sort_direction)

        # Set cache key
        cache_params = [
            f"owner:{owner_id}" if owner_id else None,
            f"type:{integration_type.value}" if integration_type else None,
            f"status:{status.value}" if status else None,
            f"active:{is_active}" if is_active is not None else None,
            f"healthy:{is_healthy}" if is_healthy is not None else None,
            f"search:{search_term}" if search_term else None,
            f"page:{page}",
            f"size:{page_size}",
            f"sort:{sort_by}:{sort_direction}",
        ]
        cache_key_parts = [part for part in cache_params if part is not None]
        self.cache_key = f"integrations_list:{':'.join(cache_key_parts)}"
        self.cache_ttl = 120  # 2 minutes

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        valid_sort_fields = [
            "name",
            "system_name",
            "integration_type",
            "status",
            "created_at",
            "updated_at",
            "last_health_check",
        ]

        if self.sort_by not in valid_sort_fields:
            raise ValidationError(
                f"Invalid sort_by field. Must be one of: {valid_sort_fields}"
            )

        if self.search_term and len(self.search_term) < 2:
            raise ValidationError("search_term must be at least 2 characters")


class ListIntegrationsQueryHandler(
    QueryHandler[ListIntegrationsQuery, list[IntegrationListItemDTO]]
):
    """Handler for listing integrations."""

    def __init__(self, integration_repository: Any):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integration data
        """
        super().__init__()
        self._integration_repository = integration_repository

    async def handle(
        self, query: ListIntegrationsQuery
    ) -> list[IntegrationListItemDTO]:
        """Handle list integrations query.

        Args:
            query: List integrations query

        Returns:
            list[IntegrationListItemDTO]: List of integration items
        """
        logger.debug(
            "Listing integrations",
            page=query.page,
            page_size=query.page_size,
            owner_id=query.owner_id,
            integration_type=query.integration_type.value
            if query.integration_type
            else None,
        )

        # Build filter criteria
        filters = {}

        if query.owner_id:
            filters["owner_id"] = query.owner_id

        if query.integration_type:
            filters["integration_type"] = query.integration_type

        if query.status:
            filters["status"] = query.status

        if query.is_active is not None:
            filters["is_active"] = query.is_active

        if query.is_healthy is not None:
            filters["is_healthy"] = query.is_healthy

        if query.search_term:
            filters["search_term"] = query.search_term

        # Get integrations with pagination
        integrations = await self._integration_repository.get_by_filters(
            filters=filters,
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by,
            sort_direction=query.sort_direction,
        )

        # Convert to DTOs
        integration_dtos = [
            IntegrationListItemDTO.from_domain(integration)
            for integration in integrations
        ]

        logger.debug(
            "Listed integrations", count=len(integration_dtos), page=query.page
        )

        return integration_dtos

    @property
    def query_type(self) -> type[ListIntegrationsQuery]:
        """Get query type this handler processes."""
        return ListIntegrationsQuery
