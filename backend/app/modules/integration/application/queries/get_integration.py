"""Get integration query and handler.

This module provides the query and handler for retrieving detailed
integration information.
"""

from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import IntegrationDetailDTO
from typing import Any

logger = get_logger(__name__)


class GetIntegrationQuery(Query):
    """Query to get detailed integration information."""

    def __init__(
        self,
        integration_id: UUID,
        include_credentials: bool = False,
        include_mappings: bool = False,
        include_sync_jobs: bool = False,
        include_webhook_endpoints: bool = False,
    ):
        """Initialize get integration query.

        Args:
            integration_id: ID of integration to retrieve
            include_credentials: Include credential information
            include_mappings: Include mapping configurations
            include_sync_jobs: Include sync job history
            include_webhook_endpoints: Include webhook endpoints
        """
        super().__init__()

        self.integration_id = integration_id
        self.include_credentials = include_credentials
        self.include_mappings = include_mappings
        self.include_sync_jobs = include_sync_jobs
        self.include_webhook_endpoints = include_webhook_endpoints

        # Set cache key for this query
        self.cache_key = f"integration:{integration_id}:full"
        self.cache_ttl = 300  # 5 minutes

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        if not self.integration_id:
            raise ValidationError("integration_id is required")


class GetIntegrationQueryHandler(
    QueryHandler[GetIntegrationQuery, IntegrationDetailDTO]
):
    """Handler for getting integration details."""

    def __init__(
        self,
        integration_repository: Any,
        credential_repository: Any,
        mapping_repository: Any,
        sync_job_repository: Any,
        webhook_endpoint_repository: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integration data
            credential_repository: Repository for credential data
            mapping_repository: Repository for mapping data
            sync_job_repository: Repository for sync job data
            webhook_endpoint_repository: Repository for webhook endpoint data
        """
        super().__init__()
        self._integration_repository = integration_repository
        self._credential_repository = credential_repository
        self._mapping_repository = mapping_repository
        self._sync_job_repository = sync_job_repository
        self._webhook_endpoint_repository = webhook_endpoint_repository

    async def handle(self, query: GetIntegrationQuery) -> IntegrationDetailDTO:
        """Handle get integration query.

        Args:
            query: Get integration query

        Returns:
            IntegrationDetailDTO: Integration details

        Raises:
            NotFoundError: If integration not found
        """
        logger.debug("Getting integration details", integration_id=query.integration_id)

        # Get integration
        integration = await self._integration_repository.get_by_id(query.integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {query.integration_id}")

        # Create base DTO
        integration_dto = IntegrationDetailDTO.from_domain(integration)

        # Add related data if requested
        enriched_data = integration_dto.to_dict()

        if query.include_credentials:
            credentials = await self._credential_repository.get_by_integration_id(
                integration.id
            )
            enriched_data["credentials"] = [
                credential.to_dict() for credential in credentials
            ]

        if query.include_mappings:
            mappings = await self._mapping_repository.get_by_integration_id(
                integration.id
            )
            enriched_data["mappings"] = [mapping.to_dict() for mapping in mappings]

        if query.include_sync_jobs:
            sync_jobs = await self._sync_job_repository.get_recent_by_integration_id(
                integration.id, limit=20
            )
            enriched_data["recent_sync_jobs"] = [job.to_dict() for job in sync_jobs]

        if query.include_webhook_endpoints:
            endpoints = await self._webhook_endpoint_repository.get_by_integration_id(
                integration.id
            )
            enriched_data["webhook_endpoints"] = [
                endpoint.to_dict() for endpoint in endpoints
            ]

        # Create enriched DTO
        return IntegrationDetailDTO(
            **{
                k: v
                for k, v in enriched_data.items()
                if k in IntegrationDetailDTO.__dataclass_fields__
            }
        )

    @property
    def query_type(self) -> type[GetIntegrationQuery]:
        """Get query type this handler processes."""
        return GetIntegrationQuery
