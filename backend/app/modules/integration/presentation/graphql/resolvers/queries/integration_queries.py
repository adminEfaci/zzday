"""
Integration Queries for GraphQL API

This module provides comprehensive integration management queries including
configuration, status monitoring, analytics, and capability management.
"""

from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.integration_inputs import (
    AnalyticsTimeRangeInput,
    IntegrationFilterInput,
    IntegrationSortInput,
    PaginationInput,
)
from ...schemas.types.integration_type import (
    IntegrationAnalytics,
    IntegrationCapabilityInfo,
    IntegrationListItem,
    IntegrationType,
)

logger = get_logger(__name__)


@strawberry.type
class IntegrationQueries:
    """Integration-related GraphQL queries."""

    @strawberry.field(description="Get integration by ID")
    @require_auth()
    @require_permission("integration.read")
    @audit_operation("integration.get")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_integration")
    async def get_integration(
        self, info: strawberry.Info, integration_id: UUID
    ) -> IntegrationType | None:
        """
        Get detailed integration information by ID.

        Args:
            integration_id: UUID of the integration to retrieve

        Returns:
            Integration details or None if not found
        """
        try:
            service = info.context["container"].resolve("IntegrationService")
            result = await service.get_integration(integration_id)

            if not result:
                logger.warning(
                    "Integration not found",
                    integration_id=str(integration_id),
                    user_id=str(info.context.get("user_id")),
                )
                return None

            # Convert DTO to GraphQL type
            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="List integrations with filtering and pagination")
    @require_auth()
    @require_permission("integration.list")
    @audit_operation("integration.list")
    @rate_limit(requests=30, window=60)
    @track_metrics("list_integrations")
    async def list_integrations(
        self,
        info: strawberry.Info,
        filters: IntegrationFilterInput | None = None,
        sort: IntegrationSortInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[IntegrationListItem]:
        """
        List integrations with filtering, sorting, and pagination.

        Args:
            filters: Optional filtering criteria
            sort: Optional sorting configuration
            pagination: Optional pagination parameters

        Returns:
            List of integration summary items
        """
        try:
            service = info.context["container"].resolve("IntegrationService")

            # Apply default pagination if not provided
            if not pagination:
                pagination = PaginationInput(page=1, page_size=20)

            # Validate pagination
            if pagination.page_size > 100:
                raise ValidationError("Maximum page size is 100")

            result = await service.list_integrations(
                filters=filters, sort=sort, pagination=pagination
            )

            # Convert DTOs to GraphQL types
            mapper = info.context["container"].resolve("IntegrationMapper")
            return [mapper.list_item_dto_to_graphql_type(item) for item in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error listing integrations", error=str(e))
            raise

    @strawberry.field(description="Get integration configuration details")
    @require_auth()
    @require_permission("integration.configuration.read")
    @audit_operation("integration.get_configuration")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_integration_configuration")
    async def get_integration_configuration(
        self, info: strawberry.Info, integration_id: UUID
    ) -> IntegrationType | None:
        """
        Get detailed configuration for an integration.

        Args:
            integration_id: UUID of the integration

        Returns:
            Integration configuration details
        """
        try:
            service = info.context["container"].resolve("IntegrationService")
            result = await service.get_integration_configuration(integration_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.config_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving integration configuration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get integration analytics")
    @require_auth()
    @require_permission("integration.analytics.read")
    @audit_operation("integration.get_analytics")
    @rate_limit(requests=20, window=60)
    @track_metrics("get_integration_analytics")
    async def get_integration_analytics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        time_range: AnalyticsTimeRangeInput,
    ) -> IntegrationAnalytics:
        """
        Get analytics data for an integration.

        Args:
            integration_id: UUID of the integration
            time_range: Time range for analytics data

        Returns:
            Integration analytics data
        """
        try:
            # Validate time range
            if time_range.end_date <= time_range.start_date:
                raise ValidationError("End date must be after start date")

            # Limit time range to prevent excessive data queries
            max_days = 90
            days_diff = (time_range.end_date - time_range.start_date).days
            if days_diff > max_days:
                raise ValidationError(f"Time range cannot exceed {max_days} days")

            service = info.context["container"].resolve("IntegrationAnalyticsService")
            result = await service.get_analytics(integration_id, time_range)

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.analytics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving integration analytics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get integration capabilities")
    @require_auth()
    @require_permission("integration.capabilities.read")
    @audit_operation("integration.get_capabilities")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_integration_capabilities")
    async def get_integration_capabilities(
        self, info: strawberry.Info, integration_id: UUID
    ) -> list[IntegrationCapabilityInfo]:
        """
        Get detailed capability information for an integration.

        Args:
            integration_id: UUID of the integration

        Returns:
            List of capability information
        """
        try:
            service = info.context["container"].resolve("IntegrationService")
            result = await service.get_integration_capabilities(integration_id)

            mapper = info.context["container"].resolve("IntegrationMapper")
            return [mapper.capability_dto_to_graphql_type(cap) for cap in result]

        except Exception as e:
            logger.exception(
                "Error retrieving integration capabilities",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Search integrations by various criteria")
    @require_auth()
    @require_permission("integration.search")
    @audit_operation("integration.search")
    @rate_limit(requests=20, window=60)
    @track_metrics("search_integrations")
    async def search_integrations(
        self,
        info: strawberry.Info,
        query: str,
        filters: IntegrationFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[IntegrationListItem]:
        """
        Search integrations by name, description, or system name.

        Args:
            query: Search query string
            filters: Optional additional filters
            pagination: Pagination parameters

        Returns:
            List of matching integrations
        """
        try:
            if not query or len(query.strip()) < 2:
                raise ValidationError("Search query must be at least 2 characters")

            service = info.context["container"].resolve("IntegrationSearchService")
            result = await service.search_integrations(
                query=query.strip(),
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=20),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return [mapper.list_item_dto_to_graphql_type(item) for item in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error searching integrations", query=query, error=str(e))
            raise

    @strawberry.field(description="Get integration status summary")
    @require_auth()
    @require_permission("integration.status.read")
    @audit_operation("integration.get_status_summary")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_integration_status_summary")
    async def get_integration_status_summary(
        self, info: strawberry.Info, integration_ids: list[UUID] | None = None
    ) -> dict[str, Any]:
        """
        Get status summary for integrations.

        Args:
            integration_ids: Optional list of specific integration IDs

        Returns:
            Status summary data
        """
        try:
            service = info.context["container"].resolve("IntegrationStatusService")
            result = await service.get_status_summary(integration_ids)

            return {
                "total_integrations": result.total_count,
                "healthy_count": result.healthy_count,
                "unhealthy_count": result.unhealthy_count,
                "needs_attention_count": result.needs_attention_count,
                "inactive_count": result.inactive_count,
                "by_type": {
                    item.integration_type: item.count for item in result.by_type
                },
                "by_status": {item.status: item.count for item in result.by_status},
                "last_updated": result.last_updated,
            }

        except Exception as e:
            logger.exception("Error retrieving status summary", error=str(e))
            raise

    @strawberry.field(description="Get recent integration activity")
    @require_auth()
    @require_permission("integration.activity.read")
    @audit_operation("integration.get_recent_activity")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_recent_integration_activity")
    async def get_recent_integration_activity(
        self, info: strawberry.Info, integration_id: UUID | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """
        Get recent activity for integrations.

        Args:
            integration_id: Optional specific integration ID
            limit: Maximum number of activity items to return

        Returns:
            List of recent activity items
        """
        try:
            if limit > 100:
                raise ValidationError("Maximum limit is 100")

            service = info.context["container"].resolve("IntegrationActivityService")
            result = await service.get_recent_activity(
                integration_id=integration_id, limit=limit
            )

            return [
                {
                    "activity_id": str(activity.activity_id),
                    "integration_id": str(activity.integration_id),
                    "activity_type": activity.activity_type,
                    "description": activity.description,
                    "details": activity.details,
                    "timestamp": activity.timestamp,
                    "user_id": str(activity.user_id) if activity.user_id else None,
                }
                for activity in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving recent activity", error=str(e))
            raise

    @strawberry.field(description="Validate integration configuration")
    @require_auth()
    @require_permission("integration.configuration.validate")
    @audit_operation("integration.validate_configuration")
    @rate_limit(requests=10, window=60)
    @track_metrics("validate_integration_configuration")
    async def validate_integration_configuration(
        self, info: strawberry.Info, integration_id: UUID, configuration: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Validate integration configuration without saving.

        Args:
            integration_id: UUID of the integration
            configuration: Configuration to validate

        Returns:
            Validation results
        """
        try:
            service = info.context["container"].resolve("IntegrationValidationService")
            result = await service.validate_configuration(
                integration_id=integration_id, configuration=configuration
            )

            return {
                "is_valid": result.is_valid,
                "errors": result.errors,
                "warnings": result.warnings,
                "suggestions": result.suggestions,
                "validated_at": result.validated_at,
            }

        except Exception as e:
            logger.exception(
                "Error validating configuration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise


__all__ = ["IntegrationQueries"]
