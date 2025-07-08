"""Get webhook history query and handler.

This module provides the query and handler for retrieving
webhook event history and statistics.
"""

from datetime import datetime, timedelta
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import WebhookEventDTO, WebhookHistoryDTO
from app.modules.integration.domain.enums import WebhookStatus

logger = get_logger(__name__)


class GetWebhookHistoryQuery(Query):
    """Query to get webhook event history."""

    def __init__(
        self,
        integration_id: UUID,
        endpoint_id: UUID | None = None,
        status: WebhookStatus | None = None,
        event_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        include_statistics: bool = True,
        limit: int = 50,
    ):
        """Initialize get webhook history query.

        Args:
            integration_id: ID of integration
            endpoint_id: Optional specific endpoint ID
            status: Optional webhook status filter
            event_type: Optional event type filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            include_statistics: Include summary statistics
            limit: Maximum number of events to return
        """
        super().__init__()

        self.integration_id = integration_id
        self.endpoint_id = endpoint_id
        self.status = status
        self.event_type = event_type
        self.start_date = start_date or (datetime.utcnow() - timedelta(days=30))
        self.end_date = end_date or datetime.utcnow()
        self.include_statistics = include_statistics
        self.limit = min(limit, 1000)  # Cap at 1000

        # Set pagination
        self.page_size = self.limit

        # Set cache key
        cache_params = [
            f"integration:{integration_id}",
            f"endpoint:{endpoint_id}" if endpoint_id else None,
            f"status:{status.value}" if status else None,
            f"type:{event_type}" if event_type else None,
            f"start:{start_date.isoformat()}" if start_date else None,
            f"end:{end_date.isoformat()}" if end_date else None,
            f"limit:{limit}",
        ]
        cache_key_parts = [part for part in cache_params if part is not None]
        self.cache_key = f"webhook_history:{':'.join(cache_key_parts)}"
        self.cache_ttl = 60  # 1 minute

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValidationError("start_date must be before end_date")

        if self.limit < 1:
            raise ValidationError("limit must be positive")


class GetWebhookHistoryQueryHandler(
    QueryHandler[GetWebhookHistoryQuery, WebhookHistoryDTO]
):
    """Handler for getting webhook history."""

    def __init__(
        self,
        webhook_event_repository: Any,
        webhook_endpoint_repository: Any,
        integration_repository: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            webhook_event_repository: Repository for webhook event data
            webhook_endpoint_repository: Repository for webhook endpoint data
            integration_repository: Repository for integration data
        """
        super().__init__()
        self._webhook_event_repository = webhook_event_repository
        self._webhook_endpoint_repository = webhook_endpoint_repository
        self._integration_repository = integration_repository

    async def handle(self, query: GetWebhookHistoryQuery) -> WebhookHistoryDTO:
        """Handle get webhook history query.

        Args:
            query: Get webhook history query

        Returns:
            WebhookHistoryDTO: Webhook history data

        Raises:
            NotFoundError: If integration not found
        """
        logger.debug(
            "Getting webhook history",
            integration_id=query.integration_id,
            endpoint_id=query.endpoint_id,
            status=query.status.value if query.status else None,
        )

        # Verify integration exists
        integration = await self._integration_repository.get_by_id(query.integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {query.integration_id}")

        # Build filter criteria
        filters = {
            "integration_id": query.integration_id,
            "start_date": query.start_date,
            "end_date": query.end_date,
        }

        if query.endpoint_id:
            filters["endpoint_id"] = query.endpoint_id

        if query.status:
            filters["status"] = query.status

        if query.event_type:
            filters["event_type"] = query.event_type

        # Get recent webhook events
        webhook_events = await self._webhook_event_repository.get_by_filters(
            filters=filters,
            limit=query.limit,
            order_by="created_at",
            order_direction="desc",
        )

        # Convert to DTOs
        event_dtos = [WebhookEventDTO.from_domain(event) for event in webhook_events]

        # Get statistics if requested
        statistics = {}
        if query.include_statistics:
            statistics = await self._get_webhook_statistics(
                query.integration_id,
                query.start_date,
                query.end_date,
                query.endpoint_id,
            )

        return WebhookHistoryDTO(
            total_webhooks=statistics.get("total_webhooks", 0),
            successful_webhooks=statistics.get("successful_webhooks", 0),
            failed_webhooks=statistics.get("failed_webhooks", 0),
            pending_webhooks=statistics.get("pending_webhooks", 0),
            average_processing_time_ms=statistics.get(
                "average_processing_time_ms", 0.0
            ),
            webhooks_last_24h=statistics.get("webhooks_last_24h", 0),
            webhooks_last_7d=statistics.get("webhooks_last_7d", 0),
            recent_events=event_dtos,
        )

    async def _get_webhook_statistics(
        self,
        integration_id: UUID,
        start_date: datetime,
        end_date: datetime,
        endpoint_id: UUID | None = None,
    ) -> dict:
        """Get webhook statistics for the given period.

        Args:
            integration_id: Integration ID
            start_date: Start date for statistics
            end_date: End date for statistics
            endpoint_id: Optional endpoint ID filter

        Returns:
            dict: Statistics dictionary
        """
        # Get overall statistics
        stats_filters = {
            "integration_id": integration_id,
            "start_date": start_date,
            "end_date": end_date,
        }

        if endpoint_id:
            stats_filters["endpoint_id"] = endpoint_id

        total_stats = await self._webhook_event_repository.get_statistics(stats_filters)

        # Get 24h statistics
        now = datetime.utcnow()
        last_24h_filters = {
            **stats_filters,
            "start_date": now - timedelta(hours=24),
            "end_date": now,
        }
        last_24h_stats = await self._webhook_event_repository.get_statistics(
            last_24h_filters
        )

        # Get 7d statistics
        last_7d_filters = {
            **stats_filters,
            "start_date": now - timedelta(days=7),
            "end_date": now,
        }
        last_7d_stats = await self._webhook_event_repository.get_statistics(
            last_7d_filters
        )

        return {
            "total_webhooks": total_stats.get("total_count", 0),
            "successful_webhooks": total_stats.get("successful_count", 0),
            "failed_webhooks": total_stats.get("failed_count", 0),
            "pending_webhooks": total_stats.get("pending_count", 0),
            "average_processing_time_ms": total_stats.get(
                "avg_processing_time_ms", 0.0
            ),
            "webhooks_last_24h": last_24h_stats.get("total_count", 0),
            "webhooks_last_7d": last_7d_stats.get("total_count", 0),
        }

    @property
    def query_type(self) -> type[GetWebhookHistoryQuery]:
        """Get query type this handler processes."""
        return GetWebhookHistoryQuery
