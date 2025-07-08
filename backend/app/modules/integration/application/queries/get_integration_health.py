"""Get integration health query and handler.

This module provides the query and handler for retrieving
integration health status and monitoring information.
"""

from datetime import datetime, timedelta
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import (
    HealthCheckResultDTO,
    IntegrationHealthDTO,
)

logger = get_logger(__name__)


class GetIntegrationHealthQuery(Query):
    """Query to get integration health information."""

    def __init__(
        self,
        integration_id: UUID,
        include_check_history: bool = True,
        history_days: int = 7,
        include_uptime_calculation: bool = True,
    ):
        """Initialize get integration health query.

        Args:
            integration_id: ID of integration
            include_check_history: Include recent health check history
            history_days: Number of days of history to include
            include_uptime_calculation: Calculate uptime percentage
        """
        super().__init__()

        self.integration_id = integration_id
        self.include_check_history = include_check_history
        self.history_days = min(history_days, 30)  # Cap at 30 days
        self.include_uptime_calculation = include_uptime_calculation

        # Set cache key
        self.cache_key = f"integration_health:{integration_id}:{history_days}"
        self.cache_ttl = 60  # 1 minute

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if self.history_days < 1:
            raise ValidationError("history_days must be positive")


class GetIntegrationHealthQueryHandler(
    QueryHandler[GetIntegrationHealthQuery, IntegrationHealthDTO]
):
    """Handler for getting integration health."""

    def __init__(
        self,
        integration_repository: Any,
        health_check_repository: Any,
        health_service: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            integration_repository: Repository for integration data
            health_check_repository: Repository for health check data
            health_service: Service for health calculations
        """
        super().__init__()
        self._integration_repository = integration_repository
        self._health_check_repository = health_check_repository
        self._health_service = health_service

    async def handle(self, query: GetIntegrationHealthQuery) -> IntegrationHealthDTO:
        """Handle get integration health query.

        Args:
            query: Get integration health query

        Returns:
            IntegrationHealthDTO: Integration health information

        Raises:
            NotFoundError: If integration not found
        """
        logger.debug(
            "Getting integration health",
            integration_id=query.integration_id,
            history_days=query.history_days,
        )

        # Get integration
        integration = await self._integration_repository.get_by_id(query.integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {query.integration_id}")

        # Get recent health checks
        health_checks = []
        if query.include_check_history:
            start_date = datetime.utcnow() - timedelta(days=query.history_days)
            health_checks = await self._health_check_repository.get_by_integration_id(
                integration_id=integration.id, start_date=start_date, limit=100
            )

        # Convert health checks to DTOs
        health_check_dtos = [
            HealthCheckResultDTO(
                check_name=check.check_name,
                is_healthy=check.is_healthy,
                response_time_ms=check.response_time_ms,
                error_message=check.error_message,
                details=check.details,
                checked_at=check.checked_at,
            )
            for check in health_checks
        ]

        # Calculate uptime percentage
        uptime_percentage = 100.0
        if query.include_uptime_calculation and health_checks:
            uptime_percentage = await self._calculate_uptime_percentage(
                health_checks, query.history_days
            )

        # Calculate average response time
        average_response_time = 0.0
        if health_checks:
            successful_checks = [
                check
                for check in health_checks
                if check.is_healthy and check.response_time_ms
            ]
            if successful_checks:
                total_time = sum(check.response_time_ms for check in successful_checks)
                average_response_time = total_time / len(successful_checks)

        # Get next check time
        next_check_at = await self._health_service.get_next_check_time(integration.id)

        return IntegrationHealthDTO(
            integration_id=integration.id,
            integration_name=integration.name,
            status=integration.status,
            is_healthy=integration.is_healthy,
            last_check_at=integration.last_health_check,
            next_check_at=next_check_at,
            consecutive_failures=integration.health_check_failures,
            uptime_percentage=uptime_percentage,
            average_response_time_ms=average_response_time,
            health_checks=health_check_dtos,
        )

    async def _calculate_uptime_percentage(
        self, health_checks: list[Any], days: int
    ) -> float:
        """Calculate uptime percentage for the given period.

        Args:
            health_checks: List of health check records
            days: Number of days to calculate over

        Returns:
            float: Uptime percentage
        """
        if not health_checks:
            return 100.0

        # Group checks by time windows (e.g., hourly)
        total_windows = days * 24  # Hourly windows
        healthy_windows = 0

        now = datetime.utcnow()
        timedelta(hours=1)

        for i in range(total_windows):
            window_start = now - timedelta(hours=i + 1)
            window_end = now - timedelta(hours=i)

            # Find checks in this window
            window_checks = [
                check
                for check in health_checks
                if window_start <= check.checked_at < window_end
            ]

            if not window_checks:
                # No checks in this window - assume healthy if integration is old enough
                if window_start > (now - timedelta(days=days)):
                    healthy_windows += 1
                continue

            # Check if majority of checks in window were healthy
            healthy_count = sum(1 for check in window_checks if check.is_healthy)
            if healthy_count > len(window_checks) / 2:
                healthy_windows += 1

        if total_windows == 0:
            return 100.0

        return (healthy_windows / total_windows) * 100.0

    @property
    def query_type(self) -> type[GetIntegrationHealthQuery]:
        """Get query type this handler processes."""
        return GetIntegrationHealthQuery
