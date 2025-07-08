"""Health monitoring service for integrations.

This module provides health checking and monitoring for external integrations.
"""

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.aggregates import Integration
from app.modules.integration.infrastructure.http_clients import (
    GraphQLClient,
    RestApiClient,
)
from app.modules.integration.infrastructure.repositories import IntegrationRepository

logger = logging.getLogger(__name__)


class HealthMonitorService:
    """Service for monitoring integration health."""

    def __init__(
        self,
        integration_repo: IntegrationRepository,
        check_interval_seconds: int = 300,
        timeout_seconds: int = 30,
        failure_threshold: int = 3,
        alert_callback: Callable | None = None,
    ):
        """Initialize health monitor."""
        self.integration_repo = integration_repo
        self.check_interval_seconds = check_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.failure_threshold = failure_threshold
        self.alert_callback = alert_callback

        # Monitoring state
        self._monitoring = False
        self._monitor_task: asyncio.Task | None = None

        # Health check results cache
        self._health_cache: dict[UUID, dict[str, Any]] = {}

        # Metrics
        self.metrics = {
            "total_checks": 0,
            "successful_checks": 0,
            "failed_checks": 0,
            "alerts_sent": 0,
        }

    async def check_integration_health(
        self, integration: Integration
    ) -> dict[str, Any]:
        """Check health of a single integration.

        Args:
            integration: Integration to check

        Returns:
            Health check result
        """
        self.metrics["total_checks"] += 1
        start_time = datetime.now(UTC)

        try:
            # Create appropriate client
            if integration.integration_type.value == "rest_api":
                client = RestApiClient(
                    base_url=integration.api_endpoint.base_url,
                    timeout=self.timeout_seconds,
                )
            elif integration.integration_type.value == "graphql":
                client = GraphQLClient(
                    endpoint=integration.api_endpoint.base_url + "/graphql",
                    timeout=self.timeout_seconds,
                )
            else:
                # Default to REST
                client = RestApiClient(
                    base_url=integration.api_endpoint.base_url,
                    timeout=self.timeout_seconds,
                )

            # Perform health check
            health_endpoint = integration.api_endpoint.health_check_path or "/health"

            if isinstance(client, GraphQLClient):
                # GraphQL health check
                result = await client.health_check()
                is_healthy = result
                response_data = {"graphql": "ok"} if result else {"error": "unhealthy"}
            else:
                # REST health check
                response = await client.get(health_endpoint)
                is_healthy = response.get("status") == "ok" or response.get(
                    "healthy", False
                )
                response_data = response

            # Calculate response time
            response_time = (datetime.now(UTC) - start_time).total_seconds() * 1000

            # Update integration health status
            integration.health_check(
                is_healthy=is_healthy, response_time_ms=response_time
            )

            self.metrics["successful_checks"] += 1

            # Cache result
            result = {
                "integration_id": integration.id,
                "is_healthy": is_healthy,
                "response_time_ms": response_time,
                "checked_at": datetime.now(UTC),
                "response_data": response_data,
            }

            self._health_cache[integration.id] = result

            # Close client
            if hasattr(client, "close"):
                await client.close()

            return result

        except Exception as e:
            logger.exception(f"Health check failed for {integration.name}: {e}")
            self.metrics["failed_checks"] += 1

            # Update integration with error
            integration.health_check(is_healthy=False, error_message=str(e))

            # Check if we should send alert
            if integration.health_check_failures >= self.failure_threshold:
                await self._send_alert(integration, str(e))

            # Cache failed result
            result = {
                "integration_id": integration.id,
                "is_healthy": False,
                "error": str(e),
                "checked_at": datetime.now(UTC),
            }

            self._health_cache[integration.id] = result

            return result

    async def check_all_integrations(self) -> list[dict[str, Any]]:
        """Check health of all active integrations.

        Returns:
            List of health check results
        """
        # Get integrations needing health check
        integrations = await self.integration_repo.find_needing_health_check(
            check_interval_minutes=self.check_interval_seconds // 60
        )

        # Check each integration concurrently
        tasks = [
            self.check_integration_health(integration) for integration in integrations
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Health check error: {result}")
            else:
                valid_results.append(result)

        return valid_results

    async def start_monitoring(self) -> None:
        """Start background health monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Health monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop background health monitoring."""
        self._monitoring = False

        if self._monitor_task:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task

        logger.info("Health monitoring stopped")

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._monitoring:
            try:
                # Check all integrations
                await self.check_all_integrations()

                # Save updated integrations
                # In real implementation, would batch save

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}", exc_info=True)

            # Wait for next check
            await asyncio.sleep(self.check_interval_seconds)

    async def _send_alert(self, integration: Integration, error_message: str) -> None:
        """Send health alert.

        Args:
            integration: Failed integration
            error_message: Error details
        """
        self.metrics["alerts_sent"] += 1

        if self.alert_callback:
            try:
                await self.alert_callback(
                    integration=integration,
                    error=error_message,
                    failures=integration.health_check_failures,
                )
            except Exception as e:
                logger.exception(f"Alert callback failed: {e}")

    def get_health_status(self, integration_id: UUID | None = None) -> dict[str, Any]:
        """Get current health status.

        Args:
            integration_id: Specific integration (all if None)

        Returns:
            Health status summary
        """
        if integration_id:
            cached = self._health_cache.get(integration_id)
            if cached:
                return cached
            return {"integration_id": integration_id, "status": "unknown"}

        # Overall health summary
        total_integrations = len(self._health_cache)
        healthy_count = sum(
            1
            for result in self._health_cache.values()
            if result.get("is_healthy", False)
        )

        return {
            "total_integrations": total_integrations,
            "healthy_count": healthy_count,
            "unhealthy_count": total_integrations - healthy_count,
            "health_percentage": (
                (healthy_count / total_integrations * 100)
                if total_integrations > 0
                else 0
            ),
            "last_check": max(
                (r["checked_at"] for r in self._health_cache.values()), default=None
            ),
        }

    def get_metrics(self) -> dict[str, Any]:
        """Get monitor metrics."""
        total = self.metrics["total_checks"]
        return {
            **self.metrics,
            "success_rate": (
                self.metrics["successful_checks"] / total if total > 0 else 0
            ),
            "failure_rate": (self.metrics["failed_checks"] / total if total > 0 else 0),
            "monitoring_active": self._monitoring,
        }
