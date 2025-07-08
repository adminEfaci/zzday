"""
Health Monitoring Subscriptions for GraphQL API

This module provides real-time health monitoring subscriptions for
integration status updates, health alerts, and system events.
"""

import asyncio
from collections.abc import AsyncGenerator
from uuid import UUID

import strawberry

from app.core.logging import get_logger
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    subscription_auth,
    track_metrics,
)

from ...schemas.types.health_type import (
    HealthAlert,
    HealthCheckResult,
    HealthMetrics,
    IntegrationHealthStatus,
    SystemHealthOverview,
)

logger = get_logger(__name__)


@strawberry.type
class HealthSubscriptions:
    """Health monitoring GraphQL subscriptions."""

    @strawberry.subscription(
        description="Subscribe to integration health status updates"
    )
    @subscription_auth("integration.health.subscribe")
    @audit_operation("health.subscribe_integration_status")
    @track_metrics("subscribe_integration_health")
    async def integration_health_status(
        self, info: strawberry.Info, integration_id: UUID, include_metrics: bool = False
    ) -> AsyncGenerator[IntegrationHealthStatus, None]:
        """
        Subscribe to real-time health status updates for a specific integration.

        Args:
            integration_id: UUID of the integration to monitor
            include_metrics: Whether to include detailed metrics in updates

        Yields:
            Real-time health status updates
        """
        logger.info(
            "Health subscription started",
            integration_id=str(integration_id),
            user_id=str(info.context.get("user_id")),
            include_metrics=include_metrics,
        )

        try:
            # Get subscription service
            subscription_service = info.context["container"].resolve(
                "HealthSubscriptionService"
            )

            # Subscribe to health updates
            async for health_update in subscription_service.subscribe_integration_health(
                integration_id=integration_id,
                include_metrics=include_metrics,
                subscriber_id=info.context.get("user_id"),
            ):
                # Map DTO to GraphQL type
                mapper = info.context["container"].resolve("HealthMapper")
                yield mapper.health_dto_to_graphql_type(health_update)

        except Exception as e:
            logger.exception(
                "Error in health subscription",
                integration_id=str(integration_id),
                error=str(e),
            )
            # Re-raise to terminate subscription
            raise

    @strawberry.subscription(description="Subscribe to health alerts")
    @subscription_auth("integration.health.alerts.subscribe")
    @audit_operation("health.subscribe_alerts")
    @track_metrics("subscribe_health_alerts")
    async def health_alerts(
        self,
        info: strawberry.Info,
        integration_ids: list[UUID] | None = None,
        severity_levels: list[str] | None = None,
        alert_types: list[str] | None = None,
    ) -> AsyncGenerator[HealthAlert, None]:
        """
        Subscribe to real-time health alerts.

        Args:
            integration_ids: Optional specific integration IDs to monitor
            severity_levels: Optional severity levels to filter by
            alert_types: Optional alert types to filter by

        Yields:
            Real-time health alerts
        """
        logger.info(
            "Health alerts subscription started",
            integration_count=len(integration_ids) if integration_ids else 0,
            user_id=str(info.context.get("user_id")),
        )

        try:
            # Get subscription service
            subscription_service = info.context["container"].resolve(
                "HealthAlertSubscriptionService"
            )

            # Subscribe to health alerts
            async for alert in subscription_service.subscribe_health_alerts(
                integration_ids=integration_ids,
                severity_levels=severity_levels,
                alert_types=alert_types,
                subscriber_id=info.context.get("user_id"),
            ):
                # Map DTO to GraphQL type
                mapper = info.context["container"].resolve("HealthMapper")
                yield mapper.health_alert_dto_to_graphql_type(alert)

        except Exception as e:
            logger.exception("Error in health alerts subscription", error=str(e))
            raise

    @strawberry.subscription(description="Subscribe to health check results")
    @subscription_auth("integration.health.checks.subscribe")
    @audit_operation("health.subscribe_check_results")
    @track_metrics("subscribe_health_checks")
    async def health_check_results(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        include_successful: bool = True,
    ) -> AsyncGenerator[HealthCheckResult, None]:
        """
        Subscribe to real-time health check results for an integration.

        Args:
            integration_id: UUID of the integration to monitor
            include_successful: Whether to include successful check results

        Yields:
            Real-time health check results
        """
        logger.info(
            "Health checks subscription started",
            integration_id=str(integration_id),
            include_successful=include_successful,
            user_id=str(info.context.get("user_id")),
        )

        try:
            # Get subscription service
            subscription_service = info.context["container"].resolve(
                "HealthCheckSubscriptionService"
            )

            # Subscribe to health check results
            async for check_result in subscription_service.subscribe_health_checks(
                integration_id=integration_id,
                include_successful=include_successful,
                subscriber_id=info.context.get("user_id"),
            ):
                # Map DTO to GraphQL type
                mapper = info.context["container"].resolve("HealthMapper")
                yield mapper.health_check_dto_to_graphql_type(check_result)

        except Exception as e:
            logger.exception(
                "Error in health checks subscription",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.subscription(description="Subscribe to system health overview updates")
    @subscription_auth("integration.health.system.subscribe")
    @audit_operation("health.subscribe_system_overview")
    @track_metrics("subscribe_system_health")
    async def system_health_overview(
        self, info: strawberry.Info, update_interval_seconds: int = 30
    ) -> AsyncGenerator[SystemHealthOverview, None]:
        """
        Subscribe to system-wide health overview updates.

        Args:
            update_interval_seconds: Interval between updates (minimum 10 seconds)

        Yields:
            Real-time system health overview updates
        """
        # Validate update interval
        if update_interval_seconds < 10:
            update_interval_seconds = 10
        elif update_interval_seconds > 300:  # Max 5 minutes
            update_interval_seconds = 300

        logger.info(
            "System health overview subscription started",
            update_interval=update_interval_seconds,
            user_id=str(info.context.get("user_id")),
        )

        try:
            # Get services
            health_service = info.context["container"].resolve(
                "HealthMonitoringService"
            )
            mapper = info.context["container"].resolve("HealthMapper")

            while True:
                # Get current system health overview
                overview = await health_service.get_system_health_overview(
                    include_inactive=False
                )

                # Map and yield
                yield mapper.system_overview_dto_to_graphql_type(overview)

                # Wait for next update
                await asyncio.sleep(update_interval_seconds)

        except asyncio.CancelledError:
            logger.info(
                "System health overview subscription cancelled",
                user_id=str(info.context.get("user_id")),
            )
            raise
        except Exception as e:
            logger.exception(
                "Error in system health overview subscription", error=str(e)
            )
            raise

    @strawberry.subscription(description="Subscribe to health metrics updates")
    @subscription_auth("integration.health.metrics.subscribe")
    @audit_operation("health.subscribe_metrics")
    @track_metrics("subscribe_health_metrics")
    async def health_metrics_updates(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        update_interval_seconds: int = 60,
        metrics_window_minutes: int = 15,
    ) -> AsyncGenerator[HealthMetrics, None]:
        """
        Subscribe to real-time health metrics updates for an integration.

        Args:
            integration_id: UUID of the integration to monitor
            update_interval_seconds: Interval between metric updates
            metrics_window_minutes: Time window for metrics calculation

        Yields:
            Real-time health metrics updates
        """
        # Validate parameters
        if update_interval_seconds < 30:
            update_interval_seconds = 30
        elif update_interval_seconds > 600:  # Max 10 minutes
            update_interval_seconds = 600

        if metrics_window_minutes < 5:
            metrics_window_minutes = 5
        elif metrics_window_minutes > 60:  # Max 1 hour
            metrics_window_minutes = 60

        logger.info(
            "Health metrics subscription started",
            integration_id=str(integration_id),
            update_interval=update_interval_seconds,
            metrics_window=metrics_window_minutes,
            user_id=str(info.context.get("user_id")),
        )

        try:
            from datetime import datetime, timedelta

            # Get services
            metrics_service = info.context["container"].resolve("HealthMetricsService")
            mapper = info.context["container"].resolve("HealthMapper")

            while True:
                # Calculate time range
                end_time = datetime.now()
                start_time = end_time - timedelta(minutes=metrics_window_minutes)

                # Create time range input
                from ...schemas.inputs.health_inputs import HealthMetricsTimeRangeInput

                time_range = HealthMetricsTimeRangeInput(
                    start_time=start_time, end_time=end_time
                )

                # Get current metrics
                metrics = await metrics_service.get_health_metrics(
                    integration_id=integration_id, time_range=time_range
                )

                # Map and yield
                yield mapper.health_metrics_dto_to_graphql_type(metrics)

                # Wait for next update
                await asyncio.sleep(update_interval_seconds)

        except asyncio.CancelledError:
            logger.info(
                "Health metrics subscription cancelled",
                integration_id=str(integration_id),
                user_id=str(info.context.get("user_id")),
            )
            raise
        except Exception as e:
            logger.exception(
                "Error in health metrics subscription",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.subscription(description="Subscribe to integration uptime status")
    @subscription_auth("integration.health.uptime.subscribe")
    @audit_operation("health.subscribe_uptime")
    @track_metrics("subscribe_uptime_status")
    async def uptime_status(
        self,
        info: strawberry.Info,
        integration_ids: list[UUID] | None = None,
        update_interval_seconds: int = 120,
    ) -> AsyncGenerator[list[dict], None]:
        """
        Subscribe to uptime status updates for integrations.

        Args:
            integration_ids: Optional specific integration IDs to monitor
            update_interval_seconds: Interval between uptime updates

        Yields:
            Real-time uptime status updates
        """
        # Validate update interval
        if update_interval_seconds < 60:
            update_interval_seconds = 60
        elif update_interval_seconds > 900:  # Max 15 minutes
            update_interval_seconds = 900

        logger.info(
            "Uptime status subscription started",
            integration_count=len(integration_ids) if integration_ids else 0,
            update_interval=update_interval_seconds,
            user_id=str(info.context.get("user_id")),
        )

        try:
            # Get services
            uptime_service = info.context["container"].resolve("UptimeService")

            while True:
                uptime_data = []

                # Get integrations to monitor
                target_integrations = integration_ids
                if not target_integrations:
                    # Get all active integrations if none specified
                    integration_service = info.context["container"].resolve(
                        "IntegrationService"
                    )
                    all_integrations = await integration_service.list_integrations(
                        filters={"is_active": True}
                    )
                    target_integrations = [
                        integration.integration_id for integration in all_integrations
                    ]

                # Get uptime status for each integration
                for integration_id in target_integrations:
                    try:
                        uptime_stats = await uptime_service.get_uptime_statistics(
                            integration_id=integration_id,
                            period_days=1,  # Last 24 hours
                        )

                        uptime_data.append(
                            {
                                "integration_id": str(integration_id),
                                "uptime_percentage": uptime_stats.uptime_percentage,
                                "total_checks": uptime_stats.total_checks,
                                "failed_checks": uptime_stats.failed_checks,
                                "current_status": "up"
                                if uptime_stats.uptime_percentage > 95
                                else "degraded"
                                if uptime_stats.uptime_percentage > 80
                                else "down",
                                "last_incident": uptime_stats.incidents[0]
                                if uptime_stats.incidents
                                else None,
                                "updated_at": datetime.now(),
                            }
                        )

                    except Exception as e:
                        logger.warning(
                            "Error getting uptime for integration",
                            integration_id=str(integration_id),
                            error=str(e),
                        )
                        # Continue with other integrations
                        continue

                # Yield uptime data
                yield uptime_data

                # Wait for next update
                await asyncio.sleep(update_interval_seconds)

        except asyncio.CancelledError:
            logger.info(
                "Uptime status subscription cancelled",
                user_id=str(info.context.get("user_id")),
            )
            raise
        except Exception as e:
            logger.exception("Error in uptime status subscription", error=str(e))
            raise


__all__ = ["HealthSubscriptions"]
