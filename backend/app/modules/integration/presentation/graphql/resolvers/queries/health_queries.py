"""
Health Monitoring Queries for GraphQL API

This module provides comprehensive health monitoring, diagnostics, and metrics
queries for external service integrations.
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

from ...schemas.inputs.health_inputs import (
    DiagnosticsFilterInput,
    HealthCheckInput,
    HealthMetricsTimeRangeInput,
)
from ...schemas.types.health_type import (
    HealthAlert,
    HealthCheckResult,
    HealthMetrics,
    IntegrationHealthStatus,
    ServiceDiagnostics,
    SystemHealthOverview,
)

logger = get_logger(__name__)


@strawberry.type
class HealthQueries:
    """Health monitoring GraphQL queries."""

    @strawberry.field(description="Get health status for a specific integration")
    @require_auth()
    @require_permission("integration.health.read")
    @audit_operation("integration.health.get_status")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_integration_health")
    async def get_integration_health(
        self, info: strawberry.Info, integration_id: UUID
    ) -> IntegrationHealthStatus | None:
        """
        Get comprehensive health status for an integration.

        Args:
            integration_id: UUID of the integration

        Returns:
            Health status details or None if not found
        """
        try:
            service = info.context["container"].resolve("HealthMonitoringService")
            result = await service.get_integration_health(integration_id)

            if not result:
                logger.warning(
                    "Integration health not found", integration_id=str(integration_id)
                )
                return None

            mapper = info.context["container"].resolve("HealthMapper")
            return mapper.health_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving integration health",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Perform real-time health check")
    @require_auth()
    @require_permission("integration.health.check")
    @audit_operation("integration.health.perform_check")
    @rate_limit(requests=20, window=60)
    @track_metrics("perform_health_check")
    async def perform_health_check(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        check_config: HealthCheckInput | None = None,
    ) -> HealthCheckResult:
        """
        Perform a real-time health check on an integration.

        Args:
            integration_id: UUID of the integration
            check_config: Optional health check configuration

        Returns:
            Health check results
        """
        try:
            service = info.context["container"].resolve("HealthCheckService")
            result = await service.perform_health_check(
                integration_id=integration_id, config=check_config
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return mapper.health_check_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error performing health check",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get system health overview")
    @require_auth()
    @require_permission("integration.health.overview")
    @audit_operation("integration.health.get_overview")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_system_health_overview")
    async def get_system_health_overview(
        self, info: strawberry.Info, include_inactive: bool = False
    ) -> SystemHealthOverview:
        """
        Get overall system health overview across all integrations.

        Args:
            include_inactive: Whether to include inactive integrations

        Returns:
            System health overview
        """
        try:
            service = info.context["container"].resolve("HealthMonitoringService")
            result = await service.get_system_health_overview(
                include_inactive=include_inactive
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return mapper.system_overview_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception("Error retrieving system health overview", error=str(e))
            raise

    @strawberry.field(description="Get service diagnostics")
    @require_auth()
    @require_permission("integration.diagnostics.read")
    @audit_operation("integration.diagnostics.get")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_service_diagnostics")
    async def get_service_diagnostics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: DiagnosticsFilterInput | None = None,
    ) -> ServiceDiagnostics:
        """
        Get detailed diagnostics for a service integration.

        Args:
            integration_id: UUID of the integration
            filters: Optional diagnostic filters

        Returns:
            Service diagnostics data
        """
        try:
            service = info.context["container"].resolve("DiagnosticsService")
            result = await service.get_service_diagnostics(
                integration_id=integration_id, filters=filters
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return mapper.diagnostics_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving service diagnostics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get health metrics over time")
    @require_auth()
    @require_permission("integration.health.metrics")
    @audit_operation("integration.health.get_metrics")
    @rate_limit(requests=20, window=60)
    @track_metrics("get_health_metrics")
    async def get_health_metrics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        time_range: HealthMetricsTimeRangeInput,
    ) -> HealthMetrics:
        """
        Get health metrics for an integration over a time period.

        Args:
            integration_id: UUID of the integration
            time_range: Time range for metrics

        Returns:
            Health metrics data
        """
        try:
            # Validate time range
            if time_range.end_time <= time_range.start_time:
                raise ValidationError("End time must be after start time")

            # Limit time range to prevent excessive queries
            max_hours = 24 * 7  # 1 week
            hours_diff = (
                time_range.end_time - time_range.start_time
            ).total_seconds() / 3600
            if hours_diff > max_hours:
                raise ValidationError(f"Time range cannot exceed {max_hours} hours")

            service = info.context["container"].resolve("HealthMetricsService")
            result = await service.get_health_metrics(
                integration_id=integration_id, time_range=time_range
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return mapper.health_metrics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving health metrics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get active health alerts")
    @require_auth()
    @require_permission("integration.health.alerts")
    @audit_operation("integration.health.get_alerts")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_health_alerts")
    async def get_health_alerts(
        self,
        info: strawberry.Info,
        integration_id: UUID | None = None,
        severity_levels: list[str] | None = None,
        limit: int = 50,
    ) -> list[HealthAlert]:
        """
        Get active health alerts.

        Args:
            integration_id: Optional specific integration ID
            severity_levels: Optional severity level filters
            limit: Maximum number of alerts to return

        Returns:
            List of health alerts
        """
        try:
            if limit > 100:
                raise ValidationError("Maximum limit is 100")

            service = info.context["container"].resolve("HealthAlertService")
            result = await service.get_active_alerts(
                integration_id=integration_id,
                severity_levels=severity_levels,
                limit=limit,
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return [mapper.health_alert_dto_to_graphql_type(alert) for alert in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving health alerts", error=str(e))
            raise

    @strawberry.field(description="Get health check history")
    @require_auth()
    @require_permission("integration.health.history")
    @audit_operation("integration.health.get_history")
    @rate_limit(requests=15, window=60)
    @track_metrics("get_health_check_history")
    async def get_health_check_history(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        days: int = 7,
        limit: int = 100,
    ) -> list[HealthCheckResult]:
        """
        Get health check history for an integration.

        Args:
            integration_id: UUID of the integration
            days: Number of days of history to retrieve
            limit: Maximum number of records to return

        Returns:
            List of historical health check results
        """
        try:
            if days > 30:
                raise ValidationError("Maximum history period is 30 days")

            if limit > 500:
                raise ValidationError("Maximum limit is 500")

            service = info.context["container"].resolve("HealthHistoryService")
            result = await service.get_health_check_history(
                integration_id=integration_id, days=days, limit=limit
            )

            mapper = info.context["container"].resolve("HealthMapper")
            return [mapper.health_check_dto_to_graphql_type(check) for check in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving health check history",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get uptime statistics")
    @require_auth()
    @require_permission("integration.health.uptime")
    @audit_operation("integration.health.get_uptime")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_uptime_statistics")
    async def get_uptime_statistics(
        self, info: strawberry.Info, integration_id: UUID, period_days: int = 30
    ) -> dict[str, Any]:
        """
        Get uptime statistics for an integration.

        Args:
            integration_id: UUID of the integration
            period_days: Period in days for statistics

        Returns:
            Uptime statistics
        """
        try:
            if period_days > 90:
                raise ValidationError("Maximum period is 90 days")

            service = info.context["container"].resolve("UptimeService")
            result = await service.get_uptime_statistics(
                integration_id=integration_id, period_days=period_days
            )

            return {
                "integration_id": str(integration_id),
                "period_days": period_days,
                "uptime_percentage": result.uptime_percentage,
                "total_checks": result.total_checks,
                "successful_checks": result.successful_checks,
                "failed_checks": result.failed_checks,
                "average_response_time": result.average_response_time,
                "incidents": [
                    {
                        "incident_id": str(incident.incident_id),
                        "start_time": incident.start_time,
                        "end_time": incident.end_time,
                        "duration_minutes": incident.duration_minutes,
                        "severity": incident.severity,
                        "description": incident.description,
                    }
                    for incident in result.incidents
                ],
                "daily_uptime": [
                    {
                        "date": daily.date,
                        "uptime_percentage": daily.uptime_percentage,
                        "total_checks": daily.total_checks,
                        "failed_checks": daily.failed_checks,
                    }
                    for daily in result.daily_uptime
                ],
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving uptime statistics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Check service dependencies")
    @require_auth()
    @require_permission("integration.health.dependencies")
    @audit_operation("integration.health.check_dependencies")
    @rate_limit(requests=20, window=60)
    @track_metrics("check_service_dependencies")
    async def check_service_dependencies(
        self, info: strawberry.Info, integration_id: UUID
    ) -> dict[str, Any]:
        """
        Check the health of service dependencies.

        Args:
            integration_id: UUID of the integration

        Returns:
            Dependency health status
        """
        try:
            service = info.context["container"].resolve("DependencyHealthService")
            result = await service.check_dependencies(integration_id)

            return {
                "integration_id": str(integration_id),
                "overall_status": result.overall_status,
                "dependencies": [
                    {
                        "name": dep.name,
                        "type": dep.dependency_type,
                        "status": dep.status,
                        "endpoint": dep.endpoint,
                        "response_time": dep.response_time,
                        "last_checked": dep.last_checked,
                        "error_message": dep.error_message,
                    }
                    for dep in result.dependencies
                ],
                "critical_failures": result.critical_failures,
                "warnings": result.warnings,
                "checked_at": result.checked_at,
            }

        except Exception as e:
            logger.exception(
                "Error checking service dependencies",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get performance metrics")
    @require_auth()
    @require_permission("integration.health.performance")
    @audit_operation("integration.health.get_performance")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_performance_metrics")
    async def get_performance_metrics(
        self, info: strawberry.Info, integration_id: UUID, hours: int = 24
    ) -> dict[str, Any]:
        """
        Get performance metrics for an integration.

        Args:
            integration_id: UUID of the integration
            hours: Number of hours for metrics

        Returns:
            Performance metrics data
        """
        try:
            if hours > 168:  # 1 week
                raise ValidationError("Maximum period is 168 hours (1 week)")

            service = info.context["container"].resolve("PerformanceMetricsService")
            result = await service.get_performance_metrics(
                integration_id=integration_id, hours=hours
            )

            return {
                "integration_id": str(integration_id),
                "period_hours": hours,
                "response_times": {
                    "average": result.average_response_time,
                    "median": result.median_response_time,
                    "p95": result.p95_response_time,
                    "p99": result.p99_response_time,
                    "min": result.min_response_time,
                    "max": result.max_response_time,
                },
                "throughput": {
                    "requests_per_minute": result.requests_per_minute,
                    "peak_requests_per_minute": result.peak_requests_per_minute,
                    "total_requests": result.total_requests,
                },
                "error_rates": {
                    "overall_error_rate": result.error_rate,
                    "client_error_rate": result.client_error_rate,
                    "server_error_rate": result.server_error_rate,
                    "timeout_rate": result.timeout_rate,
                },
                "trends": [
                    {
                        "timestamp": trend.timestamp,
                        "response_time": trend.response_time,
                        "request_count": trend.request_count,
                        "error_count": trend.error_count,
                    }
                    for trend in result.hourly_trends
                ],
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving performance metrics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise


__all__ = ["HealthQueries"]
