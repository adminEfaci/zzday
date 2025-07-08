"""Health check application service.

This module provides the application service for integration health monitoring,
including periodic health checks and status reporting.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ApplicationError, NotFoundError
from app.core.logging import get_logger
from app.modules.integration.application.dto import (
    HealthCheckResultDTO,
    IntegrationHealthDTO,
    SystemStatusDTO,
)
from app.modules.integration.domain.aggregates import Integration

logger = get_logger(__name__)


class HealthCheckService:
    """Application service for health monitoring."""

    def __init__(
        self,
        integration_repository: Any,
        health_check_repository: Any,
        connection_service: Any,
        credential_repository: Any,
        scheduler: Any,
        alert_service: Any,
        event_publisher: Any,
    ):
        """Initialize health check service.

        Args:
            integration_repository: Repository for integrations
            health_check_repository: Repository for health check records
            connection_service: Service for testing connections
            credential_repository: Repository for credentials
            scheduler: Service for scheduling health checks
            alert_service: Service for sending alerts
            event_publisher: Event publisher for domain events
        """
        self._integration_repository = integration_repository
        self._health_check_repository = health_check_repository
        self._connection_service = connection_service
        self._credential_repository = credential_repository
        self._scheduler = scheduler
        self._alert_service = alert_service
        self._event_publisher = event_publisher

    async def perform_health_check(self, integration_id: UUID) -> IntegrationHealthDTO:
        """Perform health check for integration.

        Args:
            integration_id: Integration ID

        Returns:
            IntegrationHealthDTO: Health check results

        Raises:
            NotFoundError: If integration not found
        """
        logger.info("Performing health check", integration_id=integration_id)

        # Get integration
        integration = await self._integration_repository.get_by_id(integration_id)
        if not integration:
            raise NotFoundError(f"Integration not found: {integration_id}")

        start_time = datetime.utcnow()
        health_checks = []
        overall_healthy = True

        try:
            # Perform various health checks
            connectivity_check = await self._check_connectivity(integration)
            health_checks.append(connectivity_check)
            overall_healthy &= connectivity_check.is_healthy

            authentication_check = await self._check_authentication(integration)
            health_checks.append(authentication_check)
            overall_healthy &= authentication_check.is_healthy

            rate_limit_check = await self._check_rate_limits(integration)
            health_checks.append(rate_limit_check)
            overall_healthy &= rate_limit_check.is_healthy

            if integration.can_receive_webhooks:
                webhook_check = await self._check_webhook_endpoints(integration)
                health_checks.append(webhook_check)
                overall_healthy &= webhook_check.is_healthy

            # Update integration health status
            total_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            integration.health_check(
                is_healthy=overall_healthy,
                response_time_ms=total_time,
                error_message=None
                if overall_healthy
                else "One or more health checks failed",
            )

            # Save integration
            await self._integration_repository.save(integration)

            # Save health check records
            for check in health_checks:
                await self._health_check_repository.save_check_result(
                    integration_id=integration.id,
                    check_name=check.check_name,
                    is_healthy=check.is_healthy,
                    response_time_ms=check.response_time_ms,
                    error_message=check.error_message,
                    details=check.details,
                    checked_at=check.checked_at,
                )

            # Publish events
            for event in integration.collect_events():
                await self._event_publisher.publish(event)

            # Send alerts if unhealthy
            if not overall_healthy:
                await self._send_health_alert(integration, health_checks)

            # Calculate uptime percentage
            uptime_percentage = await self._calculate_uptime_percentage(
                integration.id, days=7
            )

            # Calculate average response time
            avg_response_time = await self._calculate_average_response_time(
                integration.id, days=1
            )

            # Get next check time
            next_check_at = await self._get_next_check_time(integration.id)

            logger.info(
                "Health check completed",
                integration_id=integration.id,
                is_healthy=overall_healthy,
                response_time_ms=total_time,
            )

            return IntegrationHealthDTO(
                integration_id=integration.id,
                integration_name=integration.name,
                status=integration.status,
                is_healthy=overall_healthy,
                last_check_at=integration.last_health_check,
                next_check_at=next_check_at,
                consecutive_failures=integration.health_check_failures,
                uptime_percentage=uptime_percentage,
                average_response_time_ms=avg_response_time,
                health_checks=health_checks,
            )

        except Exception as e:
            logger.exception(
                "Health check failed", integration_id=integration.id, error=str(e)
            )

            # Record failed health check
            integration.health_check(
                is_healthy=False, response_time_ms=None, error_message=str(e)
            )
            await self._integration_repository.save(integration)

            raise ApplicationError(f"Health check failed: {e!s}")

    async def schedule_health_checks(self) -> None:
        """Schedule health checks for all active integrations."""
        logger.info("Scheduling health checks")

        # Get all active integrations
        integrations = await self._integration_repository.get_by_filters(
            {"is_active": True}
        )

        scheduled_count = 0
        for integration in integrations:
            try:
                # Determine check interval based on integration health
                interval = self._get_check_interval(integration)

                # Schedule health check
                await self._scheduler.schedule_health_check(
                    integration_id=integration.id, interval_minutes=interval
                )

                scheduled_count += 1

            except Exception as e:
                logger.exception(
                    "Failed to schedule health check",
                    integration_id=integration.id,
                    error=str(e),
                )

        logger.info(
            "Health checks scheduled",
            total_integrations=len(integrations),
            scheduled_count=scheduled_count,
        )

    async def get_system_status(self) -> SystemStatusDTO:
        """Get overall system health status.

        Returns:
            SystemStatusDTO: System status summary
        """
        logger.debug("Getting system status")

        # Get integration statistics
        total_integrations = await self._integration_repository.count_all()
        active_integrations = await self._integration_repository.count_by_filters(
            {"is_active": True}
        )
        connected_integrations = await self._integration_repository.count_by_filters(
            {"is_active": True, "is_connected": True}
        )
        healthy_integrations = await self._integration_repository.count_by_filters(
            {"is_active": True, "is_healthy": True}
        )
        unhealthy_integrations = await self._integration_repository.count_by_filters(
            {"is_active": True, "is_healthy": False}
        )
        attention_integrations = await self._integration_repository.count_by_filters(
            {"is_active": True, "needs_attention": True}
        )

        # Get sync job statistics
        active_sync_jobs = await self._get_active_sync_jobs_count()

        # Get webhook statistics
        pending_webhooks = await self._get_pending_webhooks_count()

        # Calculate system uptime
        system_uptime = await self._calculate_system_uptime_percentage()

        # Get last incident
        last_incident_at = await self._get_last_incident_time()

        return SystemStatusDTO(
            total_integrations=total_integrations,
            active_integrations=active_integrations,
            connected_integrations=connected_integrations,
            healthy_integrations=healthy_integrations,
            unhealthy_integrations=unhealthy_integrations,
            integrations_needing_attention=attention_integrations,
            active_sync_jobs=active_sync_jobs,
            pending_webhooks=pending_webhooks,
            system_uptime_percentage=system_uptime,
            last_incident_at=last_incident_at,
        )

    async def _check_connectivity(self, integration: Integration) -> Any:
        """Check integration connectivity.

        Args:
            integration: Integration to check

        Returns:
            HealthCheckResultDTO: Connectivity check result
        """
        start_time = datetime.utcnow()

        try:
            # Test basic connectivity
            response = await self._connection_service.ping(integration)

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            return HealthCheckResultDTO(
                check_name="connectivity",
                is_healthy=response.get("success", False),
                response_time_ms=response_time,
                error_message=response.get("error")
                if not response.get("success")
                else None,
                details=response,
                checked_at=datetime.utcnow(),
            )

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            return HealthCheckResultDTO(
                check_name="connectivity",
                is_healthy=False,
                response_time_ms=response_time,
                error_message=str(e),
                details={"error": str(e)},
                checked_at=datetime.utcnow(),
            )

    async def _check_authentication(self, integration: Integration) -> Any:
        """Check integration authentication.

        Args:
            integration: Integration to check

        Returns:
            HealthCheckResultDTO: Authentication check result
        """
        start_time = datetime.utcnow()

        try:
            # Get active credential
            credentials = await self._credential_repository.get_by_integration_id(
                integration.id, active_only=True
            )

            if not credentials:
                return HealthCheckResultDTO(
                    check_name="authentication",
                    is_healthy=False,
                    response_time_ms=0,
                    error_message="No active credentials found",
                    details={"error": "no_credentials"},
                    checked_at=datetime.utcnow(),
                )

            credential = credentials[0]  # Use first active credential

            # Test authentication
            auth_result = await self._connection_service.test_authentication(
                integration=integration, credential=credential
            )

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            return HealthCheckResultDTO(
                check_name="authentication",
                is_healthy=auth_result.get("success", False),
                response_time_ms=response_time,
                error_message=auth_result.get("error")
                if not auth_result.get("success")
                else None,
                details=auth_result,
                checked_at=datetime.utcnow(),
            )

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            return HealthCheckResultDTO(
                check_name="authentication",
                is_healthy=False,
                response_time_ms=response_time,
                error_message=str(e),
                details={"error": str(e)},
                checked_at=datetime.utcnow(),
            )

    async def _check_rate_limits(self, integration: Integration) -> Any:
        """Check rate limit status.

        Args:
            integration: Integration to check

        Returns:
            HealthCheckResultDTO: Rate limit check result
        """
        try:
            # Check current rate limit status
            rate_limit_status = await self._connection_service.get_rate_limit_status(
                integration
            )

            is_healthy = rate_limit_status.get("remaining", 0) > 0

            return HealthCheckResultDTO(
                check_name="rate_limits",
                is_healthy=is_healthy,
                response_time_ms=0,
                error_message="Rate limit exceeded" if not is_healthy else None,
                details=rate_limit_status,
                checked_at=datetime.utcnow(),
            )

        except Exception as e:
            return HealthCheckResultDTO(
                check_name="rate_limits",
                is_healthy=False,
                response_time_ms=0,
                error_message=str(e),
                details={"error": str(e)},
                checked_at=datetime.utcnow(),
            )

    async def _check_webhook_endpoints(self, integration: Integration) -> Any:
        """Check webhook endpoint health.

        Args:
            integration: Integration to check

        Returns:
            HealthCheckResultDTO: Webhook check result
        """
        try:
            # Get webhook endpoints for integration
            endpoints = await self._webhook_endpoint_repository.get_by_integration_id(
                integration.id, active_only=True
            )

            if not endpoints:
                return HealthCheckResultDTO(
                    check_name="webhooks",
                    is_healthy=True,
                    response_time_ms=0,
                    error_message=None,
                    details={"message": "No webhook endpoints configured"},
                    checked_at=datetime.utcnow(),
                )

            # Check each endpoint
            endpoint_statuses = []
            all_healthy = True

            for endpoint in endpoints:
                status = await self._connection_service.check_webhook_endpoint(
                    integration=integration, endpoint=endpoint
                )
                endpoint_statuses.append(status)
                all_healthy &= status.get("healthy", False)

            return HealthCheckResultDTO(
                check_name="webhooks",
                is_healthy=all_healthy,
                response_time_ms=0,
                error_message="One or more webhook endpoints unhealthy"
                if not all_healthy
                else None,
                details={"endpoints": endpoint_statuses},
                checked_at=datetime.utcnow(),
            )

        except Exception as e:
            return HealthCheckResultDTO(
                check_name="webhooks",
                is_healthy=False,
                response_time_ms=0,
                error_message=str(e),
                details={"error": str(e)},
                checked_at=datetime.utcnow(),
            )

    def _get_check_interval(self, integration: Integration) -> int:
        """Get health check interval for integration.

        Args:
            integration: Integration

        Returns:
            int: Check interval in minutes
        """
        # Base interval
        base_interval = 15  # 15 minutes

        # Adjust based on health
        if integration.health_check_failures == 0:
            return base_interval
        if integration.health_check_failures <= 2:
            return base_interval // 2  # 7.5 minutes
        return base_interval // 4  # 3.75 minutes (more frequent for unhealthy)

    async def _send_health_alert(
        self, integration: Integration, health_checks: list[Any]
    ) -> None:
        """Send health alert for failed checks.

        Args:
            integration: Integration with health issues
            health_checks: Health check results
        """
        try:
            failed_checks = [check for check in health_checks if not check.is_healthy]

            if not failed_checks:
                return

            # Send alert
            await self._alert_service.send_health_alert(
                integration_id=integration.id,
                integration_name=integration.name,
                failed_checks=failed_checks,
                consecutive_failures=integration.health_check_failures,
            )

        except Exception as e:
            logger.exception(
                "Failed to send health alert",
                integration_id=integration.id,
                error=str(e),
            )

    async def _calculate_uptime_percentage(
        self, integration_id: UUID, days: int
    ) -> float:
        """Calculate uptime percentage for integration.

        Args:
            integration_id: Integration ID
            days: Number of days to calculate

        Returns:
            float: Uptime percentage
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        checks = await self._health_check_repository.get_by_integration_id(
            integration_id=integration_id, start_date=start_date
        )

        if not checks:
            return 100.0

        healthy_checks = sum(1 for check in checks if check.is_healthy)
        return (healthy_checks / len(checks)) * 100.0

    async def _calculate_average_response_time(
        self, integration_id: UUID, days: int
    ) -> float:
        """Calculate average response time.

        Args:
            integration_id: Integration ID
            days: Number of days to calculate

        Returns:
            float: Average response time in milliseconds
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        checks = await self._health_check_repository.get_by_integration_id(
            integration_id=integration_id, start_date=start_date
        )

        response_times = [
            check.response_time_ms
            for check in checks
            if check.is_healthy and check.response_time_ms is not None
        ]

        if not response_times:
            return 0.0

        return sum(response_times) / len(response_times)

    async def _get_next_check_time(self, integration_id: UUID) -> datetime | None:
        """Get next scheduled check time.

        Args:
            integration_id: Integration ID

        Returns:
            datetime | None: Next check time
        """
        return await self._scheduler.get_next_check_time(integration_id)

    async def _get_active_sync_jobs_count(self) -> int:
        """Get count of active sync jobs."""
        # This would query the sync job repository
        return 0  # Placeholder

    async def _get_pending_webhooks_count(self) -> int:
        """Get count of pending webhooks."""
        # This would query the webhook event repository
        return 0  # Placeholder

    async def _calculate_system_uptime_percentage(self) -> float:
        """Calculate overall system uptime percentage."""
        # This would calculate based on all integrations
        return 99.5  # Placeholder

    async def _get_last_incident_time(self) -> datetime | None:
        """Get time of last system incident."""
        # This would query incident logs
        return None  # Placeholder
