"""Infrastructure health monitoring dashboard.

This module provides comprehensive health monitoring for all infrastructure
components including databases, caches, external services, and circuit breakers.
"""

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any

from app.core.logging import get_logger
from app.modules.identity.infrastructure.config.connection_pool import (
    ConnectionPoolManager,
    get_connection_pool_manager,
)
from app.modules.identity.infrastructure.resilience.circuit_breaker import (
    CircuitBreakerManager,
    get_circuit_breaker_manager,
)

logger = get_logger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthCheckResult:
    """Result of a health check."""
    
    def __init__(
        self,
        component: str,
        status: HealthStatus,
        message: str,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ):
        self.component = component
        self.status = status
        self.message = message
        self.details = details or {}
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "component": self.component,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class HealthChecker:
    """Base class for health checkers."""
    
    def __init__(self, name: str):
        self.name = name
    
    async def check_health(self) -> HealthCheckResult:
        """Perform health check."""
        raise NotImplementedError("Subclasses must implement check_health")


class DatabaseHealthChecker(HealthChecker):
    """Health checker for database connections."""
    
    def __init__(self, pool_manager: ConnectionPoolManager):
        super().__init__("database")
        self.pool_manager = pool_manager
    
    async def check_health(self) -> HealthCheckResult:
        """Check database health."""
        try:
            # Get pool status
            pool_status = await self.pool_manager.get_pool_status()
            
            # Perform actual health check
            health_result = await self.pool_manager.health_check()
            
            if health_result["healthy"]:
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.HEALTHY,
                    message="Database connection healthy",
                    details=pool_status,
                )
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message="Database connection failed",
                details=health_result,
            )
                
        except Exception as e:
            logger.exception("Database health check failed", error=str(e))
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Database health check error: {e!s}",
                details={"error": str(e)},
            )


class CacheHealthChecker(HealthChecker):
    """Health checker for cache connections."""
    
    def __init__(self, cache_client: Any):
        super().__init__("cache")
        self.cache_client = cache_client
    
    async def check_health(self) -> HealthCheckResult:
        """Check cache health."""
        try:
            # Test cache connectivity
            test_key = f"health_check_{datetime.utcnow().timestamp()}"
            test_value = "health_check_value"
            
            # Set test value
            await self.cache_client.set(test_key, test_value, ttl=60)
            
            # Get test value
            retrieved_value = await self.cache_client.get(test_key)
            
            # Clean up
            await self.cache_client.delete(test_key)
            
            if retrieved_value == test_value:
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.HEALTHY,
                    message="Cache connection healthy",
                    details={"test_key": test_key},
                )
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message="Cache value mismatch",
                details={
                    "expected": test_value,
                    "actual": retrieved_value,
                },
            )
                
        except Exception as e:
            logger.exception("Cache health check failed", error=str(e))
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Cache health check error: {e!s}",
                details={"error": str(e)},
            )


class CircuitBreakerHealthChecker(HealthChecker):
    """Health checker for circuit breakers."""
    
    def __init__(self, circuit_breaker_manager: CircuitBreakerManager):
        super().__init__("circuit_breakers")
        self.circuit_breaker_manager = circuit_breaker_manager
    
    async def check_health(self) -> HealthCheckResult:
        """Check circuit breaker health."""
        try:
            # Get circuit breaker health
            health_result = await self.circuit_breaker_manager.health_check()
            
            if health_result["healthy"]:
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.HEALTHY,
                    message="All circuit breakers healthy",
                    details=health_result,
                )
            # Check if any circuit breakers are open
            open_breakers = []
            for name, cb_health in health_result["circuit_breakers"].items():
                if not cb_health["healthy"]:
                    open_breakers.append(name)
            
            status = HealthStatus.WARNING if open_breakers else HealthStatus.HEALTHY
            message = f"Circuit breakers open: {', '.join(open_breakers)}" if open_breakers else "All circuit breakers healthy"
            
            return HealthCheckResult(
                component=self.name,
                status=status,
                message=message,
                details=health_result,
            )
                
        except Exception as e:
            logger.exception("Circuit breaker health check failed", error=str(e))
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Circuit breaker health check error: {e!s}",
                details={"error": str(e)},
            )


class ExternalServiceHealthChecker(HealthChecker):
    """Health checker for external services."""
    
    def __init__(self, service_name: str, service_client: Any):
        super().__init__(f"external_service_{service_name}")
        self.service_name = service_name
        self.service_client = service_client
    
    async def check_health(self) -> HealthCheckResult:
        """Check external service health."""
        try:
            # Perform health check on external service
            if hasattr(self.service_client, 'health_check'):
                health_result = await self.service_client.health_check()
                
                if health_result.get("healthy", False):
                    return HealthCheckResult(
                        component=self.name,
                        status=HealthStatus.HEALTHY,
                        message=f"External service {self.service_name} healthy",
                        details=health_result,
                    )
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.CRITICAL,
                    message=f"External service {self.service_name} unhealthy",
                    details=health_result,
                )
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNKNOWN,
                message=f"External service {self.service_name} has no health check",
                details={"service_name": self.service_name},
            )
                
        except Exception as e:
            logger.exception("External service health check failed", service=self.service_name, error=str(e))
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.CRITICAL,
                message=f"External service {self.service_name} health check error: {e!s}",
                details={"error": str(e)},
            )


class HealthDashboard:
    """Infrastructure health monitoring dashboard."""
    
    def __init__(self):
        self.health_checkers: dict[str, HealthChecker] = {}
        self.last_check_time: datetime | None = None
        self.last_results: dict[str, HealthCheckResult] = {}
        self.check_interval = 30  # seconds
        self.running = False
        self.background_task: asyncio.Task | None = None
    
    def add_health_checker(self, checker: HealthChecker):
        """Add a health checker to the dashboard."""
        self.health_checkers[checker.name] = checker
        logger.info(f"Added health checker: {checker.name}")
    
    def remove_health_checker(self, name: str):
        """Remove a health checker from the dashboard."""
        if name in self.health_checkers:
            del self.health_checkers[name]
            logger.info(f"Removed health checker: {name}")
    
    async def check_all_health(self) -> dict[str, HealthCheckResult]:
        """Check health of all components."""
        results = {}
        
        # Run all health checks concurrently
        tasks = [
            self._run_health_check(name, checker)
            for name, checker in self.health_checkers.items()
        ]
        
        if tasks:
            completed_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(completed_results):
                checker_name = list(self.health_checkers.keys())[i]
                
                if isinstance(result, Exception):
                    logger.exception(f"Health check failed for {checker_name}", error=str(result))
                    results[checker_name] = HealthCheckResult(
                        component=checker_name,
                        status=HealthStatus.CRITICAL,
                        message=f"Health check exception: {result!s}",
                        details={"error": str(result)},
                    )
                else:
                    results[checker_name] = result
        
        self.last_check_time = datetime.utcnow()
        self.last_results = results
        
        return results
    
    async def _run_health_check(self, name: str, checker: HealthChecker) -> HealthCheckResult:
        """Run a single health check with timeout."""
        try:
            return await asyncio.wait_for(checker.check_health(), timeout=10.0)
        except TimeoutError:
            return HealthCheckResult(
                component=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check timeout for {name}",
                details={"timeout": 10.0},
            )
    
    async def get_health_summary(self) -> dict[str, Any]:
        """Get overall health summary."""
        if not self.last_results:
            results = await self.check_all_health()
        else:
            results = self.last_results
        
        summary = {
            "overall_status": HealthStatus.HEALTHY,
            "timestamp": self.last_check_time.isoformat() if self.last_check_time else None,
            "components": {},
            "statistics": {
                "total_components": len(results),
                "healthy": 0,
                "warning": 0,
                "critical": 0,
                "unknown": 0,
            },
        }
        
        # Process results
        for name, result in results.items():
            summary["components"][name] = result.to_dict()
            
            # Update statistics
            summary["statistics"][result.status.value] += 1
            
            # Update overall status
            if result.status == HealthStatus.CRITICAL:
                summary["overall_status"] = HealthStatus.CRITICAL
            elif result.status == HealthStatus.WARNING and summary["overall_status"] != HealthStatus.CRITICAL:
                summary["overall_status"] = HealthStatus.WARNING
            elif result.status == HealthStatus.UNKNOWN and summary["overall_status"] == HealthStatus.HEALTHY:
                summary["overall_status"] = HealthStatus.UNKNOWN
        
        return summary
    
    async def start_background_monitoring(self):
        """Start background health monitoring."""
        if self.running:
            logger.warning("Background monitoring already running")
            return
        
        self.running = True
        self.background_task = asyncio.create_task(self._background_monitoring_loop())
        logger.info("Started background health monitoring")
    
    async def stop_background_monitoring(self):
        """Stop background health monitoring."""
        if not self.running:
            return
        
        self.running = False
        if self.background_task:
            self.background_task.cancel()
            try:
                await self.background_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped background health monitoring")
    
    async def _background_monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                await self.check_all_health()
                
                # Log any critical issues
                for name, result in self.last_results.items():
                    if result.status == HealthStatus.CRITICAL:
                        logger.error(
                            "Critical health issue detected",
                            component=name,
                            message=result.message,
                            details=result.details,
                        )
                
                # Wait for next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("Error in health monitoring loop", error=str(e))
                await asyncio.sleep(self.check_interval)
    
    def get_health_history(self, component: str, hours: int = 24) -> list[dict[str, Any]]:
        """Get health history for a component (placeholder - would need persistent storage)."""
        # This would typically query a time-series database
        # For now, return current state
        if component in self.last_results:
            return [self.last_results[component].to_dict()]
        return []
    
    async def get_dashboard_data(self) -> dict[str, Any]:
        """Get complete dashboard data."""
        summary = await self.get_health_summary()
        
        # Add additional dashboard data
        dashboard_data = {
            "summary": summary,
            "last_check_time": self.last_check_time.isoformat() if self.last_check_time else None,
            "check_interval": self.check_interval,
            "monitoring_running": self.running,
            "total_checkers": len(self.health_checkers),
        }
        
        return dashboard_data


# Global health dashboard instance
_health_dashboard = HealthDashboard()


def get_health_dashboard() -> HealthDashboard:
    """Get the global health dashboard instance."""
    return _health_dashboard


async def initialize_health_dashboard():
    """Initialize the health dashboard with default health checkers."""
    dashboard = get_health_dashboard()
    
    # Add database health checker
    try:
        pool_manager = get_connection_pool_manager()
        db_checker = DatabaseHealthChecker(pool_manager)
        dashboard.add_health_checker(db_checker)
    except RuntimeError:
        logger.warning("Connection pool not initialized, skipping database health checker")
    
    # Add circuit breaker health checker
    circuit_breaker_manager = get_circuit_breaker_manager()
    cb_checker = CircuitBreakerHealthChecker(circuit_breaker_manager)
    dashboard.add_health_checker(cb_checker)
    
    # Start background monitoring
    await dashboard.start_background_monitoring()
    
    logger.info("Health dashboard initialized")


async def get_infrastructure_health() -> dict[str, Any]:
    """Get current infrastructure health status."""
    dashboard = get_health_dashboard()
    return await dashboard.get_dashboard_data()