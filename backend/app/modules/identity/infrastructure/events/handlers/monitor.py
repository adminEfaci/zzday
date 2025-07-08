"""
Event Handler Health Monitor

Provides comprehensive health monitoring and performance tracking
for event handlers with alerting, metrics collection, and diagnostics.
"""

import asyncio
import contextlib
import statistics
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.core.logging import get_logger

from .base import HandlerResult
from .executor import EventHandlerExecutor
from .registry import EventHandlerRegistry

logger = get_logger(__name__)


class HandlerHealthStatus(Enum):
    """Handler health status levels."""
    
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HandlerMetrics:
    """
    Comprehensive metrics for a single handler.
    
    Tracks performance, reliability, and health indicators
    for monitoring and alerting purposes.
    """
    
    # Basic counters
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    
    # Timing metrics (in milliseconds)
    total_execution_time_ms: float = 0.0
    min_execution_time_ms: float = float('inf')
    max_execution_time_ms: float = 0.0
    
    # Recent performance tracking
    recent_execution_times: deque = field(default_factory=lambda: deque(maxlen=100))
    recent_successes: deque = field(default_factory=lambda: deque(maxlen=50))
    
    # Error tracking
    recent_errors: deque = field(default_factory=lambda: deque(maxlen=20))
    error_types: dict[str, int] = field(default_factory=dict)
    
    # Health indicators
    last_execution: datetime | None = None
    last_success: datetime | None = None
    last_failure: datetime | None = None
    consecutive_failures: int = 0
    
    # Status tracking
    current_status: HandlerHealthStatus = HandlerHealthStatus.UNKNOWN
    status_changed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    @property
    def success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.total_executions == 0:
            return 1.0
        return self.successful_executions / self.total_executions
    
    @property
    def recent_success_rate(self) -> float:
        """Calculate recent success rate from last 50 executions."""
        if not self.recent_successes:
            return 1.0
        return sum(self.recent_successes) / len(self.recent_successes)
    
    @property
    def average_execution_time_ms(self) -> float:
        """Calculate average execution time."""
        if self.total_executions == 0:
            return 0.0
        return self.total_execution_time_ms / self.total_executions
    
    @property
    def recent_average_execution_time_ms(self) -> float:
        """Calculate recent average execution time."""
        if not self.recent_execution_times:
            return 0.0
        return statistics.mean(self.recent_execution_times)
    
    @property
    def execution_time_p95_ms(self) -> float:
        """Calculate 95th percentile execution time."""
        if not self.recent_execution_times:
            return 0.0
        sorted_times = sorted(self.recent_execution_times)
        index = int(0.95 * len(sorted_times))
        return sorted_times[min(index, len(sorted_times) - 1)]
    
    def update_from_result(self, result: HandlerResult) -> None:
        """
        Update metrics from a handler execution result.
        
        Args:
            result: Handler execution result
        """
        # Update basic counters
        self.total_executions += 1
        
        if result.success:
            self.successful_executions += 1
            self.last_success = result.completed_at
            self.consecutive_failures = 0
            self.recent_successes.append(1.0)
        else:
            self.failed_executions += 1
            self.last_failure = result.completed_at
            self.consecutive_failures += 1
            self.recent_successes.append(0.0)
            
            # Track error information
            if result.error:
                error_type = type(result.error).__name__
                self.error_types[error_type] = self.error_types.get(error_type, 0) + 1
                
                self.recent_errors.append({
                    "timestamp": result.completed_at.isoformat(),
                    "error_type": error_type,
                    "error_message": str(result.error)[:200],  # Truncate long messages
                    "execution_id": str(result.execution_id)
                })
        
        # Update timing metrics
        execution_time = result.duration_ms
        self.total_execution_time_ms += execution_time
        self.min_execution_time_ms = min(self.min_execution_time_ms, execution_time)
        self.max_execution_time_ms = max(self.max_execution_time_ms, execution_time)
        self.recent_execution_times.append(execution_time)
        
        # Update last execution time
        self.last_execution = result.completed_at
    
    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            "total_executions": self.total_executions,
            "successful_executions": self.successful_executions,
            "failed_executions": self.failed_executions,
            "success_rate": self.success_rate,
            "recent_success_rate": self.recent_success_rate,
            "average_execution_time_ms": self.average_execution_time_ms,
            "recent_average_execution_time_ms": self.recent_average_execution_time_ms,
            "min_execution_time_ms": self.min_execution_time_ms if self.min_execution_time_ms != float('inf') else 0.0,
            "max_execution_time_ms": self.max_execution_time_ms,
            "execution_time_p95_ms": self.execution_time_p95_ms,
            "consecutive_failures": self.consecutive_failures,
            "error_types": dict(self.error_types),
            "recent_errors": list(self.recent_errors),
            "last_execution": self.last_execution.isoformat() if self.last_execution else None,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "current_status": self.current_status.value,
            "status_changed_at": self.status_changed_at.isoformat(),
        }


@dataclass
class HealthCheckResult:
    """Result of a health check operation."""
    
    handler_id: str
    check_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: HandlerHealthStatus = HandlerHealthStatus.UNKNOWN
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metrics_snapshot: dict[str, Any] = field(default_factory=dict)


class HandlersHealthMonitor:
    """
    Comprehensive health monitor for event handlers.
    
    Provides real-time monitoring, health checks, alerting, and diagnostics
    for all registered event handlers with configurable thresholds and policies.
    
    Design Features:
    - Real-time metrics collection and analysis
    - Configurable health check thresholds
    - Automatic status detection and alerting
    - Performance trend analysis
    - Error pattern detection
    - Comprehensive reporting and diagnostics
    - Integration with monitoring systems
    
    Usage Example:
        monitor = HandlersHealthMonitor(registry, executor)
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Check handler health
        health = monitor.check_handler_health("user.UserCreatedHandler")
        
        # Get system overview
        overview = monitor.get_system_health_overview()
        
        # Configure alerting
        monitor.add_health_alert_callback(alert_handler)
    """
    
    def __init__(
        self,
        registry: EventHandlerRegistry,
        executor: EventHandlerExecutor | None = None,
        health_check_interval_seconds: float = 60.0,
        # Health thresholds
        success_rate_warning_threshold: float = 0.95,
        success_rate_critical_threshold: float = 0.85,
        consecutive_failures_warning_threshold: int = 3,
        consecutive_failures_critical_threshold: int = 5,
        execution_time_warning_threshold_ms: float = 5000.0,
        execution_time_critical_threshold_ms: float = 10000.0,
        stale_handler_warning_hours: int = 24,
        stale_handler_critical_hours: int = 72,
    ):
        """
        Initialize the health monitor.
        
        Args:
            registry: Handler registry to monitor
            executor: Optional executor for integration
            health_check_interval_seconds: Interval between health checks
            success_rate_warning_threshold: Success rate warning threshold
            success_rate_critical_threshold: Success rate critical threshold
            consecutive_failures_warning_threshold: Consecutive failures warning
            consecutive_failures_critical_threshold: Consecutive failures critical
            execution_time_warning_threshold_ms: Execution time warning threshold
            execution_time_critical_threshold_ms: Execution time critical threshold
            stale_handler_warning_hours: Hours before handler considered stale (warning)
            stale_handler_critical_hours: Hours before handler considered stale (critical)
        """
        self.registry = registry
        self.executor = executor
        self.health_check_interval_seconds = health_check_interval_seconds
        
        # Health thresholds
        self.success_rate_warning_threshold = success_rate_warning_threshold
        self.success_rate_critical_threshold = success_rate_critical_threshold
        self.consecutive_failures_warning_threshold = consecutive_failures_warning_threshold
        self.consecutive_failures_critical_threshold = consecutive_failures_critical_threshold
        self.execution_time_warning_threshold_ms = execution_time_warning_threshold_ms
        self.execution_time_critical_threshold_ms = execution_time_critical_threshold_ms
        self.stale_handler_warning_hours = stale_handler_warning_hours
        self.stale_handler_critical_hours = stale_handler_critical_hours
        
        # Monitoring state
        self._handler_metrics: dict[str, HandlerMetrics] = {}
        self._monitoring_task: asyncio.Task | None = None
        self._is_monitoring = False
        
        # Alert callbacks
        self._alert_callbacks: list[Callable[[HealthCheckResult], None]] = []
        
        # Historical data
        self._health_check_history: deque = deque(maxlen=1000)
        
        logger.info(
            "Health monitor initialized",
            health_check_interval=health_check_interval_seconds,
            success_rate_warning=success_rate_warning_threshold,
            success_rate_critical=success_rate_critical_threshold
        )
    
    async def start_monitoring(self) -> None:
        """Start continuous health monitoring."""
        if self._is_monitoring:
            logger.warning("Health monitoring already started")
            return
        
        self._is_monitoring = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Health monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop health monitoring."""
        if not self._is_monitoring:
            return
        
        self._is_monitoring = False
        
        if self._monitoring_task:
            self._monitoring_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitoring_task
            self._monitoring_task = None
        
        logger.info("Health monitoring stopped")
    
    def record_handler_result(self, result: HandlerResult) -> None:
        """
        Record a handler execution result for monitoring.
        
        Args:
            result: Handler execution result
        """
        handler_id = result.handler_id
        
        # Get or create metrics for handler
        if handler_id not in self._handler_metrics:
            self._handler_metrics[handler_id] = HandlerMetrics()
        
        metrics = self._handler_metrics[handler_id]
        
        # Update metrics
        old_status = metrics.current_status
        metrics.update_from_result(result)
        
        # Check for status change
        new_status = self._evaluate_handler_health(handler_id, metrics)
        if new_status != old_status:
            metrics.current_status = new_status
            metrics.status_changed_at = datetime.now(UTC)
            
            # Trigger alert if status degraded
            if self._is_status_degradation(old_status, new_status):
                health_result = self.check_handler_health(handler_id)
                self._trigger_alerts(health_result)
    
    def check_handler_health(self, handler_id: str) -> HealthCheckResult:
        """
        Perform comprehensive health check for a specific handler.
        
        Args:
            handler_id: Handler ID to check
            
        Returns:
            HealthCheckResult: Health check result
        """
        if handler_id not in self._handler_metrics:
            return HealthCheckResult(
                handler_id=handler_id,
                status=HandlerHealthStatus.UNKNOWN,
                issues=["No metrics available for handler"],
                recommendations=["Handler has not been executed yet"]
            )
        
        metrics = self._handler_metrics[handler_id]
        issues = []
        recommendations = []
        
        # Check success rate
        success_rate = metrics.recent_success_rate
        if success_rate < self.success_rate_critical_threshold:
            issues.append(f"Critical: Success rate {success_rate:.2%} below {self.success_rate_critical_threshold:.2%}")
            recommendations.append("Investigate recent failures and fix underlying issues")
        elif success_rate < self.success_rate_warning_threshold:
            issues.append(f"Warning: Success rate {success_rate:.2%} below {self.success_rate_warning_threshold:.2%}")
            recommendations.append("Monitor error patterns and consider preventive measures")
        
        # Check consecutive failures
        if metrics.consecutive_failures >= self.consecutive_failures_critical_threshold:
            issues.append(f"Critical: {metrics.consecutive_failures} consecutive failures")
            recommendations.append("Disable handler temporarily and investigate immediately")
        elif metrics.consecutive_failures >= self.consecutive_failures_warning_threshold:
            issues.append(f"Warning: {metrics.consecutive_failures} consecutive failures")
            recommendations.append("Monitor closely and prepare for potential issues")
        
        # Check execution time
        recent_avg_time = metrics.recent_average_execution_time_ms
        if recent_avg_time > self.execution_time_critical_threshold_ms:
            issues.append(f"Critical: Average execution time {recent_avg_time:.1f}ms exceeds {self.execution_time_critical_threshold_ms}ms")
            recommendations.append("Optimize handler performance or increase timeout")
        elif recent_avg_time > self.execution_time_warning_threshold_ms:
            issues.append(f"Warning: Average execution time {recent_avg_time:.1f}ms exceeds {self.execution_time_warning_threshold_ms}ms")
            recommendations.append("Consider performance optimization")
        
        # Check stale handlers
        if metrics.last_execution:
            hours_since_execution = (datetime.now(UTC) - metrics.last_execution).total_seconds() / 3600
            if hours_since_execution > self.stale_handler_critical_hours:
                issues.append(f"Critical: Handler not executed for {hours_since_execution:.1f} hours")
                recommendations.append("Verify handler registration and event flow")
            elif hours_since_execution > self.stale_handler_warning_hours:
                issues.append(f"Warning: Handler not executed for {hours_since_execution:.1f} hours")
                recommendations.append("Check if handler should be receiving events")
        
        # Determine overall status
        status = self._evaluate_handler_health(handler_id, metrics)
        
        return HealthCheckResult(
            handler_id=handler_id,
            status=status,
            issues=issues,
            recommendations=recommendations,
            metrics_snapshot=metrics.to_dict()
        )
    
    def get_system_health_overview(self) -> dict[str, Any]:
        """
        Get system-wide health overview.
        
        Returns:
            Dict[str, Any]: System health overview
        """
        all_handlers = self.registry.get_all_handlers()
        enabled_handlers = self.registry.get_enabled_handlers()
        
        # Count handlers by status
        status_counts = defaultdict(int)
        for handler in all_handlers:
            handler_id = handler.metadata.handler_id
            if handler_id in self._handler_metrics:
                metrics = self._handler_metrics[handler_id]
                status_counts[metrics.current_status.value] += 1
            else:
                status_counts[HandlerHealthStatus.UNKNOWN.value] += 1
        
        # Calculate system metrics
        total_executions = sum(m.total_executions for m in self._handler_metrics.values())
        total_successes = sum(m.successful_executions for m in self._handler_metrics.values())
        total_failures = sum(m.failed_executions for m in self._handler_metrics.values())
        
        system_success_rate = total_successes / max(total_executions, 1)
        
        # Find problematic handlers
        critical_handlers = []
        warning_handlers = []
        
        for handler_id, metrics in self._handler_metrics.items():
            if metrics.current_status == HandlerHealthStatus.CRITICAL:
                critical_handlers.append(handler_id)
            elif metrics.current_status == HandlerHealthStatus.WARNING:
                warning_handlers.append(handler_id)
        
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "total_handlers": len(all_handlers),
            "enabled_handlers": len(enabled_handlers),
            "handlers_with_metrics": len(self._handler_metrics),
            "status_distribution": dict(status_counts),
            "system_metrics": {
                "total_executions": total_executions,
                "total_successes": total_successes,
                "total_failures": total_failures,
                "system_success_rate": system_success_rate,
            },
            "problematic_handlers": {
                "critical": critical_handlers,
                "warning": warning_handlers,
            },
            "monitoring_active": self._is_monitoring,
            "last_health_check": (
                self._health_check_history[-1]["timestamp"] 
                if self._health_check_history else None
            ),
        }
    
    def get_handler_metrics(self, handler_id: str) -> HandlerMetrics | None:
        """
        Get metrics for a specific handler.
        
        Args:
            handler_id: Handler ID
            
        Returns:
            Optional[HandlerMetrics]: Handler metrics or None
        """
        return self._handler_metrics.get(handler_id)
    
    def get_all_handler_metrics(self) -> dict[str, HandlerMetrics]:
        """Get metrics for all handlers."""
        return dict(self._handler_metrics)
    
    def add_health_alert_callback(self, callback: Callable[[HealthCheckResult], None]) -> None:
        """
        Add a callback for health alerts.
        
        Args:
            callback: Function to call when health alerts are triggered
        """
        self._alert_callbacks.append(callback)
        logger.info(f"Added health alert callback: {callback.__name__}")
    
    def remove_health_alert_callback(self, callback: Callable[[HealthCheckResult], None]) -> None:
        """
        Remove a health alert callback.
        
        Args:
            callback: Callback function to remove
        """
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)
            logger.info(f"Removed health alert callback: {callback.__name__}")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._is_monitoring:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in monitoring loop")
                await asyncio.sleep(min(60.0, self.health_check_interval_seconds))
    
    async def _perform_health_checks(self) -> None:
        """Perform health checks for all handlers."""
        check_timestamp = datetime.now(UTC)
        
        all_handlers = self.registry.get_all_handlers()
        
        for handler in all_handlers:
            handler_id = handler.metadata.handler_id
            
            try:
                health_result = self.check_handler_health(handler_id)
                
                # Store in history
                self._health_check_history.append({
                    "timestamp": check_timestamp.isoformat(),
                    "handler_id": handler_id,
                    "status": health_result.status.value,
                    "issues_count": len(health_result.issues)
                })
                
                # Update status if changed
                if handler_id in self._handler_metrics:
                    metrics = self._handler_metrics[handler_id]
                    if metrics.current_status != health_result.status:
                        old_status = metrics.current_status
                        metrics.current_status = health_result.status
                        metrics.status_changed_at = check_timestamp
                        
                        # Trigger alert on degradation
                        if self._is_status_degradation(old_status, health_result.status):
                            self._trigger_alerts(health_result)
                
            except Exception:
                logger.exception(
                    f"Error checking health for handler {handler_id}",
                    handler_id=handler_id
                )
    
    def _evaluate_handler_health(self, handler_id: str, metrics: HandlerMetrics) -> HandlerHealthStatus:
        """Evaluate handler health status based on metrics."""
        # Check for critical conditions
        if (
            metrics.recent_success_rate < self.success_rate_critical_threshold or
            metrics.consecutive_failures >= self.consecutive_failures_critical_threshold or
            metrics.recent_average_execution_time_ms > self.execution_time_critical_threshold_ms
        ):
            return HandlerHealthStatus.CRITICAL
        
        # Check for stale handlers
        if metrics.last_execution:
            hours_since_execution = (datetime.now(UTC) - metrics.last_execution).total_seconds() / 3600
            if hours_since_execution > self.stale_handler_critical_hours:
                return HandlerHealthStatus.CRITICAL
        
        # Check for warning conditions
        if (
            metrics.recent_success_rate < self.success_rate_warning_threshold or
            metrics.consecutive_failures >= self.consecutive_failures_warning_threshold or
            metrics.recent_average_execution_time_ms > self.execution_time_warning_threshold_ms
        ):
            return HandlerHealthStatus.WARNING
        
        # Check for stale handlers (warning)
        if metrics.last_execution:
            hours_since_execution = (datetime.now(UTC) - metrics.last_execution).total_seconds() / 3600
            if hours_since_execution > self.stale_handler_warning_hours:
                return HandlerHealthStatus.WARNING
        
        # Handler is healthy
        if metrics.total_executions > 0:
            return HandlerHealthStatus.HEALTHY
        return HandlerHealthStatus.UNKNOWN
    
    def _is_status_degradation(self, old_status: HandlerHealthStatus, new_status: HandlerHealthStatus) -> bool:
        """Check if status change represents degradation."""
        status_levels = {
            HandlerHealthStatus.HEALTHY: 3,
            HandlerHealthStatus.WARNING: 2,
            HandlerHealthStatus.CRITICAL: 1,
            HandlerHealthStatus.UNKNOWN: 0,
        }
        
        old_level = status_levels.get(old_status, 0)
        new_level = status_levels.get(new_status, 0)
        
        return new_level < old_level
    
    def _trigger_alerts(self, health_result: HealthCheckResult) -> None:
        """Trigger alert callbacks for health issues."""
        for callback in self._alert_callbacks:
            try:
                callback(health_result)
            except Exception:
                logger.exception(
                    f"Error in health alert callback {callback.__name__}",
                    callback=callback.__name__,
                    handler_id=health_result.handler_id
                )


# Export all classes
__all__ = [
    "HandlerHealthStatus",
    "HandlerMetrics",
    "HandlersHealthMonitor",
    "HealthCheckResult",
]