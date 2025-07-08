"""Monitoring and metrics collection following pure Python principles.

This module provides comprehensive monitoring infrastructure for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are
completely independent of any framework (FastAPI, Pydantic, etc.).

The monitoring system handles Prometheus metrics, performance tracking, health monitoring,
and provides framework-agnostic observability capabilities with rich error handling
and security features.

Design Principles:
- Pure Python classes with explicit configuration validation
- Framework-agnostic design for maximum portability
- Comprehensive metrics collection and analysis
- Rich error handling and recovery mechanisms
- Performance monitoring with statistical analysis
- Security-focused metric filtering and sanitization
- Environment-specific monitoring strategies
- Configurable metric collection and retention

Architecture:
- PerformanceTracker: Statistical analysis and performance monitoring
- PrometheusMetrics: Prometheus metrics management and collection
- HealthMonitor: System health monitoring and checks
- MonitoringManager: Central coordination and lifecycle management
- SecurityFilter: Metric sanitization and security filtering
"""

import asyncio
import contextlib
import os
import statistics
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from typing import Any
from uuid import uuid4

from prometheus_client import (
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    multiprocess,
    start_http_server,
)

# Handle missing config
try:
    from app.core.config import MetricsConfig
except ImportError:
    from dataclasses import dataclass
    
    @dataclass
    class MetricsConfig:
        """Fallback metrics configuration."""
        enable_prometheus: bool = True
        enable_multiprocess_mode: bool = False
        prometheus_port: int = 8000
        prometheus_host: str = "0.0.0.0"
        prometheus_endpoint: str = "/metrics"
        health_check_interval: int = 30
        health_check_timeout: int = 10
        max_health_failures: int = 3
        retention_period: int = 3600
        max_metric_history: int = 1000
        enable_anomaly_detection: bool = True
        enable_health_checks: bool = True
        enable_monitoring: bool = True
        collection_interval: int = 60
        
        def to_dict(self) -> dict[str, bool]:
            return {
                "enable_prometheus": self.enable_prometheus,
                "enable_monitoring": self.enable_monitoring,
            }

# Handle missing enums
try:
    from app.core.enums import AlertSeverity, HealthStatus, MetricType
except ImportError:
    from enum import Enum
    
    class AlertSeverity(Enum):
        """Alert severity levels."""
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
        WARNING = "warning"
    
    class HealthStatus(Enum):
        """Health status values."""
        HEALTHY = "healthy"
        DEGRADED = "degraded"
        UNHEALTHY = "unhealthy"
        UNKNOWN = "unknown"
    
    class MetricType(Enum):
        """Metric type values."""
        COUNTER = "counter"
        GAUGE = "gauge"
        HISTOGRAM = "histogram"

from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)


# =====================================================================================
# DATA CLASSES
# =====================================================================================


@dataclass
class MetricDataPoint:
    """Individual metric data point with timestamp."""

    timestamp: datetime
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StatisticalSummary:
    """Statistical summary of metric data."""

    count: int
    mean: float
    median: float
    std_dev: float
    min_value: float
    max_value: float
    percentile_95: float
    percentile_99: float
    trend_direction: str  # "increasing", "decreasing", "stable"
    trend_strength: float  # 0.0 to 1.0


@dataclass
class HealthCheckResult:
    """Result of a health check operation."""

    name: str
    status: HealthStatus
    response_time: float
    message: str
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


# =====================================================================================
# PERFORMANCE TRACKING AND STATISTICS
# =====================================================================================


class PerformanceTracker:
    """
    Performance tracker with comprehensive statistical analysis.

    Provides detailed performance monitoring, trend analysis, and anomaly detection
    for metrics and system performance indicators.

    Design Features:
    - Pure Python implementation
    - Statistical analysis with trend detection
    - Rolling window calculations
    - Anomaly detection algorithms
    - Memory-efficient data storage
    - Configurable retention policies

    Usage Example:
        tracker = PerformanceTracker(
            retention_period=3600,
            enable_anomaly_detection=True
        )

        # Track metric values
        tracker.record_metric("response_time", 0.150)
        tracker.record_metric("error_rate", 0.001)

        # Get statistical analysis
        stats = tracker.get_statistics("response_time")

        # Check for anomalies
        anomalies = tracker.detect_anomalies("response_time")
    """

    def __init__(
        self,
        retention_period: int = 3600,
        max_data_points: int = 10000,
        enable_anomaly_detection: bool = True,
        anomaly_threshold: float = 2.0,
    ):
        """
        Initialize performance tracker.

        Args:
            retention_period: Data retention period in seconds
            max_data_points: Maximum data points per metric
            enable_anomaly_detection: Whether to enable anomaly detection
            anomaly_threshold: Standard deviations for anomaly detection
        """
        self.retention_period = retention_period
        self.max_data_points = max_data_points
        self.enable_anomaly_detection = enable_anomaly_detection
        self.anomaly_threshold = anomaly_threshold

        # Data storage
        self._metrics_data: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_data_points)
        )
        self._statistics_cache: dict[str, StatisticalSummary] = {}
        self._cache_timestamps: dict[str, datetime] = {}

        # Anomaly tracking
        self._anomalies: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._baseline_stats: dict[str, dict[str, float]] = {}

        logger.info(
            "PerformanceTracker initialized",
            retention_period=retention_period,
            max_data_points=max_data_points,
            anomaly_detection=enable_anomaly_detection,
        )

    def record_metric(
        self,
        metric_name: str,
        value: float,
        labels: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Record a metric value with timestamp.

        Args:
            metric_name: Name of the metric
            value: Metric value
            labels: Optional metric labels
            metadata: Optional metadata
        """
        if not isinstance(value, int | float):
            logger.warning(
                f"Invalid metric value type for {metric_name}: {type(value)}"
            )
            return

        if not (-1e10 <= value <= 1e10):  # Reasonable bounds check
            logger.warning(f"Metric value out of bounds for {metric_name}: {value}")
            return

        timestamp = datetime.utcnow()
        data_point = MetricDataPoint(
            timestamp=timestamp,
            value=float(value),
            labels=labels or {},
            metadata=metadata or {},
        )

        # Store data point
        self._metrics_data[metric_name].append(data_point)

        # Invalidate statistics cache
        if metric_name in self._statistics_cache:
            del self._statistics_cache[metric_name]
            del self._cache_timestamps[metric_name]

        # Perform anomaly detection if enabled
        if self.enable_anomaly_detection:
            self._check_for_anomaly(metric_name, value, timestamp)

        logger.debug(
            "Metric recorded",
            metric_name=metric_name,
            value=value,
            data_points=len(self._metrics_data[metric_name]),
        )

    def get_statistics(
        self, metric_name: str, force_refresh: bool = False
    ) -> StatisticalSummary | None:
        """
        Get statistical summary for a metric.

        Args:
            metric_name: Name of the metric
            force_refresh: Whether to force cache refresh

        Returns:
            StatisticalSummary: Statistical analysis or None if no data
        """
        if metric_name not in self._metrics_data:
            return None

        # Check cache validity
        cache_age = 300  # 5 minutes
        now = datetime.utcnow()

        if (
            not force_refresh
            and metric_name in self._statistics_cache
            and metric_name in self._cache_timestamps
            and (now - self._cache_timestamps[metric_name]).total_seconds() < cache_age
        ):
            return self._statistics_cache[metric_name]

        # Clean old data
        self._clean_old_data(metric_name)

        data_points = list(self._metrics_data[metric_name])
        if not data_points:
            return None

        # Extract values
        values = [dp.value for dp in data_points]

        if len(values) < 2:
            # Not enough data for meaningful statistics
            return StatisticalSummary(
                count=len(values),
                mean=values[0],
                median=values[0],
                std_dev=0.0,
                min_value=values[0],
                max_value=values[0],
                percentile_95=values[0],
                percentile_99=values[0],
                trend_direction="stable",
                trend_strength=0.0,
            )

        # Calculate statistics
        try:
            count = len(values)
            mean = statistics.mean(values)
            median = statistics.median(values)
            std_dev = statistics.stdev(values) if count > 1 else 0.0
            min_value = min(values)
            max_value = max(values)

            # Calculate percentiles safely
            sorted_values = sorted(values)
            p95_idx = max(0, min(int(0.95 * (count - 1)), count - 1))
            p99_idx = max(0, min(int(0.99 * (count - 1)), count - 1))
            percentile_95 = sorted_values[p95_idx]
            percentile_99 = sorted_values[p99_idx]

            # Calculate trend
            trend_direction, trend_strength = self._calculate_trend(values)

            summary = StatisticalSummary(
                count=count,
                mean=mean,
                median=median,
                std_dev=std_dev,
                min_value=min_value,
                max_value=max_value,
                percentile_95=percentile_95,
                percentile_99=percentile_99,
                trend_direction=trend_direction,
                trend_strength=trend_strength,
            )

        except Exception as e:
            logger.exception(
                "Failed to calculate statistics", metric_name=metric_name, error=str(e)
            )
            return None
        else:
            # Cache result
            self._statistics_cache[metric_name] = summary
            self._cache_timestamps[metric_name] = now

            return summary

    def detect_anomalies(
        self, metric_name: str, lookback_minutes: int = 60
    ) -> list[dict[str, Any]]:
        """
        Detect anomalies in metric data.

        Args:
            metric_name: Name of the metric
            lookback_minutes: Minutes to look back for anomalies

        Returns:
            List of anomaly records
        """
        if not self.enable_anomaly_detection or metric_name not in self._anomalies:
            return []

        cutoff_time = datetime.utcnow() - timedelta(minutes=lookback_minutes)

        # Filter recent anomalies
        return [
            anomaly
            for anomaly in self._anomalies[metric_name]
            if anomaly["timestamp"] >= cutoff_time
        ]

    def get_metric_names(self) -> list[str]:
        """Get list of all tracked metric names."""
        return list(self._metrics_data.keys())

    def get_data_points(
        self, metric_name: str, limit: int | None = None, since: datetime | None = None
    ) -> list[MetricDataPoint]:
        """
        Get raw data points for a metric.

        Args:
            metric_name: Name of the metric
            limit: Maximum number of data points
            since: Only return data points after this time

        Returns:
            List of data points
        """
        if metric_name not in self._metrics_data:
            return []

        data_points = list(self._metrics_data[metric_name])

        # Filter by time
        if since:
            data_points = [dp for dp in data_points if dp.timestamp >= since]

        # Apply limit
        if limit and len(data_points) > limit:
            data_points = data_points[-limit:]

        return data_points

    def clear_metric(self, metric_name: str) -> None:
        """Clear all data for a specific metric."""
        if metric_name in self._metrics_data:
            self._metrics_data[metric_name].clear()

        if metric_name in self._statistics_cache:
            del self._statistics_cache[metric_name]
            del self._cache_timestamps[metric_name]

        if metric_name in self._anomalies:
            self._anomalies[metric_name].clear()

        logger.info(f"Cleared metric data for {metric_name}")

    def get_performance_summary(self) -> dict[str, Any]:
        """Get overall performance summary."""
        total_data_points = sum(len(data) for data in self._metrics_data.values())
        total_anomalies = sum(len(anomalies) for anomalies in self._anomalies.values())

        metrics_with_data = len(
            [name for name, data in self._metrics_data.items() if data]
        )

        return {
            "total_metrics": len(self._metrics_data),
            "metrics_with_data": metrics_with_data,
            "total_data_points": total_data_points,
            "total_anomalies": total_anomalies,
            "cache_size": len(self._statistics_cache),
            "retention_period": self.retention_period,
            "anomaly_detection_enabled": self.enable_anomaly_detection,
        }

    def _clean_old_data(self, metric_name: str) -> None:
        """Remove data points older than retention period."""
        if metric_name not in self._metrics_data:
            return

        cutoff_time = datetime.utcnow() - timedelta(seconds=self.retention_period)
        data_points = self._metrics_data[metric_name]

        # Remove old data points
        while data_points and data_points[0].timestamp < cutoff_time:
            data_points.popleft()

    def _calculate_trend(self, values: list[float]) -> tuple[str, float]:
        """Calculate trend direction and strength."""
        if len(values) < 3:
            return "stable", 0.0

        # Simple linear regression to detect trend
        n = len(values)
        x_values = list(range(n))

        try:
            # Calculate correlation coefficient
            x_mean = sum(x_values) / n
            y_mean = sum(values) / n

            numerator = sum(
                (x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n)
            )
            x_variance = sum((x - x_mean) ** 2 for x in x_values)
            y_variance = sum((y - y_mean) ** 2 for y in values)

            if x_variance == 0 or y_variance == 0:
                return "stable", 0.0

            correlation = numerator / (x_variance * y_variance) ** 0.5

            # Determine trend direction and strength
            if abs(correlation) < 0.1:
                return "stable", abs(correlation)
            if correlation > 0:
                return "increasing", abs(correlation)
            return "decreasing", abs(correlation)

        except Exception:
            return "stable", 0.0

    def _check_for_anomaly(
        self, metric_name: str, value: float, timestamp: datetime
    ) -> None:
        """Check if a value is anomalous based on historical data."""
        if metric_name not in self._baseline_stats:
            # Build baseline from recent data
            self._update_baseline_stats(metric_name)

        baseline = self._baseline_stats.get(metric_name, {})
        if not baseline:
            return

        mean = baseline.get("mean", 0.0)
        std_dev = baseline.get("std_dev", 0.0)

        if std_dev == 0:
            return  # No variance, can't detect anomalies

        # Calculate z-score
        z_score = abs(value - mean) / std_dev

        if z_score > self.anomaly_threshold:
            anomaly = {
                "timestamp": timestamp,
                "value": value,
                "expected_range": (
                    mean - self.anomaly_threshold * std_dev,
                    mean + self.anomaly_threshold * std_dev,
                ),
                "z_score": z_score,
                "severity": "high"
                if z_score > self.anomaly_threshold * 2
                else "medium",
            }

            self._anomalies[metric_name].append(anomaly)

            # Keep only recent anomalies
            cutoff_time = timestamp - timedelta(hours=24)
            self._anomalies[metric_name] = [
                a for a in self._anomalies[metric_name] if a["timestamp"] >= cutoff_time
            ]

            logger.warning(
                "Anomaly detected",
                metric_name=metric_name,
                value=value,
                z_score=z_score,
                severity=anomaly["severity"],
            )

    def _update_baseline_stats(self, metric_name: str) -> None:
        """Update baseline statistics for anomaly detection."""
        if metric_name not in self._metrics_data:
            return

        # Use last 100 data points for baseline (excluding very recent ones)
        data_points = list(self._metrics_data[metric_name])
        if len(data_points) < 10:
            return  # Not enough data for baseline

        # Exclude the most recent 5 points to avoid including potential anomalies
        baseline_points = data_points[:-5] if len(data_points) > 5 else data_points[:-1]
        values = [dp.value for dp in baseline_points]

        if len(values) < 2:
            return

        try:
            mean = statistics.mean(values)
            std_dev = statistics.stdev(values)

            self._baseline_stats[metric_name] = {
                "mean": mean,
                "std_dev": std_dev,
                "sample_size": len(values),
                "updated_at": datetime.utcnow(),
            }

        except Exception as e:
            logger.exception(
                "Failed to update baseline stats", metric_name=metric_name, error=str(e)
            )


# =====================================================================================
# PROMETHEUS METRICS MANAGEMENT
# =====================================================================================


class PrometheusMetrics:
    """
    Prometheus metrics manager with comprehensive metric lifecycle management.

    Provides framework-agnostic Prometheus metrics collection, registration,
    and export capabilities with security filtering and performance optimization.

    Design Features:
    - Pure Python implementation
    - Dynamic metric registration
    - Security-focused label filtering
    - Performance-optimized collection
    - Multiprocess support
    - Comprehensive error handling

    Usage Example:
        metrics = PrometheusMetrics(config)
        await metrics.initialize()

        # Register custom metrics
        metrics.register_counter("api_requests", "API request count", ["method", "endpoint"])

        # Increment metrics
        metrics.increment_counter("api_requests", {"method": "GET", "endpoint": "/users"})

        # Export metrics
        metrics_data = metrics.export_metrics()
    """

    def __init__(self, config: MetricsConfig):
        """
        Initialize Prometheus metrics manager.

        Args:
            config: Metrics configuration
        """
        self.config = config
        self.registry: CollectorRegistry | None = None
        self._metrics: dict[str, Any] = {}
        self._http_server_task: asyncio.Task | None = None
        self._initialized = False

        # Pre-defined metrics from original file
        self._initialize_builtin_metrics()

        logger.info(
            "PrometheusMetrics initialized",
            prometheus_enabled=config.enable_prometheus,
            multiprocess_mode=config.enable_multiprocess_mode,
        )

    async def initialize(self) -> None:
        """
        Initialize Prometheus metrics collection.

        Raises:
            InfrastructureError: If initialization fails
        """
        if self._initialized:
            logger.warning("PrometheusMetrics already initialized")
            return

        try:
            # Set up registry
            if (
                self.config.enable_multiprocess_mode
                and "PROMETHEUS_MULTIPROC_DIR" in os.environ
            ):
                self.registry = CollectorRegistry()
                multiprocess.MultiProcessCollector(self.registry)
                logger.info("Initialized Prometheus in multiprocess mode")
            else:
                self.registry = CollectorRegistry()
                self.registry.register(PROCESS_COLLECTOR)
                self.registry.register(PLATFORM_COLLECTOR)
                logger.info("Initialized Prometheus in single process mode")

            # Start HTTP server if enabled
            if self.config.enable_prometheus:
                await self._start_http_server()

            self._initialized = True

            logger.info("PrometheusMetrics initialization completed")

        except Exception as e:
            logger.exception(
                "Failed to initialize PrometheusMetrics",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise InfrastructureError(f"Prometheus initialization failed: {e}") from e

    async def shutdown(self) -> None:
        """Shutdown Prometheus metrics collection."""
        if self._http_server_task:
            self._http_server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._http_server_task

        self._initialized = False
        logger.info("PrometheusMetrics shutdown completed")

    def register_counter(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
        namespace: str = "ezzday",
    ) -> Counter:
        """Register a Prometheus counter metric."""
        full_name = f"{namespace}_{name}"

        if full_name in self._metrics:
            return self._metrics[full_name]

        counter = Counter(
            full_name, description, labelnames=labels or [], registry=self.registry
        )

        self._metrics[full_name] = counter

        logger.debug("Counter metric registered", name=full_name, labels=labels)

        return counter

    def register_histogram(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
        buckets: list[float] | None = None,
        namespace: str = "ezzday",
    ) -> Histogram:
        """Register a Prometheus histogram metric."""
        full_name = f"{namespace}_{name}"

        if full_name in self._metrics:
            return self._metrics[full_name]

        histogram = Histogram(
            full_name,
            description,
            labelnames=labels or [],
            buckets=buckets,
            registry=self.registry,
        )

        self._metrics[full_name] = histogram

        logger.debug(
            "Histogram metric registered",
            name=full_name,
            labels=labels,
            buckets=buckets,
        )

        return histogram

    def register_gauge(
        self,
        name: str,
        description: str,
        labels: list[str] | None = None,
        namespace: str = "ezzday",
    ) -> Gauge:
        """Register a Prometheus gauge metric."""
        full_name = f"{namespace}_{name}"

        if full_name in self._metrics:
            return self._metrics[full_name]

        gauge = Gauge(
            full_name, description, labelnames=labels or [], registry=self.registry
        )

        self._metrics[full_name] = gauge

        logger.debug("Gauge metric registered", name=full_name, labels=labels)

        return gauge

    def get_metric(self, name: str) -> Any | None:
        """Get a registered metric by name."""
        return self._metrics.get(name)

    def export_metrics(self) -> str:
        """Export all metrics in Prometheus format."""
        if not self.registry:
            return ""

        try:
            return generate_latest(self.registry).decode("utf-8")
        except Exception as e:
            logger.exception("Failed to export metrics", error=str(e))
            return ""

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get summary of registered metrics."""
        return {
            "total_metrics": len(self._metrics),
            "metric_names": list(self._metrics.keys()),
            "registry_initialized": self.registry is not None,
            "http_server_running": self._http_server_task is not None
            and not self._http_server_task.done(),
            "multiprocess_mode": self.config.enable_multiprocess_mode,
        }

    def _initialize_builtin_metrics(self) -> None:
        """Initialize built-in metrics from the original monitoring file."""
        # This will be called after registry is set up

    async def _start_http_server(self) -> None:
        """Start HTTP server for metrics endpoint."""
        try:
            start_http_server(
                port=self.config.prometheus_port,
                addr=self.config.prometheus_host,
                registry=self.registry,
            )

            logger.info(
                "Prometheus HTTP server started",
                host=self.config.prometheus_host,
                port=self.config.prometheus_port,
                endpoint=self.config.prometheus_endpoint,
            )

        except Exception as e:
            logger.exception(
                "Failed to start Prometheus HTTP server",
                error=str(e),
                host=self.config.prometheus_host,
                port=self.config.prometheus_port,
            )
            raise


# =====================================================================================
# HEALTH MONITORING
# =====================================================================================


class HealthMonitor:
    """
    Comprehensive system health monitor with detailed diagnostics.

    Provides health checking capabilities for various system components
    including database, cache, external services, and application health.

    Design Features:
    - Pure Python implementation
    - Configurable health checks
    - Performance tracking
    - Alert generation
    - Historical health data
    - Comprehensive error handling
    """

    def __init__(self, config: MetricsConfig):
        """Initialize health monitor."""
        self.config = config
        self._health_checks: dict[str, Callable] = {}
        self._health_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._last_check_times: dict[str, datetime] = {}
        self._consecutive_failures: dict[str, int] = defaultdict(int)
        self._alerts: list[dict[str, Any]] = []

        logger.info(
            "HealthMonitor initialized",
            check_interval=config.health_check_interval,
            timeout=config.health_check_timeout,
        )

    def register_health_check(
        self,
        name: str,
        check_function: Callable,
        critical: bool = True,
        timeout: int | None = None,
    ) -> None:
        """
        Register a health check function.

        Args:
            name: Name of the health check
            check_function: Async function that performs the check
            critical: Whether this check is critical for overall health
            timeout: Custom timeout for this check
        """
        self._health_checks[name] = {
            "function": check_function,
            "critical": critical,
            "timeout": timeout or self.config.health_check_timeout,
            "registered_at": datetime.utcnow(),
        }

        logger.info(
            "Health check registered", name=name, critical=critical, timeout=timeout
        )

    async def run_health_check(self, name: str) -> HealthCheckResult:
        """
        Run a specific health check.

        Args:
            name: Name of the health check

        Returns:
            HealthCheckResult: Result of the health check
        """
        if name not in self._health_checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                response_time=0.0,
                message="Health check not registered",
                timestamp=datetime.utcnow(),
            )

        check_config = self._health_checks[name]
        start_time = time.time()

        try:
            # Run the health check with timeout
            result = await asyncio.wait_for(
                check_config["function"](), timeout=check_config["timeout"]
            )

            response_time = time.time() - start_time

            # Reset consecutive failures on success
            self._consecutive_failures[name] = 0

            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.HEALTHY,
                response_time=response_time,
                message=result.get("message", "Health check passed"),
                timestamp=datetime.utcnow(),
                metadata=result.get("metadata", {}),
            )

        except TimeoutError:
            response_time = time.time() - start_time
            self._consecutive_failures[name] += 1

            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message="Health check timed out",
                timestamp=datetime.utcnow(),
            )

        except Exception as e:
            response_time = time.time() - start_time
            self._consecutive_failures[name] += 1

            health_result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Health check failed: {e!s}",
                timestamp=datetime.utcnow(),
                metadata={"error_type": type(e).__name__},
            )

        # Store result in history
        self._health_history[name].append(health_result)
        self._last_check_times[name] = health_result.timestamp

        # Check for alerts
        self._check_for_alerts(name, health_result)

        logger.debug(
            "Health check completed",
            name=name,
            status=health_result.status.value,
            response_time=response_time,
            consecutive_failures=self._consecutive_failures[name],
        )

        return health_result

    async def run_all_health_checks(self) -> dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}

        # Run all checks concurrently
        tasks = {name: self.run_health_check(name) for name in self._health_checks}

        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for name, result in zip(tasks.keys(), completed, strict=False):
            if isinstance(result, Exception):
                results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    response_time=0.0,
                    message=f"Health check execution failed: {result!s}",
                    timestamp=datetime.utcnow(),
                )
            else:
                results[name] = result

        return results

    def get_overall_health(self) -> dict[str, Any]:
        """Get overall system health status."""
        if not self._health_checks:
            return {
                "status": HealthStatus.UNKNOWN.value,
                "message": "No health checks registered",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Get latest results
        latest_results = {}
        for name in self._health_checks:
            if self._health_history.get(name):
                latest_results[name] = self._health_history[name][-1]

        if not latest_results:
            return {
                "status": HealthStatus.UNKNOWN.value,
                "message": "No health check results available",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Determine overall status
        critical_checks = [
            result
            for name, result in latest_results.items()
            if self._health_checks[name]["critical"]
        ]

        non_critical_checks = [
            result
            for name, result in latest_results.items()
            if not self._health_checks[name]["critical"]
        ]

        # Check critical health checks
        critical_unhealthy = any(
            result.status == HealthStatus.UNHEALTHY for result in critical_checks
        )

        critical_degraded = any(
            result.status == HealthStatus.DEGRADED for result in critical_checks
        )

        if critical_unhealthy:
            overall_status = HealthStatus.UNHEALTHY
            message = "One or more critical health checks are failing"
        elif critical_degraded:
            overall_status = HealthStatus.DEGRADED
            message = "One or more critical health checks are degraded"
        elif any(
            result.status == HealthStatus.UNHEALTHY for result in non_critical_checks
        ):
            overall_status = HealthStatus.DEGRADED
            message = "One or more non-critical health checks are failing"
        else:
            overall_status = HealthStatus.HEALTHY
            message = "All health checks are passing"

        return {
            "status": overall_status.value,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                name: {
                    "status": result.status.value,
                    "response_time": result.response_time,
                    "message": result.message,
                    "critical": self._health_checks[name]["critical"],
                }
                for name, result in latest_results.items()
            },
            "summary": {
                "total_checks": len(latest_results),
                "healthy": len(
                    [
                        r
                        for r in latest_results.values()
                        if r.status == HealthStatus.HEALTHY
                    ]
                ),
                "degraded": len(
                    [
                        r
                        for r in latest_results.values()
                        if r.status == HealthStatus.DEGRADED
                    ]
                ),
                "unhealthy": len(
                    [
                        r
                        for r in latest_results.values()
                        if r.status == HealthStatus.UNHEALTHY
                    ]
                ),
            },
        }

    def get_health_history(self, name: str, limit: int = 50) -> list[HealthCheckResult]:
        """Get health check history for a specific check."""
        if name not in self._health_history:
            return []

        history = list(self._health_history[name])
        return history[-limit:] if limit else history

    def get_alerts(self, severity: AlertSeverity = None) -> list[dict[str, Any]]:
        """Get health-related alerts."""
        if severity:
            return [
                alert for alert in self._alerts if alert["severity"] == severity.value
            ]
        return self._alerts.copy()

    def _check_for_alerts(self, name: str, result: HealthCheckResult) -> None:
        """Check if an alert should be generated."""
        consecutive_failures = self._consecutive_failures[name]
        check_config = self._health_checks[name]

        # Generate alert for consecutive failures
        if (
            consecutive_failures >= self.config.max_health_failures
            and result.status == HealthStatus.UNHEALTHY
        ):
            severity = (
                AlertSeverity.CRITICAL
                if check_config["critical"]
                else AlertSeverity.WARNING
            )

            alert = {
                "id": str(uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "severity": severity.value,
                "type": "health_check_failure",
                "name": name,
                "message": f"Health check '{name}' has failed {consecutive_failures} consecutive times",
                "consecutive_failures": consecutive_failures,
                "critical": check_config["critical"],
                "last_error": result.message,
            }

            self._alerts.append(alert)

            # Keep only last 1000 alerts
            if len(self._alerts) > 1000:
                self._alerts = self._alerts[-1000:]

            logger.error(
                "Health check alert generated",
                name=name,
                consecutive_failures=consecutive_failures,
                severity=severity.value,
                critical=check_config["critical"],
            )


# =====================================================================================
# MONITORING MANAGER
# =====================================================================================


class MonitoringManager:
    """
    Central monitoring manager coordinating all monitoring components.

    Provides unified monitoring management with lifecycle coordination,
    performance tracking, health monitoring, and metrics collection.

    Design Features:
    - Pure Python implementation
    - Comprehensive component coordination
    - Unified monitoring interface
    - Performance optimization
    - Error handling and recovery
    - Configurable monitoring strategies
    """

    def __init__(self, config: MetricsConfig):
        """Initialize monitoring manager."""
        self.config = config
        self.performance_tracker = PerformanceTracker(
            retention_period=config.retention_period,
            max_data_points=config.max_metric_history,
            enable_anomaly_detection=config.enable_anomaly_detection,
        )
        self.prometheus_metrics = (
            PrometheusMetrics(config) if config.enable_prometheus else None
        )
        self.health_monitor = (
            HealthMonitor(config) if config.enable_health_checks else None
        )

        self._initialized = False
        self._monitoring_task: asyncio.Task | None = None
        self._shutdown = False

        logger.info("MonitoringManager initialized", config=config.to_dict())

    async def initialize(self) -> None:
        """Initialize all monitoring components."""
        if self._initialized:
            logger.warning("MonitoringManager already initialized")
            return

        try:
            # Initialize Prometheus metrics
            if self.prometheus_metrics:
                await self.prometheus_metrics.initialize()

            # Start monitoring loop
            if self.config.enable_monitoring:
                self._monitoring_task = asyncio.create_task(self._monitoring_loop())

            self._initialized = True

            logger.info("MonitoringManager initialization completed")

        except Exception as e:
            logger.exception(
                "Failed to initialize MonitoringManager",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise InfrastructureError(f"Monitoring initialization failed: {e}") from e

    async def shutdown(self) -> None:
        """Shutdown all monitoring components."""
        if self._shutdown:
            return

        self._shutdown = True

        # Cancel monitoring task
        if self._monitoring_task:
            self._monitoring_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitoring_task

        # Shutdown Prometheus
        if self.prometheus_metrics:
            await self.prometheus_metrics.shutdown()

        logger.info("MonitoringManager shutdown completed")

    def record_metric(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        metric_type: MetricType = MetricType.GAUGE,
    ) -> None:
        """Record a metric value across all monitoring systems."""
        # Record in performance tracker
        self.performance_tracker.record_metric(name, value, labels)

        # Record in Prometheus if available
        if self.prometheus_metrics:
            self._record_prometheus_metric(name, value, labels, metric_type)

    def get_comprehensive_status(self) -> dict[str, Any]:
        """Get comprehensive monitoring status."""
        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "monitoring_enabled": self.config.enable_monitoring,
            "components": {},
        }

        # Performance tracker status
        if self.performance_tracker:
            status["components"][
                "performance_tracker"
            ] = self.performance_tracker.get_performance_summary()

        # Prometheus status
        if self.prometheus_metrics:
            status["components"][
                "prometheus"
            ] = self.prometheus_metrics.get_metrics_summary()

        # Health monitor status
        if self.health_monitor:
            status["components"][
                "health_monitor"
            ] = self.health_monitor.get_overall_health()

        return status

    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        logger.info("Monitoring loop started")

        while not self._shutdown:
            try:
                await asyncio.sleep(self.config.collection_interval)

                if self._shutdown:
                    break

                # Run health checks if enabled
                if self.health_monitor:
                    await self.health_monitor.run_all_health_checks()

                # Additional monitoring tasks can be added here

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Error in monitoring loop",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                await asyncio.sleep(5)  # Brief pause before retry

    def _record_prometheus_metric(
        self, name: str, value: float, labels: dict[str, str], metric_type: MetricType
    ) -> None:
        """Record metric in Prometheus."""
        try:
            metric = self.prometheus_metrics.get_metric(f"ezzday_{name}")
            if not metric:
                return

            if metric_type == MetricType.COUNTER:
                self._record_counter_metric(metric, value, labels)
            elif metric_type == MetricType.GAUGE:
                self._record_gauge_metric(metric, value, labels)
            elif metric_type == MetricType.HISTOGRAM:
                self._record_histogram_metric(metric, value, labels)

        except Exception as e:
            logger.exception(
                "Failed to record Prometheus metric", name=name, error=str(e)
            )

    def _record_counter_metric(self, metric, value: float, labels: dict[str, str]) -> None:
        """Record counter metric value."""
        if labels:
            metric.labels(**labels).inc(value)
        else:
            metric.inc(value)

    def _record_gauge_metric(self, metric, value: float, labels: dict[str, str]) -> None:
        """Record gauge metric value."""
        if labels:
            metric.labels(**labels).set(value)
        else:
            metric.set(value)

    def _record_histogram_metric(self, metric, value: float, labels: dict[str, str]) -> None:
        """Record histogram metric value."""
        if labels:
            metric.labels(**labels).observe(value)
        else:
            metric.observe(value)


# =====================================================================================
# GLOBAL INSTANCES AND FACTORY FUNCTIONS
# =====================================================================================

# Global monitoring manager (initialized by application)
_monitoring_manager: MonitoringManager | None = None


def initialize_monitoring(config: MetricsConfig | None = None) -> None:
    """
    Initialize global monitoring system.

    Args:
        config: Monitoring configuration
    """
    global _monitoring_manager  # noqa: PLW0603 - Required to initialize global manager

    if config is None:
        try:
            from app.core.config import settings
            config = settings.metrics
        except (ImportError, AttributeError):
            config = MetricsConfig()

    _monitoring_manager = MonitoringManager(config)
    logger.info("Monitoring system initialized")


async def startup_monitoring() -> None:
    """Startup monitoring system."""
    if not _monitoring_manager:
        raise InfrastructureError(
            "Monitoring not initialized - call initialize_monitoring() first"
        )

    await _monitoring_manager.initialize()
    logger.info("Monitoring system startup completed")


async def shutdown_monitoring() -> None:
    """Shutdown monitoring system."""
    if _monitoring_manager:
        await _monitoring_manager.shutdown()

    logger.info("Monitoring system shutdown completed")


def get_monitoring_manager() -> MonitoringManager | None:
    """Get global monitoring manager."""
    return _monitoring_manager


def record_metric(
    name: str,
    value: float,
    labels: dict[str, str] | None = None,
    metric_type: MetricType = MetricType.GAUGE,
) -> None:
    """Record a metric (convenience function)."""
    if _monitoring_manager:
        _monitoring_manager.record_metric(name, value, labels, metric_type)


async def get_system_health() -> dict[str, Any]:
    """Get comprehensive system health (convenience function)."""
    if not _monitoring_manager:
        return {"error": "Monitoring not initialized"}

    return _monitoring_manager.get_comprehensive_status()


# =====================================================================================
# LEGACY METRICS (from original file) - Preserved for compatibility
# =====================================================================================

# Original Prometheus metrics are preserved below for backward compatibility
# These will be gradually migrated to use the new architecture

# --- Application info ---
app_info = Info(
    "ezzday_app",
    "Application information",
)

# --- HTTP Metrics ---
http_requests_total = Counter(
    "ezzday_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

http_request_duration_seconds = Histogram(
    "ezzday_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint", "status"],
    buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10],
)

# --- GraphQL Metrics ---
graphql_requests_total = Counter(
    "ezzday_graphql_requests_total",
    "Total GraphQL requests",
    ["operation_type", "operation_name", "status"],
)

graphql_request_duration_seconds = Histogram(
    "ezzday_graphql_request_duration_seconds",
    "GraphQL request duration in seconds",
    ["operation_type", "operation_name", "status"],
    buckets=[0.005, 0.01, 0.05, 0.1, 0.2, 0.5, 1, 2],
)

# --- Database Metrics ---
db_queries_total = Counter(
    "ezzday_db_queries_total",
    "Total database queries",
    ["query_type", "table", "status"],
)

db_query_duration_seconds = Histogram(
    "ezzday_db_query_duration_seconds",
    "Database query duration in seconds",
    ["query_type", "status"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2],
)

# --- Cache Metrics ---
cache_hits_total = Counter(
    "ezzday_cache_hits_total",
    "Total cache hits",
    ["cache_name"],
)

cache_misses_total = Counter(
    "ezzday_cache_misses_total",
    "Total cache misses",
    ["cache_name"],
)

# --- Authentication Metrics ---
authentication_success = Counter(
    "ezzday_authentication_success_total",
    "Successful authentication attempts",
    ["method", "mfa_verified"],
)

authentication_failures = Counter(
    "ezzday_authentication_failures_total",
    "Failed authentication attempts",
    ["method", "reason"],
)

# --- Event System Metrics ---
events_published = Counter(
    "ezzday_events_published_total",
    "Total events published",
    ["event_type", "bus", "priority"],
)

events_processed = Counter(
    "ezzday_events_processed_total",
    "Total events processed",
    ["event_type", "handler", "status"],
)


# --- Legacy helper functions ---
def track_time(metric: Histogram, label_fn: Callable[..., dict[str, str]]):
    """Legacy decorator for tracking execution time."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            status = "success"
            try:
                return await func(*args, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                duration = time.time() - start
                labels = label_fn(*args, **kwargs)
                labels["status"] = status
                metric.labels(**labels).observe(duration)

        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            start = time.time()
            status = "success"
            try:
                return func(*args, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                duration = time.time() - start
                labels = label_fn(*args, **kwargs)
                labels["status"] = status
                metric.labels(**labels).observe(duration)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def increment_counter(counter: Counter, labels: dict | None = None) -> None:
    """Legacy function to increment a counter metric safely."""
    if labels:
        counter.labels(**labels).inc()
    else:
        counter.inc()


# =====================================================================================
# MISSING METRICS FOR EVENT TRACKING
# =====================================================================================

# Add missing metrics that are used in other modules
events_tracked = Counter(
    "ezzday_events_tracked_total",
    "Total events tracked by the event tracking system",
    ["event_type"],
)

auth_attempts = Counter(
    "ezzday_auth_attempts_total",
    "Total authentication attempts",
    ["scheme", "status"],
)


# =====================================================================================
# METRICS NAMESPACE FOR BACKWARD COMPATIBILITY
# =====================================================================================


class MetricsNamespace:
    """Namespace for accessing metrics in a convenient way."""

    # Event metrics
    events_tracked = events_tracked
    events_published = events_published
    events_processed = events_processed

    # Auth metrics
    auth_attempts = auth_attempts
    authentication_success = authentication_success
    authentication_failures = authentication_failures

    # HTTP metrics
    http_requests_total = http_requests_total
    http_request_duration_seconds = http_request_duration_seconds

    # Database metrics
    db_queries_total = db_queries_total


# Global metrics instance for backward compatibility
metrics = MetricsNamespace()


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "HealthCheckResult",
    "HealthMonitor",
    # Data classes
    "MetricDataPoint",
    "MonitoringManager",
    # Core classes
    "PerformanceTracker",
    "PrometheusMetrics",
    "StatisticalSummary",
    "auth_attempts",
    "authentication_success",
    "db_queries_total",
    "events_published",
    "events_tracked",
    # Convenience functions
    "get_monitoring_manager",
    "get_system_health",
    "http_request_duration_seconds",
    # Legacy metrics (for compatibility)
    "http_requests_total",
    "increment_counter",
    # Factory functions
    "initialize_monitoring",
    # Metrics namespace
    "metrics",
    "record_metric",
    "shutdown_monitoring",
    "startup_monitoring",
    "track_time",
]
