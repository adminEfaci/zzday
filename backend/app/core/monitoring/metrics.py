"""
Performance Monitoring and Metrics Collection

Comprehensive metrics collection system for infrastructure monitoring
including database performance, cache hits, API response times, and resource utilization.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import asyncio
import json
from pathlib import Path
import threading
import psutil
import logging

from app.core.logging import get_logger

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricPoint:
    """Individual metric data point."""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.GAUGE


@dataclass
class MetricSummary:
    """Summary statistics for a metric."""
    name: str
    count: int
    sum: float
    min: float
    max: float
    avg: float
    p50: float
    p95: float
    p99: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Centralized metrics collection and storage."""
    
    def __init__(self, max_points: int = 10000):
        self.metrics: Dict[str, List[MetricPoint]] = {}
        self.max_points = max_points
        self._lock = threading.Lock()
        self._running = False
        self._collection_task = None
        
    def start(self):
        """Start background metrics collection."""
        if self._running:
            return
            
        self._running = True
        self._collection_task = asyncio.create_task(self._collect_system_metrics())
        logger.info("Metrics collection started")
        
    async def stop(self):
        """Stop background metrics collection."""
        if not self._running:
            return
            
        self._running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Metrics collection stopped")
    
    def record(self, name: str, value: float, labels: Optional[Dict[str, str]] = None, 
               metric_type: MetricType = MetricType.GAUGE):
        """Record a metric point."""
        point = MetricPoint(
            name=name,
            value=value,
            timestamp=datetime.now(),
            labels=labels or {},
            metric_type=metric_type
        )
        
        with self._lock:
            if name not in self.metrics:
                self.metrics[name] = []
            
            self.metrics[name].append(point)
            
            # Trim old points if necessary
            if len(self.metrics[name]) > self.max_points:
                self.metrics[name] = self.metrics[name][-self.max_points:]
    
    def increment(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        self.record(name, value, labels, MetricType.COUNTER)
    
    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric."""
        self.record(name, value, labels, MetricType.GAUGE)
    
    def histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram metric."""
        self.record(name, value, labels, MetricType.HISTOGRAM)
    
    def timer(self, name: str, duration: float, labels: Optional[Dict[str, str]] = None):
        """Record a timer metric."""
        self.record(name, duration, labels, MetricType.TIMER)
    
    def get_metrics(self, name: str, since: Optional[datetime] = None) -> List[MetricPoint]:
        """Get metrics for a specific name."""
        with self._lock:
            points = self.metrics.get(name, [])
            
            if since:
                points = [p for p in points if p.timestamp >= since]
            
            return points.copy()
    
    def get_all_metrics(self) -> Dict[str, List[MetricPoint]]:
        """Get all metrics."""
        with self._lock:
            return {name: points.copy() for name, points in self.metrics.items()}
    
    def get_summary(self, name: str, since: Optional[datetime] = None) -> Optional[MetricSummary]:
        """Get summary statistics for a metric."""
        points = self.get_metrics(name, since)
        
        if not points:
            return None
        
        values = [p.value for p in points]
        values.sort()
        
        count = len(values)
        sum_val = sum(values)
        min_val = min(values)
        max_val = max(values)
        avg_val = sum_val / count
        
        # Calculate percentiles
        p50_idx = int(count * 0.5)
        p95_idx = int(count * 0.95)
        p99_idx = int(count * 0.99)
        
        p50 = values[p50_idx] if p50_idx < count else values[-1]
        p95 = values[p95_idx] if p95_idx < count else values[-1]
        p99 = values[p99_idx] if p99_idx < count else values[-1]
        
        return MetricSummary(
            name=name,
            count=count,
            sum=sum_val,
            min=min_val,
            max=max_val,
            avg=avg_val,
            p50=p50,
            p95=p95,
            p99=p99
        )
    
    async def _collect_system_metrics(self):
        """Collect system metrics periodically."""
        while self._running:
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                self.gauge("system.cpu.usage", cpu_percent, {"unit": "percent"})
                
                # Memory metrics
                memory = psutil.virtual_memory()
                self.gauge("system.memory.usage", memory.percent, {"unit": "percent"})
                self.gauge("system.memory.available", memory.available, {"unit": "bytes"})
                self.gauge("system.memory.total", memory.total, {"unit": "bytes"})
                
                # Disk metrics
                disk = psutil.disk_usage('/')
                self.gauge("system.disk.usage", disk.percent, {"unit": "percent"})
                self.gauge("system.disk.free", disk.free, {"unit": "bytes"})
                self.gauge("system.disk.total", disk.total, {"unit": "bytes"})
                
                # Network metrics
                net_io = psutil.net_io_counters()
                self.gauge("system.network.bytes_sent", net_io.bytes_sent, {"unit": "bytes"})
                self.gauge("system.network.bytes_recv", net_io.bytes_recv, {"unit": "bytes"})
                
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(10)


class DatabaseMetrics:
    """Database-specific metrics collection."""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        
    def record_query_time(self, query_type: str, duration: float, table: str = None):
        """Record database query execution time."""
        labels = {"query_type": query_type}
        if table:
            labels["table"] = table
            
        self.collector.timer("database.query.duration", duration, labels)
        self.collector.increment("database.query.count", 1, labels)
    
    def record_connection_count(self, active: int, idle: int, total: int):
        """Record database connection pool metrics."""
        self.collector.gauge("database.connections.active", active)
        self.collector.gauge("database.connections.idle", idle)
        self.collector.gauge("database.connections.total", total)
    
    def record_slow_query(self, query: str, duration: float, table: str = None):
        """Record slow query for analysis."""
        labels = {"query_hash": str(hash(query))}
        if table:
            labels["table"] = table
            
        self.collector.timer("database.slow_query.duration", duration, labels)
        self.collector.increment("database.slow_query.count", 1, labels)
    
    def record_deadlock(self, table: str = None):
        """Record database deadlock occurrence."""
        labels = {}
        if table:
            labels["table"] = table
            
        self.collector.increment("database.deadlock.count", 1, labels)
    
    def record_cache_hit(self, hit: bool, cache_type: str = "query"):
        """Record cache hit/miss."""
        labels = {"cache_type": cache_type, "result": "hit" if hit else "miss"}
        self.collector.increment("database.cache.requests", 1, labels)


class APIMetrics:
    """API-specific metrics collection."""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record API request metrics."""
        labels = {
            "method": method,
            "endpoint": endpoint,
            "status_code": str(status_code)
        }
        
        self.collector.timer("api.request.duration", duration, labels)
        self.collector.increment("api.request.count", 1, labels)
        
        # Record error rates
        if status_code >= 400:
            self.collector.increment("api.request.errors", 1, labels)
    
    def record_rate_limit(self, endpoint: str, limit_type: str):
        """Record rate limit hit."""
        labels = {"endpoint": endpoint, "limit_type": limit_type}
        self.collector.increment("api.rate_limit.hits", 1, labels)
    
    def record_authentication_failure(self, reason: str):
        """Record authentication failure."""
        labels = {"reason": reason}
        self.collector.increment("api.auth.failures", 1, labels)


class InfrastructureMetrics:
    """Infrastructure-specific metrics collection."""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        
    def record_cache_operation(self, operation: str, hit: bool, cache_type: str = "redis"):
        """Record cache operation metrics."""
        labels = {
            "operation": operation,
            "cache_type": cache_type,
            "result": "hit" if hit else "miss"
        }
        
        self.collector.increment("infrastructure.cache.operations", 1, labels)
    
    def record_circuit_breaker(self, service: str, state: str):
        """Record circuit breaker state changes."""
        labels = {"service": service, "state": state}
        self.collector.increment("infrastructure.circuit_breaker.state_changes", 1, labels)
    
    def record_retry_attempt(self, service: str, attempt: int, success: bool):
        """Record retry attempt."""
        labels = {
            "service": service,
            "attempt": str(attempt),
            "success": str(success)
        }
        
        self.collector.increment("infrastructure.retry.attempts", 1, labels)
    
    def record_background_task(self, task_name: str, duration: float, success: bool):
        """Record background task execution."""
        labels = {
            "task_name": task_name,
            "success": str(success)
        }
        
        self.collector.timer("infrastructure.background_task.duration", duration, labels)
        self.collector.increment("infrastructure.background_task.count", 1, labels)


class PerformanceMonitor:
    """Context manager for performance monitoring."""
    
    def __init__(self, collector: MetricsCollector, metric_name: str, labels: Optional[Dict[str, str]] = None):
        self.collector = collector
        self.metric_name = metric_name
        self.labels = labels or {}
        self.start_time = None
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.collector.timer(self.metric_name, duration, self.labels)
            
            # Record success/failure
            success_labels = self.labels.copy()
            success_labels["success"] = str(exc_type is None)
            self.collector.increment(f"{self.metric_name}.count", 1, success_labels)


class MetricsExporter:
    """Export metrics to various formats."""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        for name, points in self.collector.get_all_metrics().items():
            if not points:
                continue
                
            latest_point = points[-1]
            
            # Convert metric name to Prometheus format
            prom_name = name.replace(".", "_")
            
            # Add help text
            lines.append(f"# HELP {prom_name} {name} metric")
            lines.append(f"# TYPE {prom_name} gauge")
            
            # Add metric with labels
            label_str = ""
            if latest_point.labels:
                label_parts = [f'{k}="{v}"' for k, v in latest_point.labels.items()]
                label_str = "{" + ",".join(label_parts) + "}"
            
            lines.append(f"{prom_name}{label_str} {latest_point.value}")
        
        return "\n".join(lines)
    
    def export_json(self, since: Optional[datetime] = None) -> str:
        """Export metrics as JSON."""
        data = {}
        
        for name, points in self.collector.get_all_metrics().items():
            if since:
                points = [p for p in points if p.timestamp >= since]
            
            if not points:
                continue
                
            data[name] = {
                "points": [
                    {
                        "value": p.value,
                        "timestamp": p.timestamp.isoformat(),
                        "labels": p.labels
                    }
                    for p in points
                ],
                "summary": self._get_summary_dict(name, since)
            }
        
        return json.dumps(data, indent=2)
    
    def _get_summary_dict(self, name: str, since: Optional[datetime] = None) -> Dict[str, Any]:
        """Get summary as dictionary."""
        summary = self.collector.get_summary(name, since)
        if not summary:
            return {}
            
        return {
            "count": summary.count,
            "sum": summary.sum,
            "min": summary.min,
            "max": summary.max,
            "avg": summary.avg,
            "p50": summary.p50,
            "p95": summary.p95,
            "p99": summary.p99
        }


# Global metrics collector instance
metrics_collector = MetricsCollector()
database_metrics = DatabaseMetrics(metrics_collector)
api_metrics = APIMetrics(metrics_collector)
infrastructure_metrics = InfrastructureMetrics(metrics_collector)
metrics_exporter = MetricsExporter(metrics_collector)


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector."""
    return metrics_collector


def get_database_metrics() -> DatabaseMetrics:
    """Get database metrics instance."""
    return database_metrics


def get_api_metrics() -> APIMetrics:
    """Get API metrics instance."""
    return api_metrics


def get_infrastructure_metrics() -> InfrastructureMetrics:
    """Get infrastructure metrics instance."""
    return infrastructure_metrics


def get_metrics_exporter() -> MetricsExporter:
    """Get metrics exporter instance."""
    return metrics_exporter


def monitor_performance(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator for performance monitoring."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with PerformanceMonitor(metrics_collector, metric_name, labels):
                return func(*args, **kwargs)
        return wrapper
    return decorator


__all__ = [
    "MetricsCollector",
    "DatabaseMetrics", 
    "APIMetrics",
    "InfrastructureMetrics",
    "PerformanceMonitor",
    "MetricsExporter",
    "get_metrics_collector",
    "get_database_metrics",
    "get_api_metrics", 
    "get_infrastructure_metrics",
    "get_metrics_exporter",
    "monitor_performance"
]