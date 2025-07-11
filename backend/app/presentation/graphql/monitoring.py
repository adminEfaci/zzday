"""
Advanced GraphQL Monitoring and Analytics

Provides comprehensive monitoring, metrics collection, and analytics for GraphQL operations
with real-time dashboards, performance tracking, and query optimization insights.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from strawberry.extensions import Extension
from strawberry.types import ExecutionContext, ExecutionResult

logger = logging.getLogger(__name__)


class QueryStatus(Enum):
    """Query execution status."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    COMPLEXITY_REJECTED = "complexity_rejected"


@dataclass
class QueryMetrics:
    """Comprehensive query execution metrics."""
    query_id: str
    operation_name: Optional[str]
    operation_type: str
    query_text: str
    variables: Dict[str, Any]
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    
    # Timing metrics
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    
    # Execution metrics
    status: QueryStatus = QueryStatus.SUCCESS
    complexity: Optional[int] = None
    depth: Optional[int] = None
    fields_requested: int = 0
    fields_resolved: int = 0
    
    # Performance metrics
    database_queries: int = 0
    database_time_ms: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    dataloader_hits: int = 0
    dataloader_misses: int = 0
    
    # Error metrics
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Resource usage
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    request_id: Optional[str] = None
    tracing_id: Optional[str] = None
    
    def mark_complete(self, status: QueryStatus = QueryStatus.SUCCESS):
        """Mark query as complete and calculate duration."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        self.status = status


@dataclass
class AggregatedMetrics:
    """Aggregated metrics for reporting."""
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    average_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    p99_duration_ms: float = 0.0
    queries_per_second: float = 0.0
    
    # Operation type breakdown
    query_operations: int = 0
    mutation_operations: int = 0
    subscription_operations: int = 0
    
    # Error breakdown
    validation_errors: int = 0
    authorization_errors: int = 0
    complexity_errors: int = 0
    timeout_errors: int = 0
    internal_errors: int = 0
    
    # Performance metrics
    average_complexity: float = 0.0
    average_depth: float = 0.0
    cache_hit_rate: float = 0.0
    dataloader_hit_rate: float = 0.0
    
    # Top queries
    slowest_queries: List[Dict[str, Any]] = field(default_factory=list)
    most_complex_queries: List[Dict[str, Any]] = field(default_factory=list)
    most_frequent_queries: List[Dict[str, Any]] = field(default_factory=list)
    
    # Time window
    window_start: datetime = field(default_factory=datetime.utcnow)
    window_end: datetime = field(default_factory=datetime.utcnow)


class GraphQLMonitor:
    """
    Advanced GraphQL monitoring and analytics system.
    
    Tracks query execution, performance metrics, and provides real-time insights.
    """
    
    def __init__(
        self,
        max_stored_queries: int = 10000,
        metrics_window_minutes: int = 60,
        slow_query_threshold_ms: float = 1000.0,
        complex_query_threshold: int = 500,
        enable_query_sampling: bool = True,
        sampling_rate: float = 0.1
    ):
        self.max_stored_queries = max_stored_queries
        self.metrics_window_minutes = metrics_window_minutes
        self.slow_query_threshold_ms = slow_query_threshold_ms
        self.complex_query_threshold = complex_query_threshold
        self.enable_query_sampling = enable_query_sampling
        self.sampling_rate = sampling_rate
        
        # Storage for query metrics
        self.query_metrics: deque = deque(maxlen=max_stored_queries)
        self.active_queries: Dict[str, QueryMetrics] = {}
        
        # Aggregated metrics
        self.query_counts: Dict[str, int] = defaultdict(int)
        self.operation_counts: Dict[str, int] = defaultdict(int)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.user_activity: Dict[str, List[datetime]] = defaultdict(list)
        
        # Performance tracking
        self.slow_queries: deque = deque(maxlen=100)
        self.complex_queries: deque = deque(maxlen=100)
        self.recent_durations: deque = deque(maxlen=1000)
        
        # Real-time metrics
        self.current_connections: int = 0
        self.peak_connections: int = 0
        self.total_queries_processed: int = 0
        
        # Alerts and thresholds
        self.alert_handlers: List[callable] = []
        self.performance_thresholds = {
            'error_rate': 0.05,  # 5% error rate
            'avg_duration_ms': 2000,  # 2 seconds
            'p95_duration_ms': 5000,  # 5 seconds
            'queries_per_second': 1000  # 1000 QPS
        }
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the monitoring system."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_old_metrics())
        self._metrics_task = asyncio.create_task(self._calculate_metrics())
        logger.info("GraphQL monitoring started")
    
    async def stop(self):
        """Stop the monitoring system."""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._metrics_task:
            self._metrics_task.cancel()
        
        logger.info("GraphQL monitoring stopped")
    
    def start_query(
        self,
        query_id: str,
        operation_name: Optional[str],
        operation_type: str,
        query_text: str,
        variables: Dict[str, Any],
        context: Dict[str, Any]
    ) -> QueryMetrics:
        """Start tracking a new query."""
        
        # Check if we should sample this query
        if self.enable_query_sampling and not self._should_sample_query():
            return None
        
        metrics = QueryMetrics(
            query_id=query_id,
            operation_name=operation_name,
            operation_type=operation_type,
            query_text=query_text,
            variables=variables,
            user_id=context.get('user', {}).get('id'),
            ip_address=context.get('ip_address'),
            user_agent=context.get('user_agent'),
            start_time=time.time(),
            request_id=context.get('request_id'),
            tracing_id=context.get('tracing_id')
        )
        
        self.active_queries[query_id] = metrics
        self.total_queries_processed += 1
        
        # Track user activity
        if metrics.user_id:
            self.user_activity[metrics.user_id].append(datetime.utcnow())
        
        return metrics
    
    def finish_query(
        self,
        query_id: str,
        result: ExecutionResult,
        status: QueryStatus = QueryStatus.SUCCESS,
        complexity: Optional[int] = None,
        depth: Optional[int] = None
    ):
        """Finish tracking a query."""
        metrics = self.active_queries.pop(query_id, None)
        if not metrics:
            return
        
        metrics.mark_complete(status)
        metrics.complexity = complexity
        metrics.depth = depth
        
        # Process errors
        if result.errors:
            metrics.errors = [
                {
                    'message': str(error),
                    'locations': getattr(error, 'locations', None),
                    'path': getattr(error, 'path', None),
                    'extensions': getattr(error, 'extensions', None)
                }
                for error in result.errors
            ]
        
        # Store completed metrics
        self.query_metrics.append(metrics)
        
        # Update aggregated metrics
        self._update_aggregated_metrics(metrics)
        
        # Check for alerts
        self._check_alerts(metrics)
    
    def record_database_query(self, query_id: str, duration_ms: float):
        """Record a database query for a GraphQL operation."""
        if query_id in self.active_queries:
            metrics = self.active_queries[query_id]
            metrics.database_queries += 1
            metrics.database_time_ms += duration_ms
    
    def record_cache_hit(self, query_id: str):
        """Record a cache hit."""
        if query_id in self.active_queries:
            self.active_queries[query_id].cache_hits += 1
    
    def record_cache_miss(self, query_id: str):
        """Record a cache miss."""
        if query_id in self.active_queries:
            self.active_queries[query_id].cache_misses += 1
    
    def record_dataloader_hit(self, query_id: str):
        """Record a dataloader hit."""
        if query_id in self.active_queries:
            self.active_queries[query_id].dataloader_hits += 1
    
    def record_dataloader_miss(self, query_id: str):
        """Record a dataloader miss."""
        if query_id in self.active_queries:
            self.active_queries[query_id].dataloader_misses += 1
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for dashboard."""
        now = datetime.utcnow()
        recent_queries = [
            m for m in self.query_metrics 
            if now - m.created_at <= timedelta(minutes=5)
        ]
        
        if not recent_queries:
            return self._empty_metrics()
        
        # Calculate metrics
        total_queries = len(recent_queries)
        successful_queries = sum(1 for m in recent_queries if m.status == QueryStatus.SUCCESS)
        failed_queries = total_queries - successful_queries
        
        durations = [m.duration_ms for m in recent_queries if m.duration_ms]
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        # Calculate percentiles
        sorted_durations = sorted(durations)
        p95_duration = sorted_durations[int(len(sorted_durations) * 0.95)] if sorted_durations else 0
        p99_duration = sorted_durations[int(len(sorted_durations) * 0.99)] if sorted_durations else 0
        
        return {
            'timestamp': now.isoformat(),
            'total_queries': total_queries,
            'successful_queries': successful_queries,
            'failed_queries': failed_queries,
            'success_rate': successful_queries / total_queries if total_queries > 0 else 0,
            'queries_per_second': total_queries / 300,  # 5 minutes
            'average_duration_ms': avg_duration,
            'p95_duration_ms': p95_duration,
            'p99_duration_ms': p99_duration,
            'active_queries': len(self.active_queries),
            'current_connections': self.current_connections,
            'peak_connections': self.peak_connections,
            'total_processed': self.total_queries_processed,
            'slow_queries_count': len([m for m in recent_queries if m.duration_ms and m.duration_ms > self.slow_query_threshold_ms]),
            'complex_queries_count': len([m for m in recent_queries if m.complexity and m.complexity > self.complex_query_threshold]),
            'cache_hit_rate': self._calculate_cache_hit_rate(recent_queries),
            'dataloader_hit_rate': self._calculate_dataloader_hit_rate(recent_queries),
            'operation_breakdown': self._get_operation_breakdown(recent_queries),
            'error_breakdown': self._get_error_breakdown(recent_queries),
            'top_users': self._get_top_users(recent_queries),
            'resource_usage': self._get_resource_usage()
        }
    
    def get_aggregated_metrics(self, window_minutes: int = 60) -> AggregatedMetrics:
        """Get aggregated metrics for a time window."""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)
        
        relevant_queries = [
            m for m in self.query_metrics 
            if window_start <= m.created_at <= now
        ]
        
        if not relevant_queries:
            return AggregatedMetrics(window_start=window_start, window_end=now)
        
        # Calculate aggregated metrics
        total_queries = len(relevant_queries)
        successful_queries = sum(1 for m in relevant_queries if m.status == QueryStatus.SUCCESS)
        failed_queries = total_queries - successful_queries
        
        durations = [m.duration_ms for m in relevant_queries if m.duration_ms]
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        sorted_durations = sorted(durations)
        p95_duration = sorted_durations[int(len(sorted_durations) * 0.95)] if sorted_durations else 0
        p99_duration = sorted_durations[int(len(sorted_durations) * 0.99)] if sorted_durations else 0
        
        return AggregatedMetrics(
            total_queries=total_queries,
            successful_queries=successful_queries,
            failed_queries=failed_queries,
            average_duration_ms=avg_duration,
            p95_duration_ms=p95_duration,
            p99_duration_ms=p99_duration,
            queries_per_second=total_queries / (window_minutes * 60),
            query_operations=sum(1 for m in relevant_queries if m.operation_type == 'query'),
            mutation_operations=sum(1 for m in relevant_queries if m.operation_type == 'mutation'),
            subscription_operations=sum(1 for m in relevant_queries if m.operation_type == 'subscription'),
            cache_hit_rate=self._calculate_cache_hit_rate(relevant_queries),
            dataloader_hit_rate=self._calculate_dataloader_hit_rate(relevant_queries),
            slowest_queries=self._get_slowest_queries(relevant_queries),
            most_complex_queries=self._get_most_complex_queries(relevant_queries),
            most_frequent_queries=self._get_most_frequent_queries(relevant_queries),
            window_start=window_start,
            window_end=now
        )
    
    def get_query_analysis(self, query_text: str) -> Dict[str, Any]:
        """Analyze a specific query pattern."""
        matching_queries = [
            m for m in self.query_metrics 
            if m.query_text == query_text
        ]
        
        if not matching_queries:
            return {'error': 'No matching queries found'}
        
        durations = [m.duration_ms for m in matching_queries if m.duration_ms]
        complexities = [m.complexity for m in matching_queries if m.complexity]
        
        return {
            'query_text': query_text,
            'execution_count': len(matching_queries),
            'success_rate': sum(1 for m in matching_queries if m.status == QueryStatus.SUCCESS) / len(matching_queries),
            'average_duration_ms': sum(durations) / len(durations) if durations else 0,
            'min_duration_ms': min(durations) if durations else 0,
            'max_duration_ms': max(durations) if durations else 0,
            'average_complexity': sum(complexities) / len(complexities) if complexities else 0,
            'database_queries_avg': sum(m.database_queries for m in matching_queries) / len(matching_queries),
            'cache_hit_rate': self._calculate_cache_hit_rate(matching_queries),
            'most_recent_execution': max(m.created_at for m in matching_queries).isoformat(),
            'common_errors': self._get_common_errors(matching_queries),
            'performance_trend': self._get_performance_trend(matching_queries)
        }
    
    def add_alert_handler(self, handler: callable):
        """Add an alert handler function."""
        self.alert_handlers.append(handler)
    
    def _should_sample_query(self) -> bool:
        """Determine if query should be sampled."""
        import random
        return random.random() < self.sampling_rate
    
    def _update_aggregated_metrics(self, metrics: QueryMetrics):
        """Update aggregated metrics."""
        self.query_counts[metrics.query_text] += 1
        self.operation_counts[metrics.operation_type] += 1
        
        if metrics.errors:
            for error in metrics.errors:
                error_type = error.get('extensions', {}).get('code', 'unknown')
                self.error_counts[error_type] += 1
        
        if metrics.duration_ms:
            self.recent_durations.append(metrics.duration_ms)
            
            if metrics.duration_ms > self.slow_query_threshold_ms:
                self.slow_queries.append({
                    'query': metrics.query_text,
                    'duration_ms': metrics.duration_ms,
                    'operation_name': metrics.operation_name,
                    'timestamp': metrics.created_at
                })
        
        if metrics.complexity and metrics.complexity > self.complex_query_threshold:
            self.complex_queries.append({
                'query': metrics.query_text,
                'complexity': metrics.complexity,
                'operation_name': metrics.operation_name,
                'timestamp': metrics.created_at
            })
    
    def _check_alerts(self, metrics: QueryMetrics):
        """Check if any alerts should be triggered."""
        alerts = []
        
        # Slow query alert
        if metrics.duration_ms and metrics.duration_ms > self.slow_query_threshold_ms * 2:
            alerts.append({
                'type': 'slow_query',
                'severity': 'warning',
                'message': f'Very slow query detected: {metrics.duration_ms:.2f}ms',
                'query': metrics.query_text,
                'operation_name': metrics.operation_name,
                'user_id': metrics.user_id
            })
        
        # High complexity alert
        if metrics.complexity and metrics.complexity > self.complex_query_threshold * 2:
            alerts.append({
                'type': 'complex_query',
                'severity': 'warning',
                'message': f'Very complex query detected: {metrics.complexity}',
                'query': metrics.query_text,
                'operation_name': metrics.operation_name,
                'user_id': metrics.user_id
            })
        
        # Error alert
        if metrics.errors:
            alerts.append({
                'type': 'query_error',
                'severity': 'error',
                'message': f'Query failed with {len(metrics.errors)} errors',
                'query': metrics.query_text,
                'operation_name': metrics.operation_name,
                'user_id': metrics.user_id,
                'errors': metrics.errors
            })
        
        # Send alerts
        for alert in alerts:
            self._send_alert(alert)
    
    def _send_alert(self, alert: Dict[str, Any]):
        """Send alert to all registered handlers."""
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error sending alert: {e}")
    
    def _calculate_cache_hit_rate(self, queries: List[QueryMetrics]) -> float:
        """Calculate cache hit rate."""
        total_hits = sum(m.cache_hits for m in queries)
        total_misses = sum(m.cache_misses for m in queries)
        total_requests = total_hits + total_misses
        
        return total_hits / total_requests if total_requests > 0 else 0
    
    def _calculate_dataloader_hit_rate(self, queries: List[QueryMetrics]) -> float:
        """Calculate dataloader hit rate."""
        total_hits = sum(m.dataloader_hits for m in queries)
        total_misses = sum(m.dataloader_misses for m in queries)
        total_requests = total_hits + total_misses
        
        return total_hits / total_requests if total_requests > 0 else 0
    
    def _get_operation_breakdown(self, queries: List[QueryMetrics]) -> Dict[str, int]:
        """Get operation type breakdown."""
        breakdown = defaultdict(int)
        for query in queries:
            breakdown[query.operation_type] += 1
        return dict(breakdown)
    
    def _get_error_breakdown(self, queries: List[QueryMetrics]) -> Dict[str, int]:
        """Get error type breakdown."""
        breakdown = defaultdict(int)
        for query in queries:
            for error in query.errors:
                error_type = error.get('extensions', {}).get('code', 'unknown')
                breakdown[error_type] += 1
        return dict(breakdown)
    
    def _get_top_users(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get top users by query count."""
        user_counts = defaultdict(int)
        for query in queries:
            if query.user_id:
                user_counts[query.user_id] += 1
        
        return [
            {'user_id': user_id, 'query_count': count}
            for user_id, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage."""
        # This would integrate with system monitoring
        return {
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0,
            'active_connections': len(self.active_queries),
            'query_queue_size': 0
        }
    
    def _get_slowest_queries(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get slowest queries."""
        sorted_queries = sorted(
            [q for q in queries if q.duration_ms],
            key=lambda q: q.duration_ms,
            reverse=True
        )
        
        return [
            {
                'query': q.query_text,
                'duration_ms': q.duration_ms,
                'operation_name': q.operation_name,
                'complexity': q.complexity,
                'timestamp': q.created_at.isoformat()
            }
            for q in sorted_queries[:10]
        ]
    
    def _get_most_complex_queries(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get most complex queries."""
        sorted_queries = sorted(
            [q for q in queries if q.complexity],
            key=lambda q: q.complexity,
            reverse=True
        )
        
        return [
            {
                'query': q.query_text,
                'complexity': q.complexity,
                'duration_ms': q.duration_ms,
                'operation_name': q.operation_name,
                'timestamp': q.created_at.isoformat()
            }
            for q in sorted_queries[:10]
        ]
    
    def _get_most_frequent_queries(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get most frequent queries."""
        query_counts = defaultdict(int)
        for query in queries:
            query_counts[query.query_text] += 1
        
        return [
            {'query': query_text, 'count': count}
            for query_text, count in sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _get_common_errors(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get common errors for a query."""
        error_counts = defaultdict(int)
        for query in queries:
            for error in query.errors:
                error_message = error.get('message', 'Unknown error')
                error_counts[error_message] += 1
        
        return [
            {'error': error_msg, 'count': count}
            for error_msg, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
    
    def _get_performance_trend(self, queries: List[QueryMetrics]) -> List[Dict[str, Any]]:
        """Get performance trend for a query."""
        # Sort by timestamp and group by hour
        sorted_queries = sorted(queries, key=lambda q: q.created_at)
        
        trend_data = []
        current_hour = None
        hour_durations = []
        
        for query in sorted_queries:
            hour = query.created_at.replace(minute=0, second=0, microsecond=0)
            
            if current_hour is None:
                current_hour = hour
            
            if hour != current_hour:
                if hour_durations:
                    trend_data.append({
                        'timestamp': current_hour.isoformat(),
                        'avg_duration_ms': sum(hour_durations) / len(hour_durations),
                        'query_count': len(hour_durations)
                    })
                current_hour = hour
                hour_durations = []
            
            if query.duration_ms:
                hour_durations.append(query.duration_ms)
        
        # Add last hour
        if hour_durations:
            trend_data.append({
                'timestamp': current_hour.isoformat(),
                'avg_duration_ms': sum(hour_durations) / len(hour_durations),
                'query_count': len(hour_durations)
            })
        
        return trend_data
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics structure."""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'success_rate': 0,
            'queries_per_second': 0,
            'average_duration_ms': 0,
            'p95_duration_ms': 0,
            'p99_duration_ms': 0,
            'active_queries': 0,
            'current_connections': 0,
            'peak_connections': 0,
            'total_processed': 0,
            'slow_queries_count': 0,
            'complex_queries_count': 0,
            'cache_hit_rate': 0,
            'dataloader_hit_rate': 0,
            'operation_breakdown': {},
            'error_breakdown': {},
            'top_users': [],
            'resource_usage': {}
        }
    
    async def _cleanup_old_metrics(self):
        """Clean up old metrics periodically."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
                # Remove old user activity
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                for user_id, activities in self.user_activity.items():
                    self.user_activity[user_id] = [
                        activity for activity in activities 
                        if activity > cutoff_time
                    ]
                
                # Remove empty user activity lists
                self.user_activity = {
                    user_id: activities 
                    for user_id, activities in self.user_activity.items()
                    if activities
                }
                
                logger.debug("Cleaned up old metrics")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics cleanup: {e}")
    
    async def _calculate_metrics(self):
        """Calculate and update metrics periodically."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Calculate every minute
                
                # Update peak connections
                self.peak_connections = max(self.peak_connections, self.current_connections)
                
                # Check performance thresholds
                recent_metrics = self.get_real_time_metrics()
                
                # Check error rate
                if recent_metrics['total_queries'] > 0:
                    error_rate = recent_metrics['failed_queries'] / recent_metrics['total_queries']
                    if error_rate > self.performance_thresholds['error_rate']:
                        self._send_alert({
                            'type': 'high_error_rate',
                            'severity': 'critical',
                            'message': f'High error rate detected: {error_rate:.2%}',
                            'current_value': error_rate,
                            'threshold': self.performance_thresholds['error_rate']
                        })
                
                # Check average duration
                if recent_metrics['average_duration_ms'] > self.performance_thresholds['avg_duration_ms']:
                    self._send_alert({
                        'type': 'high_avg_duration',
                        'severity': 'warning',
                        'message': f'High average duration: {recent_metrics["average_duration_ms"]:.2f}ms',
                        'current_value': recent_metrics['average_duration_ms'],
                        'threshold': self.performance_thresholds['avg_duration_ms']
                    })
                
                logger.debug("Calculated periodic metrics")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics calculation: {e}")


class GraphQLMonitoringExtension(Extension):
    """Strawberry extension for GraphQL monitoring."""
    
    def __init__(self, monitor: GraphQLMonitor):
        self.monitor = monitor
        self.query_id = None
        self.query_metrics = None
    
    def on_request_start(self):
        """Start monitoring a request."""
        self.query_id = str(uuid4())
        
        # Extract query information
        operation_name = getattr(self.execution_context, 'operation_name', None)
        operation_type = 'query'  # Default
        
        if hasattr(self.execution_context, 'operation_type'):
            operation_type = self.execution_context.operation_type
        
        query_text = getattr(self.execution_context, 'query', '')
        variables = getattr(self.execution_context, 'variable_values', {}) or {}
        context = getattr(self.execution_context, 'context', {})
        
        self.query_metrics = self.monitor.start_query(
            query_id=self.query_id,
            operation_name=operation_name,
            operation_type=operation_type,
            query_text=query_text,
            variables=variables,
            context=context
        )
    
    def on_request_end(self, result: ExecutionResult):
        """Finish monitoring a request."""
        if not self.query_metrics:
            return
        
        # Determine status
        status = QueryStatus.SUCCESS
        if result.errors:
            status = QueryStatus.ERROR
        
        # Get complexity and depth from result extensions
        complexity = None
        depth = None
        
        if result.extensions:
            performance = result.extensions.get('performance', {})
            complexity = performance.get('complexity')
            depth = performance.get('depth')
        
        self.monitor.finish_query(
            query_id=self.query_id,
            result=result,
            status=status,
            complexity=complexity,
            depth=depth
        )


# Global monitoring instance
graphql_monitor = GraphQLMonitor()


# Context manager for tracking database operations
@asynccontextmanager
async def track_database_operation(query_id: str):
    """Context manager to track database operations."""
    start_time = time.time()
    try:
        yield
    finally:
        duration_ms = (time.time() - start_time) * 1000
        graphql_monitor.record_database_query(query_id, duration_ms)


# Utility functions for integration
def get_current_query_id() -> Optional[str]:
    """Get the current query ID from context."""
    # This would be implemented to extract from request context
    return None


def record_cache_operation(hit: bool):
    """Record a cache operation."""
    query_id = get_current_query_id()
    if query_id:
        if hit:
            graphql_monitor.record_cache_hit(query_id)
        else:
            graphql_monitor.record_cache_miss(query_id)


def record_dataloader_operation(hit: bool):
    """Record a dataloader operation."""
    query_id = get_current_query_id()
    if query_id:
        if hit:
            graphql_monitor.record_dataloader_hit(query_id)
        else:
            graphql_monitor.record_dataloader_miss(query_id)


__all__ = [
    'GraphQLMonitor',
    'GraphQLMonitoringExtension',
    'QueryMetrics',
    'QueryStatus',
    'AggregatedMetrics',
    'graphql_monitor',
    'track_database_operation',
    'record_cache_operation',
    'record_dataloader_operation',
]