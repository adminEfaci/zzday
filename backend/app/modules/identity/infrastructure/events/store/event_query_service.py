"""
Event query service for complex event searching and filtering.

Provides advanced querying capabilities with performance optimizations,
caching, and support for complex filtering logic.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from .event_store import EventStore
from .schemas import EventFilter, EventRecord, EventSearchCriteria, EventSearchResult


@dataclass
class QueryPerformanceMetrics:
    """Performance metrics for event queries."""
    
    query_duration_ms: float
    result_count: int
    total_matched: int
    cache_hit: bool = False
    index_usage: list[str] | None = None
    optimization_suggestions: list[str] | None = None


class EventQueryService:
    """
    Advanced event querying service with optimization and caching.
    
    Provides sophisticated querying capabilities including:
    - Complex filtering with multiple conditions
    - Performance optimization and caching
    - Query result pagination and streaming
    - Full-text search in event data
    - Temporal queries and time-series analysis
    - Aggregate-based queries
    - Performance monitoring and optimization suggestions
    """
    
    def __init__(self, event_store: EventStore, enable_caching: bool = True):
        self.event_store = event_store
        self.enable_caching = enable_caching
        self._query_cache: dict[str, Any] = {}
        self._cache_ttl_seconds = 300  # 5 minutes
        self._performance_stats: dict[str, Any] = {}
    
    async def query_events(
        self,
        criteria: EventSearchCriteria,
        advanced_filter: EventFilter | None = None,
        enable_cache: bool = True
    ) -> tuple[EventSearchResult, QueryPerformanceMetrics]:
        """
        Execute an event query with performance tracking.
        
        Args:
            criteria: Basic search criteria
            advanced_filter: Advanced filtering options
            enable_cache: Whether to use query caching
            
        Returns:
            Tuple of (search result, performance metrics)
        """
        start_time = datetime.utcnow()
        cache_key = self._generate_cache_key(criteria, advanced_filter)
        
        # Check cache first
        if enable_cache and self.enable_caching:
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                duration = (datetime.utcnow() - start_time).total_seconds() * 1000
                metrics = QueryPerformanceMetrics(
                    query_duration_ms=duration,
                    result_count=len(cached_result.events),
                    total_matched=cached_result.total_count,
                    cache_hit=True
                )
                return cached_result, metrics
        
        # Execute query
        result = await self.event_store.search_events(criteria, advanced_filter)
        
        # Cache result
        if enable_cache and self.enable_caching:
            self._cache_result(cache_key, result)
        
        # Calculate metrics
        duration = (datetime.utcnow() - start_time).total_seconds() * 1000
        metrics = QueryPerformanceMetrics(
            query_duration_ms=duration,
            result_count=len(result.events),
            total_matched=result.total_count,
            cache_hit=False
        )
        
        # Add optimization suggestions
        metrics.optimization_suggestions = self._analyze_query_performance(
            criteria, advanced_filter, metrics
        )
        
        return result, metrics
    
    async def find_events_by_correlation(
        self, 
        correlation_id: str
    ) -> list[EventRecord]:
        """
        Find all events with the same correlation ID.
        
        Args:
            correlation_id: The correlation ID to search for
            
        Returns:
            List of correlated events
        """
        criteria = EventSearchCriteria(
            correlation_ids=[correlation_id],
            sort_by="created_at",
            sort_order="asc",
            limit=1000
        )
        
        result, _ = await self.query_events(criteria)
        return result.events
    
    async def find_events_by_causation(
        self, 
        causation_id: str
    ) -> list[EventRecord]:
        """
        Find all events caused by a specific event.
        
        Args:
            causation_id: The causation ID to search for
            
        Returns:
            List of caused events
        """
        # Use JSON path filtering for causation_id in metadata
        advanced_filter = EventFilter(
            json_path_filters={
                "metadata.causation_id": causation_id
            }
        )
        
        criteria = EventSearchCriteria(
            sort_by="created_at",
            sort_order="asc",
            limit=1000
        )
        
        result, _ = await self.query_events(criteria, advanced_filter)
        return result.events
    
    async def search_event_content(
        self, 
        search_text: str,
        event_types: list[str] | None = None,
        aggregate_types: list[str] | None = None
    ) -> list[EventRecord]:
        """
        Search for events containing specific text in their data.
        
        Args:
            search_text: Text to search for
            event_types: Optional event type filter
            aggregate_types: Optional aggregate type filter
            
        Returns:
            List of matching events
        """
        advanced_filter = EventFilter(
            text_search=search_text,
            search_fields=["event_data", "metadata"]
        )
        
        criteria = EventSearchCriteria(
            event_types=event_types,
            aggregate_types=aggregate_types,
            sort_by="created_at",
            sort_order="desc",
            limit=500
        )
        
        result, _ = await self.query_events(criteria, advanced_filter)
        return result.events
    
    async def get_aggregate_timeline(
        self, 
        aggregate_id: UUID,
        aggregate_type: str,
        from_time: datetime | None = None,
        to_time: datetime | None = None
    ) -> list[EventRecord]:
        """
        Get the complete timeline of events for an aggregate.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            from_time: Optional start time filter
            to_time: Optional end time filter
            
        Returns:
            Chronological list of events for the aggregate
        """
        criteria = EventSearchCriteria(
            aggregate_ids=[aggregate_id],
            aggregate_types=[aggregate_type],
            from_timestamp=from_time,
            to_timestamp=to_time,
            sort_by="created_at",
            sort_order="asc",
            limit=10000  # Large limit for complete timeline
        )
        
        result, _ = await self.query_events(criteria)
        return result.events
    
    async def get_event_statistics(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        group_by: str = "event_type"
    ) -> dict[str, Any]:
        """
        Get statistical information about events.
        
        Args:
            from_time: Start time for statistics
            to_time: End time for statistics
            group_by: Field to group statistics by
            
        Returns:
            Statistical information
        """
        criteria = EventSearchCriteria(
            from_timestamp=from_time,
            to_timestamp=to_time,
            limit=10000,
            include_event_data=False  # Only need metadata for stats
        )
        
        result, _ = await self.query_events(criteria, enable_cache=False)
        
        # Calculate statistics
        stats = {
            'total_events': result.total_count,
            'time_range': {
                'from': from_time.isoformat() if from_time else None,
                'to': to_time.isoformat() if to_time else None
            },
            'grouped_counts': {},
            'top_aggregates': {},
            'event_volume_over_time': []
        }
        
        # Group by specified field
        if group_by == "event_type":
            counts = {}
            for event in result.events:
                counts[event.event_type] = counts.get(event.event_type, 0) + 1
            stats['grouped_counts'] = counts
            
        elif group_by == "aggregate_type":
            counts = {}
            for event in result.events:
                counts[event.aggregate_type] = counts.get(event.aggregate_type, 0) + 1
            stats['grouped_counts'] = counts
        
        # Top aggregates by event count
        aggregate_counts = {}
        for event in result.events:
            key = f"{event.aggregate_type}:{event.aggregate_id}"
            aggregate_counts[key] = aggregate_counts.get(key, 0) + 1
        
        stats['top_aggregates'] = dict(
            sorted(aggregate_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        
        return stats
    
    async def find_pattern_events(
        self,
        pattern: dict[str, Any],
        time_window_hours: int = 24
    ) -> list[list[EventRecord]]:
        """
        Find sequences of events matching a specific pattern.
        
        Args:
            pattern: Pattern to match (simplified version)
            time_window_hours: Time window for pattern matching
            
        Returns:
            List of event sequences matching the pattern
        """
        # This is a simplified implementation
        # A full implementation would require more sophisticated pattern matching
        
        # For now, just find events with specific characteristics
        criteria = EventSearchCriteria(
            from_timestamp=datetime.utcnow() - timedelta(hours=time_window_hours),
            limit=5000
        )
        
        # Use JSON path filters to match pattern
        advanced_filter = EventFilter(
            json_path_filters=pattern
        )
        
        result, _ = await self.query_events(criteria, advanced_filter)
        
        # Group by correlation ID to find related sequences
        sequences = {}
        for event in result.events:
            correlation_id = event.metadata.correlation_id
            if correlation_id:
                if correlation_id not in sequences:
                    sequences[correlation_id] = []
                sequences[correlation_id].append(event)
        
        # Sort events within each sequence
        for seq in sequences.values():
            seq.sort(key=lambda e: e.created_at)
        
        return list(sequences.values())
    
    async def get_user_activity_timeline(
        self, 
        user_id: UUID,
        from_time: datetime | None = None,
        to_time: datetime | None = None
    ) -> list[EventRecord]:
        """
        Get all events related to a specific user's activity.
        
        Args:
            user_id: The user ID
            from_time: Optional start time
            to_time: Optional end time
            
        Returns:
            Timeline of user-related events
        """
        criteria = EventSearchCriteria(
            user_ids=[user_id],
            from_timestamp=from_time,
            to_timestamp=to_time,
            sort_by="created_at",
            sort_order="asc",
            limit=5000
        )
        
        result, _ = await self.query_events(criteria)
        return result.events
    
    async def find_anomalous_events(
        self,
        time_window_hours: int = 24,
        threshold_multiplier: float = 3.0
    ) -> list[EventRecord]:
        """
        Find events that might be anomalous based on frequency patterns.
        
        Args:
            time_window_hours: Time window to analyze
            threshold_multiplier: Multiplier for anomaly detection
            
        Returns:
            List of potentially anomalous events
        """
        from_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        criteria = EventSearchCriteria(
            from_timestamp=from_time,
            limit=10000,
            include_event_data=False
        )
        
        result, _ = await self.query_events(criteria, enable_cache=False)
        
        # Simple anomaly detection based on event type frequency
        event_type_counts = {}
        for event in result.events:
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        
        # Calculate mean and standard deviation
        counts = list(event_type_counts.values())
        if not counts:
            return []
        
        mean_count = sum(counts) / len(counts)
        std_dev = (sum((x - mean_count) ** 2 for x in counts) / len(counts)) ** 0.5
        
        # Find events with counts above threshold
        anomalous_types = set()
        threshold = mean_count + (threshold_multiplier * std_dev)
        
        for event_type, count in event_type_counts.items():
            if count > threshold:
                anomalous_types.add(event_type)
        
        # Return events of anomalous types
        return [event for event in result.events if event.event_type in anomalous_types]
    
    def invalidate_cache(self, pattern: str | None = None) -> int:
        """
        Invalidate cached query results.
        
        Args:
            pattern: Optional pattern to match cache keys
            
        Returns:
            Number of cache entries invalidated
        """
        if pattern is None:
            count = len(self._query_cache)
            self._query_cache.clear()
            return count
        
        # Remove entries matching pattern
        keys_to_remove = [
            key for key in self._query_cache 
            if pattern in key
        ]
        
        for key in keys_to_remove:
            del self._query_cache[key]
        
        return len(keys_to_remove)
    
    def get_query_performance_stats(self) -> dict[str, Any]:
        """Get query performance statistics."""
        return {
            'cache_entries': len(self._query_cache),
            'cache_hit_rate': self._performance_stats.get('cache_hit_rate', 0.0),
            'avg_query_duration_ms': self._performance_stats.get('avg_duration', 0.0),
            'total_queries': self._performance_stats.get('total_queries', 0),
            'most_common_queries': self._performance_stats.get('common_queries', []),
        }
    
    def _generate_cache_key(
        self, 
        criteria: EventSearchCriteria, 
        advanced_filter: EventFilter | None
    ) -> str:
        """Generate a cache key for the query."""
        key_data = {
            'criteria': criteria.__dict__,
            'filter': advanced_filter.__dict__ if advanced_filter else None
        }
        
        # Create a hash of the query parameters
        import hashlib
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> EventSearchResult | None:
        """Get cached result if available and not expired."""
        if cache_key in self._query_cache:
            cached_data = self._query_cache[cache_key]
            cache_time = cached_data['timestamp']
            
            # Check if cache is still valid
            if (datetime.utcnow() - cache_time).total_seconds() < self._cache_ttl_seconds:
                return cached_data['result']
            # Remove expired cache entry
            del self._query_cache[cache_key]
        
        return None
    
    def _cache_result(self, cache_key: str, result: EventSearchResult) -> None:
        """Cache a query result."""
        self._query_cache[cache_key] = {
            'result': result,
            'timestamp': datetime.utcnow()
        }
        
        # Prevent cache from growing too large
        if len(self._query_cache) > 1000:
            # Remove oldest entries
            oldest_keys = sorted(
                self._query_cache.keys(),
                key=lambda k: self._query_cache[k]['timestamp']
            )[:100]
            
            for key in oldest_keys:
                del self._query_cache[key]
    
    def _analyze_query_performance(
        self,
        criteria: EventSearchCriteria,
        advanced_filter: EventFilter | None,
        metrics: QueryPerformanceMetrics
    ) -> list[str]:
        """Analyze query performance and provide optimization suggestions."""
        suggestions = []
        
        # Check for slow queries
        if metrics.query_duration_ms > 1000:  # > 1 second
            suggestions.append("Query is slow - consider adding more specific filters")
        
        # Check for large result sets
        if metrics.result_count > 1000:
            suggestions.append("Large result set - consider using pagination")
        
        # Check for missing time filters
        if not criteria.from_timestamp and not criteria.to_timestamp:
            suggestions.append("Add time range filters to improve performance")
        
        # Check for inefficient sorting
        if criteria.sort_by not in ['created_at', 'global_position']:
            suggestions.append("Consider sorting by indexed fields like 'created_at'")
        
        return suggestions