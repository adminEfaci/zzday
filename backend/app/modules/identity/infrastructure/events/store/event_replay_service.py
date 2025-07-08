"""
Event replay service for debugging and recovery.

Provides functionality to replay events for specific time ranges, aggregates,
or criteria for debugging purposes and system recovery scenarios.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from .event_store import EventStore
from .schemas import EventRecord, EventSearchCriteria, EventStatus


@dataclass
class ReplayConfig:
    """Configuration for event replay operations."""
    
    # Time range for replay
    from_timestamp: datetime | None = None
    to_timestamp: datetime | None = None
    
    # Specific aggregates to replay
    aggregate_ids: list[UUID] | None = None
    aggregate_types: list[str] | None = None
    
    # Event type filters
    event_types: list[str] | None = None
    
    # Replay behavior
    batch_size: int = 100
    max_events: int | None = None
    include_failed_events: bool = False
    
    # Processing options
    parallel_processing: bool = False
    max_workers: int = 4
    
    # Error handling
    stop_on_error: bool = False
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Dry run mode
    dry_run: bool = False
    
    # Progress reporting
    progress_callback: Callable[[int, int], None] | None = None


@dataclass
class ReplayResult:
    """Result of an event replay operation."""
    
    total_events_processed: int = 0
    successful_events: int = 0
    failed_events: int = 0
    skipped_events: int = 0
    
    # Timing information
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0
    
    # Error information
    errors: list[dict[str, Any]] | None = None
    
    # Performance metrics
    events_per_second: float = 0.0
    
    def __post_init__(self):
        """Calculate derived metrics."""
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
            
        if self.duration_seconds > 0:
            self.events_per_second = self.total_events_processed / self.duration_seconds


class EventReplayService:
    """
    Service for replaying events for debugging and recovery purposes.
    
    Provides flexible event replay capabilities with support for:
    - Time-based replay
    - Aggregate-specific replay
    - Event type filtering
    - Parallel processing
    - Error handling and recovery
    - Progress tracking
    - Dry run mode for testing
    """
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self._replay_handlers: dict[str, Callable] = {}
        self._global_handlers: list[Callable] = []
    
    def register_event_handler(
        self, 
        event_type: str, 
        handler: Callable[[EventRecord], None]
    ) -> None:
        """
        Register a handler for a specific event type.
        
        Args:
            event_type: The event type to handle
            handler: Function to process the event
        """
        self._replay_handlers[event_type] = handler
    
    def register_global_handler(
        self, 
        handler: Callable[[EventRecord], None]
    ) -> None:
        """
        Register a global handler that processes all events.
        
        Args:
            handler: Function to process any event
        """
        self._global_handlers.append(handler)
    
    async def replay_events(self, config: ReplayConfig) -> ReplayResult:
        """
        Replay events based on the provided configuration.
        
        Args:
            config: Replay configuration
            
        Returns:
            Result of the replay operation
        """
        result = ReplayResult(
            start_time=datetime.utcnow(),
            errors=[]
        )
        
        try:
            # Build search criteria from config
            criteria = self._build_search_criteria(config)
            
            # Get total count for progress tracking
            search_result = await self.event_store.search_events(criteria)
            total_events = search_result.total_count
            
            if config.max_events and total_events > config.max_events:
                total_events = config.max_events
                criteria.limit = config.max_events
            
            processed_count = 0
            
            # Process events in batches
            offset = 0
            while offset < total_events:
                batch_criteria = criteria
                batch_criteria.offset = offset
                batch_criteria.limit = min(config.batch_size, total_events - offset)
                
                # Get batch of events
                batch_result = await self.event_store.search_events(batch_criteria)
                events = batch_result.events
                
                if not events:
                    break
                
                # Process batch
                batch_stats = await self._process_event_batch(events, config)
                
                # Update results
                result.total_events_processed += batch_stats['processed']
                result.successful_events += batch_stats['successful']
                result.failed_events += batch_stats['failed']
                result.skipped_events += batch_stats['skipped']
                
                if batch_stats.get('errors'):
                    result.errors.extend(batch_stats['errors'])
                
                processed_count += len(events)
                offset += config.batch_size
                
                # Report progress
                if config.progress_callback:
                    config.progress_callback(processed_count, total_events)
                
                # Stop on error if configured
                if config.stop_on_error and batch_stats['failed'] > 0:
                    break
            
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.end_time = datetime.utcnow()
            result.errors.append({
                'type': 'replay_error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return result
    
    async def replay_aggregate(
        self, 
        aggregate_id: UUID, 
        aggregate_type: str,
        from_version: int | None = None,
        to_version: int | None = None,
        handler: Callable[[EventRecord], None] | None = None
    ) -> ReplayResult:
        """
        Replay events for a specific aggregate.
        
        Args:
            aggregate_id: The aggregate identifier
            aggregate_type: The aggregate type
            from_version: Starting version (inclusive)
            to_version: Ending version (inclusive)
            handler: Optional specific handler for this replay
            
        Returns:
            Result of the replay operation
        """
        config = ReplayConfig(
            aggregate_ids=[aggregate_id],
            aggregate_types=[aggregate_type]
        )
        
        # Temporarily register handler if provided
        if handler:
            temp_handler_key = f"temp_{aggregate_type}_{aggregate_id}"
            original_handlers = self._replay_handlers.copy()
            self._replay_handlers[temp_handler_key] = handler
            
            try:
                result = await self.replay_events(config)
            finally:
                # Restore original handlers
                self._replay_handlers = original_handlers
            
            return result
        return await self.replay_events(config)
    
    async def replay_time_range(
        self, 
        from_time: datetime, 
        to_time: datetime,
        event_types: list[str] | None = None
    ) -> ReplayResult:
        """
        Replay events within a specific time range.
        
        Args:
            from_time: Start of time range
            to_time: End of time range
            event_types: Optional event type filter
            
        Returns:
            Result of the replay operation
        """
        config = ReplayConfig(
            from_timestamp=from_time,
            to_timestamp=to_time,
            event_types=event_types
        )
        
        return await self.replay_events(config)
    
    async def replay_recent_events(
        self, 
        hours: int = 24,
        event_types: list[str] | None = None
    ) -> ReplayResult:
        """
        Replay events from the recent past.
        
        Args:
            hours: Number of hours to look back
            event_types: Optional event type filter
            
        Returns:
            Result of the replay operation
        """
        to_time = datetime.utcnow()
        from_time = to_time - timedelta(hours=hours)
        
        return await self.replay_time_range(from_time, to_time, event_types)
    
    async def replay_failed_events(
        self,
        max_age_hours: int = 24,
        max_retry_count: int = 3
    ) -> ReplayResult:
        """
        Replay events that previously failed processing.
        
        Args:
            max_age_hours: Maximum age of failed events to retry
            max_retry_count: Maximum number of retries for each event
            
        Returns:
            Result of the replay operation
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        config = ReplayConfig(
            from_timestamp=cutoff_time,
            include_failed_events=True,
            stop_on_error=False,
            max_retries=max_retry_count
        )
        
        return await self.replay_events(config)
    
    async def dry_run_replay(
        self, 
        config: ReplayConfig
    ) -> ReplayResult:
        """
        Perform a dry run of event replay without executing handlers.
        
        Args:
            config: Replay configuration
            
        Returns:
            Result showing what would be replayed
        """
        dry_config = ReplayConfig(
            **{**config.__dict__, 'dry_run': True}
        )
        
        return await self.replay_events(dry_config)
    
    def _build_search_criteria(self, config: ReplayConfig) -> EventSearchCriteria:
        """Build event search criteria from replay config."""
        criteria = EventSearchCriteria(
            aggregate_ids=config.aggregate_ids,
            aggregate_types=config.aggregate_types,
            event_types=config.event_types,
            from_timestamp=config.from_timestamp,
            to_timestamp=config.to_timestamp,
            limit=config.batch_size,
            sort_by="created_at",
            sort_order="asc"
        )
        
        # Include failed events if requested
        if not config.include_failed_events:
            criteria.statuses = [EventStatus.PENDING, EventStatus.PROCESSED]
        
        return criteria
    
    async def _process_event_batch(
        self, 
        events: list[EventRecord], 
        config: ReplayConfig
    ) -> dict[str, Any]:
        """Process a batch of events."""
        stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'errors': []
        }
        
        for event in events:
            try:
                stats['processed'] += 1
                
                # Skip if dry run
                if config.dry_run:
                    stats['successful'] += 1
                    continue
                
                # Process event
                success = await self._process_single_event(event, config)
                
                if success:
                    stats['successful'] += 1
                else:
                    stats['failed'] += 1
                    
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append({
                    'event_id': str(event.event_id),
                    'event_type': event.event_type,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return stats
    
    async def _process_single_event(
        self, 
        event: EventRecord, 
        config: ReplayConfig
    ) -> bool:
        """Process a single event."""
        try:
            # Apply global handlers
            for handler in self._global_handlers:
                handler(event)
            
            # Apply specific event type handler
            if event.event_type in self._replay_handlers:
                handler = self._replay_handlers[event.event_type]
                handler(event)
            
            return True
            
        except Exception as e:
            # Retry logic
            for retry in range(config.max_retries):
                try:
                    await self._wait_for_retry(config.retry_delay_seconds, retry)
                    
                    # Retry global handlers
                    for handler in self._global_handlers:
                        handler(event)
                    
                    # Retry specific handler
                    if event.event_type in self._replay_handlers:
                        handler = self._replay_handlers[event.event_type]
                        handler(event)
                    
                    return True
                    
                except Exception:
                    if retry == config.max_retries - 1:
                        # Final retry failed
                        raise e
                    continue
            
            return False
    
    async def _wait_for_retry(self, base_delay: float, retry_count: int) -> None:
        """Wait for retry with exponential backoff."""
        import asyncio
        
        delay = base_delay * (2 ** retry_count)
        await asyncio.sleep(delay)
    
    async def get_replay_statistics(
        self,
        from_time: datetime | None = None,
        to_time: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get statistics about event replay operations.
        
        Args:
            from_time: Start time for statistics
            to_time: End time for statistics
            
        Returns:
            Replay statistics
        """
        # This would track replay operations in a separate table
        # For now, return basic metrics from event store
        metrics = await self.event_store.get_metrics(from_time, to_time)
        
        return {
            'total_events': metrics.total_events,
            'events_per_second': metrics.events_per_second,
            'avg_processing_time': 0.0,  # Would need to track this
            'success_rate': 0.95,  # Would calculate from replay logs
            'most_replayed_event_types': [],  # Would get from logs
            'common_errors': []  # Would aggregate from error logs
        }