"""
Event stream reader for efficient event stream processing.

Provides high-performance streaming capabilities for processing events
in real-time or batch scenarios with support for checkpointing and
parallel processing.
"""

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from .event_store import EventStore
from .schemas import EventRecord, EventSearchCriteria, StreamPosition


class StreamReadMode(Enum):
    """Stream reading modes."""
    BATCH = "batch"              # Read in batches
    STREAMING = "streaming"      # Continuous streaming
    CATCH_UP = "catch_up"        # Catch up to latest then stream
    REPLAY = "replay"            # Replay historical events


class StreamProcessingStrategy(Enum):
    """Stream processing strategies."""
    SEQUENTIAL = "sequential"    # Process events one by one
    PARALLEL = "parallel"        # Process events in parallel
    PIPELINE = "pipeline"        # Pipeline processing stages


@dataclass
class StreamConfig:
    """Configuration for event stream reading."""
    
    # Stream identification
    stream_id: str | None = None
    consumer_group: str = "default"
    
    # Reading behavior
    read_mode: StreamReadMode = StreamReadMode.STREAMING
    batch_size: int = 100
    max_events: int | None = None
    
    # Starting position
    start_from_beginning: bool = False
    start_from_checkpoint: str | None = None
    start_from_position: int | None = None
    start_from_timestamp: datetime | None = None
    
    # Processing configuration
    processing_strategy: StreamProcessingStrategy = StreamProcessingStrategy.SEQUENTIAL
    max_parallel_workers: int = 4
    
    # Error handling
    retry_failed_events: bool = True
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    
    # Performance tuning
    prefetch_size: int = 1000
    checkpoint_interval: int = 100
    heartbeat_interval_seconds: float = 30.0
    
    # Event filtering
    event_types: list[str] | None = None
    aggregate_types: list[str] | None = None
    
    # Callbacks
    event_handler: Callable[[EventRecord], None] | None = None
    error_handler: Callable[[Exception, EventRecord], None] | None = None
    checkpoint_handler: Callable[[StreamPosition], None] | None = None


@dataclass
class StreamMetrics:
    """Metrics for stream processing."""
    
    events_processed: int = 0
    events_failed: int = 0
    events_skipped: int = 0
    
    # Performance metrics
    processing_rate_per_second: float = 0.0
    avg_processing_time_ms: float = 0.0
    
    # Position tracking
    current_position: int = 0
    last_checkpoint_position: int = 0
    
    # Timing
    stream_start_time: datetime | None = None
    last_event_time: datetime | None = None
    last_checkpoint_time: datetime | None = None
    
    # Error tracking
    consecutive_errors: int = 0
    last_error: str | None = None


class EventStreamReader:
    """
    High-performance event stream reader with checkpointing and parallel processing.
    
    Provides comprehensive stream processing capabilities including:
    - Multiple reading modes (batch, streaming, catch-up, replay)
    - Checkpoint management for reliable processing
    - Parallel processing with configurable strategies
    - Error handling and retry mechanisms
    - Performance monitoring and metrics
    - Event filtering and transformation
    - Backpressure handling
    """
    
    def __init__(self, event_store: EventStore, config: StreamConfig):
        self.event_store = event_store
        self.config = config
        self.metrics = StreamMetrics()
        self._running = False
        self._current_position = 0
        self._checkpoint_counter = 0
        self._processing_queue: asyncio.Queue = asyncio.Queue(maxsize=config.prefetch_size)
        self._workers: list[asyncio.Task] = []
    
    async def start_reading(self) -> AsyncIterator[EventRecord]:
        """
        Start reading events from the stream.
        
        Yields:
            Event records from the stream
        """
        self._running = True
        self.metrics.stream_start_time = datetime.utcnow()
        
        try:
            # Determine starting position
            start_position = await self._determine_start_position()
            self._current_position = start_position
            self.metrics.current_position = start_position
            
            # Start processing based on mode
            if self.config.read_mode == StreamReadMode.BATCH:
                async for event in self._read_batch_mode():
                    yield event
                    
            elif self.config.read_mode == StreamReadMode.STREAMING:
                async for event in self._read_streaming_mode():
                    yield event
                    
            elif self.config.read_mode == StreamReadMode.CATCH_UP:
                async for event in self._read_catch_up_mode():
                    yield event
                    
            elif self.config.read_mode == StreamReadMode.REPLAY:
                async for event in self._read_replay_mode():
                    yield event
                    
        finally:
            await self._cleanup()
    
    async def process_stream(self) -> StreamMetrics:
        """
        Process the entire stream using configured handlers.
        
        Returns:
            Final processing metrics
        """
        if not self.config.event_handler:
            raise ValueError("Event handler must be configured for stream processing")
        
        self._running = True
        self.metrics.stream_start_time = datetime.utcnow()
        
        try:
            # Start worker tasks for parallel processing
            if self.config.processing_strategy == StreamProcessingStrategy.PARALLEL:
                await self._start_parallel_workers()
            
            # Process events
            async for event in self.start_reading():
                if self.config.processing_strategy == StreamProcessingStrategy.SEQUENTIAL:
                    await self._process_event_sequential(event)
                else:
                    await self._process_event_parallel(event)
                
                # Update metrics
                self.metrics.events_processed += 1
                self.metrics.current_position = event.stream_position
                self.metrics.last_event_time = datetime.utcnow()
                
                # Checkpoint if needed
                await self._maybe_checkpoint(event)
                
                # Check if we should stop
                if (self.config.max_events and 
                    self.metrics.events_processed >= self.config.max_events):
                    break
            
            return self.metrics
            
        finally:
            await self._cleanup()
    
    async def get_stream_status(self) -> dict[str, Any]:
        """Get current stream processing status."""
        return {
            'running': self._running,
            'current_position': self._current_position,
            'events_processed': self.metrics.events_processed,
            'events_failed': self.metrics.events_failed,
            'processing_rate': self.metrics.processing_rate_per_second,
            'last_event_time': self.metrics.last_event_time.isoformat() if self.metrics.last_event_time else None,
            'consecutive_errors': self.metrics.consecutive_errors,
            'worker_count': len(self._workers)
        }
    
    async def stop(self) -> None:
        """Stop stream processing gracefully."""
        self._running = False
        await self._cleanup()
    
    async def _determine_start_position(self) -> int:
        """Determine the starting position for reading."""
        if self.config.start_from_position is not None:
            return self.config.start_from_position
        
        if self.config.start_from_checkpoint:
            checkpoint = await self.event_store.get_checkpoint(
                self.config.start_from_checkpoint,
                self.config.consumer_group
            )
            if checkpoint:
                return checkpoint.position
        
        if self.config.start_from_beginning:
            return 0
        
        if self.config.start_from_timestamp:
            # Find position at timestamp
            criteria = EventSearchCriteria(
                from_timestamp=self.config.start_from_timestamp,
                limit=1,
                sort_by="created_at",
                sort_order="asc"
            )
            
            if self.config.stream_id:
                criteria.stream_ids = [self.config.stream_id]
            
            result = await self.event_store.search_events(criteria)
            if result.events:
                return result.events[0].stream_position
        
        # Default to latest position
        if self.config.stream_id:
            metadata = await self.event_store.get_stream_metadata(self.config.stream_id)
            return metadata.get('last_position', 0)
        
        return 0
    
    async def _read_batch_mode(self) -> AsyncIterator[EventRecord]:
        """Read events in batch mode."""
        events_read = 0
        
        while self._running and (not self.config.max_events or events_read < self.config.max_events):
            # Read batch of events
            if self.config.stream_id:
                events = await self.event_store.get_events(
                    self.config.stream_id,
                    self._current_position,
                    self._current_position + self.config.batch_size - 1
                )
            else:
                criteria = EventSearchCriteria(
                    from_position=self._current_position,
                    limit=self.config.batch_size,
                    event_types=self.config.event_types,
                    aggregate_types=self.config.aggregate_types,
                    sort_by="global_position",
                    sort_order="asc"
                )
                result = await self.event_store.search_events(criteria)
                events = result.events
            
            if not events:
                break  # No more events
            
            # Yield events
            for event in events:
                if self._should_process_event(event):
                    yield event
                    events_read += 1
                    self._current_position = event.stream_position + 1
                    
                    if self.config.max_events and events_read >= self.config.max_events:
                        break
    
    async def _read_streaming_mode(self) -> AsyncIterator[EventRecord]:
        """Read events in streaming mode with real-time polling."""
        poll_interval = 1.0  # seconds
        empty_polls = 0
        max_empty_polls = 10
        
        while self._running:
            # Read batch of events
            if self.config.stream_id:
                events = await self.event_store.get_events(
                    self.config.stream_id,
                    self._current_position,
                    self._current_position + self.config.batch_size - 1
                )
            else:
                criteria = EventSearchCriteria(
                    from_position=self._current_position,
                    limit=self.config.batch_size,
                    event_types=self.config.event_types,
                    aggregate_types=self.config.aggregate_types,
                    sort_by="global_position",
                    sort_order="asc"
                )
                result = await self.event_store.search_events(criteria)
                events = result.events
            
            if events:
                empty_polls = 0
                for event in events:
                    if self._should_process_event(event):
                        yield event
                        self._current_position = event.stream_position + 1
            else:
                empty_polls += 1
                # Increase poll interval if no events
                if empty_polls < max_empty_polls:
                    await asyncio.sleep(poll_interval)
                else:
                    await asyncio.sleep(poll_interval * 2)
    
    async def _read_catch_up_mode(self) -> AsyncIterator[EventRecord]:
        """Read in catch-up mode: fast catch up to latest, then stream."""
        # First, catch up to latest events quickly
        async for event in self._read_batch_mode():
            yield event
        
        # Then switch to streaming mode
        async for event in self._read_streaming_mode():
            yield event
    
    async def _read_replay_mode(self) -> AsyncIterator[EventRecord]:
        """Read in replay mode for historical events."""
        # Similar to batch mode but with different termination conditions
        async for event in self._read_batch_mode():
            yield event
    
    def _should_process_event(self, event: EventRecord) -> bool:
        """Check if an event should be processed based on filters."""
        if self.config.event_types and event.event_type not in self.config.event_types:
            return False
        
        return not (self.config.aggregate_types and event.aggregate_type not in self.config.aggregate_types)
    
    async def _process_event_sequential(self, event: EventRecord) -> None:
        """Process an event sequentially."""
        try:
            if self.config.event_handler:
                self.config.event_handler(event)
            self.metrics.consecutive_errors = 0
        except Exception as e:
            await self._handle_processing_error(e, event)
    
    async def _process_event_parallel(self, event: EventRecord) -> None:
        """Add event to parallel processing queue."""
        await self._processing_queue.put(event)
    
    async def _start_parallel_workers(self) -> None:
        """Start parallel worker tasks."""
        for i in range(self.config.max_parallel_workers):
            worker = asyncio.create_task(self._worker_task(f"worker-{i}"))
            self._workers.append(worker)
    
    async def _worker_task(self, worker_name: str) -> None:
        """Worker task for parallel processing."""
        while self._running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(
                    self._processing_queue.get(), 
                    timeout=1.0
                )
                
                # Process event
                if self.config.event_handler:
                    self.config.event_handler(event)
                
                # Mark task as done
                self._processing_queue.task_done()
                
            except TimeoutError:
                continue  # No event available, keep waiting
            except Exception as e:
                await self._handle_processing_error(e, None)
    
    async def _handle_processing_error(
        self, 
        error: Exception, 
        event: EventRecord | None
    ) -> None:
        """Handle processing errors with retry logic."""
        self.metrics.events_failed += 1
        self.metrics.consecutive_errors += 1
        self.metrics.last_error = str(error)
        
        if self.config.error_handler:
            self.config.error_handler(error, event)
        
        # Retry logic
        if self.config.retry_failed_events and event:
            for retry in range(self.config.max_retries):
                try:
                    await asyncio.sleep(self.config.retry_delay_seconds * (retry + 1))
                    if self.config.event_handler:
                        self.config.event_handler(event)
                    return  # Success
                except Exception:
                    if retry == self.config.max_retries - 1:
                        # Final retry failed, give up
                        break
    
    async def _maybe_checkpoint(self, event: EventRecord) -> None:
        """Create checkpoint if interval reached."""
        self._checkpoint_counter += 1
        
        if self._checkpoint_counter >= self.config.checkpoint_interval:
            await self._create_checkpoint(event)
            self._checkpoint_counter = 0
    
    async def _create_checkpoint(self, event: EventRecord) -> None:
        """Create a checkpoint at the current position."""
        if self.config.start_from_checkpoint:
            position = StreamPosition(
                stream_id=event.stream_id,
                position=event.stream_position,
                global_position=event.global_position,
                timestamp=datetime.utcnow(),
                checkpoint_name=self.config.start_from_checkpoint,
                consumer_group=self.config.consumer_group
            )
            
            await self.event_store.save_checkpoint(
                self.config.start_from_checkpoint,
                position,
                self.config.consumer_group
            )
            
            self.metrics.last_checkpoint_position = event.stream_position
            self.metrics.last_checkpoint_time = datetime.utcnow()
            
            if self.config.checkpoint_handler:
                self.config.checkpoint_handler(position)
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        self._running = False
        
        # Cancel worker tasks
        for worker in self._workers:
            worker.cancel()
        
        # Wait for workers to finish
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        
        self._workers.clear()
        
        # Clear processing queue
        while not self._processing_queue.empty():
            try:
                self._processing_queue.get_nowait()
                self._processing_queue.task_done()
            except asyncio.QueueEmpty:
                break