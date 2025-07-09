"""Event ordering and sequencing infrastructure.

This module provides event ordering guarantees for distributed event processing,
ensuring events are processed in the correct order across multiple consumers.
"""

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from app.core.logging import get_logger
from app.modules.identity.infrastructure.events.store.schemas import EventRecord

logger = get_logger(__name__)


@dataclass
class OrderedEvent:
    """Event with ordering information."""
    event_id: str
    stream_id: str
    sequence_number: int
    timestamp: datetime
    event_type: str
    event_data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    partition_key: Optional[str] = None
    ordering_key: Optional[str] = None
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid4())
        if not self.timestamp:
            self.timestamp = datetime.utcnow()


@dataclass
class EventSequence:
    """Sequence state for ordered event processing."""
    stream_id: str
    last_sequence_number: int
    pending_events: Dict[int, OrderedEvent] = field(default_factory=dict)
    consumer_positions: Dict[str, int] = field(default_factory=dict)
    last_processed_time: Optional[datetime] = None
    
    def __post_init__(self):
        if not self.last_processed_time:
            self.last_processed_time = datetime.utcnow()


class EventOrderingError(Exception):
    """Event ordering specific errors."""
    pass


class SequenceGapError(EventOrderingError):
    """Raised when there's a gap in event sequence."""
    
    def __init__(self, stream_id: str, expected: int, actual: int):
        super().__init__(f"Sequence gap in stream {stream_id}: expected {expected}, got {actual}")
        self.stream_id = stream_id
        self.expected = expected
        self.actual = actual


class EventSequencer:
    """Manages event sequencing and ordering."""
    
    def __init__(self, max_out_of_order_events: int = 1000):
        self.sequences: Dict[str, EventSequence] = {}
        self.max_out_of_order_events = max_out_of_order_events
        self.total_events_processed = 0
        self.out_of_order_events = 0
        self.sequence_gaps_detected = 0
        self._lock = asyncio.Lock()
    
    async def add_event(self, event: OrderedEvent) -> List[OrderedEvent]:
        """Add an event to the sequencer and return any events ready for processing.
        
        Args:
            event: Event to add
            
        Returns:
            List of events ready for processing in order
        """
        async with self._lock:
            # Get or create sequence
            if event.stream_id not in self.sequences:
                self.sequences[event.stream_id] = EventSequence(
                    stream_id=event.stream_id,
                    last_sequence_number=0,
                )
            
            sequence = self.sequences[event.stream_id]
            ready_events = []
            
            # Check if event is in order
            expected_sequence = sequence.last_sequence_number + 1
            
            if event.sequence_number == expected_sequence:
                # Event is in order, process it and any pending events
                ready_events.append(event)
                sequence.last_sequence_number = event.sequence_number
                sequence.last_processed_time = datetime.utcnow()
                
                # Check for pending events that are now ready
                while True:
                    next_sequence = sequence.last_sequence_number + 1
                    if next_sequence in sequence.pending_events:
                        pending_event = sequence.pending_events.pop(next_sequence)
                        ready_events.append(pending_event)
                        sequence.last_sequence_number = next_sequence
                    else:
                        break
                
                self.total_events_processed += len(ready_events)
                
            elif event.sequence_number > expected_sequence:
                # Event is out of order, store it for later processing
                sequence.pending_events[event.sequence_number] = event
                self.out_of_order_events += 1
                
                # Check for too many out-of-order events
                if len(sequence.pending_events) > self.max_out_of_order_events:
                    logger.warning(
                        "Too many out-of-order events",
                        stream_id=event.stream_id,
                        pending_count=len(sequence.pending_events),
                        max_allowed=self.max_out_of_order_events,
                    )
                    
                    # Process oldest pending events to prevent memory issues
                    oldest_sequence = min(sequence.pending_events.keys())
                    oldest_event = sequence.pending_events.pop(oldest_sequence)
                    
                    # Log the gap
                    self.sequence_gaps_detected += 1
                    logger.error(
                        "Sequence gap detected, processing out-of-order event",
                        stream_id=event.stream_id,
                        expected=expected_sequence,
                        actual=oldest_sequence,
                    )
                    
                    ready_events.append(oldest_event)
                    sequence.last_sequence_number = oldest_sequence
                    self.total_events_processed += 1
                
            else:
                # Event is a duplicate or very old, ignore it
                logger.warning(
                    "Duplicate or old event ignored",
                    stream_id=event.stream_id,
                    sequence_number=event.sequence_number,
                    expected=expected_sequence,
                )
            
            return ready_events
    
    async def get_pending_events(self, stream_id: str) -> List[OrderedEvent]:
        """Get pending events for a stream.
        
        Args:
            stream_id: Stream identifier
            
        Returns:
            List of pending events
        """
        async with self._lock:
            if stream_id not in self.sequences:
                return []
            
            sequence = self.sequences[stream_id]
            return list(sequence.pending_events.values())
    
    async def force_process_pending(self, stream_id: str, timeout_seconds: int = 30) -> List[OrderedEvent]:
        """Force process pending events after timeout.
        
        Args:
            stream_id: Stream identifier
            timeout_seconds: Timeout in seconds
            
        Returns:
            List of processed events
        """
        async with self._lock:
            if stream_id not in self.sequences:
                return []
            
            sequence = self.sequences[stream_id]
            if not sequence.pending_events:
                return []
            
            # Check if timeout has passed
            if sequence.last_processed_time:
                elapsed = (datetime.utcnow() - sequence.last_processed_time).total_seconds()
                if elapsed < timeout_seconds:
                    return []
            
            # Process all pending events in order
            processed_events = []
            for seq_num in sorted(sequence.pending_events.keys()):
                event = sequence.pending_events.pop(seq_num)
                processed_events.append(event)
                sequence.last_sequence_number = seq_num
                self.sequence_gaps_detected += 1
            
            sequence.last_processed_time = datetime.utcnow()
            self.total_events_processed += len(processed_events)
            
            logger.warning(
                "Force processed pending events due to timeout",
                stream_id=stream_id,
                processed_count=len(processed_events),
                timeout_seconds=timeout_seconds,
            )
            
            return processed_events
    
    def get_sequence_stats(self) -> Dict[str, Any]:
        """Get sequencing statistics.
        
        Returns:
            Dictionary with sequencing statistics
        """
        total_pending = sum(len(seq.pending_events) for seq in self.sequences.values())
        
        return {
            "total_streams": len(self.sequences),
            "total_events_processed": self.total_events_processed,
            "out_of_order_events": self.out_of_order_events,
            "sequence_gaps_detected": self.sequence_gaps_detected,
            "total_pending_events": total_pending,
            "max_out_of_order_events": self.max_out_of_order_events,
        }


class PartitionedEventProcessor:
    """Processes events by partition to maintain ordering within partitions."""
    
    def __init__(self, num_partitions: int = 16):
        self.num_partitions = num_partitions
        self.sequencers: Dict[int, EventSequencer] = {}
        self.partition_assignments: Dict[str, int] = {}
        self.event_processors: Dict[int, Callable] = {}
        self.processing_tasks: Dict[int, asyncio.Task] = {}
        self.event_queues: Dict[int, asyncio.Queue] = {}
        self.running = False
        
        # Initialize sequencers and queues
        for i in range(num_partitions):
            self.sequencers[i] = EventSequencer()
            self.event_queues[i] = asyncio.Queue()
    
    def get_partition(self, event: OrderedEvent) -> int:
        """Get partition for an event.
        
        Args:
            event: Event to partition
            
        Returns:
            Partition number
        """
        # Use partition key if available, otherwise use stream_id
        key = event.partition_key or event.stream_id
        
        # Simple hash-based partitioning
        return hash(key) % self.num_partitions
    
    async def submit_event(self, event: OrderedEvent) -> None:
        """Submit an event for processing.
        
        Args:
            event: Event to process
        """
        partition = self.get_partition(event)
        await self.event_queues[partition].put(event)
    
    def register_processor(self, partition: int, processor: Callable) -> None:
        """Register a processor for a partition.
        
        Args:
            partition: Partition number
            processor: Processor function
        """
        self.event_processors[partition] = processor
    
    async def start(self) -> None:
        """Start the partitioned event processor."""
        if self.running:
            return
        
        self.running = True
        
        # Start processing tasks for each partition
        for partition in range(self.num_partitions):
            task = asyncio.create_task(self._process_partition(partition))
            self.processing_tasks[partition] = task
        
        logger.info(
            "Started partitioned event processor",
            partitions=self.num_partitions,
        )
    
    async def stop(self) -> None:
        """Stop the partitioned event processor."""
        if not self.running:
            return
        
        self.running = False
        
        # Stop all processing tasks
        for task in self.processing_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.processing_tasks.values(), return_exceptions=True)
        
        self.processing_tasks.clear()
        
        logger.info("Stopped partitioned event processor")
    
    async def _process_partition(self, partition: int) -> None:
        """Process events for a specific partition.
        
        Args:
            partition: Partition number
        """
        sequencer = self.sequencers[partition]
        event_queue = self.event_queues[partition]
        processor = self.event_processors.get(partition)
        
        logger.info(f"Started processing partition {partition}")
        
        while self.running:
            try:
                # Get event from queue with timeout
                try:
                    event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Check for pending events that have timed out
                    for stream_id in list(sequencer.sequences.keys()):
                        timeout_events = await sequencer.force_process_pending(stream_id)
                        if timeout_events and processor:
                            for timeout_event in timeout_events:
                                await processor(timeout_event)
                    continue
                
                # Add event to sequencer
                ready_events = await sequencer.add_event(event)
                
                # Process ready events
                if ready_events and processor:
                    for ready_event in ready_events:
                        await processor(ready_event)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Error processing partition",
                    partition=partition,
                    error=str(e),
                )
        
        logger.info(f"Stopped processing partition {partition}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics.
        
        Returns:
            Dictionary with processor statistics
        """
        stats = {
            "num_partitions": self.num_partitions,
            "running": self.running,
            "partitions": {},
            "totals": {
                "events_processed": 0,
                "out_of_order_events": 0,
                "sequence_gaps": 0,
                "pending_events": 0,
            }
        }
        
        for partition, sequencer in self.sequencers.items():
            partition_stats = sequencer.get_sequence_stats()
            stats["partitions"][partition] = partition_stats
            
            # Aggregate totals
            stats["totals"]["events_processed"] += partition_stats["total_events_processed"]
            stats["totals"]["out_of_order_events"] += partition_stats["out_of_order_events"]
            stats["totals"]["sequence_gaps"] += partition_stats["sequence_gaps_detected"]
            stats["totals"]["pending_events"] += partition_stats["total_pending_events"]
        
        return stats


class EventOrderingService:
    """High-level service for event ordering and processing."""
    
    def __init__(self, num_partitions: int = 16):
        self.processor = PartitionedEventProcessor(num_partitions)
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self.global_handlers: List[Callable] = []
        self.running = False
    
    def register_handler(self, event_type: str, handler: Callable) -> None:
        """Register an event handler for a specific event type.
        
        Args:
            event_type: Event type to handle
            handler: Handler function
        """
        self.event_handlers[event_type].append(handler)
    
    def register_global_handler(self, handler: Callable) -> None:
        """Register a global event handler for all events.
        
        Args:
            handler: Handler function
        """
        self.global_handlers.append(handler)
    
    async def process_event(self, event: OrderedEvent) -> None:
        """Process an event through handlers.
        
        Args:
            event: Event to process
        """
        # Call global handlers
        for handler in self.global_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.exception(
                    "Global handler error",
                    event_id=event.event_id,
                    event_type=event.event_type,
                    handler=handler.__name__,
                    error=str(e),
                )
        
        # Call specific handlers
        for handler in self.event_handlers[event.event_type]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.exception(
                    "Event handler error",
                    event_id=event.event_id,
                    event_type=event.event_type,
                    handler=handler.__name__,
                    error=str(e),
                )
    
    async def start(self) -> None:
        """Start the event ordering service."""
        if self.running:
            return
        
        # Register processors for each partition
        for partition in range(self.processor.num_partitions):
            self.processor.register_processor(partition, self.process_event)
        
        await self.processor.start()
        self.running = True
        
        logger.info("Started event ordering service")
    
    async def stop(self) -> None:
        """Stop the event ordering service."""
        if not self.running:
            return
        
        await self.processor.stop()
        self.running = False
        
        logger.info("Stopped event ordering service")
    
    async def submit_event(self, event: OrderedEvent) -> None:
        """Submit an event for ordered processing.
        
        Args:
            event: Event to process
        """
        await self.processor.submit_event(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics.
        
        Returns:
            Dictionary with service statistics
        """
        return {
            "running": self.running,
            "event_handlers": {
                event_type: len(handlers)
                for event_type, handlers in self.event_handlers.items()
            },
            "global_handlers": len(self.global_handlers),
            "processor_stats": self.processor.get_stats(),
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the service.
        
        Returns:
            Health check results
        """
        stats = self.get_stats()
        healthy = self.running and stats["processor_stats"]["running"]
        
        return {
            "healthy": healthy,
            "timestamp": datetime.utcnow().isoformat(),
            "stats": stats,
        }


# Global event ordering service
_event_ordering_service: Optional[EventOrderingService] = None


def get_event_ordering_service() -> EventOrderingService:
    """Get the global event ordering service.
    
    Returns:
        EventOrderingService: Global service instance
    """
    global _event_ordering_service
    
    if _event_ordering_service is None:
        _event_ordering_service = EventOrderingService()
    
    return _event_ordering_service


async def initialize_event_ordering(num_partitions: int = 16) -> EventOrderingService:
    """Initialize the global event ordering service.
    
    Args:
        num_partitions: Number of partitions for event processing
        
    Returns:
        EventOrderingService: Initialized service
    """
    global _event_ordering_service
    
    _event_ordering_service = EventOrderingService(num_partitions)
    await _event_ordering_service.start()
    
    return _event_ordering_service


async def shutdown_event_ordering() -> None:
    """Shutdown the global event ordering service."""
    global _event_ordering_service
    
    if _event_ordering_service:
        await _event_ordering_service.stop()
        _event_ordering_service = None