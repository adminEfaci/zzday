"""
Event Batch Processing

Provides batch processing capabilities for events with performance optimization,
ordering guarantees, and configurable batch strategies.
"""

import asyncio
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

logger = get_logger(__name__)


class BatchStrategy(Enum):
    """Event batch processing strategies."""
    
    SIZE_BASED = "size_based"        # Batch by number of events
    TIME_BASED = "time_based"        # Batch by time window
    PRIORITY_BASED = "priority_based"  # Batch by event priority
    TYPE_BASED = "type_based"        # Batch by event type
    MIXED = "mixed"                  # Mixed strategy with multiple criteria


class BatchStatus(Enum):
    """Batch processing status."""
    
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class BatchMetrics:
    """Metrics for batch processing."""
    
    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0
    processing_time_seconds: float = 0.0
    batch_size_bytes: int = 0
    compression_ratio: float = 1.0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_events == 0:
            return 0.0
        return self.successful_events / self.total_events
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        return 1.0 - self.success_rate
    
    @property
    def throughput_events_per_second(self) -> float:
        """Calculate throughput in events per second."""
        if self.processing_time_seconds == 0:
            return 0.0
        return self.total_events / self.processing_time_seconds


@dataclass  
class EventBatch:
    """
    Event batch for efficient processing of multiple events.
    
    Provides batching capabilities with configurable strategies, ordering
    guarantees, and performance optimization for high-throughput scenarios.
    
    Features:
    - Multiple batching strategies
    - Configurable batch sizes and timeouts
    - Event ordering and grouping
    - Performance metrics and monitoring
    - Compression and serialization optimization
    - Error handling and partial failure support
    
    Usage:
        # Create a batch with events
        events = [event1, event2, event3]
        batch = EventBatch(
            events=events,
            batch_size=100,
            strategy=BatchStrategy.SIZE_BASED
        )
        
        # Process in batches
        async for batch_events in batch.get_batches():
            await process_batch(batch_events)
        
        # Get batch metrics
        metrics = batch.get_metrics()
        print(f"Processed {metrics.total_events} events")
    """
    
    # Core batch information
    batch_id: str = field(default_factory=lambda: str(uuid4()))
    events: list[IdentityDomainEvent] = field(default_factory=list)
    
    # Batch configuration  
    batch_size: int = 100
    strategy: BatchStrategy = BatchStrategy.SIZE_BASED
    max_batch_age_seconds: float = 30.0
    preserve_order: bool = True
    
    # Processing configuration
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    timeout_seconds: float = 60.0
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    # Processing state
    status: BatchStatus = BatchStatus.PENDING
    processed_at: datetime | None = None
    completed_at: datetime | None = None
    
    # Metrics
    metrics: BatchMetrics = field(default_factory=BatchMetrics)
    
    # Internal state
    _processing_started: bool = field(default=False, init=False)
    _sub_batches: list[list[IdentityDomainEvent]] = field(default_factory=list, init=False)
    
    def __post_init__(self):
        """Post-initialization setup."""
        self.metrics.total_events = len(self.events)
        self._prepare_batches()
        
        logger.debug(
            "EventBatch created",
            batch_id=self.batch_id,
            total_events=len(self.events),
            batch_size=self.batch_size,
            strategy=self.strategy.value,
        )
    
    def add_event(self, event: IdentityDomainEvent) -> None:
        """
        Add an event to the batch.
        
        Args:
            event: Event to add
        """
        if self._processing_started:
            raise ValueError("Cannot add events to a batch that has started processing")
        
        self.events.append(event)
        self.metrics.total_events = len(self.events)
        
        # Re-prepare batches if strategy requires it
        if self.strategy in [BatchStrategy.PRIORITY_BASED, BatchStrategy.TYPE_BASED]:
            self._prepare_batches()
    
    def add_events(self, events: list[IdentityDomainEvent]) -> None:
        """
        Add multiple events to the batch.
        
        Args:
            events: List of events to add
        """
        for event in events:
            self.add_event(event)
    
    async def get_batches(self) -> AsyncGenerator[list[IdentityDomainEvent], None]:
        """
        Get batches of events for processing.
        
        Yields:
            List[IdentityDomainEvent]: Batch of events
        """
        self._processing_started = True
        self.status = BatchStatus.PROCESSING
        self.processed_at = datetime.now(UTC)
        
        logger.info(
            "Starting batch processing",
            batch_id=self.batch_id,
            total_events=len(self.events),
            sub_batches=len(self._sub_batches),
            strategy=self.strategy.value,
        )
        
        try:
            for i, sub_batch in enumerate(self._sub_batches):
                logger.debug(
                    "Yielding sub-batch",
                    batch_id=self.batch_id,
                    sub_batch_index=i,
                    sub_batch_size=len(sub_batch),
                )
                yield sub_batch
                
                # Allow other tasks to run
                await asyncio.sleep(0)
            
            self.status = BatchStatus.COMPLETED
            self.completed_at = datetime.now(UTC)
            
        except Exception as e:
            self.status = BatchStatus.FAILED
            logger.exception(
                "Batch processing failed",
                batch_id=self.batch_id,
                error=str(e),
            )
            raise
    
    def _prepare_batches(self) -> None:
        """Prepare sub-batches based on the configured strategy."""
        self._sub_batches.clear()
        
        if not self.events:
            return
        
        if self.strategy == BatchStrategy.SIZE_BASED:
            self._prepare_size_based_batches()
        elif self.strategy == BatchStrategy.PRIORITY_BASED:
            self._prepare_priority_based_batches()
        elif self.strategy == BatchStrategy.TYPE_BASED:
            self._prepare_type_based_batches()
        elif self.strategy == BatchStrategy.MIXED:
            self._prepare_mixed_batches()
        else:
            # Default to size-based
            self._prepare_size_based_batches()
        
        logger.debug(
            "Batches prepared",
            batch_id=self.batch_id,
            strategy=self.strategy.value,
            sub_batches=len(self._sub_batches),
            total_events=len(self.events),
        )
    
    def _prepare_size_based_batches(self) -> None:
        """Prepare batches based on size."""
        events = self.events.copy() if self.preserve_order else self.events
        
        for i in range(0, len(events), self.batch_size):
            sub_batch = events[i:i + self.batch_size]
            self._sub_batches.append(sub_batch)
    
    def _prepare_priority_based_batches(self) -> None:
        """Prepare batches based on event priority."""
        # Group events by priority
        priority_groups: dict[str, list[IdentityDomainEvent]] = {}
        
        for event in self.events:
            priority = "normal"  # default
            if hasattr(event, 'get_risk_level'):
                priority = event.get_risk_level()
            
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(event)
        
        # Process high priority events first
        priority_order = ["critical", "high", "medium", "normal", "low"]
        
        for priority in priority_order:
            if priority in priority_groups:
                events = priority_groups[priority]
                # Create sub-batches for this priority level
                for i in range(0, len(events), self.batch_size):
                    sub_batch = events[i:i + self.batch_size]
                    self._sub_batches.append(sub_batch)
    
    def _prepare_type_based_batches(self) -> None:
        """Prepare batches based on event type."""
        # Group events by type
        type_groups: dict[str, list[IdentityDomainEvent]] = {}
        
        for event in self.events:
            event_type = event.__class__.__name__
            if event_type not in type_groups:
                type_groups[event_type] = []
            type_groups[event_type].append(event)
        
        # Create sub-batches for each event type
        for _event_type, events in type_groups.items():
            for i in range(0, len(events), self.batch_size):
                sub_batch = events[i:i + self.batch_size]
                self._sub_batches.append(sub_batch)
    
    def _prepare_mixed_batches(self) -> None:
        """Prepare batches using mixed strategy (priority + type)."""
        # First group by priority, then by type within each priority
        priority_groups: dict[str, dict[str, list[IdentityDomainEvent]]] = {}
        
        for event in self.events:
            priority = "normal"
            if hasattr(event, 'get_risk_level'):
                priority = event.get_risk_level()
            
            event_type = event.__class__.__name__
            
            if priority not in priority_groups:
                priority_groups[priority] = {}
            
            if event_type not in priority_groups[priority]:
                priority_groups[priority][event_type] = []
            
            priority_groups[priority][event_type].append(event)
        
        # Process in priority order, then by type within each priority
        priority_order = ["critical", "high", "medium", "normal", "low"]
        
        for priority in priority_order:
            if priority in priority_groups:
                for _event_type, events in priority_groups[priority].items():
                    for i in range(0, len(events), self.batch_size):
                        sub_batch = events[i:i + self.batch_size]
                        self._sub_batches.append(sub_batch)
    
    def mark_event_success(self, event: IdentityDomainEvent) -> None:
        """Mark an event as successfully processed."""
        self.metrics.successful_events += 1
    
    def mark_event_failure(self, event: IdentityDomainEvent, error: str | None = None) -> None:
        """Mark an event as failed."""
        self.metrics.failed_events += 1
        
        logger.warning(
            "Event in batch failed",
            batch_id=self.batch_id,
            event_type=event.__class__.__name__,
            event_id=str(getattr(event, 'event_id', 'unknown')),
            error=error,
        )
    
    def update_processing_time(self, seconds: float) -> None:
        """Update processing time metrics."""
        self.metrics.processing_time_seconds = seconds
    
    def update_batch_size_bytes(self, bytes_size: int) -> None:
        """Update batch size in bytes."""
        self.metrics.batch_size_bytes = bytes_size
    
    def get_metrics(self) -> BatchMetrics:
        """Get batch processing metrics."""
        return self.metrics
    
    def get_summary(self) -> dict[str, Any]:
        """Get batch summary for monitoring."""
        return {
            "batch_id": self.batch_id,
            "status": self.status.value,
            "strategy": self.strategy.value,
            "total_events": len(self.events),
            "sub_batches": len(self._sub_batches),
            "batch_size": self.batch_size,
            "preserve_order": self.preserve_order,
            "created_at": self.created_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "correlation_id": self.correlation_id,
            "metrics": {
                "total_events": self.metrics.total_events,
                "successful_events": self.metrics.successful_events,
                "failed_events": self.metrics.failed_events,
                "success_rate": self.metrics.success_rate,
                "processing_time_seconds": self.metrics.processing_time_seconds,
                "throughput_events_per_second": self.metrics.throughput_events_per_second,
                "batch_size_bytes": self.metrics.batch_size_bytes,
            },
        }
    
    @property
    def is_empty(self) -> bool:
        """Check if batch is empty."""
        return len(self.events) == 0
    
    @property
    def is_full(self) -> bool:
        """Check if batch has reached maximum size."""
        return len(self.events) >= self.batch_size
    
    @property
    def is_expired(self) -> bool:
        """Check if batch has exceeded maximum age."""
        if self.max_batch_age_seconds <= 0:
            return False
        
        age = (datetime.now(UTC) - self.created_at).total_seconds()
        return age >= self.max_batch_age_seconds
    
    @property
    def should_process(self) -> bool:
        """Check if batch should be processed (full or expired)."""
        return self.is_full or self.is_expired
    
    def to_dict(self) -> dict[str, Any]:
        """Convert batch to dictionary for serialization."""
        return {
            "batch_id": self.batch_id,
            "events": [event.to_dict() for event in self.events],
            "batch_size": self.batch_size,
            "strategy": self.strategy.value,
            "max_batch_age_seconds": self.max_batch_age_seconds,
            "preserve_order": self.preserve_order,
            "max_retries": self.max_retries,
            "retry_delay_seconds": self.retry_delay_seconds,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at.isoformat(),
            "correlation_id": self.correlation_id,
            "metadata": self.metadata,
            "status": self.status.value,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metrics": self.metrics.__dict__,
        }
    
    def __len__(self) -> int:
        """Return number of events in batch."""
        return len(self.events)
    
    def __bool__(self) -> bool:
        """Return True if batch has events."""
        return len(self.events) > 0
    
    def __str__(self) -> str:
        """String representation of batch."""
        return (
            f"EventBatch("
            f"batch_id={self.batch_id}, "
            f"events={len(self.events)}, "
            f"strategy={self.strategy.value}, "
            f"status={self.status.value}"
            f")"
        )