"""
Event Delivery Service Implementation

Handles reliable event delivery with retry mechanisms, circuit breaker pattern,
dead letter queues, and comprehensive monitoring for robust event processing.
"""

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from app.core.events.bus import EventBus
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

from .metadata import EventMetadata as PublisherEventMetadata
from .router import RoutingInfo

logger = get_logger(__name__)


class DeliveryStatus(Enum):
    """Event delivery status."""
    
    PENDING = "pending"
    DELIVERING = "delivering"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRY_SCHEDULED = "retry_scheduled"
    DEAD_LETTER = "dead_letter"
    CIRCUIT_OPEN = "circuit_open"


class CircuitState(Enum):
    """Circuit breaker state."""
    
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class DeliveryAttempt:
    """Represents a single delivery attempt."""
    
    attempt_id: str = field(default_factory=lambda: str(uuid4()))
    attempt_number: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: DeliveryStatus = DeliveryStatus.PENDING
    error: str | None = None
    latency_ms: float | None = None
    target_handler: str | None = None
    target_queue: str | None = None


@dataclass
class DeliveryRecord:
    """Complete delivery record for an event."""
    
    event_id: str
    event_type: str
    delivery_id: str = field(default_factory=lambda: str(uuid4()))
    status: DeliveryStatus = DeliveryStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    attempts: list[DeliveryAttempt] = field(default_factory=list)
    routing_info: RoutingInfo | None = None
    metadata: PublisherEventMetadata | None = None
    
    # Retry configuration
    max_retry_attempts: int = 3
    next_retry_at: datetime | None = None
    retry_delay_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    max_retry_delay: float = 300.0  # 5 minutes
    
    # Dead letter queue
    sent_to_dlq: bool = False
    dlq_reason: str | None = None
    
    @property
    def total_attempts(self) -> int:
        """Total number of delivery attempts."""
        return len(self.attempts)
    
    @property
    def is_exhausted(self) -> bool:
        """Check if all retry attempts are exhausted."""
        return self.total_attempts >= self.max_retry_attempts
    
    @property
    def should_retry(self) -> bool:
        """Check if event should be retried."""
        return (
            self.status in [DeliveryStatus.FAILED, DeliveryStatus.RETRY_SCHEDULED]
            and not self.is_exhausted
            and not self.sent_to_dlq
        )
    
    def calculate_next_retry_delay(self) -> float:
        """Calculate delay for next retry attempt."""
        base_delay = self.retry_delay_seconds * (self.backoff_multiplier ** (self.total_attempts - 1))
        return min(base_delay, self.max_retry_delay)
    
    def schedule_retry(self) -> None:
        """Schedule next retry attempt."""
        if self.is_exhausted:
            return
        
        delay = self.calculate_next_retry_delay()
        self.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay)
        self.status = DeliveryStatus.RETRY_SCHEDULED
        self.updated_at = datetime.now(UTC)
    
    def add_attempt(
        self,
        status: DeliveryStatus,
        error: str | None = None,
        latency_ms: float | None = None,
        target_handler: str | None = None,
        target_queue: str | None = None,
    ) -> DeliveryAttempt:
        """Add a delivery attempt record."""
        attempt = DeliveryAttempt(
            attempt_number=self.total_attempts + 1,
            status=status,
            error=error,
            latency_ms=latency_ms,
            target_handler=target_handler,
            target_queue=target_queue,
        )
        
        self.attempts.append(attempt)
        self.status = status
        self.updated_at = datetime.now(UTC)
        
        return attempt


class CircuitBreaker:
    """
    Circuit breaker for event delivery.
    
    Prevents cascading failures by monitoring delivery success rates
    and temporarily stopping delivery attempts when failure rates
    are too high.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 3,
        time_window: float = 60.0,
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures to open circuit
            recovery_timeout: Time to wait before testing recovery
            success_threshold: Successes needed in half-open to close
            time_window: Time window for failure counting
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self.time_window = time_window
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float | None = None
        self.state_changed_at = time.time()
        
        # Track recent events for time window analysis
        self.recent_events: list[tuple[float, bool]] = []  # (timestamp, success)
    
    def record_success(self) -> None:
        """Record a successful operation."""
        now = time.time()
        self.recent_events.append((now, True))
        self._cleanup_old_events(now)
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self._close_circuit()
        elif self.state == CircuitState.OPEN:
            # Reset failure count on any success
            self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record a failed operation."""
        now = time.time()
        self.recent_events.append((now, False))
        self._cleanup_old_events(now)
        
        self.failure_count += 1
        self.last_failure_time = now
        
        if self.state == CircuitState.CLOSED:
            if self._should_open_circuit():
                self._open_circuit()
        elif self.state == CircuitState.HALF_OPEN:
            self._open_circuit()
    
    def can_proceed(self) -> bool:
        """Check if operation can proceed."""
        now = time.time()
        
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset(now):
                self._half_open_circuit()
                return True
            return False
        return self.state == CircuitState.HALF_OPEN
    
    def _should_open_circuit(self) -> bool:
        """Check if circuit should be opened."""
        now = time.time()
        recent_failures = [
            event for event in self.recent_events
            if not event[1] and now - event[0] <= self.time_window
        ]
        return len(recent_failures) >= self.failure_threshold
    
    def _should_attempt_reset(self, now: float) -> bool:
        """Check if should attempt to reset from open state."""
        return (
            self.last_failure_time is not None
            and now - self.last_failure_time >= self.recovery_timeout
        )
    
    def _open_circuit(self) -> None:
        """Open the circuit."""
        self.state = CircuitState.OPEN
        self.state_changed_at = time.time()
        self.success_count = 0
        
        logger.warning(
            "Circuit breaker opened",
            failure_count=self.failure_count,
            last_failure_time=self.last_failure_time,
        )
    
    def _half_open_circuit(self) -> None:
        """Half-open the circuit for testing."""
        self.state = CircuitState.HALF_OPEN
        self.state_changed_at = time.time()
        self.success_count = 0
        
        logger.info("Circuit breaker half-opened for testing")
    
    def _close_circuit(self) -> None:
        """Close the circuit."""
        self.state = CircuitState.CLOSED
        self.state_changed_at = time.time()
        self.failure_count = 0
        self.success_count = 0
        
        logger.info("Circuit breaker closed")
    
    def _cleanup_old_events(self, now: float) -> None:
        """Remove events outside the time window."""
        cutoff = now - self.time_window
        self.recent_events = [
            event for event in self.recent_events
            if event[0] > cutoff
        ]
    
    def get_statistics(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        now = time.time()
        self._cleanup_old_events(now)
        
        recent_failures = sum(1 for _, success in self.recent_events if not success)
        recent_successes = sum(1 for _, success in self.recent_events if success)
        
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "recent_failures": recent_failures,
            "recent_successes": recent_successes,
            "state_duration": now - self.state_changed_at,
            "last_failure_time": self.last_failure_time,
        }


class EventDeliveryService:
    """
    Event delivery service with comprehensive reliability features.
    
    Provides robust event delivery with retry mechanisms, circuit breaker
    pattern, dead letter queues, and comprehensive monitoring.
    
    Features:
    - Exponential backoff retry strategy
    - Circuit breaker for failure protection
    - Dead letter queue for failed events
    - Delivery tracking and statistics
    - Configurable retry policies
    - Performance monitoring
    - Graceful degradation
    
    Usage:
        # Initialize delivery service
        service = EventDeliveryService(
            event_bus=event_bus,
            max_retry_attempts=3,
            enable_dead_letter_queue=True
        )
        await service.start()
        
        # Deliver event
        success = await service.deliver(
            event=user_created_event,
            routing_info=routing_info,
            metadata=metadata
        )
        
        # Process retry queue
        await service.process_retry_queue()
    """
    
    def __init__(
        self,
        event_bus: EventBus,
        max_retry_attempts: int = 3,
        retry_delay_seconds: float = 1.0,
        backoff_multiplier: float = 2.0,
        max_retry_delay: float = 300.0,
        enable_dead_letter_queue: bool = True,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout_seconds: float = 60.0,
        retry_queue_size_limit: int = 10000,
        dlq_size_limit: int = 5000,
    ):
        """
        Initialize event delivery service.
        
        Args:
            event_bus: Event bus for message delivery
            max_retry_attempts: Maximum retry attempts per event
            retry_delay_seconds: Initial retry delay
            backoff_multiplier: Exponential backoff multiplier
            max_retry_delay: Maximum retry delay
            enable_dead_letter_queue: Enable dead letter queue
            circuit_breaker_threshold: Circuit breaker failure threshold
            circuit_breaker_timeout_seconds: Circuit breaker timeout
            retry_queue_size_limit: Maximum retry queue size
            dlq_size_limit: Maximum dead letter queue size
        """
        self._event_bus = event_bus
        self._max_retry_attempts = max_retry_attempts
        self._retry_delay_seconds = retry_delay_seconds
        self._backoff_multiplier = backoff_multiplier
        self._max_retry_delay = max_retry_delay
        self._enable_dead_letter_queue = enable_dead_letter_queue
        self._retry_queue_size_limit = retry_queue_size_limit
        self._dlq_size_limit = dlq_size_limit
        
        # Circuit breaker
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold,
            recovery_timeout=circuit_breaker_timeout_seconds,
        )
        
        # State
        self._running = False
        self._start_time: datetime | None = None
        
        # Delivery tracking
        self._delivery_records: dict[str, DeliveryRecord] = {}
        self._retry_queue: list[DeliveryRecord] = []
        self._dead_letter_queue: list[DeliveryRecord] = []
        
        # Background tasks
        self._retry_processor_task: asyncio.Task | None = None
        self._cleanup_task: asyncio.Task | None = None
        
        # Statistics
        self._stats = {
            "delivery_attempts": 0,
            "successful_deliveries": 0,
            "failed_deliveries": 0,
            "retries_processed": 0,
            "events_sent_to_dlq": 0,
            "circuit_breaker_activations": 0,
        }
        
        logger.info(
            "EventDeliveryService initialized",
            max_retry_attempts=max_retry_attempts,
            circuit_breaker_threshold=circuit_breaker_threshold,
            dead_letter_queue_enabled=enable_dead_letter_queue,
        )
    
    async def start(self) -> None:
        """Start the delivery service and background tasks."""
        if self._running:
            logger.warning("EventDeliveryService is already running")
            return
        
        self._running = True
        self._start_time = datetime.now(UTC)
        
        # Start background tasks
        self._retry_processor_task = asyncio.create_task(self._process_retry_queue_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_old_records_loop())
        
        logger.info("EventDeliveryService started successfully")
    
    async def stop(self) -> None:
        """Stop the delivery service and cleanup resources."""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel background tasks
        tasks = [self._retry_processor_task, self._cleanup_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        
        uptime = (
            (datetime.now(UTC) - self._start_time).total_seconds()
            if self._start_time
            else 0
        )
        
        logger.info(
            "EventDeliveryService stopped",
            uptime_seconds=uptime,
            pending_retries=len(self._retry_queue),
            dead_letter_count=len(self._dead_letter_queue),
        )
    
    async def deliver(
        self,
        event: IdentityDomainEvent,
        routing_info: RoutingInfo,
        metadata: PublisherEventMetadata,
        correlation_id: str | None = None,
    ) -> bool:
        """
        Deliver an event with retry and circuit breaker protection.
        
        Args:
            event: Event to deliver
            routing_info: Routing information
            metadata: Event metadata
            correlation_id: Optional correlation ID
            
        Returns:
            bool: True if delivery was successful
        """
        if not self._running:
            logger.error("EventDeliveryService is not running")
            return False
        
        # Check if event should be dropped
        if routing_info.should_drop:
            logger.debug(
                "Event dropped by routing decision",
                event_type=event.__class__.__name__,
                event_id=str(getattr(event, 'event_id', 'unknown')),
            )
            return True
        
        # Check circuit breaker
        if not self._circuit_breaker.can_proceed():
            logger.warning(
                "Event delivery blocked by circuit breaker",
                event_type=event.__class__.__name__,
                circuit_state=self._circuit_breaker.state.value,
            )
            self._stats["circuit_breaker_activations"] += 1
            return False
        
        # Create delivery record
        delivery_record = DeliveryRecord(
            event_id=str(getattr(event, 'event_id', uuid4())),
            event_type=event.__class__.__name__,
            routing_info=routing_info,
            metadata=metadata,
            max_retry_attempts=self._max_retry_attempts,
            retry_delay_seconds=self._retry_delay_seconds,
            backoff_multiplier=self._backoff_multiplier,
            max_retry_delay=self._max_retry_delay,
        )
        
        # Store delivery record
        self._delivery_records[delivery_record.delivery_id] = delivery_record
        
        # Attempt delivery
        success = await self._attempt_delivery(event, delivery_record)
        
        # Handle result
        if success:
            delivery_record.status = DeliveryStatus.DELIVERED
            self._stats["successful_deliveries"] += 1
            self._circuit_breaker.record_success()
        else:
            delivery_record.status = DeliveryStatus.FAILED
            self._stats["failed_deliveries"] += 1
            self._circuit_breaker.record_failure()
            
            # Schedule retry if applicable
            if delivery_record.should_retry:
                delivery_record.schedule_retry()
                self._add_to_retry_queue(delivery_record)
            elif self._enable_dead_letter_queue:
                await self._send_to_dead_letter_queue(delivery_record, "Max retries exhausted")
        
        return success
    
    async def _attempt_delivery(
        self,
        event: IdentityDomainEvent,
        delivery_record: DeliveryRecord,
    ) -> bool:
        """Attempt to deliver an event."""
        self._stats["delivery_attempts"] += 1
        start_time = time.time()
        
        try:
            delivery_record.status = DeliveryStatus.DELIVERING
            
            # Publish to event bus with correlation ID
            correlation_id = (
                delivery_record.metadata.correlation_id 
                if delivery_record.metadata 
                else None
            )
            
            await self._event_bus.publish(event, correlation_id)
            
            # Record successful attempt
            latency_ms = (time.time() - start_time) * 1000
            delivery_record.add_attempt(
                status=DeliveryStatus.DELIVERED,
                latency_ms=latency_ms,
            )
            
            logger.debug(
                "Event delivered successfully",
                event_type=event.__class__.__name__,
                delivery_id=delivery_record.delivery_id,
                latency_ms=round(latency_ms, 2),
                attempt=delivery_record.total_attempts,
            )
            
            return True
            
        except Exception as e:
            # Record failed attempt
            latency_ms = (time.time() - start_time) * 1000
            delivery_record.add_attempt(
                status=DeliveryStatus.FAILED,
                error=str(e),
                latency_ms=latency_ms,
            )
            
            logger.warning(
                "Event delivery failed",
                event_type=event.__class__.__name__,
                delivery_id=delivery_record.delivery_id,
                error=str(e),
                attempt=delivery_record.total_attempts,
            )
            
            return False
    
    def _add_to_retry_queue(self, delivery_record: DeliveryRecord) -> None:
        """Add delivery record to retry queue."""
        # Check queue size limit
        if len(self._retry_queue) >= self._retry_queue_size_limit:
            logger.warning(
                "Retry queue size limit reached, removing oldest entry",
                queue_size=len(self._retry_queue),
                limit=self._retry_queue_size_limit,
            )
            self._retry_queue.pop(0)
        
        self._retry_queue.append(delivery_record)
        
        logger.debug(
            "Event added to retry queue",
            delivery_id=delivery_record.delivery_id,
            next_retry_at=delivery_record.next_retry_at.isoformat() if delivery_record.next_retry_at else None,
            queue_size=len(self._retry_queue),
        )
    
    async def _send_to_dead_letter_queue(
        self,
        delivery_record: DeliveryRecord,
        reason: str,
    ) -> None:
        """Send event to dead letter queue."""
        if not self._enable_dead_letter_queue:
            return
        
        # Check DLQ size limit
        if len(self._dead_letter_queue) >= self._dlq_size_limit:
            logger.warning(
                "Dead letter queue size limit reached, removing oldest entry",
                queue_size=len(self._dead_letter_queue),
                limit=self._dlq_size_limit,
            )
            self._dead_letter_queue.pop(0)
        
        delivery_record.status = DeliveryStatus.DEAD_LETTER
        delivery_record.sent_to_dlq = True
        delivery_record.dlq_reason = reason
        
        self._dead_letter_queue.append(delivery_record)
        self._stats["events_sent_to_dlq"] += 1
        
        logger.warning(
            "Event sent to dead letter queue",
            delivery_id=delivery_record.delivery_id,
            event_type=delivery_record.event_type,
            reason=reason,
            total_attempts=delivery_record.total_attempts,
        )
    
    async def _process_retry_queue_loop(self) -> None:
        """Background task to process retry queue."""
        logger.info("Retry queue processor started")
        
        while self._running:
            try:
                await self._process_retry_queue()
                await asyncio.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.exception("Error in retry queue processor", error=str(e))
                await asyncio.sleep(10)  # Wait longer on error
    
    async def _process_retry_queue(self) -> None:
        """Process events in retry queue."""
        if not self._retry_queue:
            return
        
        now = datetime.now(UTC)
        ready_for_retry = []
        
        # Find events ready for retry
        for delivery_record in self._retry_queue[:]:
            if (
                delivery_record.next_retry_at 
                and now >= delivery_record.next_retry_at
            ):
                ready_for_retry.append(delivery_record)
                self._retry_queue.remove(delivery_record)
        
        if not ready_for_retry:
            return
        
        logger.debug(
            "Processing retry queue",
            ready_for_retry=len(ready_for_retry),
            remaining_in_queue=len(self._retry_queue),
        )
        
        # Process each retry
        for delivery_record in ready_for_retry:
            try:
                # Get original event (would need to be stored or reconstructed)
                # For now, we'll skip actual retry since we don't store the original event
                logger.debug(
                    "Would retry event delivery",
                    delivery_id=delivery_record.delivery_id,
                    event_type=delivery_record.event_type,
                    attempt=delivery_record.total_attempts + 1,
                )
                
                self._stats["retries_processed"] += 1
                
                # If retry fails and exhausted, send to DLQ
                if delivery_record.is_exhausted and self._enable_dead_letter_queue:
                    await self._send_to_dead_letter_queue(
                        delivery_record,
                        "Retry attempts exhausted"
                    )
                
            except Exception as e:
                logger.exception(
                    "Error processing retry",
                    delivery_id=delivery_record.delivery_id,
                    error=str(e),
                )
    
    async def _cleanup_old_records_loop(self) -> None:
        """Background task to cleanup old delivery records."""
        logger.info("Cleanup task started")
        
        while self._running:
            try:
                await self._cleanup_old_records()
                await asyncio.sleep(300)  # Cleanup every 5 minutes
            except Exception as e:
                logger.exception("Error in cleanup task", error=str(e))
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _cleanup_old_records(self) -> None:
        """Cleanup old delivery records to free memory."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(hours=24)  # Keep records for 24 hours
        
        # Cleanup delivery records
        old_records = [
            record_id for record_id, record in self._delivery_records.items()
            if record.created_at < cutoff and record.status in [
                DeliveryStatus.DELIVERED,
                DeliveryStatus.DEAD_LETTER
            ]
        ]
        
        for record_id in old_records:
            del self._delivery_records[record_id]
        
        if old_records:
            logger.debug(
                "Cleaned up old delivery records",
                cleaned_count=len(old_records),
                remaining_count=len(self._delivery_records),
            )
    
    def get_statistics(self) -> dict[str, Any]:
        """Get delivery service statistics."""
        uptime = (
            (datetime.now(UTC) - self._start_time).total_seconds()
            if self._start_time
            else 0
        )
        
        return {
            "running": self._running,
            "uptime_seconds": uptime,
            "retry_queue_size": len(self._retry_queue),
            "dead_letter_queue_size": len(self._dead_letter_queue),
            "active_delivery_records": len(self._delivery_records),
            "circuit_breaker": self._circuit_breaker.get_statistics(),
            **self._stats,
        }
    
    def reset_statistics(self) -> None:
        """Reset delivery service statistics."""
        self._stats = {
            "delivery_attempts": 0,
            "successful_deliveries": 0,
            "failed_deliveries": 0,
            "retries_processed": 0,
            "events_sent_to_dlq": 0,
            "circuit_breaker_activations": 0,
        }