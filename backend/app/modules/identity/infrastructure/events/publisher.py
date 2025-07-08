"""
Event Publisher Implementation

Main interface for publishing domain events with comprehensive routing, delivery,
retry mechanisms, and monitoring support.
"""

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from app.core.events.bus import EventBus, create_event_bus
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

from .batch import EventBatch
from .delivery import EventDeliveryService
from .metadata import EventMetadata as PublisherEventMetadata
from .router import EventRouter
from .serializer import EventSerializer

logger = get_logger(__name__)


class EventPublisherError(Exception):
    """Base exception for event publisher operations."""


class EventPublisher:
    """
    Main event publisher interface for the identity module.
    
    Provides comprehensive event publishing with routing, delivery guarantees,
    retry mechanisms, dead letter queues, and comprehensive monitoring.
    
    Features:
    - Synchronous and asynchronous event publishing
    - Event routing based on event type and configuration
    - Retry mechanisms with exponential backoff
    - Dead letter queue for failed events
    - Event deduplication
    - Batch processing for performance
    - Transaction support
    - Circuit breaker pattern
    - Comprehensive metrics and monitoring
    
    Usage:
        # Initialize publisher
        publisher = EventPublisher(
            event_bus=event_bus,
            enable_dead_letter_queue=True,
            enable_deduplication=True
        )
        await publisher.start()
        
        # Publish single event
        await publisher.publish(UserCreated(user_id=user_id, email=email))
        
        # Publish multiple events
        events = [UserCreated(...), ProfileUpdated(...)]
        await publisher.publish_batch(events)
        
        # Publish with transaction support
        async with publisher.transaction() as tx:
            await tx.publish(UserCreated(...))
            await tx.publish(ProfileUpdated(...))
            # Events published only on successful completion
    """
    
    def __init__(
        self,
        event_bus: EventBus | None = None,
        enable_dead_letter_queue: bool = True,
        enable_deduplication: bool = True,
        enable_metrics: bool = True,
        max_retry_attempts: int = 3,
        retry_delay_seconds: float = 1.0,
        batch_size: int = 100,
        deduplication_window_seconds: int = 300,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout_seconds: int = 60,
    ):
        """
        Initialize event publisher.
        
        Args:
            event_bus: Event bus instance (creates default if None)
            enable_dead_letter_queue: Enable dead letter queue for failed events
            enable_deduplication: Enable event deduplication
            enable_metrics: Enable metrics collection
            max_retry_attempts: Maximum retry attempts for failed events
            retry_delay_seconds: Initial retry delay
            batch_size: Default batch size for batch operations
            deduplication_window_seconds: Deduplication window in seconds
            circuit_breaker_threshold: Circuit breaker failure threshold
            circuit_breaker_timeout_seconds: Circuit breaker timeout
        """
        self._event_bus = event_bus or create_event_bus("hybrid")
        self._router = EventRouter()
        self._serializer = EventSerializer()
        self._delivery_service = EventDeliveryService(
            event_bus=self._event_bus,
            max_retry_attempts=max_retry_attempts,
            retry_delay_seconds=retry_delay_seconds,
            enable_dead_letter_queue=enable_dead_letter_queue,
            circuit_breaker_threshold=circuit_breaker_threshold,
            circuit_breaker_timeout_seconds=circuit_breaker_timeout_seconds,
        )
        
        # Configuration
        self._enable_deduplication = enable_deduplication
        self._enable_metrics = enable_metrics
        self._batch_size = batch_size
        self._deduplication_window = timedelta(seconds=deduplication_window_seconds)
        
        # State
        self._running = False
        self._start_time: datetime | None = None
        self._published_events_count = 0
        self._failed_events_count = 0
        
        # Deduplication cache (event_id -> timestamp)
        self._deduplication_cache: dict[str, datetime] = {}
        self._cache_cleanup_task: asyncio.Task | None = None
        
        # Transaction support
        self._current_transaction: EventTransaction | None = None
        
        logger.info(
            "EventPublisher initialized",
            enable_dead_letter_queue=enable_dead_letter_queue,
            enable_deduplication=enable_deduplication,
            max_retry_attempts=max_retry_attempts,
            batch_size=batch_size,
        )
    
    async def start(self) -> None:
        """
        Start the event publisher and all its components.
        
        Raises:
            EventPublisherError: If startup fails
        """
        if self._running:
            raise EventPublisherError("Event publisher is already running")
        
        try:
            # Start event bus
            await self._event_bus.start()
            
            # Start delivery service
            await self._delivery_service.start()
            
            # Start cache cleanup task
            if self._enable_deduplication:
                self._cache_cleanup_task = asyncio.create_task(
                    self._cleanup_deduplication_cache()
                )
            
            self._running = True
            self._start_time = datetime.utcnow()
            
            logger.info(
                "Event publisher started successfully",
                start_time=self._start_time.isoformat(),
            )
            
        except Exception as e:
            logger.exception("Failed to start event publisher", error=str(e))
            raise EventPublisherError(f"Failed to start event publisher: {e}") from e
    
    async def stop(self) -> None:
        """Stop the event publisher and cleanup resources."""
        if not self._running:
            return
        
        self._running = False
        
        try:
            # Stop cache cleanup task
            if self._cache_cleanup_task and not self._cache_cleanup_task.done():
                self._cache_cleanup_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._cache_cleanup_task
            
            # Stop delivery service
            await self._delivery_service.stop()
            
            # Stop event bus
            await self._event_bus.stop()
            
            uptime = (
                (datetime.utcnow() - self._start_time).total_seconds()
                if self._start_time
                else 0
            )
            
            logger.info(
                "Event publisher stopped",
                uptime_seconds=uptime,
                published_events=self._published_events_count,
                failed_events=self._failed_events_count,
            )
            
        except Exception as e:
            logger.warning("Error during event publisher shutdown", error=str(e))
    
    async def publish(
        self,
        event: IdentityDomainEvent,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Publish a single domain event.
        
        Args:
            event: Domain event to publish
            correlation_id: Optional correlation ID for tracing
            metadata: Additional metadata for the event
            
        Returns:
            bool: True if event was published successfully
            
        Raises:
            EventPublisherError: If publisher is not running or event is invalid
        """
        if not self._running:
            raise EventPublisherError("Event publisher is not running")
        
        if not isinstance(event, IdentityDomainEvent):
            raise EventPublisherError(
                f"Event must be an IdentityDomainEvent, got {type(event)}"
            )
        
        # Check if we're in a transaction
        if self._current_transaction:
            return await self._current_transaction.add_event(event, correlation_id, metadata)
        
        # Create publisher metadata
        pub_metadata = PublisherEventMetadata.create(
            event=event,
            correlation_id=correlation_id,
            additional_metadata=metadata or {},
        )
        
        # Check deduplication
        if self._enable_deduplication and self._is_duplicate(event):
            logger.debug(
                "Skipping duplicate event",
                event_type=event.__class__.__name__,
                event_id=str(event.event_id),
            )
            return True
        
        try:
            # Route and deliver event
            routing_info = self._router.route(event)
            success = await self._delivery_service.deliver(
                event=event,
                routing_info=routing_info,
                metadata=pub_metadata,
                correlation_id=correlation_id,
            )
            
            if success:
                self._published_events_count += 1
                if self._enable_deduplication:
                    self._add_to_deduplication_cache(event)
                
                logger.debug(
                    "Event published successfully",
                    event_type=event.__class__.__name__,
                    event_id=str(event.event_id),
                    correlation_id=correlation_id,
                )
            else:
                self._failed_events_count += 1
                logger.warning(
                    "Event publishing failed",
                    event_type=event.__class__.__name__,
                    event_id=str(event.event_id),
                    correlation_id=correlation_id,
                )
            
            return success
            
        except Exception as e:
            self._failed_events_count += 1
            logger.exception(
                "Exception during event publishing",
                event_type=event.__class__.__name__,
                event_id=str(event.event_id),
                error=str(e),
            )
            return False
    
    async def publish_batch(
        self,
        events: list[IdentityDomainEvent],
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Publish multiple events in a batch.
        
        Args:
            events: List of domain events to publish
            correlation_id: Optional correlation ID for tracing
            metadata: Additional metadata for all events
            
        Returns:
            dict: Publishing results with success/failure counts
        """
        if not self._running:
            raise EventPublisherError("Event publisher is not running")
        
        if not events:
            return {"total": 0, "successful": 0, "failed": 0, "skipped": 0}
        
        # Create event batch
        batch = EventBatch(
            events=events,
            batch_size=self._batch_size,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )
        
        results = {"total": len(events), "successful": 0, "failed": 0, "skipped": 0}
        
        logger.info(
            "Starting batch event publishing",
            total_events=len(events),
            batch_size=self._batch_size,
            correlation_id=correlation_id,
        )
        
        # Process events in batches
        async for batch_events in batch.get_batches():
            batch_results = await asyncio.gather(
                *[
                    self.publish(event, correlation_id, metadata)
                    for event in batch_events
                ],
                return_exceptions=True,
            )
            
            # Count results
            for result in batch_results:
                if isinstance(result, Exception):
                    results["failed"] += 1
                elif result is True:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
        
        logger.info(
            "Batch event publishing completed",
            **results,
            correlation_id=correlation_id,
        )
        
        return results
    
    @asynccontextmanager
    async def transaction(self):
        """
        Create a transaction context for event publishing.
        
        Events published within the transaction are buffered and only
        published when the transaction completes successfully.
        
        Usage:
            async with publisher.transaction() as tx:
                await tx.publish(UserCreated(...))
                await tx.publish(ProfileUpdated(...))
                # Events published only on successful completion
        """
        if self._current_transaction:
            raise EventPublisherError("Nested transactions are not supported")
        
        transaction = EventTransaction(self)
        self._current_transaction = transaction
        
        try:
            yield transaction
            # Commit transaction - publish all buffered events
            await transaction.commit()
        except Exception as e:
            # Rollback transaction - discard buffered events
            await transaction.rollback()
            logger.warning(
                "Transaction rolled back due to exception",
                error=str(e),
                buffered_events=len(transaction._buffered_events),
            )
            raise
        finally:
            self._current_transaction = None
    
    def _is_duplicate(self, event: IdentityDomainEvent) -> bool:
        """Check if event is a duplicate within the deduplication window."""
        if not self._enable_deduplication:
            return False
        
        event_key = f"{event.__class__.__name__}:{event.event_id}"
        last_seen = self._deduplication_cache.get(event_key)
        
        if last_seen is None:
            return False
        
        # Check if within deduplication window
        age = datetime.utcnow() - last_seen
        return age < self._deduplication_window
    
    def _add_to_deduplication_cache(self, event: IdentityDomainEvent) -> None:
        """Add event to deduplication cache."""
        if not self._enable_deduplication:
            return
        
        event_key = f"{event.__class__.__name__}:{event.event_id}"
        self._deduplication_cache[event_key] = datetime.utcnow()
    
    async def _cleanup_deduplication_cache(self) -> None:
        """Periodically cleanup expired entries from deduplication cache."""
        while self._running:
            try:
                now = datetime.utcnow()
                expired_keys = [
                    key
                    for key, timestamp in self._deduplication_cache.items()
                    if now - timestamp > self._deduplication_window
                ]
                
                for key in expired_keys:
                    del self._deduplication_cache[key]
                
                if expired_keys:
                    logger.debug(
                        "Cleaned up deduplication cache",
                        expired_entries=len(expired_keys),
                        remaining_entries=len(self._deduplication_cache),
                    )
                
                # Sleep for half the deduplication window
                await asyncio.sleep(self._deduplication_window.total_seconds() / 2)
                
            except Exception as e:
                logger.exception("Error in deduplication cache cleanup", error=str(e))
                await asyncio.sleep(60)  # Wait before retrying
    
    def get_statistics(self) -> dict[str, Any]:
        """Get publisher statistics for monitoring."""
        uptime = (
            (datetime.utcnow() - self._start_time).total_seconds()
            if self._start_time
            else 0
        )
        
        return {
            "running": self._running,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "uptime_seconds": uptime,
            "published_events": self._published_events_count,
            "failed_events": self._failed_events_count,
            "success_rate": (
                self._published_events_count
                / max(self._published_events_count + self._failed_events_count, 1)
            ),
            "deduplication_cache_size": len(self._deduplication_cache),
            "delivery_service_stats": self._delivery_service.get_statistics(),
        }


class EventTransaction:
    """
    Transaction context for event publishing.
    
    Buffers events and publishes them only when the transaction completes
    successfully. Provides transactional semantics for event publishing.
    """
    
    def __init__(self, publisher: EventPublisher):
        """Initialize transaction."""
        self._publisher = publisher
        self._buffered_events: list[tuple[IdentityDomainEvent, str | None, dict[str, Any] | None]] = []
        self._transaction_id = str(uuid4())
        self._committed = False
        self._rolled_back = False
    
    async def publish(
        self,
        event: IdentityDomainEvent,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Add event to transaction buffer.
        
        Args:
            event: Domain event to publish
            correlation_id: Optional correlation ID
            metadata: Additional metadata
        """
        if self._committed or self._rolled_back:
            raise EventPublisherError("Transaction has already been completed")
        
        self._buffered_events.append((event, correlation_id, metadata))
        
        logger.debug(
            "Event added to transaction",
            transaction_id=self._transaction_id,
            event_type=event.__class__.__name__,
            buffered_count=len(self._buffered_events),
        )
    
    async def add_event(
        self,
        event: IdentityDomainEvent,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Add event to transaction (alias for publish)."""
        await self.publish(event, correlation_id, metadata)
        return True
    
    async def commit(self) -> dict[str, Any]:
        """
        Commit transaction by publishing all buffered events.
        
        Returns:
            dict: Publishing results
        """
        if self._committed or self._rolled_back:
            raise EventPublisherError("Transaction has already been completed")
        
        if not self._buffered_events:
            self._committed = True
            return {"total": 0, "successful": 0, "failed": 0}
        
        logger.info(
            "Committing transaction",
            transaction_id=self._transaction_id,
            buffered_events=len(self._buffered_events),
        )
        
        # Temporarily clear current transaction to avoid recursion
        original_transaction = self._publisher._current_transaction
        self._publisher._current_transaction = None
        
        try:
            # Publish all buffered events
            results = {"total": len(self._buffered_events), "successful": 0, "failed": 0}
            
            for event, correlation_id, metadata in self._buffered_events:
                try:
                    success = await self._publisher.publish(event, correlation_id, metadata)
                    if success:
                        results["successful"] += 1
                    else:
                        results["failed"] += 1
                except Exception as e:
                    logger.exception(
                        "Failed to publish event in transaction commit",
                        transaction_id=self._transaction_id,
                        event_type=event.__class__.__name__,
                        error=str(e),
                    )
                    results["failed"] += 1
            
            self._committed = True
            
            logger.info(
                "Transaction committed",
                transaction_id=self._transaction_id,
                **results,
            )
            
            return results
            
        finally:
            # Restore transaction context
            self._publisher._current_transaction = original_transaction
    
    async def rollback(self) -> None:
        """Rollback transaction by discarding all buffered events."""
        if self._committed or self._rolled_back:
            return
        
        logger.info(
            "Rolling back transaction",
            transaction_id=self._transaction_id,
            discarded_events=len(self._buffered_events),
        )
        
        self._buffered_events.clear()
        self._rolled_back = True