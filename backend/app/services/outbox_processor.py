"""
OutboxProcessor Service

Background service to process outbox events with retry logic.
"""

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.models.outbox_event import OutboxEvent
from app.repositories.outbox_repository import OutboxRepository

logger = get_logger(__name__)


class EventBus:
    """
    Abstract event bus interface for publishing events.
    
    This interface should be implemented by concrete event bus adapters
    (e.g., RabbitMQ, Redis, Kafka, etc.).
    """
    
    async def publish(self, event: dict[str, Any]) -> None:
        """
        Publish domain event to event bus.
        
        Args:
            event: Domain event to publish
            
        Raises:
            Exception: If publishing fails
        """
        raise NotImplementedError("EventBus.publish must be implemented")


class RetryPolicy:
    """
    Retry policy for outbox event processing.
    
    Implements exponential backoff with jitter for retry delays.
    """
    
    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
        jitter: bool = True
    ):
        """
        Initialize retry policy.
        
        Args:
            base_delay: Base delay in seconds between retries
            max_delay: Maximum delay in seconds
            backoff_multiplier: Multiplier for exponential backoff
            jitter: Whether to add jitter to delays
        """
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.jitter = jitter
    
    def calculate_delay(self, retry_count: int) -> float:
        """
        Calculate delay for retry attempt.
        
        Args:
            retry_count: Current retry count
            
        Returns:
            Delay in seconds
        """
        import random
        
        # Calculate exponential backoff delay
        delay = self.base_delay * (self.backoff_multiplier ** retry_count)
        
        # Cap at maximum delay
        delay = min(delay, self.max_delay)
        
        # Add jitter to avoid thundering herd
        if self.jitter:
            delay = delay * (0.5 + random.random() * 0.5)
        
        return delay


class OutboxProcessor:
    """
    Background service to process outbox events.
    
    This service polls the outbox repository for unprocessed events
    and publishes them to the event bus with retry logic.
    """
    
    def __init__(
        self,
        outbox_repo: OutboxRepository,
        event_bus: EventBus,
        retry_policy: RetryPolicy | None = None,
        batch_size: int = 100,
        poll_interval: float = 5.0,
        max_concurrent_events: int = 10
    ):
        """
        Initialize outbox processor.
        
        Args:
            outbox_repo: Repository for outbox events
            event_bus: Event bus for publishing events
            retry_policy: Retry policy for failed events
            batch_size: Maximum events to process in one batch
            poll_interval: Interval between polling cycles in seconds
            max_concurrent_events: Maximum concurrent event processing
        """
        self.outbox_repo = outbox_repo
        self.event_bus = event_bus
        self.retry_policy = retry_policy or RetryPolicy()
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.max_concurrent_events = max_concurrent_events
        
        # Processing state
        self._running = False
        self._task: asyncio.Task | None = None
        self._semaphore = asyncio.Semaphore(max_concurrent_events)
    
    async def start(self) -> None:
        """
        Start the background processor.
        
        Starts polling for unprocessed events and processing them.
        """
        if self._running:
            logger.warning("OutboxProcessor already running")
            return
        
        self._running = True
        self._task = asyncio.create_task(self._processing_loop())
        
        logger.info(
            "OutboxProcessor started",
            batch_size=self.batch_size,
            poll_interval=self.poll_interval,
            max_concurrent_events=self.max_concurrent_events
        )
    
    async def stop(self) -> None:
        """
        Stop the background processor.
        
        Gracefully stops the processing loop and waits for completion.
        """
        if not self._running:
            logger.warning("OutboxProcessor not running")
            return
        
        self._running = False
        
        if self._task:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("OutboxProcessor stopped")
    
    async def _processing_loop(self) -> None:
        """
        Main processing loop for outbox events.
        
        Continuously polls for unprocessed events and processes them.
        """
        logger.info("Starting outbox processing loop")
        
        while self._running:
            try:
                # Get unprocessed events
                events = await self.outbox_repo.get_unprocessed_events(
                    limit=self.batch_size
                )
                
                if events:
                    logger.debug(
                        "Processing outbox events batch",
                        event_count=len(events)
                    )
                    
                    # Process events concurrently
                    tasks = []
                    for event in events:
                        task = asyncio.create_task(
                            self._process_event_with_semaphore(event)
                        )
                        tasks.append(task)
                    
                    # Wait for all events to be processed
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
                    logger.debug(
                        "Completed processing outbox events batch",
                        event_count=len(events)
                    )
                else:
                    logger.debug("No unprocessed events found")
                
                # Wait before next poll
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                logger.exception(
                    "Error in outbox processing loop",
                    error=str(e)
                )
                # Wait before retrying
                await asyncio.sleep(self.poll_interval)
    
    async def _process_event_with_semaphore(self, event: OutboxEvent) -> None:
        """
        Process event with semaphore for concurrency control.
        
        Args:
            event: Event to process
        """
        async with self._semaphore:
            await self._process_event(event)
    
    async def _process_event(self, event: OutboxEvent) -> None:
        """
        Process a single outbox event.
        
        Attempts to publish the event to the event bus and handles
        success/failure accordingly.
        
        Args:
            event: Event to process
        """
        try:
            logger.debug(
                "Processing outbox event",
                event_id=str(event.id),
                event_type=event.event_type,
                retry_count=event.retry_count
            )
            
            # Convert to domain event format
            domain_event = event.to_domain_event()
            
            # Publish to event bus
            await self.event_bus.publish(domain_event)
            
            # Mark as processed
            await self.outbox_repo.mark_processed(event.id)
            
            logger.debug(
                "Successfully processed outbox event",
                event_id=str(event.id),
                event_type=event.event_type
            )
            
        except Exception as e:
            logger.exception(
                "Failed to process outbox event",
                event_id=str(event.id),
                event_type=event.event_type,
                retry_count=event.retry_count,
                error=str(e)
            )
            
            # Increment retry count
            await self.outbox_repo.increment_retry(event.id, str(e))
            
            # Apply retry delay if event can still be retried
            if event.can_retry():
                delay = self.retry_policy.calculate_delay(event.retry_count)
                logger.debug(
                    "Applying retry delay",
                    event_id=str(event.id),
                    retry_count=event.retry_count,
                    delay=delay
                )
                await asyncio.sleep(delay)
            else:
                logger.warning(
                    "Event exhausted retries",
                    event_id=str(event.id),
                    event_type=event.event_type,
                    retry_count=event.retry_count,
                    max_retries=event.max_retries
                )
    
    async def process_events(self) -> None:
        """
        Process unprocessed events from outbox (one-time processing).
        
        This method can be called directly for one-time processing
        without starting the background loop.
        """
        logger.info("Starting one-time outbox event processing")
        
        events = await self.outbox_repo.get_unprocessed_events(
            limit=self.batch_size
        )
        
        if not events:
            logger.info("No unprocessed events found")
            return
        
        logger.info(
            "Processing outbox events",
            event_count=len(events)
        )
        
        # Process events concurrently
        tasks = []
        for event in events:
            task = asyncio.create_task(
                self._process_event_with_semaphore(event)
            )
            tasks.append(task)
        
        # Wait for all events to be processed
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successes and failures
        successes = sum(1 for r in results if not isinstance(r, Exception))
        failures = len(results) - successes
        
        logger.info(
            "Completed one-time outbox event processing",
            total_events=len(events),
            successes=successes,
            failures=failures
        )
    
    async def get_failed_events(self) -> list[OutboxEvent]:
        """
        Get events that have exhausted retries.
        
        Returns:
            List of failed events
        """
        return await self.outbox_repo.get_failed_events()
    
    async def cleanup_processed_events(self, older_than_days: int = 30) -> int:
        """
        Clean up processed events older than specified days.
        
        Args:
            older_than_days: Remove events processed more than this many days ago
            
        Returns:
            Number of events deleted
        """
        return await self.outbox_repo.cleanup_processed_events(older_than_days)
    
    @property
    def is_running(self) -> bool:
        """Check if processor is running."""
        return self._running