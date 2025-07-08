"""Event handlers following pure Python principles.

This module provides comprehensive event handler infrastructure for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are completely
independent of any framework (Pydantic, FastAPI, etc.).

The event handler system supports synchronous and asynchronous handlers, batch processing,
compensation logic, and comprehensive error handling with performance monitoring.

Design Principles:
- Pure Python classes with explicit validation
- Framework-agnostic design for maximum portability
- Comprehensive error handling and recovery
- Performance monitoring and metrics collection
- Flexible handler lifecycle management
- Security-focused handler isolation
- Configurable processing strategies
- Rich debugging and observability

Architecture:
- HandlerConfig: Configuration management with validation
- EventHandler: Base handler interface with lifecycle management
- AsyncEventHandler: Asynchronous event handler with concurrency control
- BatchEventHandler: Batch processing with configurable strategies
- CompensatingEventHandler: Handler with compensation logic
- HandlerMetrics: Performance monitoring and statistics
- HandlerRegistry: Handler registration and discovery
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Generic, TypeVar

from app.core.errors import ConfigurationError, InfrastructureError, ValidationError
from app.core.events.types import DomainEvent
from app.core.logging import get_logger

logger = get_logger(__name__)

TEvent = TypeVar("TEvent", bound=DomainEvent)


# =====================================================================================
# ENUMS AND CONSTANTS
# =====================================================================================


class HandlerPriority(Enum):
    """Handler execution priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class HandlerState(Enum):
    """Handler execution states."""

    IDLE = "idle"
    PROCESSING = "processing"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"


class BatchStrategy(Enum):
    """Batch processing strategies."""

    SIZE_BASED = "size_based"
    TIME_BASED = "time_based"
    HYBRID = "hybrid"


class CompensationStrategy(Enum):
    """Compensation execution strategies."""

    IMMEDIATE = "immediate"
    DELAYED = "delayed"
    MANUAL = "manual"


# =====================================================================================
# CONFIGURATION CLASSES
# =====================================================================================


@dataclass
class HandlerConfig:
    """
    Event handler configuration with comprehensive validation.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Performance optimization settings
    - Error handling configuration
    - Security and isolation settings
    - Framework-agnostic implementation

    Usage Example:
        config = HandlerConfig(
            max_concurrent_events=10,
            timeout_seconds=30,
            retry_attempts=3,
            enable_metrics=True
        )

        # Validate configuration
        config.validate()
    """

    # Performance settings
    max_concurrent_events: int = field(default=5)
    timeout_seconds: int = field(default=30)
    batch_size: int = field(default=100)
    batch_timeout_seconds: float = field(default=1.0)

    # Error handling
    retry_attempts: int = field(default=3)
    retry_delay_seconds: float = field(default=1.0)
    retry_backoff_multiplier: float = field(default=2.0)
    max_retry_delay: float = field(default=300.0)

    # Monitoring and metrics
    enable_metrics: bool = field(default=True)
    enable_performance_tracking: bool = field(default=True)
    enable_error_tracking: bool = field(default=True)

    # Handler behavior
    priority: HandlerPriority = field(default=HandlerPriority.NORMAL)
    enable_parallel_processing: bool = field(default=True)
    enable_circuit_breaker: bool = field(default=True)
    circuit_breaker_threshold: int = field(default=5)

    # Security settings
    enable_handler_isolation: bool = field(default=True)
    max_memory_usage_mb: int = field(default=100)
    max_processing_time_seconds: int = field(default=300)

    def __post_init__(self):
        """Post-initialization validation."""
        self.validate()

    def validate(self) -> None:
        """
        Validate handler configuration parameters.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        if self.max_concurrent_events < 1:
            raise ConfigurationError("max_concurrent_events must be at least 1")

        if self.timeout_seconds < 1:
            raise ConfigurationError("timeout_seconds must be at least 1")

        if self.batch_size < 1:
            raise ConfigurationError("batch_size must be at least 1")

        if self.batch_timeout_seconds <= 0:
            raise ConfigurationError("batch_timeout_seconds must be positive")

        if self.retry_attempts < 0:
            raise ConfigurationError("retry_attempts cannot be negative")

        if self.retry_delay_seconds <= 0:
            raise ConfigurationError("retry_delay_seconds must be positive")

        if self.retry_backoff_multiplier < 1:
            raise ConfigurationError("retry_backoff_multiplier must be at least 1")

        if self.circuit_breaker_threshold < 1:
            raise ConfigurationError("circuit_breaker_threshold must be at least 1")


@dataclass
class HandlerMetrics:
    """Handler performance metrics and statistics."""

    # Processing statistics
    total_events_processed: int = field(default=0)
    successful_events: int = field(default=0)
    failed_events: int = field(default=0)

    # Timing statistics
    total_processing_time: float = field(default=0.0)
    avg_processing_time: float = field(default=0.0)
    min_processing_time: float = field(default=float("inf"))
    max_processing_time: float = field(default=0.0)

    # Error statistics
    error_count: int = field(default=0)
    retry_count: int = field(default=0)
    compensation_count: int = field(default=0)

    # State tracking
    last_event_time: datetime | None = field(default=None)
    current_state: HandlerState = field(default=HandlerState.IDLE)
    circuit_breaker_trips: int = field(default=0)

    def update_processing_time(self, duration: float) -> None:
        """Update processing time statistics."""
        self.total_processing_time += duration
        self.total_events_processed += 1

        if self.total_events_processed > 0:
            self.avg_processing_time = (
                self.total_processing_time / self.total_events_processed
            )

        self.min_processing_time = min(self.min_processing_time, duration)
        self.max_processing_time = max(self.max_processing_time, duration)

    def record_success(self) -> None:
        """Record successful event processing."""
        self.successful_events += 1
        self.last_event_time = datetime.now(UTC)

    def record_failure(self) -> None:
        """Record failed event processing."""
        self.failed_events += 1
        self.error_count += 1

    def record_retry(self) -> None:
        """Record retry attempt."""
        self.retry_count += 1

    def record_compensation(self) -> None:
        """Record compensation execution."""
        self.compensation_count += 1

    def get_success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_events_processed == 0:
            return 0.0
        return self.successful_events / self.total_events_processed

    def get_error_rate(self) -> float:
        """Calculate error rate."""
        if self.total_events_processed == 0:
            return 0.0
        return self.failed_events / self.total_events_processed

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_events_processed": self.total_events_processed,
            "successful_events": self.successful_events,
            "failed_events": self.failed_events,
            "success_rate": self.get_success_rate(),
            "error_rate": self.get_error_rate(),
            "total_processing_time": self.total_processing_time,
            "avg_processing_time": self.avg_processing_time,
            "min_processing_time": self.min_processing_time
            if self.min_processing_time != float("inf")
            else 0.0,
            "max_processing_time": self.max_processing_time,
            "error_count": self.error_count,
            "retry_count": self.retry_count,
            "compensation_count": self.compensation_count,
            "last_event_time": self.last_event_time.isoformat()
            if self.last_event_time
            else None,
            "current_state": self.current_state.value,
            "circuit_breaker_trips": self.circuit_breaker_trips,
            "throughput_per_second": self.get_throughput_per_second(),
            "health_score": self.get_health_score(),
        }
    
    def get_throughput_per_second(self) -> float:
        """Calculate events processed per second."""
        if not self.last_event_time or self.total_processing_time == 0:
            return 0.0
        return self.total_events_processed / self.total_processing_time
    
    def get_health_score(self) -> float:
        """Calculate handler health score (0.0 to 1.0)."""
        if self.total_events_processed == 0:
            return 1.0
        
        success_rate = self.get_success_rate()
        error_rate = self.get_error_rate()
        
        # Base score from success rate
        health_score = success_rate
        
        # Penalize high error rates
        if error_rate > 0.1:  # More than 10% errors
            health_score *= 0.5
        
        # Penalize circuit breaker trips
        if self.circuit_breaker_trips > 0:
            health_score *= 0.8
        
        # Penalize if currently in error state
        if self.current_state == HandlerState.ERROR:
            health_score *= 0.6
        
        return max(0.0, min(1.0, health_score))


# =====================================================================================
# BASE EVENT HANDLER
# =====================================================================================


class EventHandler(ABC, Generic[TEvent]):
    """
    Base event handler following pure Python principles.

    Provides framework-agnostic event handling with comprehensive error handling,
    performance monitoring, and lifecycle management.

    Design Features:
    - Pure Python implementation
    - Comprehensive error handling and recovery
    - Performance monitoring and metrics
    - Configurable retry and timeout logic
    - Circuit breaker pattern support
    - Rich debugging and observability

    Usage Example:
        class UserRegisteredHandler(EventHandler[UserRegistered]):
            def __init__(self, user_service: UserService):
                super().__init__()
                self.user_service = user_service

            @property
            def event_type(self) -> Type[UserRegistered]:
                return UserRegistered

            async def handle_event(self, event: UserRegistered) -> None:
                await self.user_service.send_welcome_email(event.user_id)

        # Use handler
        handler = UserRegisteredHandler(user_service)
        await handler.process_event(event)
    """

    def __init__(self, config: HandlerConfig = None):
        """
        Initialize event handler.

        Args:
            config: Handler configuration
        """
        self.config = config or HandlerConfig()
        self.metrics = HandlerMetrics()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_events)
        self._circuit_breaker_failures = 0
        self._circuit_breaker_last_failure: datetime | None = None

        logger.debug(
            "Event handler initialized",
            handler_class=self.__class__.__name__,
            config=self.config.__dict__,
        )

    @property
    @abstractmethod
    def event_type(self) -> type[TEvent]:
        """
        The event type this handler processes.

        Returns:
            Type[TEvent]: Event type class
        """

    @abstractmethod
    async def handle_event(self, event: TEvent) -> None:
        """
        Handle the event (must be implemented by subclasses).

        Args:
            event: Event to handle

        Raises:
            Any: Handler-specific exceptions
        """

    async def process_event(self, event: TEvent) -> None:
        """
        Process event with full lifecycle management.

        Args:
            event: Event to process

        Raises:
            InfrastructureError: If processing fails after retries
        """
        # Validate event type
        if not isinstance(event, self.event_type):
            raise ValidationError(
                f"Expected {self.event_type.__name__}, got {type(event).__name__}"
            )

        # Check circuit breaker
        if self._is_circuit_breaker_open():
            logger.warning(
                "Circuit breaker is open, skipping event",
                handler=self.__class__.__name__,
                event_id=str(getattr(event, 'event_id', 'unknown')),
            )
            raise InfrastructureError("Circuit breaker is open")

        # Check handler health before processing
        if self.metrics.get_health_score() < 0.3:
            logger.warning(
                "Handler health is poor, consider investigation",
                handler=self.__class__.__name__,
                health_score=self.metrics.get_health_score(),
                event_id=str(getattr(event, 'event_id', 'unknown')),
            )

        # Acquire semaphore for concurrency control
        async with self._semaphore:
            await self._process_with_retry(event)

    async def _process_with_retry(self, event: TEvent) -> None:
        """Process event with retry logic."""
        last_exception = None

        for attempt in range(self.config.retry_attempts + 1):
            try:
                await self._process_single_event(event)

                # Reset circuit breaker on success
                self._circuit_breaker_failures = 0
                return

            except Exception as e:
                last_exception = e
                self.metrics.record_failure()
                self._circuit_breaker_failures += 1
                self._circuit_breaker_last_failure = datetime.now(UTC)

                if attempt < self.config.retry_attempts:
                    # Calculate retry delay with backoff
                    delay = min(
                        self.config.retry_delay_seconds
                        * (self.config.retry_backoff_multiplier**attempt),
                        self.config.max_retry_delay,
                    )

                    self.metrics.record_retry()

                    logger.warning(
                        "Event processing failed, retrying",
                        handler=self.__class__.__name__,
                        event_id=str(event.event_id),
                        attempt=attempt + 1,
                        max_attempts=self.config.retry_attempts + 1,
                        delay=delay,
                        error=str(e),
                    )

                    await asyncio.sleep(delay)
                else:
                    logger.exception(
                        "Event processing failed after all retries",
                        handler=self.__class__.__name__,
                        event_id=str(event.event_id),
                        attempts=attempt + 1,
                        error=str(e),
                    )

        # All retries exhausted
        if last_exception:
            raise InfrastructureError(
                f"Event processing failed after {self.config.retry_attempts + 1} attempts: {last_exception}"
            )

    async def _process_single_event(self, event: TEvent) -> None:
        """Process a single event with timeout and monitoring."""
        start_time = time.time()
        self.metrics.current_state = HandlerState.PROCESSING

        try:
            # Process with timeout
            await asyncio.wait_for(
                self.handle_event(event), timeout=self.config.timeout_seconds
            )

            # Record success
            processing_time = time.time() - start_time
            self.metrics.update_processing_time(processing_time)
            self.metrics.record_success()
            self.metrics.current_state = HandlerState.IDLE

            logger.debug(
                "Event processed successfully",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                processing_time=processing_time,
            )

        except TimeoutError:
            processing_time = time.time() - start_time
            self.metrics.current_state = HandlerState.ERROR

            logger.exception(
                "Event processing timed out",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                timeout=self.config.timeout_seconds,
                processing_time=processing_time,
            )
            raise InfrastructureError(
                f"Event processing timed out after {self.config.timeout_seconds} seconds"
            )

        except Exception as e:
            processing_time = time.time() - start_time
            self.metrics.current_state = HandlerState.ERROR

            logger.exception(
                "Event processing failed",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                processing_time=processing_time,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    def _is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open."""
        if not self.config.enable_circuit_breaker:
            return False

        if self._circuit_breaker_failures < self.config.circuit_breaker_threshold:
            return False

        # Check if enough time has passed to try again
        if self._circuit_breaker_last_failure:
            time_since_failure = datetime.now(UTC) - self._circuit_breaker_last_failure
            if time_since_failure > timedelta(minutes=5):  # 5-minute cooldown
                self._circuit_breaker_failures = 0
                return False

        return True

    def get_metrics(self) -> dict[str, Any]:
        """Get handler performance metrics."""
        return self.metrics.to_dict()

    def reset_metrics(self) -> None:
        """Reset handler metrics."""
        self.metrics = HandlerMetrics()

    def __str__(self) -> str:
        """String representation of handler."""
        return f"{self.__class__.__name__}(event_type={self.event_type.__name__})"


# =====================================================================================
# ASYNC EVENT HANDLER
# =====================================================================================


class AsyncEventHandler(EventHandler[TEvent]):
    """
    Asynchronous event handler with enhanced concurrency control.

    Provides advanced async processing capabilities with task management,
    background processing, and comprehensive monitoring.
    """

    def __init__(self, config: HandlerConfig = None):
        """Initialize async event handler."""
        super().__init__(config)
        self._background_tasks: set[asyncio.Task] = set()
        self._shutdown = False

    async def handle_event_async(self, event: TEvent) -> None:
        """
        Async event handling method (to be implemented by subclasses).

        Args:
            event: Event to handle
        """
        await self.handle_event(event)

    async def start_background_processing(self) -> None:
        """Start background processing tasks."""

    async def stop_background_processing(self) -> None:
        """Stop background processing tasks."""
        self._shutdown = True

        # Cancel all background tasks
        for task in self._background_tasks:
            task.cancel()

        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

        self._background_tasks.clear()

    def _create_background_task(self, coro) -> asyncio.Task:
        """Create and track a background task."""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task


# =====================================================================================
# BATCH EVENT HANDLER
# =====================================================================================


class BatchEventHandler(AsyncEventHandler[TEvent]):
    """
    Event handler with batch processing capabilities.

    Supports configurable batching strategies with size-based, time-based,
    and hybrid batching approaches.

    Design Features:
    - Multiple batching strategies
    - Configurable batch size and timeout
    - Automatic batch flushing
    - Performance optimization
    - Error handling per batch
    """

    def __init__(
        self,
        config: HandlerConfig = None,
        strategy: BatchStrategy = BatchStrategy.HYBRID,
    ):
        """Initialize batch event handler."""
        super().__init__(config)
        self.strategy = strategy
        self._batch: deque[TEvent] = deque()
        self._batch_lock = asyncio.Lock()
        self._last_flush_time = time.time()
        self._flush_task: asyncio.Task | None = None
        self._start_batch_processor()

    async def handle_event(self, event: TEvent) -> None:
        """Add event to batch for processing."""
        async with self._batch_lock:
            self._batch.append(event)

            # Check if we should flush based on strategy
            should_flush = False

            if self.strategy in [BatchStrategy.SIZE_BASED, BatchStrategy.HYBRID]:
                should_flush = len(self._batch) >= self.config.batch_size

            if should_flush:
                await self._flush_batch()

    @abstractmethod
    async def handle_batch(self, events: list[TEvent]) -> None:
        """
        Handle a batch of events (must be implemented by subclasses).

        Args:
            events: List of events to process
        """

    async def _flush_batch(self) -> None:
        """Flush current batch."""
        if not self._batch:
            return

        # Extract current batch
        current_batch = list(self._batch)
        self._batch.clear()
        self._last_flush_time = time.time()

        if not current_batch:
            return

        try:
            start_time = time.time()
            await self.handle_batch(current_batch)

            # Update metrics for all events in batch
            processing_time = time.time() - start_time
            for _ in current_batch:
                self.metrics.update_processing_time(
                    processing_time / len(current_batch)
                )
                self.metrics.record_success()

            logger.debug(
                "Batch processed successfully",
                handler=self.__class__.__name__,
                batch_size=len(current_batch),
                processing_time=processing_time,
            )

        except Exception as e:
            # Record failures for all events in batch
            for _event in current_batch:
                self.metrics.record_failure()

            logger.exception(
                "Batch processing failed",
                handler=self.__class__.__name__,
                batch_size=len(current_batch),
                error=str(e),
            )
            raise

    def _start_batch_processor(self) -> None:
        """Start background batch processor for time-based flushing."""
        if self.strategy in [BatchStrategy.TIME_BASED, BatchStrategy.HYBRID]:
            self._flush_task = self._create_background_task(self._batch_flush_loop())

    async def _batch_flush_loop(self) -> None:
        """Background loop for time-based batch flushing."""
        while not self._shutdown:
            try:
                await asyncio.sleep(self.config.batch_timeout_seconds)

                current_time = time.time()
                time_since_flush = current_time - self._last_flush_time

                if (
                    time_since_flush >= self.config.batch_timeout_seconds
                    and len(self._batch) > 0
                ):
                    async with self._batch_lock:
                        await self._flush_batch()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Batch flush loop error",
                    handler=self.__class__.__name__,
                    error=str(e),
                )
                await asyncio.sleep(1)

    async def force_flush(self) -> None:
        """Force immediate flush of current batch."""
        async with self._batch_lock:
            await self._flush_batch()

    async def stop_background_processing(self) -> None:
        """Stop batch processing and flush remaining events."""
        # Flush any remaining events
        await self.force_flush()

        # Stop background processing
        await super().stop_background_processing()


# =====================================================================================
# COMPENSATING EVENT HANDLER
# =====================================================================================


class CompensatingEventHandler(AsyncEventHandler[TEvent]):
    """
    Event handler with compensation logic for handling failures.

    Provides automatic compensation execution when event processing fails,
    supporting different compensation strategies and retry logic.

    Design Features:
    - Automatic compensation on failure
    - Multiple compensation strategies
    - Compensation retry logic
    - Detailed compensation tracking
    """

    def __init__(
        self,
        config: HandlerConfig = None,
        compensation_strategy: CompensationStrategy = CompensationStrategy.IMMEDIATE,
    ):
        """Initialize compensating event handler."""
        super().__init__(config)
        self.compensation_strategy = compensation_strategy
        self._compensation_queue: deque[TEvent] = deque()
        self._compensation_task: asyncio.Task | None = None

        if compensation_strategy == CompensationStrategy.DELAYED:
            self._start_compensation_processor()

    @abstractmethod
    async def compensate(self, event: TEvent, original_error: Exception) -> None:
        """
        Execute compensation logic (must be implemented by subclasses).

        Args:
            event: Original event that failed
            original_error: Error that occurred during processing
        """

    async def _process_single_event(self, event: TEvent) -> None:
        """Process event with compensation on failure."""
        try:
            await super()._process_single_event(event)
        except Exception as e:
            logger.warning(
                "Event processing failed, executing compensation",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                error=str(e),
            )

            try:
                if self.compensation_strategy == CompensationStrategy.IMMEDIATE:
                    await self._execute_compensation(event, e)
                elif self.compensation_strategy == CompensationStrategy.DELAYED:
                    self._compensation_queue.append(event)
                # MANUAL strategy requires explicit compensation trigger

            except Exception as comp_error:
                logger.exception(
                    "Compensation execution failed",
                    handler=self.__class__.__name__,
                    event_id=str(event.event_id),
                    compensation_error=str(comp_error),
                )

            # Re-raise original exception
            raise

    async def _execute_compensation(
        self, event: TEvent, original_error: Exception
    ) -> None:
        """Execute compensation with monitoring."""
        start_time = time.time()

        try:
            await self.compensate(event, original_error)

            compensation_time = time.time() - start_time
            self.metrics.record_compensation()

            logger.info(
                "Compensation executed successfully",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                compensation_time=compensation_time,
            )

        except Exception as e:
            compensation_time = time.time() - start_time

            logger.exception(
                "Compensation execution failed",
                handler=self.__class__.__name__,
                event_id=str(event.event_id),
                compensation_time=compensation_time,
                error=str(e),
            )
            raise

    def _start_compensation_processor(self) -> None:
        """Start background compensation processor."""
        self._compensation_task = self._create_background_task(
            self._compensation_loop()
        )

    async def _compensation_loop(self) -> None:
        """Background loop for delayed compensation processing."""
        while not self._shutdown:
            try:
                if self._compensation_queue:
                    event = self._compensation_queue.popleft()
                    await self._execute_compensation(
                        event, Exception("Delayed compensation")
                    )
                else:
                    await asyncio.sleep(1)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Compensation loop error",
                    handler=self.__class__.__name__,
                    error=str(e),
                )
                await asyncio.sleep(1)

    async def trigger_manual_compensation(
        self, event: TEvent, error: Exception
    ) -> None:
        """Manually trigger compensation for an event."""
        if self.compensation_strategy == CompensationStrategy.MANUAL:
            await self._execute_compensation(event, error)
        else:
            logger.warning(
                "Manual compensation triggered but strategy is not MANUAL",
                handler=self.__class__.__name__,
                strategy=self.compensation_strategy.value,
            )


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "AsyncEventHandler",
    "BatchEventHandler",
    "BatchStrategy",
    "CompensatingEventHandler",
    "CompensationStrategy",
    # Core classes
    "EventHandler",
    # Configuration
    "HandlerConfig",
    "HandlerMetrics",
    # Enums
    "HandlerPriority",
    "HandlerState",
    # Type variable
    "TEvent",
]
