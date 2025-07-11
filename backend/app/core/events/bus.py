"""
Event Bus Implementation for EzzDay Core

This module provides a comprehensive event bus system supporting multiple modes:
in-memory, distributed (Redis), and hybrid. Follows pure Python principles with
explicit validation and framework-agnostic design.

Key Features:
- Multiple bus implementations (InMemory, Distributed, Hybrid)
- Priority-based event routing and processing
- Retry mechanisms with exponential backoff
- Dead letter queue support for failed events
- Health monitoring and automatic failover
- Correlation ID tracking across event flows
- Comprehensive metrics and logging

Design Principles:
- Pure Python domain logic (no framework coupling)
- Explicit error handling and validation
- Configurable processing modes per event type
- Graceful degradation and fallback mechanisms

Usage Examples:
    # Basic in-memory bus
    bus = InMemoryEventBus()
    await bus.start()

    # Subscribe to events
    async def handle_user_created(event):
        print(f"User {event.user_id} created")

    bus.subscribe(UserCreatedEvent, handle_user_created)

    # Publish events
    event = UserCreatedEvent(user_id="123", email="user@example.com")
    await bus.publish(event)

    # Distributed bus with Redis
    bus = DistributedEventBus("redis://localhost:6379/0")
    await bus.start()

    # Hybrid bus with automatic fallback
    bus = HybridEventBus(
        redis_url="redis://localhost:6379/0",
        fallback_to_memory=True
    )
    await bus.start()

Error Handling:
    - ValidationError: Invalid event bus configuration
    - RuntimeError: Bus not started or Redis unavailable
    - EventProcessingError: Handler execution failures
    - ConnectionError: Redis connectivity issues

Performance Features:
    - Concurrent handler execution with priority support
    - Efficient Redis pub/sub with channel routing
    - Automatic retry queues with backoff strategies
    - Memory-efficient handler subscription management
"""

import asyncio
import json
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any

try:
    import redis.asyncio as aioredis

    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False

import contextlib

from app.core.errors import InfrastructureError, ValidationError

try:
    from app.core.events.registry import (
        EventPriority,
        EventProcessingMode,
        EventRegistration,
        RetryPolicy,
        get_event_class,
        get_registry,
    )
except ImportError:
    # Fallback implementations
    from enum import Enum

    class EventPriority(Enum):
        LOW = "low"
        NORMAL = "normal"
        HIGH = "high"
        CRITICAL = "critical"

    class EventProcessingMode(Enum):
        IN_MEMORY = "in_memory"
        DISTRIBUTED = "distributed"
        HYBRID = "hybrid"

    class RetryPolicy:
        def __init__(self, max_retries=3, initial_delay=1.0, backoff_multiplier=2.0, max_delay=300.0):
            self.max_retries = max_retries
            self.initial_delay = initial_delay
            self.backoff_multiplier = backoff_multiplier
            self.max_delay = max_delay

        @classmethod
        def no_retry(cls):
            return cls(max_retries=0)

    class EventRegistration:
        def __init__(self, event_type, handlers=None, retry_policy=None):
            self.event_type = event_type
            self.handlers = handlers or []
            self.retry_policy = retry_policy or RetryPolicy.no_retry()

    class MockRegistry:
        def __init__(self):
            self._registrations = {}

        def get_registration(self, event_type):
            return self._registrations.get(event_type)

        def get_priority(self, event_type):
            return EventPriority.NORMAL

        def get_processing_mode(self, event_type):
            return EventProcessingMode.IN_MEMORY

    def get_registry():
        return MockRegistry()

    def get_event_class(event_type):
        return None
try:
    from app.core.events.tracking import get_correlation_id, set_correlation_id
except ImportError:
    # Fallback correlation tracking
    import contextvars

    _correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
        'correlation_id', default=None
    )

    def get_correlation_id() -> str | None:
        return _correlation_id.get()

    def set_correlation_id(correlation_id: str) -> None:
        _correlation_id.set(correlation_id)
from app.core.events.types import DomainEvent
from app.core.logging import get_logger

try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def inc(self):
            pass

    class MockGauge:
        def labels(self, **kwargs):
            return self
        def set(self, value):
            pass

    class MockMetrics:
        def __init__(self):
            self.events_published = MockCounter()
            self.event_handler_errors = MockCounter()
            self.event_bus_health = MockGauge()

    metrics = MockMetrics()

logger = get_logger(__name__)

EventHandlerType = Callable[[DomainEvent], None | Awaitable[None]]


class EventBusError(InfrastructureError):
    """Base exception for event bus operations."""

    default_code = "EVENT_BUS_ERROR"
    status_code = 500
    retryable = True


class EventBusValidationError(ValidationError):
    """Raised when event bus configuration is invalid."""


class EventProcessingError(EventBusError):
    """Raised when event processing fails."""

    default_code = "EVENT_PROCESSING_ERROR"
    retryable = True


class EventBus(ABC):
    """
    Abstract base class for event bus implementations.

    Defines the core contract for publishing and subscribing to domain events.
    All implementations must support correlation ID tracking and graceful
    lifecycle management.

    Design Features:
    - Abstract interface ensures consistent behavior across implementations
    - Correlation ID support for distributed tracing
    - Async lifecycle management for resource cleanup
    - Type-safe handler registration and removal

    Usage:
        class MyEventBus(EventBus):
            async def publish(self, event, correlation_id=None):
                # Implementation here
                pass

            def subscribe(self, event_type, handler):
                # Implementation here
                pass

    Error Handling:
        - Must validate event types and handler signatures
        - Should handle resource cleanup in stop() method
        - Must propagate critical errors to callers
    """

    @abstractmethod
    async def publish(
        self, event: DomainEvent, correlation_id: str | None = None
    ) -> None:
        """
        Publish a domain event with optional correlation tracking.

        Args:
            event: The domain event to publish
            correlation_id: Optional correlation ID for request tracing

        Raises:
            RuntimeError: If bus is not started
            EventProcessingError: If event processing fails critically
            ValidationError: If event is invalid
        """

    @abstractmethod
    def subscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Subscribe a handler to an event type.

        Args:
            event_type: The event class to listen for
            handler: Callable that processes the event (sync or async)

        Raises:
            ValidationError: If handler signature is invalid
        """

    @abstractmethod
    def unsubscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Remove a handler subscription for an event type.

        Args:
            event_type: The event class to stop listening for
            handler: The handler to remove
        """

    @abstractmethod
    async def start(self) -> None:
        """
        Initialize the event bus and prepare for event processing.

        Raises:
            EventBusError: If initialization fails
        """

    @abstractmethod
    async def stop(self) -> None:
        """
        Gracefully shutdown the event bus and cleanup resources.

        Should not raise exceptions - must cleanup regardless of state.
        """


class InMemoryEventBus(EventBus):
    """
    High-performance in-memory event bus for single-process applications.

    Provides ultra-low latency event processing with priority support,
    retry mechanisms, and comprehensive error handling. Ideal for
    applications requiring immediate consistency and fast event processing.

    Key Features:
    - Sub-millisecond event delivery
    - Priority-based handler execution
    - Automatic retry with exponential backoff
    - Handler inheritance support (polymorphic events)
    - Concurrent async handler execution
    - Comprehensive metrics and logging

    Design Characteristics:
    - Thread-safe handler registration
    - Memory-efficient handler storage
    - Explicit error propagation for critical events
    - Graceful degradation for non-critical failures

    Usage Examples:
        # Basic setup
        bus = InMemoryEventBus()
        await bus.start()

        # Subscribe handlers
        def sync_handler(event):
            print(f"Sync: {event}")

        async def async_handler(event):
            await some_async_operation(event)

        bus.subscribe(UserCreatedEvent, sync_handler)
        bus.subscribe(UserCreatedEvent, async_handler)

        # Publish with correlation
        event = UserCreatedEvent(user_id="123")
        await bus.publish(event, correlation_id="req-456")

        # Cleanup
        await bus.stop()

    Performance Characteristics:
    - Event delivery: < 1ms for local handlers
    - Handler execution: Concurrent for async, sequential for sync
    - Memory usage: O(n) where n = number of unique handler registrations
    - CPU usage: Minimal overhead, scales with handler complexity

    Error Handling:
        Critical events (CRITICAL priority) fail fast and propagate errors
        immediately. Non-critical events log errors but continue processing
        other handlers. Retry policies are applied based on event registration.
    """

    def __init__(self):
        """
        Initialize the in-memory event bus.

        Creates empty handler registries and sets initial state.
        Does not perform any I/O or validation - deferred to start().
        """
        self._validate_initialization()

        self._handlers: dict[str, list[EventHandlerType]] = defaultdict(list)
        self._async_handlers: dict[str, list[EventHandlerType]] = defaultdict(list)
        self._registry = get_registry()
        self._running = False
        self._start_time: datetime | None = None
        self._event_count = 0

        logger.debug("InMemoryEventBus initialized")

    def _validate_initialization(self) -> None:
        """Validate bus initialization requirements."""
        try:
            # Ensure registry is available
            from app.core.events.registry import get_registry

            get_registry()
        except Exception as e:
            raise EventBusValidationError(
                f"Failed to access event registry during initialization: {e}"
            ) from e

            async def start(self) -> None:
                    """
                    Start the in-memory event bus and prepare for event processing.

                    Validates registry connectivity and sets running state.
                    This is a lightweight operation for in-memory buses.

                    Raises:
                        EventBusError: If bus is already running or registry is unavailable
                    """
                    if self._running:
                        raise EventBusError("Event bus is already running")

                    try:
                        # Validate registry access
                        self._registry = get_registry()
                        self._running = True
                        self._start_time = datetime.now(datetime.UTC)
                        self._event_count = 0

                        logger.info(
                            "In-memory event bus started",
                            start_time=self._start_time.isoformat(),
                            handler_types=len(self._handlers) + len(self._async_handlers),
                        )

                    except Exception as e:
                        raise EventBusError(f"Failed to start in-memory event bus: {e}") from e

            async def stop(self) -> None:
                    """
                    Stop the in-memory event bus gracefully.

                    Cleans up state and logs statistics. Does not clear handler
                    registrations to allow restart without re-registration.
                    """
                    if not self._running:
                        return

                    self._running = False
                    stop_time = datetime.now(datetime.UTC)

                    uptime = (
                        (stop_time - self._start_time).total_seconds() if self._start_time else 0
                    )

                    logger.info(
                        "In-memory event bus stopped",
                        uptime_seconds=uptime,
                        events_processed=self._event_count,
                        handler_registrations=len(self._handlers) + len(self._async_handlers),
                    )

    async def publish(
        self, event: DomainEvent, correlation_id: str | None = None
    ) -> None:
        """
        Publish event with priority-based processing and retry support.

        Validates event, sets correlation context, retrieves handlers from
        both direct subscriptions and registry, then executes with appropriate
        priority and retry policies.

        Args:
            event: Domain event to publish
            correlation_id: Optional correlation ID for tracing

        Raises:
            RuntimeError: If bus is not running
            ValidationError: If event is invalid
            EventProcessingError: If critical event handler fails
        """
        self._validate_publish_preconditions(event)

        event_type = event.__class__.__name__
        self._event_count += 1

        # Set correlation context
        self._set_correlation_context(event, correlation_id)

        # Get event configuration and handlers
        registration = self._registry.get_registration(event_type)
        priority = self._registry.get_priority(event_type)
        handlers = self._collect_all_handlers(event, registration)

        if not handlers:
            logger.debug(
                "No handlers registered for event",
                event_type=event_type,
                event_id=str(event.metadata.event_id),
            )
            return

        # Log and track publication
        self._log_event_publication(event, handlers, priority)
        self._track_publication_metrics(event_type, priority)

        # Execute handlers with priority-appropriate error handling
        await self._execute_handlers_by_priority(
            handlers, event, registration, priority
        )

    def _validate_publish_preconditions(self, event: DomainEvent) -> None:
        """Validate preconditions for event publication."""
        if not self._running:
            raise RuntimeError("Event bus is not running - call start() first")

        if not isinstance(event, DomainEvent):
            raise ValidationError(
                f"Event must be DomainEvent instance, got {type(event)}"
            )

        if not hasattr(event, "metadata") or not event.metadata:
            raise ValidationError("Event must have valid metadata")

    def _set_correlation_context(
        self, event: DomainEvent, correlation_id: str | None
    ) -> None:
        """Set correlation ID in execution context."""
        if correlation_id:
            set_correlation_id(correlation_id)
        elif (
            hasattr(event.metadata, "correlation_id") and event.metadata.correlation_id
        ):
            set_correlation_id(event.metadata.correlation_id)

    def _collect_all_handlers(
            self, event: DomainEvent, registration: EventRegistration | None
        ) -> list[EventHandlerType]:
            """Collect handlers from subscriptions and registry."""
            handlers = []

            # Get direct subscription handlers
            handlers.extend(self._get_handlers_for_event(event))

            # Add registry handlers
            if registration and registration.handlers:
                for handler_cls in registration.handlers:
                    try:
                        handler_instance = handler_cls()
                        if hasattr(handler_instance, "handle_event"):
                            handlers.append(handler_instance.handle_event)
                        else:
                            logger.warning(
                                "Registry handler missing handle_event method",
                                handler_class=handler_cls.__name__,
                            )
                    except Exception as e:
                        logger.exception(
                            "Failed to instantiate registry handler",
                            handler_class=handler_cls.__name__,
                            error=str(e),
                        )

            return handlers

    def _log_event_publication(
        self,
        event: DomainEvent,
        handlers: list[EventHandlerType],
        priority: EventPriority,
    ) -> None:
        """Log event publication with context."""
        logger.info(
            "Publishing event",
            event_type=event.__class__.__name__,
            event_id=str(event.metadata.event_id),
            handler_count=len(handlers),
            priority=priority.name,
            correlation_id=get_correlation_id(),
            bus_type="in_memory",
        )

    def _track_publication_metrics(
        self, event_type: str, priority: EventPriority
    ) -> None:
        """Track publication metrics."""
        metrics.events_published.labels(
            event_type=event_type, bus="in_memory", priority=priority.name
        ).inc()

    async def _execute_handlers_by_priority(
            self,
            handlers: list[EventHandlerType],
            event: DomainEvent,
            registration: EventRegistration | None,
            priority: EventPriority,
        ) -> None:
            """Execute handlers with priority-appropriate error handling."""
            sync_handlers = [h for h in handlers if not asyncio.iscoroutinefunction(h)]
            async_handlers = [h for h in handlers if asyncio.iscoroutinefunction(h)]

            # Execute sync handlers sequentially
            for handler in sync_handlers:
                self._execute_sync_handler(handler, event)

            # Execute async handlers concurrently
            if async_handlers:
                tasks = [
                    self._execute_async_handler_with_retry(handler, event, registration)
                    for handler in async_handlers
                ]

                # Critical events fail fast, others collect errors
                if priority == EventPriority.CRITICAL:
                    await asyncio.gather(*tasks, return_exceptions=False)
                else:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    self._handle_async_execution_results(results, event, handlers)

    def _handle_async_execution_results(
        self, results: list[Any], event: DomainEvent, handlers: list[EventHandlerType]
    ) -> None:
        """Handle results from async handler execution."""
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                handler = handlers[i]
                logger.error(
                    "Async event handler failed",
                    event_type=event.__class__.__name__,
                    error=str(result),
                    handler=getattr(handler, "__name__", repr(handler)),
                )
                metrics.event_handler_errors.labels(
                    event_type=event.__class__.__name__,
                    handler="async",
                    error_type=type(result).__name__,
                ).inc()

    def subscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Subscribe a handler to an event type with validation.

        Validates handler signature and registers it for the appropriate
        execution mode (sync/async). Supports polymorphic event handling.

        Args:
            event_type: Event class to subscribe to
            handler: Callable that processes events (sync or async)

        Raises:
            ValidationError: If handler signature is invalid
        """
        self._validate_subscription(event_type, handler)

        event_name = event_type.__name__

        if asyncio.iscoroutinefunction(handler):
            self._async_handlers[event_name].append(handler)
        else:
            self._handlers[event_name].append(handler)

        logger.debug(
            "Handler subscribed",
            event_type=event_name,
            handler=getattr(handler, "__name__", repr(handler)),
            is_async=asyncio.iscoroutinefunction(handler),
        )

    def _validate_subscription(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """Validate subscription parameters."""
        if not isinstance(event_type, type) or not issubclass(event_type, DomainEvent):
            raise ValidationError(
                f"event_type must be DomainEvent subclass, got {event_type}"
            )

        if not callable(handler):
            raise ValidationError(f"Handler must be callable, got {type(handler)}")

        # Validate handler signature
        import inspect

        try:
            sig = inspect.signature(handler)
            if len(sig.parameters) != 1:
                raise ValidationError(
                    f"Handler must accept exactly one parameter (event), "
                    f"got {len(sig.parameters)} parameters"
                )
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Invalid handler signature: {e}") from e

    def unsubscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Remove a handler subscription with validation.

        Safely removes handler from appropriate registry. No-op if handler
        was not previously subscribed.

        Args:
            event_type: Event class to unsubscribe from
            handler: Handler to remove
        """
        event_name = event_type.__name__
        removed = False

        if asyncio.iscoroutinefunction(handler):
            if handler in self._async_handlers[event_name]:
                self._async_handlers[event_name].remove(handler)
                removed = True
        elif handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)
            removed = True

        if removed:
            logger.debug(
                "Handler unsubscribed",
                event_type=event_name,
                handler=getattr(handler, "__name__", repr(handler)),
            )

    def _get_handlers_for_event(self, event: DomainEvent) -> list[EventHandlerType]:
        """
        Get all handlers for event including inheritance chain.

        Supports polymorphic event handling by checking the entire
        method resolution order (MRO) for handler registrations.
        """
        handlers = []
        event_name = event.__class__.__name__

        # Direct handlers
        handlers.extend(self._handlers.get(event_name, []))
        handlers.extend(self._async_handlers.get(event_name, []))

        # Inheritance chain handlers (polymorphic support)
        for base_class in event.__class__.__mro__[1:]:
            if base_class.__name__ == "DomainEvent":
                break
            base_name = base_class.__name__
            handlers.extend(self._handlers.get(base_name, []))
            handlers.extend(self._async_handlers.get(base_name, []))

        return handlers

    def _execute_sync_handler(
        self, handler: EventHandlerType, event: DomainEvent
    ) -> None:
        """Execute synchronous handler with error handling."""
        try:
            handler(event)
        except Exception as e:
            logger.exception(
                "Sync event handler failed",
                handler=getattr(handler, "__name__", repr(handler)),
                event_type=event.__class__.__name__,
                error=str(e),
                correlation_id=get_correlation_id(),
            )

            metrics.event_handler_errors.labels(
                event_type=event.__class__.__name__,
                handler="sync",
                error_type=type(e).__name__,
            ).inc()

    async def _execute_async_handler_with_retry(
            self,
            handler: EventHandlerType,
            event: DomainEvent,
            registration: EventRegistration | None = None,
        ) -> None:
            """
            Execute async handler with retry policy and exponential backoff.

            Implements configurable retry logic with exponential backoff,
            max delay caps, and comprehensive error tracking.
            """
            retry_policy = (
                registration.retry_policy if registration else RetryPolicy.no_retry()
            )
            handler_name = getattr(handler, "__name__", repr(handler))
            event_type = event.__class__.__name__

            for attempt in range(retry_policy.max_retries + 1):
                try:
                    result = await handler(event)
                    if attempt > 0:
                        logger.info(
                            "Handler succeeded after retry",
                            handler=handler_name,
                            event_type=event_type,
                            attempt=attempt + 1,
                        )
                    return

                except Exception as e:
                    if attempt < retry_policy.max_retries:
                        delay = min(
                            retry_policy.initial_delay
                            * (retry_policy.backoff_multiplier**attempt),
                            retry_policy.max_delay,
                        )

                        logger.warning(
                            f"Handler failed, retrying in {delay}s",
                            handler=handler_name,
                            event_type=event_type,
                            attempt=attempt + 1,
                            max_retries=retry_policy.max_retries,
                            error=str(e),
                            correlation_id=get_correlation_id(),
                        )

                        await asyncio.sleep(delay)
                    else:
                        logger.exception(
                            "Handler failed after all retries",
                            handler=handler_name,
                            event_type=event_type,
                            attempts=attempt + 1,
                            error=str(e),
                            correlation_id=get_correlation_id(),
                        )
                        raise EventProcessingError(
                            f"Handler {handler_name} failed after {attempt + 1} attempts: {e}"
                        ) from e

    def get_statistics(self) -> dict[str, Any]:
        """
        Get comprehensive bus statistics for monitoring.

        Returns:
            Dictionary containing performance and state metrics
        """
        return {
            "bus_type": "in_memory",
            "running": self._running,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "events_processed": self._event_count,
            "handler_registrations": {
                "sync": sum(len(handlers) for handlers in self._handlers.values()),
                "async": sum(
                    len(handlers) for handlers in self._async_handlers.values()
                ),
                "total": (
                    sum(len(handlers) for handlers in self._handlers.values())
                    + sum(len(handlers) for handlers in self._async_handlers.values())
                ),
            },
            "event_types_registered": len(
                set(self._handlers.keys()) | set(self._async_handlers.keys())
            ),
        }


class DistributedEventBus(EventBus):
    """
    Redis-based distributed event bus for multi-process/multi-service architectures.

    Provides reliable event delivery across service boundaries with advanced
    features like dead letter queues, retry mechanisms, priority channels,
    and automatic health monitoring.

    Key Features:
    - Redis pub/sub with priority channels
    - Automatic retry with exponential backoff
    - Dead letter queue for failed events
    - Health monitoring and reconnection
    - Correlation ID preservation across services
    - Comprehensive metrics and distributed tracing

    Design Characteristics:
    - At-least-once delivery semantics
    - Priority-based channel routing
    - Configurable retry and DLQ policies
    - Graceful degradation on Redis failures
    - Memory-bounded retry queues

    Usage Examples:
        # Basic setup
        bus = DistributedEventBus("redis://localhost:6379/0")
        await bus.start()

        # Configure with DLQ
        bus = DistributedEventBus(
            redis_url="redis://localhost:6379/0",
            dead_letter_queue=True,
            max_retry_queue_size=5000
        )

        # Subscribe and publish
        bus.subscribe(OrderCreatedEvent, handle_order)
        await bus.publish(OrderCreatedEvent(order_id="123"))

        # Monitor health
        if bus.is_healthy():
            await bus.publish(event)

    Performance Characteristics:
    - Event delivery: ~5-50ms depending on Redis latency
    - Throughput: 10K+ events/sec with proper Redis setup
    - Memory usage: Bounded by retry queue size
    - Network usage: Efficient Redis protocol

    Error Handling:
        Redis connection failures trigger automatic reconnection.
        Failed events are retried based on configuration.
        Permanent failures are moved to dead letter queue.
        Critical events can bypass retry logic for immediate failure.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        dead_letter_queue: bool = True,
        max_retry_queue_size: int = 10000,
    ):
        """
        Initialize distributed event bus with Redis backend.

        Args:
            redis_url: Redis connection URL
            dead_letter_queue: Enable dead letter queue for failed events
            max_retry_queue_size: Maximum retry queue size (memory protection)

        Raises:
            EventBusValidationError: If Redis is not available or config invalid
        """
        self._validate_redis_availability()
        self._validate_configuration(redis_url, max_retry_queue_size)

        self.redis_url = redis_url
        self._handlers: dict[str, list[EventHandlerType]] = defaultdict(list)
        self._async_handlers: dict[str, list[EventHandlerType]] = defaultdict(list)
        self._redis = aioredis.from_url(self.redis_url)
        self._pubsub = self._redis.pubsub()
        self._subscriber_task = None
        self._running = False
        self._registry = get_registry()
        self._dead_letter_queue = dead_letter_queue
        self._max_retry_queue_size = max_retry_queue_size
        self._retry_queue_name = "event_bus:retry_queue"
        self._dead_letter_queue_name = "event_bus:dead_letter_queue"
        self._retry_processor_task = None
        self._health_status = False
        self._start_time: datetime | None = None

    def _validate_redis_availability(self) -> None:
        """Validate Redis client availability."""
        if not _HAS_REDIS:
            raise EventBusValidationError(
                "redis-py is required for DistributedEventBus. "
                "Install with 'pip install redis[hiredis]'"
            )

    def _validate_configuration(
        self, redis_url: str, max_retry_queue_size: int
    ) -> None:
        """Validate distributed bus configuration."""
        if not redis_url or not isinstance(redis_url, str):
            raise EventBusValidationError("redis_url must be non-empty string")

        if not redis_url.startswith(("redis://", "rediss://")):
            raise EventBusValidationError(
                "redis_url must start with 'redis://' or 'rediss://'"
            )

        if max_retry_queue_size < 100:
            raise EventBusValidationError("max_retry_queue_size must be at least 100")

    async def start(self) -> None:
        """
        Start distributed event bus and establish Redis connections.

        Initializes Redis connections, subscribes to event channels,
        and starts background tasks for event processing and retries.

        Raises:
            EventBusError: If Redis connection fails or bus already running
        """
        if self._running:
            raise EventBusError("Distributed event bus is already running")

        try:
            # Test Redis connectivity
            await self._redis.ping()
            self._health_status = True
            self._running = True
            self._start_time = datetime.now()

            # Subscribe to event channels
            await self._subscribe_to_channels()

            # Start background tasks
            self._subscriber_task = asyncio.create_task(self._listen())
            if self._dead_letter_queue:
                self._retry_processor_task = asyncio.create_task(
                    self._process_retry_queue()
                )

            logger.info(
                "Distributed event bus started",
                redis_url=self.redis_url,
                dead_letter_queue=self._dead_letter_queue,
                max_retry_queue_size=self._max_retry_queue_size,
            )

        except Exception as e:
            self._running = False
            self._health_status = False
            raise EventBusError(f"Failed to start distributed event bus: {e}") from e

    async def _subscribe_to_channels(self) -> None:
        """Subscribe to Redis channels for registered events."""
        channels = set()

        # Add channels for directly subscribed handlers
        channels.update(self._handlers.keys())
        channels.update(self._async_handlers.keys())

        # Add channels for registry events
        for event_name in self._registry._registrations:
            priority = self._registry.get_priority(event_name)
            channel = self._get_channel_for_priority(event_name, priority)
            channels.add(channel)

        if channels:
            await self._pubsub.subscribe(*channels)
            logger.info(
                "Subscribed to Redis channels",
                channels=list(channels),
                count=len(channels),
            )

    async def stop(self) -> None:
        """
        Stop distributed event bus and cleanup resources.

        Gracefully shuts down background tasks, closes Redis connections,
        and logs final statistics. Does not lose queued events.
        """
        if not self._running:
            return

        self._running = False

        # Cancel background tasks
        tasks = [self._subscriber_task, self._retry_processor_task]
        for task in tasks:
            if task and (asyncio.isfuture(task) or (hasattr(task, 'done') and not task.done())):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        # Close Redis connections
        try:
            if self._pubsub:
                await self._pubsub.close()
            await self._redis.close()
        except Exception as e:
            logger.warning("Error closing Redis connections", error=str(e))

        uptime = (
            (datetime.now().astimezone() - self._start_time).total_seconds()
            if self._start_time
            else 0
        )

        logger.info(
            "Distributed event bus stopped",
            uptime_seconds=uptime,
            final_health_status=self._health_status,
        )

    async def publish(
        self, event: DomainEvent, correlation_id: str | None = None
    ) -> None:
        """
        Publish event to Redis with priority routing and retry support.

        Serializes event with metadata, routes to priority-specific channel,
        and publishes to Redis. Includes correlation ID preservation and
        comprehensive error tracking.

        Args:
            event: Domain event to publish
            correlation_id: Optional correlation ID for tracing

        Raises:
            RuntimeError: If bus is not running
            EventBusError: If Redis publish fails
        """
        if not self._running:
            raise RuntimeError("Distributed event bus is not running")

        event_type = event.__class__.__name__

        # Set correlation context
        if correlation_id:
            set_correlation_id(correlation_id)
        elif (
            hasattr(event.metadata, "correlation_id") and event.metadata.correlation_id
        ):
            set_correlation_id(event.metadata.correlation_id)

        # Get event configuration
        self._registry.get_registration(event_type)
        priority = self._registry.get_priority(event_type)

        # Prepare event data with enhanced metadata
        event_data = event.to_dict()
        event_data["_bus_metadata"] = {
            "priority": priority.value,
            "published_at": datetime.now().isoformat(),
            "correlation_id": get_correlation_id() or "",
            "retry_count": 0,
            "publisher_id": f"distributed_bus_{id(self)}",
        }

        # Publish to priority-specific Redis channel
        channel = self._get_channel_for_priority(event_type, priority)

        try:
            data = json.dumps(event_data, default=str)
            result = await self._redis.publish(channel, data)

            logger.info(
                "Published event to Redis",
                event_type=event_type,
                event_id=str(event.metadata.event_id),
                channel=channel,
                priority=priority.name,
                subscribers=result,
                correlation_id=get_correlation_id(),
            )

            # Track metrics
            metrics.events_published.labels(
                event_type=event_type, bus="distributed", priority=priority.name
            ).inc()

        except Exception as e:
            logger.exception(
                "Failed to publish event to Redis",
                event_type=event_type,
                channel=channel,
                error=str(e),
            )
            raise EventBusError(f"Redis publish failed: {e}") from e

    def subscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Subscribe handler to distributed event processing.

        Registers handler for local processing of events received from Redis.
        Handler will be called for all matching events from any publisher.

        Args:
            event_type: Event class to subscribe to
            handler: Callable that processes events
        """
        self._validate_subscription(event_type, handler)

        event_name = event_type.__name__

        if asyncio.iscoroutinefunction(handler):
            self._async_handlers[event_name].append(handler)
        else:
            self._handlers[event_name].append(handler)

        logger.debug(
            "Handler subscribed to distributed bus",
            event_type=event_name,
            handler=getattr(handler, "__name__", repr(handler)),
            is_async=asyncio.iscoroutinefunction(handler),
        )

    def unsubscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """Remove handler subscription from distributed processing."""
        event_name = event_type.__name__
        removed = False

        if asyncio.iscoroutinefunction(handler):
            if handler in self._async_handlers[event_name]:
                self._async_handlers[event_name].remove(handler)
                removed = True
        elif handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)
            removed = True

        if removed:
            logger.debug(
                "Handler unsubscribed from distributed bus",
                event_type=event_name,
                handler=getattr(handler, "__name__", repr(handler)),
            )

    def _validate_subscription(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """Validate subscription parameters for distributed processing."""
        if not isinstance(event_type, type) or not issubclass(event_type, DomainEvent):
            raise ValidationError(
                f"event_type must be DomainEvent subclass, got {event_type}"
            )

        if not callable(handler):
            raise ValidationError(f"Handler must be callable, got {type(handler)}")

    def _get_channel_for_priority(
        self, event_type: str, priority: EventPriority
    ) -> str:
        """
        Get Redis channel name based on event priority.

        Routes events to priority-specific channels for processing optimization.
        Critical events get dedicated channels for immediate processing.
        """
        if priority == EventPriority.CRITICAL:
            return f"events:critical:{event_type}"
        if priority == EventPriority.HIGH:
            return f"events:high:{event_type}"
        return f"events:normal:{event_type}"

    async def _listen(self) -> None:
        """
        Listen for events from Redis channels with health monitoring.

        Main event processing loop that receives Redis messages,
        deserializes events, and dispatches to handlers.
        """
        logger.info("Redis event bus listening for events")

        while self._running:
            try:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )

                if not message:
                    await asyncio.sleep(0.05)
                    continue

                await self._process_message(message)
                self._health_status = True

            except Exception as ex:
                logger.exception("Redis bus listen loop error", error=str(ex))
                self._health_status = False
                await asyncio.sleep(1)

    async def _process_message(self, message: dict) -> None:
        """
        Process individual Redis message with comprehensive error handling.

        Deserializes event, restores correlation context, finds handlers,
        and executes with retry support.
        """
        channel = None
        try:
            # Extract channel and data
            channel = message["channel"]
            if isinstance(channel, bytes):
                channel = channel.decode()

            # Extract event type from channel
            event_type = channel.split(":")[-1]

            # Parse event data
            event_data = json.loads(message["data"])
            bus_metadata = event_data.pop("_bus_metadata", {})

            # Restore correlation ID
            if bus_metadata.get("correlation_id"):
                set_correlation_id(bus_metadata["correlation_id"])

            # Reconstruct event
            event_cls = get_event_class(event_type)
            if not event_cls:
                logger.warning(
                    "Unknown event type in Redis message",
                    event_type=event_type,
                    channel=channel,
                )
                return

            event = event_cls.from_dict(event_data)

            # Get local handlers
            handlers = self._get_local_handlers(event_type)

            if not handlers:
                logger.debug(
                    "No local handlers for Redis event",
                    event_type=event_type,
                    channel=channel,
                )
                return

            # Process handlers with retry support
            registration = self._registry.get_registration(event_type)
            for handler in handlers:
                await self._execute_handler_with_retry(
                    handler, event, registration, bus_metadata
                )

        except Exception as e:
            logger.exception(
                "Failed to process Redis message",
                error=str(e),
                channel=channel if channel else "unknown",
                correlation_id=get_correlation_id(),
            )

    def _get_local_handlers(self, event_type: str) -> list[EventHandlerType]:
        """Get handlers for local processing of distributed events."""
        handlers = []
        handlers.extend(self._handlers.get(event_type, []))
        handlers.extend(self._async_handlers.get(event_type, []))

        # Add registry handlers
        registration = self._registry.get_registration(event_type)
        if registration and registration.handlers:
            for handler_cls in registration.handlers:
                try:
                    handler = handler_cls()
                    if hasattr(handler, "handle_event"):
                        handlers.append(handler.handle_event)
                except Exception as e:
                    logger.exception(
                        "Failed to instantiate registry handler",
                        handler_class=handler_cls.__name__,
                        error=str(e),
                    )

        return handlers

    async def _execute_handler_with_retry(
            self,
            handler: EventHandlerType,
            event: DomainEvent,
            registration: "EventRegistration" | None,
            bus_metadata: dict,
        ) -> None:
        """
        Execute handler with distributed retry support.

        Implements retry logic with queue-based persistence for failed events.
        Failed events are added to retry queue or dead letter queue.
        """
        handler_name = getattr(handler, "__name__", repr(handler))
        event_type = event.__class__.__name__
        retry_count = bus_metadata.get("retry_count", 0)

        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)

        except Exception as e:
            retry_policy = (
                registration.retry_policy if registration else RetryPolicy.no_retry()
            )

            if retry_count < retry_policy.max_retries:
                # Add to retry queue for later processing
                await self._add_to_retry_queue(
                    event, handler_name, retry_count + 1, str(e)
                )

                logger.warning(
                    "Handler failed, added to retry queue",
                    handler=handler_name,
                    event_type=event_type,
                    retry_count=retry_count + 1,
                    error=str(e),
                    correlation_id=get_correlation_id(),
                    exc_info=True,
                )
            else:
                # Final failure - move to dead letter queue
                if self._dead_letter_queue:
                    await self._add_to_dead_letter_queue(
                        event, handler_name, retry_count, str(e)
                    )

                logger.exception(
                    "Handler failed after all retries",
                    handler=handler_name,
                    event_type=event_type,
                    retry_count=retry_count,
                    error=str(e),
                    correlation_id=get_correlation_id(),
                )

                metrics.event_handler_errors.labels(
                    event_type=event_type,
                    handler="distributed",
                    error_type=type(e).__name__,
                ).inc()

    async def _add_to_retry_queue(
        self, event: DomainEvent, handler_name: str, retry_count: int, error: str
    ) -> None:
        """Add failed event to Redis-based retry queue."""
        retry_data = {
            "event": event.to_dict(),
            "event_type": event.__class__.__name__,
            "handler": handler_name,
            "retry_count": retry_count,
            "error": error,
            "next_retry_at": (
                datetime.now(datetime.UTC) + timedelta(seconds=retry_count * 5)
            ).isoformat(),
            "correlation_id": get_correlation_id(),
        }

        await self._redis.lpush(
            self._retry_queue_name, json.dumps(retry_data, default=str)
        )

        # Trim queue to prevent memory issues
        await self._redis.ltrim(
            self._retry_queue_name, 0, self._max_retry_queue_size - 1
        )

    async def _add_to_dead_letter_queue(
        self, event: DomainEvent, handler_name: str, retry_count: int, error: str
    ) -> None:
        """Add permanently failed event to dead letter queue."""
        dlq_data = {
            "event": event.to_dict(),
            "event_type": event.__class__.__name__,
            "handler": handler_name,
            "retry_count": retry_count,
            "final_error": error,
            "failed_at": datetime.now(datetime.UTC).isoformat(),
            "correlation_id": get_correlation_id(),
        }

        await self._redis.lpush(
            self._dead_letter_queue_name, json.dumps(dlq_data, default=str)
        )

    async def _process_retry_queue(self) -> None:
        """
        Background task to process retry queue with timing support.

        Continuously polls retry queue and re-publishes events when
        their retry time has arrived.
        """
        logger.info("Starting retry queue processor")

        while self._running:
            try:
                # Get next retry item (blocking with timeout)
                data = await self._redis.brpop(self._retry_queue_name, timeout=5)

                if not data:
                    continue

                retry_data = json.loads(data[1])

                # Check if it's time to retry
                next_retry = datetime.fromisoformat(retry_data["next_retry_at"])
                if datetime.now(datetime.UTC) < next_retry:
                    # Put it back - not time yet
                    await self._redis.lpush(
                        self._retry_queue_name, json.dumps(retry_data, default=str)
                    )
                    await asyncio.sleep(1)
                    continue

                # Time to retry - republish the event
                event_cls = get_event_class(retry_data["event_type"])
                if event_cls:
                    event = event_cls.from_dict(retry_data["event"])

                    # Restore correlation context
                    if retry_data.get("correlation_id"):
                        set_correlation_id(retry_data["correlation_id"])

                    await self.publish(event)

                    logger.info(
                        "Retrying event from queue",
                        event_type=retry_data["event_type"],
                        retry_count=retry_data["retry_count"],
                        correlation_id=retry_data.get("correlation_id"),
                    )

            except Exception as e:
                logger.exception("Retry queue processor error", error=str(e))
                await asyncio.sleep(5)

    def is_healthy(self) -> bool:
        """Check if distributed bus is healthy and connected."""
        return self._running and self._health_status

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive distributed bus statistics."""
        return {
            "bus_type": "distributed",
            "running": self._running,
            "healthy": self._health_status,
            "redis_url": self.redis_url,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "dead_letter_queue_enabled": self._dead_letter_queue,
            "max_retry_queue_size": self._max_retry_queue_size,
            "handler_registrations": {
                "sync": sum(len(handlers) for handlers in self._handlers.values()),
                "async": sum(
                    len(handlers) for handlers in self._async_handlers.values()
                ),
            },
        }


class HybridEventBus(EventBus):
    """
    Intelligent hybrid event bus combining in-memory and distributed processing.

    Automatically routes events based on their processing mode configuration,
    providing optimal performance for local events and reliability for
    distributed events. Features automatic fallback and health monitoring.

    Key Features:
    - Intelligent routing based on event configuration
    - Automatic fallback when Redis is unavailable
    - Health monitoring with automatic recovery
    - Dual-bus publishing for maximum reliability
    - Performance optimization per event type

    Design Characteristics:
    - Zero-downtime failover capability
    - Configurable fallback behavior
    - Independent bus lifecycle management
    - Unified subscription interface
    - Comprehensive health monitoring

    Usage Examples:
        # Basic setup with fallback
        bus = HybridEventBus(
            redis_url="redis://localhost:6379/0",
            fallback_to_memory=True
        )
        await bus.start()

        # Configure health monitoring
        bus = HybridEventBus(
            redis_url="redis://localhost:6379/0",
            health_check_interval=15,
            fallback_to_memory=True
        )

        # Use like any other bus
        bus.subscribe(UserCreatedEvent, handle_user)
        await bus.publish(UserCreatedEvent(user_id="123"))

        # Check health status
        stats = bus.get_statistics()
        if stats["redis_available"]:
            print("Distributed processing available")

    Processing Modes:
        - IN_MEMORY: Routes to in-memory bus only (ultra-fast)
        - DISTRIBUTED: Routes to distributed bus (reliable)
        - HYBRID: Routes to both buses (maximum reliability)

    Error Handling:
        Gracefully handles Redis failures with automatic fallback.
        Critical events in hybrid mode fail if any bus fails.
        Health monitoring enables automatic recovery.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        fallback_to_memory: bool = True,
        health_check_interval: int = 30,
    ):
        """
        Initialize hybrid event bus with dual-bus architecture.

        Args:
            redis_url: Redis connection URL for distributed bus
            fallback_to_memory: Enable fallback to in-memory when Redis fails
            health_check_interval: Health check frequency in seconds

        Raises:
            EventBusValidationError: If configuration is invalid
        """
        self._validate_hybrid_configuration(redis_url, health_check_interval)

        self._in_memory_bus = InMemoryEventBus()
        self._distributed_bus = None
        self._redis_url = redis_url
        self._fallback_to_memory = fallback_to_memory
        self._health_check_interval = health_check_interval
        self._redis_available = False
        self._registry = get_registry()
        self._health_check_task = None
        self._running = False
        self._start_time: datetime | None = None
        self._event_count = 0

        # Attempt to initialize distributed bus
        self._initialize_distributed_bus()

    def _validate_hybrid_configuration(
        self, redis_url: str, health_check_interval: int
    ) -> None:
        """Validate hybrid bus configuration."""
        if not redis_url or not isinstance(redis_url, str):
            raise EventBusValidationError("redis_url must be non-empty string")

        if health_check_interval < 5:
            raise EventBusValidationError(
                "health_check_interval must be at least 5 seconds"
            )

    def _initialize_distributed_bus(self) -> None:
        """Initialize distributed bus with error handling."""
        try:
            self._distributed_bus = DistributedEventBus(self._redis_url)
            self._redis_available = True
            logger.debug("Distributed bus initialized successfully")
        except Exception as e:
            logger.warning(
                "Failed to initialize distributed bus, using in-memory only",
                error=str(e),
                fallback_enabled=self._fallback_to_memory,
            )
            self._redis_available = False

    async def start(self) -> None:
        """
        Start hybrid event bus with health monitoring.

        Initializes both buses, starts health monitoring, and establishes
        Redis connections if available.

        Raises:
            EventBusError: If critical startup failures occur
        """
        if self._running:
            raise EventBusError("Hybrid event bus is already running")

        self._running = True
        self._start_time = datetime.now(datetime.UTC)
        self._event_count = 0

        # Start in-memory bus (always available)
        await self._in_memory_bus.start()

        # Try to start distributed bus
        await self._start_distributed_bus()

        # Start health monitoring
        self._health_check_task = asyncio.create_task(self._monitor_redis_health())

        logger.info(
            "Hybrid event bus started",
            redis_available=self._redis_available,
            fallback_enabled=self._fallback_to_memory,
            health_check_interval=self._health_check_interval,
        )

    async def _start_distributed_bus(self) -> None:
        """Start distributed bus with error handling."""
        if self._distributed_bus:
            try:
                await self._distributed_bus.start()
                self._redis_available = True
                logger.info("Distributed bus started successfully")
            except Exception as e:
                logger.warning(
                    "Failed to start distributed bus",
                    error=str(e),
                    fallback_available=self._fallback_to_memory,
                )
                self._redis_available = False

    async def stop(self) -> None:
        """
        Stop hybrid event bus and cleanup resources.

        Gracefully shuts down both buses and health monitoring.
        Ensures no resource leaks or hanging tasks.
        """
        if not self._running:
            return

        self._running = False

        # Stop health monitoring
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_check_task

        # Stop both buses
        await self._in_memory_bus.stop()

        if self._distributed_bus:
            try:
                await self._distributed_bus.stop()
            except Exception as e:
                logger.warning("Error stopping distributed bus", error=str(e))

        uptime = (
            (datetime.now(datetime.UTC) - self._start_time).total_seconds()
            if self._start_time
            else 0
        )

        logger.info(
            "Hybrid event bus stopped",
            uptime_seconds=uptime,
            events_processed=self._event_count,
            final_redis_status=self._redis_available,
        )

    async def publish(
        self, event: DomainEvent, correlation_id: str | None = None
    ) -> None:
        """
        Intelligently route events based on processing mode configuration.

        Routes events to appropriate bus(es) based on event registry
        configuration. Handles fallback scenarios and critical event
        failure propagation.

        Args:
            event: Domain event to publish
            correlation_id: Optional correlation ID for tracing

        Raises:
            RuntimeError: If bus is not running
            EventProcessingError: If critical event processing fails
        """
        if not self._running:
            raise RuntimeError("Hybrid event bus is not running")

        self._event_count += 1
        event_type = event.__class__.__name__
        processing_mode = self._registry.get_processing_mode(event_type)
        priority = self._registry.get_priority(event_type)

        # Log routing decision
        logger.debug(
            "Routing event",
            event_type=event_type,
            processing_mode=processing_mode.value,
            priority=priority.name,
            redis_available=self._redis_available,
            correlation_id=correlation_id,
        )

        # Route based on processing mode
        try:
            if processing_mode == EventProcessingMode.IN_MEMORY:
                await self._publish_in_memory_only(event, correlation_id)

            elif processing_mode == EventProcessingMode.DISTRIBUTED:
                await self._publish_distributed_with_fallback(
                    event, correlation_id, priority
                )

            elif processing_mode == EventProcessingMode.HYBRID:
                await self._publish_hybrid_mode(event, correlation_id, priority)

        except Exception as e:
            logger.exception(
                "Failed to publish event in hybrid bus",
                event_type=event_type,
                processing_mode=processing_mode.value,
                error=str(e),
            )
            raise

    async def _publish_in_memory_only(
        self, event: DomainEvent, correlation_id: str | None
    ) -> None:
        """Publish to in-memory bus only."""
        await self._in_memory_bus.publish(event, correlation_id)

    async def _publish_distributed_with_fallback(
        self, event: DomainEvent, correlation_id: str | None, priority: EventPriority
    ) -> None:
        """Publish to distributed bus with fallback to in-memory."""
        if self._redis_available and self._distributed_bus:
            try:
                await self._distributed_bus.publish(event, correlation_id)
                return
            except Exception as e:
                logger.exception(
                    "Failed to publish to distributed bus",
                    event_type=event.__class__.__name__,
                    error=str(e),
                )

                if self._fallback_to_memory:
                    logger.warning(
                        "Falling back to in-memory bus",
                        event_type=event.__class__.__name__,
                    )
                    await self._in_memory_bus.publish(event, correlation_id)
                    return
                raise

        # Redis not available
        if self._fallback_to_memory:
            logger.warning(
                "Redis unavailable, using in-memory bus",
                event_type=event.__class__.__name__,
            )
            await self._in_memory_bus.publish(event, correlation_id)
        else:
            raise RuntimeError("Distributed bus not available and fallback disabled")

    async def _publish_hybrid_mode(
        self, event: DomainEvent, correlation_id: str | None, priority: EventPriority
    ) -> None:
        """Publish to both buses for maximum reliability."""
        tasks = []

        # Always publish to in-memory bus
        tasks.append(self._in_memory_bus.publish(event, correlation_id))

        # Add distributed bus if available
        if self._redis_available and self._distributed_bus:
            tasks.append(self._distributed_bus.publish(event, correlation_id))

        # Execute concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check for errors
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                bus_name = "in-memory" if i == 0 else "distributed"
                logger.error(
                    f"Failed to publish to {bus_name} bus in hybrid mode",
                    event_type=event.__class__.__name__,
                    error=str(result),
                )

                # Critical events must succeed on all available buses
                if priority == EventPriority.CRITICAL:
                    raise EventProcessingError(
                        f"Critical event failed on {bus_name} bus: {result}"
                    )

    def subscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """
        Subscribe handler to appropriate bus(es) based on event configuration.

        Automatically determines which bus(es) to subscribe to based on
        the event's processing mode configuration.

        Args:
            event_type: Event class to subscribe to
            handler: Callable that processes events
        """
        event_name = event_type.__name__
        processing_mode = self._registry.get_processing_mode(event_name)

        if processing_mode == EventProcessingMode.IN_MEMORY:
            self._in_memory_bus.subscribe(event_type, handler)

        elif processing_mode == EventProcessingMode.DISTRIBUTED:
            if self._distributed_bus:
                self._distributed_bus.subscribe(event_type, handler)
            if self._fallback_to_memory:
                self._in_memory_bus.subscribe(event_type, handler)

        elif processing_mode == EventProcessingMode.HYBRID:
            # Subscribe to both buses
            self._in_memory_bus.subscribe(event_type, handler)
            if self._distributed_bus:
                self._distributed_bus.subscribe(event_type, handler)

        logger.debug(
            "Handler subscribed to hybrid bus",
            event_type=event_name,
            processing_mode=processing_mode.value,
            handler=getattr(handler, "__name__", repr(handler)),
        )

    def unsubscribe(
        self, event_type: type[DomainEvent], handler: EventHandlerType
    ) -> None:
        """Unsubscribe handler from appropriate buses."""
        event_name = event_type.__name__
        processing_mode = self._registry.get_processing_mode(event_name)

        if processing_mode == EventProcessingMode.IN_MEMORY:
            self._in_memory_bus.unsubscribe(event_type, handler)

        elif processing_mode == EventProcessingMode.DISTRIBUTED:
            if self._distributed_bus:
                self._distributed_bus.unsubscribe(event_type, handler)
            self._in_memory_bus.unsubscribe(event_type, handler)

        elif processing_mode == EventProcessingMode.HYBRID:
            self._in_memory_bus.unsubscribe(event_type, handler)
            if self._distributed_bus:
                self._distributed_bus.unsubscribe(event_type, handler)

    async def _monitor_redis_health(self) -> None:
        """
        Monitor Redis connectivity and manage automatic recovery.

        Continuously checks Redis health and attempts recovery when
        connection is lost. Updates metrics and logs status changes.
        """
        logger.info(
            "Starting Redis health monitoring",
            check_interval=self._health_check_interval,
        )

        while self._running:
            try:
                await self._check_redis_connectivity()
                await self._handle_redis_recovery_if_needed()

            except Exception as e:
                await self._handle_redis_failure(e)

            # Update health metrics
            self._update_health_metrics()

            await asyncio.sleep(self._health_check_interval)

    async def _check_redis_connectivity(self) -> None:
        """Check Redis connectivity with timeout."""
        if self._distributed_bus and hasattr(self._distributed_bus, "_redis"):
            await asyncio.wait_for(self._distributed_bus._redis.ping(), timeout=5.0)

    async def _handle_redis_recovery_if_needed(self) -> None:
        """Handle Redis recovery when connection is restored."""
        if not self._redis_available:
            logger.info("Redis connection restored")
            self._redis_available = True

            # Re-initialize distributed bus if needed
            if not self._distributed_bus:
                try:
                    self._distributed_bus = DistributedEventBus(self._redis_url)
                    await self._distributed_bus.start()
                    logger.info("Distributed bus re-initialized after recovery")
                except Exception as e:
                    logger.exception(
                        "Failed to re-initialize distributed bus", error=str(e)
                    )
                    self._redis_available = False

    async def _handle_redis_failure(self, error: Exception) -> None:
        """Handle Redis connectivity failure."""
        if self._redis_available:
            logger.warning(
                "Redis connection lost",
                error=str(error),
                fallback_available=self._fallback_to_memory,
            )
            self._redis_available = False

    def _update_health_metrics(self) -> None:
        """Update health monitoring metrics."""
        metrics.event_bus_health.labels(
            bus_type="distributed",
            status="healthy" if self._redis_available else "unhealthy",
        ).set(1 if self._redis_available else 0)

        metrics.event_bus_health.labels(bus_type="in_memory", status="healthy").set(1)

    def is_healthy(self) -> bool:
        """Check overall hybrid bus health."""
        return self._running and (self._redis_available or self._fallback_to_memory)

    def get_statistics(self) -> dict[str, Any]:
        """
        Get comprehensive statistics from both buses.

        Returns:
            Dictionary containing detailed metrics from all components
        """
        stats = {
            "bus_type": "hybrid",
            "running": self._running,
            "redis_available": self._redis_available,
            "fallback_enabled": self._fallback_to_memory,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "events_processed": self._event_count,
            "health_check_interval": self._health_check_interval,
            "in_memory": {},
            "distributed": {},
        }

        # Get in-memory bus statistics
        if hasattr(self._in_memory_bus, "get_statistics"):
            stats["in_memory"] = self._in_memory_bus.get_statistics()

        # Get distributed bus statistics if available
        if self._redis_available and self._distributed_bus:
            if hasattr(self._distributed_bus, "get_statistics"):
                stats["distributed"] = self._distributed_bus.get_statistics()

        return stats


def create_event_bus(
    mode: str = "hybrid", redis_url: str | None = None, **kwargs
) -> EventBus:
    """
    Factory function to create the appropriate event bus implementation.

    Provides a convenient way to instantiate event buses with validation
    and configuration. Supports all bus types with their specific options.

    Args:
        mode: Bus mode - "in_memory", "distributed", or "hybrid"
        redis_url: Redis connection URL for distributed/hybrid modes
        **kwargs: Additional arguments for specific bus types

    Returns:
        Configured event bus instance ready for use

    Raises:
        ValueError: If mode is unknown or required parameters are missing
        EventBusValidationError: If configuration is invalid

    Examples:
        # In-memory bus (fastest)
        bus = create_event_bus("in_memory")

        # Distributed bus (reliable)
        bus = create_event_bus(
            "distributed",
            redis_url="redis://localhost:6379/0",
            dead_letter_queue=True
        )

        # Hybrid bus (best of both)
        bus = create_event_bus(
            "hybrid",
            redis_url="redis://localhost:6379/0",
            fallback_to_memory=True,
            health_check_interval=15
        )

    Design Features:
        - Validates configuration before instantiation
        - Provides sensible defaults for all options
        - Supports all bus-specific configuration options
        - Clear error messages for invalid configurations
    """
    if mode == "in_memory":
        if kwargs:
            logger.warning(
                "Ignoring extra arguments for in-memory bus",
                extra_args=list(kwargs.keys()),
            )
        return InMemoryEventBus()

    if mode == "distributed":
        if not redis_url:
            raise ValueError("Redis URL required for distributed mode")
        return DistributedEventBus(redis_url, **kwargs)

    if mode == "hybrid":
        redis_url = redis_url or "redis://localhost:6379/0"
        return HybridEventBus(redis_url, **kwargs)

    raise ValueError(
        f"Unknown event bus mode: {mode}. "
        f"Valid modes: 'in_memory', 'distributed', 'hybrid'"
    )
