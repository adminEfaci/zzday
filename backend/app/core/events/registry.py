"""Event registry following pure Python principles.

This module provides comprehensive event registration infrastructure for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are completely
independent of any framework (Pydantic, FastAPI, etc.).

The event registry handles event type registration, handler discovery, processing configuration,
and provides centralized event management with rich metadata and performance monitoring.

Design Principles:
- Pure Python classes with explicit validation
- Framework-agnostic design for maximum portability
- Comprehensive event lifecycle management
- Rich error handling and recovery mechanisms
- Performance monitoring and metrics collection
- Security-focused event validation
- Configurable processing strategies
- Dynamic handler registration and discovery

Architecture:
- RegistryConfig: Configuration management with validation
- RetryPolicy: Retry configuration with comprehensive options
- EventRegistration: Event metadata and handler management
- EventRegistry: Central registry with discovery and monitoring
- RegistryManager: Registry lifecycle and coordination
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from app.core.errors import ConfigurationError, ValidationError
from app.core.events.handlers import EventHandler, HandlerPriority
from app.core.events.types import DomainEvent, EventPriority
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
    
    class MockMetrics:
        def __init__(self):
            self.events_registered = MockCounter()
            self.handlers_registered = MockCounter()
            self.registry_lookups = MockCounter()
    
    metrics = MockMetrics()

logger = get_logger(__name__)


# =====================================================================================
# ENUMS AND CONSTANTS
# =====================================================================================


class EventProcessingMode(Enum):
    """Event processing modes for different scenarios."""

    IN_MEMORY = "in_memory"
    DISTRIBUTED = "distributed"
    HYBRID = "hybrid"


class RegistryState(Enum):
    """Registry operational states."""

    INITIALIZING = "initializing"
    READY = "ready"
    ERROR = "error"
    SHUTDOWN = "shutdown"


class HandlerScope(Enum):
    """Handler registration scopes."""

    GLOBAL = "global"
    LOCAL = "local"
    TENANT = "tenant"
    USER = "user"


# =====================================================================================
# CONFIGURATION CLASSES
# =====================================================================================


@dataclass
class RegistryConfig:
    """
    Event registry configuration with comprehensive validation.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Performance optimization settings
    - Security and isolation configuration
    - Framework-agnostic implementation

    Usage Example:
        config = RegistryConfig(
            enable_dynamic_registration=True,
            max_handlers_per_event=10,
            enable_performance_monitoring=True
        )

        # Validate configuration
        config.validate()
    """

    # Core registry settings
    enable_dynamic_registration: bool = field(default=True)
    enable_handler_discovery: bool = field(default=True)
    enable_performance_monitoring: bool = field(default=True)

    # Capacity limits
    max_registered_events: int = field(default=1000)
    max_handlers_per_event: int = field(default=20)
    max_handler_types: int = field(default=500)

    # Processing configuration
    default_processing_mode: EventProcessingMode = field(
        default=EventProcessingMode.IN_MEMORY
    )
    default_priority: EventPriority = field(default=EventPriority.NORMAL)
    default_handler_priority: HandlerPriority = field(default=HandlerPriority.NORMAL)

    # Validation settings
    enable_strict_validation: bool = field(default=True)
    enable_type_checking: bool = field(default=True)
    enable_duplicate_detection: bool = field(default=True)

    # Performance settings
    enable_caching: bool = field(default=True)
    cache_ttl_seconds: int = field(default=300)
    enable_metrics_collection: bool = field(default=True)

    # Security settings
    enable_handler_isolation: bool = field(default=True)
    allowed_handler_modules: list[str] = field(default_factory=list)
    blocked_handler_modules: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Post-initialization validation."""
        self.validate()

    def validate(self) -> None:
        """
        Validate registry configuration parameters.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        if self.max_registered_events < 1:
            raise ConfigurationError("max_registered_events must be at least 1")

        if self.max_handlers_per_event < 1:
            raise ConfigurationError("max_handlers_per_event must be at least 1")

        if self.max_handler_types < 1:
            raise ConfigurationError("max_handler_types must be at least 1")

        if self.cache_ttl_seconds < 1:
            raise ConfigurationError("cache_ttl_seconds must be at least 1")


@dataclass
class RetryPolicy:
    """
    Retry policy configuration for event processing.

    Design Features:
    - Comprehensive retry configuration
    - Multiple backoff strategies
    - Exception-specific retry rules
    - Performance optimization
    """

    # Basic retry settings
    max_retries: int = field(default=3)
    initial_delay: float = field(default=1.0)
    backoff_multiplier: float = field(default=2.0)
    max_delay: float = field(default=300.0)

    # Advanced settings
    jitter: bool = field(default=True)
    jitter_factor: float = field(default=0.1)
    enable_exponential_backoff: bool = field(default=True)

    # Exception handling
    retry_on_exceptions: set[type[Exception]] = field(default_factory=set)
    no_retry_on_exceptions: set[type[Exception]] = field(default_factory=set)

    # Circuit breaker
    enable_circuit_breaker: bool = field(default=True)
    circuit_breaker_threshold: int = field(default=5)
    circuit_breaker_timeout: int = field(default=300)  # seconds

    def __post_init__(self):
        """Post-initialization validation."""
        self.validate()

    def validate(self) -> None:
        """Validate retry policy parameters."""
        if self.max_retries < 0:
            raise ConfigurationError("max_retries cannot be negative")

        if self.initial_delay <= 0:
            raise ConfigurationError("initial_delay must be positive")

        if self.backoff_multiplier < 1:
            raise ConfigurationError("backoff_multiplier must be at least 1")

        if self.max_delay <= 0:
            raise ConfigurationError("max_delay must be positive")

        if not 0 <= self.jitter_factor <= 1:
            raise ConfigurationError("jitter_factor must be between 0 and 1")

        if self.circuit_breaker_threshold < 1:
            raise ConfigurationError("circuit_breaker_threshold must be at least 1")

    @classmethod
    def default(cls) -> "RetryPolicy":
        """Get default retry policy."""
        return cls()

    @classmethod
    def no_retry(cls) -> "RetryPolicy":
        """Get no-retry policy."""
        return cls(max_retries=0)

    @classmethod
    def aggressive(cls) -> "RetryPolicy":
        """Get aggressive retry policy for critical events."""
        return cls(
            max_retries=5,
            initial_delay=0.5,
            backoff_multiplier=1.5,
            max_delay=60.0,
            circuit_breaker_threshold=10,
        )

    @classmethod
    def conservative(cls) -> "RetryPolicy":
        """Get conservative retry policy for low-priority events."""
        return cls(
            max_retries=2,
            initial_delay=2.0,
            backoff_multiplier=3.0,
            max_delay=600.0,
            circuit_breaker_threshold=3,
        )


@dataclass
class RegistryMetrics:
    """Registry performance metrics and statistics."""

    # Registration statistics
    total_events_registered: int = field(default=0)
    total_handlers_registered: int = field(default=0)
    registration_failures: int = field(default=0)

    # Processing statistics
    total_lookups: int = field(default=0)
    successful_lookups: int = field(default=0)
    failed_lookups: int = field(default=0)
    cache_hits: int = field(default=0)
    cache_misses: int = field(default=0)

    # Performance statistics
    avg_lookup_time: float = field(default=0.0)
    max_lookup_time: float = field(default=0.0)
    total_lookup_time: float = field(default=0.0)

    # State tracking
    last_registration_time: datetime | None = field(default=None)
    last_lookup_time: datetime | None = field(default=None)
    registry_state: RegistryState = field(default=RegistryState.INITIALIZING)

    def record_registration(self, success: bool = True) -> None:
        """Record event/handler registration."""
        if success:
            self.total_events_registered += 1
        else:
            self.registration_failures += 1
        self.last_registration_time = datetime.now(UTC)

    def record_handler_registration(self) -> None:
        """Record handler registration."""
        self.total_handlers_registered += 1

    def record_lookup(
        self, success: bool, lookup_time: float, cache_hit: bool = False
    ) -> None:
        """Record lookup operation."""
        self.total_lookups += 1
        self.total_lookup_time += lookup_time
        self.avg_lookup_time = self.total_lookup_time / self.total_lookups
        self.max_lookup_time = max(self.max_lookup_time, lookup_time)

        if success:
            self.successful_lookups += 1
        else:
            self.failed_lookups += 1

        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

        self.last_lookup_time = datetime.now(UTC)

    def get_cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    def get_lookup_success_rate(self) -> float:
        """Calculate lookup success rate."""
        return (
            self.successful_lookups / self.total_lookups
            if self.total_lookups > 0
            else 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_events_registered": self.total_events_registered,
            "total_handlers_registered": self.total_handlers_registered,
            "registration_failures": self.registration_failures,
            "total_lookups": self.total_lookups,
            "successful_lookups": self.successful_lookups,
            "failed_lookups": self.failed_lookups,
            "lookup_success_rate": self.get_lookup_success_rate(),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.get_cache_hit_rate(),
            "avg_lookup_time": self.avg_lookup_time,
            "max_lookup_time": self.max_lookup_time,
            "last_registration_time": self.last_registration_time.isoformat()
            if self.last_registration_time
            else None,
            "last_lookup_time": self.last_lookup_time.isoformat()
            if self.last_lookup_time
            else None,
            "registry_state": self.registry_state.value,
        }


# =====================================================================================
# EVENT REGISTRATION
# =====================================================================================


@dataclass
class EventRegistration:
    """
    Enhanced event registration with comprehensive metadata.

    Design Features:
    - Complete event metadata management
    - Handler lifecycle coordination
    - Performance monitoring integration
    - Security and validation features
    """

    # Core registration data
    event_type: type[DomainEvent]
    event_name: str = field(default="")

    # Handler management
    handlers: list[type[EventHandler]] = field(default_factory=list)
    handler_priorities: dict[type[EventHandler], HandlerPriority] = field(
        default_factory=dict
    )
    handler_scopes: dict[type[EventHandler], HandlerScope] = field(default_factory=dict)

    # Processing configuration
    processing_mode: EventProcessingMode = field(default=EventProcessingMode.IN_MEMORY)
    priority: EventPriority = field(default=EventPriority.NORMAL)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy.default)

    # Advanced settings
    dead_letter_queue: bool = field(default=True)
    max_processing_time: timedelta = field(
        default_factory=lambda: timedelta(seconds=30)
    )
    enable_ordering: bool = field(default=False)

    # Metadata and categorization
    tags: set[str] = field(default_factory=set)
    category: str = field(default="general")
    description: str = field(default="")
    version: str = field(default="1.0.0")

    # State tracking
    registration_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_accessed: datetime | None = field(default=None)
    access_count: int = field(default=0)

    def __post_init__(self):
        """Post-initialization setup."""
        if not self.event_name:
            self.event_name = self.event_type.__name__
        self.validate()

    def validate(self) -> None:
        """Validate registration data."""
        if not self.event_name:
            raise ValidationError("event_name cannot be empty")

        if not issubclass(self.event_type, DomainEvent):
            raise ValidationError("event_type must be a DomainEvent subclass")

        # Validate handlers
        for handler in self.handlers:
            if not issubclass(handler, EventHandler):
                raise ValidationError(
                    f"Handler {handler} must be an EventHandler subclass"
                )

    def add_handler(
        self,
        handler: type[EventHandler],
        priority: HandlerPriority = HandlerPriority.NORMAL,
        scope: HandlerScope = HandlerScope.GLOBAL,
    ) -> None:
        """Add a handler to this event registration."""
        if handler not in self.handlers:
            self.handlers.append(handler)
            self.handler_priorities[handler] = priority
            self.handler_scopes[handler] = scope

            logger.debug(
                "Handler added to event registration",
                event=self.event_name,
                handler=handler.__name__,
                priority=priority.value,
                scope=scope.value,
            )

    def remove_handler(self, handler: type[EventHandler]) -> None:
        """Remove a handler from this event registration."""
        if handler in self.handlers:
            self.handlers.remove(handler)
            self.handler_priorities.pop(handler, None)
            self.handler_scopes.pop(handler, None)

            logger.debug(
                "Handler removed from event registration",
                event=self.event_name,
                handler=handler.__name__,
            )

    def get_handlers_by_priority(self) -> list[type[EventHandler]]:
        """Get handlers sorted by priority."""
        return sorted(
            self.handlers,
            key=lambda h: self.handler_priorities.get(h, HandlerPriority.NORMAL).value,
            reverse=True,
        )

    def get_handlers_by_scope(self, scope: HandlerScope) -> list[type[EventHandler]]:
        """Get handlers filtered by scope."""
        return [
            handler
            for handler in self.handlers
            if self.handler_scopes.get(handler, HandlerScope.GLOBAL) == scope
        ]

    def record_access(self) -> None:
        """Record access to this registration."""
        self.access_count += 1
        self.last_accessed = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert registration to dictionary."""
        return {
            "event_name": self.event_name,
            "event_type": self.event_type.__name__,
            "event_module": self.event_type.__module__,
            "handler_count": len(self.handlers),
            "processing_mode": self.processing_mode.value,
            "priority": self.priority.value,
            "dead_letter_queue": self.dead_letter_queue,
            "max_processing_time": self.max_processing_time.total_seconds(),
            "enable_ordering": self.enable_ordering,
            "tags": list(self.tags),
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "registration_time": self.registration_time.isoformat(),
            "last_accessed": self.last_accessed.isoformat()
            if self.last_accessed
            else None,
            "access_count": self.access_count,
            "retry_policy": {
                "max_retries": self.retry_policy.max_retries,
                "initial_delay": self.retry_policy.initial_delay,
                "max_delay": self.retry_policy.max_delay,
            },
        }


# =====================================================================================
# EVENT REGISTRY
# =====================================================================================


class EventRegistry:
    """
    Enhanced event registry following pure Python principles.

    Provides comprehensive event registration, handler discovery, and processing
    configuration management with performance monitoring and security features.

    Design Features:
    - Pure Python implementation
    - Dynamic event and handler registration
    - Performance monitoring and caching
    - Security validation and isolation
    - Comprehensive error handling
    - Rich metadata and categorization

    Usage Example:
        registry = EventRegistry(config)

        # Register event with handlers
        registration = registry.register(
            UserRegistered,
            handlers=[EmailHandler, LoggingHandler],
            processing_mode=EventProcessingMode.HYBRID,
            priority=EventPriority.HIGH
        )

        # Look up handlers
        handlers = registry.get_handlers("UserRegistered")
    """

    def __init__(self, config: RegistryConfig = None):
        """
        Initialize event registry.

        Args:
            config: Registry configuration
        """
        self.config = config or RegistryConfig()
        self.metrics = RegistryMetrics()

        # Storage
        self._registrations: dict[str, EventRegistration] = {}
        self._event_types: dict[str, type[DomainEvent]] = {}
        self._handler_registry: dict[type[EventHandler], set[str]] = defaultdict(set)

        # Caching
        self._lookup_cache: dict[str, Any] = {}
        self._cache_timestamps: dict[str, datetime] = {}

        # State tracking
        self._initialized = False
        self.metrics.registry_state = RegistryState.INITIALIZING

        logger.info("Event registry initialized", config=self.config.__dict__)

    def initialize(self) -> None:
        """Initialize registry and load default configurations."""
        if self._initialized:
            logger.warning("Registry already initialized")
            return

        try:
            # Register system events
            self._register_system_events()

            # Set state
            self._initialized = True
            self.metrics.registry_state = RegistryState.READY

            logger.info("Event registry initialization completed")

        except Exception as e:
            self.metrics.registry_state = RegistryState.ERROR
            logger.exception(f"Failed to initialize event registry: {e}")
            raise ConfigurationError(f"Registry initialization failed: {e}")

    def register(
        self,
        event_type: type[DomainEvent],
        handlers: list[type[EventHandler]] | None = None,
        processing_mode: EventProcessingMode = None,
        priority: EventPriority = None,
        retry_policy: RetryPolicy | None = None,
        dead_letter_queue: bool = True,
        max_processing_time: timedelta | None = None,
        tags: set[str] | None = None,
        category: str = "general",
        description: str = "",
        version: str = "1.0.0",
        enable_ordering: bool = False,
    ) -> EventRegistration:
        """
        Register an event type with its configuration.

        Args:
            event_type: Event class to register
            handlers: List of handler classes
            processing_mode: Processing mode for the event
            priority: Event priority level
            retry_policy: Retry configuration
            dead_letter_queue: Enable dead letter queue
            max_processing_time: Maximum processing time
            tags: Event tags for categorization
            category: Event category
            description: Event description
            version: Event version
            enable_ordering: Whether to maintain event ordering

        Returns:
            EventRegistration: Created registration

        Raises:
            ConfigurationError: If registration fails
        """
        start_time = time.time()
        event_name = event_type.__name__

        try:
            # Validate capacity limits
            if len(self._registrations) >= self.config.max_registered_events:
                raise ConfigurationError(
                    f"Maximum registered events limit reached: {self.config.max_registered_events}"
                )

            # Check for existing registration
            if (
                event_name in self._registrations
                and not self.config.enable_dynamic_registration
            ):
                raise ConfigurationError(f"Event {event_name} is already registered")

            # Apply defaults
            processing_mode = processing_mode or self.config.default_processing_mode
            priority = priority or self.config.default_priority
            retry_policy = retry_policy or RetryPolicy.default()
            max_processing_time = max_processing_time or timedelta(seconds=30)
            handlers = handlers or []
            tags = tags or set()

            # Validate handlers
            if len(handlers) > self.config.max_handlers_per_event:
                raise ConfigurationError(
                    f"Too many handlers for event {event_name}: {len(handlers)} > {self.config.max_handlers_per_event}"
                )

            # Create registration
            registration = EventRegistration(
                event_type=event_type,
                event_name=event_name,
                handlers=handlers.copy(),
                processing_mode=processing_mode,
                priority=priority,
                retry_policy=retry_policy,
                dead_letter_queue=dead_letter_queue,
                max_processing_time=max_processing_time,
                tags=tags,
                category=category,
                description=description,
                version=version,
                enable_ordering=enable_ordering,
            )

            # Store registration
            self._registrations[event_name] = registration
            self._event_types[event_name] = event_type

            # Update handler registry
            for handler in handlers:
                self._handler_registry[handler].add(event_name)

            # Clear relevant cache entries
            self._invalidate_cache(event_name)

            # Record metrics
            self.metrics.record_registration(True)
            for _ in handlers:
                self.metrics.record_handler_registration()
            
            # Update external metrics if available
            try:
                metrics.events_registered.labels(
                    event_type=event_name,
                    processing_mode=processing_mode.value,
                    priority=priority.value
                ).inc()
            except Exception:
                pass  # Ignore metrics errors

            lookup_time = time.time() - start_time

            logger.info(
                "Event registered successfully",
                event=event_name,
                processing_mode=processing_mode.value,
                priority=priority.value,
                handler_count=len(handlers),
                registration_time=lookup_time,
            )

            return registration

        except Exception as e:
            self.metrics.record_registration(False)
            logger.exception(
                "Failed to register event",
                event=event_name,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    def register_handler(
        self,
        event_type: type[DomainEvent],
        handler: type[EventHandler],
        priority: HandlerPriority = HandlerPriority.NORMAL,
        scope: HandlerScope = HandlerScope.GLOBAL,
    ) -> None:
        """
        Register a handler for an event type.

        Args:
            event_type: Event type to handle
            handler: Handler class
            priority: Handler priority
            scope: Handler scope
        """
        event_name = event_type.__name__

        # Auto-register event if not exists
        if event_name not in self._registrations:
            self.register(event_type)

        # Add handler to registration
        registration = self._registrations[event_name]
        registration.add_handler(handler, priority, scope)

        # Update handler registry
        self._handler_registry[handler].add(event_name)

        # Clear cache
        self._invalidate_cache(event_name)

        # Record metrics
        self.metrics.record_handler_registration()

        logger.debug(
            "Handler registered for event",
            event=event_name,
            handler=handler.__name__,
            priority=priority.value,
            scope=scope.value,
        )

    def get_registration(self, event_type: str) -> EventRegistration | None:
        """
        Get registration for an event type.

        Args:
            event_type: Event type name

        Returns:
            EventRegistration: Registration or None if not found
        """
        start_time = time.time()

        try:
            # Check cache first
            cache_key = f"registration:{event_type}"
            if self.config.enable_caching and cache_key in self._lookup_cache:
                cache_timestamp = self._cache_timestamps.get(cache_key)
                if (
                    cache_timestamp
                    and (datetime.now(UTC) - cache_timestamp).total_seconds()
                    < self.config.cache_ttl_seconds
                ):
                    lookup_time = time.time() - start_time
                    self.metrics.record_lookup(True, lookup_time, cache_hit=True)
                    return self._lookup_cache[cache_key]

            # Get from registry
            registration = self._registrations.get(event_type)

            if registration:
                registration.record_access()

                # Cache result
                if self.config.enable_caching:
                    self._lookup_cache[cache_key] = registration
                    self._cache_timestamps[cache_key] = datetime.now(UTC)

            lookup_time = time.time() - start_time
            self.metrics.record_lookup(
                registration is not None, lookup_time, cache_hit=False
            )

            return registration

        except Exception as e:
            lookup_time = time.time() - start_time
            self.metrics.record_lookup(False, lookup_time, cache_hit=False)
            logger.exception(f"Failed to get registration for {event_type}: {e}")
            return None

    def get_handlers(
        self, event_type: str, scope: HandlerScope = None
    ) -> list[type[EventHandler]]:
        """
        Get handlers for an event type.

        Args:
            event_type: Event type name
            scope: Optional scope filter

        Returns:
            list[Type[EventHandler]]: List of handler classes
        """
        registration = self.get_registration(event_type)
        if not registration:
            return []

        if scope:
            return registration.get_handlers_by_scope(scope)
        return registration.get_handlers_by_priority()

    def get_event_type(self, event_type: str) -> type[DomainEvent] | None:
        """Get event class by name."""
        return self._event_types.get(event_type)

    def get_processing_mode(self, event_type: str) -> EventProcessingMode:
        """Get processing mode for an event type."""
        registration = self.get_registration(event_type)
        return (
            registration.processing_mode
            if registration
            else self.config.default_processing_mode
        )

    def get_priority(self, event_type: str) -> EventPriority:
        """Get priority for an event type."""
        registration = self.get_registration(event_type)
        return registration.priority if registration else self.config.default_priority

    def get_retry_policy(self, event_type: str) -> RetryPolicy:
        """Get retry policy for an event type."""
        registration = self.get_registration(event_type)
        return registration.retry_policy if registration else RetryPolicy.default()

    def should_use_distributed_processing(self, event_type: str) -> bool:
        """Check if event should use distributed processing."""
        mode = self.get_processing_mode(event_type)
        return mode in [EventProcessingMode.DISTRIBUTED, EventProcessingMode.HYBRID]

    def get_by_category(self, category: str) -> list[EventRegistration]:
        """Get all events in a category."""
        return [
            registration
            for registration in self._registrations.values()
            if registration.category == category
        ]

    def get_by_tag(self, tag: str) -> list[EventRegistration]:
        """Get all events with a specific tag."""
        return [
            registration
            for registration in self._registrations.values()
            if tag in registration.tags
        ]

    def get_events_for_handler(self, handler: type[EventHandler]) -> list[str]:
        """Get event types handled by a specific handler."""
        return list(self._handler_registry.get(handler, set()))

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._lookup_cache.clear()
        self._cache_timestamps.clear()
        logger.debug("Registry cache cleared")

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive registry statistics."""
        # Calculate distribution statistics
        mode_counts = defaultdict(int)
        priority_counts = defaultdict(int)
        category_counts = defaultdict(int)

        for registration in self._registrations.values():
            mode_counts[registration.processing_mode.value] += 1
            priority_counts[registration.priority.value] += 1
            category_counts[registration.category] += 1

        return {
            "total_events": len(self._registrations),
            "total_handlers": sum(
                len(r.handlers) for r in self._registrations.values()
            ),
            "total_handler_types": len(self._handler_registry),
            "by_mode": dict(mode_counts),
            "by_priority": dict(priority_counts),
            "by_category": dict(category_counts),
            "cache_size": len(self._lookup_cache),
            "cache_hit_rate": self.metrics.get_cache_hit_rate(),
            "lookup_success_rate": self.metrics.get_lookup_success_rate(),
            "metrics": self.metrics.to_dict(),
            "initialized": self._initialized,
            "health_status": self._get_health_status(),
        }
    
    def _get_health_status(self) -> dict[str, Any]:
        """Get registry health status."""
        issues = []
        
        # Check capacity
        if len(self._registrations) > self.config.max_registered_events * 0.9:
            issues.append("Approaching maximum event capacity")
        
        # Check cache performance
        if self.metrics.get_cache_hit_rate() < 0.5:
            issues.append("Low cache hit rate")
        
        # Check lookup performance
        if self.metrics.get_lookup_success_rate() < 0.95:
            issues.append("High lookup failure rate")
        
        # Determine overall health
        if not issues:
            status = "healthy"
        elif len(issues) <= 1:
            status = "warning"
        else:
            status = "critical"
        
        return {
            "status": status,
            "issues": issues,
            "capacity_usage": len(self._registrations) / self.config.max_registered_events,
            "performance_score": min(
                self.metrics.get_cache_hit_rate(),
                self.metrics.get_lookup_success_rate()
            ),
        }

    def _register_system_events(self) -> None:
        """Register system events."""
        try:
            from app.core.events.types import (
                ApplicationStarted,
                ApplicationStopping,
                SystemEvent,
            )

            # Register system events
            self.register(
                SystemEvent,
                processing_mode=EventProcessingMode.IN_MEMORY,
                priority=EventPriority.HIGH,
                category="system",
            )

            self.register(
                ApplicationStarted,
                processing_mode=EventProcessingMode.HYBRID,
                priority=EventPriority.HIGH,
                category="system",
            )

            self.register(
                ApplicationStopping,
                processing_mode=EventProcessingMode.HYBRID,
                priority=EventPriority.CRITICAL,
                category="system",
            )

            logger.info("System events registered")

        except Exception as e:
            logger.warning(f"Failed to register system events: {e}")

    def _invalidate_cache(self, event_type: str) -> None:
        """Invalidate cache entries for an event type."""
        if not self.config.enable_caching:
            return

        keys_to_remove = [key for key in self._lookup_cache if event_type in key]

        for key in keys_to_remove:
            self._lookup_cache.pop(key, None)
            self._cache_timestamps.pop(key, None)


# =====================================================================================
# LEGACY COMPATIBILITY
# =====================================================================================

# Global enhanced registry instance
_enhanced_registry: EventRegistry | None = None

# Original simple registry for backward compatibility
_EVENT_REGISTRY: dict[str, type[DomainEvent]] = {}


def get_registry() -> EventRegistry:
    """Get the enhanced event registry instance."""
    global _enhanced_registry
    if _enhanced_registry is None:
        _enhanced_registry = EventRegistry()
        _enhanced_registry.initialize()
    return _enhanced_registry


def register_event(event_cls: type[DomainEvent]):
    """Register an event class (backward compatibility)."""
    _EVENT_REGISTRY[event_cls.__name__] = event_cls
    # Also register in enhanced registry with defaults
    get_registry().register(event_cls)


def get_event_class(event_type: str) -> type[DomainEvent]:
    """Get event class by name (backward compatibility)."""
    # Try enhanced registry first
    registry = get_registry()
    event_class = registry.get_event_type(event_type)
    if event_class:
        return event_class

    # Fallback to legacy registry
    if event_type in _EVENT_REGISTRY:
        return _EVENT_REGISTRY[event_type]

    raise ValueError(f"Unknown event type: {event_type}")


def register_enhanced(event_type: type[DomainEvent], **kwargs) -> EventRegistration:
    """Register an event with enhanced configuration."""
    return get_registry().register(event_type, **kwargs)


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Enums
    "EventProcessingMode",
    # Core classes
    "EventRegistration",
    "EventRegistry",
    "HandlerScope",
    # Configuration
    "RegistryConfig",
    "RegistryMetrics",
    "RegistryState",
    "RetryPolicy",
    "get_event_class",
    # Factory functions
    "get_registry",
    "register_enhanced",
    # Legacy compatibility
    "register_event",
]
