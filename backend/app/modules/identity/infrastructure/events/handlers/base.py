"""
Event Handler Base Infrastructure

Provides the foundation for all event handlers in the identity domain,
including base classes, metadata management, decorators, and core abstractions.
"""

import asyncio
import inspect
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, ClassVar, Generic, TypeVar
from uuid import UUID, uuid4

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent, EventValidator
from app.core.logging import get_logger

logger = get_logger(__name__)

# Type variable for event types
EventType = TypeVar("EventType", bound=DomainEvent)


class HandlerPriority(Enum):
    """Handler execution priority levels."""
    
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


class HandlerRetryPolicy(Enum):
    """Handler retry policies for error handling."""
    
    NONE = "none"           # No retries
    EXPONENTIAL = "exponential"  # Exponential backoff
    FIXED = "fixed"         # Fixed interval
    LINEAR = "linear"       # Linear increase


@dataclass
class HandlerMetadata:
    """
    Metadata for event handlers including configuration and capabilities.
    
    Tracks handler information, retry policies, timeouts, and performance
    characteristics for optimal execution and monitoring.
    """
    
    # Handler identification
    handler_id: str
    handler_name: str
    event_types: set[str]
    
    # Execution configuration
    priority: HandlerPriority = HandlerPriority.NORMAL
    async_handler: bool = False
    timeout_seconds: float = 30.0
    
    # Retry configuration
    retry_policy: HandlerRetryPolicy = HandlerRetryPolicy.EXPONENTIAL
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    retry_backoff_multiplier: float = 2.0
    
    # Feature flags
    supports_batch_processing: bool = False
    requires_transaction: bool = False
    idempotent: bool = True
    
    # Health and monitoring
    enabled: bool = True
    last_executed: datetime | None = None
    execution_count: int = 0
    error_count: int = 0
    
    # Tags and categorization
    tags: set[str] = field(default_factory=set)
    category: str = "general"
    
    def __post_init__(self):
        """Validate metadata after initialization."""
        self.validate()
    
    def validate(self) -> None:
        """Validate handler metadata."""
        self.handler_id = EventValidator.validate_string(
            self.handler_id, "handler_id", required=True, min_length=1, max_length=100
        )
        self.handler_name = EventValidator.validate_string(
            self.handler_name, "handler_name", required=True, min_length=1, max_length=200
        )
        
        if not self.event_types:
            raise ValidationError("Handler must support at least one event type")
        
        # Validate timeout
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValidationError("Timeout must be between 0 and 300 seconds")
        
        # Validate retry configuration
        if self.max_retries < 0 or self.max_retries > 10:
            raise ValidationError("Max retries must be between 0 and 10")
        
        if self.retry_delay_seconds < 0 or self.retry_delay_seconds > 60:
            raise ValidationError("Retry delay must be between 0 and 60 seconds")
    
    def should_retry(self, attempt: int, error: Exception) -> bool:
        """
        Determine if handler should retry based on policy and error.
        
        Args:
            attempt: Current attempt number (1-based)
            error: Exception that occurred
            
        Returns:
            bool: True if should retry
        """
        if self.retry_policy == HandlerRetryPolicy.NONE:
            return False
        
        if attempt > self.max_retries:
            return False
        
        # Don't retry validation errors (they won't change)
        return not isinstance(error, ValidationError)
    
    def get_retry_delay(self, attempt: int) -> float:
        """
        Calculate retry delay based on policy and attempt number.
        
        Args:
            attempt: Current attempt number (1-based)
            
        Returns:
            float: Delay in seconds
        """
        if self.retry_policy == HandlerRetryPolicy.NONE:
            return 0.0
        
        base_delay = self.retry_delay_seconds
        
        if self.retry_policy == HandlerRetryPolicy.FIXED:
            return base_delay
        if self.retry_policy == HandlerRetryPolicy.LINEAR:
            return base_delay * attempt
        if self.retry_policy == HandlerRetryPolicy.EXPONENTIAL:
            return base_delay * (self.retry_backoff_multiplier ** (attempt - 1))
        
        return base_delay
    
    def increment_execution(self) -> None:
        """Increment execution counter and update last executed time."""
        self.execution_count += 1
        self.last_executed = datetime.now(UTC)
    
    def increment_error(self) -> None:
        """Increment error counter."""
        self.error_count += 1
    
    def get_success_rate(self) -> float:
        """Calculate handler success rate."""
        if self.execution_count == 0:
            return 1.0
        return 1.0 - (self.error_count / self.execution_count)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "handler_id": self.handler_id,
            "handler_name": self.handler_name,
            "event_types": list(self.event_types),
            "priority": self.priority.value,
            "async_handler": self.async_handler,
            "timeout_seconds": self.timeout_seconds,
            "retry_policy": self.retry_policy.value,
            "max_retries": self.max_retries,
            "retry_delay_seconds": self.retry_delay_seconds,
            "retry_backoff_multiplier": self.retry_backoff_multiplier,
            "supports_batch_processing": self.supports_batch_processing,
            "requires_transaction": self.requires_transaction,
            "idempotent": self.idempotent,
            "enabled": self.enabled,
            "last_executed": self.last_executed.isoformat() if self.last_executed else None,
            "execution_count": self.execution_count,
            "error_count": self.error_count,
            "tags": list(self.tags),
            "category": self.category,
        }


@dataclass
class HandlerExecutionContext:
    """
    Context information for handler execution.
    
    Provides runtime context, tracing information, and execution metadata
    for handlers during event processing.
    """
    
    # Event information
    event: DomainEvent
    event_id: UUID
    correlation_id: str | None
    
    # Execution context
    execution_id: UUID = field(default_factory=uuid4)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    attempt_number: int = 1
    
    # Handler context
    handler_id: str = ""
    handler_name: str = ""
    
    # Processing flags
    is_retry: bool = False
    batch_processing: bool = False
    transaction_required: bool = False
    
    # Additional context
    user_id: UUID | None = None
    tenant_id: UUID | None = None
    trace_id: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for logging."""
        return {
            "execution_id": str(self.execution_id),
            "event_id": str(self.event_id),
            "event_type": self.event.__class__.__name__,
            "correlation_id": self.correlation_id,
            "started_at": self.started_at.isoformat(),
            "attempt_number": self.attempt_number,
            "handler_id": self.handler_id,
            "handler_name": self.handler_name,
            "is_retry": self.is_retry,
            "batch_processing": self.batch_processing,
            "transaction_required": self.transaction_required,
            "user_id": str(self.user_id) if self.user_id else None,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "trace_id": self.trace_id,
        }


@dataclass
class HandlerResult:
    """
    Result of handler execution with success/failure information.
    
    Captures execution outcome, timing, errors, and additional metadata
    for monitoring and debugging purposes.
    """
    
    # Execution outcome
    success: bool
    handler_id: str
    execution_id: UUID
    
    # Timing information
    started_at: datetime
    completed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    # Error information
    error: Exception | None = None
    error_message: str | None = None
    error_type: str | None = None
    
    # Additional data
    result_data: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    
    @property
    def duration_ms(self) -> float:
        """Get execution duration in milliseconds."""
        delta = self.completed_at - self.started_at
        return delta.total_seconds() * 1000
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for logging."""
        return {
            "success": self.success,
            "handler_id": self.handler_id,
            "execution_id": str(self.execution_id),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "error_type": self.error_type,
            "result_data": self.result_data,
            "metrics": self.metrics,
        }


class EventHandlerBase(ABC, Generic[EventType]):
    """
    Abstract base class for all event handlers.
    
    Provides the foundation for event handler implementations with support
    for both synchronous and asynchronous processing, error handling,
    and comprehensive metadata management.
    
    Design Features:
    - Type-safe event handling with generics
    - Automatic metadata generation and validation
    - Support for both sync and async handlers
    - Built-in error handling and isolation
    - Comprehensive logging and monitoring
    - Transaction support detection
    - Idempotency handling
    
    Usage Example:
        class UserCreatedHandler(EventHandlerBase[UserCreated]):
            async def handle(self, event: UserCreated, context: HandlerExecutionContext) -> HandlerResult:
                # Process user creation
                await self.send_welcome_email(event.email)
                await self.setup_default_preferences(event.user_id)
                
                return HandlerResult(
                    success=True,
                    handler_id=self.metadata.handler_id,
                    execution_id=context.execution_id,
                    started_at=context.started_at,
                    result_data={"welcome_email_sent": True}
                )
    """
    
    # Class-level metadata (set by subclasses)
    handler_name: ClassVar[str] = ""
    event_types: ClassVar[set[str]] = set()
    priority: ClassVar[HandlerPriority] = HandlerPriority.NORMAL
    category: ClassVar[str] = "general"
    
    def __init__(self):
        """Initialize event handler with metadata."""
        self._metadata = self._create_metadata()
        self._validate_implementation()
    
    @property
    def metadata(self) -> HandlerMetadata:
        """Get handler metadata."""
        return self._metadata
    
    def _create_metadata(self) -> HandlerMetadata:
        """Create handler metadata from class configuration."""
        # Generate handler ID from class name
        handler_id = f"{self.__class__.__module__}.{self.__class__.__name__}"
        
        # Use class name as default handler name
        handler_name = self.handler_name or self.__class__.__name__
        
        # Determine if handler is async
        is_async = asyncio.iscoroutinefunction(self.handle)
        
        # Get event types from class or infer from generic
        event_types = set(self.event_types)
        if not event_types:
            # Try to infer from generic type annotation
            orig_bases = getattr(self.__class__, "__orig_bases__", ())
            for base in orig_bases:
                if (hasattr(base, "__origin__") and base.__origin__ is EventHandlerBase and
                    hasattr(base, "__args__") and base.__args__):
                        event_type = base.__args__[0]
                        if hasattr(event_type, "__name__"):
                            event_types.add(event_type.__name__)
        
        return HandlerMetadata(
            handler_id=handler_id,
            handler_name=handler_name,
            event_types=event_types,
            priority=self.priority,
            async_handler=is_async,
            category=self.category,
            **self._get_handler_config()
        )
    
    def _get_handler_config(self) -> dict[str, Any]:
        """
        Get handler-specific configuration.
        
        Override this method to provide custom configuration for the handler.
        
        Returns:
            dict[str, Any]: Handler configuration
        """
        return {}
    
    def _validate_implementation(self) -> None:
        """Validate handler implementation."""
        # Check that handle method is implemented
        if not hasattr(self, "handle"):
            raise ValidationError(f"Handler {self.__class__.__name__} must implement handle method")
        
        # Check handle method signature
        sig = inspect.signature(self.handle)
        params = list(sig.parameters.keys())
        
        if len(params) < 2:
            raise ValidationError(
                f"Handler {self.__class__.__name__}.handle must accept at least 2 parameters: event and context"
            )
        
        # Validate that event types are specified
        if not self.metadata.event_types:
            raise ValidationError(f"Handler {self.__class__.__name__} must specify event_types")
    
    @abstractmethod
    async def handle(self, event: EventType, context: HandlerExecutionContext) -> HandlerResult:
        """
        Handle the domain event.
        
        This method must be implemented by all concrete handlers to process
        the specific event type and return execution results.
        
        Args:
            event: The domain event to process
            context: Execution context with tracing and metadata
            
        Returns:
            HandlerResult: Execution result with success/failure information
            
        Raises:
            ValidationError: If event is invalid
            Exception: Any processing error (will be caught and handled by executor)
        """
    
    def can_handle(self, event: DomainEvent) -> bool:
        """
        Check if this handler can process the given event.
        
        Args:
            event: Domain event to check
            
        Returns:
            bool: True if handler can process the event
        """
        return event.__class__.__name__ in self.metadata.event_types
    
    def is_enabled(self) -> bool:
        """Check if handler is currently enabled."""
        return self.metadata.enabled
    
    def enable(self) -> None:
        """Enable the handler."""
        self.metadata.enabled = True
        logger.info(f"Handler {self.metadata.handler_name} enabled")
    
    def disable(self) -> None:
        """Disable the handler."""
        self.metadata.enabled = False
        logger.warning(f"Handler {self.metadata.handler_name} disabled")
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the handler."""
        self.metadata.tags.add(tag)
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the handler."""
        self.metadata.tags.discard(tag)
    
    def has_tag(self, tag: str) -> bool:
        """Check if handler has a specific tag."""
        return tag in self.metadata.tags
    
    def __str__(self) -> str:
        """String representation of handler."""
        return f"{self.__class__.__name__}(id={self.metadata.handler_id})"
    
    def __repr__(self) -> str:
        """Detailed representation of handler."""
        return (
            f"{self.__class__.__name__}("
            f"id={self.metadata.handler_id}, "
            f"events={list(self.metadata.event_types)}, "
            f"priority={self.metadata.priority.name}, "
            f"async={self.metadata.async_handler}, "
            f"enabled={self.metadata.enabled}"
            f")"
        )


def event_handler(
    event_types: list[str] | str | None = None,
    priority: HandlerPriority = HandlerPriority.NORMAL,
    category: str = "general",
    timeout_seconds: float = 30.0,
    retry_policy: HandlerRetryPolicy = HandlerRetryPolicy.EXPONENTIAL,
    max_retries: int = 3,
    requires_transaction: bool = False,
    idempotent: bool = True,
    tags: list[str] | None = None,
) -> Callable[[type], type]:
    """
    Decorator for event handler classes.
    
    Provides a convenient way to configure event handler metadata
    using decorator syntax instead of class attributes.
    
    Args:
        event_types: Event types this handler processes
        priority: Handler execution priority
        category: Handler category for organization
        timeout_seconds: Handler timeout in seconds
        retry_policy: Retry policy for failed executions
        max_retries: Maximum number of retries
        requires_transaction: Whether handler requires transaction
        idempotent: Whether handler is idempotent
        tags: Handler tags for categorization
        **kwargs: Additional handler configuration
        
    Returns:
        Callable: Decorator function
        
    Usage Example:
        @event_handler(
            event_types=["UserCreated", "UserActivated"],
            priority=HandlerPriority.HIGH,
            category="user_lifecycle",
            timeout_seconds=60.0,
            tags=["critical", "user"]
        )
        class UserLifecycleHandler(EventHandlerBase):
            async def handle(self, event, context):
                # Handle user lifecycle events
                pass
    """
    def decorator(handler_class: type) -> type:
        # Set class attributes from decorator parameters
        if event_types is not None:
            if isinstance(event_types, str):
                handler_class.event_types = {event_types}
            else:
                handler_class.event_types = set(event_types)
        
        handler_class.priority = priority
        handler_class.category = category
        
        # Store additional configuration for _get_handler_config
        config = {
            "timeout_seconds": timeout_seconds,
            "retry_policy": retry_policy,
            "max_retries": max_retries,
            "requires_transaction": requires_transaction,
            "idempotent": idempotent,
            "tags": set(tags) if tags else set(),
        }
        
        # Override _get_handler_config method
        original_get_config = getattr(handler_class, "_get_handler_config", lambda self: {})
        
        def _get_handler_config(self) -> dict[str, Any]:
            base_config = original_get_config(self)
            base_config.update(config)
            return base_config
        
        handler_class._get_handler_config = _get_handler_config
        
        return handler_class
    
    return decorator


# Export all classes and functions
__all__ = [
    "EventHandlerBase",
    "EventType",
    "HandlerExecutionContext",
    "HandlerMetadata",
    "HandlerPriority",
    "HandlerResult",
    "HandlerRetryPolicy",
    "event_handler",
]