"""
Circuit Breaker Pattern Implementation for EzzDay Core

This module provides a robust circuit breaker pattern implementation for protecting
core services from cascading failures. Implements the classic circuit breaker
states (CLOSED, OPEN, HALF_OPEN) with configurable policies and comprehensive
monitoring capabilities.

Key Features:
- Classic circuit breaker state management
- Configurable failure thresholds and recovery policies
- Automatic and manual recovery mechanisms
- Comprehensive metrics and health monitoring
- Async/await support for non-blocking operations
- Pluggable failure detection strategies

Design Principles:
- Fail-fast when service is unavailable
- Automatic recovery attempts with backoff
- Comprehensive logging and monitoring
- Configurable policies for different service types
- Thread-safe operations for concurrent access

Usage Examples:
    # Basic circuit breaker for database operations
    db_breaker = CircuitBreaker(
        name="database",
        failure_threshold=5,
        recovery_timeout=30.0,
        expected_exception=DatabaseError
    )
    
    @db_breaker
    async def get_user(user_id: str) -> User:
        # Database operation that may fail
        return await database.get_user(user_id)
    
    # Manual circuit breaker control
    breaker = CircuitBreaker("payment_service")
    
    async def process_payment(payment_data):
        if breaker.can_execute():
            try:
                result = await payment_service.charge(payment_data)
                await breaker.record_success()
                return result
            except PaymentError as e:
                await breaker.record_failure(e)
                raise
        else:
            raise CircuitBreakerOpenError("Payment service unavailable")

Error Handling:
    - CircuitBreakerOpenError: Service unavailable due to circuit breaker
    - CircuitBreakerError: General circuit breaker operation errors
    - ValidationError: Invalid circuit breaker configuration

Performance Features:
    - Minimal overhead when circuit is closed
    - Efficient state transitions with atomic operations
    - Configurable monitoring intervals
    - Memory-efficient failure tracking
"""

import asyncio
import enum
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Generic, TypeVar
from weakref import WeakKeyDictionary

from app.core.errors import InfrastructureError, ValidationError
from app.core.logging import get_logger

try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def inc(self, count=1):
            pass
    
    class MockHistogram:
        def labels(self, **kwargs):
            return self
        def observe(self, value):
            pass
    
    class MockGauge:
        def labels(self, **kwargs):
            return self
        def set(self, value):
            pass
    
    class MockMetrics:
        def __init__(self):
            self.circuit_breaker_state_changes = MockCounter()
            self.circuit_breaker_failures = MockCounter()
            self.circuit_breaker_successes = MockCounter()
            self.circuit_breaker_requests_blocked = MockCounter()
            self.circuit_breaker_recovery_attempts = MockCounter()
            self.circuit_breaker_response_time = MockHistogram()
            self.circuit_breaker_failure_rate = MockGauge()
    
    metrics = MockMetrics()

logger = get_logger(__name__)

T = TypeVar("T")


class CircuitBreakerError(InfrastructureError):
    """Base exception for circuit breaker operations."""
    
    default_code = "CIRCUIT_BREAKER_ERROR"
    status_code = 503
    retryable = True


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised when circuit breaker is open and service is unavailable."""
    
    default_code = "CIRCUIT_BREAKER_OPEN"
    status_code = 503
    retryable = True


class CircuitBreakerState(enum.Enum):
    """
    Circuit breaker states following the classic pattern.
    
    State transitions:
    - CLOSED: Normal operation, failures are counted
    - OPEN: Service unavailable, all requests fail fast
    - HALF_OPEN: Testing recovery, limited requests allowed
    """
    
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    
    # Failure detection
    failure_threshold: int = 5
    failure_rate_threshold: float = 0.5
    minimum_requests: int = 10
    
    # Recovery settings
    recovery_timeout: float = 60.0
    half_open_max_requests: int = 3
    
    # Monitoring
    monitoring_window: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    
    # Exception handling
    expected_exception: type[Exception] | None = None
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.failure_threshold < 1:
            raise ValidationError("failure_threshold must be at least 1")
        
        if not 0 < self.failure_rate_threshold <= 1:
            raise ValidationError("failure_rate_threshold must be between 0 and 1")
        
        if self.minimum_requests < 1:
            raise ValidationError("minimum_requests must be at least 1")
        
        if self.recovery_timeout <= 0:
            raise ValidationError("recovery_timeout must be positive")
        
        if self.half_open_max_requests < 1:
            raise ValidationError("half_open_max_requests must be at least 1")


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring."""
    
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    blocked_requests: int = 0
    
    last_failure_time: datetime | None = None
    last_success_time: datetime | None = None
    
    state_changes: int = 0
    recovery_attempts: int = 0
    
    def failure_rate(self) -> float:
        """Calculate current failure rate."""
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests
    
    def success_rate(self) -> float:
        """Calculate current success rate."""
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests
    
    def reset(self) -> None:
        """Reset counters for new monitoring window."""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.blocked_requests = 0


class CircuitBreaker:
    """
    Circuit breaker implementation with configurable policies.
    
    Provides automatic failure detection and recovery for service calls.
    Supports both decorator and manual usage patterns.
    
    Key Features:
    - Configurable failure thresholds and recovery policies
    - Automatic state transitions based on service health
    - Comprehensive monitoring and metrics
    - Thread-safe operations for concurrent access
    - Pluggable failure detection strategies
    
    Usage Patterns:
        # Decorator usage (recommended)
        @circuit_breaker(name="user_service")
        async def get_user(user_id: str) -> User:
            return await user_service.get(user_id)
        
        # Manual usage
        breaker = CircuitBreaker("payment_service")
        
        if breaker.can_execute():
            try:
                result = await payment_service.charge(data)
                await breaker.record_success()
                return result
            except PaymentError as e:
                await breaker.record_failure(e)
                raise
        else:
            raise CircuitBreakerOpenError("Service unavailable")
    
    State Management:
        - CLOSED: Normal operation with failure tracking
        - OPEN: Fast-fail mode, service considered unavailable
        - HALF_OPEN: Recovery testing with limited requests
    """
    
    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        **kwargs
    ):
        """
        Initialize circuit breaker with configuration.
        
        Args:
            name: Unique name for the circuit breaker
            config: Configuration object (overrides other parameters)
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time to wait before attempting recovery
            **kwargs: Additional configuration parameters
        """
        self.name = name
        self.config = config or CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            **kwargs
        )
        
        # State management
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time: datetime | None = None
        self._next_attempt_time: datetime | None = None
        self._half_open_requests = 0
        
        # Metrics and monitoring
        self._metrics = CircuitBreakerMetrics()
        self._created_at = datetime.now(datetime.UTC)
        self._monitoring_window_start = datetime.now(datetime.UTC)
        
        # Thread safety
        self._lock = asyncio.Lock()
        
        logger.info(
            "Circuit breaker initialized",
            name=self.name,
            config=self.config.__dict__
        )
    
    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self._state
    
    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit breaker is closed (normal operation)."""
        return self._state == CircuitBreakerState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit breaker is open (service unavailable)."""
        return self._state == CircuitBreakerState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit breaker is half-open (testing recovery)."""
        return self._state == CircuitBreakerState.HALF_OPEN
    
    def can_execute(self) -> bool:
        """
        Check if requests can be executed based on current state.
        
        Returns:
            True if request can proceed, False if should be blocked
        """
        current_time = datetime.now(datetime.UTC)
        
        if self._state == CircuitBreakerState.CLOSED:
            return True
        
        if self._state == CircuitBreakerState.OPEN:
            # Check if recovery timeout has passed
            if (self._next_attempt_time and 
                current_time >= self._next_attempt_time):
                # Transition to half-open for recovery testing
                asyncio.create_task(self._transition_to_half_open())
                return True
            return False
        
        if self._state == CircuitBreakerState.HALF_OPEN:
            # Allow limited requests during recovery testing
            return self._half_open_requests < self.config.half_open_max_requests
        
        return False
    
    async def record_success(self) -> None:
        """Record successful request execution."""
        async with self._lock:
            current_time = datetime.now(datetime.UTC)
            
            self._metrics.total_requests += 1
            self._metrics.successful_requests += 1
            self._metrics.last_success_time = current_time
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Success during recovery testing
                self._half_open_requests += 1
                
                # Check if we should transition back to closed
                if self._half_open_requests >= self.config.half_open_max_requests:
                    await self._transition_to_closed()
            
            elif self._state == CircuitBreakerState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0
            
            # Update metrics
            metrics.circuit_breaker_successes.labels(
                name=self.name,
                state=self._state.value
            ).inc()
            
            logger.debug(
                "Circuit breaker recorded success",
                name=self.name,
                state=self._state.value,
                success_count=self._metrics.successful_requests
            )
    
    async def record_failure(self, exception: Exception | None = None) -> None:
        """Record failed request execution."""
        async with self._lock:
            current_time = datetime.now(datetime.UTC)
            
            # Check if this is an expected failure type
            if (self.config.expected_exception and 
                exception and 
                not isinstance(exception, self.config.expected_exception)):
                logger.debug(
                    "Ignoring unexpected exception type",
                    name=self.name,
                    exception_type=type(exception).__name__,
                    expected_type=self.config.expected_exception.__name__
                )
                return
            
            self._metrics.total_requests += 1
            self._metrics.failed_requests += 1
            self._metrics.last_failure_time = current_time
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Failure during recovery testing - go back to open
                await self._transition_to_open()
            
            elif self._state == CircuitBreakerState.CLOSED:
                self._failure_count += 1
                self._last_failure_time = current_time
                
                # Check if we should open the circuit
                if self._should_open_circuit():
                    await self._transition_to_open()
            
            # Update metrics
            metrics.circuit_breaker_failures.labels(
                name=self.name,
                state=self._state.value,
                exception_type=type(exception).__name__ if exception else "unknown"
            ).inc()
            
            logger.debug(
                "Circuit breaker recorded failure",
                name=self.name,
                state=self._state.value,
                failure_count=self._failure_count,
                exception=str(exception) if exception else None
            )
    
    async def record_blocked_request(self) -> None:
        """Record request that was blocked by circuit breaker."""
        async with self._lock:
            self._metrics.blocked_requests += 1
            
            metrics.circuit_breaker_requests_blocked.labels(
                name=self.name,
                state=self._state.value
            ).inc()
            
            logger.debug(
                "Circuit breaker blocked request",
                name=self.name,
                state=self._state.value,
                blocked_count=self._metrics.blocked_requests
            )
    
    def _should_open_circuit(self) -> bool:
        """Check if circuit should be opened based on failure criteria."""
        # Check failure count threshold
        if self._failure_count >= self.config.failure_threshold:
            return True
        
        # Check failure rate threshold
        if (self._metrics.total_requests >= self.config.minimum_requests and
            self._metrics.failure_rate() >= self.config.failure_rate_threshold):
            return True
        
        return False
    
    async def _transition_to_open(self) -> None:
        """Transition circuit breaker to open state."""
        old_state = self._state
        self._state = CircuitBreakerState.OPEN
        
        # Set next attempt time
        self._next_attempt_time = (
            datetime.now(datetime.UTC) + 
            timedelta(seconds=self.config.recovery_timeout)
        )
        
        # Reset half-open counter
        self._half_open_requests = 0
        
        await self._log_state_change(old_state, self._state)
        
        logger.warning(
            "Circuit breaker opened",
            name=self.name,
            failure_count=self._failure_count,
            failure_rate=self._metrics.failure_rate(),
            next_attempt_time=self._next_attempt_time.isoformat()
        )
    
    async def _transition_to_half_open(self) -> None:
        """Transition circuit breaker to half-open state."""
        async with self._lock:
            old_state = self._state
            self._state = CircuitBreakerState.HALF_OPEN
            self._half_open_requests = 0
            
            await self._log_state_change(old_state, self._state)
            
            logger.info(
                "Circuit breaker transitioned to half-open",
                name=self.name,
                max_test_requests=self.config.half_open_max_requests
            )
    
    async def _transition_to_closed(self) -> None:
        """Transition circuit breaker to closed state."""
        old_state = self._state
        self._state = CircuitBreakerState.CLOSED
        
        # Reset failure tracking
        self._failure_count = 0
        self._last_failure_time = None
        self._next_attempt_time = None
        self._half_open_requests = 0
        
        await self._log_state_change(old_state, self._state)
        
        logger.info(
            "Circuit breaker closed - service recovered",
            name=self.name,
            recovery_time=datetime.now(datetime.UTC).isoformat()
        )
    
    async def _log_state_change(
        self, old_state: CircuitBreakerState, new_state: CircuitBreakerState
    ) -> None:
        """Log state change with metrics."""
        self._metrics.state_changes += 1
        
        metrics.circuit_breaker_state_changes.labels(
            name=self.name,
            old_state=old_state.value,
            new_state=new_state.value
        ).inc()
        
        logger.info(
            "Circuit breaker state changed",
            name=self.name,
            old_state=old_state.value,
            new_state=new_state.value,
            total_changes=self._metrics.state_changes
        )
    
    async def force_open(self) -> None:
        """Manually force circuit breaker to open state."""
        async with self._lock:
            if self._state != CircuitBreakerState.OPEN:
                await self._transition_to_open()
                
                logger.warning(
                    "Circuit breaker manually forced open",
                    name=self.name
                )
    
    async def force_closed(self) -> None:
        """Manually force circuit breaker to closed state."""
        async with self._lock:
            if self._state != CircuitBreakerState.CLOSED:
                await self._transition_to_closed()
                
                logger.warning(
                    "Circuit breaker manually forced closed",
                    name=self.name
                )
    
    async def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        async with self._lock:
            self._state = CircuitBreakerState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None
            self._next_attempt_time = None
            self._half_open_requests = 0
            
            # Reset metrics
            self._metrics.reset()
            self._monitoring_window_start = datetime.now(datetime.UTC)
            
            logger.info(
                "Circuit breaker reset",
                name=self.name
            )
    
    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive circuit breaker statistics."""
        current_time = datetime.now(datetime.UTC)
        
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "metrics": {
                "total_requests": self._metrics.total_requests,
                "successful_requests": self._metrics.successful_requests,
                "failed_requests": self._metrics.failed_requests,
                "blocked_requests": self._metrics.blocked_requests,
                "failure_rate": self._metrics.failure_rate(),
                "success_rate": self._metrics.success_rate(),
            },
            "configuration": {
                "failure_threshold": self.config.failure_threshold,
                "failure_rate_threshold": self.config.failure_rate_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "half_open_max_requests": self.config.half_open_max_requests,
            },
            "timing": {
                "created_at": self._created_at.isoformat(),
                "last_failure_time": self._metrics.last_failure_time.isoformat() 
                                   if self._metrics.last_failure_time else None,
                "last_success_time": self._metrics.last_success_time.isoformat()
                                   if self._metrics.last_success_time else None,
                "next_attempt_time": self._next_attempt_time.isoformat()
                                   if self._next_attempt_time else None,
            },
            "recovery": {
                "state_changes": self._metrics.state_changes,
                "recovery_attempts": self._metrics.recovery_attempts,
                "half_open_requests": self._half_open_requests,
            }
        }
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator interface for circuit breaker."""
        if asyncio.iscoroutinefunction(func):
            return self._async_decorator(func)
        else:
            return self._sync_decorator(func)
    
    def _async_decorator(self, func: Callable[..., T]) -> Callable[..., T]:
        """Async decorator implementation."""
        async def wrapper(*args, **kwargs) -> T:
            if not self.can_execute():
                await self.record_blocked_request()
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open - service unavailable"
                )
            
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                await self.record_success()
                
                # Record response time
                response_time = time.time() - start_time
                metrics.circuit_breaker_response_time.labels(
                    name=self.name,
                    result="success"
                ).observe(response_time)
                
                return result
                
            except Exception as e:
                await self.record_failure(e)
                
                # Record response time
                response_time = time.time() - start_time
                metrics.circuit_breaker_response_time.labels(
                    name=self.name,
                    result="failure"
                ).observe(response_time)
                
                raise
        
        return wrapper
    
    def _sync_decorator(self, func: Callable[..., T]) -> Callable[..., T]:
        """Sync decorator implementation."""
        def wrapper(*args, **kwargs) -> T:
            if not self.can_execute():
                asyncio.create_task(self.record_blocked_request())
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open - service unavailable"
                )
            
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                asyncio.create_task(self.record_success())
                
                # Record response time
                response_time = time.time() - start_time
                metrics.circuit_breaker_response_time.labels(
                    name=self.name,
                    result="success"
                ).observe(response_time)
                
                return result
                
            except Exception as e:
                asyncio.create_task(self.record_failure(e))
                
                # Record response time
                response_time = time.time() - start_time
                metrics.circuit_breaker_response_time.labels(
                    name=self.name,
                    result="failure"
                ).observe(response_time)
                
                raise
        
        return wrapper


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers.
    
    Provides centralized management of circuit breakers with
    global monitoring and configuration capabilities.
    """
    
    def __init__(self):
        """Initialize circuit breaker registry."""
        self._breakers: dict[str, CircuitBreaker] = {}
        self._default_config = CircuitBreakerConfig()
        self._created_at = datetime.now(datetime.UTC)
        
        logger.info("Circuit breaker registry initialized")
    
    def get_or_create(
        self, 
        name: str, 
        config: CircuitBreakerConfig | None = None,
        **kwargs
    ) -> CircuitBreaker:
        """
        Get existing circuit breaker or create new one.
        
        Args:
            name: Circuit breaker name
            config: Configuration (uses default if None)
            **kwargs: Additional configuration parameters
            
        Returns:
            CircuitBreaker instance
        """
        if name in self._breakers:
            return self._breakers[name]
        
        # Create new circuit breaker
        breaker_config = config or CircuitBreakerConfig(**kwargs)
        breaker = CircuitBreaker(name, breaker_config)
        self._breakers[name] = breaker
        
        logger.info(
            "Circuit breaker created",
            name=name,
            total_breakers=len(self._breakers)
        )
        
        return breaker
    
    def get(self, name: str) -> CircuitBreaker | None:
        """Get circuit breaker by name."""
        return self._breakers.get(name)
    
    def remove(self, name: str) -> bool:
        """Remove circuit breaker from registry."""
        if name in self._breakers:
            del self._breakers[name]
            logger.info(
                "Circuit breaker removed",
                name=name,
                remaining_breakers=len(self._breakers)
            )
            return True
        return False
    
    def get_all_statistics(self) -> dict[str, Any]:
        """Get statistics for all circuit breakers."""
        return {
            "registry": {
                "total_breakers": len(self._breakers),
                "created_at": self._created_at.isoformat(),
            },
            "breakers": {
                name: breaker.get_statistics()
                for name, breaker in self._breakers.items()
            }
        }
    
    async def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            await breaker.reset()
        
        logger.info(
            "All circuit breakers reset",
            count=len(self._breakers)
        )
    
    def list_breakers(self) -> list[str]:
        """List all circuit breaker names."""
        return list(self._breakers.keys())


# Global registry instance
_registry = CircuitBreakerRegistry()


def circuit_breaker(
    name: str,
    config: CircuitBreakerConfig | None = None,
    **kwargs
) -> CircuitBreaker:
    """
    Decorator factory for creating circuit breakers.
    
    Args:
        name: Circuit breaker name
        config: Configuration object
        **kwargs: Additional configuration parameters
        
    Returns:
        Circuit breaker decorator
    """
    return _registry.get_or_create(name, config, **kwargs)


def get_circuit_breaker(name: str) -> CircuitBreaker | None:
    """Get circuit breaker by name from global registry."""
    return _registry.get(name)


def get_all_circuit_breakers() -> dict[str, Any]:
    """Get statistics for all circuit breakers."""
    return _registry.get_all_statistics()


async def reset_all_circuit_breakers() -> None:
    """Reset all circuit breakers."""
    await _registry.reset_all()


# Export main classes and functions
__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig", 
    "CircuitBreakerError",
    "CircuitBreakerOpenError",
    "CircuitBreakerRegistry",
    "CircuitBreakerState",
    "circuit_breaker",
    "get_circuit_breaker",
    "get_all_circuit_breakers",
    "reset_all_circuit_breakers",
]