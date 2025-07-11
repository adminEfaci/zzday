"""Circuit breaker pattern implementation for external service resilience.

This module provides circuit breaker functionality to prevent cascading failures
when external services are unavailable, improving overall system availability.
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5        # Number of failures before opening
    recovery_timeout: int = 60        # Seconds before attempting recovery
    success_threshold: int = 3        # Successful calls to close circuit
    timeout: int = 30                 # Timeout for individual calls
    expected_exception: type[Exception] = Exception  # Exception type to catch
    
    # Advanced settings
    half_open_max_calls: int = 10     # Max calls in half-open state
    failure_rate_threshold: float = 0.5  # Failure rate to open circuit (0.0-1.0)
    minimum_throughput: int = 10      # Minimum calls before calculating failure rate


class CircuitBreakerError(Exception):
    """Circuit breaker specific errors."""


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised when circuit breaker is open."""


class CircuitBreakerTimeoutError(CircuitBreakerError):
    """Raised when circuit breaker times out."""


class CircuitBreakerStats:
    """Statistics for circuit breaker."""
    
    def __init__(self):
        self.total_calls = 0
        self.failed_calls = 0
        self.successful_calls = 0
        self.timeout_calls = 0
        self.rejected_calls = 0
        self.last_failure_time: datetime | None = None
        self.last_success_time: datetime | None = None
        self.state_changes = 0
        self.current_state_start_time = datetime.utcnow()
    
    @property
    def failure_rate(self) -> float:
        """Calculate current failure rate."""
        if self.total_calls == 0:
            return 0.0
        return self.failed_calls / self.total_calls
    
    @property
    def success_rate(self) -> float:
        """Calculate current success rate."""
        if self.total_calls == 0:
            return 1.0
        return self.successful_calls / self.total_calls
    
    def record_call(self) -> None:
        """Record a call attempt."""
        self.total_calls += 1
    
    def record_success(self) -> None:
        """Record a successful call."""
        self.successful_calls += 1
        self.last_success_time = datetime.utcnow()
    
    def record_failure(self) -> None:
        """Record a failed call."""
        self.failed_calls += 1
        self.last_failure_time = datetime.utcnow()
    
    def record_timeout(self) -> None:
        """Record a timeout."""
        self.timeout_calls += 1
        self.record_failure()
    
    def record_rejection(self) -> None:
        """Record a rejected call."""
        self.rejected_calls += 1
    
    def record_state_change(self) -> None:
        """Record a state change."""
        self.state_changes += 1
        self.current_state_start_time = datetime.utcnow()
    
    def reset(self) -> None:
        """Reset statistics."""
        self.total_calls = 0
        self.failed_calls = 0
        self.successful_calls = 0
        self.timeout_calls = 0
        self.rejected_calls = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.state_changes = 0
        self.current_state_start_time = datetime.utcnow()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_calls": self.total_calls,
            "failed_calls": self.failed_calls,
            "successful_calls": self.successful_calls,
            "timeout_calls": self.timeout_calls,
            "rejected_calls": self.rejected_calls,
            "failure_rate": self.failure_rate,
            "success_rate": self.success_rate,
            "state_changes": self.state_changes,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "current_state_duration": (datetime.utcnow() - self.current_state_start_time).total_seconds(),
        }


class CircuitBreaker:
    """Circuit breaker implementation for external service calls."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        """Initialize circuit breaker.
        
        Args:
            name: Name of the circuit breaker
            config: Circuit breaker configuration
        """
        self.name = name
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_failure_time = 0
        self.half_open_calls = 0
        self.half_open_successes = 0
        self._lock = asyncio.Lock()
        
        logger.info(
            "Circuit breaker initialized",
            name=name,
            failure_threshold=config.failure_threshold,
            recovery_timeout=config.recovery_timeout,
            timeout=config.timeout,
        )
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpenError: If circuit breaker is open
            CircuitBreakerTimeoutError: If call times out
            Exception: Original exception from function
        """
        async with self._lock:
            self.stats.record_call()
            
            # Check if circuit breaker should allow the call
            if not self._should_allow_call():
                self.stats.record_rejection()
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open. "
                    f"Last failure: {self.stats.last_failure_time}"
                )
            
            # Execute the call with timeout
            try:
                result = await asyncio.wait_for(
                    self._execute_call(func, *args, **kwargs),
                    timeout=self.config.timeout
                )
                
                # Record success and update state
                await self._handle_success()
                return result
                
            except TimeoutError:
                self.stats.record_timeout()
                await self._handle_failure()
                raise CircuitBreakerTimeoutError(
                    f"Circuit breaker '{self.name}' call timed out after {self.config.timeout}s"
                )
                
            except self.config.expected_exception as e:
                self.stats.record_failure()
                await self._handle_failure()
                raise e
    
    async def _execute_call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute the actual function call."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)
    
    def _should_allow_call(self) -> bool:
        """Check if call should be allowed based on current state."""
        current_time = time.time()
        
        if self.state == CircuitBreakerState.CLOSED:
            return True
        
        if self.state == CircuitBreakerState.OPEN:
            # Check if recovery timeout has passed
            if current_time - self.last_failure_time >= self.config.recovery_timeout:
                self._transition_to_half_open()
                return True
            return False
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            # Allow limited calls in half-open state
            return self.half_open_calls < self.config.half_open_max_calls
        
        return False
    
    async def _handle_success(self) -> None:
        """Handle successful call."""
        self.stats.record_success()
        
        logger.debug(
            "Circuit breaker call succeeded",
            name=self.name,
            state=self.state.value,
            success_rate=self.stats.success_rate,
        )
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.half_open_successes += 1
            
            # Check if we should close the circuit
            if self.half_open_successes >= self.config.success_threshold:
                self._transition_to_closed()
        
        elif self.state == CircuitBreakerState.CLOSED:
            # Reset failure count on success
            if self.stats.total_calls > 0:
                # Calculate if we should stay closed based on failure rate
                if (self.stats.total_calls >= self.config.minimum_throughput and
                    self.stats.failure_rate < self.config.failure_rate_threshold):
                    # Stay closed, optionally reset some stats
                    pass
    
    async def _handle_failure(self) -> None:
        """Handle failed call."""
        self.last_failure_time = time.time()
        
        logger.warning(
            "Circuit breaker call failed",
            name=self.name,
            state=self.state.value,
            failure_rate=self.stats.failure_rate,
            failed_calls=self.stats.failed_calls,
        )
        
        if self.state == CircuitBreakerState.CLOSED:
            # Check if we should open the circuit
            should_open = False
            
            # Check simple failure threshold
            if self.stats.failed_calls >= self.config.failure_threshold or (self.stats.total_calls >= self.config.minimum_throughput and
                  self.stats.failure_rate >= self.config.failure_rate_threshold):
                should_open = True
            
            if should_open:
                self._transition_to_open()
        
        elif self.state == CircuitBreakerState.HALF_OPEN:
            # Any failure in half-open state opens the circuit
            self._transition_to_open()
    
    def _transition_to_open(self) -> None:
        """Transition to open state."""
        self.state = CircuitBreakerState.OPEN
        self.stats.record_state_change()
        
        logger.warning(
            "Circuit breaker opened",
            name=self.name,
            failed_calls=self.stats.failed_calls,
            failure_rate=self.stats.failure_rate,
        )
    
    def _transition_to_half_open(self) -> None:
        """Transition to half-open state."""
        self.state = CircuitBreakerState.HALF_OPEN
        self.half_open_calls = 0
        self.half_open_successes = 0
        self.stats.record_state_change()
        
        logger.info(
            "Circuit breaker half-opened",
            name=self.name,
            recovery_timeout=self.config.recovery_timeout,
        )
    
    def _transition_to_closed(self) -> None:
        """Transition to closed state."""
        self.state = CircuitBreakerState.CLOSED
        self.half_open_calls = 0
        self.half_open_successes = 0
        self.stats.record_state_change()
        
        logger.info(
            "Circuit breaker closed",
            name=self.name,
            success_threshold=self.config.success_threshold,
        )
    
    def get_state(self) -> CircuitBreakerState:
        """Get current state."""
        return self.state
    
    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
                "failure_rate_threshold": self.config.failure_rate_threshold,
                "minimum_throughput": self.config.minimum_throughput,
            },
            "stats": self.stats.to_dict(),
            "half_open_calls": self.half_open_calls,
            "half_open_successes": self.half_open_successes,
        }
    
    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        self.state = CircuitBreakerState.CLOSED
        self.stats.reset()
        self.half_open_calls = 0
        self.half_open_successes = 0
        self.last_failure_time = 0
        
        logger.info("Circuit breaker reset", name=self.name)
    
    async def health_check(self) -> dict[str, Any]:
        """Perform health check on circuit breaker."""
        return {
            "name": self.name,
            "healthy": self.state != CircuitBreakerState.OPEN,
            "state": self.state.value,
            "stats": self.stats.to_dict(),
            "timestamp": datetime.utcnow().isoformat(),
        }


class CircuitBreakerManager:
    """Manager for multiple circuit breakers."""
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
    
    def create_circuit_breaker(
        self, 
        name: str, 
        config: CircuitBreakerConfig | None = None
    ) -> CircuitBreaker:
        """Create or get existing circuit breaker.
        
        Args:
            name: Name of the circuit breaker
            config: Optional configuration
            
        Returns:
            CircuitBreaker: Circuit breaker instance
        """
        if name in self._circuit_breakers:
            return self._circuit_breakers[name]
        
        if config is None:
            config = CircuitBreakerConfig()
        
        circuit_breaker = CircuitBreaker(name, config)
        self._circuit_breakers[name] = circuit_breaker
        
        return circuit_breaker
    
    def get_circuit_breaker(self, name: str) -> CircuitBreaker | None:
        """Get circuit breaker by name.
        
        Args:
            name: Name of the circuit breaker
            
        Returns:
            CircuitBreaker or None if not found
        """
        return self._circuit_breakers.get(name)
    
    def get_all_circuit_breakers(self) -> dict[str, CircuitBreaker]:
        """Get all circuit breakers.
        
        Returns:
            Dict mapping names to circuit breakers
        """
        return self._circuit_breakers.copy()
    
    def get_global_stats(self) -> dict[str, Any]:
        """Get statistics for all circuit breakers.
        
        Returns:
            Dict containing global statistics
        """
        stats = {
            "total_circuit_breakers": len(self._circuit_breakers),
            "circuit_breakers": {},
            "summary": {
                "closed": 0,
                "open": 0,
                "half_open": 0,
                "total_calls": 0,
                "total_failures": 0,
                "total_successes": 0,
            }
        }
        
        for name, cb in self._circuit_breakers.items():
            cb_stats = cb.get_stats()
            stats["circuit_breakers"][name] = cb_stats
            
            # Update summary
            stats["summary"][cb.state.value] += 1
            stats["summary"]["total_calls"] += cb.stats.total_calls
            stats["summary"]["total_failures"] += cb.stats.failed_calls
            stats["summary"]["total_successes"] += cb.stats.successful_calls
        
        return stats
    
    async def health_check(self) -> dict[str, Any]:
        """Perform health check on all circuit breakers.
        
        Returns:
            Dict containing health check results
        """
        health_results = {
            "healthy": True,
            "timestamp": datetime.utcnow().isoformat(),
            "circuit_breakers": {},
        }
        
        for name, cb in self._circuit_breakers.items():
            cb_health = await cb.health_check()
            health_results["circuit_breakers"][name] = cb_health
            
            if not cb_health["healthy"]:
                health_results["healthy"] = False
        
        return health_results
    
    def reset_all(self) -> None:
        """Reset all circuit breakers."""
        for cb in self._circuit_breakers.values():
            cb.reset()
        
        logger.info("All circuit breakers reset")


# Global circuit breaker manager
_circuit_breaker_manager = CircuitBreakerManager()


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Get the global circuit breaker manager.
    
    Returns:
        CircuitBreakerManager: Global manager instance
    """
    return _circuit_breaker_manager


def circuit_breaker(
    name: str, 
    config: CircuitBreakerConfig | None = None
) -> Callable:
    """Decorator for applying circuit breaker to functions.
    
    Args:
        name: Name of the circuit breaker
        config: Optional circuit breaker configuration
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        cb = _circuit_breaker_manager.create_circuit_breaker(name, config)
        
        async def wrapper(*args, **kwargs):
            return await cb.call(func, *args, **kwargs)
        
        return wrapper
    
    return decorator