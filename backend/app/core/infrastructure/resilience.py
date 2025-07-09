"""
Enhanced Resilience Patterns with Retries, Timeouts, and Bulkheads.

Combines circuit breaker with retry logic, timeout handling, and bulkhead isolation
for comprehensive resilience in distributed systems.
"""

import asyncio
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar
from functools import wraps

from app.core.infrastructure.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, get_circuit_breaker
from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class RetryStrategy(Enum):
    """Retry strategies."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    JITTER = "jitter"


@dataclass
class RetryConfig:
    """Retry configuration."""
    max_attempts: int = 3
    base_delay_ms: int = 100
    max_delay_ms: int = 30000
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    retryable_exceptions: tuple = (Exception,)


@dataclass
class TimeoutConfig:
    """Timeout configuration."""
    connect_timeout_ms: int = 5000
    read_timeout_ms: int = 10000
    total_timeout_ms: int = 30000


@dataclass
class BulkheadConfig:
    """Bulkhead isolation configuration."""
    max_concurrent_calls: int = 10
    queue_size: int = 20
    timeout_ms: int = 5000


class RetryExhaustedError(InfrastructureError):
    """Retry attempts exhausted."""
    default_code = "RETRY_EXHAUSTED"


class TimeoutError(InfrastructureError):
    """Operation timeout."""
    default_code = "OPERATION_TIMEOUT"


class BulkheadFullError(InfrastructureError):
    """Bulkhead at capacity."""
    default_code = "BULKHEAD_FULL"


class RetryHandler:
    """Retry logic implementation."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
        self._attempt_count = 0
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        if self.config.strategy == RetryStrategy.FIXED:
            delay = self.config.base_delay_ms
        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay_ms * (attempt + 1)
        elif self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay_ms * (self.config.backoff_multiplier ** attempt)
        else:  # JITTER
            base_delay = self.config.base_delay_ms * (self.config.backoff_multiplier ** attempt)
            jitter = base_delay * self.config.jitter_factor
            delay = base_delay + random.uniform(-jitter, jitter)
        
        return min(delay, self.config.max_delay_ms) / 1000.0
    
    def is_retryable(self, exception: Exception) -> bool:
        """Check if exception is retryable."""
        return isinstance(exception, self.config.retryable_exceptions)
    
    async def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(self.config.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if not self.is_retryable(e) or attempt == self.config.max_attempts - 1:
                    raise
                
                delay = self.calculate_delay(attempt)
                logger.debug(
                    "Retrying after failure",
                    attempt=attempt + 1,
                    max_attempts=self.config.max_attempts,
                    delay_seconds=delay,
                    error=str(e)
                )
                await asyncio.sleep(delay)
        
        raise RetryExhaustedError(f"Max retries exceeded: {last_exception}")


class TimeoutHandler:
    """Timeout handling implementation."""
    
    def __init__(self, config: TimeoutConfig):
        self.config = config
    
    @asynccontextmanager
    async def timeout_context(self, timeout_ms: Optional[int] = None):
        """Context manager for timeout handling."""
        timeout_seconds = (timeout_ms or self.config.total_timeout_ms) / 1000.0
        
        try:
            async with asyncio.timeout(timeout_seconds):
                yield
        except asyncio.TimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout_seconds}s")


class Bulkhead:
    """Bulkhead isolation implementation."""
    
    def __init__(self, name: str, config: BulkheadConfig):
        self.name = name
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_calls)
        self._queue = asyncio.Queue(maxsize=config.queue_size)
        self._active_calls = 0
        self._rejected_calls = 0
        self._total_calls = 0
        
        logger.info(
            "Bulkhead initialized",
            name=name,
            max_concurrent=config.max_concurrent_calls,
            queue_size=config.queue_size
        )
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire slot in bulkhead."""
        self._total_calls += 1
        
        try:
            # Try to acquire semaphore with timeout
            await asyncio.wait_for(
                self._semaphore.acquire(),
                timeout=self.config.timeout_ms / 1000.0
            )
            
            self._active_calls += 1
            try:
                yield
            finally:
                self._active_calls -= 1
                self._semaphore.release()
                
        except asyncio.TimeoutError:
            self._rejected_calls += 1
            raise BulkheadFullError(f"Bulkhead {self.name} is full")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bulkhead statistics."""
        return {
            "name": self.name,
            "active_calls": self._active_calls,
            "rejected_calls": self._rejected_calls,
            "total_calls": self._total_calls,
            "available_capacity": self.config.max_concurrent_calls - self._active_calls,
            "rejection_rate": self._rejected_calls / self._total_calls if self._total_calls > 0 else 0
        }


class ResilienceOrchestrator:
    """Orchestrates all resilience patterns."""
    
    def __init__(
        self,
        name: str,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        timeout_config: Optional[TimeoutConfig] = None,
        bulkhead_config: Optional[BulkheadConfig] = None
    ):
        self.name = name
        self.circuit_breaker = get_circuit_breaker(name) or CircuitBreaker(name, circuit_breaker_config)
        self.retry_handler = RetryHandler(retry_config or RetryConfig())
        self.timeout_handler = TimeoutHandler(timeout_config or TimeoutConfig())
        self.bulkhead = Bulkhead(name, bulkhead_config) if bulkhead_config else None
        
        logger.info(
            "Resilience orchestrator initialized",
            name=name,
            has_circuit_breaker=True,
            has_retry=True,
            has_timeout=True,
            has_bulkhead=self.bulkhead is not None
        )
    
    async def execute(
        self,
        func: Callable[..., T],
        *args,
        timeout_ms: Optional[int] = None,
        **kwargs
    ) -> T:
        """Execute function with full resilience pattern."""
        
        # Bulkhead isolation
        if self.bulkhead:
            async with self.bulkhead.acquire():
                return await self._execute_with_resilience(func, *args, timeout_ms=timeout_ms, **kwargs)
        else:
            return await self._execute_with_resilience(func, *args, timeout_ms=timeout_ms, **kwargs)
    
    async def _execute_with_resilience(
        self,
        func: Callable[..., T],
        *args,
        timeout_ms: Optional[int] = None,
        **kwargs
    ) -> T:
        """Execute with circuit breaker, retry, and timeout."""
        
        # Circuit breaker check
        if not self.circuit_breaker.can_execute():
            await self.circuit_breaker.record_blocked_request()
            raise CircuitBreakerOpenError(f"Circuit breaker {self.name} is open")
        
        # Retry with timeout
        async def resilient_call():
            async with self.timeout_handler.timeout_context(timeout_ms):
                return await func(*args, **kwargs)
        
        try:
            result = await self.retry_handler.execute(resilient_call)
            await self.circuit_breaker.record_success()
            return result
        except Exception as e:
            await self.circuit_breaker.record_failure(e)
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive resilience statistics."""
        stats = {
            "name": self.name,
            "circuit_breaker": self.circuit_breaker.get_statistics(),
            "retry_config": {
                "max_attempts": self.retry_handler.config.max_attempts,
                "strategy": self.retry_handler.config.strategy.value,
                "base_delay_ms": self.retry_handler.config.base_delay_ms,
                "max_delay_ms": self.retry_handler.config.max_delay_ms
            },
            "timeout_config": {
                "connect_timeout_ms": self.timeout_handler.config.connect_timeout_ms,
                "read_timeout_ms": self.timeout_handler.config.read_timeout_ms,
                "total_timeout_ms": self.timeout_handler.config.total_timeout_ms
            }
        }
        
        if self.bulkhead:
            stats["bulkhead"] = self.bulkhead.get_stats()
        
        return stats


class ResilienceRegistry:
    """Registry for managing resilience orchestrators."""
    
    def __init__(self):
        self._orchestrators: Dict[str, ResilienceOrchestrator] = {}
    
    def get_or_create(
        self,
        name: str,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        retry_config: Optional[RetryConfig] = None,
        timeout_config: Optional[TimeoutConfig] = None,
        bulkhead_config: Optional[BulkheadConfig] = None
    ) -> ResilienceOrchestrator:
        """Get or create resilience orchestrator."""
        if name not in self._orchestrators:
            self._orchestrators[name] = ResilienceOrchestrator(
                name=name,
                circuit_breaker_config=circuit_breaker_config,
                retry_config=retry_config,
                timeout_config=timeout_config,
                bulkhead_config=bulkhead_config
            )
        return self._orchestrators[name]
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get stats for all orchestrators."""
        return {
            name: orchestrator.get_stats()
            for name, orchestrator in self._orchestrators.items()
        }


# Global registry
_resilience_registry = ResilienceRegistry()


def resilient(
    name: str,
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
    retry_config: Optional[RetryConfig] = None,
    timeout_config: Optional[TimeoutConfig] = None,
    bulkhead_config: Optional[BulkheadConfig] = None,
    timeout_ms: Optional[int] = None
):
    """Decorator for comprehensive resilience patterns."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        orchestrator = _resilience_registry.get_or_create(
            name=name,
            circuit_breaker_config=circuit_breaker_config,
            retry_config=retry_config,
            timeout_config=timeout_config,
            bulkhead_config=bulkhead_config
        )
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await orchestrator.execute(func, *args, timeout_ms=timeout_ms, **kwargs)
        
        return wrapper
    return decorator


def get_resilience_stats() -> Dict[str, Any]:
    """Get all resilience statistics."""
    return _resilience_registry.get_all_stats()


__all__ = [
    "RetryHandler",
    "TimeoutHandler", 
    "Bulkhead",
    "ResilienceOrchestrator",
    "RetryConfig",
    "TimeoutConfig",
    "BulkheadConfig",
    "RetryStrategy",
    "RetryExhaustedError",
    "TimeoutError",
    "BulkheadFullError",
    "resilient",
    "get_resilience_stats"
]