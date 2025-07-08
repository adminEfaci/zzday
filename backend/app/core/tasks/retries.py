"""Retry logic and policies."""

import asyncio
import random
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from app.core.errors import EzzDayError
from app.core.logging import get_logger

logger = get_logger(__name__)


class RetryStrategy(str, Enum):
    """Retry strategy types."""

    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIBONACCI = "fibonacci"


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RetryPolicy:
    """Retry policy configuration."""

    def __init__(
        self,
        max_retries: int = 3,
        strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: bool = True,
        retryable_exceptions: tuple[type[Exception], ...] | None = None,
    ):
        self.max_retries = max_retries
        self.strategy = strategy
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions or (Exception,)
        self._fibonacci_cache = {0: 0, 1: 1}

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Check if should retry for given exception."""
        if attempt >= self.max_retries:
            return False

        return isinstance(exception, self.retryable_exceptions)

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        if self.strategy == RetryStrategy.FIXED:
            delay = self.base_delay
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.base_delay * attempt
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.base_delay * (2 ** (attempt - 1))
        elif self.strategy == RetryStrategy.FIBONACCI:
            delay = self.base_delay * self._fibonacci(attempt)
        else:
            delay = self.base_delay

        # Apply max delay cap
        delay = min(delay, self.max_delay)

        # Apply jitter
        if self.jitter:
            delay *= 0.5 + random.random()  # noqa: S311 - Random jitter for retry delays is not security-sensitive

        return delay

    def _fibonacci(self, n: int) -> int:
        """Calculate fibonacci number with memoization."""
        if n in self._fibonacci_cache:
            return self._fibonacci_cache[n]

        self._fibonacci_cache[n] = self._fibonacci(n - 1) + self._fibonacci(n - 2)
        return self._fibonacci_cache[n]


class CircuitBreaker:
    """Circuit breaker implementation."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: timedelta = timedelta(seconds=60),
        expected_exception: type[Exception] = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self._failure_count = 0
        self._last_failure_time: datetime | None = None
        self._state = CircuitState.CLOSED

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        if self._state == CircuitState.OPEN and (
            self._last_failure_time
            and datetime.now(datetime.UTC) - self._last_failure_time
            > self.recovery_timeout
        ):
            self._state = CircuitState.HALF_OPEN
        return self._state

    def call(self, func: Callable[..., Any], *args, **kwargs) -> Any:
        """Execute function with circuit breaker."""
        if self.state == CircuitState.OPEN:
            raise EzzDayError("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception:
            self._on_failure()
            raise

    async def async_call(
        self,
        func: Callable[..., Any],
        *args,
        **kwargs,
    ) -> Any:
        """Execute async function with circuit breaker."""
        if self.state == CircuitState.OPEN:
            raise EzzDayError("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        """Handle successful call."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        """Handle failed call."""
        self._failure_count += 1
        self._last_failure_time = datetime.now(datetime.UTC)

        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker opened",
                failure_count=self._failure_count,
                threshold=self.failure_threshold,
            )


async def retry_async(
    func: Callable[..., Any],
    policy: RetryPolicy,
    *args,
    **kwargs,
) -> Any:
    """Retry async function with policy."""
    last_exception: Exception | None = None

    for attempt in range(1, policy.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e

            if not policy.should_retry(e, attempt):
                raise

            if attempt < policy.max_retries:
                delay = policy.get_delay(attempt)
                logger.warning(
                    "Retrying after failure",
                    attempt=attempt,
                    max_retries=policy.max_retries,
                    delay=delay,
                    error=str(e),
                )
                await asyncio.sleep(delay)

    if last_exception:
        raise last_exception
    return None
