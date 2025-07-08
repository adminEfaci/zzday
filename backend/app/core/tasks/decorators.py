"""
Task decoration utilities with prod-ready implementations.

Provides decorators for:
- Retry logic with exponential backoff
- Timeout handling
- Rate limiting with token bucket
- Performance tracking
- Circuit breaker pattern
- Caching/memoization
"""

import asyncio
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from threading import Lock
from typing import Any, TypeVar

from tenacity import (
    before_sleep_log,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from tenacity import retry as tenacity_retry

from app.core.cache import CacheManager
from app.core.errors import RateLimitError, TaskError
from app.core.logging import get_logger
from app.core.monitoring import metrics

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# Rate limiter storage
_rate_limiters: dict[str, "TokenBucket"] = {}
_rate_limiter_lock = Lock()

# Circuit breaker storage
_circuit_breakers: dict[str, "CircuitBreaker"] = {}
_circuit_breaker_lock = Lock()


@dataclass
class TokenBucket:
    rate: float
    capacity: int
    tokens: float
    last_update: float

    def consume(self, tokens: int = 1) -> tuple[bool, float]:
        now = time.time()
        elapsed = now - self.last_update

        self.tokens = min(
            float(self.capacity), self.tokens + elapsed * self.rate  # <- cast to float
        )
        self.last_update = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True, 0.0

        needed = tokens - self.tokens
        wait_time = needed / self.rate
        return False, wait_time


@dataclass
class CircuitBreakerState:
    """Circuit breaker state."""

    failure_count: int = 0
    last_failure_time: float | None = None
    state: str = "closed"  # closed, open, half_open


class CircuitBreaker:
    """Circuit breaker implementation."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type[Exception] = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.state = CircuitBreakerState()
        self._lock = Lock()

    def __enter__(self):
        self.call()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.success()
        elif issubclass(exc_type, self.expected_exception):
            self.fail()
        return False

    async def __aenter__(self):
        self.call()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.success()
        elif issubclass(exc_type, self.expected_exception):
            self.fail()
        return False

    def call(self):
        """Check if call is allowed."""
        with self._lock:
            if self.state.state == "closed":
                return

            if self.state.state == "open":
                if self.state.last_failure_time:
                    elapsed = time.time() - self.state.last_failure_time
                    if elapsed >= self.recovery_timeout:
                        self.state.state = "half_open"
                        logger.info("Circuit breaker half-open")
                    else:
                        raise TaskError("Circuit breaker is open")
                else:
                    raise TaskError("Circuit breaker is open")

    def success(self):
        """Record successful call."""
        with self._lock:
            if self.state.state == "half_open":
                self.state.state = "closed"
                self.state.failure_count = 0
                logger.info("Circuit breaker closed")

    def fail(self):
        """Record failed call."""
        with self._lock:
            self.state.failure_count += 1
            self.state.last_failure_time = time.time()

            if self.state.failure_count >= self.failure_threshold:
                self.state.state = "open"
                logger.warning(
                    "Circuit breaker opened", failures=self.state.failure_count
                )


def retry(
    max_attempts: int = 3,
    wait_exponential_multiplier: int = 1,
    wait_exponential_max: int = 60,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    before_sleep: Callable | None = None,
) -> Callable[[F], F]:
    """
    Retry decorator with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        wait_exponential_multiplier: Multiplier for exponential backoff
        wait_exponential_max: Maximum wait time between retries
        exceptions: Tuple of exceptions to retry on
        before_sleep: Optional callback before retry sleep
    """

    def decorator(func: F) -> F:
        # Configure before_sleep logging
        sleep_logger = before_sleep or before_sleep_log(logger, "WARNING")

        @tenacity_retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(
                multiplier=wait_exponential_multiplier,
                max=wait_exponential_max,
            ),
            retry=retry_if_exception_type(exceptions),
            before_sleep=sleep_logger,
        )
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)

                # Track success metrics
                metrics.task_retry_success.labels(
                    task_name=func.__name__, duration=time.time() - start_time
                ).inc()

                return result
            except exceptions as e:
                # Track failure metrics
                metrics.task_retry_failure.labels(
                    task_name=func.__name__,
                    error_type=type(e).__name__,
                    duration=time.time() - start_time,
                ).inc()
                raise

        @tenacity_retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(
                multiplier=wait_exponential_multiplier,
                max=wait_exponential_max,
            ),
            retry=retry_if_exception_type(exceptions),
            before_sleep=sleep_logger,
        )
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)

                # Track success metrics
                metrics.task_retry_success.labels(
                    task_name=func.__name__, duration=time.time() - start_time
                ).inc()

                return result
            except exceptions as e:
                # Track failure metrics
                metrics.task_retry_failure.labels(
                    task_name=func.__name__,
                    error_type=type(e).__name__,
                    duration=time.time() - start_time,
                ).inc()
                raise

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def timeout(seconds: float) -> Callable[[F], F]:
    """
    Timeout decorator for async and sync functions.

    Args:
        seconds: Timeout duration in seconds
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=seconds,
                )
            except TimeoutError:
                logger.exception(
                    "Task timeout",
                    task=func.__name__,
                    timeout=seconds,
                )
                metrics.task_timeout.labels(
                    task_name=func.__name__, timeout=seconds
                ).inc()
                raise TaskError(f"Task {func.__name__} timed out after {seconds}s")

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, use threading with timeout
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=seconds)
                except concurrent.futures.TimeoutError:
                    logger.exception(
                        "Task timeout",
                        task=func.__name__,
                        timeout=seconds,
                    )
                    metrics.task_timeout.labels(
                        task_name=func.__name__, timeout=seconds
                    ).inc()
                    raise TaskError(f"Task {func.__name__} timed out after {seconds}s")

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def rate_limit(
    calls: int,
    period: float,
    key_func: Callable[..., str] | None = None,
    cache_manager: CacheManager | None = None,
) -> Callable[[F], F]:
    """
    Rate limit decorator using token bucket algorithm.

    Args:
        calls: Number of allowed calls
        period: Time period in seconds
        key_func: Optional function to generate rate limit key
        cache_manager: Optional cache manager for distributed rate limiting
    """

    def decorator(func: F) -> F:
        # Calculate rate (tokens per second)
        rate = calls / period

        def get_rate_limit_key(*args, **kwargs) -> str:
            """Generate rate limit key."""
            if key_func:
                return key_func(*args, **kwargs)
            return f"{func.__module__}.{func.__name__}"

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            key = get_rate_limit_key(*args, **kwargs)

            if cache_manager:
                # Distributed rate limiting using cache
                cache_key = f"ratelimit:{key}"

                # Use cache atomic operations for distributed rate limiting
                # This is a simplified implementation
                current_count = await cache_manager.get(f"{cache_key}:count") or 0
                window_start = (
                    await cache_manager.get(f"{cache_key}:window") or time.time()
                )

                now = time.time()
                if now - window_start > period:
                    # New window
                    await cache_manager.set(f"{cache_key}:count", 1, ttl=int(period))
                    await cache_manager.set(f"{cache_key}:window", now, ttl=int(period))
                    return await func(*args, **kwargs)

                if current_count >= calls:
                    wait_time = period - (now - window_start)
                    logger.warning(
                        "Rate limit exceeded",
                        function=func.__name__,
                        key=key,
                        wait_time=wait_time,
                    )
                    metrics.rate_limit_exceeded.labels(
                        function=func.__name__, key=key
                    ).inc()
                    raise RateLimitError(
                        f"Rate limit exceeded. Retry after {wait_time:.2f}s"
                    )

                # Increment counter
                await cache_manager.increment(f"{cache_key}:count")
                return await func(*args, **kwargs)

            # Local rate limiting
            with _rate_limiter_lock:
                if key not in _rate_limiters:
                    _rate_limiters[key] = TokenBucket(
                        rate=rate, capacity=calls, tokens=calls, last_update=time.time()
                    )

            bucket = _rate_limiters[key]
            success, wait_time = bucket.consume()

            if not success:
                logger.warning(
                    "Rate limit exceeded",
                    function=func.__name__,
                    key=key,
                    wait_time=wait_time,
                )
                metrics.rate_limit_exceeded.labels(
                    function=func.__name__, key=key
                ).inc()
                raise RateLimitError(
                    f"Rate limit exceeded. Retry after {wait_time:.2f}s"
                )

            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            key = get_rate_limit_key(*args, **kwargs)

            # Local rate limiting only for sync functions
            with _rate_limiter_lock:
                if key not in _rate_limiters:
                    _rate_limiters[key] = TokenBucket(
                        rate=rate, capacity=calls, tokens=calls, last_update=time.time()
                    )

            bucket = _rate_limiters[key]
            success, wait_time = bucket.consume()

            if not success:
                logger.warning(
                    "Rate limit exceeded",
                    function=func.__name__,
                    key=key,
                    wait_time=wait_time,
                )
                metrics.rate_limit_exceeded.labels(
                    function=func.__name__, key=key
                ).inc()
                raise RateLimitError(
                    f"Rate limit exceeded. Retry after {wait_time:.2f}s"
                )

            return func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def track_performance(
    metric_name: str | None = None,
    include_args: bool = False,
    log_level: str = "INFO",
) -> Callable[[F], F]:
    """
    Track task performance with detailed metrics.

    Args:
        metric_name: Optional custom metric name
        include_args: Whether to include function arguments in logs
        log_level: Log level for performance logs
    """

    def decorator(func: F) -> F:
        name = metric_name or f"{func.__module__}.{func.__name__}"

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            context = {
                "task": name,
                "start_time": datetime.now(datetime.UTC).isoformat(),
            }

            if include_args and args:
                context["args"] = str(args[:3])  # First 3 args only

            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time

                context.update(
                    {
                        "duration": duration,
                        "status": "success",
                    }
                )

                getattr(logger, log_level.lower())("Task completed", **context)

                # Update metrics
                metrics.task_duration.labels(task_name=name, status="success").observe(
                    duration
                )
                metrics.task_success.labels(task_name=name).inc()

                return result

            except Exception as e:
                duration = time.time() - start_time

                context.update(
                    {
                        "duration": duration,
                        "status": "failed",
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )

                logger.error("Task failed", **context, exc_info=True)

                # Update metrics
                metrics.task_duration.labels(task_name=name, status="failed").observe(
                    duration
                )
                metrics.task_failures.labels(
                    task_name=name, error_type=type(e).__name__
                ).inc()

                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            context = {
                "task": name,
                "start_time": datetime.now(datetime.UTC).isoformat(),
            }

            if include_args and args:
                context["args"] = str(args[:3])

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                context.update(
                    {
                        "duration": duration,
                        "status": "success",
                    }
                )

                getattr(logger, log_level.lower())("Task completed", **context)

                # Update metrics
                metrics.task_duration.labels(task_name=name, status="success").observe(
                    duration
                )
                metrics.task_success.labels(task_name=name).inc()

                return result

            except Exception as e:
                duration = time.time() - start_time

                context.update(
                    {
                        "duration": duration,
                        "status": "failed",
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )

                logger.error("Task failed", **context, exc_info=True)

                # Update metrics
                metrics.task_duration.labels(task_name=name, status="failed").observe(
                    duration
                )
                metrics.task_failures.labels(
                    task_name=name, error_type=type(e).__name__
                ).inc()

                raise

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: type[Exception] = Exception,
    name: str | None = None,
) -> Callable[[F], F]:
    """
    Circuit breaker decorator to prevent cascading failures.

    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds before attempting to close circuit
        expected_exception: Exception type to count as failure
        name: Optional circuit breaker name
    """

    def decorator(func: F) -> F:
        breaker_name = name or f"{func.__module__}.{func.__name__}"

        with _circuit_breaker_lock:
            if breaker_name not in _circuit_breakers:
                _circuit_breakers[breaker_name] = CircuitBreaker(
                    failure_threshold=failure_threshold,
                    recovery_timeout=recovery_timeout,
                    expected_exception=expected_exception,
                )

        breaker = _circuit_breakers[breaker_name]

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            async with breaker:
                return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            with breaker:
                return func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def memoize(
    ttl: int | None = None,
    cache_manager: CacheManager | None = None,
    key_prefix: str | None = None,
    max_size: int = 128,
) -> Callable[[F], F]:
    """
    Memoization decorator with TTL and size limits.

    Args:
        ttl: Time to live in seconds
        cache_manager: Optional cache manager for distributed caching
        key_prefix: Optional cache key prefix
        max_size: Maximum number of cached items (local cache only)
    """

    def decorator(func: F) -> F:
        # Local cache storage
        local_cache: dict[str, tuple[Any, float | None]] = {}
        cache_order: list = []  # For LRU eviction
        cache_lock = Lock()

        prefix = key_prefix or f"{func.__module__}.{func.__name__}"

        def make_cache_key(*args, **kwargs) -> str:
            """Generate cache key from function arguments."""
            key_parts = [prefix]

            # Hash args and kwargs
            args_str = json.dumps(args, sort_keys=True, default=str)
            kwargs_str = json.dumps(kwargs, sort_keys=True, default=str)

            key_hash = hashlib.sha256(f"{args_str}:{kwargs_str}".encode()).hexdigest()[
                :16
            ]

            key_parts.append(key_hash)
            return ":".join(key_parts)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            cache_key = make_cache_key(*args, **kwargs)

            if cache_manager:
                # Try distributed cache first
                cached_value = await cache_manager.get(cache_key)
                if cached_value is not None:
                    metrics.cache_hit.labels(
                        cache_type="memoize", function=func.__name__
                    ).inc()
                    return cached_value

                # Execute function
                result = await func(*args, **kwargs)

                # Cache result
                await cache_manager.set(cache_key, result, ttl=ttl)

                metrics.cache_miss.labels(
                    cache_type="memoize", function=func.__name__
                ).inc()

                return result
            # Use local cache
            with cache_lock:
                if cache_key in local_cache:
                    value, expiry = local_cache[cache_key]
                    if expiry is None or time.time() < expiry:
                        # Move to end (LRU)
                        cache_order.remove(cache_key)
                        cache_order.append(cache_key)

                        metrics.cache_hit.labels(
                            cache_type="memoize", function=func.__name__
                        ).inc()
                        return value
                    # Expired
                    del local_cache[cache_key]
                    cache_order.remove(cache_key)

            # Execute function
            result = await func(*args, **kwargs)

            # Cache result with LRU eviction
            with cache_lock:
                # Evict oldest if at capacity
                if len(local_cache) >= max_size:
                    oldest_key = cache_order.pop(0)
                    del local_cache[oldest_key]

                expiry = time.time() + ttl if ttl else None
                local_cache[cache_key] = (result, expiry)
                cache_order.append(cache_key)

            metrics.cache_miss.labels(
                cache_type="memoize", function=func.__name__
            ).inc()

            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            cache_key = make_cache_key(*args, **kwargs)

            # Use local cache only
            with cache_lock:
                if cache_key in local_cache:
                    value, expiry = local_cache[cache_key]
                    if expiry is None or time.time() < expiry:
                        # Move to end (LRU)
                        cache_order.remove(cache_key)
                        cache_order.append(cache_key)

                        metrics.cache_hit.labels(
                            cache_type="memoize", function=func.__name__
                        ).inc()
                        return value
                    # Expired
                    del local_cache[cache_key]
                    cache_order.remove(cache_key)

            # Execute function
            result = func(*args, **kwargs)

            # Cache result with LRU eviction
            with cache_lock:
                # Evict oldest if at capacity
                if len(local_cache) >= max_size:
                    oldest_key = cache_order.pop(0)
                    del local_cache[oldest_key]

                expiry = time.time() + ttl if ttl else None
                local_cache[cache_key] = (result, expiry)
                cache_order.append(cache_key)

            metrics.cache_miss.labels(
                cache_type="memoize", function=func.__name__
            ).inc()

            return result

        # Add cache management methods
        def clear_cache():
            """Clear all cached values."""
            with cache_lock:
                local_cache.clear()
                cache_order.clear()

            if cache_manager:
                # Note: This would need to track all keys for distributed cache
                logger.warning(
                    "Distributed cache clear not implemented", function=func.__name__
                )

        def cache_info():
            """Get cache statistics."""
            with cache_lock:
                return {
                    "size": len(local_cache),
                    "max_size": max_size,
                    "hits": metrics._cache_hits.get(func.__name__, 0),
                    "misses": metrics._cache_misses.get(func.__name__, 0),
                }

        # Attach management methods
        wrapper = async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        wrapper.clear_cache = clear_cache
        wrapper.cache_info = cache_info

        return wrapper

    return decorator


def batch_process(
    batch_size: int = 100,
    flush_interval: float | None = None,
) -> Callable[[F], F]:
    """
    Batch processing decorator for aggregating calls.

    Args:
        batch_size: Maximum batch size
        flush_interval: Optional interval to flush batch
    """

    def decorator(func: F) -> F:
        # Batch storage
        batch_queue = []
        batch_lock = Lock()
        asyncio.Event() if asyncio.iscoroutinefunction(func) else None

        @wraps(func)
        async def process_batch():
            """Process accumulated batch."""
            with batch_lock:
                if not batch_queue:
                    return

                current_batch = batch_queue[:batch_size]
                batch_queue[:batch_size] = []

            try:
                # Process batch
                results = await func(current_batch)

                # Notify waiting callers
                for item, future in current_batch:
                    if not future.done():
                        future.set_result(results.get(item.get("id"), None))

            except Exception as e:
                # Notify failures
                for item, future in current_batch:
                    if not future.done():
                        future.set_exception(e)

        async def flush_periodically():
            """Flush batch periodically."""
            while True:
                await asyncio.sleep(flush_interval)
                if batch_queue:
                    await process_batch()

        # Start flush task if interval specified
        if flush_interval and asyncio.iscoroutinefunction(func):
            asyncio.create_task(flush_periodically())

        @wraps(func)
        async def async_wrapper(item):
            future = asyncio.Future()

            with batch_lock:
                batch_queue.append((item, future))
                should_process = len(batch_queue) >= batch_size

            if should_process:
                await process_batch()

            return await future

        # Batch processing for sync functions would require threading
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            logger.warning(
                "Batch processing not implemented for sync functions",
                function=func.__name__,
            )
            return func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator
