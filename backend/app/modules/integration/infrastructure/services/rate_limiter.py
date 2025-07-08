"""Rate limiting service for API calls.

This module provides rate limiting functionality for external API calls
with support for various strategies.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Any

from app.core.errors import RateLimitError
from app.modules.integration.domain.enums import RateLimitStrategy

logger = logging.getLogger(__name__)


class RateLimiterService:
    """Service for rate limiting API calls."""

    def __init__(
        self,
        strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst_allowance: float = 1.1,
        retry_after_callback: Callable | None = None,
    ):
        """Initialize rate limiter.

        Args:
            strategy: Rate limiting strategy
            requests_per_window: Maximum requests per window
            window_seconds: Window size in seconds
            burst_allowance: Burst multiplier (1.1 = 10% burst)
            retry_after_callback: Callback when rate limited
        """
        self.strategy = strategy
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.burst_allowance = burst_allowance
        self.retry_after_callback = retry_after_callback

        # Storage for different strategies
        self._fixed_windows: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "window_start": 0}
        )
        self._sliding_windows: dict[str, deque] = defaultdict(deque)
        self._token_buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"tokens": float(requests_per_window), "last_refill": time.time()}
        )
        self._leaky_buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"volume": 0.0, "last_leak": time.time()}
        )

        # Metrics
        self.metrics = defaultdict(lambda: {"allowed": 0, "blocked": 0, "total": 0})

    async def check_rate_limit(self, identifier: str, cost: int = 1) -> bool:
        """Check if request is allowed under rate limit.

        Args:
            identifier: Unique identifier (e.g., API endpoint)
            cost: Request cost (default 1)

        Returns:
            True if allowed

        Raises:
            RateLimitError: If rate limit exceeded
        """
        self.metrics[identifier]["total"] += 1

        allowed = False
        retry_after = None

        if self.strategy == RateLimitStrategy.FIXED_WINDOW:
            allowed, retry_after = self._check_fixed_window(identifier, cost)
        elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
            allowed, retry_after = self._check_sliding_window(identifier, cost)
        elif self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            allowed, retry_after = self._check_token_bucket(identifier, cost)
        elif self.strategy == RateLimitStrategy.LEAKY_BUCKET:
            allowed, retry_after = self._check_leaky_bucket(identifier, cost)

        if allowed:
            self.metrics[identifier]["allowed"] += 1
            return True
        self.metrics[identifier]["blocked"] += 1

        if self.retry_after_callback:
            await self.retry_after_callback(identifier, retry_after)

        raise RateLimitError(
            f"Rate limit exceeded for {identifier}", retry_after=retry_after
        )

    def _check_fixed_window(
        self, identifier: str, cost: int
    ) -> tuple[bool, int | None]:
        """Check rate limit using fixed window strategy.

        Args:
            identifier: Request identifier
            cost: Request cost

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        current_time = int(time.time())
        window = self._fixed_windows[identifier]

        # Check if we're in a new window
        window_start = (current_time // self.window_seconds) * self.window_seconds

        if window_start > window["window_start"]:
            # New window, reset count
            window["count"] = 0
            window["window_start"] = window_start

        # Check limit
        max_requests = int(self.requests_per_window * self.burst_allowance)
        if window["count"] + cost <= max_requests:
            window["count"] += cost
            return True, None

        # Calculate retry after
        window_end = window_start + self.window_seconds
        retry_after = window_end - current_time

        return False, retry_after

    def _check_sliding_window(
        self, identifier: str, cost: int
    ) -> tuple[bool, int | None]:
        """Check rate limit using sliding window strategy.

        Args:
            identifier: Request identifier
            cost: Request cost

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        current_time = time.time()
        window = self._sliding_windows[identifier]

        # Remove old entries
        cutoff_time = current_time - self.window_seconds
        while window and window[0] < cutoff_time:
            window.popleft()

        # Check limit
        max_requests = int(self.requests_per_window * self.burst_allowance)
        if len(window) + cost <= max_requests:
            # Add new entries
            for _ in range(cost):
                window.append(current_time)
            return True, None

        # Calculate retry after (when oldest entry expires)
        if window:
            retry_after = int(window[0] + self.window_seconds - current_time + 1)
        else:
            retry_after = 1

        return False, retry_after

    def _check_token_bucket(
        self, identifier: str, cost: int
    ) -> tuple[bool, int | None]:
        """Check rate limit using token bucket strategy.

        Args:
            identifier: Request identifier
            cost: Request cost

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        current_time = time.time()
        bucket = self._token_buckets[identifier]

        # Refill tokens
        time_passed = current_time - bucket["last_refill"]
        tokens_to_add = (time_passed / self.window_seconds) * self.requests_per_window

        max_tokens = self.requests_per_window * self.burst_allowance
        bucket["tokens"] = min(bucket["tokens"] + tokens_to_add, max_tokens)
        bucket["last_refill"] = current_time

        # Check if we have enough tokens
        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True, None

        # Calculate retry after (when we'll have enough tokens)
        tokens_needed = cost - bucket["tokens"]
        seconds_needed = (
            tokens_needed / self.requests_per_window
        ) * self.window_seconds
        retry_after = int(seconds_needed + 1)

        return False, retry_after

    def _check_leaky_bucket(
        self, identifier: str, cost: int
    ) -> tuple[bool, int | None]:
        """Check rate limit using leaky bucket strategy.

        Args:
            identifier: Request identifier
            cost: Request cost

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        current_time = time.time()
        bucket = self._leaky_buckets[identifier]

        # Leak from bucket
        time_passed = current_time - bucket["last_leak"]
        leak_rate = self.requests_per_window / self.window_seconds
        leaked = time_passed * leak_rate

        bucket["volume"] = max(0, bucket["volume"] - leaked)
        bucket["last_leak"] = current_time

        # Check if we can add to bucket
        max_volume = self.requests_per_window * self.burst_allowance
        if bucket["volume"] + cost <= max_volume:
            bucket["volume"] += cost
            return True, None

        # Calculate retry after
        overflow = (bucket["volume"] + cost) - max_volume
        seconds_needed = overflow / leak_rate
        retry_after = int(seconds_needed + 1)

        return False, retry_after

    def reset_limits(self, identifier: str | None = None) -> None:
        """Reset rate limits.

        Args:
            identifier: Specific identifier to reset (all if None)
        """
        if identifier:
            # Reset specific identifier
            if identifier in self._fixed_windows:
                del self._fixed_windows[identifier]
            if identifier in self._sliding_windows:
                del self._sliding_windows[identifier]
            if identifier in self._token_buckets:
                del self._token_buckets[identifier]
            if identifier in self._leaky_buckets:
                del self._leaky_buckets[identifier]
        else:
            # Reset all
            self._fixed_windows.clear()
            self._sliding_windows.clear()
            self._token_buckets.clear()
            self._leaky_buckets.clear()

    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier.

        Args:
            identifier: Request identifier

        Returns:
            Number of remaining requests
        """
        if self.strategy == RateLimitStrategy.FIXED_WINDOW:
            window = self._fixed_windows.get(identifier)
            if window:
                return max(0, self.requests_per_window - window["count"])

        elif self.strategy == RateLimitStrategy.SLIDING_WINDOW:
            window = self._sliding_windows.get(identifier, deque())
            current_time = time.time()
            cutoff_time = current_time - self.window_seconds

            # Count non-expired entries
            count = sum(1 for t in window if t >= cutoff_time)
            return max(0, self.requests_per_window - count)

        elif self.strategy == RateLimitStrategy.TOKEN_BUCKET:
            bucket = self._token_buckets.get(identifier)
            if bucket:
                return int(bucket["tokens"])

        elif self.strategy == RateLimitStrategy.LEAKY_BUCKET:
            bucket = self._leaky_buckets.get(identifier)
            if bucket:
                return int(self.requests_per_window - bucket["volume"])

        return self.requests_per_window

    def get_metrics(self, identifier: str | None = None) -> dict[str, Any]:
        """Get rate limiter metrics.

        Args:
            identifier: Specific identifier (all if None)

        Returns:
            Metrics dictionary
        """
        if identifier:
            metrics = self.metrics.get(identifier, {})
            return {
                **metrics,
                "remaining": self.get_remaining_requests(identifier),
                "limit": self.requests_per_window,
                "window_seconds": self.window_seconds,
            }
        # Aggregate metrics
        total_metrics = {
            "allowed": sum(m["allowed"] for m in self.metrics.values()),
            "blocked": sum(m["blocked"] for m in self.metrics.values()),
            "total": sum(m["total"] for m in self.metrics.values()),
            "endpoints": len(self.metrics),
        }

        # Success rate
        if total_metrics["total"] > 0:
            total_metrics["success_rate"] = (
                total_metrics["allowed"] / total_metrics["total"]
            )
        else:
            total_metrics["success_rate"] = 1.0

        return total_metrics

    async def wait_if_needed(self, identifier: str, cost: int = 1) -> None:
        """Wait if rate limited instead of throwing error.

        Args:
            identifier: Request identifier
            cost: Request cost
        """
        while True:
            try:
                await self.check_rate_limit(identifier, cost)
                break
            except RateLimitError as e:
                if e.retry_after:
                    logger.info(
                        f"Rate limited for {identifier}, "
                        f"waiting {e.retry_after} seconds"
                    )
                    await asyncio.sleep(e.retry_after)
                else:
                    raise
