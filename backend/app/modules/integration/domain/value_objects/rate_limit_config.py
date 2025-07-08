"""Rate limit configuration value object for API throttling.

This module provides comprehensive rate limiting configuration with
support for various strategies and burst handling.
"""

import contextlib
from datetime import datetime, timedelta
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.integration.domain.enums import RateLimitStrategy


class RateLimitConfig(ValueObject):
    """Value object representing rate limit configuration.

    This class encapsulates rate limiting settings for external API calls,
    supporting various throttling strategies and burst allowances.
    """

    def __init__(
        self,
        requests_per_window: int,
        window_seconds: int,
        strategy: RateLimitStrategy = RateLimitStrategy.FIXED_WINDOW,
        burst_size: int | None = None,
        retry_after_header: str | None = None,
        rate_limit_header: str | None = None,
        remaining_header: str | None = None,
        reset_header: str | None = None,
    ):
        """Initialize rate limit configuration.

        Args:
            requests_per_window: Number of requests allowed per window
            window_seconds: Time window in seconds
            strategy: Rate limiting strategy to use
            burst_size: Optional burst allowance
            retry_after_header: Optional header name for retry-after value
            rate_limit_header: Optional header name for rate limit
            remaining_header: Optional header name for remaining requests
            reset_header: Optional header name for reset time

        Raises:
            ValidationError: If configuration is invalid
        """
        # Validate requests per window
        if requests_per_window <= 0:
            raise ValidationError("requests_per_window must be positive")
        if requests_per_window > 1000000:
            raise ValidationError("requests_per_window seems unreasonably high")
        self.requests_per_window = requests_per_window

        # Validate window seconds
        if window_seconds <= 0:
            raise ValidationError("window_seconds must be positive")
        if window_seconds > 86400:  # 24 hours
            raise ValidationError("window_seconds cannot exceed 24 hours")
        self.window_seconds = window_seconds

        # Validate strategy
        if not isinstance(strategy, RateLimitStrategy):
            raise ValidationError("strategy must be a RateLimitStrategy enum")
        self.strategy = strategy

        # Validate burst size
        if burst_size is not None:
            if burst_size <= 0:
                raise ValidationError("burst_size must be positive if provided")
            if burst_size > requests_per_window:
                raise ValidationError("burst_size cannot exceed requests_per_window")
        self.burst_size = burst_size or requests_per_window

        # Store header names for rate limit information
        self.retry_after_header = retry_after_header or "Retry-After"
        self.rate_limit_header = rate_limit_header or "X-RateLimit-Limit"
        self.remaining_header = remaining_header or "X-RateLimit-Remaining"
        self.reset_header = reset_header or "X-RateLimit-Reset"

        # Freeze the object
        self._freeze()

    @property
    def requests_per_second(self) -> float:
        """Calculate average requests per second."""
        return self.requests_per_window / self.window_seconds

    @property
    def requests_per_minute(self) -> float:
        """Calculate average requests per minute."""
        return self.requests_per_second * 60

    @property
    def window_duration(self) -> timedelta:
        """Get window duration as timedelta."""
        return timedelta(seconds=self.window_seconds)

    @property
    def min_request_interval(self) -> float:
        """Calculate minimum interval between requests in seconds."""
        return self.window_seconds / self.requests_per_window

    @property
    def allows_burst(self) -> bool:
        """Check if configuration allows burst requests."""
        return self.burst_size > 1

    def calculate_delay(self, current_requests: int, window_start: datetime) -> float:
        """Calculate required delay before next request.

        Args:
            current_requests: Number of requests made in current window
            window_start: Start time of current window

        Returns:
            float: Delay in seconds (0 if no delay needed)
        """
        if current_requests < self.requests_per_window:
            # Check burst allowance
            if current_requests < self.burst_size:
                return 0.0

            # Calculate based on strategy
            if self.strategy == RateLimitStrategy.FIXED_WINDOW:
                # Wait until window resets
                window_elapsed = (datetime.utcnow() - window_start).total_seconds()
                return max(0, self.window_seconds - window_elapsed)

            if self.strategy == RateLimitStrategy.SLIDING_WINDOW:
                # Smooth out requests over the window
                return self.min_request_interval

            if self.strategy == RateLimitStrategy.TOKEN_BUCKET:
                # Calculate token replenishment rate
                elapsed = (datetime.utcnow() - window_start).total_seconds()
                tokens_added = elapsed * self.requests_per_second
                available_tokens = min(
                    self.requests_per_window, tokens_added - current_requests
                )

                if available_tokens >= 1:
                    return 0.0
                # Time until next token
                return (1 - available_tokens) / self.requests_per_second

            if self.strategy == RateLimitStrategy.LEAKY_BUCKET:
                # Constant rate processing
                return self.min_request_interval

        # Rate limit exceeded - wait for window reset
        window_elapsed = (datetime.utcnow() - window_start).total_seconds()
        return max(0, self.window_seconds - window_elapsed)

    def parse_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        """Parse rate limit information from response headers.

        Args:
            headers: Response headers

        Returns:
            dict[str, Any]: Parsed rate limit information
        """
        info = {}

        # Parse rate limit
        if self.rate_limit_header in headers:
            with contextlib.suppress(ValueError):
                info["limit"] = int(headers[self.rate_limit_header])

        # Parse remaining
        if self.remaining_header in headers:
            with contextlib.suppress(ValueError):
                info["remaining"] = int(headers[self.remaining_header])

        # Parse reset time
        if self.reset_header in headers:
            try:
                reset_value = headers[self.reset_header]
                # Try to parse as timestamp
                info["reset"] = datetime.fromtimestamp(int(reset_value))
            except ValueError:
                # Try to parse as seconds until reset
                with contextlib.suppress(ValueError):
                    info["reset"] = datetime.utcnow() + timedelta(
                        seconds=int(reset_value)
                    )

        # Parse retry after
        if self.retry_after_header in headers:
            try:
                retry_value = headers[self.retry_after_header]
                # Try to parse as seconds
                info["retry_after"] = int(retry_value)
            except ValueError:
                # Try to parse as HTTP date
                pass

        return info

    def should_retry(self, attempt: int, error: Exception | None = None) -> bool:
        """Determine if request should be retried.

        Args:
            attempt: Current attempt number (1-based)
            error: Optional error that occurred

        Returns:
            bool: True if should retry
        """
        # Don't retry if we've hit the rate limit
        if error and "rate limit" in str(error).lower():
            return False

        # Allow retries up to burst size for transient errors
        return attempt <= min(3, self.burst_size)

    def __str__(self) -> str:
        """Return string representation of rate limit config."""
        return f"{self.requests_per_window} requests per {self.window_seconds}s ({self.strategy.value})"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "requests_per_window": self.requests_per_window,
            "window_seconds": self.window_seconds,
            "strategy": self.strategy.value,
            "burst_size": self.burst_size,
            "requests_per_second": round(self.requests_per_second, 2),
            "requests_per_minute": round(self.requests_per_minute, 2),
            "min_request_interval": round(self.min_request_interval, 3),
            "retry_after_header": self.retry_after_header,
            "rate_limit_header": self.rate_limit_header,
            "remaining_header": self.remaining_header,
            "reset_header": self.reset_header,
        }

    @classmethod
    def from_per_second(
        cls, requests_per_second: float, burst_size: int | None = None, **kwargs
    ) -> "RateLimitConfig":
        """Create config from requests per second.

        Args:
            requests_per_second: Requests per second
            burst_size: Optional burst allowance
            **kwargs: Additional configuration options

        Returns:
            RateLimitConfig: Created configuration
        """
        # Convert to reasonable window
        if requests_per_second >= 1:
            window_seconds = 1
            requests_per_window = int(requests_per_second)
        else:
            # For sub-second rates, use larger window
            window_seconds = int(1 / requests_per_second)
            requests_per_window = 1

        return cls(
            requests_per_window=requests_per_window,
            window_seconds=window_seconds,
            burst_size=burst_size,
            **kwargs,
        )

    @classmethod
    def from_per_minute(
        cls, requests_per_minute: int, burst_size: int | None = None, **kwargs
    ) -> "RateLimitConfig":
        """Create config from requests per minute.

        Args:
            requests_per_minute: Requests per minute
            burst_size: Optional burst allowance
            **kwargs: Additional configuration options

        Returns:
            RateLimitConfig: Created configuration
        """
        return cls(
            requests_per_window=requests_per_minute,
            window_seconds=60,
            burst_size=burst_size,
            **kwargs,
        )

    @classmethod
    def from_per_hour(
        cls, requests_per_hour: int, burst_size: int | None = None, **kwargs
    ) -> "RateLimitConfig":
        """Create config from requests per hour.

        Args:
            requests_per_hour: Requests per hour
            burst_size: Optional burst allowance
            **kwargs: Additional configuration options

        Returns:
            RateLimitConfig: Created configuration
        """
        return cls(
            requests_per_window=requests_per_hour,
            window_seconds=3600,
            burst_size=burst_size,
            **kwargs,
        )
