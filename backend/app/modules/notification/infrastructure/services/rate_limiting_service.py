"""Rate limiting service for notification delivery."""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import aioredis

from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
)


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    max_requests: int
    window_seconds: int
    burst_size: int | None = None

    @property
    def burst_limit(self) -> int:
        """Get burst limit (defaults to 2x max_requests)."""
        return self.burst_size or (self.max_requests * 2)


class RateLimitingService:
    """Service for managing notification rate limits."""

    # Default rate limits by channel
    DEFAULT_LIMITS = {
        NotificationChannel.EMAIL: RateLimitConfig(
            max_requests=100, window_seconds=60, burst_size=200  # 100 per minute
        ),
        NotificationChannel.SMS: RateLimitConfig(
            max_requests=10, window_seconds=60, burst_size=20  # 10 per minute
        ),
        NotificationChannel.PUSH: RateLimitConfig(
            max_requests=1000, window_seconds=60, burst_size=2000  # 1000 per minute
        ),
        NotificationChannel.IN_APP: RateLimitConfig(
            max_requests=10000, window_seconds=60, burst_size=20000  # 10000 per minute
        ),
    }

    # Provider-specific limits
    PROVIDER_LIMITS = {
        "sendgrid": RateLimitConfig(max_requests=100, window_seconds=1),  # 100/second
        "twilio": RateLimitConfig(max_requests=1, window_seconds=1),  # 1/second
        "firebase": RateLimitConfig(max_requests=500, window_seconds=1),  # 500/second
    }

    def __init__(
        self,
        redis_client: aioredis.Redis | None = None,
        channel_limits: dict[NotificationChannel, RateLimitConfig] | None = None,
        provider_limits: dict[str, RateLimitConfig] | None = None,
    ):
        """Initialize rate limiting service.

        Args:
            redis_client: Redis client for distributed rate limiting
            channel_limits: Custom channel rate limits
            provider_limits: Custom provider rate limits
        """
        self.redis_client = redis_client
        self.channel_limits = channel_limits or self.DEFAULT_LIMITS
        self.provider_limits = provider_limits or self.PROVIDER_LIMITS

        # Local rate limit tracking (fallback when Redis not available)
        self._local_buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"tokens": 0, "last_refill": time.time()}
        )

    async def check_rate_limit(
        self,
        channel: NotificationChannel,
        provider: str | None = None,
        recipient_id: UUID | None = None,
        priority: NotificationPriority | None = None,
    ) -> tuple[bool, float | None]:
        """Check if request is within rate limits.

        Args:
            channel: Notification channel
            provider: Optional provider name
            recipient_id: Optional recipient ID for per-user limits
            priority: Optional priority for priority-based limits

        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        # Priority bypass for urgent notifications
        if priority == NotificationPriority.URGENT:
            return True, None

        # Check channel rate limit
        channel_key = f"rate_limit:channel:{channel.value}"
        channel_allowed, channel_retry = await self._check_limit(
            channel_key,
            self.channel_limits.get(
                channel, self.DEFAULT_LIMITS[NotificationChannel.EMAIL]
            ),
        )

        if not channel_allowed:
            return False, channel_retry

        # Check provider rate limit if specified
        if provider and provider in self.provider_limits:
            provider_key = f"rate_limit:provider:{provider}"
            provider_allowed, provider_retry = await self._check_limit(
                provider_key, self.provider_limits[provider]
            )

            if not provider_allowed:
                return False, provider_retry

        # Check per-recipient rate limit if specified
        if recipient_id:
            recipient_key = f"rate_limit:recipient:{recipient_id}:{channel.value}"
            # More restrictive limit for per-recipient
            recipient_config = RateLimitConfig(
                max_requests=10, window_seconds=3600  # 10 per hour per recipient
            )
            recipient_allowed, recipient_retry = await self._check_limit(
                recipient_key, recipient_config
            )

            if not recipient_allowed:
                return False, recipient_retry

        return True, None

    async def consume_rate_limit(
        self,
        channel: NotificationChannel,
        provider: str | None = None,
        recipient_id: UUID | None = None,
        count: int = 1,
    ) -> bool:
        """Consume rate limit tokens.

        Args:
            channel: Notification channel
            provider: Optional provider name
            recipient_id: Optional recipient ID
            count: Number of tokens to consume

        Returns:
            True if tokens were consumed successfully
        """
        # Consume channel tokens
        channel_key = f"rate_limit:channel:{channel.value}"
        channel_consumed = await self._consume_tokens(
            channel_key,
            self.channel_limits.get(
                channel, self.DEFAULT_LIMITS[NotificationChannel.EMAIL]
            ),
            count,
        )

        if not channel_consumed:
            return False

        # Consume provider tokens if specified
        if provider and provider in self.provider_limits:
            provider_key = f"rate_limit:provider:{provider}"
            provider_consumed = await self._consume_tokens(
                provider_key, self.provider_limits[provider], count
            )

            if not provider_consumed:
                # Rollback channel consumption
                await self._refund_tokens(channel_key, count)
                return False

        # Consume per-recipient tokens if specified
        if recipient_id:
            recipient_key = f"rate_limit:recipient:{recipient_id}:{channel.value}"
            recipient_config = RateLimitConfig(max_requests=10, window_seconds=3600)
            recipient_consumed = await self._consume_tokens(
                recipient_key, recipient_config, count
            )

            if not recipient_consumed:
                # Rollback previous consumptions
                await self._refund_tokens(channel_key, count)
                if provider:
                    provider_key = f"rate_limit:provider:{provider}"
                    await self._refund_tokens(provider_key, count)
                return False

        return True

    async def _check_limit(
        self, key: str, config: RateLimitConfig
    ) -> tuple[bool, float | None]:
        """Check rate limit for a specific key.

        Args:
            key: Rate limit key
            config: Rate limit configuration

        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        if self.redis_client:
            return await self._check_limit_redis(key, config)
        return self._check_limit_local(key, config)

    async def _check_limit_redis(
        self, key: str, config: RateLimitConfig
    ) -> tuple[bool, float | None]:
        """Check rate limit using Redis."""
        # Use sliding window algorithm
        now = time.time()
        window_start = now - config.window_seconds

        # Remove old entries
        await self.redis_client.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        current_count = await self.redis_client.zcard(key)

        if current_count >= config.max_requests:
            # Get oldest entry to calculate retry time
            oldest = await self.redis_client.zrange(key, 0, 0, withscores=True)
            if oldest:
                oldest_time = oldest[0][1]
                retry_after = (oldest_time + config.window_seconds) - now
                return False, max(retry_after, 0.1)
            return False, 1.0

        return True, None

    def _check_limit_local(
        self, key: str, config: RateLimitConfig
    ) -> tuple[bool, float | None]:
        """Check rate limit using local token bucket."""
        bucket = self._local_buckets[key]
        now = time.time()

        # Refill tokens
        time_passed = now - bucket["last_refill"]
        tokens_to_add = (time_passed / config.window_seconds) * config.max_requests
        bucket["tokens"] = min(bucket["tokens"] + tokens_to_add, config.burst_limit)
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1:
            return True, None

        # Calculate retry time
        tokens_needed = 1 - bucket["tokens"]
        retry_after = (tokens_needed / config.max_requests) * config.window_seconds
        return False, retry_after

    async def _consume_tokens(
        self, key: str, config: RateLimitConfig, count: int = 1
    ) -> bool:
        """Consume rate limit tokens.

        Args:
            key: Rate limit key
            config: Rate limit configuration
            count: Number of tokens to consume

        Returns:
            True if tokens were consumed
        """
        if self.redis_client:
            return await self._consume_tokens_redis(key, config, count)
        return self._consume_tokens_local(key, config, count)

    async def _consume_tokens_redis(
        self, key: str, config: RateLimitConfig, count: int
    ) -> bool:
        """Consume tokens using Redis."""
        now = time.time()
        window_start = now - config.window_seconds

        # Use Redis transaction
        pipe = self.redis_client.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)

        # Add new entries
        for i in range(count):
            pipe.zadd(key, {f"{now}:{i}": now})

        # Set expiry
        pipe.expire(key, config.window_seconds + 60)

        # Execute transaction
        await pipe.execute()

        return True

    def _consume_tokens_local(
        self, key: str, config: RateLimitConfig, count: int
    ) -> bool:
        """Consume tokens using local bucket."""
        bucket = self._local_buckets[key]

        # First check and refill
        allowed, _ = self._check_limit_local(key, config)
        if not allowed:
            return False

        # Consume tokens
        if bucket["tokens"] >= count:
            bucket["tokens"] -= count
            return True

        return False

    async def _refund_tokens(self, key: str, count: int) -> None:
        """Refund consumed tokens (for rollback).

        Args:
            key: Rate limit key
            count: Number of tokens to refund
        """
        if self.redis_client:
            # Remove the most recent entries
            await self.redis_client.zremrangebyrank(key, -count, -1)
        # Add tokens back to local bucket
        elif key in self._local_buckets:
            self._local_buckets[key]["tokens"] += count

    async def get_current_usage(
        self, channel: NotificationChannel | None = None, provider: str | None = None
    ) -> dict[str, Any]:
        """Get current rate limit usage statistics.

        Args:
            channel: Optional channel filter
            provider: Optional provider filter

        Returns:
            Dictionary with usage statistics
        """
        stats = {}

        if channel:
            channel_key = f"rate_limit:channel:{channel.value}"
            config = self.channel_limits.get(
                channel, self.DEFAULT_LIMITS[NotificationChannel.EMAIL]
            )

            if self.redis_client:
                window_start = time.time() - config.window_seconds
                await self.redis_client.zremrangebyscore(channel_key, 0, window_start)
                current_count = await self.redis_client.zcard(channel_key)
            else:
                bucket = self._local_buckets[channel_key]
                current_count = int(config.max_requests - bucket.get("tokens", 0))

            stats[f"{channel.value}_usage"] = {
                "current": current_count,
                "limit": config.max_requests,
                "window_seconds": config.window_seconds,
                "percentage": (current_count / config.max_requests * 100)
                if config.max_requests > 0
                else 0,
            }

        if provider and provider in self.provider_limits:
            provider_key = f"rate_limit:provider:{provider}"
            config = self.provider_limits[provider]

            if self.redis_client:
                window_start = time.time() - config.window_seconds
                await self.redis_client.zremrangebyscore(provider_key, 0, window_start)
                current_count = await self.redis_client.zcard(provider_key)
            else:
                bucket = self._local_buckets[provider_key]
                current_count = int(config.max_requests - bucket.get("tokens", 0))

            stats[f"{provider}_usage"] = {
                "current": current_count,
                "limit": config.max_requests,
                "window_seconds": config.window_seconds,
                "percentage": (current_count / config.max_requests * 100)
                if config.max_requests > 0
                else 0,
            }

        return stats

    async def reset_limits(
        self,
        channel: NotificationChannel | None = None,
        provider: str | None = None,
        recipient_id: UUID | None = None,
    ) -> None:
        """Reset rate limits.

        Args:
            channel: Optional channel to reset
            provider: Optional provider to reset
            recipient_id: Optional recipient to reset
        """
        keys_to_reset = []

        if channel:
            keys_to_reset.append(f"rate_limit:channel:{channel.value}")

        if provider:
            keys_to_reset.append(f"rate_limit:provider:{provider}")

        if recipient_id:
            if channel:
                keys_to_reset.append(
                    f"rate_limit:recipient:{recipient_id}:{channel.value}"
                )
            else:
                # Reset all channels for recipient
                for ch in NotificationChannel:
                    keys_to_reset.append(
                        f"rate_limit:recipient:{recipient_id}:{ch.value}"
                    )

        if self.redis_client:
            for key in keys_to_reset:
                await self.redis_client.delete(key)
        else:
            for key in keys_to_reset:
                if key in self._local_buckets:
                    del self._local_buckets[key]
