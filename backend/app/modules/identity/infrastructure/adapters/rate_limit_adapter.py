"""
Rate Limit Adapter

Redis-based implementation of the rate limiting port interface.
Provides rate limiting functionality using sliding window algorithm.
"""

import time
from datetime import datetime, UTC
from typing import Any

from redis.asyncio import Redis

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.monitoring.rate_limit_port import IRateLimitPort
from app.modules.identity.domain.value_objects.rate_limit_status import RateLimitStatus


class RateLimitAdapter(IRateLimitPort):
    """Redis implementation of rate limiting port."""
    
    # Default rate limit rules (can be overridden via configuration)
    DEFAULT_RULES = {
        "login": {"limit": 5, "window": 300},  # 5 attempts per 5 minutes
        "register": {"limit": 3, "window": 3600},  # 3 registrations per hour
        "password_reset": {"limit": 3, "window": 3600},  # 3 resets per hour
        "api_default": {"limit": 100, "window": 60},  # 100 requests per minute
        "api_heavy": {"limit": 10, "window": 60},  # 10 heavy requests per minute
    }
    
    def __init__(self, redis_client: Redis, rules: dict[str, dict[str, int]] | None = None):
        """Initialize rate limit adapter.
        
        Args:
            redis_client: Redis async client instance
            rules: Custom rate limit rules (overrides defaults)
        """
        self._redis = redis_client
        self._rules = rules or self.DEFAULT_RULES
        self._prefix = "ratelimit:"
    
    async def check_rate_limit(
        self,
        identifier: str,
        rule: str
    ) -> RateLimitStatus:
        """Check rate limit without incrementing.
        
        Args:
            identifier: Client identifier (IP, user ID, etc.)
            rule: Rate limit rule name
            
        Returns:
            RateLimitStatus value object
        """
        try:
            rule_config = self._rules.get(rule, self._rules["api_default"])
            limit = rule_config["limit"]
            window = rule_config["window"]
            
            # Get current usage
            key = self._make_key(identifier, rule)
            current_time = time.time()
            window_start = current_time - window
            
            # Count requests in sliding window
            usage = await self._count_in_window(key, window_start, current_time)
            
            # Calculate remaining
            remaining = max(0, limit - usage)
            exceeded = usage >= limit
            
            # Calculate reset time (end of current window)
            reset_at = datetime.fromtimestamp(current_time + window, UTC)
            
            return RateLimitStatus(
                limit=limit,
                remaining=remaining,
                reset_at=reset_at,
                window_seconds=window,
                exceeded=exceeded
            )
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            # Return permissive status on error
            return RateLimitStatus(
                limit=1000,
                remaining=1000,
                reset_at=datetime.now(UTC),
                window_seconds=60,
                exceeded=False
            )
    
    async def increment_usage(
        self,
        identifier: str,
        rule: str,
        amount: int = 1
    ) -> int:
        """Increment rate limit usage.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            amount: Increment amount
            
        Returns:
            New usage count
        """
        try:
            rule_config = self._rules.get(rule, self._rules["api_default"])
            window = rule_config["window"]
            
            key = self._make_key(identifier, rule)
            current_time = time.time()
            
            # Add to sorted set with timestamp as score
            for _ in range(amount):
                await self._redis.zadd(key, {str(current_time): current_time})
            
            # Remove old entries outside window
            window_start = current_time - window
            await self._redis.zremrangebyscore(key, 0, window_start)
            
            # Set expiration on key
            await self._redis.expire(key, window + 60)  # Extra 60s buffer
            
            # Get new count
            usage = await self._count_in_window(key, window_start, current_time)
            
            logger.debug(f"Rate limit incremented for {identifier}:{rule} - usage: {usage}")
            
            return usage
            
        except Exception as e:
            logger.error(f"Rate limit increment error: {e}")
            return 0
    
    async def reset_rate_limit(
        self,
        identifier: str,
        rule: str
    ) -> bool:
        """Reset rate limit counter.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            
        Returns:
            True if reset successfully
        """
        try:
            key = self._make_key(identifier, rule)
            result = await self._redis.delete(key)
            
            logger.info(f"Rate limit reset for {identifier}:{rule}")
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Rate limit reset error: {e}")
            return False
    
    async def get_rate_limit_status(
        self,
        identifier: str,
        rule: str
    ) -> dict[str, Any]:
        """Get current rate limit status.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            
        Returns:
            Current limit status dictionary
        """
        try:
            status = await self.check_rate_limit(identifier, rule)
            
            return {
                "identifier": identifier,
                "rule": rule,
                "limit": status.limit,
                "remaining": status.remaining,
                "reset_at": status.reset_at.isoformat(),
                "window_seconds": status.window_seconds,
                "exceeded": status.exceeded,
                "usage": status.limit - status.remaining
            }
            
        except Exception as e:
            logger.error(f"Get rate limit status error: {e}")
            return {
                "identifier": identifier,
                "rule": rule,
                "error": str(e)
            }
    
    async def _count_in_window(self, key: str, window_start: float, window_end: float) -> int:
        """Count entries in sliding window.
        
        Args:
            key: Redis key
            window_start: Window start timestamp
            window_end: Window end timestamp
            
        Returns:
            Count of entries in window
        """
        try:
            count = await self._redis.zcount(key, window_start, window_end)
            return int(count)
        except Exception:
            return 0
    
    def _make_key(self, identifier: str, rule: str) -> str:
        """Create Redis key for rate limit.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            
        Returns:
            Redis key
        """
        return f"{self._prefix}{rule}:{identifier}"
    
    async def add_custom_rule(self, rule_name: str, limit: int, window: int) -> None:
        """Add or update a custom rate limit rule.
        
        Args:
            rule_name: Name of the rule
            limit: Request limit
            window: Time window in seconds
        """
        self._rules[rule_name] = {"limit": limit, "window": window}
        logger.info(f"Added rate limit rule '{rule_name}': {limit} per {window}s")
    
    async def health_check(self) -> bool:
        """Check if rate limiter is healthy.
        
        Returns:
            True if Redis is accessible
        """
        try:
            await self._redis.ping()
            return True
        except Exception as e:
            logger.error(f"Rate limiter health check failed: {e}")
            return False