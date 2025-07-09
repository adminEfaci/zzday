"""
GraphQL Rate Limiting

Provides rate limiting functionality for GraphQL operations to prevent abuse
and ensure fair usage of API resources.
"""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Any

from strawberry import GraphQLError
from strawberry.types import Info

logger = logging.getLogger(__name__)


class RateLimitError(GraphQLError):
    """Error raised when rate limit is exceeded"""
    
    def __init__(
        self,
        retry_after: int,
        limit: int,
        window: int,
        message: str | None = None
    ):
        super().__init__(
            message or f"Rate limit exceeded. Try again in {retry_after} seconds.",
            extensions={
                "code": "RATE_LIMITED",
                "retry_after": retry_after,
                "limit": limit,
                "window": window
            }
        )


class RateLimitStrategy(Enum):
    """Different strategies for rate limiting"""
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    TOKEN_BUCKET = "token_bucket"  # noqa: S105
    LEAKY_BUCKET = "leaky_bucket"


class RateLimiter:
    """
    Base rate limiter class that can be extended for different backends.
    """
    
    def __init__(
        self,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    ):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.strategy = strategy
    
    async def check_rate_limit(
        self, 
        key: str,
        cost: int = 1
    ) -> tuple[bool, int | None]:
        """
        Check if the rate limit allows this request.
        
        Returns:
            (allowed, retry_after_seconds)
        """
        raise NotImplementedError
    
    async def reset(self, key: str):
        """Reset rate limit for a specific key"""
        raise NotImplementedError


class InMemoryRateLimiter(RateLimiter):
    """
    In-memory rate limiter for development/testing.
    Not suitable for production with multiple servers.
    """
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
    
    async def check_rate_limit(
        self, 
        key: str,
        cost: int = 1
    ) -> tuple[bool, int | None]:
        """Check rate limit using sliding window algorithm"""
        async with self._locks[key]:
            now = datetime.now().timestamp()
            window_start = now - self.window_seconds
            
            # Remove old entries
            self._buckets[key] = [
                ts for ts in self._buckets[key] 
                if ts > window_start
            ]
            
            # Check if adding this request would exceed limit
            current_count = len(self._buckets[key])
            if current_count + cost > self.requests_per_window:
                # Calculate retry after
                if self._buckets[key]:
                    oldest = self._buckets[key][0]
                    retry_after = int(oldest + self.window_seconds - now) + 1
                else:
                    retry_after = 1
                
                return False, retry_after
            
            # Add timestamps for this request
            for _ in range(cost):
                self._buckets[key].append(now)
            
            return True, None
    
    async def reset(self, key: str):
        """Reset rate limit for a key"""
        async with self._locks[key]:
            self._buckets[key] = []


class RedisRateLimiter(RateLimiter):
    """
    Redis-based rate limiter for production use.
    Supports distributed rate limiting across multiple servers.
    """
    
    def __init__(self, redis_client: Any, key_prefix: str = "rl:", **kwargs):
        super().__init__(**kwargs)
        self.redis = redis_client
        self.key_prefix = key_prefix
    
    async def check_rate_limit(
        self, 
        key: str,
        cost: int = 1
    ) -> tuple[bool, int | None]:
        """Check rate limit using Redis sorted sets for sliding window"""
        full_key = f"{self.key_prefix}{key}"
        now = datetime.now().timestamp()
        window_start = now - self.window_seconds
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(full_key, 0, window_start)
        
        # Count current entries
        pipe.zcount(full_key, window_start, now)
        
        # Execute pipeline
        results = await pipe.execute()
        current_count = results[1]
        
        # Check if adding this request would exceed limit
        if current_count + cost > self.requests_per_window:
            # Get oldest entry to calculate retry_after
            oldest_entries = await self.redis.zrange(
                full_key, 0, 0, withscores=True
            )
            if oldest_entries:
                oldest_timestamp = oldest_entries[0][1]
                retry_after = int(oldest_timestamp + self.window_seconds - now) + 1
            else:
                retry_after = 1
            
            return False, retry_after
        
        # Add entries for this request
        pipe = self.redis.pipeline()
        for i in range(cost):
            # Add small offset to ensure unique scores
            pipe.zadd(full_key, {f"{now}:{i}": now + i * 0.001})
        
        # Set expiry
        pipe.expire(full_key, self.window_seconds + 60)
        
        await pipe.execute()
        
        return True, None
    
    async def reset(self, key: str):
        """Reset rate limit for a key"""
        full_key = f"{self.key_prefix}{key}"
        await self.redis.delete(full_key)


# ============================================================================
# Rate Limiting Decorators
# ============================================================================

def rate_limited(
    requests: int = 10,
    window: int = 60,
    key_fn: Callable | None = None,
    cost_fn: Callable | None = None,
    rate_limiter: RateLimiter | None = None
):
    """
    Decorator to rate limit GraphQL resolvers.
    
    Args:
        requests: Number of requests allowed per window
        window: Time window in seconds
        key_fn: Function to generate rate limit key from (info, args, kwargs)
        cost_fn: Function to calculate request cost from (info, args, kwargs)
        rate_limiter: Custom rate limiter instance
    
    Usage:
        @strawberry.field
        @rate_limited(requests=10, window=60)
        async def expensive_query(self, info: Info) -> str:
            return "data"
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):  # noqa: PLR0912
            # Find the Info object
            info = None
            for arg in args:
                if isinstance(arg, Info):
                    info = arg
                    break
            if not info:
                for arg in kwargs.values():
                    if isinstance(arg, Info):
                        info = arg
                        break
            
            if not info:
                raise RuntimeError("No Info object found in resolver arguments")
            
            # Get or create rate limiter
            limiter = rate_limiter
            if not limiter:
                # Try to get from context
                limiter = info.context.get("rate_limiter")
                if not limiter:
                    # Create in-memory limiter as fallback
                    limiter = InMemoryRateLimiter(
                        requests_per_window=requests,
                        window_seconds=window
                    )
            
            # Generate rate limit key
            if key_fn:
                key = key_fn(info, args, kwargs)
            else:
                # Default key based on user or IP
                user = info.context.get("user")
                if user:
                    key = f"user:{user.id}:{func.__name__}"
                else:
                    # Use IP address for anonymous users
                    request = info.context.get("request")
                    ip = getattr(request, "client", {}).get("host", "unknown")
                    key = f"ip:{ip}:{func.__name__}"
            
            # Calculate cost
            cost = cost_fn(info, args, kwargs) if cost_fn else 1
            
            # Check rate limit
            allowed, retry_after = await limiter.check_rate_limit(key, cost)
            
            if not allowed:
                logger.warning(f"Rate limit exceeded for key: {key}")
                raise RateLimitError(
                    retry_after=retry_after,
                    limit=requests,
                    window=window
                )
            
            # Call the original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


class ComplexityBasedRateLimiter:
    """
    Rate limiter that uses query complexity as the cost metric.
    
    Instead of counting requests, it tracks total complexity points used.
    """
    
    def __init__(
        self,
        complexity_limit: int = 10000,
        window_seconds: int = 60,
        rate_limiter: RateLimiter | None = None
    ):
        self.complexity_limit = complexity_limit
        self.window_seconds = window_seconds
        self.rate_limiter = rate_limiter or InMemoryRateLimiter(
            requests_per_window=complexity_limit,
            window_seconds=window_seconds
        )
    
    async def check_complexity_limit(
        self,
        key: str,
        complexity: int
    ) -> tuple[bool, int | None]:
        """Check if the complexity limit allows this query"""
        return await self.rate_limiter.check_rate_limit(key, complexity)


# ============================================================================
# Rate Limit Key Generators
# ============================================================================

def user_key_generator(info: Info, args: tuple, kwargs: dict) -> str:
    """Generate rate limit key based on authenticated user"""
    user = info.context.get("user")
    if user:
        return f"user:{user.id}"
    # Fallback to IP
    request = info.context.get("request")
    ip = getattr(request, "client", {}).get("host", "unknown")
    return f"ip:{ip}"


def operation_key_generator(operation: str) -> Callable:
    """Generate rate limit key based on user and operation"""
    def generator(info: Info, args: tuple, kwargs: dict) -> str:
        user_key = user_key_generator(info, args, kwargs)
        return f"{user_key}:op:{operation}"
    return generator


def field_key_generator(info: Info, args: tuple, kwargs: dict) -> str:
    """Generate rate limit key based on user and field"""
    user_key = user_key_generator(info, args, kwargs)
    field_name = info.field_name
    parent_type = info.parent_type.name if info.parent_type else "unknown"
    return f"{user_key}:field:{parent_type}.{field_name}"


# ============================================================================
# GraphQL Extension for Rate Limiting
# ============================================================================

class RateLimitExtension:
    """
    Strawberry extension for automatic rate limiting.
    
    Usage:
        schema = strawberry.Schema(
            query=Query,
            extensions=[
                RateLimitExtension(
                    rate_limiter=redis_rate_limiter,
                    global_limit=1000,
                    global_window=60
                )
            ]
        )
    """
    
    def __init__(
        self,
        rate_limiter: RateLimiter,
        global_limit: int = 1000,
        global_window: int = 60,
        use_complexity: bool = True
    ):
        self.rate_limiter = rate_limiter
        self.global_limit = global_limit
        self.global_window = global_window
        self.use_complexity = use_complexity
        
        if use_complexity:
            self.complexity_limiter = ComplexityBasedRateLimiter(
                complexity_limit=global_limit,
                window_seconds=global_window,
                rate_limiter=rate_limiter
            )
    
    async def on_request_start(self):
        """Called at the start of a request"""
    
    async def on_request_end(self, result):
        """Called at the end of a request"""
        # Check global rate limit
        if hasattr(result, "context"):
            user_key = user_key_generator(result.context, (), {})
            
            if self.use_complexity and hasattr(result, "extensions"):
                # Use complexity as cost
                complexity = result.extensions.get("complexity", 1)
                allowed, retry_after = await self.complexity_limiter.check_complexity_limit(
                    f"{user_key}:global",
                    complexity
                )
            else:
                # Use request count
                allowed, retry_after = await self.rate_limiter.check_rate_limit(
                    f"{user_key}:global",
                    1
                )
            
            if not allowed:
                raise RateLimitError(
                    retry_after=retry_after,
                    limit=self.global_limit,
                    window=self.global_window,
                    message="Global rate limit exceeded"
                )


__all__ = [
    # Rate limiters
    "ComplexityBasedRateLimiter",
    "InMemoryRateLimiter",
    # Errors
    "RateLimitError",
    # Extensions
    "RateLimitExtension",
    # Enums
    "RateLimitStrategy",
    "RateLimiter",
    "RedisRateLimiter",
    # Key generators
    "field_key_generator",
    "operation_key_generator",
    # Decorators
    "rate_limited",
    "user_key_generator",
]