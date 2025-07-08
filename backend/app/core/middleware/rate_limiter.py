"""Rate limiting middleware."""

import hashlib
import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# Handle missing cache manager
try:
    from app.core.cache import cache_manager
except ImportError:
    # Fallback cache manager
    class MockCacheManager:
        async def get(self, key: str):
            return None
        
        async def set(self, key: str, value: any, ttl: int | None = None):
            pass
    
    cache_manager = MockCacheManager()

# Handle missing config
try:
    from app.core.config import settings
except ImportError:
    # Fallback settings
    class MockSettings:
        RATE_LIMIT_ENABLED = True
        RATE_LIMIT_DEFAULT = "100/hour"
        RATE_LIMIT_AUTH = "10/minute"
    
    settings = MockSettings()

# Handle missing constants
try:
    from app.core.constants import CACHE_KEY_RATE_LIMIT
except ImportError:
    CACHE_KEY_RATE_LIMIT = "rate_limit:{key}:{window}"

from app.core.errors import RateLimitError
from app.core.logging import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using token bucket algorithm."""

    def __init__(self, app):
        super().__init__(app)
        self.enabled = settings.RATE_LIMIT_ENABLED
        self.default_limit = self._parse_rate_limit(settings.RATE_LIMIT_DEFAULT)
        self.auth_limit = self._parse_rate_limit(settings.RATE_LIMIT_AUTH)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Apply rate limiting."""
        if not self.enabled:
            return await call_next(request)

        # Skip rate limiting for certain paths
        if self._is_exempt(request.url.path):
            return await call_next(request)

        # Determine rate limit key and limits
        key = self._get_rate_limit_key(request)
        limit, window = self._get_rate_limit(request)

        # Check rate limit
        allowed, remaining, reset_time = await self._check_rate_limit(
            key,
            limit,
            window,
        )

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                key=key,
                limit=limit,
                window=window,
            )
            raise RateLimitError(str(limit), f"{window}s")

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)

        return response

    def _parse_rate_limit(self, limit_str: str) -> tuple[int, int]:
        """Parse rate limit string (e.g., '100/hour')."""
        parts = limit_str.split("/")
        if len(parts) != 2:
            return 100, 3600  # Default: 100 per hour

        try:
            count = int(parts[0])

            # Parse time window
            time_str = parts[1].lower()
            if time_str == "second":
                window = 1
            elif time_str == "minute":
                window = 60
            elif time_str == "hour":
                window = 3600
            elif time_str == "day":
                window = 86400
            else:
                window = 3600  # Default to hour

            return count, window
        except ValueError:
            return 100, 3600  # Default: 100 per hour

    def _get_rate_limit_key(self, request: Request) -> str:
        """Get rate limit key for request."""
        # Use user ID if authenticated
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"user:{user_id}"

        # Use IP address for anonymous requests
        client_ip = "unknown"
        if request.client and hasattr(request.client, "host"):
            client_ip = request.client.host
        elif hasattr(request, "headers"):
            # Check for forwarded headers
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                client_ip = forwarded_for.split(",")[0].strip()
            else:
                real_ip = request.headers.get("X-Real-IP")
                if real_ip:
                    client_ip = real_ip.strip()

        # Hash the IP for privacy
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        return f"ip:{ip_hash}"

    def _get_rate_limit(self, request: Request) -> tuple[int, int]:
        """Get rate limit for request."""
        path = request.url.path

        # Auth endpoints have stricter limits
        if path.startswith("/graphql") and request.method == "POST":
            # Check if it's a login mutation
            # This is a simplified check
            return self.auth_limit

        return self.default_limit

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from rate limiting."""
        exempt_paths = [
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

        return any(path.startswith(p) for p in exempt_paths)

    async def _check_rate_limit(
        self,
        key: str,
        limit: int,
        window: int,
    ) -> tuple[bool, int, int]:
        """Check rate limit using token bucket algorithm."""
        current_time = int(time.time())
        window_start = current_time - window

        # Cache key for this rate limit
        cache_key = CACHE_KEY_RATE_LIMIT.format(key=key, window=window)

        # Get current count from cache
        count_data = await cache_manager.get(cache_key)

        if count_data is None:
            # First request in window
            await cache_manager.set(
                cache_key,
                {"count": 1, "window_start": current_time},
                ttl=window,
            )
            return True, limit - 1, current_time + window

        count = count_data.get("count", 0)
        cached_window_start = count_data.get("window_start", current_time)

        # Check if we're still in the same window
        if cached_window_start < window_start:
            # New window, reset count
            await cache_manager.set(
                cache_key,
                {"count": 1, "window_start": current_time},
                ttl=window,
            )
            return True, limit - 1, current_time + window

        # Check if limit exceeded
        if count >= limit:
            reset_time = cached_window_start + window
            return False, 0, reset_time

        # Increment count
        count_data["count"] = count + 1
        await cache_manager.set(cache_key, count_data, ttl=window)

        remaining = limit - count - 1
        reset_time = cached_window_start + window

        return True, remaining, reset_time
