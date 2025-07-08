"""
Redis Cache Adapter

Production-ready implementation of ICachePort using Redis.
"""

import json
from typing import Any
from uuid import UUID

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort,
)


class RedisCacheAdapter(ICachePort):
    """Redis implementation of cache port."""

    def __init__(
        self,
        redis_client: redis.Redis,
        key_prefix: str = "identity:",
        default_ttl: int = 3600,
    ):
        """Initialize Redis cache adapter.

        Args:
            redis_client: Async Redis client
            key_prefix: Prefix for all keys
            default_ttl: Default TTL in seconds
        """
        self._redis = redis_client
        self._prefix = key_prefix
        self._default_ttl = default_ttl

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session from cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            data = await self._redis.get(key)

            if data is None:
                return None

            return json.loads(data)

        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting session {session_id}: {e}")
            return None

    async def store_session(
        self, session_id: str, data: dict[str, Any], ttl: int
    ) -> bool:
        """Store session in cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            serialized = json.dumps(data, default=str)

            result = await self._redis.setex(key, ttl, serialized)
            return bool(result)

        except (RedisError, json.JSONEncodeError) as e:
            logger.error(f"Error storing session {session_id}: {e}")
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete session from cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            result = await self._redis.delete(key)
            return result > 0

        except RedisError as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False

    async def get_user_cache(
        self, user_id: UUID, key: str
    ) -> Any | None:
        """Get user-specific cache value."""
        try:
            cache_key = f"{self._prefix}user:{user_id}:{key}"
            data = await self._redis.get(cache_key)

            if data is None:
                return None

            return json.loads(data)

        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting user cache {user_id}:{key}: {e}")
            return None

    async def set_user_cache(
        self,
        user_id: UUID,
        key: str,
        value: Any,
        ttl: int | None = None,
    ) -> bool:
        """Set user-specific cache value."""
        try:
            cache_key = f"{self._prefix}user:{user_id}:{key}"
            serialized = json.dumps(value, default=str)
            ttl_seconds = ttl or self._default_ttl

            result = await self._redis.setex(
                cache_key, ttl_seconds, serialized
            )
            return bool(result)

        except (RedisError, json.JSONEncodeError) as e:
            logger.error(f"Error setting user cache {user_id}:{key}: {e}")
            return False

    async def invalidate_user_cache(self, user_id: UUID) -> None:
        """Invalidate all user cache entries."""
        try:
            pattern = f"{self._prefix}user:{user_id}:*"

            # Use SCAN for production safety
            cursor = 0
            while True:
                cursor, keys = await self._redis.scan(
                    cursor, match=pattern, count=100
                )
                if keys:
                    await self._redis.delete(*keys)
                if cursor == 0:
                    break

        except RedisError as e:
            logger.error(f"Error invalidating user cache {user_id}: {e}")

    async def increment_counter(
        self, key: str, amount: int = 1
    ) -> int:
        """Increment counter atomically."""
        try:
            cache_key = f"{self._prefix}counter:{key}"
            new_value = await self._redis.incrby(cache_key, amount)
            return new_value

        except RedisError as e:
            logger.error(f"Error incrementing counter {key}: {e}")
            return -1