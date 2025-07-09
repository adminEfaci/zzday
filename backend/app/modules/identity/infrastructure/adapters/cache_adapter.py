"""
Redis Cache Adapter Implementation

Production-ready Redis implementation of ICachePort interface.
"""

import json
import logging
from typing import Any
from uuid import UUID

import redis.asyncio as redis
from redis.exceptions import RedisError

from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort,
)

logger = logging.getLogger(__name__)


class RedisCacheAdapter(ICachePort):
    """Production Redis implementation of cache port."""
    
    def __init__(
        self,
        redis_client: redis.Redis,
        key_prefix: str = "identity:",
        default_ttl: int = 3600
    ):
        """Initialize Redis cache adapter.
        
        Args:
            redis_client: Async Redis client instance
            key_prefix: Prefix for all cache keys
            default_ttl: Default TTL in seconds
        """
        self._redis = redis_client
        self._prefix = key_prefix
        self._default_ttl = default_ttl
    
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session from Redis cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            data = await self._redis.get(key)
            
            if data is None:
                logger.debug(f"Session cache miss: {session_id}")
                return None
            
            logger.debug(f"Session cache hit: {session_id}")
            return json.loads(data)
            
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting session {session_id} from cache: {e}")
            return None
    
    async def store_session(
        self,
        session_id: str,
        data: dict[str, Any],
        ttl: int
    ) -> bool:
        """Store session in Redis cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            serialized_data = json.dumps(data, default=str)
            
            result = await self._redis.setex(key, ttl, serialized_data)
            
            if result:
                logger.debug(f"Session cached: {session_id} (TTL: {ttl}s)")
                return True
            logger.warning(f"Failed to cache session: {session_id}")
            return False
                
        except (RedisError, json.JSONEncodeError, TypeError) as e:
            logger.error(f"Error storing session {session_id} in cache: {e}")
            return False
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session from Redis cache."""
        try:
            key = f"{self._prefix}session:{session_id}"
            result = await self._redis.delete(key)
            
            if result > 0:
                logger.debug(f"Session deleted from cache: {session_id}")
                return True
            logger.debug(f"Session not found in cache: {session_id}")
            return False
                
        except RedisError as e:
            logger.error(f"Error deleting session {session_id} from cache: {e}")
            return False
    
    async def get_user_cache(
        self,
        user_id: UUID,
        key: str
    ) -> Any | None:
        """Get user-specific cache value."""
        try:
            cache_key = f"{self._prefix}user:{user_id}:{key}"
            data = await self._redis.get(cache_key)
            
            if data is None:
                logger.debug(f"User cache miss: {user_id}:{key}")
                return None
            
            logger.debug(f"User cache hit: {user_id}:{key}")
            return json.loads(data)
            
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error getting user cache {user_id}:{key}: {e}")
            return None
    
    async def set_user_cache(
        self,
        user_id: UUID,
        key: str,
        value: Any,
        ttl: int | None = None
    ) -> bool:
        """Set user-specific cache value."""
        try:
            cache_key = f"{self._prefix}user:{user_id}:{key}"
            serialized_value = json.dumps(value, default=str)
            ttl_seconds = ttl or self._default_ttl
            
            result = await self._redis.setex(cache_key, ttl_seconds, serialized_value)
            
            if result:
                logger.debug(f"User cache set: {user_id}:{key} (TTL: {ttl_seconds}s)")
                return True
            logger.warning(f"Failed to set user cache: {user_id}:{key}")
            return False
                
        except (RedisError, json.JSONEncodeError, TypeError) as e:
            logger.error(f"Error setting user cache {user_id}:{key}: {e}")
            return False
    
    async def invalidate_user_cache(self, user_id: UUID) -> None:
        """Invalidate all user cache entries using pattern matching."""
        try:
            pattern = f"{self._prefix}user:{user_id}:*"
            
            # Use SCAN to find matching keys (safer than KEYS in production)
            keys_to_delete = []
            async for key in self._redis.scan_iter(match=pattern, count=100):
                keys_to_delete.append(key)
            
            if keys_to_delete:
                deleted_count = await self._redis.delete(*keys_to_delete)
                logger.info(f"Invalidated {deleted_count} cache entries for user {user_id}")
            else:
                logger.debug(f"No cache entries found for user {user_id}")
                
        except RedisError as e:
            logger.error(f"Error invalidating user cache for {user_id}: {e}")
    
    async def increment_counter(
        self,
        key: str,
        amount: int = 1
    ) -> int:
        """Increment counter atomically in Redis."""
        try:
            cache_key = f"{self._prefix}counter:{key}"
            new_value = await self._redis.incrby(cache_key, amount)
            
            logger.debug(f"Counter incremented: {key} -> {new_value}")
            return new_value
            
        except RedisError as e:
            logger.error(f"Error incrementing counter {key}: {e}")
            # Return -1 to indicate error (counters should be non-negative)
            return -1
    
    async def health_check(self) -> bool:
        """Check Redis connection health."""
        try:
            await self._redis.ping()
            return True
        except RedisError:
            logger.error("Redis health check failed")
            return False
    
    async def clear_all_cache(self) -> bool:
        """Clear all cache entries with our prefix (USE WITH CAUTION)."""
        try:
            pattern = f"{self._prefix}*"
            
            keys_to_delete = []
            async for key in self._redis.scan_iter(match=pattern, count=1000):
                keys_to_delete.append(key)
            
            if keys_to_delete:
                deleted_count = await self._redis.delete(*keys_to_delete)
                logger.warning(f"Cleared {deleted_count} cache entries")
                return True
            logger.info("No cache entries to clear")
            return True
                
        except RedisError as e:
            logger.error(f"Error clearing cache: {e}")
            return False