"""
Application Cache Service Adapter

Redis-based implementation of the application layer cache service interface.
Provides general-purpose caching functionality for the application layer.
"""

import json
import pickle
from typing import Any

from redis.asyncio import Redis

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)


class ApplicationCacheAdapter(ICacheService):
    """Redis implementation of application cache service."""
    
    def __init__(self, redis_client: Redis, default_ttl: int = 3600):
        """Initialize cache adapter.
        
        Args:
            redis_client: Redis async client instance
            default_ttl: Default TTL in seconds (1 hour)
        """
        self._redis = redis_client
        self._default_ttl = default_ttl
        self._prefix = "app:cache:"
    
    async def get(self, key: str) -> Any | None:
        """Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        try:
            full_key = f"{self._prefix}{key}"
            value = await self._redis.get(full_key)
            
            if value is None:
                return None
            
            # Try to deserialize as JSON first
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                # Fall back to pickle for complex objects
                try:
                    return pickle.loads(value)
                except Exception:
                    # Return as string if all else fails
                    return value.decode('utf-8') if isinstance(value, bytes) else value
                    
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (uses default if not specified)
        """
        try:
            full_key = f"{self._prefix}{key}"
            ttl = ttl or self._default_ttl
            
            # Serialize value
            if isinstance(value, (str, int, float, bool)):
                # Simple types can be stored directly
                serialized = str(value)
            else:
                # Try JSON serialization first
                try:
                    serialized = json.dumps(value)
                except (TypeError, ValueError):
                    # Fall back to pickle for complex objects
                    serialized = pickle.dumps(value)
            
            await self._redis.setex(full_key, ttl, serialized)
            
            logger.debug(f"Cached key {key} with TTL {ttl}s")
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            # Don't raise - caching should not break the application
    
    async def delete(self, key: str) -> None:
        """Delete value from cache.
        
        Args:
            key: Cache key to delete
        """
        try:
            full_key = f"{self._prefix}{key}"
            deleted = await self._redis.delete(full_key)
            
            if deleted:
                logger.debug(f"Deleted cache key {key}")
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            # Don't raise - caching should not break the application
    
    async def clear_pattern(self, pattern: str) -> None:
        """Clear all keys matching pattern.
        
        Args:
            pattern: Pattern to match (supports Redis wildcards)
        """
        try:
            full_pattern = f"{self._prefix}{pattern}"
            
            # Use SCAN to avoid blocking on large keyspaces
            cursor = 0
            deleted_count = 0
            
            while True:
                cursor, keys = await self._redis.scan(
                    cursor, 
                    match=full_pattern,
                    count=100  # Process in batches
                )
                
                if keys:
                    deleted_count += await self._redis.delete(*keys)
                
                if cursor == 0:
                    break
            
            logger.info(f"Cleared {deleted_count} cache keys matching pattern {pattern}")
            
        except Exception as e:
            logger.error(f"Cache clear pattern error for pattern {pattern}: {e}")
            # Don't raise - caching should not break the application
    
    async def health_check(self) -> bool:
        """Check if cache is healthy and accessible.
        
        Returns:
            True if cache is accessible, False otherwise
        """
        try:
            await self._redis.ping()
            return True
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            return False
    
    async def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary containing cache statistics
        """
        try:
            info = await self._redis.info()
            
            return {
                "connected": True,
                "used_memory": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "total_commands": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "hit_rate": self._calculate_hit_rate(
                    info.get("keyspace_hits", 0),
                    info.get("keyspace_misses", 0)
                )
            }
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {
                "connected": False,
                "error": str(e)
            }
    
    def _calculate_hit_rate(self, hits: int, misses: int) -> float:
        """Calculate cache hit rate percentage.
        
        Args:
            hits: Number of cache hits
            misses: Number of cache misses
            
        Returns:
            Hit rate as percentage (0-100)
        """
        total = hits + misses
        if total == 0:
            return 0.0
        return round((hits / total) * 100, 2)