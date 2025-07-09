"""
Redis Cache Backend Implementation for EzzDay Core.

This module provides a Redis-based cache backend implementation that integrates
with the CacheCoordinator for distributed caching capabilities.

Features:
- Redis cluster support
- Connection pooling
- Automatic serialization/deserialization
- Pub/Sub for cache invalidation
- TTL support
- Atomic operations
- Pipeline support for batch operations
"""

import asyncio
import builtins
import json
import pickle
from datetime import datetime
from typing import Any

import redis.asyncio as redis
from redis.asyncio.cluster import RedisCluster
from redis.asyncio.sentinel import Sentinel
from redis.exceptions import RedisError

from app.core.infrastructure.cache_coordinator import CacheBackend, CacheEntry
from app.core.logging import get_logger

logger = get_logger(__name__)


class RedisCacheBackend(CacheBackend):
    """Redis-based cache backend implementation."""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "cache:",
        serializer: str = "json",
        max_connections: int = 50,
        socket_timeout: float = 5.0,
        socket_connect_timeout: float = 5.0,
        decode_responses: bool = False,
        health_check_interval: int = 30,
        enable_cluster_mode: bool = False,
        sentinel_hosts: list[tuple[str, int]] | None = None,
        sentinel_service_name: str | None = None,
    ):
        """
        Initialize Redis cache backend.
        
        Args:
            redis_url: Redis connection URL
            key_prefix: Prefix for all cache keys
            serializer: Serialization method ('json' or 'pickle')
            max_connections: Maximum number of connections in pool
            socket_timeout: Socket timeout in seconds
            socket_connect_timeout: Socket connection timeout in seconds
            decode_responses: Whether to decode responses
            health_check_interval: Health check interval in seconds
            enable_cluster_mode: Whether to use Redis cluster
            sentinel_hosts: List of Sentinel hosts for HA
            sentinel_service_name: Sentinel service name
        """
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._serializer = serializer
        self._max_connections = max_connections
        self._decode_responses = decode_responses
        self._health_check_interval = health_check_interval
        self._enable_cluster_mode = enable_cluster_mode
        self._sentinel_hosts = sentinel_hosts
        self._sentinel_service_name = sentinel_service_name
        
        # Connection pool options
        self._pool_options = {
            "max_connections": max_connections,
            "socket_timeout": socket_timeout,
            "socket_connect_timeout": socket_connect_timeout,
            "decode_responses": decode_responses,
            "health_check_interval": health_check_interval,
        }
        
        self._client: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None
        self._invalidation_channel = f"{key_prefix}invalidation"
        self._connected = False
        self._lock = asyncio.Lock()
        
        logger.info(
            "Redis cache backend initialized",
            redis_url=redis_url,
            key_prefix=key_prefix,
            serializer=serializer,
            cluster_mode=enable_cluster_mode
        )
    
    async def connect(self) -> None:
        """Establish connection to Redis."""
        async with self._lock:
            if self._connected:
                return
            
            try:
                if self._sentinel_hosts:
                    # Use Sentinel for high availability
                    sentinel = Sentinel(
                        self._sentinel_hosts,
                        socket_timeout=self._pool_options["socket_timeout"]
                    )
                    self._client = await sentinel.master_for(
                        self._sentinel_service_name,
                        redis_class=redis.Redis,
                        **self._pool_options
                    )
                elif self._enable_cluster_mode:
                    # Use Redis Cluster
                    self._client = await RedisCluster.from_url(
                        self._redis_url,
                        **self._pool_options
                    )
                else:
                    # Use standard Redis
                    self._client = await redis.from_url(
                        self._redis_url,
                        **self._pool_options
                    )
                
                # Test connection
                await self._client.ping()
                
                # Setup pub/sub for invalidation
                self._pubsub = self._client.pubsub()
                await self._pubsub.subscribe(self._invalidation_channel)
                
                self._connected = True
                
                logger.info("Redis connection established")
                
            except Exception as e:
                logger.error(
                    "Failed to connect to Redis",
                    error=str(e)
                )
                raise
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        async with self._lock:
            if not self._connected:
                return
            
            try:
                if self._pubsub:
                    await self._pubsub.unsubscribe(self._invalidation_channel)
                    await self._pubsub.close()
                
                if self._client:
                    await self._client.close()
                
                self._connected = False
                
                logger.info("Redis connection closed")
                
            except Exception as e:
                logger.error(
                    "Error closing Redis connection",
                    error=str(e)
                )
    
    def _make_key(self, key: str) -> str:
        """Create Redis key with prefix."""
        return f"{self._key_prefix}{key}"
    
    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage."""
        if self._serializer == "json":
            return json.dumps(value).encode("utf-8")
        if self._serializer == "pickle":
            return pickle.dumps(value)
        raise ValueError(f"Unknown serializer: {self._serializer}")
    
    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage."""
        if data is None:
            return None
        
        if self._serializer == "json":
            return json.loads(data.decode("utf-8"))
        if self._serializer == "pickle":
            return pickle.loads(data)
        raise ValueError(f"Unknown serializer: {self._serializer}")
    
    def _entry_to_dict(self, entry: CacheEntry) -> dict[str, Any]:
        """Convert cache entry to dictionary for storage."""
        return {
            "key": entry.key,
            "value": self._serialize(entry.value),
            "version": entry.version,
            "created_at": entry.created_at.isoformat(),
            "updated_at": entry.updated_at.isoformat(),
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "tags": list(entry.tags)
        }
    
    def _dict_to_entry(self, data: dict[str, Any]) -> CacheEntry:
        """Convert dictionary to cache entry."""
        return CacheEntry(
            key=data["key"],
            value=self._deserialize(data["value"]),
            version=data["version"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data["expires_at"] else None,
            tags=set(data["tags"])
        )
    
    async def get(self, key: str) -> CacheEntry | None:
        """Get cache entry by key."""
        if not self._connected:
            await self.connect()
        
        try:
            redis_key = self._make_key(key)
            data = await self._client.get(redis_key)
            
            if data is None:
                return None
            
            # Deserialize entry
            entry_dict = json.loads(data)
            entry = self._dict_to_entry(entry_dict)
            
            # Check expiration
            if entry.is_expired():
                await self._client.delete(redis_key)
                return None
            
            return entry
            
        except RedisError as e:
            logger.error(
                "Redis get operation failed",
                key=key,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to get cache entry",
                key=key,
                error=str(e)
            )
            return None
    
    async def set(self, entry: CacheEntry) -> None:
        """Set cache entry."""
        if not self._connected:
            await self.connect()
        
        try:
            redis_key = self._make_key(entry.key)
            entry_dict = self._entry_to_dict(entry)
            
            # Calculate TTL
            ttl = None
            if entry.expires_at:
                ttl_seconds = (entry.expires_at - datetime.now(datetime.UTC)).total_seconds()
                if ttl_seconds > 0:
                    ttl = int(ttl_seconds)
            
            # Store in Redis
            data = json.dumps(entry_dict)
            if ttl:
                await self._client.setex(redis_key, ttl, data)
            else:
                await self._client.set(redis_key, data)
            
            # Store tags in separate sets for efficient tag-based invalidation
            if entry.tags:
                pipeline = self._client.pipeline()
                for tag in entry.tags:
                    tag_key = f"{self._key_prefix}tag:{tag}"
                    pipeline.sadd(tag_key, entry.key)
                    if ttl:
                        pipeline.expire(tag_key, ttl)
                await pipeline.execute()
            
            # Publish invalidation event
            await self._publish_invalidation(entry.key)
            
        except RedisError as e:
            logger.error(
                "Redis set operation failed",
                key=entry.key,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to set cache entry",
                key=entry.key,
                error=str(e)
            )
            raise
    
    async def delete(self, key: str) -> bool:
        """Delete cache entry by key."""
        if not self._connected:
            await self.connect()
        
        try:
            # Get entry to clean up tags
            entry = await self.get(key)
            
            redis_key = self._make_key(key)
            result = await self._client.delete(redis_key)
            
            # Clean up tags
            if entry and entry.tags:
                pipeline = self._client.pipeline()
                for tag in entry.tags:
                    tag_key = f"{self._key_prefix}tag:{tag}"
                    pipeline.srem(tag_key, key)
                await pipeline.execute()
            
            # Publish invalidation event
            if result > 0:
                await self._publish_invalidation(key)
            
            return result > 0
            
        except RedisError as e:
            logger.error(
                "Redis delete operation failed",
                key=key,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to delete cache entry",
                key=key,
                error=str(e)
            )
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        if not self._connected:
            await self.connect()
        
        try:
            redis_key = self._make_key(key)
            return await self._client.exists(redis_key) > 0
            
        except RedisError as e:
            logger.error(
                "Redis exists operation failed",
                key=key,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to check key existence",
                key=key,
                error=str(e)
            )
            return False
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        if not self._connected:
            await self.connect()
        
        try:
            # Use SCAN to avoid blocking with KEYS
            cursor = 0
            pattern = f"{self._key_prefix}*"
            
            while True:
                cursor, keys = await self._client.scan(
                    cursor,
                    match=pattern,
                    count=1000
                )
                
                if keys:
                    await self._client.delete(*keys)
                
                if cursor == 0:
                    break
            
            # Publish bulk invalidation event
            await self._publish_invalidation("*")
            
            logger.info("Redis cache cleared")
            
        except RedisError as e:
            logger.error(
                "Redis clear operation failed",
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to clear cache",
                error=str(e)
            )
            raise
    
    async def keys(self, pattern: str | None = None) -> list[str]:
        """Get all keys matching pattern."""
        if not self._connected:
            await self.connect()
        
        try:
            # Build Redis pattern
            if pattern:
                redis_pattern = f"{self._key_prefix}{pattern}"
            else:
                redis_pattern = f"{self._key_prefix}*"
            
            # Use SCAN to avoid blocking
            all_keys = []
            cursor = 0
            
            while True:
                cursor, keys = await self._client.scan(
                    cursor,
                    match=redis_pattern,
                    count=1000
                )
                
                # Remove prefix from keys
                for key in keys:
                    if isinstance(key, bytes):
                        key = key.decode("utf-8")
                    if key.startswith(self._key_prefix):
                        all_keys.append(key[len(self._key_prefix):])
                
                if cursor == 0:
                    break
            
            return all_keys
            
        except RedisError as e:
            logger.error(
                "Redis keys operation failed",
                pattern=pattern,
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to get keys",
                pattern=pattern,
                error=str(e)
            )
            return []
    
    async def size(self) -> int:
        """Get cache size."""
        if not self._connected:
            await self.connect()
        
        try:
            # Count keys with our prefix
            count = 0
            cursor = 0
            pattern = f"{self._key_prefix}*"
            
            while True:
                cursor, keys = await self._client.scan(
                    cursor,
                    match=pattern,
                    count=1000
                )
                
                count += len(keys)
                
                if cursor == 0:
                    break
            
            return count
            
        except RedisError as e:
            logger.error(
                "Redis size operation failed",
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to get cache size",
                error=str(e)
            )
            return 0
    
    def get_backend_type(self) -> str:
        """Get backend type identifier."""
        return "redis"
    
    async def get_by_tags(self, tags: builtins.set[str]) -> list[str]:
        """Get all keys that have any of the specified tags."""
        if not self._connected:
            await self.connect()
        
        try:
            # Get union of all tag sets
            tag_keys = [f"{self._key_prefix}tag:{tag}" for tag in tags]
            
            if not tag_keys:
                return []
            
            # Use SUNION to get all keys with any of the tags
            keys = await self._client.sunion(tag_keys)
            
            return list(keys)
            
        except RedisError as e:
            logger.error(
                "Redis get_by_tags operation failed",
                tags=list(tags),
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to get keys by tags",
                tags=list(tags),
                error=str(e)
            )
            return []
    
    async def _publish_invalidation(self, key: str) -> None:
        """Publish cache invalidation event."""
        try:
            message = json.dumps({
                "action": "invalidate",
                "key": key,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            await self._client.publish(
                self._invalidation_channel,
                message
            )
            
        except Exception as e:
            logger.warning(
                "Failed to publish invalidation event",
                key=key,
                error=str(e)
            )
    
    async def batch_get(self, keys: list[str]) -> dict[str, CacheEntry | None]:
        """Get multiple cache entries in a single operation."""
        if not self._connected:
            await self.connect()
        
        try:
            # Build Redis keys
            redis_keys = [self._make_key(key) for key in keys]
            
            # Use MGET for batch retrieval
            values = await self._client.mget(redis_keys)
            
            # Process results
            result = {}
            for key, value in zip(keys, values, strict=False):
                if value is None:
                    result[key] = None
                else:
                    try:
                        entry_dict = json.loads(value)
                        entry = self._dict_to_entry(entry_dict)
                        
                        # Check expiration
                        if entry.is_expired():
                            await self._client.delete(self._make_key(key))
                            result[key] = None
                        else:
                            result[key] = entry
                    except Exception as e:
                        logger.warning(
                            "Failed to deserialize cache entry",
                            key=key,
                            error=str(e)
                        )
                        result[key] = None
            
            return result
            
        except RedisError as e:
            logger.error(
                "Redis batch_get operation failed",
                keys_count=len(keys),
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to batch get cache entries",
                keys_count=len(keys),
                error=str(e)
            )
            return dict.fromkeys(keys)
    
    async def batch_set(self, entries: list[CacheEntry]) -> None:
        """Set multiple cache entries in a single operation."""
        if not self._connected:
            await self.connect()
        
        try:
            pipeline = self._client.pipeline()
            
            for entry in entries:
                redis_key = self._make_key(entry.key)
                entry_dict = self._entry_to_dict(entry)
                data = json.dumps(entry_dict)
                
                # Calculate TTL
                ttl = None
                if entry.expires_at:
                    ttl_seconds = (entry.expires_at - datetime.now(datetime.UTC)).total_seconds()
                    if ttl_seconds > 0:
                        ttl = int(ttl_seconds)
                
                # Add to pipeline
                if ttl:
                    pipeline.setex(redis_key, ttl, data)
                else:
                    pipeline.set(redis_key, data)
                
                # Handle tags
                if entry.tags:
                    for tag in entry.tags:
                        tag_key = f"{self._key_prefix}tag:{tag}"
                        pipeline.sadd(tag_key, entry.key)
                        if ttl:
                            pipeline.expire(tag_key, ttl)
            
            # Execute pipeline
            await pipeline.execute()
            
            # Publish invalidation events
            for entry in entries:
                await self._publish_invalidation(entry.key)
            
        except RedisError as e:
            logger.error(
                "Redis batch_set operation failed",
                entries_count=len(entries),
                error=str(e)
            )
            raise
        except Exception as e:
            logger.exception(
                "Failed to batch set cache entries",
                entries_count=len(entries),
                error=str(e)
            )
            raise
    
    async def get_stats(self) -> dict[str, Any]:
        """Get Redis cache statistics."""
        if not self._connected:
            await self.connect()
        
        try:
            # Get Redis INFO
            info = await self._client.info()
            
            # Get memory stats
            memory_info = await self._client.info("memory")
            
            # Get connection pool stats
            pool_stats = {}
            if hasattr(self._client, "connection_pool"):
                pool = self._client.connection_pool
                pool_stats = {
                    "created_connections": pool.created_connections,
                    "available_connections": len(pool._available_connections),
                    "in_use_connections": len(pool._in_use_connections),
                    "max_connections": pool.max_connections,
                }
            
            return {
                "backend_type": self.get_backend_type(),
                "connected": self._connected,
                "redis_version": info.get("redis_version"),
                "used_memory": memory_info.get("used_memory"),
                "used_memory_human": memory_info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
                "total_commands_processed": info.get("total_commands_processed"),
                "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec"),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "cache_size": await self.size(),
                "connection_pool": pool_stats,
            }
            
        except Exception as e:
            logger.error(
                "Failed to get Redis stats",
                error=str(e)
            )
            return {
                "backend_type": self.get_backend_type(),
                "connected": self._connected,
                "error": str(e)
            }


__all__ = ["RedisCacheBackend"]