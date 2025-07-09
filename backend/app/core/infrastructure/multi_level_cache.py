"""
Multi-Level Cache Implementation for High-Performance Caching.

This module provides a sophisticated multi-level caching solution that combines
fast L1 memory cache with distributed L2 Redis cache for optimal performance
and scalability.

Features:
- L1 Memory Cache (fast, limited size)
- L2 Redis Cache (distributed, larger capacity)
- Write-through and write-behind strategies
- Cache warming and preloading
- Intelligent cache promotion/demotion
- Automatic failover between levels
- Performance monitoring and statistics
"""

import asyncio
import builtins
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar

from app.core.infrastructure.cache_coordinator import (
    CacheCoordinator,
    CacheEntry,
    ConsistencyLevel,
    MemoryCacheBackend,
)
from app.core.infrastructure.redis_cache_backend import RedisCacheBackend
from app.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class CacheStrategy(Enum):
    """Cache write strategy."""
    
    WRITE_THROUGH = "write_through"  # Write to all levels immediately
    WRITE_BEHIND = "write_behind"    # Write to L1, async write to L2
    WRITE_AROUND = "write_around"    # Write only to L2, bypass L1


class CacheLevel(Enum):
    """Cache levels."""
    
    L1_MEMORY = "l1_memory"
    L2_REDIS = "l2_redis"


@dataclass
class CacheConfig:
    """Multi-level cache configuration."""
    
    # L1 Memory cache settings
    l1_max_size: int = 10000
    l1_ttl_seconds: int = 300  # 5 minutes default
    
    # L2 Redis cache settings
    l2_redis_url: str = "redis://localhost:6379/0"
    l2_key_prefix: str = "mlcache:"
    l2_ttl_seconds: int = 3600  # 1 hour default
    l2_max_connections: int = 50
    
    # Cache behavior
    write_strategy: CacheStrategy = CacheStrategy.WRITE_THROUGH
    read_through: bool = True  # Populate L1 from L2 on miss
    enable_stats: bool = True
    enable_warming: bool = True
    
    # Performance tuning
    batch_size: int = 100
    async_write_delay: float = 0.1  # Delay for write-behind
    
    # Failover settings
    l2_failure_mode: str = "bypass"  # "bypass" or "error"
    l1_promotion_threshold: int = 3  # Hits before promoting to L1


@dataclass
class CacheStats:
    """Cache statistics."""
    
    l1_hits: int = 0
    l1_misses: int = 0
    l2_hits: int = 0
    l2_misses: int = 0
    
    l1_writes: int = 0
    l2_writes: int = 0
    
    l1_evictions: int = 0
    l2_evictions: int = 0
    
    promotions: int = 0  # L2 to L1
    demotions: int = 0   # L1 to L2
    
    total_operations: int = 0
    total_errors: int = 0
    
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())
    
    @property
    def l1_hit_rate(self) -> float:
        """Calculate L1 hit rate."""
        total = self.l1_hits + self.l1_misses
        return self.l1_hits / total if total > 0 else 0.0
    
    @property
    def l2_hit_rate(self) -> float:
        """Calculate L2 hit rate."""
        total = self.l2_hits + self.l2_misses
        return self.l2_hits / total if total > 0 else 0.0
    
    @property
    def overall_hit_rate(self) -> float:
        """Calculate overall hit rate."""
        hits = self.l1_hits + self.l2_hits
        total = hits + self.l2_misses
        return hits / total if total > 0 else 0.0


class MultiLevelCache:
    """
    Multi-level cache implementation with L1 memory and L2 Redis.
    
    Provides high-performance caching with automatic level management,
    intelligent promotion/demotion, and comprehensive statistics.
    """
    
    def __init__(self, config: CacheConfig | None = None):
        """
        Initialize multi-level cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config or CacheConfig()
        
        # Initialize cache coordinator
        self.coordinator = CacheCoordinator(
            consistency_level=ConsistencyLevel.EVENTUAL
        )
        
        # Initialize L1 memory cache
        self._l1_cache = MemoryCacheBackend(
            max_size=self.config.l1_max_size
        )
        self.coordinator.add_cache_layer("l1_memory", self._l1_cache)
        
        # Initialize L2 Redis cache
        self._l2_cache = RedisCacheBackend(
            redis_url=self.config.l2_redis_url,
            key_prefix=self.config.l2_key_prefix,
            max_connections=self.config.l2_max_connections
        )
        self.coordinator.add_cache_layer("l2_redis", self._l2_cache)
        
        # Statistics
        self._stats = CacheStats() if self.config.enable_stats else None
        
        # Access tracking for promotion
        self._access_counts: dict[str, int] = {}
        self._access_lock = asyncio.Lock()
        
        # Write-behind queue
        self._write_queue: list[CacheEntry] = []
        self._write_task: asyncio.Task | None = None
        
        # Warming cache
        self._warm_keys: set[str] = set()
        
        logger.info(
            "Multi-level cache initialized",
            config=self.config
        )
    
    async def start(self) -> None:
        """Start cache services."""
        # Connect to Redis
        await self._l2_cache.connect()
        
        # Start write-behind task if needed
        if self.config.write_strategy == CacheStrategy.WRITE_BEHIND:
            self._write_task = asyncio.create_task(self._write_behind_worker())
        
        logger.info("Multi-level cache started")
    
    async def stop(self) -> None:
        """Stop cache services."""
        # Stop write-behind task
        if self._write_task:
            self._write_task.cancel()
            try:
                await self._write_task
            except asyncio.CancelledError:
                pass
        
        # Flush any pending writes
        if self._write_queue:
            await self._flush_write_queue()
        
        # Disconnect from Redis
        await self._l2_cache.disconnect()
        
        logger.info("Multi-level cache stopped")
    
    async def get(
        self,
        key: str,
        fetch_func: Callable[[], Any] | None = None,
        ttl: int | None = None,
        tags: set[str] | None = None
    ) -> Any | None:
        """
        Get value from cache with automatic level management.
        
        Args:
            key: Cache key
            fetch_func: Optional function to fetch value if not cached
            ttl: Optional TTL override
            tags: Optional tags for the entry
            
        Returns:
            Cached value or None
        """
        start_time = time.time()
        
        try:
            # Try L1 first
            entry = await self._l1_cache.get(key)
            if entry and not entry.is_expired():
                self._record_hit(CacheLevel.L1_MEMORY)
                await self._track_access(key)
                return entry.value
            
            self._record_miss(CacheLevel.L1_MEMORY)
            
            # Try L2
            try:
                entry = await self._l2_cache.get(key)
                if entry and not entry.is_expired():
                    self._record_hit(CacheLevel.L2_REDIS)
                    
                    # Promote to L1 if read-through enabled
                    if self.config.read_through:
                        await self._promote_to_l1(entry)
                    
                    await self._track_access(key)
                    return entry.value
            except Exception as e:
                logger.warning(
                    "L2 cache read failed",
                    key=key,
                    error=str(e)
                )
                if self.config.l2_failure_mode == "error":
                    raise
            
            self._record_miss(CacheLevel.L2_REDIS)
            
            # Fetch if function provided
            if fetch_func:
                value = await self._fetch_and_cache(
                    key, fetch_func, ttl, tags
                )
                return value
            
            return None
            
        finally:
            self._record_operation_time(time.time() - start_time)
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
        tags: set[str] | None = None,
        skip_l1: bool = False
    ) -> None:
        """
        Set value in cache with configured write strategy.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Optional TTL override
            tags: Optional tags for the entry
            skip_l1: Whether to skip L1 cache
        """
        start_time = time.time()
        
        try:
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                version=int(time.time() * 1000000),
                expires_at=datetime.utcnow() + timedelta(seconds=ttl or self.config.l1_ttl_seconds),
                tags=tags or set()
            )
            
            # Handle write strategy
            if self.config.write_strategy == CacheStrategy.WRITE_THROUGH:
                await self._write_through(entry, skip_l1)
            elif self.config.write_strategy == CacheStrategy.WRITE_BEHIND:
                await self._write_behind(entry, skip_l1)
            elif self.config.write_strategy == CacheStrategy.WRITE_AROUND:
                await self._write_around(entry)
            
            # Track warm keys
            if self.config.enable_warming and key in self._warm_keys:
                self._warm_keys.add(key)
            
        finally:
            self._record_operation_time(time.time() - start_time)
    
    async def delete(self, key: str) -> bool:
        """Delete value from all cache levels."""
        deleted = False
        
        # Delete from L1
        try:
            if await self._l1_cache.delete(key):
                deleted = True
        except Exception as e:
            logger.warning(
                "L1 cache delete failed",
                key=key,
                error=str(e)
            )
        
        # Delete from L2
        try:
            if await self._l2_cache.delete(key):
                deleted = True
        except Exception as e:
            logger.warning(
                "L2 cache delete failed",
                key=key,
                error=str(e)
            )
            if self.config.l2_failure_mode == "error":
                raise
        
        # Remove from access tracking
        async with self._access_lock:
            self._access_counts.pop(key, None)
        
        return deleted
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all entries matching pattern."""
        total_invalidated = 0
        
        # Invalidate in L1
        try:
            l1_keys = await self._l1_cache.keys(pattern)
            for key in l1_keys:
                if await self._l1_cache.delete(key):
                    total_invalidated += 1
        except Exception as e:
            logger.warning(
                "L1 pattern invalidation failed",
                pattern=pattern,
                error=str(e)
            )
        
        # Invalidate in L2
        try:
            l2_keys = await self._l2_cache.keys(pattern)
            for key in l2_keys:
                if await self._l2_cache.delete(key):
                    total_invalidated += 1
        except Exception as e:
            logger.warning(
                "L2 pattern invalidation failed",
                pattern=pattern,
                error=str(e)
            )
            if self.config.l2_failure_mode == "error":
                raise
        
        return total_invalidated
    
    async def invalidate_by_tags(self, tags: builtins.set[str]) -> int:
        """Invalidate all entries with specified tags."""
        return await self.coordinator.invalidate_by_tags(tags)
    
    async def warm_cache(self, keys: list[str]) -> None:
        """
        Pre-warm cache with specified keys.
        
        Args:
            keys: List of keys to warm
        """
        if not self.config.enable_warming:
            return
        
        logger.info(
            "Starting cache warming",
            keys_count=len(keys)
        )
        
        # Add to warm keys set
        self._warm_keys.update(keys)
        
        # Batch get from L2
        try:
            entries = await self._l2_cache.batch_get(keys)
            
            # Promote to L1
            valid_entries = []
            for key, entry in entries.items():
                if entry and not entry.is_expired():
                    valid_entries.append(entry)
            
            if valid_entries:
                for entry in valid_entries:
                    await self._l1_cache.set(entry)
            
            logger.info(
                "Cache warming completed",
                warmed_count=len(valid_entries),
                total_keys=len(keys)
            )
            
        except Exception as e:
            logger.error(
                "Cache warming failed",
                error=str(e)
            )
    
    async def get_stats(self) -> dict[str, Any]:
        """Get comprehensive cache statistics."""
        stats = {
            "config": {
                "l1_max_size": self.config.l1_max_size,
                "l2_key_prefix": self.config.l2_key_prefix,
                "write_strategy": self.config.write_strategy.value,
                "read_through": self.config.read_through,
            }
        }
        
        # Add performance stats
        if self._stats:
            stats["performance"] = {
                "l1_hits": self._stats.l1_hits,
                "l1_misses": self._stats.l1_misses,
                "l1_hit_rate": self._stats.l1_hit_rate,
                "l2_hits": self._stats.l2_hits,
                "l2_misses": self._stats.l2_misses,
                "l2_hit_rate": self._stats.l2_hit_rate,
                "overall_hit_rate": self._stats.overall_hit_rate,
                "total_operations": self._stats.total_operations,
                "total_errors": self._stats.total_errors,
                "promotions": self._stats.promotions,
                "demotions": self._stats.demotions,
                "uptime_seconds": (datetime.utcnow() - self._stats.created_at).total_seconds()
            }
        
        # Add cache sizes
        try:
            stats["sizes"] = {
                "l1_size": await self._l1_cache.size(),
                "l2_size": await self._l2_cache.size(),
                "write_queue_size": len(self._write_queue),
                "warm_keys_count": len(self._warm_keys)
            }
        except Exception as e:
            logger.warning(
                "Failed to get cache sizes",
                error=str(e)
            )
        
        # Add Redis stats
        try:
            stats["redis"] = await self._l2_cache.get_stats()
        except Exception as e:
            logger.warning(
                "Failed to get Redis stats",
                error=str(e)
            )
        
        return stats
    
    async def clear_all(self) -> None:
        """Clear all cache levels."""
        await self.coordinator.clear_all()
        
        # Clear tracking data
        async with self._access_lock:
            self._access_counts.clear()
        self._warm_keys.clear()
        
        logger.info("All cache levels cleared")
    
    # Private helper methods
    
    async def _fetch_and_cache(
        self,
        key: str,
        fetch_func: Callable[[], Any],
        ttl: int | None,
        tags: builtins.set[str] | None
    ) -> Any:
        """Fetch value and cache it."""
        try:
            # Fetch value
            if asyncio.iscoroutinefunction(fetch_func):
                value = await fetch_func()
            else:
                value = fetch_func()
            
            # Cache the value
            await self.set(key, value, ttl=ttl, tags=tags)
            
            return value
            
        except Exception as e:
            logger.exception(
                "Failed to fetch and cache value",
                key=key,
                error=str(e)
            )
            raise
    
    async def _write_through(self, entry: CacheEntry, skip_l1: bool) -> None:
        """Write-through strategy: write to all levels immediately."""
        errors = []
        
        # Write to L1
        if not skip_l1:
            try:
                await self._l1_cache.set(entry)
                self._record_write(CacheLevel.L1_MEMORY)
            except Exception as e:
                errors.append(("L1", str(e)))
        
        # Write to L2
        try:
            # Adjust TTL for L2
            l2_entry = CacheEntry(
                key=entry.key,
                value=entry.value,
                version=entry.version,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                expires_at=datetime.utcnow() + timedelta(seconds=self.config.l2_ttl_seconds),
                tags=entry.tags
            )
            await self._l2_cache.set(l2_entry)
            self._record_write(CacheLevel.L2_REDIS)
        except Exception as e:
            errors.append(("L2", str(e)))
            if self.config.l2_failure_mode == "error":
                raise
        
        if errors:
            logger.warning(
                "Write-through completed with errors",
                key=entry.key,
                errors=errors
            )
    
    async def _write_behind(self, entry: CacheEntry, skip_l1: bool) -> None:
        """Write-behind strategy: write to L1 immediately, L2 asynchronously."""
        # Write to L1 immediately
        if not skip_l1:
            try:
                await self._l1_cache.set(entry)
                self._record_write(CacheLevel.L1_MEMORY)
            except Exception as e:
                logger.error(
                    "L1 write failed in write-behind",
                    key=entry.key,
                    error=str(e)
                )
                raise
        
        # Queue for async L2 write
        self._write_queue.append(entry)
    
    async def _write_around(self, entry: CacheEntry) -> None:
        """Write-around strategy: write only to L2, bypass L1."""
        try:
            # Adjust TTL for L2
            l2_entry = CacheEntry(
                key=entry.key,
                value=entry.value,
                version=entry.version,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                expires_at=datetime.utcnow() + timedelta(seconds=self.config.l2_ttl_seconds),
                tags=entry.tags
            )
            await self._l2_cache.set(l2_entry)
            self._record_write(CacheLevel.L2_REDIS)
        except Exception as e:
            logger.error(
                "L2 write failed in write-around",
                key=entry.key,
                error=str(e)
            )
            if self.config.l2_failure_mode == "error":
                raise
    
    async def _write_behind_worker(self) -> None:
        """Background worker for write-behind strategy."""
        while True:
            try:
                await asyncio.sleep(self.config.async_write_delay)
                
                if self._write_queue:
                    await self._flush_write_queue()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Write-behind worker error",
                    error=str(e)
                )
    
    async def _flush_write_queue(self) -> None:
        """Flush pending writes to L2."""
        if not self._write_queue:
            return
        
        # Get entries to write
        entries_to_write = self._write_queue[:self.config.batch_size]
        self._write_queue = self._write_queue[self.config.batch_size:]
        
        # Adjust TTLs for L2
        l2_entries = []
        for entry in entries_to_write:
            l2_entry = CacheEntry(
                key=entry.key,
                value=entry.value,
                version=entry.version,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                expires_at=datetime.utcnow() + timedelta(seconds=self.config.l2_ttl_seconds),
                tags=entry.tags
            )
            l2_entries.append(l2_entry)
        
        # Batch write to L2
        try:
            await self._l2_cache.batch_set(l2_entries)
            
            for _ in l2_entries:
                self._record_write(CacheLevel.L2_REDIS)
            
            logger.debug(
                "Flushed write queue to L2",
                entries_count=len(l2_entries)
            )
            
        except Exception as e:
            logger.error(
                "Failed to flush write queue",
                entries_count=len(l2_entries),
                error=str(e)
            )
            if self.config.l2_failure_mode == "error":
                raise
    
    async def _promote_to_l1(self, entry: CacheEntry) -> None:
        """Promote entry from L2 to L1."""
        try:
            # Adjust TTL for L1
            l1_entry = CacheEntry(
                key=entry.key,
                value=entry.value,
                version=entry.version,
                created_at=entry.created_at,
                updated_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(seconds=self.config.l1_ttl_seconds),
                tags=entry.tags
            )
            
            await self._l1_cache.set(l1_entry)
            
            if self._stats:
                self._stats.promotions += 1
            
            logger.debug(
                "Entry promoted to L1",
                key=entry.key
            )
            
        except Exception as e:
            logger.warning(
                "Failed to promote entry to L1",
                key=entry.key,
                error=str(e)
            )
    
    async def _track_access(self, key: str) -> None:
        """Track key access for promotion decisions."""
        if not self.config.read_through:
            return
        
        async with self._access_lock:
            self._access_counts[key] = self._access_counts.get(key, 0) + 1
            
            # Check if should promote
            if self._access_counts[key] >= self.config.l1_promotion_threshold:
                # Reset counter
                self._access_counts[key] = 0
                
                # Check if in L1
                if not await self._l1_cache.exists(key):
                    # Get from L2 and promote
                    entry = await self._l2_cache.get(key)
                    if entry:
                        await self._promote_to_l1(entry)
    
    def _record_hit(self, level: CacheLevel) -> None:
        """Record cache hit."""
        if not self._stats:
            return
        
        if level == CacheLevel.L1_MEMORY:
            self._stats.l1_hits += 1
        else:
            self._stats.l2_hits += 1
    
    def _record_miss(self, level: CacheLevel) -> None:
        """Record cache miss."""
        if not self._stats:
            return
        
        if level == CacheLevel.L1_MEMORY:
            self._stats.l1_misses += 1
        else:
            self._stats.l2_misses += 1
    
    def _record_write(self, level: CacheLevel) -> None:
        """Record cache write."""
        if not self._stats:
            return
        
        if level == CacheLevel.L1_MEMORY:
            self._stats.l1_writes += 1
        else:
            self._stats.l2_writes += 1
    
    def _record_operation_time(self, duration: float) -> None:
        """Record operation time."""
        if not self._stats:
            return
        
        self._stats.total_operations += 1


__all__ = ["CacheConfig", "CacheLevel", "CacheStats", "CacheStrategy", "MultiLevelCache"]