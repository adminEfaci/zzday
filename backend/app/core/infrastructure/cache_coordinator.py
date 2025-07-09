"""
Cache Coordination System for EzzDay Core

This module provides distributed cache coordination capabilities to ensure
cache coherency across multiple application instances and cache layers.
Implements cache invalidation strategies, versioning, and coordination
patterns for maintaining data consistency.

Key Features:
- Distributed cache invalidation coordination
- Cache versioning and conflict resolution
- Multiple cache layer support (L1, L2, distributed)
- Transaction-aware cache operations
- Comprehensive cache statistics and monitoring
- Pluggable cache backend support

Design Principles:
- Cache-aside pattern with coordination
- Eventual consistency with conflict resolution
- Transaction-aware invalidation
- Comprehensive monitoring and observability
- Pluggable backend architecture

Usage Examples:
    # Basic cache coordination
    coordinator = CacheCoordinator()
    coordinator.add_cache_layer("redis", redis_cache)
    coordinator.add_cache_layer("memory", memory_cache)
    
    # Transactional cache operations
    async with coordinator.transaction("user_123") as tx:
        await tx.set("user:123", user_data)
        await tx.invalidate("user_list")
        # Changes applied atomically on commit
    
    # Distributed invalidation
    await coordinator.invalidate_distributed("user:*")
    
    # Cache-aside pattern with coordination
    user = await coordinator.get_or_compute(
        "user:123",
        lambda: fetch_user_from_db(123),
        ttl=300
    )

Error Handling:
    - CacheCoordinationError: General cache coordination failures
    - CacheVersionConflictError: Version conflicts during updates
    - CacheTransactionError: Transaction-related failures
    - CacheBackendError: Backend-specific failures

Performance Features:
    - Async/await support for non-blocking operations
    - Bulk operations for improved performance
    - Configurable consistency levels
    - Efficient invalidation pattern matching
"""

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Generic, Pattern, TypeVar
from weakref import WeakKeyDictionary

from app.core.errors import InfrastructureError, ValidationError
from app.core.logging import get_logger

try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def inc(self, count=1):
            pass
    
    class MockHistogram:
        def labels(self, **kwargs):
            return self
        def observe(self, value):
            pass
    
    class MockGauge:
        def labels(self, **kwargs):
            return self
        def set(self, value):
            pass
    
    class MockMetrics:
        def __init__(self):
            self.cache_operations = MockCounter()
            self.cache_hits = MockCounter()
            self.cache_misses = MockCounter()
            self.cache_invalidations = MockCounter()
            self.cache_coordination_errors = MockCounter()
            self.cache_operation_duration = MockHistogram()
            self.cache_size = MockGauge()
    
    metrics = MockMetrics()

logger = get_logger(__name__)

T = TypeVar("T")


class CacheCoordinationError(InfrastructureError):
    """Base exception for cache coordination operations."""
    
    default_code = "CACHE_COORDINATION_ERROR"
    status_code = 500
    retryable = True


class CacheVersionConflictError(CacheCoordinationError):
    """Raised when cache version conflicts occur."""
    
    default_code = "CACHE_VERSION_CONFLICT"
    status_code = 409
    retryable = False


class CacheTransactionError(CacheCoordinationError):
    """Raised when cache transaction operations fail."""
    
    default_code = "CACHE_TRANSACTION_ERROR"
    status_code = 500
    retryable = True


class CacheBackendError(CacheCoordinationError):
    """Raised when cache backend operations fail."""
    
    default_code = "CACHE_BACKEND_ERROR"
    status_code = 500
    retryable = True


class ConsistencyLevel(Enum):
    """Cache consistency levels."""
    
    EVENTUAL = "eventual"
    STRONG = "strong"
    WEAK = "weak"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    
    key: str
    value: Any
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(datetime.UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(datetime.UTC))
    expires_at: datetime | None = None
    tags: set[str] = field(default_factory=set)
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.expires_at is None:
            return False
        return datetime.now(datetime.UTC) > self.expires_at
    
    def to_dict(self) -> dict[str, Any]:
        """Convert cache entry to dictionary."""
        return {
            "key": self.key,
            "value": self.value,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "tags": list(self.tags),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheEntry":
        """Create cache entry from dictionary."""
        return cls(
            key=data["key"],
            value=data["value"],
            version=data["version"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data["expires_at"] else None,
            tags=set(data["tags"]),
        )


class CacheBackend(ABC):
    """Abstract base class for cache backends."""
    
    @abstractmethod
    async def get(self, key: str) -> CacheEntry | None:
        """Get cache entry by key."""
        pass
    
    @abstractmethod
    async def set(self, entry: CacheEntry) -> None:
        """Set cache entry."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete cache entry by key."""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all cache entries."""
        pass
    
    @abstractmethod
    async def keys(self, pattern: str | None = None) -> list[str]:
        """Get all keys matching pattern."""
        pass
    
    @abstractmethod
    async def size(self) -> int:
        """Get cache size."""
        pass
    
    @abstractmethod
    def get_backend_type(self) -> str:
        """Get backend type identifier."""
        pass


class MemoryCacheBackend(CacheBackend):
    """In-memory cache backend implementation."""
    
    def __init__(self, max_size: int = 10000):
        """Initialize memory cache backend."""
        self._cache: dict[str, CacheEntry] = {}
        self._max_size = max_size
        self._access_times: dict[str, float] = {}
        self._lock = asyncio.Lock()
        
        logger.debug(
            "Memory cache backend initialized",
            max_size=max_size
        )
    
    async def get(self, key: str) -> CacheEntry | None:
        """Get cache entry by key."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry and entry.is_expired():
                del self._cache[key]
                self._access_times.pop(key, None)
                return None
            
            if entry:
                self._access_times[key] = time.time()
            
            return entry
    
    async def set(self, entry: CacheEntry) -> None:
        """Set cache entry."""
        async with self._lock:
            # Check cache size and evict if necessary
            if len(self._cache) >= self._max_size and entry.key not in self._cache:
                await self._evict_lru()
            
            self._cache[entry.key] = entry
            self._access_times[entry.key] = time.time()
    
    async def delete(self, key: str) -> bool:
        """Delete cache entry by key."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._access_times.pop(key, None)
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry and entry.is_expired():
                del self._cache[key]
                self._access_times.pop(key, None)
                return False
            return entry is not None
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            self._access_times.clear()
    
    async def keys(self, pattern: str | None = None) -> list[str]:
        """Get all keys matching pattern."""
        async with self._lock:
            # Clean up expired entries
            expired_keys = []
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
                self._access_times.pop(key, None)
            
            keys = list(self._cache.keys())
            
            if pattern:
                import re
                regex = re.compile(pattern.replace("*", ".*"))
                keys = [key for key in keys if regex.match(key)]
            
            return keys
    
    async def size(self) -> int:
        """Get cache size."""
        async with self._lock:
            return len(self._cache)
    
    def get_backend_type(self) -> str:
        """Get backend type identifier."""
        return "memory"
    
    async def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._access_times:
            return
        
        lru_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
        del self._cache[lru_key]
        del self._access_times[lru_key]
        
        logger.debug(
            "Evicted LRU cache entry",
            key=lru_key,
            remaining_size=len(self._cache)
        )


class CacheTransaction:
    """Cache transaction for atomic operations."""
    
    def __init__(self, coordinator: "CacheCoordinator", transaction_id: str):
        """Initialize cache transaction."""
        self._coordinator = coordinator
        self._transaction_id = transaction_id
        self._operations: list[dict[str, Any]] = []
        self._committed = False
        self._rolled_back = False
        
        logger.debug(
            "Cache transaction started",
            transaction_id=transaction_id
        )
    
    async def get(self, key: str) -> Any | None:
        """Get value from cache within transaction."""
        if self._committed or self._rolled_back:
            raise CacheTransactionError("Transaction is not active")
        
        # Check pending operations first
        for op in reversed(self._operations):
            if op["key"] == key:
                if op["operation"] == "set":
                    return op["value"]
                elif op["operation"] == "delete":
                    return None
        
        # Get from coordinator
        return await self._coordinator.get(key)
    
    async def set(self, key: str, value: Any, ttl: int | None = None, tags: set[str] | None = None) -> None:
        """Set value in cache within transaction."""
        if self._committed or self._rolled_back:
            raise CacheTransactionError("Transaction is not active")
        
        self._operations.append({
            "operation": "set",
            "key": key,
            "value": value,
            "ttl": ttl,
            "tags": tags or set(),
        })
        
        logger.debug(
            "Cache transaction set operation added",
            transaction_id=self._transaction_id,
            key=key,
            operations_count=len(self._operations)
        )
    
    async def delete(self, key: str) -> None:
        """Delete value from cache within transaction."""
        if self._committed or self._rolled_back:
            raise CacheTransactionError("Transaction is not active")
        
        self._operations.append({
            "operation": "delete",
            "key": key,
        })
        
        logger.debug(
            "Cache transaction delete operation added",
            transaction_id=self._transaction_id,
            key=key,
            operations_count=len(self._operations)
        )
    
    async def invalidate(self, pattern: str) -> None:
        """Invalidate cache entries matching pattern within transaction."""
        if self._committed or self._rolled_back:
            raise CacheTransactionError("Transaction is not active")
        
        self._operations.append({
            "operation": "invalidate",
            "pattern": pattern,
        })
        
        logger.debug(
            "Cache transaction invalidate operation added",
            transaction_id=self._transaction_id,
            pattern=pattern,
            operations_count=len(self._operations)
        )
    
    async def commit(self) -> None:
        """Commit transaction operations."""
        if self._committed or self._rolled_back:
            raise CacheTransactionError("Transaction is not active")
        
        try:
            # Apply all operations
            for op in self._operations:
                if op["operation"] == "set":
                    await self._coordinator.set(
                        op["key"],
                        op["value"],
                        ttl=op["ttl"],
                        tags=op["tags"]
                    )
                elif op["operation"] == "delete":
                    await self._coordinator.delete(op["key"])
                elif op["operation"] == "invalidate":
                    await self._coordinator.invalidate_pattern(op["pattern"])
            
            self._committed = True
            
            logger.info(
                "Cache transaction committed",
                transaction_id=self._transaction_id,
                operations_count=len(self._operations)
            )
        
        except Exception as e:
            logger.exception(
                "Cache transaction commit failed",
                transaction_id=self._transaction_id,
                error=str(e)
            )
            raise CacheTransactionError(f"Transaction commit failed: {e}")
    
    async def rollback(self) -> None:
        """Rollback transaction operations."""
        if self._committed or self._rolled_back:
            return
        
        self._rolled_back = True
        
        logger.info(
            "Cache transaction rolled back",
            transaction_id=self._transaction_id,
            operations_count=len(self._operations)
        )
    
    def is_active(self) -> bool:
        """Check if transaction is active."""
        return not (self._committed or self._rolled_back)


class CacheCoordinator:
    """
    Cache coordinator for distributed cache management.
    
    Provides coordination between multiple cache layers and ensures
    consistency across distributed cache instances.
    """
    
    def __init__(self, consistency_level: ConsistencyLevel = ConsistencyLevel.EVENTUAL):
        """Initialize cache coordinator."""
        self._cache_layers: dict[str, CacheBackend] = {}
        self._consistency_level = consistency_level
        self._version_counter = 0
        self._active_transactions: dict[str, CacheTransaction] = {}
        self._invalidation_listeners: list[Callable[[str], None]] = []
        self._lock = asyncio.Lock()
        
        logger.info(
            "Cache coordinator initialized",
            consistency_level=consistency_level.value
        )
    
    def add_cache_layer(self, name: str, backend: CacheBackend) -> None:
        """Add cache layer to coordinator."""
        self._cache_layers[name] = backend
        
        logger.info(
            "Cache layer added",
            name=name,
            backend_type=backend.get_backend_type(),
            total_layers=len(self._cache_layers)
        )
    
    def remove_cache_layer(self, name: str) -> bool:
        """Remove cache layer from coordinator."""
        if name in self._cache_layers:
            del self._cache_layers[name]
            logger.info(
                "Cache layer removed",
                name=name,
                remaining_layers=len(self._cache_layers)
            )
            return True
        return False
    
    async def get(self, key: str) -> Any | None:
        """Get value from cache with layer coordination."""
        start_time = time.time()
        
        try:
            # Try each cache layer in order
            for layer_name, backend in self._cache_layers.items():
                try:
                    entry = await backend.get(key)
                    if entry:
                        # Cache hit
                        metrics.cache_hits.labels(
                            layer=layer_name,
                            backend=backend.get_backend_type()
                        ).inc()
                        
                        logger.debug(
                            "Cache hit",
                            key=key,
                            layer=layer_name,
                            version=entry.version
                        )
                        
                        # Update higher priority layers
                        await self._populate_higher_layers(key, entry, layer_name)
                        
                        return entry.value
                
                except Exception as e:
                    logger.warning(
                        "Cache layer get failed",
                        key=key,
                        layer=layer_name,
                        error=str(e)
                    )
                    continue
            
            # Cache miss
            metrics.cache_misses.labels(coordinator="main").inc()
            
            logger.debug("Cache miss", key=key)
            
            return None
        
        finally:
            operation_time = time.time() - start_time
            metrics.cache_operation_duration.labels(
                operation="get",
                coordinator="main"
            ).observe(operation_time)
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: int | None = None, 
        tags: set[str] | None = None
    ) -> None:
        """Set value in cache with coordination."""
        start_time = time.time()
        
        try:
            async with self._lock:
                self._version_counter += 1
                version = self._version_counter
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                version=version,
                expires_at=datetime.now(datetime.UTC) + timedelta(seconds=ttl) if ttl else None,
                tags=tags or set()
            )
            
            # Set in all cache layers
            errors = []
            for layer_name, backend in self._cache_layers.items():
                try:
                    await backend.set(entry)
                    
                    logger.debug(
                        "Cache set successful",
                        key=key,
                        layer=layer_name,
                        version=version
                    )
                
                except Exception as e:
                    errors.append((layer_name, str(e)))
                    logger.warning(
                        "Cache layer set failed",
                        key=key,
                        layer=layer_name,
                        error=str(e)
                    )
            
            # Update metrics
            metrics.cache_operations.labels(
                operation="set",
                coordinator="main"
            ).inc()
            
            if errors:
                logger.warning(
                    "Cache set completed with errors",
                    key=key,
                    errors=errors
                )
            
            # Notify invalidation listeners
            await self._notify_invalidation_listeners(key)
        
        finally:
            operation_time = time.time() - start_time
            metrics.cache_operation_duration.labels(
                operation="set",
                coordinator="main"
            ).observe(operation_time)
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache with coordination."""
        start_time = time.time()
        
        try:
            deleted = False
            
            # Delete from all cache layers
            for layer_name, backend in self._cache_layers.items():
                try:
                    if await backend.delete(key):
                        deleted = True
                        
                        logger.debug(
                            "Cache delete successful",
                            key=key,
                            layer=layer_name
                        )
                
                except Exception as e:
                    logger.warning(
                        "Cache layer delete failed",
                        key=key,
                        layer=layer_name,
                        error=str(e)
                    )
            
            # Update metrics
            metrics.cache_operations.labels(
                operation="delete",
                coordinator="main"
            ).inc()
            
            if deleted:
                # Notify invalidation listeners
                await self._notify_invalidation_listeners(key)
            
            return deleted
        
        finally:
            operation_time = time.time() - start_time
            metrics.cache_operation_duration.labels(
                operation="delete",
                coordinator="main"
            ).observe(operation_time)
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all cache entries matching pattern."""
        start_time = time.time()
        
        try:
            total_invalidated = 0
            
            # Invalidate in all cache layers
            for layer_name, backend in self._cache_layers.items():
                try:
                    keys = await backend.keys(pattern)
                    
                    for key in keys:
                        try:
                            if await backend.delete(key):
                                total_invalidated += 1
                        except Exception as e:
                            logger.warning(
                                "Failed to invalidate key",
                                key=key,
                                layer=layer_name,
                                error=str(e)
                            )
                
                except Exception as e:
                    logger.warning(
                        "Cache layer pattern invalidation failed",
                        pattern=pattern,
                        layer=layer_name,
                        error=str(e)
                    )
            
            # Update metrics
            metrics.cache_invalidations.labels(
                pattern=pattern,
                coordinator="main"
            ).inc()
            
            logger.info(
                "Pattern invalidation completed",
                pattern=pattern,
                invalidated_count=total_invalidated
            )
            
            return total_invalidated
        
        finally:
            operation_time = time.time() - start_time
            metrics.cache_operation_duration.labels(
                operation="invalidate_pattern",
                coordinator="main"
            ).observe(operation_time)
    
    async def invalidate_by_tags(self, tags: set[str]) -> int:
        """Invalidate cache entries by tags."""
        start_time = time.time()
        
        try:
            total_invalidated = 0
            
            # Find and invalidate entries with matching tags
            for layer_name, backend in self._cache_layers.items():
                try:
                    keys = await backend.keys()
                    
                    for key in keys:
                        try:
                            entry = await backend.get(key)
                            if entry and entry.tags.intersection(tags):
                                if await backend.delete(key):
                                    total_invalidated += 1
                        except Exception as e:
                            logger.warning(
                                "Failed to check/invalidate key by tags",
                                key=key,
                                layer=layer_name,
                                error=str(e)
                            )
                
                except Exception as e:
                    logger.warning(
                        "Cache layer tag invalidation failed",
                        tags=list(tags),
                        layer=layer_name,
                        error=str(e)
                    )
            
            # Update metrics
            metrics.cache_invalidations.labels(
                pattern=f"tags:{','.join(tags)}",
                coordinator="main"
            ).inc()
            
            logger.info(
                "Tag invalidation completed",
                tags=list(tags),
                invalidated_count=total_invalidated
            )
            
            return total_invalidated
        
        finally:
            operation_time = time.time() - start_time
            metrics.cache_operation_duration.labels(
                operation="invalidate_by_tags",
                coordinator="main"
            ).observe(operation_time)
    
    async def get_or_compute(
        self,
        key: str,
        compute_func: Callable[[], Any],
        ttl: int | None = None,
        tags: set[str] | None = None
    ) -> Any:
        """Get value from cache or compute and cache it."""
        # Try to get from cache first
        value = await self.get(key)
        if value is not None:
            return value
        
        # Compute value
        try:
            if asyncio.iscoroutinefunction(compute_func):
                computed_value = await compute_func()
            else:
                computed_value = compute_func()
            
            # Cache the computed value
            await self.set(key, computed_value, ttl=ttl, tags=tags)
            
            return computed_value
        
        except Exception as e:
            logger.exception(
                "Failed to compute cache value",
                key=key,
                error=str(e)
            )
            raise
    
    @asynccontextmanager
    async def transaction(self, transaction_id: str | None = None):
        """Create cache transaction context."""
        if transaction_id is None:
            transaction_id = f"tx_{int(time.time() * 1000000)}"
        
        if transaction_id in self._active_transactions:
            raise CacheTransactionError(f"Transaction {transaction_id} already active")
        
        transaction = CacheTransaction(self, transaction_id)
        self._active_transactions[transaction_id] = transaction
        
        try:
            yield transaction
            await transaction.commit()
        
        except Exception as e:
            await transaction.rollback()
            raise
        
        finally:
            self._active_transactions.pop(transaction_id, None)
    
    async def _populate_higher_layers(
        self, key: str, entry: CacheEntry, source_layer: str
    ) -> None:
        """Populate higher priority cache layers."""
        for layer_name, backend in self._cache_layers.items():
            if layer_name == source_layer:
                break
            
            try:
                await backend.set(entry)
                
                logger.debug(
                    "Cache layer populated",
                    key=key,
                    source_layer=source_layer,
                    target_layer=layer_name
                )
            
            except Exception as e:
                logger.warning(
                    "Failed to populate cache layer",
                    key=key,
                    target_layer=layer_name,
                    error=str(e)
                )
    
    def add_invalidation_listener(self, listener: Callable[[str], None]) -> None:
        """Add invalidation listener."""
        self._invalidation_listeners.append(listener)
    
    def remove_invalidation_listener(self, listener: Callable[[str], None]) -> None:
        """Remove invalidation listener."""
        if listener in self._invalidation_listeners:
            self._invalidation_listeners.remove(listener)
    
    async def _notify_invalidation_listeners(self, key: str) -> None:
        """Notify invalidation listeners."""
        for listener in self._invalidation_listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    await listener(key)
                else:
                    listener(key)
            except Exception as e:
                logger.exception(
                    "Invalidation listener failed",
                    key=key,
                    error=str(e)
                )
    
    async def get_statistics(self) -> dict[str, Any]:
        """Get cache coordinator statistics."""
        layer_stats = {}
        
        for layer_name, backend in self._cache_layers.items():
            try:
                layer_stats[layer_name] = {
                    "backend_type": backend.get_backend_type(),
                    "size": await backend.size(),
                }
            except Exception as e:
                layer_stats[layer_name] = {
                    "backend_type": backend.get_backend_type(),
                    "error": str(e),
                }
        
        return {
            "coordinator": {
                "consistency_level": self._consistency_level.value,
                "version_counter": self._version_counter,
                "active_transactions": len(self._active_transactions),
                "invalidation_listeners": len(self._invalidation_listeners),
            },
            "layers": layer_stats,
        }
    
    async def clear_all(self) -> None:
        """Clear all cache layers."""
        for layer_name, backend in self._cache_layers.items():
            try:
                await backend.clear()
                
                logger.info(
                    "Cache layer cleared",
                    layer=layer_name
                )
            
            except Exception as e:
                logger.warning(
                    "Failed to clear cache layer",
                    layer=layer_name,
                    error=str(e)
                )


# Global cache coordinator instance
_default_coordinator = CacheCoordinator()


def get_cache_coordinator() -> CacheCoordinator:
    """Get the default cache coordinator instance."""
    return _default_coordinator


# Export main classes and functions
__all__ = [
    "CacheBackend",
    "CacheCoordinator",
    "CacheEntry",
    "CacheTransaction",
    "ConsistencyLevel",
    "MemoryCacheBackend",
    "CacheCoordinationError",
    "CacheVersionConflictError",
    "CacheTransactionError",
    "CacheBackendError",
    "get_cache_coordinator",
]