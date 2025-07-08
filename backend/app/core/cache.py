"""Cache management following pure Python principles.

This module provides a comprehensive caching system that follows clean architecture
principles with pure Python classes, completely independent of any specific
caching framework or backend.

The caching layer provides multiple backends, sophisticated policies, performance
monitoring, and rich functionality for distributed and local caching scenarios.

Design Principles:
- Pure Python implementation with explicit configuration
- Framework-agnostic design supporting multiple backends
- Rich functionality with comprehensive error handling
- Performance monitoring and analytics
- Configurable policies and strategies
- Type safety and validation
- Comprehensive logging and debugging

Architecture:
- CacheBackend: Abstract interface for cache implementations
- CacheManager: Main cache coordination service
- CacheMetrics: Performance monitoring and analytics
- Decorators: Function-level caching utilities

Note: Configuration classes (CacheConfig, CachePolicy) are now in app.core.config
"""

import asyncio
import contextlib
import hashlib
import json
import pickle
import secrets
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Generic, TypeVar

from app.core.config import CacheConfig, CachePolicy
from app.core.errors import ConfigurationError, InfrastructureError, ValidationError
from app.core.logging import get_logger

# Import enums from utils/shared modules
try:
    from app.core.enums import (
        CacheBackendType,
        CacheStrategy,
        EvictionPolicy,
        SerializationFormat,
    )
except ImportError:
    # Fallback enum definitions
    class CacheBackendType(Enum):
        MEMORY = "memory"
        REDIS = "redis"
        MEMCACHED = "memcached"
        HYBRID = "hybrid"
        
        @property
        def is_distributed(self) -> bool:
            return self in {self.REDIS, self.MEMCACHED}

    class CacheStrategy(Enum):
        NO_CACHE = "no_cache"
        CACHE_ASIDE = "cache_aside"
        WRITE_THROUGH = "write_through"
        WRITE_BEHIND = "write_behind"
        REFRESH_AHEAD = "refresh_ahead"
        
        @property
        def provides_strong_consistency(self) -> bool:
            return self in {self.WRITE_THROUGH, self.WRITE_BEHIND}
        
        @property
        def requires_storage_backend(self) -> bool:
            return self in {self.WRITE_BEHIND, self.REFRESH_AHEAD}

    class EvictionPolicy(Enum):
        LRU = "lru"
        LFU = "lfu"
        FIFO = "fifo"
        LIFO = "lifo"
        TTL = "ttl"
        RANDOM = "random"
        
        @property
        def requires_access_tracking(self) -> bool:
            return self in {self.LRU, self.LFU}

    class SerializationFormat(Enum):
        JSON = "json"
        PICKLE = "pickle"
        MSGPACK = "msgpack"
        AUTO = "auto"

logger = get_logger(__name__)

# Type variables
T = TypeVar("T")
CacheKey = str | tuple[Any, ...]
CacheValue = Any

# Security constants
SECURE_HASH_TRUNCATION_LENGTH = 16  # Use more secure hash truncation
MAX_KEY_GENERATION_ATTEMPTS = 3


# =====================================================================================
# CACHE METRICS AND MONITORING
# =====================================================================================


@dataclass
class CacheMetrics:
    """
    Cache performance metrics and statistics.

    Tracks cache performance including hit/miss ratios, operation times,
    error rates, and other important metrics for monitoring and optimization.
    """

    # Operation counts
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    errors: int = 0

    # Timing statistics
    total_get_time: float = 0.0
    total_set_time: float = 0.0
    total_delete_time: float = 0.0

    # Size statistics
    current_size: int = 0
    max_size_reached: int = 0
    evictions: int = 0

    # Health metrics
    connection_errors: int = 0
    serialization_errors: int = 0
    last_error: str | None = None
    last_error_time: datetime | None = None

    def record_hit(self, operation_time: float = 0.0) -> None:
        """Record a cache hit."""
        self.hits += 1
        self.total_get_time += operation_time

    def record_miss(self, operation_time: float = 0.0) -> None:
        """Record a cache miss."""
        self.misses += 1
        self.total_get_time += operation_time

    def record_set(self, operation_time: float = 0.0) -> None:
        """Record a cache set operation."""
        self.sets += 1
        self.total_set_time += operation_time

    def record_delete(self, operation_time: float = 0.0) -> None:
        """Record a cache delete operation."""
        self.deletes += 1
        self.total_delete_time += operation_time

    def record_error(self, error_message: str) -> None:
        """Record a cache error."""
        self.errors += 1
        self.last_error = error_message
        self.last_error_time = datetime.utcnow()

    def record_eviction(self) -> None:
        """Record a cache eviction."""
        self.evictions += 1

    def record_connection_error(self) -> None:
        """Record a connection error."""
        self.connection_errors += 1
        self.errors += 1

    def record_serialization_error(self, error_message: str) -> None:
        """Record a serialization error."""
        self.serialization_errors += 1
        self.record_error(f"Serialization error: {error_message}")

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_operations = self.hits + self.misses
        return self.hits / total_operations if total_operations > 0 else 0.0

    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate."""
        return 1.0 - self.hit_rate

    @property
    def average_get_time(self) -> float:
        """Calculate average get operation time."""
        total_gets = self.hits + self.misses
        return self.total_get_time / total_gets if total_gets > 0 else 0.0

    @property
    def average_set_time(self) -> float:
        """Calculate average set operation time."""
        return self.total_set_time / self.sets if self.sets > 0 else 0.0

    @property
    def average_delete_time(self) -> float:
        """Calculate average delete operation time."""
        return self.total_delete_time / self.deletes if self.deletes > 0 else 0.0

    @property
    def error_rate(self) -> float:
        """Calculate error rate."""
        total_operations = self.hits + self.misses + self.sets + self.deletes
        return self.errors / total_operations if total_operations > 0 else 0.0

    @property
    def operations_per_second(self) -> float:
        """Calculate operations per second (rough estimate)."""
        total_time = self.total_get_time + self.total_set_time + self.total_delete_time
        total_operations = self.hits + self.misses + self.sets + self.deletes
        return total_operations / total_time if total_time > 0 else 0.0

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.errors = 0
        self.total_get_time = 0.0
        self.total_set_time = 0.0
        self.total_delete_time = 0.0
        self.evictions = 0
        self.connection_errors = 0
        self.serialization_errors = 0
        self.last_error = None
        self.last_error_time = None

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "deletes": self.deletes,
            "errors": self.errors,
            "hit_rate": self.hit_rate,
            "miss_rate": self.miss_rate,
            "error_rate": self.error_rate,
            "average_get_time": self.average_get_time,
            "average_set_time": self.average_set_time,
            "average_delete_time": self.average_delete_time,
            "operations_per_second": self.operations_per_second,
            "current_size": self.current_size,
            "max_size_reached": self.max_size_reached,
            "evictions": self.evictions,
            "connection_errors": self.connection_errors,
            "serialization_errors": self.serialization_errors,
            "last_error": self.last_error,
            "last_error_time": self.last_error_time.isoformat()
            if self.last_error_time
            else None,
        }


# =====================================================================================
# CACHE BACKEND INTERFACE
# =====================================================================================


class CacheBackend(ABC, Generic[T]):
    """
    Abstract cache backend interface.

    Defines the contract for cache implementations, providing a consistent
    interface across different caching technologies and storage mechanisms.

    Design Features:
    - Framework-agnostic interface
    - Async/await support for all operations
    - Rich error handling and validation
    - Performance monitoring integration
    - Health checking capabilities
    - Batch operations support

    Usage Example:
        class CustomCacheBackend(CacheBackend):
            async def get(self, key: str) -> Any | None:
                # Implementation specific logic
                pass

            async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
                # Implementation specific logic
                pass
    """

    def __init__(self, config: CacheConfig, policy: CachePolicy):
        """
        Initialize cache backend.

        Args:
            config: Cache configuration (from app.core.config.CacheConfig)
            policy: Cache policy (from app.core.config.CachePolicy)
        """
        self.config = config
        self.policy = policy
        self.metrics = CacheMetrics()
        self._initialized = False
        self._healthy = False

    @abstractmethod
    async def get(self, key: str) -> T | None:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            T | None: Cached value if found, None otherwise
        """

    @abstractmethod
    async def set(self, key: str, value: T, ttl: int | None = None) -> None:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
        """

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            bool: True if key was deleted, False if not found
        """

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            bool: True if key exists, False otherwise
        """

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cached values."""

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Perform health check on cache backend.

        Returns:
            bool: True if backend is healthy, False otherwise
        """

    async def batch_get(self, keys: list[str]) -> dict[str, T | None]:
        """
        Get multiple values from cache.

        Args:
            keys: List of cache keys

        Returns:
            dict[str, T | None]: Mapping of keys to values
        """
        results = {}
        for key in keys:
            results[key] = await self.get(key)
        return results

    async def batch_set(self, items: dict[str, T], ttl: int | None = None) -> None:
        """
        Set multiple values in cache.

        Args:
            items: Mapping of keys to values
            ttl: Time to live in seconds
        """
        for key, value in items.items():
            await self.set(key, value, ttl)

    async def batch_delete(self, keys: list[str]) -> int:
        """
        Delete multiple values from cache.

        Args:
            keys: List of cache keys

        Returns:
            int: Number of keys deleted
        """
        deleted_count = 0
        for key in keys:
            if await self.delete(key):
                deleted_count += 1
        return deleted_count

    def validate_key(self, key: str) -> None:
        """
        Validate cache key.

        Args:
            key: Cache key to validate

        Raises:
            ValidationError: If key is invalid
        """
        if not key:
            raise ValidationError("Cache key cannot be empty")

        if len(key) > self.policy.max_key_length:
            raise ValidationError(
                f"Cache key too long: {len(key)} > {self.policy.max_key_length}"
            )

        # Check for invalid characters that could cause issues
        invalid_chars = ["\n", "\r", "\t", " ", "\0"]
        if any(char in key for char in invalid_chars):
            raise ValidationError("Cache key contains invalid characters")

    def validate_value(self, value: Any) -> None:
        """
        Validate cache value.

        Args:
            value: Value to validate

        Raises:
            ValidationError: If value is invalid
        """
        if value is None:
            return

        # Check size if we can estimate it
        try:
            if self.policy.serialization_format == SerializationFormat.JSON:
                serialized_size = len(json.dumps(value, default=str))
            elif self.policy.serialization_format == SerializationFormat.PICKLE:
                serialized_size = len(pickle.dumps(value))
            else:
                # For AUTO or MSGPACK, use JSON as approximation
                serialized_size = len(json.dumps(value, default=str))

            if serialized_size > self.policy.max_value_size:
                raise ValidationError(
                    f"Cache value too large: {serialized_size} > {self.policy.max_value_size}"
                )

        except (TypeError, ValueError, pickle.PickleError) as e:
            # If we can't serialize, that's also an error
            raise ValidationError(f"Cache value cannot be serialized: {e!s}") from e

    def generate_cache_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments using secure hashing.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            str: Generated cache key
        """
        key_parts = []

        # Add positional arguments
        for arg in args:
            if isinstance(arg, str | int | float | bool):
                key_parts.append(str(arg))
            else:
                # Use SHA-256 for secure hashing instead of MD5
                key_parts.append(
                    hashlib.sha256(str(arg).encode()).hexdigest()[:SECURE_HASH_TRUNCATION_LENGTH]
                )

        # Add keyword arguments (sorted for consistency)
        for k, v in sorted(kwargs.items()):
            if isinstance(v, str | int | float | bool):
                key_parts.append(f"{k}={v}")
            else:
                key_parts.append(
                    f"{k}={hashlib.sha256(str(v).encode()).hexdigest()[:SECURE_HASH_TRUNCATION_LENGTH]}"
                )

        return self.config.namespace_separator.join(key_parts)

    async def initialize(self) -> None:
        """Initialize cache backend."""
        self._initialized = True
        self._healthy = await self.health_check()

        logger.info(
            "Cache backend initialized",
            backend_type=self.config.backend_type.value,
            strategy=self.config.cache_strategy.value,
            healthy=self._healthy,
        )

    async def shutdown(self) -> None:
        """Shutdown cache backend and cleanup resources."""
        self._initialized = False
        self._healthy = False

        logger.info(
            "Cache backend shutdown", backend_type=self.config.backend_type.value
        )

    @property
    def is_initialized(self) -> bool:
        """Check if backend is initialized."""
        return self._initialized

    @property
    def is_healthy(self) -> bool:
        """Check if backend is healthy."""
        return self._healthy


# =====================================================================================
# MEMORY CACHE IMPLEMENTATION
# =====================================================================================


class MemoryCacheBackend(CacheBackend[T]):
    """
    In-memory cache backend implementation.

    Provides fast local caching using Python dictionaries with TTL support,
    eviction policies, and size management.

    Design Features:
    - LRU/LFU/TTL/FIFO/RANDOM eviction policies
    - Memory usage monitoring
    - TTL expiration handling
    - Thread-safe operations with asyncio.Lock
    - Comprehensive metrics
    - Automatic cleanup of expired entries

    Usage Example:
        from app.core.config import CacheConfig, CachePolicy
        from app.enums import CacheBackendType

        config = CacheConfig(backend_type=CacheBackendType.MEMORY)
        policy = CachePolicy(max_entries=1000)
        cache = MemoryCacheBackend(config, policy)

        await cache.set("key1", "value1", ttl=300)
        value = await cache.get("key1")
    """

    def __init__(self, config: CacheConfig, policy: CachePolicy):
        """Initialize memory cache backend."""
        super().__init__(config, policy)

        self._data: dict[str, Any] = {}
        self._timestamps: dict[str, float] = {}  # For TTL
        self._access_times: dict[str, float] = {}  # For LRU
        self._access_counts: dict[str, int] = {}  # For LFU
        self._insertion_order: list[str] = []  # For FIFO

        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task | None = None

    async def get(self, key: str) -> T | None:
        """Get value from memory cache."""
        start_time = time.time()

        try:
            self.validate_key(key)

            async with self._lock:
                # Check if key exists and is not expired
                if key not in self._data:
                    self.metrics.record_miss(time.time() - start_time)
                    return None

                # Check TTL
                if self._is_expired(key):
                    await self._remove_key(key)
                    self.metrics.record_miss(time.time() - start_time)
                    return None

                # Update access tracking for eviction policies
                if self.policy.track_statistics:
                    self._access_times[key] = time.time()
                    self._access_counts[key] = self._access_counts.get(key, 0) + 1

                value = self._data[key]
                self.metrics.record_hit(time.time() - start_time)
                return value

        except Exception as e:
            self.metrics.record_error(str(e))
            logger.exception("Memory cache get error", key=key)
            return None

    async def set(self, key: str, value: T, ttl: int | None = None) -> None:
        """Set value in memory cache."""
        start_time = time.time()

        try:
            self.validate_key(key)
            self.validate_value(value)

            async with self._lock:
                # Check if we need to evict entries
                if key not in self._data and self.policy.max_entries and len(self._data) >= self.policy.max_entries:
                    await self._evict_entry()

                # Set the value
                self._data[key] = value
                current_time = time.time()

                # Set TTL if provided
                if ttl is not None:
                    self._timestamps[key] = current_time + ttl
                elif self.policy.default_ttl:
                    self._timestamps[key] = (
                        current_time + self.policy.default_ttl.total_seconds()
                    )

                # Update tracking for eviction policies
                if self.policy.track_statistics:
                    self._access_times[key] = current_time
                    self._access_counts[key] = self._access_counts.get(key, 0) + 1

                # Track insertion order for FIFO
                if key not in self._insertion_order:
                    self._insertion_order.append(key)

                # Update metrics
                self.metrics.record_set(time.time() - start_time)
                self.metrics.current_size = len(self._data)

                # Update max size tracking
                self.metrics.max_size_reached = max(
                    self.metrics.current_size, self.metrics.max_size_reached
                )

        except Exception as e:
            self.metrics.record_error(str(e))
            logger.exception("Memory cache set error", key=key)
            raise InfrastructureError(f"Failed to set cache value: {e!s}") from e

    async def delete(self, key: str) -> bool:
        """Delete value from memory cache."""
        start_time = time.time()

        try:
            self.validate_key(key)

            async with self._lock:
                if key in self._data:
                    await self._remove_key(key)
                    self.metrics.record_delete(time.time() - start_time)
                    self.metrics.current_size = len(self._data)
                    return True
                return False

        except Exception as e:
            self.metrics.record_error(str(e))
            logger.exception("Memory cache delete error", key=key)
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in memory cache."""
        try:
            self.validate_key(key)

            async with self._lock:
                if key not in self._data:
                    return False

                if self._is_expired(key):
                    await self._remove_key(key)
                    return False

                return True

        except Exception as e:
            self.metrics.record_error(str(e))
            return False

    async def clear(self) -> None:
        """Clear all cached values."""
        async with self._lock:
            self._data.clear()
            self._timestamps.clear()
            self._access_times.clear()
            self._access_counts.clear()
            self._insertion_order.clear()
            self.metrics.current_size = 0

        logger.info("Memory cache cleared")

    async def health_check(self) -> bool:
        """Perform health check on memory cache."""
        try:
            # Test basic operations
            test_key = "__health_check__"
            test_value = "test"

            await self.set(test_key, test_value, ttl=1)
            result = await self.get(test_key)
            await self.delete(test_key)
        except Exception:
            logger.exception("Memory cache health check failed")
            return False
        else:
            return result == test_value

    def _is_expired(self, key: str) -> bool:
        """Check if key is expired."""
        if key not in self._timestamps:
            return False

        return time.time() > self._timestamps[key]

    async def _remove_key(self, key: str) -> None:
        """Remove key and all its tracking data."""
        self._data.pop(key, None)
        self._timestamps.pop(key, None)
        self._access_times.pop(key, None)
        self._access_counts.pop(key, None)

        if key in self._insertion_order:
            self._insertion_order.remove(key)

    def _select_eviction_candidate(self) -> str | None:
        """Select candidate for eviction based on policy."""
        if not self._data:
            return None

        # Use a mapping to avoid multiple return statements
        selection_methods = {
            EvictionPolicy.LRU: self._select_lru_candidate,
            EvictionPolicy.LFU: self._select_lfu_candidate,
            EvictionPolicy.FIFO: self._select_fifo_candidate,
            EvictionPolicy.TTL: self._select_ttl_candidate,
            EvictionPolicy.RANDOM: self._select_random_candidate,
        }
        
        method = selection_methods.get(self.policy.eviction_policy)
        return method() if method else None

    def _select_lru_candidate(self) -> str | None:
        """Select least recently used candidate."""
        if not self._access_times:
            return None
        
        oldest_time = float("inf")
        key_to_evict = None
        for key, access_time in self._access_times.items():
            if access_time < oldest_time:
                oldest_time = access_time
                key_to_evict = key
        return key_to_evict

    def _select_lfu_candidate(self) -> str | None:
        """Select least frequently used candidate."""
        if not self._access_counts:
            return None
        
        min_count = float("inf")
        key_to_evict = None
        for key, count in self._access_counts.items():
            if count < min_count:
                min_count = count
                key_to_evict = key
        return key_to_evict

    def _select_fifo_candidate(self) -> str | None:
        """Select first in, first out candidate."""
        return self._insertion_order[0] if self._insertion_order else None

    def _select_ttl_candidate(self) -> str | None:
        """Select candidate with earliest expiration."""
        if not self._timestamps:
            return None
        
        earliest_expiry = float("inf")
        key_to_evict = None
        for key, expiry_time in self._timestamps.items():
            if expiry_time < earliest_expiry:
                earliest_expiry = expiry_time
                key_to_evict = key
        return key_to_evict

    def _select_random_candidate(self) -> str | None:
        """Select random candidate using cryptographically secure random."""
        if not self._data:
            return None
        
        keys = list(self._data.keys())
        return secrets.choice(keys)  # Use secrets.choice instead of random.choice

    async def _evict_entry(self) -> None:
        """Evict entry based on eviction policy."""
        key_to_evict = self._select_eviction_candidate()

        if key_to_evict:
            await self._remove_key(key_to_evict)
            self.metrics.record_eviction()

            if self.policy.log_cache_events:
                logger.debug(
                    "Cache entry evicted",
                    key=key_to_evict,
                    policy=self.policy.eviction_policy.value,
                )

    async def _cleanup_expired(self) -> None:
        """Clean up expired entries."""
        async with self._lock:
            current_time = time.time()
            expired_keys = [
                key
                for key, expiry_time in self._timestamps.items()
                if current_time > expiry_time
            ]

            for key in expired_keys:
                await self._remove_key(key)

            if expired_keys:
                self.metrics.current_size = len(self._data)

                if self.policy.log_cache_events:
                    logger.debug(
                        "Expired cache entries cleaned up", count=len(expired_keys)
                    )

    async def initialize(self) -> None:
        """Initialize memory cache backend."""
        await super().initialize()

        # Start cleanup task if configured
        if self.config.memory_cleanup_interval > 0:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def shutdown(self) -> None:
        """Shutdown memory cache backend."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

        await super().shutdown()

    async def _periodic_cleanup(self) -> None:
        """Periodic cleanup of expired entries."""
        while True:
            try:
                await asyncio.sleep(self.config.memory_cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Periodic cleanup error")


# =====================================================================================
# NO-CACHE BACKEND (for NO_CACHE strategy)
# =====================================================================================


class NoCacheBackend(CacheBackend[T]):
    """
    No-op cache backend for when caching is disabled.

    This backend implements the CacheBackend interface but doesn't
    actually cache anything. Useful for testing or when caching
    should be disabled without changing application code.
    """

    async def get(self, key: str) -> T | None:
        """Always returns None (cache miss)."""
        self.metrics.record_miss()
        return None

    async def set(self, key: str, value: T, ttl: int | None = None) -> None:
        """No-op set operation."""
        self.metrics.record_set()

    async def delete(self, key: str) -> bool:
        """Always returns False (key not found)."""
        self.metrics.record_delete()
        return False

    async def exists(self, key: str) -> bool:
        """Always returns False."""
        return False

    async def clear(self) -> None:
        """No-op clear operation."""

    async def health_check(self) -> bool:
        """Always healthy since there's nothing to break."""
        return True


# =====================================================================================
# CACHE MANAGER
# =====================================================================================


class CacheManager:
    """
    Main cache coordination service.

    Provides a unified interface to caching with support for multiple backends,
    fallback strategies, and comprehensive management capabilities.

    Design Features:
    - Multiple backend support with fallback
    - Cache strategy implementation
    - Namespace management
    - Performance monitoring
    - Health checking and auto-recovery
    - Configuration management
    - Decorator utilities

    Usage Example:
        from app.core.config import CacheConfig, CachePolicy
        from app.enums import CacheBackendType, CacheStrategy

        config = CacheConfig(
            backend_type=CacheBackendType.MEMORY,
            cache_strategy=CacheStrategy.CACHE_ASIDE
        )
        policy = CachePolicy(default_ttl=timedelta(minutes=10))
        cache_manager = CacheManager(config, policy)

        await cache_manager.initialize()

        # Basic operations
        await cache_manager.set("key1", "value1")
        value = await cache_manager.get("key1")

        # Namespace operations
        await cache_manager.set("key2", "value2", namespace="users")
        value = await cache_manager.get("key2", namespace="users")
    """

    def __init__(self, config: CacheConfig, policy: CachePolicy):
        """
        Initialize cache manager.

        Args:
            config: Cache configuration (from app.core.config.CacheConfig)
            policy: Cache policy (from app.core.config.CachePolicy)
        """
        self.config = config
        self.policy = policy

        self._primary_backend: CacheBackend | None = None
        self._fallback_backend: CacheBackend | None = None
        self._initialized = False

        # Overall metrics
        self._total_operations = 0
        self._total_errors = 0
        self._start_time = datetime.utcnow()

    async def initialize(self) -> None:
        """Initialize cache manager and backends."""
        if self._initialized:
            return

        try:
            # Handle NO_CACHE strategy
            if self.config.cache_strategy == CacheStrategy.NO_CACHE:
                self._primary_backend = NoCacheBackend(self.config, self.policy)
                await self._primary_backend.initialize()
                self._initialized = True
                logger.info("Cache manager initialized with NO_CACHE strategy")
                return

            # Initialize primary backend
            self._primary_backend = await self._create_backend(self.config.backend_type)
            await self._primary_backend.initialize()

            # Initialize fallback backend if configured
            if self.config.fallback_backend:
                self._fallback_backend = await self._create_backend(
                    self.config.fallback_backend
                )
                await self._fallback_backend.initialize()

            self._initialized = True

            logger.info(
                "Cache manager initialized",
                primary_backend=self.config.backend_type.value,
                fallback_backend=self.config.fallback_backend.value
                if self.config.fallback_backend
                else None,
                strategy=self.config.cache_strategy.value,
                eviction_policy=self.policy.eviction_policy.value,
            )

        except Exception:
            logger.exception("Cache manager initialization failed")
            raise ConfigurationError("Failed to initialize cache manager") from None

    async def _create_backend(self, backend_type: CacheBackendType) -> CacheBackend:
        """Create cache backend instance."""
        if backend_type == CacheBackendType.MEMORY:
            return MemoryCacheBackend(self.config, self.policy)
        if backend_type == CacheBackendType.REDIS:
            # Redis backend would be implemented here
            raise NotImplementedError("Redis backend not implemented in this example")
        if backend_type == CacheBackendType.MEMCACHED:
            # Memcached backend would be implemented here
            raise NotImplementedError(
                "Memcached backend not implemented in this example"
            )
        if backend_type == CacheBackendType.HYBRID:
            # Hybrid backend would be implemented here
            raise NotImplementedError("Hybrid backend not implemented in this example")
        raise ConfigurationError(f"Unsupported backend type: {backend_type}")

    async def get(self, key: str, namespace: str | None = None) -> Any | None:
        """
        Get value from cache.

        Args:
            key: Cache key
            namespace: Optional namespace

        Returns:
            Any | None: Cached value if found, None otherwise
        """
        if not self._initialized:
            logger.warning("Cache manager not initialized")
            return None

        cache_key = self._build_key(key, namespace)
        self._total_operations += 1

        try:
            # Try primary backend first
            if self._primary_backend:
                result = await self._primary_backend.get(cache_key)
                if result is not None:
                    return result

            # Try fallback backend
            if self._fallback_backend:
                return await self._fallback_backend.get(cache_key)

        except Exception:
            self._total_errors += 1
            logger.exception("Cache get operation failed", key=cache_key)

        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | timedelta | None = None,
        namespace: str | None = None,
    ) -> None:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live
            namespace: Optional namespace
        """
        if not self._initialized:
            logger.warning("Cache manager not initialized")
            return

        cache_key = self._build_key(key, namespace)
        ttl_seconds = self._convert_ttl(ttl)
        self._total_operations += 1

        try:
            # Set in primary backend
            if self._primary_backend:
                await self._primary_backend.set(cache_key, value, ttl_seconds)

            # Set in fallback backend for redundancy (depending on strategy)
            if (
                self._fallback_backend
                and self.config.cache_strategy.provides_strong_consistency
            ):
                await self._fallback_backend.set(cache_key, value, ttl_seconds)

        except Exception:
            self._total_errors += 1
            logger.exception("Cache set operation failed", key=cache_key)
            raise InfrastructureError("Failed to set cache value") from None

    async def delete(self, key: str, namespace: str | None = None) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key
            namespace: Optional namespace

        Returns:
            bool: True if key was deleted from any backend
        """
        if not self._initialized:
            logger.warning("Cache manager not initialized")
            return False

        cache_key = self._build_key(key, namespace)
        self._total_operations += 1
        deleted = False

        try:
            # Delete from primary backend
            if self._primary_backend and await self._primary_backend.delete(cache_key):
                deleted = True

            # Delete from fallback backend
            if self._fallback_backend and await self._fallback_backend.delete(cache_key):
                deleted = True

        except Exception:
            self._total_errors += 1
            logger.exception("Cache delete operation failed", key=cache_key)

        return deleted

    async def exists(self, key: str, namespace: str | None = None) -> bool:
        """Check if key exists in cache."""
        if not self._initialized:
            return False

        cache_key = self._build_key(key, namespace)

        try:
            # Check primary backend first
            if self._primary_backend and await self._primary_backend.exists(cache_key):
                return True

            # Check fallback backend
            return bool(
                self._fallback_backend
                and await self._fallback_backend.exists(cache_key)
            )

        except Exception:
            logger.exception("Cache exists operation failed", key=cache_key)

        return False

    async def clear(self, namespace: str | None = None) -> None:
        """Clear cache entries."""
        if not self._initialized:
            return

        try:
            if namespace:
                # Clear specific namespace (would need pattern matching in production)
                logger.warning("Namespace-specific clear not fully implemented")
                # In a production system, you'd implement pattern-based deletion
            else:
                # Clear all
                if self._primary_backend:
                    await self._primary_backend.clear()

                if self._fallback_backend:
                    await self._fallback_backend.clear()

        except Exception:
            logger.exception("Cache clear operation failed")

    def _build_key(self, key: str, namespace: str | None = None) -> str:
        """Build cache key with prefix and namespace."""
        parts = [self.config.key_prefix]

        if namespace:
            parts.append(namespace)

        parts.append(key)

        return self.config.namespace_separator.join(parts)

    def _convert_ttl(self, ttl: int | timedelta | None) -> int | None:
        """Convert TTL to seconds."""
        if ttl is None:
            if self.policy.default_ttl:
                return int(self.policy.default_ttl.total_seconds())
            return None

        if isinstance(ttl, timedelta):
            return int(ttl.total_seconds())

        return int(ttl)

    async def health_check(self) -> dict[str, Any]:
        """Perform comprehensive health check."""
        health_status = {
            "healthy": True,
            "backends": {},
            "strategy": self.config.cache_strategy.value,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check primary backend
        if self._primary_backend:
            try:
                backend_healthy = await self._primary_backend.health_check()
            except Exception:
                health_status["backends"]["primary"] = {
                    "type": self.config.backend_type.value,
                    "healthy": False,
                    "error": "Health check failed",
                }
                health_status["healthy"] = False
            else:
                health_status["backends"]["primary"] = {
                    "type": self.config.backend_type.value,
                    "healthy": backend_healthy,
                    "metrics": self._primary_backend.metrics.to_dict(),
                }
                if not backend_healthy:
                    health_status["healthy"] = False

        # Check fallback backend
        if self._fallback_backend:
            try:
                backend_healthy = await self._fallback_backend.health_check()
                health_status["backends"]["fallback"] = {
                    "type": self.config.fallback_backend.value,
                    "healthy": backend_healthy,
                    "metrics": self._fallback_backend.metrics.to_dict(),
                }
            except Exception:
                health_status["backends"]["fallback"] = {
                    "type": self.config.fallback_backend.value,
                    "healthy": False,
                    "error": "Health check failed",
                }

        return health_status

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive cache statistics."""
        uptime = (datetime.utcnow() - self._start_time).total_seconds()

        stats = {
            "manager": {
                "initialized": self._initialized,
                "uptime_seconds": uptime,
                "total_operations": self._total_operations,
                "total_errors": self._total_errors,
                "error_rate": self._total_errors / max(self._total_operations, 1),
            },
            "config": {
                "backend_type": self.config.backend_type.value,
                "fallback_backend": self.config.fallback_backend.value
                if self.config.fallback_backend
                else None,
                "cache_strategy": self.config.cache_strategy.value,
                "key_prefix": self.config.key_prefix,
                "caching_enabled": self.config.is_caching_enabled,
            },
            "policy": {
                "default_ttl_seconds": self.policy.default_ttl.total_seconds()
                if self.policy.default_ttl
                else None,
                "eviction_policy": self.policy.eviction_policy.value,
                "max_entries": self.policy.max_entries,
                "serialization_format": self.policy.serialization_format.value,
                "max_key_length": self.policy.max_key_length,
                "max_value_size": self.policy.max_value_size,
            },
        }

        # Add backend statistics
        if self._primary_backend:
            stats["primary_backend"] = self._primary_backend.metrics.to_dict()

        if self._fallback_backend:
            stats["fallback_backend"] = self._fallback_backend.metrics.to_dict()

        return stats

    async def shutdown(self) -> None:
        """Shutdown cache manager and backends."""
        try:
            if self._primary_backend:
                await self._primary_backend.shutdown()

            if self._fallback_backend:
                await self._fallback_backend.shutdown()

            self._initialized = False
            logger.info("Cache manager shutdown completed")

        except Exception:
            logger.exception("Cache manager shutdown failed")


# =====================================================================================
# CACHE DECORATORS
# =====================================================================================


def cached(
    key_template: str,
    ttl: int | timedelta | None = None,
    namespace: str | None = None,
    cache_manager: CacheManager | None = None,
) -> Callable:
    """
    Cache decorator for async functions.

    Args:
        key_template: Template for cache key (supports .format() with function args)
        ttl: Time to live for cached values
        namespace: Optional cache namespace
        cache_manager: Cache manager instance (uses global if not provided)

    Returns:
        Callable: Decorated function

    Usage Example:
        @cached("user:{user_id}", ttl=300, namespace="users")
        async def get_user(user_id: str) -> User:
            # Function implementation
            pass
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Get cache manager (would use global instance in real implementation)
            if not cache_manager:
                logger.warning("No cache manager provided to decorator")
                return await func(*args, **kwargs)

            # Skip caching if strategy is NO_CACHE
            if cache_manager.config.cache_strategy == CacheStrategy.NO_CACHE:
                return await func(*args, **kwargs)

            # Generate cache key
            try:
                cache_key = key_template.format(*args, **kwargs)
            except (KeyError, IndexError, ValueError):
                logger.warning("Failed to generate cache key")
                return await func(*args, **kwargs)

            # Try to get from cache
            try:
                cached_result = await cache_manager.get(cache_key, namespace)
            except Exception:
                logger.warning("Cache get failed")
            else:
                if cached_result is not None:
                    logger.debug("Cache hit", function=func.__name__, key=cache_key)
                    return cached_result

            # Execute function and cache result
            try:
                result = await func(*args, **kwargs)
                await cache_manager.set(cache_key, result, ttl, namespace)
                logger.debug("Cache set", function=func.__name__, key=cache_key)
            except Exception:
                logger.exception("Function execution failed")
                raise
            else:
                return result

        return wrapper

    return decorator


def invalidate_cache(
    key_template: str,
    namespace: str | None = None,
    cache_manager: CacheManager | None = None,
) -> Callable:
    """
    Cache invalidation decorator for async functions.

    Args:
        key_template: Template for cache key to invalidate
        namespace: Optional cache namespace
        cache_manager: Cache manager instance

    Returns:
        Callable: Decorated function

    Usage Example:
        @invalidate_cache("user:{user_id}", namespace="users")
        async def update_user(user_id: str, data: dict) -> User:
            # Function implementation that modifies user data
            pass
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            # Execute function first
            result = await func(*args, **kwargs)

            # Invalidate cache
            if (
                cache_manager
                and cache_manager.config.cache_strategy != CacheStrategy.NO_CACHE
            ):
                try:
                    cache_key = key_template.format(*args, **kwargs)
                    await cache_manager.delete(cache_key, namespace)
                    logger.debug(
                        "Cache invalidated", function=func.__name__, key=cache_key
                    )
                except Exception:
                    logger.warning("Cache invalidation failed")

            return result

        return wrapper

    return decorator


def cache_aside(
    key_template: str, ttl: int | timedelta | None = None, namespace: str | None = None
) -> Callable:
    """
    Cache-aside pattern decorator (alias for cached).

    This is the most common caching pattern where the application
    manages the cache manually.
    """
    return cached(key_template, ttl, namespace)


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Backends
    "CacheBackend",
    # Type aliases  
    "CacheKey",
    # Manager
    "CacheManager",
    # Metrics
    "CacheMetrics",
    "CacheValue",
    "MemoryCacheBackend",
    "NoCacheBackend",
    # Decorators
    "cache_aside",
    "cached",
    "invalidate_cache",
]
