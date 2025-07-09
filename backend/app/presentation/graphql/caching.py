"""
GraphQL Query Caching System

Provides intelligent caching for GraphQL queries with cache invalidation,
TTL management, and performance optimizations.
"""

import asyncio
import builtins
import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from strawberry.extensions import Extension
from strawberry.types import ExecutionContext, ExecutionResult

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Caching strategies for different query types."""
    NO_CACHE = "no_cache"
    SHORT_TERM = "short_term"  # 1-5 minutes
    MEDIUM_TERM = "medium_term"  # 5-30 minutes
    LONG_TERM = "long_term"  # 30+ minutes
    PERMANENT = "permanent"  # Cache until explicit invalidation


@dataclass
class CacheEntry:
    """Represents a cached query result."""
    key: str
    result: ExecutionResult
    created_at: datetime
    expires_at: datetime | None
    tags: set[str]
    hit_count: int = 0
    last_accessed: datetime = None
    
    def __post_init__(self):
        if self.last_accessed is None:
            self.last_accessed = self.created_at
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def record_hit(self):
        """Record a cache hit."""
        self.hit_count += 1
        self.last_accessed = datetime.utcnow()


class CacheKeyGenerator:
    """Generates cache keys for GraphQL queries."""
    
    def __init__(self, include_user_context: bool = True):
        self.include_user_context = include_user_context
    
    def generate_key(self, context: ExecutionContext) -> str:
        """Generate a cache key for a GraphQL query."""
        # Base components
        components = [
            self._normalize_query(context.query),
            self._serialize_variables(context.variable_values or {}),
        ]
        
        # Add user context if enabled
        if self.include_user_context:
            user_id = self._extract_user_id(context)
            if user_id:
                components.append(f"user:{user_id}")
        
        # Add operation name
        if context.operation_name:
            components.append(f"op:{context.operation_name}")
        
        # Create hash
        key_string = "|".join(components)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query string for consistent caching."""
        # Remove extra whitespace and comments
        lines = []
        for original_line in query.split('\n'):
            line = original_line.strip()
            if line and not line.startswith('#'):
                lines.append(line)
        
        return ' '.join(lines)
    
    def _serialize_variables(self, variables: dict[str, Any]) -> str:
        """Serialize variables for cache key."""
        if not variables:
            return ""
        
        # Sort keys for consistent ordering
        sorted_vars = dict(sorted(variables.items()))
        return json.dumps(sorted_vars, sort_keys=True, default=str)
    
    def _extract_user_id(self, context: ExecutionContext) -> str | None:
        """Extract user ID from execution context."""
        try:
            user = context.context.get("user")
            if user:
                return str(user.get("id", ""))
        except Exception:
            pass
        return None


class QueryCacheManager:
    """Manages GraphQL query caching with intelligent invalidation."""
    
    def __init__(self, 
                 default_ttl: int = 300,  # 5 minutes
                 max_entries: int = 10000,
                 cleanup_interval: int = 60):
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self.cleanup_interval = cleanup_interval
        
        self.cache: dict[str, CacheEntry] = {}
        self.tag_to_keys: dict[str, set[str]] = defaultdict(set)
        self.key_generator = CacheKeyGenerator()
        self.cache_strategies: dict[str, CacheStrategy] = {}
        self.strategy_rules: list[Callable] = []
        
        self._cleanup_task = None
        self._running = False
    
    async def start(self):
        """Start the cache manager."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_entries())
        logger.info("Query cache manager started")
    
    async def stop(self):
        """Stop the cache manager."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        logger.info("Query cache manager stopped")
    
    def get(self, key: str) -> ExecutionResult | None:
        """Get cached result by key."""
        entry = self.cache.get(key)
        if not entry:
            return None
        
        if entry.is_expired():
            self._remove_entry(key)
            return None
        
        entry.record_hit()
        return entry.result
    
    def set(self, key: str, result: ExecutionResult, ttl: int | None = None, tags: set[str] | None = None):
        """Cache a query result."""
        if not self._should_cache(result):
            return
        
        # Remove old entry if exists
        if key in self.cache:
            self._remove_entry(key)
        
        # Calculate expiration
        expires_at = None
        if ttl is not None:
            expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        elif self.default_ttl > 0:
            expires_at = datetime.utcnow() + timedelta(seconds=self.default_ttl)
        
        # Create cache entry
        entry = CacheEntry(
            key=key,
            result=result,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            tags=tags or set()
        )
        
        # Add to cache
        self.cache[key] = entry
        
        # Add to tag index
        for tag in entry.tags:
            self.tag_to_keys[tag].add(key)
        
        # Evict if over limit
        if len(self.cache) > self.max_entries:
            self._evict_lru()
    
    def invalidate_by_key(self, key: str):
        """Invalidate cache entry by key."""
        self._remove_entry(key)
    
    def invalidate_by_tags(self, tags: builtins.set[str]):
        """Invalidate cache entries by tags."""
        keys_to_remove = set()
        
        for tag in tags:
            keys_to_remove.update(self.tag_to_keys.get(tag, set()))
        
        for key in keys_to_remove:
            self._remove_entry(key)
    
    def invalidate_by_pattern(self, pattern: str):
        """Invalidate cache entries matching a pattern."""
        import re
        regex = re.compile(pattern)
        
        keys_to_remove = [
            key for key in self.cache
            if regex.match(key)
        ]
        
        for key in keys_to_remove:
            self._remove_entry(key)
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self.tag_to_keys.clear()
        logger.info("Cache cleared")
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_hits = sum(entry.hit_count for entry in self.cache.values())
        total_entries = len(self.cache)
        
        # Calculate hit rate (this is approximate)
        hit_rate = 0.0
        if total_entries > 0:
            hit_rate = total_hits / max(total_entries, 1)
        
        return {
            "total_entries": total_entries,
            "total_hits": total_hits,
            "hit_rate": hit_rate,
            "memory_usage_mb": self._estimate_memory_usage() / 1024 / 1024,
            "tags_count": len(self.tag_to_keys),
            "oldest_entry": min(
                (entry.created_at for entry in self.cache.values()),
                default=None
            ),
            "newest_entry": max(
                (entry.created_at for entry in self.cache.values()),
                default=None
            )
        }
    
    def add_strategy_rule(self, rule: Callable[[ExecutionContext], CacheStrategy]):
        """Add a rule for determining cache strategy."""
        self.strategy_rules.append(rule)
    
    def determine_strategy(self, context: ExecutionContext) -> CacheStrategy:
        """Determine cache strategy for a query."""
        # Check custom rules first
        for rule in self.strategy_rules:
            try:
                strategy = rule(context)
                if strategy:
                    return strategy
            except Exception:
                continue
        
        # Default rules
        query_str = context.query.lower()
        
        # Don't cache mutations
        if 'mutation' in query_str:
            return CacheStrategy.NO_CACHE
        
        # Don't cache introspection
        if '__schema' in query_str or '__type' in query_str:
            return CacheStrategy.NO_CACHE
        
        # Short-term for user-specific data
        if any(field in query_str for field in ['me', 'myprofile', 'mysessions']):
            return CacheStrategy.SHORT_TERM
        
        # Medium-term for list queries
        if any(field in query_str for field in ['users', 'roles', 'permissions']):
            return CacheStrategy.MEDIUM_TERM
        
        # Long-term for reference data
        if any(field in query_str for field in ['config', 'settings', 'metadata']):
            return CacheStrategy.LONG_TERM
        
        return CacheStrategy.SHORT_TERM
    
    def _should_cache(self, result: ExecutionResult) -> bool:
        """Check if result should be cached."""
        # Don't cache errors
        if result.errors:
            return False
        
        # Don't cache empty results
        return bool(result.data)
    
    def _remove_entry(self, key: str):
        """Remove cache entry and clean up indexes."""
        entry = self.cache.pop(key, None)
        if not entry:
            return
        
        # Remove from tag index
        for tag in entry.tags:
            self.tag_to_keys[tag].discard(key)
            if not self.tag_to_keys[tag]:
                del self.tag_to_keys[tag]
    
    def _evict_lru(self):
        """Evict least recently used entries."""
        # Sort by last accessed time and remove oldest
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: x[1].last_accessed
        )
        
        # Remove oldest 10% or at least 1
        remove_count = max(1, len(sorted_entries) // 10)
        
        for key, _ in sorted_entries[:remove_count]:
            self._remove_entry(key)
    
    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage in bytes."""
        # Rough estimate - not perfectly accurate
        total_size = 0
        
        for entry in self.cache.values():
            # Estimate size of result
            if entry.result.data:
                total_size += len(str(entry.result.data))
            
            # Add overhead
            total_size += 500  # Estimated overhead per entry
        
        return total_size
    
    async def _cleanup_expired_entries(self):
        """Periodically remove expired entries."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                expired_keys = [
                    key for key, entry in self.cache.items()
                    if entry.is_expired()
                ]
                
                for key in expired_keys:
                    self._remove_entry(key)
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in cache cleanup")


class QueryCacheExtension(Extension):
    """Strawberry extension for query caching."""
    
    def __init__(self, cache_manager: QueryCacheManager):
        self.cache_manager = cache_manager
        self.cache_key = None
        self.cache_strategy = None
    
    def on_validation_start(self):
        """Generate cache key and check for cached result."""
        if not self.execution_context.query:
            return
        
        # Determine cache strategy
        self.cache_strategy = self.cache_manager.determine_strategy(self.execution_context)
        
        if self.cache_strategy == CacheStrategy.NO_CACHE:
            return
        
        # Generate cache key
        self.cache_key = self.cache_manager.key_generator.generate_key(self.execution_context)
        
        # Check for cached result
        cached_result = self.cache_manager.get(self.cache_key)
        if cached_result:
            # Return cached result
            self.execution_context.result = cached_result
            logger.debug(f"Cache hit for key: {self.cache_key[:16]}...")
    
    def on_request_end(self, result: ExecutionResult):
        """Cache the result if appropriate."""
        if not self.cache_key or self.cache_strategy == CacheStrategy.NO_CACHE:
            return
        
        # Determine TTL based on strategy
        ttl = self._get_ttl_for_strategy(self.cache_strategy)
        
        # Generate cache tags
        tags = self._generate_cache_tags()
        
        # Cache the result
        self.cache_manager.set(
            key=self.cache_key,
            result=result,
            ttl=ttl,
            tags=tags
        )
        
        logger.debug(f"Cached result for key: {self.cache_key[:16]}... (TTL: {ttl}s)")
    
    def _get_ttl_for_strategy(self, strategy: CacheStrategy) -> int | None:
        """Get TTL in seconds for cache strategy."""
        ttl_map = {
            CacheStrategy.SHORT_TERM: 300,    # 5 minutes
            CacheStrategy.MEDIUM_TERM: 1800,  # 30 minutes
            CacheStrategy.LONG_TERM: 3600,    # 1 hour
            CacheStrategy.PERMANENT: None,    # No expiration
        }
        
        return ttl_map.get(strategy, 300)
    
    def _generate_cache_tags(self) -> set[str]:
        """Generate cache tags for invalidation."""
        tags = set()
        
        query_str = self.execution_context.query.lower()
        
        # Add tags based on query content
        if 'users' in query_str:
            tags.add('users')
        if 'roles' in query_str:
            tags.add('roles')
        if 'permissions' in query_str:
            tags.add('permissions')
        if 'audit' in query_str:
            tags.add('audit')
        if 'notifications' in query_str:
            tags.add('notifications')
        
        # Add user-specific tag if applicable
        user_id = self.cache_manager.key_generator._extract_user_id(self.execution_context)
        if user_id:
            tags.add(f'user:{user_id}')
        
        return tags


# Global cache manager instance
cache_manager = QueryCacheManager()


# Utility functions for cache invalidation
async def invalidate_user_cache(user_id: str):
    """Invalidate all cache entries for a specific user."""
    cache_manager.invalidate_by_tags({f'user:{user_id}'})


async def invalidate_resource_cache(resource: str):
    """Invalidate cache entries for a specific resource."""
    cache_manager.invalidate_by_tags({resource})


async def invalidate_pattern_cache(pattern: str):
    """Invalidate cache entries matching a pattern."""
    cache_manager.invalidate_by_pattern(pattern)


__all__ = [
    "CacheKeyGenerator",
    "CacheStrategy",
    "QueryCacheExtension",
    "QueryCacheManager",
    "cache_manager",
    "invalidate_pattern_cache",
    "invalidate_resource_cache",
    "invalidate_user_cache",
]