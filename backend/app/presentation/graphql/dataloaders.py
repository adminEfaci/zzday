"""
GraphQL DataLoader Implementation

Provides base classes and utilities for implementing dataloaders to prevent N+1 queries.
This module includes generic dataloaders and patterns that can be extended by each module.
"""

import logging
from abc import abstractmethod
from collections import defaultdict
from collections.abc import Callable
from typing import Any, Generic, Optional, TypeVar

from strawberry.dataloader import DataLoader

logger = logging.getLogger(__name__)

# Type variables for generic dataloaders
K = TypeVar("K")  # Key type
V = TypeVar("V")  # Value type
T = TypeVar("T")  # Generic type


class BaseDataLoader(DataLoader[K, V | None], Generic[K, V]):
    """
    Base class for all dataloaders with common functionality.
    
    Features:
    - Automatic batching
    - Error handling
    - Logging
    - Metrics collection
    """
    
    def __init__(self, context: Any = None):
        """
        Initialize the dataloader.
        
        Args:
            context: Optional context object (usually contains repositories)
        """
        super().__init__(load_fn=self._load_fn)
        self.context = context
        self._load_count = 0
        self._batch_count = 0
    
    async def _load_fn(self, keys: list[K]) -> list[V | None]:
        """
        Internal load function that wraps the batch load with error handling.
        """
        self._batch_count += 1
        self._load_count += len(keys)
        
        try:
            logger.debug(
                f"{self.__class__.__name__} loading batch of {len(keys)} items"
            )
            return await self.batch_load(keys)
        except Exception as e:
            logger.error(
                f"Error in {self.__class__.__name__}.batch_load: {e}",
                exc_info=True
            )
            # Return None for all keys on error
            return [None] * len(keys)
    
    @abstractmethod
    async def batch_load(self, keys: list[K]) -> list[V | None]:
        """
        Load multiple items by their keys.
        
        Must return a list of the same length as keys, with None for missing items.
        The order must match the order of keys.
        """
    
    @property
    def metrics(self) -> dict[str, int]:
        """Get metrics about this dataloader's usage"""
        return {
            "load_count": self._load_count,
            "batch_count": self._batch_count,
            "avg_batch_size": (
                self._load_count / self._batch_count 
                if self._batch_count > 0 else 0
            )
        }


class RepositoryDataLoader(BaseDataLoader[K, V], Generic[K, V]):
    """
    Generic dataloader for repository-based loading.
    
    Usage:
        user_loader = RepositoryDataLoader(
            repository=user_repository,
            batch_load_fn=lambda repo, keys: repo.get_by_ids(keys)
        )
    """
    
    def __init__(
        self,
        repository: Any,
        batch_load_fn: Callable[[Any, list[K]], list[V | None]],
        key_fn: Callable[[V], K] | None = None
    ):
        """
        Initialize repository-based dataloader.
        
        Args:
            repository: The repository instance
            batch_load_fn: Function to load items from repository
            key_fn: Function to extract key from value (default: lambda x: x.id)
        """
        super().__init__(context=repository)
        self.repository = repository
        self.batch_load_fn = batch_load_fn
        self.key_fn = key_fn or (lambda x: x.id if hasattr(x, 'id') else None)
    
    async def batch_load(self, keys: list[K]) -> list[V | None]:
        """Load items from repository"""
        # Load all items
        items = await self.batch_load_fn(self.repository, keys)
        
        # Create a mapping
        item_map = {}
        for item in items:
            if item is not None:
                key = self.key_fn(item)
                if key is not None:
                    item_map[key] = item
        
        # Return in the same order as keys
        return [item_map.get(key) for key in keys]


class OneToManyDataLoader(BaseDataLoader[K, list[V]], Generic[K, V]):
    """
    Dataloader for one-to-many relationships.
    
    Usage:
        user_posts_loader = OneToManyDataLoader(
            repository=post_repository,
            batch_load_fn=lambda repo, user_ids: repo.get_by_user_ids(user_ids),
            group_by_fn=lambda post: post.user_id
        )
    """
    
    def __init__(
        self,
        repository: Any,
        batch_load_fn: Callable[[Any, list[K]], list[V]],
        group_by_fn: Callable[[V], K]
    ):
        """
        Initialize one-to-many dataloader.
        
        Args:
            repository: The repository instance
            batch_load_fn: Function to load all related items
            group_by_fn: Function to group items by parent key
        """
        super().__init__(context=repository)
        self.repository = repository
        self.batch_load_fn = batch_load_fn
        self.group_by_fn = group_by_fn
    
    async def batch_load(self, keys: list[K]) -> list[list[V]]:
        """Load related items for multiple parent keys"""
        # Load all related items
        all_items = await self.batch_load_fn(self.repository, keys)
        
        # Group by parent key
        grouped = defaultdict(list)
        for item in all_items:
            parent_key = self.group_by_fn(item)
            grouped[parent_key].append(item)
        
        # Return grouped results in the same order as keys
        return [grouped.get(key, []) for key in keys]


class ManyToManyDataLoader(BaseDataLoader[K, list[V]], Generic[K, V]):
    """
    Dataloader for many-to-many relationships.
    
    Usage:
        user_roles_loader = ManyToManyDataLoader(
            repository=role_repository,
            batch_load_fn=lambda repo, user_ids: repo.get_roles_for_users(user_ids),
            key_fn=lambda role: role.id,
            relationship_fn=lambda mapping: (mapping.user_id, mapping.role_id)
        )
    """
    
    def __init__(
        self,
        repository: Any,
        batch_load_fn: Callable[[Any, list[K]], tuple[list[V], list[Any]]],
        key_fn: Callable[[V], Any],
        relationship_fn: Callable[[Any], tuple[K, Any]]
    ):
        """
        Initialize many-to-many dataloader.
        
        Args:
            repository: The repository instance
            batch_load_fn: Function that returns (items, mappings)
            key_fn: Function to extract key from item
            relationship_fn: Function to extract (parent_key, item_key) from mapping
        """
        super().__init__(context=repository)
        self.repository = repository
        self.batch_load_fn = batch_load_fn
        self.key_fn = key_fn
        self.relationship_fn = relationship_fn
    
    async def batch_load(self, keys: list[K]) -> list[list[V]]:
        """Load related items for multiple parent keys"""
        # Load items and mappings
        items, mappings = await self.batch_load_fn(self.repository, keys)
        
        # Create item lookup
        item_map = {self.key_fn(item): item for item in items}
        
        # Group by parent key
        grouped = defaultdict(list)
        for mapping in mappings:
            parent_key, item_key = self.relationship_fn(mapping)
            if item_key in item_map:
                grouped[parent_key].append(item_map[item_key])
        
        # Return grouped results in the same order as keys
        return [grouped.get(key, []) for key in keys]


class CachedDataLoader(BaseDataLoader[K, V], Generic[K, V]):
    """
    Dataloader with caching support.
    
    Features:
    - In-memory caching with TTL
    - Cache invalidation
    - Cache warming
    """
    
    def __init__(
        self,
        base_loader: BaseDataLoader[K, V],
        cache_ttl: int = 300,  # 5 minutes default
        max_cache_size: int = 1000
    ):
        """
        Initialize cached dataloader.
        
        Args:
            base_loader: The underlying dataloader
            cache_ttl: Cache time-to-live in seconds
            max_cache_size: Maximum number of items to cache
        """
        super().__init__(context=base_loader.context)
        self.base_loader = base_loader
        self.cache_ttl = cache_ttl
        self.max_cache_size = max_cache_size
        self._cache: dict[K, tuple[V, float]] = {}
    
    async def batch_load(self, keys: list[K]) -> list[V | None]:
        """Load with caching"""
        import time
        current_time = time.time()
        
        # Separate cached and uncached keys
        uncached_keys = []
        key_to_index = {}
        results = [None] * len(keys)
        
        for i, key in enumerate(keys):
            if key in self._cache:
                value, timestamp = self._cache[key]
                if current_time - timestamp < self.cache_ttl:
                    results[i] = value
                else:
                    # Expired
                    del self._cache[key]
                    uncached_keys.append(key)
                    key_to_index[key] = i
            else:
                uncached_keys.append(key)
                key_to_index[key] = i
        
        # Load uncached keys
        if uncached_keys:
            uncached_values = await self.base_loader.batch_load(uncached_keys)
            
            # Update cache and results
            for key, value in zip(uncached_keys, uncached_values, strict=False):
                if value is not None:
                    # Add to cache
                    self._cache[key] = (value, current_time)
                    
                    # Enforce cache size limit (simple LRU)
                    if len(self._cache) > self.max_cache_size:
                        # Remove oldest entry
                        oldest_key = min(
                            self._cache.keys(),
                            key=lambda k: self._cache[k][1]
                        )
                        del self._cache[oldest_key]
                
                # Update results
                results[key_to_index[key]] = value
        
        return results
    
    def invalidate(self, key: K):
        """Invalidate a specific cache entry"""
        self._cache.pop(key, None)
    
    def invalidate_all(self):
        """Clear the entire cache"""
        self._cache.clear()


# ============================================================================
# DataLoader Registry
# ============================================================================

class DataLoaderRegistry:
    """
    Central registry for all dataloaders in the application.
    
    Usage:
        loaders = DataLoaderRegistry()
        loaders.register("user", user_loader)
        loaders.register("user_roles", user_roles_loader)
        
        # In resolver
        user = await info.context.loaders.get("user").load(user_id)
    """
    
    def __init__(self):
        self._loaders: dict[str, DataLoader] = {}
    
    def register(self, name: str, loader: DataLoader):
        """Register a dataloader"""
        self._loaders[name] = loader
        # Also set as attribute for dot notation access
        setattr(self, name, loader)
    
    def get(self, name: str) -> DataLoader | None:
        """Get a dataloader by name"""
        return self._loaders.get(name)
    
    def get_metrics(self) -> dict[str, dict[str, int]]:
        """Get metrics for all dataloaders"""
        metrics = {}
        for name, loader in self._loaders.items():
            if hasattr(loader, 'metrics'):
                metrics[name] = loader.metrics
        return metrics
    
    def clear_all(self):
        """Clear all dataloader caches"""
        for loader in self._loaders.values():
            if hasattr(loader, 'clear'):
                loader.clear()


# ============================================================================
# Context Helper
# ============================================================================

def create_loaders(container: Any) -> DataLoaderRegistry:
    """
    Create and configure all dataloaders for the application.
    
    This function should be called once per request to create fresh dataloaders.
    """
    registry = DataLoaderRegistry()
    
    # Import repositories from container
    from app.modules.identity.domain.interfaces import (
        IPermissionRepository,
        IRoleRepository,
        ISessionRepository,
        IUserRepository,
    )
    
    # User loader
    user_repo = container.resolve(IUserRepository)
    user_loader = RepositoryDataLoader(
        repository=user_repo,
        batch_load_fn=lambda repo, ids: repo.get_by_ids(ids)
    )
    registry.register("user", user_loader)
    
    # User roles loader (one-to-many)
    role_repo = container.resolve(IRoleRepository)
    user_roles_loader = OneToManyDataLoader(
        repository=role_repo,
        batch_load_fn=lambda repo, user_ids: repo.get_roles_for_users(user_ids),
        group_by_fn=lambda role_assignment: role_assignment.user_id
    )
    registry.register("user_roles", user_roles_loader)
    
    # Role permissions loader (many-to-many)
    permission_repo = container.resolve(IPermissionRepository)
    role_permissions_loader = ManyToManyDataLoader(
        repository=permission_repo,
        batch_load_fn=lambda repo, role_ids: repo.get_permissions_for_roles(role_ids),
        key_fn=lambda perm: perm.id,
        relationship_fn=lambda mapping: (mapping.role_id, mapping.permission_id)
    )
    registry.register("role_permissions", role_permissions_loader)
    
    # User sessions loader
    session_repo = container.resolve(ISessionRepository)
    user_sessions_loader = OneToManyDataLoader(
        repository=session_repo,
        batch_load_fn=lambda repo, user_ids: repo.get_active_sessions_for_users(user_ids),
        group_by_fn=lambda session: session.user_id
    )
    registry.register("user_sessions", user_sessions_loader)
    
    # Add more dataloaders as needed...
    
    return registry


__all__ = [
    # Base classes
    "BaseDataLoader",
    "CachedDataLoader",
    # Registry
    "DataLoaderRegistry",
    "ManyToManyDataLoader",
    "OneToManyDataLoader",
    "RepositoryDataLoader",
    "create_loaders",
]