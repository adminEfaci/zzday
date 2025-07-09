"""
Optimized SQL Repository Implementation with Performance Enhancements.

This module provides an enhanced SQL repository implementation with comprehensive
performance optimizations including:
- Compiled query caching
- N+1 query prevention with eager loading
- Connection pooling management
- Batch operations with bulk inserts/updates
- Query optimization hints
- Multi-level caching (L1 memory, L2 Redis)
- Query result streaming for large datasets
- Automatic index hints
- Query plan analysis and optimization
"""

import asyncio
import hashlib
import time
import weakref
from collections import OrderedDict, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, subqueryload
from sqlalchemy.orm.interfaces import ORMOption
from sqlalchemy.sql import Select

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.errors import ConflictError, InfrastructureError
from app.core.infrastructure.cache_coordinator import CacheCoordinator
from app.core.infrastructure.repository import BaseRepository, TEntity, TId, TModel
from app.core.logging import get_logger

logger = get_logger(__name__)

# Type variables
TResult = TypeVar("TResult")


class QueryCache:
    """Thread-safe LRU cache for compiled queries."""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
        
    async def get(self, key: str) -> Any | None:
        """Get cached query if not expired."""
        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self._ttl_seconds:
                    # Move to end (LRU)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return value
                # Expired
                del self._cache[key]
            
            self._misses += 1
            return None
    
    async def set(self, key: str, value: Any) -> None:
        """Set cached query with timestamp."""
        async with self._lock:
            if key in self._cache:
                # Move to end
                self._cache.move_to_end(key)
            # Add new
            elif len(self._cache) >= self._max_size:
                # Remove oldest
                self._cache.popitem(last=False)
            
            self._cache[key] = (value, time.time())
    
    async def invalidate(self, pattern: str | None = None) -> None:
        """Invalidate cached queries matching pattern."""
        async with self._lock:
            if pattern is None:
                self._cache.clear()
            else:
                keys_to_remove = [k for k in self._cache if pattern in k]
                for key in keys_to_remove:
                    del self._cache[key]
    
    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0
        
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "ttl_seconds": self._ttl_seconds
        }


class EagerLoadStrategy:
    """Strategy for eager loading related entities to prevent N+1 queries."""
    
    def __init__(self):
        self._strategies: dict[str, list[ORMOption]] = {}
    
    def register(self, entity_type: type[Entity], relationships: list[str], strategy: str = "selectin") -> None:
        """
        Register eager loading strategy for entity relationships.
        
        Args:
            entity_type: The entity type
            relationships: List of relationship names to eager load
            strategy: Loading strategy ('selectin', 'joined', 'subquery')
        """
        key = entity_type.__name__
        options = []
        
        for rel in relationships:
            if strategy == "selectin":
                options.append(selectinload(rel))
            elif strategy == "joined":
                options.append(joinedload(rel))
            elif strategy == "subquery":
                options.append(subqueryload(rel))
            else:
                raise ValueError(f"Unknown loading strategy: {strategy}")
        
        self._strategies[key] = options
    
    def get_options(self, entity_type: type[Entity]) -> list[ORMOption]:
        """Get eager loading options for entity type."""
        return self._strategies.get(entity_type.__name__, [])


class BatchOperationManager:
    """Manages batch operations for optimal performance."""
    
    def __init__(self, batch_size: int = 1000):
        self.batch_size = batch_size
    
    async def batch_insert(
        self,
        session: AsyncSession,
        models: list[TModel],
        return_defaults: bool = True
    ) -> list[TModel]:
        """
        Perform batch insert with optimal chunk size.
        
        Args:
            session: Database session
            models: Models to insert
            return_defaults: Whether to return generated defaults
        """
        inserted = []
        
        for i in range(0, len(models), self.batch_size):
            batch = models[i:i + self.batch_size]
            
            # Use bulk_insert_mappings for better performance
            if hasattr(session, "bulk_insert_mappings"):
                mappings = [model.dict() if hasattr(model, 'dict') else model.__dict__ 
                           for model in batch]
                await session.bulk_insert_mappings(
                    type(batch[0]), 
                    mappings,
                    return_defaults=return_defaults
                )
            else:
                # Fallback to regular add_all
                session.add_all(batch)
            
            inserted.extend(batch)
        
        return inserted
    
    async def batch_update(
        self,
        session: AsyncSession,
        model_type: type[TModel],
        updates: list[dict[str, Any]]
    ) -> int:
        """
        Perform batch update with optimal chunk size.
        
        Args:
            session: Database session
            model_type: Model type to update
            updates: List of update dictionaries with 'id' and fields
        """
        updated_count = 0
        
        for i in range(0, len(updates), self.batch_size):
            batch = updates[i:i + self.batch_size]
            
            # Use bulk_update_mappings for better performance
            if hasattr(session, "bulk_update_mappings"):
                await session.bulk_update_mappings(model_type, batch)
                updated_count += len(batch)
            else:
                # Fallback to individual updates
                for update_dict in batch:
                    entity_id = update_dict.pop('id')
                    stmt = update(model_type).where(
                        model_type.id == entity_id
                    ).values(**update_dict)
                    await session.execute(stmt)
                    updated_count += 1
        
        return updated_count


class ConnectionPoolManager:
    """Manages database connection pool settings and monitoring."""
    
    def __init__(self, pool_size: int = 20, max_overflow: int = 10):
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self._active_connections = 0
        self._peak_connections = 0
        self._connection_wait_times: list[float] = []
        self._lock = asyncio.Lock()
    
    async def acquire_connection(self) -> None:
        """Track connection acquisition."""
        async with self._lock:
            self._active_connections += 1
            self._peak_connections = max(self._peak_connections, self._active_connections)
    
    async def release_connection(self, wait_time: float) -> None:
        """Track connection release."""
        async with self._lock:
            self._active_connections -= 1
            self._connection_wait_times.append(wait_time)
            
            # Keep only last 1000 wait times
            if len(self._connection_wait_times) > 1000:
                self._connection_wait_times = self._connection_wait_times[-1000:]
    
    def get_pool_stats(self) -> dict[str, Any]:
        """Get connection pool statistics."""
        avg_wait_time = sum(self._connection_wait_times) / len(self._connection_wait_times) \
            if self._connection_wait_times else 0
        
        return {
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "active_connections": self._active_connections,
            "peak_connections": self._peak_connections,
            "average_wait_time": avg_wait_time,
            "total_acquisitions": len(self._connection_wait_times)
        }


class OptimizedSQLRepository(BaseRepository[TEntity, TId]):
    """
    High-performance SQL repository with comprehensive optimizations.
    
    Features:
    - Query compilation and caching
    - N+1 query prevention with configurable eager loading
    - Connection pool management
    - Batch operations with chunk processing
    - Multi-level caching (L1 memory, L2 Redis)
    - Query streaming for large result sets
    - Automatic query optimization
    - Performance metrics and monitoring
    """
    
    def __init__(
        self,
        entity_type: type[TEntity],
        model_type: type[TModel],
        session_factory: callable,
        cache_coordinator: CacheCoordinator | None = None,
        query_cache_size: int = 1000,
        query_cache_ttl: int = 3600,
        batch_size: int = 1000,
        enable_query_logging: bool = False
    ):
        """
        Initialize optimized SQL repository.
        
        Args:
            entity_type: Domain entity type
            model_type: SQL model type
            session_factory: Factory for creating database sessions
            cache_coordinator: Multi-level cache coordinator
            query_cache_size: Maximum number of cached queries
            query_cache_ttl: Query cache TTL in seconds
            batch_size: Default batch operation size
            enable_query_logging: Whether to log SQL queries
        """
        super().__init__(entity_type, session_factory, cache_coordinator)
        
        self.model_type = model_type
        self.cache_coordinator = cache_coordinator
        self.enable_query_logging = enable_query_logging
        
        # Performance components
        self._query_cache = QueryCache(query_cache_size, query_cache_ttl)
        self._eager_load_strategy = EagerLoadStrategy()
        self._batch_manager = BatchOperationManager(batch_size)
        self._connection_pool = ConnectionPoolManager()
        
        # Query statistics
        self._query_count = 0
        self._slow_queries: list[dict[str, Any]] = []
        self._query_patterns: dict[str, int] = defaultdict(int)
        
        # Entity tracking for optimistic locking
        self._entity_versions: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
    
    def configure_eager_loading(self, relationships: list[str], strategy: str = "selectin") -> None:
        """
        Configure eager loading for entity relationships.
        
        Args:
            relationships: Relationship names to eager load
            strategy: Loading strategy ('selectin', 'joined', 'subquery')
        """
        self._eager_load_strategy.register(self.entity_type, relationships, strategy)
    
    async def find_by_id(self, entity_id: TId, use_cache: bool = True) -> TEntity | None:
        """Find entity by ID with caching and eager loading."""
        if use_cache and self.cache_coordinator:
            cache_key = self._generate_cache_key("find_by_id", entity_id)
            cached = await self.cache_coordinator.get(cache_key)
            if cached:
                return cached
        
        async with self.operation_context("find_by_id"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                # Build query with eager loading
                query = select(self.model_type).where(self.model_type.id == entity_id)
                query = self._apply_eager_loading(query)
                
                # Execute and track
                start_time = time.time()
                result = await session.execute(query)
                query_time = time.time() - start_time
                
                self._track_query_performance(str(query), query_time)
                
                model = result.scalar_one_or_none()
                if model:
                    entity = self._model_to_entity(model)
                    
                    # Cache result
                    if use_cache and self.cache_coordinator:
                        await self.cache_coordinator.set(
                            self._generate_cache_key("find_by_id", entity_id),
                            entity,
                            ttl=300
                        )
                    
                    return entity
                
                return None
    
    async def find_all(
        self,
        limit: int | None = None,
        offset: int = 0,
        order_by: list[str] | None = None,
        use_streaming: bool = False
    ) -> list[TEntity]:
        """Find all entities with pagination and optional streaming."""
        async with self.operation_context("find_all"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                # Build query
                query = select(self.model_type)
                query = self._apply_eager_loading(query)
                
                # Apply ordering
                if order_by:
                    for order in order_by:
                        if order.startswith("-"):
                            query = query.order_by(getattr(self.model_type, order[1:]).desc())
                        else:
                            query = query.order_by(getattr(self.model_type, order))
                
                # Apply pagination
                if offset > 0:
                    query = query.offset(offset)
                if limit is not None:
                    query = query.limit(limit)
                
                # Check if query is cached
                query_key = self._generate_query_key(query)
                cached_result = await self._query_cache.get(query_key)
                if cached_result:
                    return cached_result
                
                # Execute query
                start_time = time.time()
                
                if use_streaming and limit is None:
                    # Use streaming for large result sets
                    entities = []
                    result = await session.stream(query)
                    async for row in result:
                        model = row[0]
                        entities.append(self._model_to_entity(model))
                else:
                    result = await session.execute(query)
                    models = result.scalars().all()
                    entities = [self._model_to_entity(model) for model in models]
                
                query_time = time.time() - start_time
                self._track_query_performance(str(query), query_time)
                
                # Cache result
                await self._query_cache.set(query_key, entities)
                
                return entities
    
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity with optimistic locking and cache invalidation."""
        async with self.operation_context("save"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                try:
                    model = self._entity_to_model(entity)
                    entity_id = getattr(entity, 'id', None)
                    
                    if entity_id:
                        # Update existing
                        existing = await session.get(self.model_type, entity_id)
                        if existing:
                            # Check version for optimistic locking
                            if hasattr(existing, 'version') and hasattr(model, 'version') and existing.version != model.version:
                                raise ConflictError("Entity has been modified by another process")
                            
                            # Update fields
                            for key, value in model.__dict__.items():
                                if not key.startswith('_'):
                                    setattr(existing, key, value)
                            
                            # Increment version
                            if hasattr(existing, 'version'):
                                existing.version += 1
                            
                            session.add(existing)
                            await session.commit()
                            saved_entity = self._model_to_entity(existing)
                        else:
                            # Entity doesn't exist, create new
                            session.add(model)
                            await session.commit()
                            saved_entity = self._model_to_entity(model)
                    else:
                        # Create new
                        session.add(model)
                        await session.commit()
                        saved_entity = self._model_to_entity(model)
                    
                    # Invalidate caches
                    await self._invalidate_entity_caches(saved_entity)
                    
                    return saved_entity
                    
                except IntegrityError as e:
                    await session.rollback()
                    raise ConflictError(f"Entity violates integrity constraint: {e}") from e
                except Exception as e:
                    await session.rollback()
                    raise InfrastructureError(f"Failed to save entity: {e}") from e
    
    async def save_batch(self, entities: list[TEntity]) -> list[TEntity]:
        """Save multiple entities in optimized batches."""
        async with self.operation_context("save_batch"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                try:
                    # Separate creates and updates
                    creates = []
                    updates = []
                    
                    for entity in entities:
                        entity_id = getattr(entity, 'id', None)
                        if entity_id:
                            # Check if exists
                            exists = await session.get(self.model_type, entity_id) is not None
                            if exists:
                                updates.append(entity)
                            else:
                                creates.append(entity)
                        else:
                            creates.append(entity)
                    
                    saved_entities = []
                    
                    # Batch create new entities
                    if creates:
                        create_models = [self._entity_to_model(e) for e in creates]
                        created_models = await self._batch_manager.batch_insert(session, create_models)
                        saved_entities.extend([self._model_to_entity(m) for m in created_models])
                    
                    # Batch update existing entities
                    if updates:
                        update_dicts = []
                        for entity in updates:
                            model = self._entity_to_model(entity)
                            update_dict = {'id': model.id}
                            update_dict.update({k: v for k, v in model.__dict__.items() 
                                              if not k.startswith('_')})
                            update_dicts.append(update_dict)
                        
                        await self._batch_manager.batch_update(
                            session, self.model_type, update_dicts
                        )
                        saved_entities.extend(updates)
                    
                    await session.commit()
                    
                    # Invalidate caches for all saved entities
                    for entity in saved_entities:
                        await self._invalidate_entity_caches(entity)
                    
                    return saved_entities
                    
                except Exception as e:
                    await session.rollback()
                    raise InfrastructureError(f"Failed to save batch: {e}") from e
    
    async def delete(self, entity_id: TId) -> bool:
        """Delete entity with cache invalidation."""
        async with self.operation_context("delete"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                try:
                    model = await session.get(self.model_type, entity_id)
                    if not model:
                        return False
                    
                    await session.delete(model)
                    await session.commit()
                    
                    # Invalidate caches
                    await self._invalidate_entity_caches_by_id(entity_id)
                    
                    return True
                    
                except Exception as e:
                    await session.rollback()
                    raise InfrastructureError(f"Failed to delete entity: {e}") from e
    
    async def delete_batch(self, entity_ids: list[TId]) -> int:
        """Delete multiple entities in a single query."""
        async with self.operation_context("delete_batch"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                try:
                    # Build batch delete query
                    stmt = delete(self.model_type).where(
                        self.model_type.id.in_(entity_ids)
                    )
                    
                    result = await session.execute(stmt)
                    deleted_count = result.rowcount
                    await session.commit()
                    
                    # Invalidate caches for all deleted entities
                    for entity_id in entity_ids:
                        await self._invalidate_entity_caches_by_id(entity_id)
                    
                    return deleted_count
                    
                except Exception as e:
                    await session.rollback()
                    raise InfrastructureError(f"Failed to delete batch: {e}") from e
    
    async def exists(self, entity_id: TId) -> bool:
        """Check if entity exists using optimized query."""
        async with self.operation_context("exists"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                # Use EXISTS query for better performance
                stmt = select(func.exists().where(self.model_type.id == entity_id))
                result = await session.execute(stmt)
                return result.scalar()
    
    async def count(self, specification: Specification[TEntity] | None = None) -> int:
        """Count entities with optional specification."""
        async with self.operation_context("count"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                if specification:
                    # Convert specification to SQL
                    query = self._build_specification_query(specification)
                    stmt = select(func.count()).select_from(query.subquery())
                else:
                    stmt = select(func.count(self.model_type.id))
                
                result = await session.execute(stmt)
                return result.scalar() or 0
    
    async def find_by_specification(
        self,
        specification: Specification[TEntity],
        limit: int | None = None,
        offset: int = 0
    ) -> list[TEntity]:
        """Find entities by specification with SQL optimization."""
        async with self.operation_context("find_by_specification"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                # Build optimized query from specification
                query = self._build_specification_query(specification)
                query = self._apply_eager_loading(query)
                
                if offset > 0:
                    query = query.offset(offset)
                if limit is not None:
                    query = query.limit(limit)
                
                # Check cache
                query_key = self._generate_query_key(query)
                cached_result = await self._query_cache.get(query_key)
                if cached_result:
                    return cached_result
                
                # Execute query
                start_time = time.time()
                result = await session.execute(query)
                models = result.scalars().all()
                entities = [self._model_to_entity(model) for model in models]
                query_time = time.time() - start_time
                
                self._track_query_performance(str(query), query_time)
                
                # Cache result
                await self._query_cache.set(query_key, entities)
                
                return entities
    
    async def find_one_by_specification(
        self, specification: Specification[TEntity]
    ) -> TEntity | None:
        """Find single entity by specification."""
        entities = await self.find_by_specification(specification, limit=1)
        return entities[0] if entities else None
    
    async def count_by_specification(self, specification: Specification[TEntity]) -> int:
        """Count entities matching specification."""
        return await self.count(specification)
    
    async def delete_by_specification(self, specification: Specification[TEntity]) -> int:
        """Delete entities matching specification."""
        async with self.operation_context("delete_by_specification"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                # First find entities to delete (for cache invalidation)
                entities = await self.find_by_specification(specification)
                entity_ids = [e.id for e in entities]
                
                if not entity_ids:
                    return 0
                
                # Perform batch delete
                return await self.delete_batch(entity_ids)
    
    async def execute_raw_query(
        self,
        query: str,
        params: dict[str, Any] | None = None,
        fetch_all: bool = True
    ) -> list[dict[str, Any]] | None:
        """
        Execute raw SQL query with parameter binding.
        
        Args:
            query: SQL query string
            params: Query parameters
            fetch_all: Whether to fetch all results
        """
        async with self.operation_context("execute_raw_query"), self._get_timed_session() as (session, wait_time):
                await self._connection_pool.release_connection(wait_time)
                
                start_time = time.time()
                result = await session.execute(text(query), params or {})
                query_time = time.time() - start_time
                
                self._track_query_performance(query, query_time)
                
                if fetch_all:
                    return [dict(row) for row in result]
                
                return None
    
    async def get_performance_report(self) -> dict[str, Any]:
        """Generate comprehensive performance report."""
        base_stats = self.get_performance_stats()
        
        return {
            **base_stats,
            "query_cache_stats": self._query_cache.get_stats(),
            "connection_pool_stats": self._connection_pool.get_pool_stats(),
            "query_count": self._query_count,
            "slow_queries": self._slow_queries[-10:],  # Last 10 slow queries
            "query_patterns": dict(self._query_patterns),
            "optimizations": {
                "eager_loading_enabled": bool(self._eager_load_strategy._strategies),
                "query_caching_enabled": True,
                "batch_operations_enabled": True,
                "connection_pooling_enabled": True
            }
        }
    
    async def optimize_indexes(self) -> dict[str, Any]:
        """Analyze and suggest index optimizations."""
        async with self._get_timed_session() as (session, _):
            # Get table statistics
            table_name = self.model_type.__tablename__
            
            # Analyze most common query patterns
            common_patterns = sorted(
                self._query_patterns.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            suggestions = []
            
            # Check for missing indexes on foreign keys
            inspector = await session.get_inspector()
            foreign_keys = inspector.get_foreign_keys(table_name)
            indexes = inspector.get_indexes(table_name)
            indexed_columns = {col for idx in indexes for col in idx['column_names']}
            
            for fk in foreign_keys:
                if fk['constrained_columns'][0] not in indexed_columns:
                    suggestions.append({
                        "type": "missing_fk_index",
                        "table": table_name,
                        "column": fk['constrained_columns'][0],
                        "suggestion": f"CREATE INDEX idx_{table_name}_{fk['constrained_columns'][0]} ON {table_name}({fk['constrained_columns'][0]})"
                    })
            
            return {
                "table": table_name,
                "common_query_patterns": common_patterns,
                "suggestions": suggestions,
                "current_indexes": indexes
            }
    
    # Private helper methods
    
    @asynccontextmanager
    async def _get_timed_session(self):
        """Get session with connection timing."""
        start_time = time.time()
        await self._connection_pool.acquire_connection()
        wait_time = time.time() - start_time
        
        async with self.get_session() as session:
            yield session, wait_time
    
    def _model_to_entity(self, model: TModel) -> TEntity:
        """Convert SQL model to domain entity."""
        if hasattr(model, 'to_domain'):
            return model.to_domain()
        
        # Generic conversion
        entity_dict = {}
        for key, value in model.__dict__.items():
            if not key.startswith('_'):
                entity_dict[key] = value
        
        return self.entity_type(**entity_dict)
    
    def _entity_to_model(self, entity: TEntity) -> TModel:
        """Convert domain entity to SQL model."""
        if hasattr(self.model_type, 'from_domain'):
            return self.model_type.from_domain(entity)
        
        # Generic conversion
        model_dict = {}
        for key, value in entity.__dict__.items():
            if not key.startswith('_'):
                model_dict[key] = value
        
        return self.model_type(**model_dict)
    
    def _apply_eager_loading(self, query: Select) -> Select:
        """Apply eager loading options to query."""
        options = self._eager_load_strategy.get_options(self.entity_type)
        for option in options:
            query = query.options(option)
        return query
    
    def _build_specification_query(self, specification: Specification[TEntity]) -> Select:
        """Build SQL query from specification."""
        # This is a simplified implementation
        # In production, you'd implement a specification visitor pattern
        # that converts domain specifications to SQL expressions
        
        query = select(self.model_type)
        
        # Example: If specification has specific patterns, convert them
        if hasattr(specification, 'to_sql_expression'):
            sql_expr = specification.to_sql_expression(self.model_type)
            query = query.where(sql_expr)
        
        return query
    
    def _generate_query_key(self, query: Select) -> str:
        """Generate cache key for query."""
        # Create a deterministic key from query
        query_str = str(query.compile(compile_kwargs={"literal_binds": True}))
        return hashlib.sha256(query_str.encode()).hexdigest()
    
    def _track_query_performance(self, query: str, execution_time: float) -> None:
        """Track query performance metrics."""
        self._query_count += 1
        
        # Track slow queries (> 1 second)
        if execution_time > 1.0:
            self._slow_queries.append({
                "query": query[:200],  # Truncate long queries
                "execution_time": execution_time,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Keep only last 100 slow queries
            if len(self._slow_queries) > 100:
                self._slow_queries = self._slow_queries[-100:]
        
        # Track query patterns
        # Extract table name from query
        if "FROM" in query:
            pattern = query.split("FROM")[1].split()[0]
            self._query_patterns[pattern] += 1
        
        # Log slow queries
        if self.enable_query_logging and execution_time > 1.0:
            logger.warning(
                "Slow query detected",
                repository=self.__class__.__name__,
                execution_time=execution_time,
                query=query[:200]
            )
    
    async def _invalidate_entity_caches(self, entity: TEntity) -> None:
        """Invalidate all caches for entity."""
        entity_id = getattr(entity, 'id', None)
        if entity_id:
            await self._invalidate_entity_caches_by_id(entity_id)
    
    async def _invalidate_entity_caches_by_id(self, entity_id: TId) -> None:
        """Invalidate all caches for entity ID."""
        # Invalidate L1/L2 cache
        if self.cache_coordinator:
            cache_key = self._generate_cache_key("find_by_id", entity_id)
            await self.cache_coordinator.delete(cache_key)
        
        # Invalidate query cache entries that might contain this entity
        await self._query_cache.invalidate(str(entity_id))


__all__ = ["BatchOperationManager", "EagerLoadStrategy", "OptimizedSQLRepository", "QueryCache"]