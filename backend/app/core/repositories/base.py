"""Enhanced repository base interfaces and implementations.

Provides comprehensive repository patterns with specification support,
advanced querying, caching, and transaction management.
"""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Generic, TypeVar

# Handle missing domain components
try:
    from app.core.domain.base import AggregateRoot, Entity
except ImportError:
    from abc import ABC
    from datetime import datetime
    from uuid import UUID
    
    class Entity(ABC):
        """Fallback entity base class."""
        def __init__(self):
            self.id: UUID | None = None
            self.created_at: datetime | None = None
            self.updated_at: datetime | None = None
    
    class AggregateRoot(Entity):
        """Fallback aggregate root base class."""
        def get_events(self):
            return []
        
        def clear_events(self):
            pass

# Handle missing specification pattern
try:
    from app.core.domain.specification import Specification
except ImportError:
    from abc import ABC, abstractmethod
    from typing import Generic
    
    # Define TEntity for fallback specification classes
    TEntity = TypeVar("TEntity")
    
    class Specification(ABC, Generic[TEntity]):
        """Fallback specification interface."""
        
        @abstractmethod
        def is_satisfied_by(self, entity: TEntity) -> bool:
            """Check if entity satisfies specification."""
        
        def and_(self, other: "Specification[TEntity]") -> "Specification[TEntity]":
            """Combine with AND logic."""
            return AndSpecification(self, other)
        
        def or_(self, other: "Specification[TEntity]") -> "Specification[TEntity]":
            """Combine with OR logic."""
            return OrSpecification(self, other)
    
    class AndSpecification(Specification[TEntity]):
        def __init__(self, left: Specification[TEntity], right: Specification[TEntity]):
            self.left = left
            self.right = right
        
        def is_satisfied_by(self, entity: TEntity) -> bool:
            return self.left.is_satisfied_by(entity) and self.right.is_satisfied_by(entity)
    
    class OrSpecification(Specification[TEntity]):
        def __init__(self, left: Specification[TEntity], right: Specification[TEntity]):
            self.left = left
            self.right = right
        
        def is_satisfied_by(self, entity: TEntity) -> bool:
            return self.left.is_satisfied_by(entity) or self.right.is_satisfied_by(entity)

from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Type variables
TEntity = TypeVar("TEntity", bound=Entity)
TAggregate = TypeVar("TAggregate", bound=AggregateRoot)
TId = TypeVar("TId")


class IRepository(ABC, Generic[TEntity, TId]):
    """Enhanced repository interface with comprehensive functionality."""

    @abstractmethod
    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """Find entity by ID."""

    @abstractmethod
    async def find_all(
        self,
        limit: int | None = None,
        offset: int = 0,
        order_by: str | None = None,
        order_desc: bool = False,
    ) -> list[TEntity]:
        """Find all entities with pagination and ordering."""

    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity (create or update)."""

    @abstractmethod
    async def delete(self, entity_id: TId) -> bool:
        """Delete entity by ID."""

    @abstractmethod
    async def exists(self, entity_id: TId) -> bool:
        """Check if entity exists."""

    @abstractmethod
    async def count(self) -> int:
        """Count total entities."""

    @abstractmethod
    async def batch_save(self, entities: list[TEntity]) -> list[TEntity]:
        """Save multiple entities efficiently."""

    @abstractmethod
    async def batch_delete(self, entity_ids: list[TId]) -> int:
        """Delete multiple entities efficiently."""


class ISpecificationRepository(IRepository[TEntity, TId], ABC):
    """Repository interface with specification pattern support."""

    @abstractmethod
    async def find_by_specification(
        self,
        specification: Specification[TEntity],
        limit: int | None = None,
        offset: int = 0,
        order_by: str | None = None,
        order_desc: bool = False,
    ) -> list[TEntity]:
        """Find entities matching specification."""

    @abstractmethod
    async def find_one_by_specification(
        self, specification: Specification[TEntity]
    ) -> TEntity | None:
        """Find single entity matching specification."""

    @abstractmethod
    async def count_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Count entities matching specification."""

    @abstractmethod
    async def delete_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Delete entities matching specification."""


class IUnitOfWork(ABC):
    """Unit of Work interface for transaction management."""

    @abstractmethod
    async def __aenter__(self) -> "IUnitOfWork":
        """Enter context."""

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context."""

    @abstractmethod
    async def commit(self) -> None:
        """Commit changes."""

    @abstractmethod
    async def rollback(self) -> None:
        """Rollback changes."""

    @abstractmethod
    def get_repository(self, entity_type: type[TEntity]) -> IRepository[TEntity, Any]:
        """Get repository for entity type."""


class IRepositoryFactory(ABC):
    """Factory interface for creating repository instances."""

    @abstractmethod
    def create_repository(
        self, entity_type: type[TEntity]
    ) -> IRepository[TEntity, Any]:
        """Create repository for entity type."""

    @abstractmethod
    def create_unit_of_work(self) -> IUnitOfWork:
        """Create unit of work instance."""

    @abstractmethod
    def register_repository(
        self, entity_type: type[TEntity], repository_type: type[IRepository]
    ) -> None:
        """Register repository implementation for entity type."""


class BaseRepository(ISpecificationRepository[TEntity, TId]):
    """Enhanced base repository implementation."""

    def __init__(
        self,
        entity_type: type[TEntity],
        session_factory: Callable,
        cache: Any | None = None,
        event_publisher: Any | None = None,
    ):
        """Initialize repository."""
        self.entity_type = entity_type
        self.session_factory = session_factory
        self.cache = cache
        self.event_publisher = event_publisher

        # Performance tracking
        self._operation_count = 0
        self._total_operation_time = 0.0
        self._error_count = 0
        self._cache_hits = 0
        self._cache_misses = 0

        # Repository metadata
        self._created_at = datetime.utcnow()

    @asynccontextmanager
    async def get_session(self):
        """Get database session with error handling."""
        session = None
        try:
            session = self.session_factory()
            yield session
        except Exception as e:
            if session:
                await self._handle_session_error(session, e)
            raise InfrastructureError(f"Database session error: {e!s}")
        finally:
            if session:
                await self._cleanup_session(session)

    async def _handle_session_error(self, session, error: Exception) -> None:
        """Handle session errors with cleanup."""
        try:
            if hasattr(session, "rollback"):
                if asyncio.iscoroutinefunction(session.rollback):
                    await session.rollback()
                else:
                    session.rollback()
        except Exception as rollback_error:
            logger.exception(
                "Failed to rollback session after error",
                repository=self.__class__.__name__,
                original_error=str(error),
                rollback_error=str(rollback_error),
            )

    async def _cleanup_session(self, session) -> None:
        """Clean up database session."""
        try:
            if hasattr(session, "close"):
                if asyncio.iscoroutinefunction(session.close):
                    await session.close()
                else:
                    session.close()
        except Exception as e:
            logger.exception(
                "Failed to close database session",
                repository=self.__class__.__name__,
                error=str(e),
            )

    @asynccontextmanager
    async def operation_context(self, operation_name: str):
        """Context manager for tracking operations."""
        import time

        start_time = time.time()

        logger.debug(
            "Starting repository operation",
            repository=self.__class__.__name__,
            operation=operation_name,
            entity_type=self.entity_type.__name__,
        )

        try:
            yield

            execution_time = time.time() - start_time
            self._operation_count += 1
            self._total_operation_time += execution_time

            logger.debug(
                "Repository operation completed",
                repository=self.__class__.__name__,
                operation=operation_name,
                execution_time=execution_time,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self._error_count += 1
            self._total_operation_time += execution_time

            logger.exception(
                "Repository operation failed",
                repository=self.__class__.__name__,
                operation=operation_name,
                error=str(e),
                execution_time=execution_time,
            )
            raise

    async def _get_from_cache(self, cache_key: str) -> Any | None:
        """Get item from cache."""
        if not self.cache:
            return None

        try:
            if hasattr(self.cache, "get"):
                if asyncio.iscoroutinefunction(self.cache.get):
                    result = await self.cache.get(cache_key)
                else:
                    result = self.cache.get(cache_key)
                
                if result is not None:
                    self._cache_hits += 1
                    return result

            self._cache_misses += 1
            return None

        except Exception as e:
            logger.warning(
                "Cache get operation failed",
                repository=self.__class__.__name__,
                cache_key=cache_key,
                error=str(e),
            )
            self._cache_misses += 1
            return None

    async def _set_cache(
        self, cache_key: str, item: Any, ttl: int | None = None
    ) -> None:
        """Set item in cache."""
        if not self.cache:
            return

        try:
            if hasattr(self.cache, "set"):
                if asyncio.iscoroutinefunction(self.cache.set):
                    if ttl:
                        await self.cache.set(cache_key, item, ttl)
                    else:
                        await self.cache.set(cache_key, item)
                elif ttl:
                    self.cache.set(cache_key, item, ttl)
                else:
                    self.cache.set(cache_key, item)
        except Exception as e:
            logger.warning(
                "Cache set operation failed",
                repository=self.__class__.__name__,
                cache_key=cache_key,
                error=str(e),
            )

    def _generate_cache_key(self, operation: str, *args) -> str:
        """Generate cache key for operation."""
        key_parts = [self.__class__.__name__, self.entity_type.__name__, operation]
        key_parts.extend(str(arg) for arg in args)
        return ":".join(key_parts)

    async def invalidate_cache_for_entity(self, entity_id: TId) -> None:
        """Invalidate cache entries for entity."""
        if not self.cache:
            return

        cache_keys = [
            self._generate_cache_key("find_by_id", entity_id),
            # Add other cache keys that should be invalidated
        ]

        for cache_key in cache_keys:
            try:
                if hasattr(self.cache, "delete"):
                    if asyncio.iscoroutinefunction(self.cache.delete):
                        await self.cache.delete(cache_key)
                    else:
                        self.cache.delete(cache_key)
            except Exception as e:
                logger.warning(
                    "Cache invalidation failed", cache_key=cache_key, error=str(e)
                )

    async def _publish_events(self, entity: TEntity) -> None:
        """Publish domain events if entity has them."""
        if not self.event_publisher:
            return

        if hasattr(entity, "get_events"):
            events = entity.get_events()
            if events:
                try:
                    await self.event_publisher.publish(events)
                    # Clear events after publishing
                    if hasattr(entity, "clear_events"):
                        entity.clear_events()
                except Exception as e:
                    logger.exception(
                        "Failed to publish domain events",
                        entity_type=self.entity_type.__name__,
                        entity_id=str(getattr(entity, "id", "unknown")),
                        error=str(e),
                    )

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics."""
        avg_time = self._total_operation_time / max(self._operation_count, 1)
        error_rate = self._error_count / max(self._operation_count, 1)
        cache_hit_rate = self._cache_hits / max(
            self._cache_hits + self._cache_misses, 1
        )

        return {
            "repository_class": self.__class__.__name__,
            "entity_type": self.entity_type.__name__,
            "created_at": self._created_at.isoformat(),
            "operation_count": self._operation_count,
            "error_count": self._error_count,
            "total_operation_time": self._total_operation_time,
            "average_operation_time": avg_time,
            "error_rate": error_rate,
            "cache_enabled": self.cache is not None,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": cache_hit_rate,
        }


class SpecificationRepository(BaseRepository[TEntity, TId]):
    """Repository with advanced specification support."""

    def __init__(
        self,
        entity_type: type[TEntity],
        session_factory: Callable,
        cache: Any | None = None,
        event_publisher: Any | None = None,
        query_optimizer: Any | None = None,
    ):
        """Initialize specification repository."""
        super().__init__(entity_type, session_factory, cache, event_publisher)
        self.query_optimizer = query_optimizer

    async def find_by_specifications(
        self,
        specifications: list[Specification[TEntity]],
        combine_with_and: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[TEntity]:
        """Find entities matching multiple specifications."""
        if not specifications:
            return await self.find_all(limit=limit, offset=offset)

        # Combine specifications
        if len(specifications) == 1:
            combined_spec = specifications[0]
        else:
            combined_spec = specifications[0]
            for spec in specifications[1:]:
                if combine_with_and:
                    combined_spec = combined_spec.and_(spec)
                else:
                    combined_spec = combined_spec.or_(spec)

        return await self.find_by_specification(
            combined_spec, limit=limit, offset=offset
        )

    async def find_with_complex_query(
        self,
        filters: dict[str, Any] | None = None,
        specification: Specification[TEntity] | None = None,
        order_by: str | None = None,
        order_desc: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[TEntity]:
        """Find entities with complex query combining filters and specifications."""
        # This is a placeholder - actual implementation would depend on the ORM
        # For now, delegate to specification-based query
        if specification:
            return await self.find_by_specification(
                specification,
                limit=limit,
                offset=offset,
                order_by=order_by,
                order_desc=order_desc,
            )
        return await self.find_all(
            limit=limit, offset=offset, order_by=order_by, order_desc=order_desc
        )


class RepositoryFactory(IRepositoryFactory):
    """Enhanced repository factory with dependency injection."""

    def __init__(self):
        """Initialize factory."""
        self._session_factory = None
        self._cache = None
        self._event_publisher = None
        self._registered_repositories: dict[type, type] = {}
        self._repository_instances: dict[type, IRepository] = {}
        self._singleton_mode = False

    def configure(
        self,
        session_factory: Callable,
        cache: Any | None = None,
        event_publisher: Any | None = None,
        singleton_mode: bool = False,
    ) -> None:
        """Configure factory dependencies."""
        self._session_factory = session_factory
        self._cache = cache
        self._event_publisher = event_publisher
        self._singleton_mode = singleton_mode

    def register_repository(
        self, entity_type: type[TEntity], repository_type: type[IRepository]
    ) -> None:
        """Register repository implementation."""
        self._registered_repositories[entity_type] = repository_type

    def create_repository(
        self, entity_type: type[TEntity]
    ) -> IRepository[TEntity, Any]:
        """Create repository instance."""
        if self._singleton_mode and entity_type in self._repository_instances:
            return self._repository_instances[entity_type]

        if entity_type not in self._registered_repositories:
            raise InfrastructureError(
                f"No repository registered for entity type {entity_type.__name__}"
            )

        repository_type = self._registered_repositories[entity_type]

        # Create repository with dependencies
        repository = repository_type(
            entity_type=entity_type,
            session_factory=self._session_factory,
            cache=self._cache,
            event_publisher=self._event_publisher,
        )

        if self._singleton_mode:
            self._repository_instances[entity_type] = repository

        return repository

    def create_unit_of_work(self) -> IUnitOfWork:
        """Create unit of work instance."""
        from app.core.repositories.transaction import UnitOfWork
from app.core.infrastructure.repository import BaseRepository

        return UnitOfWork(self)

    def get_registered_entities(self) -> list[type[TEntity]]:
        """Get list of registered entity types."""
        return list(self._registered_repositories.keys())

    def clear_cache(self) -> None:
        """Clear repository instance cache."""
        self._repository_instances.clear()


__all__ = [
    "BaseRepository",
    "IRepository",
    "IRepositoryFactory",
    "ISpecificationRepository",
    "IUnitOfWork",
    "RepositoryFactory",
    "SpecificationRepository",
]
