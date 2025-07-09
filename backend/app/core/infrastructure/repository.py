"""Repository pattern implementation following pure Python principles.

This module provides a comprehensive repository pattern implementation that follows
Domain-Driven Design principles with pure Python classes, completely independent
of any specific ORM or database framework.

The repository pattern encapsulates data access logic and provides a more object-oriented
view of the persistence layer. This implementation supports various data sources
and provides framework-agnostic abstractions.

Design Principles:
- Pure Python interfaces with explicit contracts
- Framework-agnostic design (works with SQLAlchemy, Django ORM, etc.)
- Rich functionality with comprehensive error handling
- Specification pattern integration for complex queries
- Performance monitoring and caching support
- Transaction management integration points
- Connection health monitoring

Architecture:
- Repository: Abstract base for domain-specific repositories
- BaseRepository: Common functionality for all repositories
- SpecificationRepository: Repository with specification support
- CacheableRepository: Repository with caching capabilities
- EventSourcedRepository: Repository with event sourcing support
- AggregateRepository: Repository for aggregate roots
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from typing import Any, Generic, TypeVar

from app.core.domain.base import AggregateRoot, Entity
from app.core.domain.specification import Specification
from app.core.errors import InfrastructureError
from app.core.logging import get_logger


# Custom exceptions for repository operations
class RepositoryError(InfrastructureError):
    """Base exception for repository-specific errors."""
    
    default_code = "REPOSITORY_ERROR"
    

class DatabaseConnectivityError(RepositoryError):
    """Database connectivity test failed."""
    
    default_code = "DATABASE_CONNECTIVITY_ERROR"


class CacheConnectivityError(RepositoryError):
    """Cache connectivity test failed."""
    
    default_code = "CACHE_CONNECTIVITY_ERROR"


# Metrics implementation with repository-specific attributes
class _MockCounter:
    def labels(self, **kwargs):
        return self
    def inc(self):
        pass
    def observe(self, value):
        pass

class _MockHistogram:
    def labels(self, **kwargs):
        return self
    def observe(self, value):
        pass

class _RepositoryMetrics:
    """Repository-specific metrics wrapper."""
    def __init__(self):
        self.repository_operations = _MockCounter()
        self.repository_errors = _MockCounter()
        self.repository_operation_duration = _MockHistogram()
        self.cache_operations = _MockCounter()

# Use repository-specific metrics to avoid conflicts with global metrics
metrics = _RepositoryMetrics()

logger = get_logger(__name__)

# Type variables for repository pattern
TEntity = TypeVar("TEntity", bound=Entity)
TAggregate = TypeVar("TAggregate", bound=AggregateRoot)
TId = TypeVar("TId")
TModel = TypeVar("TModel")  # Database model type


# =====================================================================================
# BASE REPOSITORY INTERFACES
# =====================================================================================


class Repository(ABC, Generic[TEntity, TId]):
    """
    Abstract base repository interface following pure Python principles.

    Defines the contract for domain repositories without coupling to any
    specific data access technology. Implementations can use SQLAlchemy,
    Django ORM, MongoDB, or any other persistence mechanism.

    Design Features:
    - Framework-agnostic interface
    - Rich query capabilities
    - Specification pattern support
    - Performance monitoring
    - Error handling standardization
    - Transaction integration points

    Usage Example:
        class UserRepository(Repository[User, UUID]):
            async def find_by_email(self, email: str) -> User | None:
                # Implementation specific to chosen data access technology
                pass

            async def find_active_users(self) -> list[User]:
                spec = ActiveUserSpecification()
                return await self.find_by_specification(spec)
    """

    @abstractmethod
    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """
        Find entity by its identifier.

        Args:
            entity_id: Unique identifier of the entity

        Returns:
            TEntity | None: Entity if found, None otherwise

        Raises:
            InfrastructureError: If data access fails
        """

    @abstractmethod
    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[TEntity]:
        """
        Find all entities with optional pagination.

        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip

        Returns:
            list[TEntity]: List of entities

        Raises:
            InfrastructureError: If data access fails
        """

    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """
        Save (create or update) an entity.

        Args:
            entity: Entity to save

        Returns:
            TEntity: Saved entity

        Raises:
            InfrastructureError: If save operation fails
            ConflictError: If entity conflicts with existing data
        """

    @abstractmethod
    async def delete(self, entity_id: TId) -> bool:
        """
        Delete entity by identifier.

        Args:
            entity_id: Identifier of entity to delete

        Returns:
            bool: True if entity was deleted, False if not found

        Raises:
            InfrastructureError: If delete operation fails
        """

    @abstractmethod
    async def exists(self, entity_id: TId) -> bool:
        """
        Check if entity exists by identifier.

        Args:
            entity_id: Identifier to check

        Returns:
            bool: True if entity exists, False otherwise

        Raises:
            InfrastructureError: If check operation fails
        """

    @abstractmethod
    async def count(self) -> int:
        """
        Count total number of entities.

        Returns:
            int: Total count of entities

        Raises:
            InfrastructureError: If count operation fails
        """


class SpecificationRepository(Repository[TEntity, TId], ABC):
    """
    Repository interface with specification pattern support.

    Extends the base repository with specification-based querying capabilities,
    allowing complex business rules to be encapsulated in reusable specifications.
    """

    @abstractmethod
    async def find_by_specification(
        self, specification: Specification[TEntity]
    ) -> list[TEntity]:
        """
        Find entities that satisfy the given specification.

        Args:
            specification: Specification to evaluate

        Returns:
            list[TEntity]: Entities that satisfy the specification

        Raises:
            InfrastructureError: If query operation fails
        """

    @abstractmethod
    async def find_one_by_specification(
        self, specification: Specification[TEntity]
    ) -> TEntity | None:
        """
        Find single entity that satisfies the given specification.

        Args:
            specification: Specification to evaluate

        Returns:
            TEntity | None: First entity that satisfies specification, None if none found

        Raises:
            InfrastructureError: If query operation fails
        """

    @abstractmethod
    async def count_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """
        Count entities that satisfy the given specification.

        Args:
            specification: Specification to evaluate

        Returns:
            int: Count of entities that satisfy the specification

        Raises:
            InfrastructureError: If count operation fails
        """

    @abstractmethod
    async def delete_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """
        Delete entities that satisfy the given specification.

        Args:
            specification: Specification to evaluate

        Returns:
            int: Number of entities deleted

        Raises:
            InfrastructureError: If delete operation fails
        """


# =====================================================================================
# BASE REPOSITORY IMPLEMENTATION
# =====================================================================================


class BaseRepository(SpecificationRepository[TEntity, TId]):
    """
    Base repository implementation with common functionality.

    Provides common repository operations and framework-agnostic functionality
    that can be shared across different repository implementations.

    Design Features:
    - Performance monitoring and metrics
    - Error handling standardization
    - Caching integration points
    - Connection health monitoring
    - Transaction support hooks
    - Comprehensive logging

    Usage Example:
        class SqlUserRepository(BaseRepository[User, UUID]):
            def __init__(self, session_factory, cache=None):
                super().__init__(User, session_factory, cache)

            async def find_by_email(self, email: str) -> User | None:
                async with self.get_session() as session:
                    # SQLAlchemy specific implementation
                    result = await session.execute(
                        select(UserModel).where(UserModel.email == email)
                    )
                    model = result.scalar_one_or_none()
                    return self._model_to_entity(model) if model else None
    """

    def __init__(
        self,
        entity_type: type[TEntity],
        session_factory: Callable,
        cache: Any | None = None,
    ):
        """
        Initialize base repository.

        Args:
            entity_type: Type of entity this repository manages
            session_factory: Factory function for creating database sessions
            cache: Optional cache implementation for performance optimization
        """
        self.entity_type = entity_type
        self.session_factory = session_factory
        self.cache = cache

        # Performance metrics
        self._operation_count = 0
        self._total_operation_time = 0.0
        self._error_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._last_operation = None

        # Repository metadata
        self._created_at = datetime.utcnow()

    @asynccontextmanager
    async def get_session(self):
        """
        Get database session with error handling and resource cleanup.

        Yields:
            Database session

        Raises:
            InfrastructureError: If session creation fails
        """
        session = None
        try:
            session = self.session_factory()
            yield session
        except Exception as e:
            if session:
                await self._handle_session_error(session, e)
            raise InfrastructureError(f"Database session error: {e!s}") from e
        finally:
            if session:
                await self._cleanup_session(session)

    async def _handle_session_error(self, session, error: Exception) -> None:
        """
        Handle session errors with appropriate cleanup.

        Args:
            session: Database session
            error: Exception that occurred
        """
        try:
            if hasattr(session, "rollback"):
                await session.rollback()
        except Exception as rollback_error:
            logger.exception(
                "Failed to rollback session after error",
                repository=self.__class__.__name__,
                original_error=str(error),
                rollback_error=str(rollback_error),
            )

    async def _cleanup_session(self, session) -> None:
        """
        Clean up database session.

        Args:
            session: Database session to clean up
        """
        try:
            if hasattr(session, "close"):
                await session.close()
        except Exception as e:
            logger.exception(
                "Failed to close database session",
                repository=self.__class__.__name__,
                error=str(e),
            )

    @asynccontextmanager
    async def operation_context(self, operation_name: str):
        """
        Context manager for tracking repository operations.

        Args:
            operation_name: Name of the operation being performed
        """
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
            self._last_operation = datetime.utcnow()

            # Record metrics
            try:
                metrics.repository_operations.labels(
                    repository=self.__class__.__name__,
                    operation=operation_name,
                    entity_type=self.entity_type.__name__,
                    status="success"
                ).inc()
                
                metrics.repository_operation_duration.labels(
                    repository=self.__class__.__name__,
                    operation=operation_name
                ).observe(execution_time)
            except Exception as e:
                logger.debug(
                    "Metrics recording failed for success",
                    repository=self.__class__.__name__,
                    operation=operation_name,
                    error=str(e)
                )

            logger.debug(
                "Repository operation completed successfully",
                repository=self.__class__.__name__,
                operation=operation_name,
                execution_time=execution_time,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self._error_count += 1
            self._total_operation_time += execution_time

            # Record error metrics
            try:
                metrics.repository_operations.labels(
                    repository=self.__class__.__name__,
                    operation=operation_name,
                    entity_type=self.entity_type.__name__,
                    status="error"
                ).inc()
                
                metrics.repository_errors.labels(
                    repository=self.__class__.__name__,
                    operation=operation_name,
                    error_type=type(e).__name__
                ).inc()
            except Exception as metrics_error:
                logger.debug(
                    "Metrics recording failed for error",
                    repository=self.__class__.__name__,
                    operation=operation_name,
                    error=str(metrics_error)
                )

            logger.exception(
                "Repository operation failed",
                repository=self.__class__.__name__,
                operation=operation_name,
                error=str(e),
                execution_time=execution_time,
                error_type=type(e).__name__,
            )
            raise

    async def _get_from_cache(self, cache_key: str) -> Any | None:
        """
        Get item from cache if available.

        Args:
            cache_key: Cache key to retrieve

        Returns:
            Any | None: Cached item if found, None otherwise
        """
        if not self.cache:
            return None

        try:
            if hasattr(self.cache, "get"):
                result = await self.cache.get(cache_key)
                if result is not None:
                    self._cache_hits += 1
                    # Record cache hit metric
                    with suppress(Exception):
                        metrics.cache_operations.labels(
                            repository=self.__class__.__name__,
                            operation="get",
                            result="hit"
                        ).inc()
                    return result

        except Exception as e:
            logger.warning(
                "Cache get operation failed",
                repository=self.__class__.__name__,
                cache_key=cache_key,
                error=str(e),
            )
            self._cache_misses += 1
            # Record cache error metric
            with suppress(Exception):
                metrics.cache_operations.labels(
                    repository=self.__class__.__name__,
                    operation="get",
                    result="error"
                ).inc()
            return None
        else:
            self._cache_misses += 1
            # Record cache miss metric
            with suppress(Exception):
                metrics.cache_operations.labels(
                    repository=self.__class__.__name__,
                    operation="get",
                    result="miss"
                ).inc()
            return None

    async def _set_cache(
        self, cache_key: str, item: Any, ttl: int | None = None
    ) -> None:
        """
        Set item in cache if available.

        Args:
            cache_key: Cache key to set
            item: Item to cache
            ttl: Time-to-live in seconds
        """
        if not self.cache:
            return

        try:
            if hasattr(self.cache, "set"):
                if ttl:
                    await self.cache.set(cache_key, item, ttl)
                else:
                    await self.cache.set(cache_key, item)

        except Exception as e:
            logger.warning(
                "Cache set operation failed",
                repository=self.__class__.__name__,
                cache_key=cache_key,
                error=str(e),
            )

    async def _delete_from_cache(self, cache_key: str) -> None:
        """
        Delete item from cache if available.

        Args:
            cache_key: Cache key to delete
        """
        if not self.cache:
            return

        try:
            if hasattr(self.cache, "delete"):
                await self.cache.delete(cache_key)

        except Exception as e:
            logger.warning(
                "Cache delete operation failed",
                repository=self.__class__.__name__,
                cache_key=cache_key,
                error=str(e),
            )

    def _generate_cache_key(self, operation: str, *args) -> str:
        """
        Generate cache key for operation.

        Args:
            operation: Operation name
            *args: Operation arguments

        Returns:
            str: Generated cache key
        """
        key_parts = [self.__class__.__name__, self.entity_type.__name__, operation]
        key_parts.extend(str(arg) for arg in args)
        return ":".join(key_parts)

    async def get_by_id_cached(
        self, entity_id: TId, ttl: int | None = 300
    ) -> TEntity | None:
        """
        Get entity by ID with caching support.

        Args:
            entity_id: Entity identifier
            ttl: Cache time-to-live in seconds

        Returns:
            TEntity | None: Entity if found, None otherwise
        """
        cache_key = self._generate_cache_key("find_by_id", entity_id)

        # Try cache first
        cached_entity = await self._get_from_cache(cache_key)
        if cached_entity is not None:
            return cached_entity

        # Fetch from database
        entity = await self.find_by_id(entity_id)

        # Cache the result
        if entity is not None:
            await self._set_cache(cache_key, entity, ttl)

        return entity

    async def invalidate_cache_for_entity(self, entity_id: TId) -> None:
        """
        Invalidate cache entries for a specific entity.

        Args:
            entity_id: Entity identifier
        """
        cache_keys = [
            self._generate_cache_key("find_by_id", entity_id),
            # Add other cache keys that should be invalidated
        ]

        for cache_key in cache_keys:
            await self._delete_from_cache(cache_key)

    async def batch_find_by_ids(self, entity_ids: list[TId]) -> dict[TId, TEntity]:
        """
        Find multiple entities by IDs efficiently.

        Args:
            entity_ids: List of entity identifiers

        Returns:
            dict[TId, TEntity]: Mapping of IDs to entities
        """
        async with self.operation_context("batch_find_by_ids"):
            results = {}

            for entity_id in entity_ids:
                entity = await self.find_by_id(entity_id)
                if entity:
                    results[entity_id] = entity

            return results

    async def batch_save(self, entities: list[TEntity]) -> list[TEntity]:
        """
        Save multiple entities efficiently.

        Args:
            entities: List of entities to save

        Returns:
            list[TEntity]: List of saved entities
        """
        async with self.operation_context("batch_save"):
            saved_entities = []

            for entity in entities:
                saved_entity = await self.save(entity)
                saved_entities.append(saved_entity)

            return saved_entities

    async def batch_delete(self, entity_ids: list[TId]) -> int:
        """
        Delete multiple entities efficiently.

        Args:
            entity_ids: List of entity identifiers to delete

        Returns:
            int: Number of entities deleted
        """
        async with self.operation_context("batch_delete"):
            deleted_count = 0

            for entity_id in entity_ids:
                if await self.delete(entity_id):
                    deleted_count += 1

            return deleted_count

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for this repository."""
        avg_time = self._total_operation_time / max(self._operation_count, 1)
        error_rate = self._error_count / max(self._operation_count, 1)
        cache_hit_rate = self._cache_hits / max(
            self._cache_hits + self._cache_misses, 1
        )
        
        # Calculate performance score (0.0 to 1.0)
        performance_score = self._calculate_performance_score(avg_time, error_rate, cache_hit_rate)
        
        # Calculate throughput (operations per second)
        uptime_seconds = (datetime.utcnow() - self._created_at).total_seconds()
        throughput = self._operation_count / max(uptime_seconds, 1)

        return {
            "repository_class": self.__class__.__name__,
            "entity_type": self.entity_type.__name__,
            "created_at": self._created_at.isoformat(),
            "uptime_seconds": uptime_seconds,
            "operation_count": self._operation_count,
            "error_count": self._error_count,
            "total_operation_time": self._total_operation_time,
            "average_operation_time": avg_time,
            "error_rate": error_rate,
            "throughput_ops_per_second": throughput,
            "performance_score": performance_score,
            "cache_enabled": self.cache is not None,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": cache_hit_rate,
            "last_operation": self._last_operation.isoformat()
            if self._last_operation
            else None,
        }
    
    def _calculate_performance_score(self, avg_time: float, error_rate: float, cache_hit_rate: float) -> float:
        """
        Calculate overall performance score.
        
        Args:
            avg_time: Average operation time
            error_rate: Error rate (0.0 to 1.0)
            cache_hit_rate: Cache hit rate (0.0 to 1.0)
            
        Returns:
            float: Performance score (0.0 to 1.0)
        """
        # Validate inputs
        avg_time = max(0.0, avg_time)
        error_rate = max(0.0, min(1.0, error_rate))
        cache_hit_rate = max(0.0, min(1.0, cache_hit_rate))
        
        # Base score starts at 1.0
        score = 1.0
        
        # Penalize high average operation times with smoother curve
        if avg_time > 2.0:  # More than 2 seconds
            score *= 0.3
        elif avg_time > 1.0:  # More than 1 second
            score *= 0.5
        elif avg_time > 0.5:  # More than 500ms
            score *= 0.7
        elif avg_time > 0.1:  # More than 100ms
            score *= 0.9
        elif avg_time > 0.05:  # More than 50ms
            score *= 0.95
        
        # Penalize high error rates with exponential penalty
        if error_rate > 0:
            score *= (1.0 - error_rate) ** 2
        
        # Reward good cache performance (if cache is enabled)
        if self.cache is not None:
            # Give more weight to cache performance
            cache_bonus = 0.3 + 0.7 * cache_hit_rate
            score *= cache_bonus
        
        return max(0.0, min(1.0, score))
    
    def is_performing_well(self) -> bool:
        """Check if repository is performing well."""
        stats = self.get_performance_stats()
        return (
            stats["performance_score"] >= 0.7 and
            stats["error_rate"] <= 0.05 and
            stats["average_operation_time"] <= 1.0
        )

    async def health_check(self) -> dict[str, Any]:
        """
        Perform health check on repository and its dependencies.

        Returns:
            dict[str, Any]: Health check results
        """
        health_status = {
            "repository": self.__class__.__name__,
            "entity_type": self.entity_type.__name__,
            "healthy": True,
            "checks": {},
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check database connectivity
        try:
            async with self.get_session() as session:
                # Perform a simple query to test connectivity
                await self._test_database_connectivity(session)
                health_status["checks"]["database"] = {
                    "status": "healthy",
                    "message": "Database connection successful",
                }
        except Exception as e:
            health_status["healthy"] = False
            health_status["checks"]["database"] = {
                "status": "unhealthy",
                "message": str(e),
            }

        # Check cache connectivity if available
        if self.cache:
            try:
                await self._test_cache_connectivity()
                health_status["checks"]["cache"] = {
                    "status": "healthy",
                    "message": "Cache connection successful",
                }
            except Exception as e:
                health_status["checks"]["cache"] = {
                    "status": "unhealthy",
                    "message": str(e),
                }
        else:
            health_status["checks"]["cache"] = {
                "status": "not_configured",
                "message": "Cache not configured",
            }

        return health_status

    async def _test_database_connectivity(self, session) -> None:
        """
        Test database connectivity with a simple query.

        Args:
            session: Database session

        Raises:
            DatabaseConnectivityError: If connectivity test fails
        """
        # This is a generic implementation - override in specific repository classes
        # For example, with SQLAlchemy: await session.execute(text(HEALTH_CHECK_QUERY))
        
        # Generic test - try to access session attributes
        if not hasattr(session, '__dict__'):
            raise DatabaseConnectivityError("Invalid session object")
        
        # If session has an execute method, try a simple operation
        if hasattr(session, 'execute'):
            try:
                # Try different query formats based on ORM type
                if hasattr(session, 'scalar'):
                    # SQLAlchemy 2.0+ style
                    from sqlalchemy import text
                    await session.scalar(text("SELECT 1"))
                elif asyncio.iscoroutinefunction(session.execute):
                    # Async session
                    await session.execute("SELECT 1")
                else:
                    # Sync session
                    session.execute("SELECT 1")
            except Exception as e:
                # If the above fails, it might be a different ORM
                # Log the attempt and re-raise
                logger.debug(
                    "Database connectivity test failed with SELECT 1",
                    error=str(e),
                    session_type=type(session).__name__
                )
                raise

    async def _test_cache_connectivity(self) -> None:
        """
        Test cache connectivity.

        Raises:
            CacheConnectivityError: If connectivity test fails
        """
        test_key = f"health_check_{self.__class__.__name__}"
        test_value = "test"

        # Set a test value
        await self._set_cache(test_key, test_value, 10)

        # Try to retrieve it
        retrieved_value = await self._get_from_cache(test_key)

        if retrieved_value != test_value:
            raise CacheConnectivityError("Cache connectivity test failed - value mismatch")

        # Clean up
        await self._delete_from_cache(test_key)

    # Abstract methods that must be implemented by concrete repositories
    @abstractmethod
    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[TEntity]:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def delete(self, entity_id: TId) -> bool:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def exists(self, entity_id: TId) -> bool:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def count(self) -> int:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def find_by_specification(
        self, specification: Specification[TEntity]
    ) -> list[TEntity]:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def find_one_by_specification(
        self, specification: Specification[TEntity]
    ) -> TEntity | None:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def count_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Must be implemented by concrete repository classes."""

    @abstractmethod
    async def delete_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Must be implemented by concrete repository classes."""


# =====================================================================================
# TRANSACTION SUPPORT
# =====================================================================================


class TransactionContext:
    """
    Transaction context for repository operations.
    
    Provides transaction management capabilities that can be implemented
    by different database technologies.
    """
    
    def __init__(self, session_factory: Callable):
        """
        Initialize transaction context.
        
        Args:
            session_factory: Factory for creating database sessions
        """
        self.session_factory = session_factory
        self._session = None
        self._transaction = None
        self._is_active = False
    
    async def __aenter__(self):
        """Enter transaction context."""
        self._session = self.session_factory()
        
        # Start transaction if supported
        if hasattr(self._session, "begin"):
            self._transaction = await self._session.begin()
        
        self._is_active = True
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit transaction context."""
        try:
            if exc_type is None:
                await self.commit()
            else:
                await self.rollback()
        finally:
            await self._cleanup()
    
    async def commit(self):
        """Commit the transaction."""
        if self._transaction and hasattr(self._transaction, "commit"):
            await self._transaction.commit()
        elif self._session and hasattr(self._session, "commit"):
            await self._session.commit()
    
    async def rollback(self):
        """Rollback the transaction."""
        if self._transaction and hasattr(self._transaction, "rollback"):
            await self._transaction.rollback()
        elif self._session and hasattr(self._session, "rollback"):
            await self._session.rollback()
    
    async def _cleanup(self):
        """Clean up transaction resources."""
        if self._session and hasattr(self._session, "close"):
            await self._session.close()
        
        self._session = None
        self._transaction = None
        self._is_active = False
    
    @property
    def session(self):
        """Get the current session."""
        return self._session
    
    @property
    def is_active(self) -> bool:
        """Check if transaction is active."""
        return self._is_active


class TransactionalRepository(BaseRepository[TEntity, TId]):
    """
    Repository with explicit transaction support.
    
    Provides methods for working within explicit transactions,
    useful for complex operations that span multiple repositories.
    """
    
    def __init__(
        self,
        entity_type: type[TEntity],
        session_factory: Callable,
        cache: Any | None = None,
    ):
        """
        Initialize transactional repository.
        
        Args:
            entity_type: Type of entity this repository manages
            session_factory: Factory function for creating database sessions
            cache: Optional cache implementation
        """
        super().__init__(entity_type, session_factory, cache)
    
    def create_transaction(self) -> TransactionContext:
        """
        Create a new transaction context.
        
        Returns:
            TransactionContext: New transaction context
        """
        return TransactionContext(self.session_factory)
    
    async def save_in_transaction(
        self, entity: TEntity, transaction: TransactionContext
    ) -> TEntity:
        """
        Save entity within an existing transaction.
        
        Args:
            entity: Entity to save
            transaction: Active transaction context
            
        Returns:
            TEntity: Saved entity
        """
        if not transaction.is_active:
            raise InfrastructureError("Transaction is not active")
        
        # Use the transaction's session for the save operation
        return await self._save_with_session(entity, transaction.session)
    
    async def delete_in_transaction(
        self, entity_id: TId, transaction: TransactionContext
    ) -> bool:
        """
        Delete entity within an existing transaction.
        
        Args:
            entity_id: ID of entity to delete
            transaction: Active transaction context
            
        Returns:
            bool: True if entity was deleted
        """
        if not transaction.is_active:
            raise InfrastructureError("Transaction is not active")
        
        # Use the transaction's session for the delete operation
        return await self._delete_with_session(entity_id, transaction.session)
    
    async def _save_with_session(self, entity: TEntity, session) -> TEntity:
        """
        Save entity using specific session.
        
        Args:
            entity: Entity to save
            session: Database session to use
            
        Returns:
            TEntity: Saved entity
        """
        # This method should be implemented by concrete repository classes
        # to use the provided session for the save operation
        raise NotImplementedError("Concrete repositories must implement _save_with_session")
    
    async def _delete_with_session(self, entity_id: TId, session) -> bool:
        """
        Delete entity using specific session.
        
        Args:
            entity_id: ID of entity to delete
            session: Database session to use
            
        Returns:
            bool: True if entity was deleted
        """
        # This method should be implemented by concrete repository classes
        # to use the provided session for the delete operation
        raise NotImplementedError("Concrete repositories must implement _delete_with_session")


# =====================================================================================
# SPECIALIZED REPOSITORY CLASSES
# =====================================================================================


class CacheableRepository(BaseRepository[TEntity, TId]):
    """
    Repository with enhanced caching capabilities.

    Provides advanced caching features including cache warming,
    invalidation strategies, and cache statistics.
    """

    def __init__(
        self,
        entity_type: type[TEntity],
        session_factory: Callable,
        cache: Any,
        default_ttl: int = 300,
    ):
        """
        Initialize cacheable repository.

        Args:
            entity_type: Type of entity this repository manages
            session_factory: Factory function for creating database sessions
            cache: Cache implementation
            default_ttl: Default cache time-to-live in seconds
        """
        super().__init__(entity_type, session_factory, cache)
        self.default_ttl = default_ttl

    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """Find by ID with automatic caching."""
        return await self.get_by_id_cached(entity_id, self.default_ttl)

    async def save(self, entity: TEntity) -> TEntity:
        """Save entity and invalidate related cache entries."""
        # Get entity ID for cache invalidation
        entity_id = getattr(entity, "id", None)

        # Save entity
        saved_entity = await super().save(entity)

        # Invalidate cache
        if entity_id:
            await self.invalidate_cache_for_entity(entity_id)

        return saved_entity

    async def delete(self, entity_id: TId) -> bool:
        """Delete entity and invalidate cache."""
        result = await super().delete(entity_id)

        if result:
            await self.invalidate_cache_for_entity(entity_id)

        return result

    async def warm_cache(self, entity_ids: list[TId]) -> None:
        """
        Pre-load entities into cache.

        Args:
            entity_ids: List of entity IDs to cache
        """
        async with self.operation_context("warm_cache"):
            for entity_id in entity_ids:
                await self.get_by_id_cached(entity_id, self.default_ttl)


class EventSourcedRepository(BaseRepository[TAggregate, TId]):
    """
    Repository with event sourcing capabilities.

    Handles aggregate roots with domain events, providing event
    storage and replay capabilities.
    """

    def __init__(
        self,
        entity_type: type[TAggregate],
        session_factory: Callable,
        event_store: Any | None = None,
        cache: Any | None = None,
    ):
        """
        Initialize event sourced repository.

        Args:
            entity_type: Type of aggregate root this repository manages
            session_factory: Factory function for creating database sessions
            event_store: Optional event store for domain events
            cache: Optional cache implementation
        """
        super().__init__(entity_type, session_factory, cache)
        self.event_store = event_store

    async def save(self, aggregate: TAggregate) -> TAggregate:
        """
        Save aggregate and handle domain events.

        Args:
            aggregate: Aggregate root to save

        Returns:
            TAggregate: Saved aggregate
        """
        async with self.operation_context("save_aggregate"):
            # Save the aggregate state
            saved_aggregate = await super().save(aggregate)

            # Handle domain events if available
            if hasattr(aggregate, "get_events"):
                events = aggregate.get_events()
                if events and self.event_store:
                    await self._store_events(aggregate.id, events)

                    # Clear events after storing
                    if hasattr(aggregate, "clear_events"):
                        aggregate.clear_events()

            return saved_aggregate

    async def _store_events(self, aggregate_id: Any, events: list[Any]) -> None:
        """
        Store domain events in event store.

        Args:
            aggregate_id: ID of the aggregate that generated the events
            events: List of domain events to store
        """
        if not self.event_store:
            # Log events if no event store configured
            for event in events:
                logger.debug(
                    "Domain event (no event store)",
                    aggregate_type=self.entity_type.__name__,
                    aggregate_id=str(aggregate_id),
                    event_type=type(event).__name__,
                )
            return

        # Store events using the event store
        try:
            if hasattr(self.event_store, "store_events"):
                await self.event_store.store_events(aggregate_id, events)
            else:
                # Generic event storage
                for event in events:
                    await self.event_store.store(aggregate_id, event)

        except Exception as e:
            logger.exception(
                "Failed to store domain events",
                aggregate_type=self.entity_type.__name__,
                aggregate_id=str(aggregate_id),
                event_count=len(events),
                error=str(e),
            )
            raise InfrastructureError(f"Failed to store domain events: {e!s}") from e


class ReadOnlyRepository(ABC, Generic[TEntity, TId]):
    """
    Read-only repository interface for query-only operations.

    Useful for repositories that only need to read data, such as
    reporting repositories or read replicas.
    """

    @abstractmethod
    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """Find entity by ID."""

    @abstractmethod
    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[TEntity]:
        """Find all entities with pagination."""

    @abstractmethod
    async def exists(self, entity_id: TId) -> bool:
        """Check if entity exists."""

    @abstractmethod
    async def count(self) -> int:
        """Count total entities."""


class WriteOnlyRepository(ABC, Generic[TEntity, TId]):
    """
    Write-only repository interface for write-only operations.

    Useful for repositories that only need to write data, such as
    event stores or audit logs.
    """

    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity."""

    @abstractmethod
    async def delete(self, entity_id: TId) -> bool:
        """Delete entity by ID."""


# =====================================================================================
# REPOSITORY FACTORY
# =====================================================================================


class RepositoryFactory:
    """
    Factory for creating repository instances with dependency injection.

    Provides centralized repository creation with consistent configuration
    and dependency injection.
    """

    def __init__(self):
        """Initialize repository factory."""
        self._session_factory = None
        self._cache = None
        self._event_store = None
        self._registered_repositories: dict[type, type] = {}

    def configure(
        self,
        session_factory: Callable,
        cache: Any | None = None,
        event_store: Any | None = None,
    ) -> None:
        """
        Configure factory with dependencies.

        Args:
            session_factory: Database session factory
            cache: Optional cache implementation
            event_store: Optional event store implementation
            
        Raises:
            InfrastructureError: If configuration is invalid
        """
        # Validate session factory
        if not callable(session_factory):
            raise InfrastructureError("Session factory must be callable")
        
        # Test session factory by creating a test session
        def _validate_session_factory():
            """Helper function to validate session factory."""
            test_session = session_factory()
            if test_session is None:
                raise InfrastructureError("Session factory returned None")
            return test_session
        
        try:
            test_session = _validate_session_factory()
            
            # Clean up test session if possible
            if hasattr(test_session, 'close'):
                if asyncio.iscoroutinefunction(test_session.close):
                    # Can't await here, just log
                    logger.debug("Test session requires async cleanup")
                else:
                    test_session.close()
                    
        except Exception as e:
            raise InfrastructureError(f"Session factory validation failed: {e}") from e
        
        # Validate cache if provided
        if cache is not None:
            required_cache_methods = ['get', 'set', 'delete']
            missing_methods = []
            for method in required_cache_methods:
                if not hasattr(cache, method):
                    missing_methods.append(method)
            
            if missing_methods:
                logger.warning(
                    "Cache implementation missing methods",
                    missing_methods=missing_methods,
                    cache_type=type(cache).__name__
                )
        
        # Validate event store if provided
        if event_store is not None and not hasattr(event_store, 'store') and not hasattr(event_store, 'store_events'):
            logger.warning(
                "Event store implementation missing required methods",
                event_store_type=type(event_store).__name__,
                required_methods=['store', 'store_events']
            )
        
        self._session_factory = session_factory
        self._cache = cache
        self._event_store = event_store
        
        logger.info(
            "Repository factory configured",
            cache_enabled=cache is not None,
            event_store_enabled=event_store is not None,
            session_factory_type=type(session_factory).__name__
        )

    def register_repository(
        self, entity_type: type[TEntity], repository_type: type[BaseRepository]
    ) -> None:
        """
        Register repository implementation for entity type.

        Args:
            entity_type: Entity type
            repository_type: Repository implementation type
        """
        self._registered_repositories[entity_type] = repository_type

    def create_repository(
        self, entity_type: type[TEntity]
    ) -> BaseRepository[TEntity, Any]:
        """
        Create repository instance for entity type.

        Args:
            entity_type: Entity type

        Returns:
            BaseRepository: Repository instance

        Raises:
            InfrastructureError: If repository type not registered or not configured
        """
        if entity_type not in self._registered_repositories:
            raise InfrastructureError(
                f"No repository registered for entity type {entity_type.__name__}"
            )

        if self._session_factory is None:
            raise InfrastructureError(
                "Repository factory not configured - call configure() first"
            )

        repository_type = self._registered_repositories[entity_type]

        # Create repository with appropriate dependencies
        if issubclass(repository_type, EventSourcedRepository):
            return repository_type(
                entity_type, self._session_factory, self._event_store, self._cache
            )
        if issubclass(repository_type, CacheableRepository):
            return repository_type(entity_type, self._session_factory, self._cache)
        return repository_type(entity_type, self._session_factory, self._cache)


# =====================================================================================
# SQL-SPECIFIC REPOSITORY IMPLEMENTATION
# =====================================================================================


class SQLRepository(BaseRepository[TEntity, TId]):
    """
    SQL-specific repository implementation using SQLModel/SQLAlchemy.
    
    Provides SQL-specific functionality on top of BaseRepository including:
    - SQLModel/SQLAlchemy session management
    - Domain entity to SQL model conversion
    - SQL query optimization
    - Connection pooling support
    """
    
    def __init__(
        self,
        session: Any,
        model_type: type[TModel],
        entity_type: type[TEntity] | None = None,
        cache: Any | None = None,
    ):
        """
        Initialize SQL repository.
        
        Args:
            session: SQLModel/SQLAlchemy session
            model_type: SQL model type
            entity_type: Domain entity type (inferred from type if not provided)
            cache: Optional cache implementation
        """
        # Create session factory from session
        def session_factory():
            return session
        
        # Infer entity type from generic type if not provided
        if entity_type is None:
            # Try to infer from class generic parameters
            import inspect
            orig_bases = getattr(self.__class__, '__orig_bases__', ())
            if orig_bases:
                for base in orig_bases:
                    if hasattr(base, '__args__'):
                        entity_type = base.__args__[0]
                        break
            
            if entity_type is None:
                raise InfrastructureError("Entity type must be provided or inferrable from generics")
        
        super().__init__(entity_type, session_factory, cache)
        self.session = session
        self.model_type = model_type
    
    def _entity_to_model(self, entity: TEntity) -> TModel:
        """
        Convert domain entity to SQL model.
        
        Args:
            entity: Domain entity
            
        Returns:
            TModel: SQL model instance
        """
        if hasattr(self.model_type, 'from_domain'):
            return self.model_type.from_domain(entity)
        else:
            # Generic conversion - assumes model constructor accepts entity attributes
            try:
                entity_dict = entity.__dict__ if hasattr(entity, '__dict__') else {}
                return self.model_type(**entity_dict)
            except Exception as e:
                raise InfrastructureError(f"Failed to convert entity to model: {e}")
    
    def _model_to_entity(self, model: TModel) -> TEntity:
        """
        Convert SQL model to domain entity.
        
        Args:
            model: SQL model instance
            
        Returns:
            TEntity: Domain entity
        """
        if hasattr(model, 'to_domain'):
            return model.to_domain()
        else:
            # Generic conversion - assumes entity constructor accepts model attributes
            try:
                model_dict = model.__dict__ if hasattr(model, '__dict__') else {}
                return self.entity_type(**model_dict)
            except Exception as e:
                raise InfrastructureError(f"Failed to convert model to entity: {e}")
    
    async def find_by_id(self, entity_id: TId) -> TEntity | None:
        """Find entity by ID using SQL query."""
        async with self.operation_context("find_by_id"):
            try:
                model = await self.session.get(self.model_type, entity_id)
                return self._model_to_entity(model) if model else None
            except Exception as e:
                logger.exception(
                    "Failed to find entity by ID",
                    repository=self.__class__.__name__,
                    entity_id=str(entity_id),
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to find entity by ID: {e}")
    
    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[TEntity]:
        """Find all entities with pagination."""
        async with self.operation_context("find_all"):
            try:
                # Import here to avoid circular imports
                from sqlmodel import select
                
                stmt = select(self.model_type)
                if offset > 0:
                    stmt = stmt.offset(offset)
                if limit is not None:
                    stmt = stmt.limit(limit)
                
                result = await self.session.exec(stmt)
                models = result.all()
                
                return [self._model_to_entity(model) for model in models]
            except Exception as e:
                logger.exception(
                    "Failed to find all entities",
                    repository=self.__class__.__name__,
                    limit=limit,
                    offset=offset,
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to find all entities: {e}")
    
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity to database."""
        async with self.operation_context("save"):
            try:
                model = self._entity_to_model(entity)
                
                # Check if entity exists
                entity_id = getattr(entity, 'id', None)
                if entity_id:
                    existing = await self.session.get(self.model_type, entity_id)
                    if existing:
                        # Update existing
                        for key, value in model.__dict__.items():
                            if not key.startswith('_'):
                                setattr(existing, key, value)
                        self.session.add(existing)
                        await self.session.commit()
                        return self._model_to_entity(existing)
                
                # Create new
                self.session.add(model)
                await self.session.commit()
                return self._model_to_entity(model)
                
            except Exception as e:
                await self.session.rollback()
                logger.exception(
                    "Failed to save entity",
                    repository=self.__class__.__name__,
                    entity_type=self.entity_type.__name__,
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to save entity: {e}")
    
    async def delete(self, entity_id: TId) -> bool:
        """Delete entity by ID."""
        async with self.operation_context("delete"):
            try:
                model = await self.session.get(self.model_type, entity_id)
                if not model:
                    return False
                
                await self.session.delete(model)
                await self.session.commit()
                return True
                
            except Exception as e:
                await self.session.rollback()
                logger.exception(
                    "Failed to delete entity",
                    repository=self.__class__.__name__,
                    entity_id=str(entity_id),
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to delete entity: {e}")
    
    async def exists(self, entity_id: TId) -> bool:
        """Check if entity exists."""
        async with self.operation_context("exists"):
            try:
                model = await self.session.get(self.model_type, entity_id)
                return model is not None
            except Exception as e:
                logger.exception(
                    "Failed to check entity existence",
                    repository=self.__class__.__name__,
                    entity_id=str(entity_id),
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to check entity existence: {e}")
    
    async def count(self) -> int:
        """Count total entities."""
        async with self.operation_context("count"):
            try:
                # Import here to avoid circular imports
                from sqlmodel import select, func
                
                stmt = select(func.count(self.model_type.id))
                result = await self.session.exec(stmt)
                return result.first() or 0
            except Exception as e:
                logger.exception(
                    "Failed to count entities",
                    repository=self.__class__.__name__,
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to count entities: {e}")
    
    async def find_by_specification(
        self, specification: Specification[TEntity]
    ) -> list[TEntity]:
        """Find entities by specification."""
        async with self.operation_context("find_by_specification"):
            try:
                # This is a simplified implementation
                # In a real implementation, you'd convert specification to SQL
                all_entities = await self.find_all()
                return [entity for entity in all_entities if specification.is_satisfied_by(entity)]
            except Exception as e:
                logger.exception(
                    "Failed to find entities by specification",
                    repository=self.__class__.__name__,
                    specification=type(specification).__name__,
                    error=str(e),
                )
                raise InfrastructureError(f"Failed to find entities by specification: {e}")
    
    async def find_one_by_specification(
        self, specification: Specification[TEntity]
    ) -> TEntity | None:
        """Find first entity by specification."""
        entities = await self.find_by_specification(specification)
        return entities[0] if entities else None
    
    async def count_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Count entities by specification."""
        entities = await self.find_by_specification(specification)
        return len(entities)
    
    async def delete_by_specification(
        self, specification: Specification[TEntity]
    ) -> int:
        """Delete entities by specification."""
        entities = await self.find_by_specification(specification)
        deleted_count = 0
        
        for entity in entities:
            entity_id = getattr(entity, 'id', None)
            if entity_id and await self.delete(entity_id):
                deleted_count += 1
        
        return deleted_count


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Implementations
    "BaseRepository",
    "CacheableRepository",
    "EventSourcedRepository",
    "ReadOnlyRepository",
    "SQLRepository",
    # Interfaces
    "Repository",
    # Factory
    "RepositoryFactory",
    "SQLRepository",
    "SpecificationRepository",
    "TAggregate",
    # Type variables
    "TEntity",
    "TId",
    "TModel",
    # Transaction support
    "TransactionContext",
    "TransactionalRepository",
    "WriteOnlyRepository",
]
