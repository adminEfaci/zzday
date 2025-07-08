"""Repository Factory Implementation

Provides comprehensive repository factory with dependency injection support,
automatic registration, and performance monitoring.
"""

from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, TypeVar

from app.core.domain.base import Entity
from app.core.errors import ConfigurationError, InfrastructureError
from app.core.logging import get_logger
from app.core.monitoring import metrics
from app.core.repositories.base import IRepository, IRepositoryFactory, IUnitOfWork
from app.core.repositories.transaction import TransactionManager, UnitOfWork

logger = get_logger(__name__)

TEntity = TypeVar("TEntity", bound=Entity)
TRepository = TypeVar("TRepository", bound=IRepository)


class RepositoryRegistration:
    """Repository registration metadata."""

    def __init__(
        self,
        entity_type: type[TEntity],
        repository_interface: type[IRepository],
        repository_implementation: type[IRepository],
        is_singleton: bool = True,
        cache_enabled: bool = True,
        cache_ttl: int | None = None,
    ):
        """Initialize repository registration."""
        self.entity_type = entity_type
        self.repository_interface = repository_interface
        self.repository_implementation = repository_implementation
        self.is_singleton = is_singleton
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.created_at = datetime.utcnow()


class RepositoryFactory(IRepositoryFactory):
    """
    Advanced repository factory with comprehensive features.

    Features:
    - Automatic repository discovery and registration
    - Dependency injection integration
    - Repository lifecycle management (singleton/transient)
    - Performance monitoring and caching
    - Transaction management integration
    - Health check support
    """

    def __init__(
        self,
        session_factory: Callable | None = None,
        cache_provider: Any | None = None,
        event_publisher: Any | None = None,
        enable_monitoring: bool = True,
    ):
        """
        Initialize repository factory.

        Args:
            session_factory: Database session factory
            cache_provider: Cache provider implementation
            event_publisher: Domain event publisher
            enable_monitoring: Enable performance monitoring
        """
        self._session_factory = session_factory
        self._cache_provider = cache_provider
        self._event_publisher = event_publisher
        self._enable_monitoring = enable_monitoring

        # Repository registrations
        self._registrations: dict[type[Entity], RepositoryRegistration] = {}
        self._interface_mappings: dict[type[IRepository], type[Entity]] = {}

        # Repository instances (for singletons)
        self._instances: dict[type[Entity], IRepository] = {}

        # Transaction manager
        self._transaction_manager: TransactionManager | None = None

        # Performance tracking
        self._creation_count = 0
        self._cache_hits = 0
        self._cache_misses = 0

        logger.info(
            "Repository factory initialized",
            cache_enabled=cache_provider is not None,
            monitoring_enabled=enable_monitoring,
        )

    def configure(
        self,
        session_factory: Callable,
        cache: Any | None = None,
        event_publisher: Any | None = None,
        singleton_mode: bool = False,
    ) -> None:
        """Configure factory dependencies."""
        self._session_factory = session_factory
        self._cache_provider = cache
        self._event_publisher = event_publisher

        # Create transaction manager
        self._transaction_manager = TransactionManager(session_factory, self)

        logger.debug("Repository factory configured")

    def register_repository(
        self,
        entity_type: type[TEntity],
        repository_type: type[IRepository],
        repository_interface: type[IRepository] | None = None,
        is_singleton: bool = True,
        cache_enabled: bool = True,
        cache_ttl: int | None = None,
    ) -> None:
        """
        Register repository implementation for entity type.

        Args:
            entity_type: Entity type this repository manages
            repository_type: Repository implementation class
            repository_interface: Repository interface (optional)
            is_singleton: Whether to create singleton instance
            cache_enabled: Whether to enable caching
            cache_ttl: Cache time-to-live in seconds
        """
        # Validate registration
        self._validate_registration(entity_type, repository_type)

        # Create registration
        registration = RepositoryRegistration(
            entity_type=entity_type,
            repository_interface=repository_interface or IRepository,
            repository_implementation=repository_type,
            is_singleton=is_singleton,
            cache_enabled=cache_enabled,
            cache_ttl=cache_ttl,
        )

        # Register entity mapping
        self._registrations[entity_type] = registration

        # Register interface mapping if provided
        if repository_interface:
            self._interface_mappings[repository_interface] = entity_type

        logger.debug(
            "Repository registered",
            entity_type=entity_type.__name__,
            repository_type=repository_type.__name__,
            is_singleton=is_singleton,
        )

    def _validate_registration(
        self, entity_type: type[TEntity], repository_type: type[IRepository]
    ) -> None:
        """Validate repository registration."""
        if not issubclass(entity_type, Entity):
            raise ConfigurationError(
                f"Entity type must inherit from Entity: {entity_type}"
            )

        if not issubclass(repository_type, IRepository):
            raise ConfigurationError(
                f"Repository must implement IRepository: {repository_type}"
            )

    def create_repository(
        self, entity_type: type[TEntity]
    ) -> IRepository[TEntity, Any]:
        """Create repository instance for entity type."""
        # Check if entity type is registered
        if entity_type not in self._registrations:
            raise InfrastructureError(
                f"No repository registered for entity type: {entity_type.__name__}"
            )

        registration = self._registrations[entity_type]

        # Return singleton instance if exists
        if registration.is_singleton and entity_type in self._instances:
            self._cache_hits += 1
            return self._instances[entity_type]

        self._cache_misses += 1

        # Create new repository instance
        repository = self._create_repository_instance(registration)

        # Store singleton instance
        if registration.is_singleton:
            self._instances[entity_type] = repository

        return repository

    def create_repository_by_interface(
        self, repository_interface: type[TRepository]
    ) -> TRepository:
        """Create repository by interface type."""
        # Find entity type for interface
        if repository_interface not in self._interface_mappings:
            raise InfrastructureError(
                f"No entity mapping for repository interface: {repository_interface}"
            )

        entity_type = self._interface_mappings[repository_interface]
        return self.create_repository(entity_type)

    def _create_repository_instance(
        self, registration: RepositoryRegistration
    ) -> IRepository:
        """Create repository instance with dependencies."""
        if not self._session_factory:
            raise ConfigurationError("Session factory not configured")

        # Prepare repository dependencies
        kwargs = {
            "entity_type": registration.entity_type,
            "session_factory": self._session_factory,
        }

        # Add optional dependencies
        if registration.cache_enabled and self._cache_provider:
            kwargs["cache"] = self._cache_provider
            if registration.cache_ttl:
                kwargs["cache_ttl"] = registration.cache_ttl

        if self._event_publisher:
            kwargs["event_publisher"] = self._event_publisher

        # Create repository instance
        try:
            repository = registration.repository_implementation(**kwargs)
            self._creation_count += 1

            if self._enable_monitoring:
                self._track_repository_creation(registration)

            return repository

        except Exception as e:
            logger.exception(
                "Failed to create repository",
                entity_type=registration.entity_type.__name__,
                repository_type=registration.repository_implementation.__name__,
                error=str(e),
            )
            raise InfrastructureError(
                f"Failed to create repository for {registration.entity_type.__name__}: {e!s}"
            )

    def _track_repository_creation(self, registration: RepositoryRegistration) -> None:
        """Track repository creation metrics."""
        metrics.repository_creations.labels(
            entity_type=registration.entity_type.__name__,
            repository_type=registration.repository_implementation.__name__,
            is_singleton=str(registration.is_singleton),
        ).inc()

    def create_unit_of_work(self) -> IUnitOfWork:
        """Create unit of work instance."""
        return UnitOfWork(self)

    @asynccontextmanager
    async def unit_of_work(self):
        """Context manager for unit of work pattern."""
        uow = self.create_unit_of_work()
        async with uow:
            yield uow

    def register_identity_repositories(self) -> None:
        """Register all identity module repositories."""
        from app.modules.identity.domain.aggregates import (
            Permission,
            Role,
            Session,
            User,
        )
        from app.modules.identity.domain.interfaces.repositories import (
            IPermissionRepository,
            IRoleRepository,
            ISessionRepository,
            IUserRepository,
        )
        from app.modules.identity.infrastructure.repositories import (
            PermissionRepository,
            RoleRepository,
            SessionRepository,
            UserRepository,
        )

        # Register user repository
        self.register_repository(
            entity_type=User,
            repository_type=UserRepository,
            repository_interface=IUserRepository,
            cache_ttl=300,  # 5 minutes
        )

        # Register role repository
        self.register_repository(
            entity_type=Role,
            repository_type=RoleRepository,
            repository_interface=IRoleRepository,
            cache_ttl=600,  # 10 minutes
        )

        # Register session repository
        self.register_repository(
            entity_type=Session,
            repository_type=SessionRepository,
            repository_interface=ISessionRepository,
            cache_ttl=60,  # 1 minute
        )

        # Register permission repository
        self.register_repository(
            entity_type=Permission,
            repository_type=PermissionRepository,
            repository_interface=IPermissionRepository,
            cache_ttl=900,  # 15 minutes
        )

        logger.info("Identity repositories registered")

    def get_statistics(self) -> dict[str, Any]:
        """Get factory statistics."""
        return {
            "registered_repositories": len(self._registrations),
            "singleton_instances": len(self._instances),
            "creation_count": self._creation_count,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": self._cache_hits
            / max(self._cache_hits + self._cache_misses, 1),
            "registrations": [
                {
                    "entity_type": reg.entity_type.__name__,
                    "repository_type": reg.repository_implementation.__name__,
                    "is_singleton": reg.is_singleton,
                    "cache_enabled": reg.cache_enabled,
                    "created_at": reg.created_at.isoformat(),
                }
                for reg in self._registrations.values()
            ],
        }

    async def health_check(self) -> dict[str, Any]:
        """Perform health check on repositories."""
        results = {
            "status": "healthy",
            "repositories": {},
            "checked_at": datetime.utcnow().isoformat(),
        }

        # Check each registered repository
        for entity_type, _registration in self._registrations.items():
            try:
                repository = self.create_repository(entity_type)

                # Try a simple operation
                if hasattr(repository, "count"):
                    count = await repository.count()
                    results["repositories"][entity_type.__name__] = {
                        "status": "healthy",
                        "count": count,
                    }
                else:
                    results["repositories"][entity_type.__name__] = {
                        "status": "healthy"
                    }

            except Exception as e:
                results["status"] = "unhealthy"
                results["repositories"][entity_type.__name__] = {
                    "status": "unhealthy",
                    "error": str(e),
                }

        return results

    def clear_singletons(self) -> None:
        """Clear all singleton instances."""
        count = len(self._instances)
        self._instances.clear()
        logger.info(f"Cleared {count} singleton repository instances")


# Global factory instance
_repository_factory: RepositoryFactory | None = None


def get_repository_factory() -> RepositoryFactory:
    """Get global repository factory instance."""
    global _repository_factory
    if _repository_factory is None:
        _repository_factory = RepositoryFactory()
    return _repository_factory


def configure_repository_factory(
    session_factory: Callable,
    cache: Any | None = None,
    event_publisher: Any | None = None,
) -> RepositoryFactory:
    """Configure and return repository factory."""
    factory = get_repository_factory()
    factory.configure(
        session_factory=session_factory, cache=cache, event_publisher=event_publisher
    )
    return factory


__all__ = [
    "RepositoryFactory",
    "RepositoryRegistration",
    "configure_repository_factory",
    "get_repository_factory",
]
