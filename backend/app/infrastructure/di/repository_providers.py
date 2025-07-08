"""Repository Dependency Injection Providers

Configures and registers all repository implementations with the DI container.
"""

from dependency_injector import containers, providers

from app.core.cache import CacheProvider
from app.core.events import EventPublisher
from app.core.repositories import configure_repository_factory
from app.infrastructure.database import get_session_factory

# Import identity aggregates and repositories
from app.modules.identity.domain.aggregates import Permission, Role, Session, User
from app.modules.identity.domain.entities import (
    AuditLog,
    MfaDevice,
    UserPreference,
    UserProfile,
)
from app.modules.identity.domain.interfaces.repositories import (
    IAuditLogRepository,
    IMfaDeviceRepository,
    IPermissionRepository,
    IRoleRepository,
    ISessionRepository,
    IUserPreferenceRepository,
    IUserProfileRepository,
    IUserRepository,
)
from app.modules.identity.infrastructure.repositories import (
    AuditLogRepository,
    MfaDeviceRepository,
    PermissionRepository,
    RoleRepository,
    SessionRepository,
    UserPreferenceRepository,
    UserProfileRepository,
    UserRepository,
)


class RepositoryContainer(containers.DeclarativeContainer):
    """DI container for repository services."""

    # External dependencies
    config = providers.Configuration()
    cache_provider = providers.Dependency(instance_of=CacheProvider)
    event_publisher = providers.Dependency(instance_of=EventPublisher)

    # Database session factory
    session_factory = providers.Factory(
        get_session_factory,
        database_url=config.database.url,
        pool_size=config.database.pool_size,
        max_overflow=config.database.max_overflow,
    )

    # Repository factory configuration
    repository_factory = providers.Singleton(
        configure_repository_factory,
        session_factory=session_factory,
        cache=cache_provider,
        event_publisher=event_publisher,
    )

    # Identity repositories
    user_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IUserRepository),
        factory=repository_factory,
    )

    role_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IRoleRepository),
        factory=repository_factory,
    )

    permission_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IPermissionRepository),
        factory=repository_factory,
    )

    session_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(ISessionRepository),
        factory=repository_factory,
    )

    audit_log_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IAuditLogRepository),
        factory=repository_factory,
    )

    mfa_device_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IMfaDeviceRepository),
        factory=repository_factory,
    )

    user_profile_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(IUserProfileRepository),
        factory=repository_factory,
    )

    user_preference_repository = providers.Factory(
        lambda factory: factory.create_repository_by_interface(
            IUserPreferenceRepository
        ),
        factory=repository_factory,
    )

    # Unit of Work
    unit_of_work = providers.Factory(
        lambda factory: factory.create_unit_of_work(), factory=repository_factory
    )


def register_repositories(factory: "RepositoryFactory") -> None:
    """Register all repository implementations with the factory."""

    # Register user aggregate repositories
    factory.register_repository(
        entity_type=User,
        repository_type=UserRepository,
        repository_interface=IUserRepository,
        cache_ttl=300,  # 5 minutes
    )

    # Register role aggregate repositories
    factory.register_repository(
        entity_type=Role,
        repository_type=RoleRepository,
        repository_interface=IRoleRepository,
        cache_ttl=600,  # 10 minutes
    )

    # Register permission repositories
    factory.register_repository(
        entity_type=Permission,
        repository_type=PermissionRepository,
        repository_interface=IPermissionRepository,
        cache_ttl=900,  # 15 minutes
    )

    # Register session repositories
    factory.register_repository(
        entity_type=Session,
        repository_type=SessionRepository,
        repository_interface=ISessionRepository,
        cache_ttl=60,  # 1 minute
    )

    # Register entity repositories
    factory.register_repository(
        entity_type=AuditLog,
        repository_type=AuditLogRepository,
        repository_interface=IAuditLogRepository,
        is_singleton=False,  # New instance each time
        cache_enabled=False,  # No caching for audit logs
    )

    factory.register_repository(
        entity_type=MfaDevice,
        repository_type=MfaDeviceRepository,
        repository_interface=IMfaDeviceRepository,
        cache_ttl=120,  # 2 minutes
    )

    factory.register_repository(
        entity_type=UserProfile,
        repository_type=UserProfileRepository,
        repository_interface=IUserProfileRepository,
        cache_ttl=300,  # 5 minutes
    )

    factory.register_repository(
        entity_type=UserPreference,
        repository_type=UserPreferenceRepository,
        repository_interface=IUserPreferenceRepository,
        cache_ttl=600,  # 10 minutes
    )


def setup_repositories(
    cache_provider: CacheProvider, event_publisher: EventPublisher, database_url: str
) -> RepositoryContainer:
    """Setup and configure repository container."""

    # Create container
    container = RepositoryContainer()

    # Configure container
    container.config.database.url.from_value(database_url)
    container.config.database.pool_size.from_value(20)
    container.config.database.max_overflow.from_value(10)

    # Provide dependencies
    container.cache_provider.override(cache_provider)
    container.event_publisher.override(event_publisher)

    # Get factory and register repositories
    factory = container.repository_factory()
    register_repositories(factory)

    return container


# Health check for repositories
async def check_repository_health(container: RepositoryContainer) -> dict:
    """Perform health check on all repositories."""

    results = {"status": "healthy", "repositories": {}, "errors": []}

    # Check each repository
    repositories_to_check = [
        ("users", container.user_repository),
        ("roles", container.role_repository),
        ("permissions", container.permission_repository),
        ("sessions", container.session_repository),
        ("audit_logs", container.audit_log_repository),
        ("mfa_devices", container.mfa_device_repository),
        ("user_profiles", container.user_profile_repository),
        ("user_preferences", container.user_preference_repository),
    ]

    for name, repository_provider in repositories_to_check:
        try:
            repository = repository_provider()
            # Try a simple count operation
            count = await repository.count()
            results["repositories"][name] = {"status": "healthy", "count": count}
        except Exception as e:
            results["status"] = "unhealthy"
            results["repositories"][name] = {"status": "unhealthy", "error": str(e)}
            results["errors"].append({"repository": name, "error": str(e)})

    return results


__all__ = [
    "RepositoryContainer",
    "check_repository_health",
    "register_repositories",
    "setup_repositories",
]
