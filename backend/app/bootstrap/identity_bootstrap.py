"""
Identity module bootstrap configuration.

This module handles the initialization and dependency injection setup
for the Identity bounded context.
"""

import logging

from dependency_injector import containers, providers

from app.modules.identity.application.command_handlers import (
    AssignRoleCommandHandler,
    AuthenticateUserCommandHandler,
    ChangePasswordCommandHandler,
    CreateRoleCommandHandler,
    CreateSessionCommandHandler,
    CreateUserCommandHandler,
    DeleteUserCommandHandler,
    InvalidateSessionCommandHandler,
    UpdateUserCommandHandler,
)
from app.modules.identity.application.event_handlers import (
    SessionEventHandler,
    UserEventHandler,
)
from app.modules.identity.application.query_handlers import (
    GetActiveSessionQueryHandler,
    GetPermissionQueryHandler,
    GetPermissionsQueryHandler,
    GetRoleQueryHandler,
    GetRolesQueryHandler,
    GetUserQueryHandler,
    GetUserSessionsQueryHandler,
    GetUsersQueryHandler,
)
from app.modules.identity.application.services import (
    AuthenticationApplicationService,
    AuthorizationApplicationService,
    SessionApplicationService,
    UserApplicationService,
)
from app.modules.identity.domain.services import (
    AuthenticationDomainService,
    AuthorizationDomainService,
    UserDomainService,
)
from app.modules.identity.infrastructure.caching import (
    PermissionCacheService,
    RoleCacheService,
    SessionCacheService,
    UserCacheService,
)
from app.modules.identity.infrastructure.repositories import (
    SqlPermissionRepository,
    SqlRoleRepository,
    SqlSessionRepository,
    SqlUserRepository,
)
from app.modules.identity.infrastructure.services import (
    BcryptPasswordService,
    JwtTokenService,
    RedisSessionStore,
)

logger = logging.getLogger(__name__)


class IdentityContainer(containers.DeclarativeContainer):
    """Identity module dependency injection container."""

    # Core dependencies (injected from main container)
    database = providers.Dependency()
    cache_manager = providers.Dependency()
    command_bus = providers.Dependency()
    query_bus = providers.Dependency()
    event_bus = providers.Dependency()
    config = providers.Dependency()

    # Infrastructure services
    password_service = providers.Singleton(
        BcryptPasswordService,
        rounds=config.provided.identity.password_hash_rounds,
    )

    token_service = providers.Singleton(
        JwtTokenService,
        secret_key=config.provided.identity.jwt_secret,
        algorithm=config.provided.identity.jwt_algorithm,
        access_token_expire_minutes=config.provided.identity.access_token_expire_minutes,
        refresh_token_expire_days=config.provided.identity.refresh_token_expire_days,
    )

    session_store = providers.Singleton(
        RedisSessionStore,
        cache_manager=cache_manager,
        session_timeout=config.provided.identity.session_timeout_minutes,
    )

    # Cache services
    user_cache = providers.Singleton(
        UserCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.identity.cache_ttl,
    )

    role_cache = providers.Singleton(
        RoleCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.identity.cache_ttl,
    )

    permission_cache = providers.Singleton(
        PermissionCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.identity.cache_ttl,
    )

    session_cache = providers.Singleton(
        SessionCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.identity.session_cache_ttl,
    )

    # Repositories
    user_repository = providers.Singleton(
        SqlUserRepository,
        database=database,
        cache_service=user_cache,
    )

    role_repository = providers.Singleton(
        SqlRoleRepository,
        database=database,
        cache_service=role_cache,
    )

    permission_repository = providers.Singleton(
        SqlPermissionRepository,
        database=database,
        cache_service=permission_cache,
    )

    session_repository = providers.Singleton(
        SqlSessionRepository,
        database=database,
        session_store=session_store,
        cache_service=session_cache,
    )

    # Domain services
    user_domain_service = providers.Singleton(
        UserDomainService,
        user_repository=user_repository,
        password_service=password_service,
    )

    authentication_domain_service = providers.Singleton(
        AuthenticationDomainService,
        user_repository=user_repository,
        password_service=password_service,
        token_service=token_service,
    )

    authorization_domain_service = providers.Singleton(
        AuthorizationDomainService,
        user_repository=user_repository,
        role_repository=role_repository,
        permission_repository=permission_repository,
    )

    # Application services
    user_application_service = providers.Singleton(
        UserApplicationService,
        user_repository=user_repository,
        user_domain_service=user_domain_service,
        event_bus=event_bus,
    )

    authentication_application_service = providers.Singleton(
        AuthenticationApplicationService,
        authentication_domain_service=authentication_domain_service,
        session_repository=session_repository,
        event_bus=event_bus,
    )

    authorization_application_service = providers.Singleton(
        AuthorizationApplicationService,
        authorization_domain_service=authorization_domain_service,
        event_bus=event_bus,
    )

    session_application_service = providers.Singleton(
        SessionApplicationService,
        session_repository=session_repository,
        user_repository=user_repository,
        event_bus=event_bus,
    )

    # Command handlers
    create_user_command_handler = providers.Singleton(
        CreateUserCommandHandler,
        user_application_service=user_application_service,
    )

    update_user_command_handler = providers.Singleton(
        UpdateUserCommandHandler,
        user_application_service=user_application_service,
    )

    delete_user_command_handler = providers.Singleton(
        DeleteUserCommandHandler,
        user_application_service=user_application_service,
    )

    change_password_command_handler = providers.Singleton(
        ChangePasswordCommandHandler,
        user_application_service=user_application_service,
    )

    authenticate_user_command_handler = providers.Singleton(
        AuthenticateUserCommandHandler,
        authentication_application_service=authentication_application_service,
    )

    create_role_command_handler = providers.Singleton(
        CreateRoleCommandHandler,
        authorization_application_service=authorization_application_service,
    )

    assign_role_command_handler = providers.Singleton(
        AssignRoleCommandHandler,
        authorization_application_service=authorization_application_service,
    )

    create_session_command_handler = providers.Singleton(
        CreateSessionCommandHandler,
        session_application_service=session_application_service,
    )

    invalidate_session_command_handler = providers.Singleton(
        InvalidateSessionCommandHandler,
        session_application_service=session_application_service,
    )

    # Query handlers
    get_user_query_handler = providers.Singleton(
        GetUserQueryHandler,
        user_repository=user_repository,
    )

    get_users_query_handler = providers.Singleton(
        GetUsersQueryHandler,
        user_repository=user_repository,
    )

    get_role_query_handler = providers.Singleton(
        GetRoleQueryHandler,
        role_repository=role_repository,
    )

    get_roles_query_handler = providers.Singleton(
        GetRolesQueryHandler,
        role_repository=role_repository,
    )

    get_permission_query_handler = providers.Singleton(
        GetPermissionQueryHandler,
        permission_repository=permission_repository,
    )

    get_permissions_query_handler = providers.Singleton(
        GetPermissionsQueryHandler,
        permission_repository=permission_repository,
    )

    get_user_sessions_query_handler = providers.Singleton(
        GetUserSessionsQueryHandler,
        session_repository=session_repository,
    )

    get_active_session_query_handler = providers.Singleton(
        GetActiveSessionQueryHandler,
        session_repository=session_repository,
    )

    # Event handlers
    user_event_handler = providers.Singleton(
        UserEventHandler,
        user_cache=user_cache,
        role_cache=role_cache,
    )

    session_event_handler = providers.Singleton(
        SessionEventHandler,
        session_cache=session_cache,
        user_cache=user_cache,
    )


class IdentityBootstrap:
    """Bootstrap class for Identity module."""

    def __init__(self, main_container):
        """
        Initialize Identity bootstrap.

        Args:
            main_container: Main application container
        """
        self.main_container = main_container
        self.logger = logging.getLogger(self.__class__.__name__)

    def bootstrap(self) -> IdentityContainer:
        """
        Bootstrap the Identity module.

        Returns:
            IdentityContainer: Configured Identity container
        """
        self.logger.info("Bootstrapping Identity module")

        try:
            # Create container with dependencies
            container = IdentityContainer()
            container.database.override(self.main_container.database())
            container.cache_manager.override(self.main_container.cache_manager())
            container.command_bus.override(self.main_container.command_bus())
            container.query_bus.override(self.main_container.query_bus())
            container.event_bus.override(self.main_container.event_bus())
            container.config.override(self.main_container.config())

            # Register command handlers
            self._register_command_handlers(container)

            # Register query handlers
            self._register_query_handlers(container)

            # Register event handlers
            self._register_event_handlers(container)

            # Initialize services
            self._initialize_services(container)

            self.logger.info("Identity module bootstrapped successfully")
            return container

        except Exception as e:
            self.logger.exception(f"Failed to bootstrap Identity module: {e}")
            raise

    def _register_command_handlers(self, container: IdentityContainer) -> None:
        """Register command handlers with the command bus."""
        self.logger.debug("Registering Identity command handlers")

        command_bus = container.command_bus()

        # Import commands
        from app.modules.identity.application.commands import (
            AssignRoleCommand,
            AuthenticateUserCommand,
            ChangePasswordCommand,
            CreateRoleCommand,
            CreateSessionCommand,
            CreateUserCommand,
            DeleteUserCommand,
            InvalidateSessionCommand,
            UpdateUserCommand,
        )

        # Register handlers
        command_bus.register(CreateUserCommand, container.create_user_command_handler())
        command_bus.register(UpdateUserCommand, container.update_user_command_handler())
        command_bus.register(DeleteUserCommand, container.delete_user_command_handler())
        command_bus.register(
            ChangePasswordCommand, container.change_password_command_handler()
        )
        command_bus.register(
            AuthenticateUserCommand, container.authenticate_user_command_handler()
        )
        command_bus.register(CreateRoleCommand, container.create_role_command_handler())
        command_bus.register(AssignRoleCommand, container.assign_role_command_handler())
        command_bus.register(
            CreateSessionCommand, container.create_session_command_handler()
        )
        command_bus.register(
            InvalidateSessionCommand, container.invalidate_session_command_handler()
        )

        self.logger.debug("Identity command handlers registered")

    def _register_query_handlers(self, container: IdentityContainer) -> None:
        """Register query handlers with the query bus."""
        self.logger.debug("Registering Identity query handlers")

        query_bus = container.query_bus()

        # Import queries
        from app.modules.identity.application.queries import (
            GetActiveSessionQuery,
            GetPermissionQuery,
            GetPermissionsQuery,
            GetRoleQuery,
            GetRolesQuery,
            GetUserQuery,
            GetUserSessionsQuery,
            GetUsersQuery,
        )

        # Register handlers
        query_bus.register(GetUserQuery, container.get_user_query_handler())
        query_bus.register(GetUsersQuery, container.get_users_query_handler())
        query_bus.register(GetRoleQuery, container.get_role_query_handler())
        query_bus.register(GetRolesQuery, container.get_roles_query_handler())
        query_bus.register(GetPermissionQuery, container.get_permission_query_handler())
        query_bus.register(
            GetPermissionsQuery, container.get_permissions_query_handler()
        )
        query_bus.register(
            GetUserSessionsQuery, container.get_user_sessions_query_handler()
        )
        query_bus.register(
            GetActiveSessionQuery, container.get_active_session_query_handler()
        )

        self.logger.debug("Identity query handlers registered")

    def _register_event_handlers(self, container: IdentityContainer) -> None:
        """Register event handlers with the event bus."""
        self.logger.debug("Registering Identity event handlers")

        event_bus = container.event_bus()

        # Import events
        from app.modules.identity.domain.events import (
            SessionCreatedEvent,
            SessionExpiredEvent,
            SessionInvalidatedEvent,
            UserAuthenticatedEvent,
            UserAuthenticationFailedEvent,
            UserCreatedEvent,
            UserDeletedEvent,
            UserPasswordChangedEvent,
            UserUpdatedEvent,
        )

        # Get handlers
        user_event_handler = container.user_event_handler()
        session_event_handler = container.session_event_handler()

        # Register user events
        event_bus.subscribe(UserCreatedEvent, user_event_handler.handle_user_created)
        event_bus.subscribe(UserUpdatedEvent, user_event_handler.handle_user_updated)
        event_bus.subscribe(UserDeletedEvent, user_event_handler.handle_user_deleted)
        event_bus.subscribe(
            UserPasswordChangedEvent, user_event_handler.handle_password_changed
        )
        event_bus.subscribe(
            UserAuthenticatedEvent, user_event_handler.handle_user_authenticated
        )
        event_bus.subscribe(
            UserAuthenticationFailedEvent,
            user_event_handler.handle_authentication_failed,
        )

        # Register session events
        event_bus.subscribe(
            SessionCreatedEvent, session_event_handler.handle_session_created
        )
        event_bus.subscribe(
            SessionInvalidatedEvent, session_event_handler.handle_session_invalidated
        )
        event_bus.subscribe(
            SessionExpiredEvent, session_event_handler.handle_session_expired
        )

        self.logger.debug("Identity event handlers registered")

    def _initialize_services(self, container: IdentityContainer) -> None:
        """Initialize and configure services."""
        self.logger.debug("Initializing Identity services")

        # Initialize password service
        password_service = container.password_service()
        password_service.initialize()

        # Initialize token service
        token_service = container.token_service()
        token_service.initialize()

        # Initialize session store
        session_store = container.session_store()
        session_store.initialize()

        # Initialize cache services
        container.user_cache().initialize()
        container.role_cache().initialize()
        container.permission_cache().initialize()
        container.session_cache().initialize()

        # Warm up caches if in production
        config = container.config()
        if config.environment == "production":
            self._warm_up_caches(container)

        self.logger.debug("Identity services initialized")

    def _warm_up_caches(self, container: IdentityContainer) -> None:
        """Warm up caches for production performance."""
        self.logger.debug("Warming up Identity caches")

        try:
            # Pre-load frequently accessed data
            role_repository = container.role_repository()
            permission_repository = container.permission_repository()

            # Cache all roles and permissions (they're relatively static)
            roles = role_repository.find_all()
            permissions = permission_repository.find_all()

            self.logger.debug(
                f"Cached {len(roles)} roles and {len(permissions)} permissions"
            )

        except Exception as e:
            self.logger.warning(f"Failed to warm up caches: {e}")
