"""
Bootstrap module for initializing the entire application.

This module provides the main bootstrap function that initializes all modules
and their dependencies in the correct order.
"""

import logging
from typing import Any

from dependency_injector import containers, providers
from dependency_injector.wiring import Provide, inject

from app.core.cache import CacheManager
from app.core.config import Config
from app.core.database import Database
from app.core.logging import setup_logging
from app.core.messaging import CommandBus, EventBus, MessageBus, QueryBus

from .audit_bootstrap import AuditBootstrap
from .identity_bootstrap import IdentityBootstrap
from .integration_bootstrap import IntegrationBootstrap
from .notification_bootstrap import NotificationBootstrap

logger = logging.getLogger(__name__)


class ApplicationContainer(containers.DeclarativeContainer):
    """Main application dependency injection container."""

    wiring_config = containers.WiringConfiguration(
        modules=[
            "app.modules.identity.interfaces.rest",
            "app.modules.audit.interfaces.rest",
            "app.modules.notification.interfaces.rest",
            "app.modules.integration.interfaces.rest",
        ]
    )

    # Configuration
    config = providers.Singleton(Config)

    # Core infrastructure
    database = providers.Singleton(
        Database,
        connection_string=config.provided.database.connection_string,
        pool_size=config.provided.database.pool_size,
        max_overflow=config.provided.database.max_overflow,
    )

    cache_manager = providers.Singleton(
        CacheManager,
        redis_url=config.provided.cache.redis_url,
        default_ttl=config.provided.cache.default_ttl,
    )

    # Message buses
    command_bus = providers.Singleton(CommandBus)
    query_bus = providers.Singleton(QueryBus)
    event_bus = providers.Singleton(EventBus)

    message_bus = providers.Singleton(
        MessageBus,
        command_bus=command_bus,
        query_bus=query_bus,
        event_bus=event_bus,
    )

    # Module containers
    identity_container = providers.DependenciesContainer()
    audit_container = providers.DependenciesContainer()
    notification_container = providers.DependenciesContainer()
    integration_container = providers.DependenciesContainer()


def create_application() -> ApplicationContainer:
    """
    Create and configure the main application container.

    Returns:
        ApplicationContainer: Configured application container
    """
    container = ApplicationContainer()

    # Initialize configuration
    config = container.config()

    # Setup logging
    setup_logging(
        level=config.logging.level,
        format_string=config.logging.format,
        enable_json=config.logging.json_format,
    )

    logger.info("Starting application bootstrap process")

    try:
        # Initialize core infrastructure
        _initialize_core_infrastructure(container)

        # Bootstrap modules in dependency order
        _bootstrap_modules(container)

        # Setup cross-module event subscriptions
        _setup_cross_module_events(container)

        # Wire dependencies
        container.wire(modules=container.wiring_config.modules)

        logger.info("Application bootstrap completed successfully")
        return container

    except Exception:
        logger.exception("Application bootstrap failed")
        raise


def _initialize_core_infrastructure(container: ApplicationContainer) -> None:
    """Initialize core infrastructure components."""
    logger.info("Initializing core infrastructure")

    # Initialize database
    database = container.database()
    database.initialize()

    # Initialize cache
    cache_manager = container.cache_manager()
    cache_manager.initialize()

    # Initialize message buses
    container.command_bus()
    container.query_bus()
    container.event_bus()
    container.message_bus()

    logger.info("Core infrastructure initialized")


def _bootstrap_modules(container: ApplicationContainer) -> None:
    """Bootstrap all application modules in dependency order."""
    logger.info("Bootstrapping application modules")

    # Identity module (no dependencies)
    identity_bootstrap = IdentityBootstrap(container)
    identity_container = identity_bootstrap.bootstrap()
    container.identity_container.override(identity_container)

    # Audit module (depends on Identity for user context)
    audit_bootstrap = AuditBootstrap(container)
    audit_container = audit_bootstrap.bootstrap()
    container.audit_container.override(audit_container)

    # Notification module (depends on Identity for user preferences)
    notification_bootstrap = NotificationBootstrap(container)
    notification_container = notification_bootstrap.bootstrap()
    container.notification_container.override(notification_container)

    # Integration module (depends on all other modules)
    integration_bootstrap = IntegrationBootstrap(container)
    integration_container = integration_bootstrap.bootstrap()
    container.integration_container.override(integration_container)

    logger.info("All modules bootstrapped successfully")


def _setup_cross_module_events(container: ApplicationContainer) -> None:
    """Setup cross-module event subscriptions."""
    logger.info("Setting up cross-module event subscriptions")

    event_bus = container.event_bus()

    # Identity events -> Audit
    from app.modules.audit.application.event_handlers import IdentityEventHandler
    from app.modules.identity.domain.events import (
        UserCreatedEvent,
        UserDeletedEvent,
        UserUpdatedEvent,
    )

    audit_identity_handler = container.audit_container.identity_event_handler()
    event_bus.subscribe(UserCreatedEvent, audit_identity_handler.handle_user_created)
    event_bus.subscribe(UserUpdatedEvent, audit_identity_handler.handle_user_updated)
    event_bus.subscribe(UserDeletedEvent, audit_identity_handler.handle_user_deleted)

    # Identity events -> Notification
    from app.modules.notification.application.event_handlers import (
        IdentityEventHandler as NotificationIdentityHandler,
    )

    notification_identity_handler = (
        container.notification_container.identity_event_handler()
    )
    event_bus.subscribe(
        UserCreatedEvent, notification_identity_handler.handle_user_created
    )
    event_bus.subscribe(
        UserUpdatedEvent, notification_identity_handler.handle_user_updated
    )

    # Audit events -> Notification
    from app.modules.audit.domain.events import CriticalActionPerformedEvent
    from app.modules.notification.application.event_handlers import AuditEventHandler

    notification_audit_handler = container.notification_container.audit_event_handler()
    event_bus.subscribe(
        CriticalActionPerformedEvent, notification_audit_handler.handle_critical_action
    )

    # All events -> Integration
    from app.modules.integration.application.event_handlers import (
        AuditEventHandler as IntegrationAuditHandler,
    )
    from app.modules.integration.application.event_handlers import (
        IdentityEventHandler as IntegrationIdentityHandler,
    )
    from app.modules.integration.application.event_handlers import (
        NotificationEventHandler as IntegrationNotificationHandler,
    )

    integration_identity_handler = (
        container.integration_container.identity_event_handler()
    )
    integration_audit_handler = container.integration_container.audit_event_handler()
    integration_notification_handler = (
        container.integration_container.notification_event_handler()
    )

    # Identity events to Integration
    event_bus.subscribe(
        UserCreatedEvent, integration_identity_handler.handle_user_created
    )
    event_bus.subscribe(
        UserUpdatedEvent, integration_identity_handler.handle_user_updated
    )
    event_bus.subscribe(
        UserDeletedEvent, integration_identity_handler.handle_user_deleted
    )

    # Audit events to Integration
    event_bus.subscribe(
        CriticalActionPerformedEvent, integration_audit_handler.handle_critical_action
    )

    # Notification events to Integration
    from app.modules.notification.domain.events import (
        NotificationFailedEvent,
        NotificationSentEvent,
    )

    event_bus.subscribe(
        NotificationSentEvent, integration_notification_handler.handle_notification_sent
    )
    event_bus.subscribe(
        NotificationFailedEvent,
        integration_notification_handler.handle_notification_failed,
    )

    logger.info("Cross-module event subscriptions configured")


@inject
def initialize_application(
    config: Config = Provide[ApplicationContainer.config],
) -> ApplicationContainer:
    """
    Initialize the application with all modules and dependencies.

    Args:
        config: Application configuration

    Returns:
        ApplicationContainer: Fully initialized application container
    """
    logger.info(f"Initializing application in {config.environment} environment")

    container = create_application()

    # Run any additional initialization based on environment
    if config.environment == "development":
        _setup_development_environment(container)
    elif config.environment == "production":
        _setup_production_environment(container)

    return container


def _setup_development_environment(container: ApplicationContainer) -> None:
    """Setup development-specific configurations."""
    logger.info("Setting up development environment")

    # Enable debug logging for development
    logging.getLogger().setLevel(logging.DEBUG)

    # Setup development database
    database = container.database()
    if hasattr(database, "setup_development_data"):
        database.setup_development_data()


def _setup_production_environment(container: ApplicationContainer) -> None:
    """Setup production-specific configurations."""
    logger.info("Setting up production environment")

    # Setup production monitoring
    cache_manager = container.cache_manager()
    cache_manager.enable_monitoring()

    # Enable production optimizations
    database = container.database()
    database.enable_connection_pooling()


def shutdown_application(container: ApplicationContainer) -> None:
    """
    Gracefully shutdown the application and cleanup resources.

    Args:
        container: Application container to shutdown
    """
    logger.info("Shutting down application")

    try:
        # Shutdown modules in reverse order
        if hasattr(container, "integration_container"):
            logger.info("Shutting down Integration module")
            # Integration module cleanup

        if hasattr(container, "notification_container"):
            logger.info("Shutting down Notification module")
            # Notification module cleanup

        if hasattr(container, "audit_container"):
            logger.info("Shutting down Audit module")
            # Audit module cleanup

        if hasattr(container, "identity_container"):
            logger.info("Shutting down Identity module")
            # Identity module cleanup

        # Shutdown core infrastructure
        if hasattr(container, "cache_manager"):
            container.cache_manager().shutdown()

        if hasattr(container, "database"):
            container.database().shutdown()

        logger.info("Application shutdown completed")

    except Exception:
        logger.exception("Error during application shutdown")
        raise
