"""
Integration module bootstrap configuration.

This module handles the initialization and dependency injection setup
for the Integration bounded context.
"""

import logging

from dependency_injector import containers, providers

from app.modules.integration.application.command_handlers import (
    CreateConnectionCommandHandler,
    CreateIntegrationCommandHandler,
    DeleteIntegrationCommandHandler,
    RegisterWebhookCommandHandler,
    SyncDataCommandHandler,
    TestConnectionCommandHandler,
    UpdateIntegrationCommandHandler,
)
from app.modules.integration.application.event_handlers import (
    AuditEventHandler,
    IdentityEventHandler,
    IntegrationEventHandler,
    NotificationEventHandler,
)
from app.modules.integration.application.query_handlers import (
    GetConnectionQueryHandler,
    GetConnectionsQueryHandler,
    GetIntegrationQueryHandler,
    GetIntegrationsQueryHandler,
    GetSyncStatusQueryHandler,
    GetWebhooksQueryHandler,
)
from app.modules.integration.application.services import (
    ConnectionApplicationService,
    IntegrationApplicationService,
    SyncApplicationService,
    WebhookApplicationService,
)
from app.modules.integration.domain.services import (
    ConnectionManagerService,
    DataSyncService,
    IntegrationDomainService,
    WebhookService,
)
from app.modules.integration.infrastructure.adapters import (
    AnalyticsAdapter,
    CrmAdapter,
    EmailMarketingAdapter,
    ErpAdapter,
    PaymentGatewayAdapter,
)
from app.modules.integration.infrastructure.caching import (
    ConnectionCacheService,
    IntegrationCacheService,
    SyncCacheService,
)
from app.modules.integration.infrastructure.repositories import (
    SqlConnectionRepository,
    SqlIntegrationRepository,
    SqlSyncStatusRepository,
    SqlWebhookRepository,
)
from app.modules.integration.infrastructure.services import (
    DatabaseClient,
    FtpClient,
    GraphQLClient,
    MessageQueueClient,
    RestApiClient,
    SoapClient,
    WebhookDeliveryService,
)

logger = logging.getLogger(__name__)


class IntegrationContainer(containers.DeclarativeContainer):
    """Integration module dependency injection container."""

    # Core dependencies (injected from main container)
    database = providers.Dependency()
    cache_manager = providers.Dependency()
    command_bus = providers.Dependency()
    query_bus = providers.Dependency()
    event_bus = providers.Dependency()
    config = providers.Dependency()

    # Infrastructure clients
    rest_api_client = providers.Singleton(
        RestApiClient,
        timeout=config.provided.integration.api.timeout,
        max_retries=config.provided.integration.api.max_retries,
        rate_limit=config.provided.integration.api.rate_limit,
    )

    graphql_client = providers.Singleton(
        GraphQLClient,
        timeout=config.provided.integration.graphql.timeout,
        max_retries=config.provided.integration.graphql.max_retries,
    )

    soap_client = providers.Singleton(
        SoapClient,
        timeout=config.provided.integration.soap.timeout,
        verify_ssl=config.provided.integration.soap.verify_ssl,
    )

    ftp_client = providers.Singleton(
        FtpClient,
        passive_mode=config.provided.integration.ftp.passive_mode,
        timeout=config.provided.integration.ftp.timeout,
    )

    database_client = providers.Singleton(
        DatabaseClient,
        connection_pool_size=config.provided.integration.database.pool_size,
        connection_timeout=config.provided.integration.database.timeout,
    )

    message_queue_client = providers.Singleton(
        MessageQueueClient,
        connection_string=config.provided.integration.queue.connection_string,
        exchange=config.provided.integration.queue.exchange,
    )

    webhook_delivery_service = providers.Singleton(
        WebhookDeliveryService,
        timeout=config.provided.integration.webhook.timeout,
        max_retries=config.provided.integration.webhook.max_retries,
        retry_delay=config.provided.integration.webhook.retry_delay,
    )

    # Integration adapters
    crm_adapter = providers.Singleton(
        CrmAdapter,
        rest_client=rest_api_client,
        config=config.provided.integration.crm,
    )

    erp_adapter = providers.Singleton(
        ErpAdapter,
        soap_client=soap_client,
        config=config.provided.integration.erp,
    )

    email_marketing_adapter = providers.Singleton(
        EmailMarketingAdapter,
        rest_client=rest_api_client,
        config=config.provided.integration.email_marketing,
    )

    payment_gateway_adapter = providers.Singleton(
        PaymentGatewayAdapter,
        rest_client=rest_api_client,
        config=config.provided.integration.payment_gateway,
    )

    analytics_adapter = providers.Singleton(
        AnalyticsAdapter,
        graphql_client=graphql_client,
        config=config.provided.integration.analytics,
    )

    # Cache services
    integration_cache = providers.Singleton(
        IntegrationCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.integration.cache_ttl,
    )

    connection_cache = providers.Singleton(
        ConnectionCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.integration.connection_cache_ttl,
    )

    sync_cache = providers.Singleton(
        SyncCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.integration.sync_cache_ttl,
    )

    # Repositories
    integration_repository = providers.Singleton(
        SqlIntegrationRepository,
        database=database,
        cache_service=integration_cache,
    )

    connection_repository = providers.Singleton(
        SqlConnectionRepository,
        database=database,
        cache_service=connection_cache,
    )

    sync_status_repository = providers.Singleton(
        SqlSyncStatusRepository,
        database=database,
        cache_service=sync_cache,
    )

    webhook_repository = providers.Singleton(
        SqlWebhookRepository,
        database=database,
    )

    # Domain services
    integration_domain_service = providers.Singleton(
        IntegrationDomainService,
        integration_repository=integration_repository,
        connection_repository=connection_repository,
    )

    connection_manager_service = providers.Singleton(
        ConnectionManagerService,
        connection_repository=connection_repository,
        rest_client=rest_api_client,
        graphql_client=graphql_client,
        soap_client=soap_client,
        database_client=database_client,
    )

    data_sync_service = providers.Singleton(
        DataSyncService,
        sync_status_repository=sync_status_repository,
        connection_manager_service=connection_manager_service,
        integration_repository=integration_repository,
    )

    webhook_service = providers.Singleton(
        WebhookService,
        webhook_repository=webhook_repository,
        webhook_delivery_service=webhook_delivery_service,
    )

    # Application services
    integration_application_service = providers.Singleton(
        IntegrationApplicationService,
        integration_domain_service=integration_domain_service,
        connection_manager_service=connection_manager_service,
        event_bus=event_bus,
    )

    connection_application_service = providers.Singleton(
        ConnectionApplicationService,
        connection_manager_service=connection_manager_service,
        connection_repository=connection_repository,
        event_bus=event_bus,
    )

    sync_application_service = providers.Singleton(
        SyncApplicationService,
        data_sync_service=data_sync_service,
        sync_status_repository=sync_status_repository,
        event_bus=event_bus,
    )

    webhook_application_service = providers.Singleton(
        WebhookApplicationService,
        webhook_service=webhook_service,
        webhook_repository=webhook_repository,
        event_bus=event_bus,
    )

    # Command handlers
    create_integration_command_handler = providers.Singleton(
        CreateIntegrationCommandHandler,
        integration_application_service=integration_application_service,
    )

    update_integration_command_handler = providers.Singleton(
        UpdateIntegrationCommandHandler,
        integration_application_service=integration_application_service,
    )

    delete_integration_command_handler = providers.Singleton(
        DeleteIntegrationCommandHandler,
        integration_application_service=integration_application_service,
    )

    create_connection_command_handler = providers.Singleton(
        CreateConnectionCommandHandler,
        connection_application_service=connection_application_service,
    )

    test_connection_command_handler = providers.Singleton(
        TestConnectionCommandHandler,
        connection_application_service=connection_application_service,
    )

    sync_data_command_handler = providers.Singleton(
        SyncDataCommandHandler,
        sync_application_service=sync_application_service,
    )

    register_webhook_command_handler = providers.Singleton(
        RegisterWebhookCommandHandler,
        webhook_application_service=webhook_application_service,
    )

    # Query handlers
    get_integration_query_handler = providers.Singleton(
        GetIntegrationQueryHandler,
        integration_repository=integration_repository,
    )

    get_integrations_query_handler = providers.Singleton(
        GetIntegrationsQueryHandler,
        integration_repository=integration_repository,
    )

    get_connection_query_handler = providers.Singleton(
        GetConnectionQueryHandler,
        connection_repository=connection_repository,
    )

    get_connections_query_handler = providers.Singleton(
        GetConnectionsQueryHandler,
        connection_repository=connection_repository,
    )

    get_sync_status_query_handler = providers.Singleton(
        GetSyncStatusQueryHandler,
        sync_status_repository=sync_status_repository,
    )

    get_webhooks_query_handler = providers.Singleton(
        GetWebhooksQueryHandler,
        webhook_repository=webhook_repository,
    )

    # Event handlers
    identity_event_handler = providers.Singleton(
        IdentityEventHandler,
        integration_application_service=integration_application_service,
        sync_application_service=sync_application_service,
    )

    audit_event_handler = providers.Singleton(
        AuditEventHandler,
        integration_application_service=integration_application_service,
    )

    notification_event_handler = providers.Singleton(
        NotificationEventHandler,
        webhook_application_service=webhook_application_service,
    )

    integration_event_handler = providers.Singleton(
        IntegrationEventHandler,
        integration_cache=integration_cache,
        sync_application_service=sync_application_service,
    )


class IntegrationBootstrap:
    """Bootstrap class for Integration module."""

    def __init__(self, main_container):
        """
        Initialize Integration bootstrap.

        Args:
            main_container: Main application container
        """
        self.main_container = main_container
        self.logger = logging.getLogger(self.__class__.__name__)

    def bootstrap(self) -> IntegrationContainer:
        """
        Bootstrap the Integration module.

        Returns:
            IntegrationContainer: Configured Integration container
        """
        self.logger.info("Bootstrapping Integration module")

        try:
            # Create container with dependencies
            container = IntegrationContainer()
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

            # Setup adapters
            self._setup_adapters(container)

            # Setup scheduled tasks
            self._setup_scheduled_tasks(container)

            self.logger.info("Integration module bootstrapped successfully")
            return container

        except Exception as e:
            self.logger.exception(f"Failed to bootstrap Integration module: {e}")
            raise

    def _register_command_handlers(self, container: IntegrationContainer) -> None:
        """Register command handlers with the command bus."""
        self.logger.debug("Registering Integration command handlers")

        command_bus = container.command_bus()

        # Import commands
        from app.modules.integration.application.commands import (
            CreateConnectionCommand,
            CreateIntegrationCommand,
            DeleteIntegrationCommand,
            RegisterWebhookCommand,
            SyncDataCommand,
            TestConnectionCommand,
            UpdateIntegrationCommand,
        )

        # Register handlers
        command_bus.register(
            CreateIntegrationCommand, container.create_integration_command_handler()
        )
        command_bus.register(
            UpdateIntegrationCommand, container.update_integration_command_handler()
        )
        command_bus.register(
            DeleteIntegrationCommand, container.delete_integration_command_handler()
        )
        command_bus.register(
            CreateConnectionCommand, container.create_connection_command_handler()
        )
        command_bus.register(
            TestConnectionCommand, container.test_connection_command_handler()
        )
        command_bus.register(SyncDataCommand, container.sync_data_command_handler())
        command_bus.register(
            RegisterWebhookCommand, container.register_webhook_command_handler()
        )

        self.logger.debug("Integration command handlers registered")

    def _register_query_handlers(self, container: IntegrationContainer) -> None:
        """Register query handlers with the query bus."""
        self.logger.debug("Registering Integration query handlers")

        query_bus = container.query_bus()

        # Import queries
        from app.modules.integration.application.queries import (
            GetConnectionQuery,
            GetConnectionsQuery,
            GetIntegrationQuery,
            GetIntegrationsQuery,
            GetSyncStatusQuery,
            GetWebhooksQuery,
        )

        # Register handlers
        query_bus.register(
            GetIntegrationQuery, container.get_integration_query_handler()
        )
        query_bus.register(
            GetIntegrationsQuery, container.get_integrations_query_handler()
        )
        query_bus.register(GetConnectionQuery, container.get_connection_query_handler())
        query_bus.register(
            GetConnectionsQuery, container.get_connections_query_handler()
        )
        query_bus.register(
            GetSyncStatusQuery, container.get_sync_status_query_handler()
        )
        query_bus.register(GetWebhooksQuery, container.get_webhooks_query_handler())

        self.logger.debug("Integration query handlers registered")

    def _register_event_handlers(self, container: IntegrationContainer) -> None:
        """Register event handlers with the event bus."""
        self.logger.debug("Registering Integration event handlers")

        event_bus = container.event_bus()

        # Import events
        from app.modules.integration.domain.events import (
            ConnectionEstablishedEvent,
            ConnectionFailedEvent,
            DataSyncCompletedEvent,
            DataSyncFailedEvent,
            DataSyncStartedEvent,
            IntegrationCreatedEvent,
            IntegrationDeletedEvent,
            IntegrationUpdatedEvent,
            WebhookDeliveredEvent,
            WebhookFailedEvent,
            WebhookRegisteredEvent,
        )

        # Get handlers
        integration_event_handler = container.integration_event_handler()

        # Register integration events
        event_bus.subscribe(
            IntegrationCreatedEvent,
            integration_event_handler.handle_integration_created,
        )
        event_bus.subscribe(
            IntegrationUpdatedEvent,
            integration_event_handler.handle_integration_updated,
        )
        event_bus.subscribe(
            IntegrationDeletedEvent,
            integration_event_handler.handle_integration_deleted,
        )
        event_bus.subscribe(
            ConnectionEstablishedEvent,
            integration_event_handler.handle_connection_established,
        )
        event_bus.subscribe(
            ConnectionFailedEvent, integration_event_handler.handle_connection_failed
        )
        event_bus.subscribe(
            DataSyncStartedEvent, integration_event_handler.handle_data_sync_started
        )
        event_bus.subscribe(
            DataSyncCompletedEvent, integration_event_handler.handle_data_sync_completed
        )
        event_bus.subscribe(
            DataSyncFailedEvent, integration_event_handler.handle_data_sync_failed
        )
        event_bus.subscribe(
            WebhookRegisteredEvent, integration_event_handler.handle_webhook_registered
        )
        event_bus.subscribe(
            WebhookDeliveredEvent, integration_event_handler.handle_webhook_delivered
        )
        event_bus.subscribe(
            WebhookFailedEvent, integration_event_handler.handle_webhook_failed
        )

        self.logger.debug("Integration event handlers registered")

    def _initialize_services(self, container: IntegrationContainer) -> None:
        """Initialize and configure services."""
        self.logger.debug("Initializing Integration services")

        # Initialize clients
        container.rest_api_client().initialize()
        container.graphql_client().initialize()
        container.soap_client().initialize()
        container.ftp_client().initialize()
        container.database_client().initialize()
        container.message_queue_client().initialize()
        container.webhook_delivery_service().initialize()

        # Initialize cache services
        container.integration_cache().initialize()
        container.connection_cache().initialize()
        container.sync_cache().initialize()

        self.logger.debug("Integration services initialized")

    def _setup_adapters(self, container: IntegrationContainer) -> None:
        """Setup integration adapters."""
        self.logger.debug("Setting up integration adapters")

        config = container.config()

        # Initialize enabled adapters
        if config.integration.crm.enabled:
            container.crm_adapter().initialize()
            self.logger.debug("CRM adapter initialized")

        if config.integration.erp.enabled:
            container.erp_adapter().initialize()
            self.logger.debug("ERP adapter initialized")

        if config.integration.email_marketing.enabled:
            container.email_marketing_adapter().initialize()
            self.logger.debug("Email marketing adapter initialized")

        if config.integration.payment_gateway.enabled:
            container.payment_gateway_adapter().initialize()
            self.logger.debug("Payment gateway adapter initialized")

        if config.integration.analytics.enabled:
            container.analytics_adapter().initialize()
            self.logger.debug("Analytics adapter initialized")

    def _setup_scheduled_tasks(self, container: IntegrationContainer) -> None:
        """Setup scheduled tasks for integration operations."""
        self.logger.debug("Setting up Integration scheduled tasks")

        config = container.config()

        # Setup sync monitoring task
        if config.integration.enable_sync_monitoring:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._monitor_sync_status,
                trigger="interval",
                minutes=config.integration.sync_monitoring_interval_minutes,
                args=[container],
                id="monitor_sync_status",
                replace_existing=True,
            )

            self.logger.debug("Scheduled sync monitoring task")

        # Setup connection health check task
        if config.integration.enable_connection_health_check:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._check_connection_health,
                trigger="interval",
                minutes=config.integration.health_check_interval_minutes,
                args=[container],
                id="check_connection_health",
                replace_existing=True,
            )

            self.logger.debug("Scheduled connection health check task")

        # Setup webhook retry task
        if config.integration.enable_webhook_retry:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._retry_failed_webhooks,
                trigger="interval",
                minutes=config.integration.webhook_retry_interval_minutes,
                args=[container],
                id="retry_failed_webhooks",
                replace_existing=True,
            )

            self.logger.debug("Scheduled webhook retry task")

    def _monitor_sync_status(self, container: IntegrationContainer) -> None:
        """Monitor sync status and handle stalled syncs."""
        try:
            sync_application_service = container.sync_application_service()
            sync_application_service.monitor_sync_status()

            self.logger.debug("Sync status monitoring completed")

        except Exception as e:
            self.logger.exception(f"Failed to monitor sync status: {e}")

    def _check_connection_health(self, container: IntegrationContainer) -> None:
        """Check health of all active connections."""
        try:
            connection_application_service = container.connection_application_service()
            connection_application_service.check_all_connections_health()

            self.logger.debug("Connection health check completed")

        except Exception as e:
            self.logger.exception(f"Failed to check connection health: {e}")

    def _retry_failed_webhooks(self, container: IntegrationContainer) -> None:
        """Retry failed webhook deliveries."""
        try:
            webhook_application_service = container.webhook_application_service()
            webhook_application_service.retry_failed_webhooks()

            self.logger.debug("Webhook retry completed")

        except Exception as e:
            self.logger.exception(f"Failed to retry webhooks: {e}")
