"""
Notification module bootstrap configuration.

This module handles the initialization and dependency injection setup
for the Notification bounded context.
"""

import logging

from dependency_injector import containers, providers

from app.modules.notification.application.command_handlers import (
    CreateTemplateCommandHandler,
    RetryFailedNotificationCommandHandler,
    ScheduleNotificationCommandHandler,
    SendNotificationCommandHandler,
    UpdatePreferencesCommandHandler,
    UpdateTemplateCommandHandler,
)
from app.modules.notification.application.event_handlers import (
    AuditEventHandler,
    IdentityEventHandler,
    NotificationEventHandler,
)
from app.modules.notification.application.query_handlers import (
    GetDeliveryStatusQueryHandler,
    GetNotificationHistoryQueryHandler,
    GetNotificationQueryHandler,
    GetNotificationsQueryHandler,
    GetPreferencesQueryHandler,
    GetTemplateQueryHandler,
    GetTemplatesQueryHandler,
)
from app.modules.notification.application.services import (
    DeliveryApplicationService,
    NotificationApplicationService,
    PreferenceApplicationService,
    TemplateApplicationService,
)
from app.modules.notification.domain.services import (
    DeliverySchedulingService,
    NotificationDomainService,
    PreferenceManagementService,
    TemplateRenderingService,
)
from app.modules.notification.infrastructure.caching import (
    NotificationCacheService,
    PreferenceCacheService,
    TemplateCacheService,
)
from app.modules.notification.infrastructure.repositories import (
    SqlDeliveryStatusRepository,
    SqlNotificationPreferenceRepository,
    SqlNotificationRepository,
    SqlNotificationTemplateRepository,
)
from app.modules.notification.infrastructure.services import (
    DeliveryQueueService,
    EmailService,
    PushNotificationService,
    SmsService,
    TemplateEngine,
    WebhookService,
)

logger = logging.getLogger(__name__)


class NotificationContainer(containers.DeclarativeContainer):
    """Notification module dependency injection container."""

    # Core dependencies (injected from main container)
    database = providers.Dependency()
    cache_manager = providers.Dependency()
    command_bus = providers.Dependency()
    query_bus = providers.Dependency()
    event_bus = providers.Dependency()
    config = providers.Dependency()

    # Infrastructure services
    email_service = providers.Singleton(
        EmailService,
        smtp_host=config.provided.notification.email.smtp_host,
        smtp_port=config.provided.notification.email.smtp_port,
        smtp_username=config.provided.notification.email.smtp_username,
        smtp_password=config.provided.notification.email.smtp_password,
        use_tls=config.provided.notification.email.use_tls,
        from_address=config.provided.notification.email.from_address,
        from_name=config.provided.notification.email.from_name,
    )

    sms_service = providers.Singleton(
        SmsService,
        provider=config.provided.notification.sms.provider,
        api_key=config.provided.notification.sms.api_key,
        api_secret=config.provided.notification.sms.api_secret,
        from_number=config.provided.notification.sms.from_number,
    )

    push_notification_service = providers.Singleton(
        PushNotificationService,
        fcm_server_key=config.provided.notification.push.fcm_server_key,
        apns_certificate_path=config.provided.notification.push.apns_certificate_path,
        apns_key_id=config.provided.notification.push.apns_key_id,
        apns_team_id=config.provided.notification.push.apns_team_id,
    )

    webhook_service = providers.Singleton(
        WebhookService,
        timeout=config.provided.notification.webhook.timeout,
        max_retries=config.provided.notification.webhook.max_retries,
        retry_delay=config.provided.notification.webhook.retry_delay,
    )

    template_engine = providers.Singleton(
        TemplateEngine,
        template_path=config.provided.notification.template_path,
        cache_templates=config.provided.notification.cache_templates,
    )

    delivery_queue_service = providers.Singleton(
        DeliveryQueueService,
        queue_backend=config.provided.notification.queue.backend,
        connection_string=config.provided.notification.queue.connection_string,
        max_workers=config.provided.notification.queue.max_workers,
        retry_policy=config.provided.notification.queue.retry_policy,
    )

    # Cache services
    notification_cache = providers.Singleton(
        NotificationCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.notification.cache_ttl,
    )

    template_cache = providers.Singleton(
        TemplateCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.notification.template_cache_ttl,
    )

    preference_cache = providers.Singleton(
        PreferenceCacheService,
        cache_manager=cache_manager,
        ttl=config.provided.notification.preference_cache_ttl,
    )

    # Repositories
    notification_repository = providers.Singleton(
        SqlNotificationRepository,
        database=database,
        cache_service=notification_cache,
    )

    template_repository = providers.Singleton(
        SqlNotificationTemplateRepository,
        database=database,
        cache_service=template_cache,
    )

    preference_repository = providers.Singleton(
        SqlNotificationPreferenceRepository,
        database=database,
        cache_service=preference_cache,
    )

    delivery_status_repository = providers.Singleton(
        SqlDeliveryStatusRepository,
        database=database,
    )

    # Domain services
    notification_domain_service = providers.Singleton(
        NotificationDomainService,
        notification_repository=notification_repository,
        preference_repository=preference_repository,
    )

    template_rendering_service = providers.Singleton(
        TemplateRenderingService,
        template_repository=template_repository,
        template_engine=template_engine,
    )

    delivery_scheduling_service = providers.Singleton(
        DeliverySchedulingService,
        delivery_queue_service=delivery_queue_service,
        preference_repository=preference_repository,
    )

    preference_management_service = providers.Singleton(
        PreferenceManagementService,
        preference_repository=preference_repository,
    )

    # Application services
    notification_application_service = providers.Singleton(
        NotificationApplicationService,
        notification_domain_service=notification_domain_service,
        template_rendering_service=template_rendering_service,
        delivery_scheduling_service=delivery_scheduling_service,
        event_bus=event_bus,
    )

    template_application_service = providers.Singleton(
        TemplateApplicationService,
        template_repository=template_repository,
        template_rendering_service=template_rendering_service,
        event_bus=event_bus,
    )

    delivery_application_service = providers.Singleton(
        DeliveryApplicationService,
        notification_repository=notification_repository,
        delivery_status_repository=delivery_status_repository,
        email_service=email_service,
        sms_service=sms_service,
        push_notification_service=push_notification_service,
        webhook_service=webhook_service,
        event_bus=event_bus,
    )

    preference_application_service = providers.Singleton(
        PreferenceApplicationService,
        preference_management_service=preference_management_service,
        preference_repository=preference_repository,
        event_bus=event_bus,
    )

    # Command handlers
    send_notification_command_handler = providers.Singleton(
        SendNotificationCommandHandler,
        notification_application_service=notification_application_service,
    )

    create_template_command_handler = providers.Singleton(
        CreateTemplateCommandHandler,
        template_application_service=template_application_service,
    )

    update_template_command_handler = providers.Singleton(
        UpdateTemplateCommandHandler,
        template_application_service=template_application_service,
    )

    update_preferences_command_handler = providers.Singleton(
        UpdatePreferencesCommandHandler,
        preference_application_service=preference_application_service,
    )

    schedule_notification_command_handler = providers.Singleton(
        ScheduleNotificationCommandHandler,
        notification_application_service=notification_application_service,
    )

    retry_failed_notification_command_handler = providers.Singleton(
        RetryFailedNotificationCommandHandler,
        delivery_application_service=delivery_application_service,
    )

    # Query handlers
    get_notification_query_handler = providers.Singleton(
        GetNotificationQueryHandler,
        notification_repository=notification_repository,
    )

    get_notifications_query_handler = providers.Singleton(
        GetNotificationsQueryHandler,
        notification_repository=notification_repository,
    )

    get_template_query_handler = providers.Singleton(
        GetTemplateQueryHandler,
        template_repository=template_repository,
    )

    get_templates_query_handler = providers.Singleton(
        GetTemplatesQueryHandler,
        template_repository=template_repository,
    )

    get_preferences_query_handler = providers.Singleton(
        GetPreferencesQueryHandler,
        preference_repository=preference_repository,
    )

    get_delivery_status_query_handler = providers.Singleton(
        GetDeliveryStatusQueryHandler,
        delivery_status_repository=delivery_status_repository,
    )

    get_notification_history_query_handler = providers.Singleton(
        GetNotificationHistoryQueryHandler,
        notification_repository=notification_repository,
        delivery_status_repository=delivery_status_repository,
    )

    # Event handlers
    identity_event_handler = providers.Singleton(
        IdentityEventHandler,
        preference_application_service=preference_application_service,
        notification_application_service=notification_application_service,
    )

    audit_event_handler = providers.Singleton(
        AuditEventHandler,
        notification_application_service=notification_application_service,
    )

    notification_event_handler = providers.Singleton(
        NotificationEventHandler,
        notification_cache=notification_cache,
        delivery_application_service=delivery_application_service,
    )


class NotificationBootstrap:
    """Bootstrap class for Notification module."""

    def __init__(self, main_container):
        """
        Initialize Notification bootstrap.

        Args:
            main_container: Main application container
        """
        self.main_container = main_container
        self.logger = logging.getLogger(self.__class__.__name__)

    def bootstrap(self) -> NotificationContainer:
        """
        Bootstrap the Notification module.

        Returns:
            NotificationContainer: Configured Notification container
        """
        self.logger.info("Bootstrapping Notification module")

        try:
            # Create container with dependencies
            container = NotificationContainer()
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

            # Setup delivery workers
            self._setup_delivery_workers(container)

            # Setup default templates
            self._setup_default_templates(container)

            self.logger.info("Notification module bootstrapped successfully")
            return container

        except Exception as e:
            self.logger.exception(f"Failed to bootstrap Notification module: {e}")
            raise

    def _register_command_handlers(self, container: NotificationContainer) -> None:
        """Register command handlers with the command bus."""
        self.logger.debug("Registering Notification command handlers")

        command_bus = container.command_bus()

        # Import commands
        from app.modules.notification.application.commands import (
            CreateTemplateCommand,
            RetryFailedNotificationCommand,
            ScheduleNotificationCommand,
            SendNotificationCommand,
            UpdatePreferencesCommand,
            UpdateTemplateCommand,
        )

        # Register handlers
        command_bus.register(
            SendNotificationCommand, container.send_notification_command_handler()
        )
        command_bus.register(
            CreateTemplateCommand, container.create_template_command_handler()
        )
        command_bus.register(
            UpdateTemplateCommand, container.update_template_command_handler()
        )
        command_bus.register(
            UpdatePreferencesCommand, container.update_preferences_command_handler()
        )
        command_bus.register(
            ScheduleNotificationCommand,
            container.schedule_notification_command_handler(),
        )
        command_bus.register(
            RetryFailedNotificationCommand,
            container.retry_failed_notification_command_handler(),
        )

        self.logger.debug("Notification command handlers registered")

    def _register_query_handlers(self, container: NotificationContainer) -> None:
        """Register query handlers with the query bus."""
        self.logger.debug("Registering Notification query handlers")

        query_bus = container.query_bus()

        # Import queries
        from app.modules.notification.application.queries import (
            GetDeliveryStatusQuery,
            GetNotificationHistoryQuery,
            GetNotificationQuery,
            GetNotificationsQuery,
            GetPreferencesQuery,
            GetTemplateQuery,
            GetTemplatesQuery,
        )

        # Register handlers
        query_bus.register(
            GetNotificationQuery, container.get_notification_query_handler()
        )
        query_bus.register(
            GetNotificationsQuery, container.get_notifications_query_handler()
        )
        query_bus.register(GetTemplateQuery, container.get_template_query_handler())
        query_bus.register(GetTemplatesQuery, container.get_templates_query_handler())
        query_bus.register(
            GetPreferencesQuery, container.get_preferences_query_handler()
        )
        query_bus.register(
            GetDeliveryStatusQuery, container.get_delivery_status_query_handler()
        )
        query_bus.register(
            GetNotificationHistoryQuery,
            container.get_notification_history_query_handler(),
        )

        self.logger.debug("Notification query handlers registered")

    def _register_event_handlers(self, container: NotificationContainer) -> None:
        """Register event handlers with the event bus."""
        self.logger.debug("Registering Notification event handlers")

        event_bus = container.event_bus()

        # Import events
        from app.modules.notification.domain.events import (
            NotificationCreatedEvent,
            NotificationFailedEvent,
            NotificationScheduledEvent,
            NotificationSentEvent,
            PreferencesUpdatedEvent,
            TemplateCreatedEvent,
            TemplateUpdatedEvent,
        )

        # Get handlers
        notification_event_handler = container.notification_event_handler()

        # Register notification events
        event_bus.subscribe(
            NotificationCreatedEvent,
            notification_event_handler.handle_notification_created,
        )
        event_bus.subscribe(
            NotificationSentEvent, notification_event_handler.handle_notification_sent
        )
        event_bus.subscribe(
            NotificationFailedEvent,
            notification_event_handler.handle_notification_failed,
        )
        event_bus.subscribe(
            NotificationScheduledEvent,
            notification_event_handler.handle_notification_scheduled,
        )
        event_bus.subscribe(
            TemplateCreatedEvent, notification_event_handler.handle_template_created
        )
        event_bus.subscribe(
            TemplateUpdatedEvent, notification_event_handler.handle_template_updated
        )
        event_bus.subscribe(
            PreferencesUpdatedEvent,
            notification_event_handler.handle_preferences_updated,
        )

        self.logger.debug("Notification event handlers registered")

    def _initialize_services(self, container: NotificationContainer) -> None:
        """Initialize and configure services."""
        self.logger.debug("Initializing Notification services")

        # Initialize delivery services
        container.email_service().initialize()
        container.sms_service().initialize()
        container.push_notification_service().initialize()
        container.webhook_service().initialize()

        # Initialize template engine
        container.template_engine().initialize()

        # Initialize delivery queue
        container.delivery_queue_service().initialize()

        # Initialize cache services
        container.notification_cache().initialize()
        container.template_cache().initialize()
        container.preference_cache().initialize()

        self.logger.debug("Notification services initialized")

    def _setup_delivery_workers(self, container: NotificationContainer) -> None:
        """Setup delivery workers for processing notifications."""
        self.logger.debug("Setting up notification delivery workers")

        config = container.config()
        delivery_queue_service = container.delivery_queue_service()
        delivery_application_service = container.delivery_application_service()

        # Setup email worker
        delivery_queue_service.register_worker(
            queue_name="email_notifications",
            handler=delivery_application_service.process_email_notification,
            max_workers=config.notification.email.max_workers,
        )

        # Setup SMS worker
        delivery_queue_service.register_worker(
            queue_name="sms_notifications",
            handler=delivery_application_service.process_sms_notification,
            max_workers=config.notification.sms.max_workers,
        )

        # Setup push notification worker
        delivery_queue_service.register_worker(
            queue_name="push_notifications",
            handler=delivery_application_service.process_push_notification,
            max_workers=config.notification.push.max_workers,
        )

        # Setup webhook worker
        delivery_queue_service.register_worker(
            queue_name="webhook_notifications",
            handler=delivery_application_service.process_webhook_notification,
            max_workers=config.notification.webhook.max_workers,
        )

        # Start workers
        delivery_queue_service.start_workers()

        self.logger.debug("Notification delivery workers started")

    def _setup_default_templates(self, container: NotificationContainer) -> None:
        """Setup default notification templates if none exist."""
        self.logger.debug("Setting up default notification templates")

        try:
            template_repository = container.template_repository()
            existing_templates = template_repository.find_all()

            if not existing_templates:
                # Create default templates
                from app.modules.notification.domain.entities import (
                    NotificationTemplate,
                )
                from app.modules.notification.domain.value_objects import (
                    NotificationChannel,
                    TemplateType,
                )

                default_templates = [
                    NotificationTemplate(
                        name="welcome_email",
                        description="Welcome email for new users",
                        template_type=TemplateType.TRANSACTIONAL,
                        channel=NotificationChannel.EMAIL,
                        subject="Welcome to {{ app_name }}!",
                        body_template="""
                        <h1>Welcome {{ user_name }}!</h1>
                        <p>Thank you for joining {{ app_name }}. We're excited to have you aboard!</p>
                        <p>Here are some things you can do to get started:</p>
                        <ul>
                            <li>Complete your profile</li>
                            <li>Explore our features</li>
                            <li>Connect with other users</li>
                        </ul>
                        <p>If you have any questions, feel free to contact our support team.</p>
                        """,
                        variables=["user_name", "app_name"],
                        is_active=True,
                    ),
                    NotificationTemplate(
                        name="password_reset_email",
                        description="Password reset email",
                        template_type=TemplateType.TRANSACTIONAL,
                        channel=NotificationChannel.EMAIL,
                        subject="Reset your password",
                        body_template="""
                        <h1>Password Reset Request</h1>
                        <p>Hi {{ user_name }},</p>
                        <p>You requested to reset your password. Click the link below to create a new password:</p>
                        <p><a href="{{ reset_link }}">Reset Password</a></p>
                        <p>This link will expire in {{ expiry_hours }} hours.</p>
                        <p>If you didn't request this, please ignore this email.</p>
                        """,
                        variables=["user_name", "reset_link", "expiry_hours"],
                        is_active=True,
                    ),
                    NotificationTemplate(
                        name="security_alert_sms",
                        description="Security alert SMS",
                        template_type=TemplateType.ALERT,
                        channel=NotificationChannel.SMS,
                        subject=None,
                        body_template="SECURITY ALERT: Suspicious login detected on your {{ app_name }} account at {{ timestamp }}. If this wasn't you, please secure your account immediately.",
                        variables=["app_name", "timestamp"],
                        is_active=True,
                    ),
                    NotificationTemplate(
                        name="system_maintenance",
                        description="System maintenance notification",
                        template_type=TemplateType.ANNOUNCEMENT,
                        channel=NotificationChannel.PUSH,
                        subject="Scheduled Maintenance",
                        body_template="{{ app_name }} will undergo scheduled maintenance on {{ maintenance_date }} from {{ start_time }} to {{ end_time }}. Service may be temporarily unavailable.",
                        variables=[
                            "app_name",
                            "maintenance_date",
                            "start_time",
                            "end_time",
                        ],
                        is_active=True,
                    ),
                ]

                for template in default_templates:
                    template_repository.save(template)

                self.logger.info(
                    f"Created {len(default_templates)} default notification templates"
                )

        except Exception as e:
            self.logger.warning(f"Failed to setup default templates: {e}")

    def _setup_scheduled_tasks(self, container: NotificationContainer) -> None:
        """Setup scheduled tasks for notification operations."""
        self.logger.debug("Setting up Notification scheduled tasks")

        config = container.config()

        # Setup retry failed notifications task
        if config.notification.enable_retry_failed:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._retry_failed_notifications,
                trigger="interval",
                minutes=config.notification.retry_interval_minutes,
                args=[container],
                id="retry_failed_notifications",
                replace_existing=True,
            )

            self.logger.debug("Scheduled retry failed notifications task")

        # Setup cleanup old notifications task
        if config.notification.enable_cleanup:
            from app.core.scheduler import scheduler

            scheduler.add_job(
                func=self._cleanup_old_notifications,
                trigger="cron",
                hour=config.notification.cleanup_hour,
                minute=0,
                args=[container],
                id="cleanup_old_notifications",
                replace_existing=True,
            )

            self.logger.debug("Scheduled notification cleanup task")

    def _retry_failed_notifications(self, container: NotificationContainer) -> None:
        """Retry failed notifications."""
        try:
            delivery_application_service = container.delivery_application_service()
            delivery_application_service.retry_failed_notifications()

            self.logger.debug("Retried failed notifications")

        except Exception as e:
            self.logger.exception(f"Failed to retry notifications: {e}")

    def _cleanup_old_notifications(self, container: NotificationContainer) -> None:
        """Cleanup old notifications."""
        try:
            config = container.config()
            notification_repository = container.notification_repository()

            from datetime import datetime, timedelta

            cutoff_date = datetime.utcnow() - timedelta(
                days=config.notification.retention_days
            )
            notification_repository.delete_older_than(cutoff_date)

            self.logger.info(f"Cleaned up notifications older than {cutoff_date}")

        except Exception as e:
            self.logger.exception(f"Failed to cleanup old notifications: {e}")
