"""Notification Application Layer.

This module contains the application layer for the notification module,
implementing the use cases and orchestrating domain operations.

The application layer includes:
- Command handlers for modifying notification state
- Query handlers for retrieving notification data
- Application services for complex business operations
- Event handlers for cross-module integration
- DTOs for data transfer between layers

Architecture:
- Commands represent intents to change state
- Queries represent requests for information
- Handlers implement the business logic
- Services orchestrate complex operations
- Event handlers enable loose coupling between modules
"""

from dataclasses import dataclass
from typing import Any

# Commands
from app.modules.notification.application.commands import (
    CancelScheduledNotificationCommand,
    CreateTemplateCommand,
    ProcessBatchCommand,
    RetryNotificationCommand,
    ScheduleNotificationCommand,
    SendNotificationCommand,
    UpdateRecipientPreferencesCommand,
    UpdateTemplateCommand,
)

# Command Handlers
from app.modules.notification.application.commands.handlers import (
    CancelScheduledNotificationCommandHandler,
    CreateTemplateCommandHandler,
    ProcessBatchCommandHandler,
    RetryNotificationCommandHandler,
    ScheduleNotificationCommandHandler,
    SendNotificationCommandHandler,
    UpdateRecipientPreferencesCommandHandler,
    UpdateTemplateCommandHandler,
)

# DTOs
from app.modules.notification.application.dto import (
    BatchStatusDTO,
    ChannelStatusDTO,
    DeliveryReportDTO,
    NotificationHistoryDTO,
    NotificationRequestDTO,
    NotificationResponseDTO,
    RecipientPreferencesDTO,
    ScheduledNotificationDTO,
    TemplateDTO,
)

# Event Handlers
from app.modules.notification.application.event_handlers import (
    EVENT_HANDLERS,
    ComplianceViolationEventHandler,
    DataSyncCompletedEventHandler,
    SecurityIncidentDetectedEventHandler,
    UserDeactivatedEventHandler,
    UserRegisteredEventHandler,
)

# Queries
from app.modules.notification.application.queries import (
    GetBatchStatusQuery,
    GetChannelStatusQuery,
    GetDeliveryStatusQuery,
    GetNotificationHistoryQuery,
    GetNotificationMetricsQuery,
    GetNotificationQuery,
    GetRecipientPreferencesQuery,
    GetTemplateQuery,
    ListScheduledNotificationsQuery,
    ListTemplatesQuery,
    SearchNotificationsQuery,
)

# Query Handlers
from app.modules.notification.application.queries.handlers import (
    GetBatchStatusQueryHandler,
    GetChannelStatusQueryHandler,
    GetDeliveryStatusQueryHandler,
    GetNotificationHistoryQueryHandler,
    GetNotificationMetricsQueryHandler,
    GetNotificationQueryHandler,
    GetRecipientPreferencesQueryHandler,
    GetTemplateQueryHandler,
    ListScheduledNotificationsQueryHandler,
    ListTemplatesQueryHandler,
    SearchNotificationsQueryHandler,
)

# Services
from app.modules.notification.application.services import (
    DeliveryService,
    NotificationService,
    PreferenceService,
    SchedulingService,
    TemplateService,
)


@dataclass
class NotificationApplicationDependencies:
    """Dependencies for notification application module."""
    
    notification_repository: Any
    template_repository: Any
    recipient_repository: Any
    schedule_repository: Any
    batch_repository: Any
    delivery_service: Any
    channel_service: Any
    metrics_service: Any
    search_service: Any
    event_publisher: Any
    command_bus: Any
    query_bus: Any
    config: Any


class NotificationApplicationModule:
    """Main application module for notification functionality.

    This class serves as the entry point for the notification application layer,
    providing factory methods for creating handlers and services with proper
    dependency injection.
    """

    def __init__(self, dependencies: NotificationApplicationDependencies):
        """Initialize application module with dependencies."""
        self.deps = dependencies
        
        # For backward compatibility, expose dependencies as attributes
        self.notification_repository = dependencies.notification_repository
        self.template_repository = dependencies.template_repository
        self.recipient_repository = dependencies.recipient_repository
        self.schedule_repository = dependencies.schedule_repository
        self.batch_repository = dependencies.batch_repository
        self.delivery_service = dependencies.delivery_service
        self.channel_service = dependencies.channel_service
        self.metrics_service = dependencies.metrics_service
        self.search_service = dependencies.search_service
        self.event_publisher = dependencies.event_publisher
        self.command_bus = dependencies.command_bus
        self.query_bus = dependencies.query_bus
        self.config = dependencies.config

        # Initialize services
        self._init_services()

        # Register handlers
        self._register_command_handlers()
        self._register_query_handlers()
        self._register_event_handlers()

    def _init_services(self):
        """Initialize application services."""
        self.notification_service = NotificationService(
            notification_repository=self.notification_repository,
            template_repository=self.template_repository,
            recipient_repository=self.recipient_repository,
            delivery_service=self.delivery_service,
            event_publisher=self.event_publisher,
        )

        self.template_service = TemplateService(
            template_repository=self.template_repository,
            event_publisher=self.event_publisher,
        )

        self.delivery_service_wrapper = DeliveryService(
            channel_providers=self.delivery_service.channel_providers,
            rate_limiter=self.delivery_service.rate_limiter,
            metrics_service=self.metrics_service,
        )

        self.scheduling_service = SchedulingService(
            schedule_repository=self.schedule_repository,
            notification_service=self.notification_service,
            event_publisher=self.event_publisher,
        )

        self.preference_service = PreferenceService(
            recipient_repository=self.recipient_repository,
            event_publisher=self.event_publisher,
        )

    def _register_command_handlers(self):
        """Register command handlers with the command bus."""
        # Create command handlers
        send_notification_handler = SendNotificationCommandHandler(
            notification_repository=self.notification_repository,
            template_repository=self.template_repository,
            recipient_repository=self.recipient_repository,
            delivery_service=self.delivery_service,
            event_publisher=self.event_publisher,
        )

        create_template_handler = CreateTemplateCommandHandler(
            template_repository=self.template_repository,
            event_publisher=self.event_publisher,
        )

        schedule_notification_handler = ScheduleNotificationCommandHandler(
            schedule_repository=self.schedule_repository,
            event_publisher=self.event_publisher,
        )

        process_batch_handler = ProcessBatchCommandHandler(
            batch_repository=self.batch_repository,
            notification_service=self.notification_service,
            event_publisher=self.event_publisher,
        )

        update_preferences_handler = UpdateRecipientPreferencesCommandHandler(
            recipient_repository=self.recipient_repository,
            event_publisher=self.event_publisher,
        )

        cancel_scheduled_handler = CancelScheduledNotificationCommandHandler(
            schedule_repository=self.schedule_repository,
            event_publisher=self.event_publisher,
        )

        retry_notification_handler = RetryNotificationCommandHandler(
            notification_repository=self.notification_repository,
            delivery_service=self.delivery_service,
            event_publisher=self.event_publisher,
        )

        update_template_handler = UpdateTemplateCommandHandler(
            template_repository=self.template_repository,
            event_publisher=self.event_publisher,
        )

        # Register handlers
        self.command_bus.register(send_notification_handler)
        self.command_bus.register(create_template_handler)
        self.command_bus.register(schedule_notification_handler)
        self.command_bus.register(process_batch_handler)
        self.command_bus.register(update_preferences_handler)
        self.command_bus.register(cancel_scheduled_handler)
        self.command_bus.register(retry_notification_handler)
        self.command_bus.register(update_template_handler)

    def _register_query_handlers(self):
        """Register query handlers with the query bus."""
        # Create query handlers
        get_notification_handler = GetNotificationQueryHandler(
            notification_repository=self.notification_repository
        )

        get_template_handler = GetTemplateQueryHandler(
            template_repository=self.template_repository
        )

        get_preferences_handler = GetRecipientPreferencesQueryHandler(
            recipient_repository=self.recipient_repository
        )

        get_history_handler = GetNotificationHistoryQueryHandler(
            notification_repository=self.notification_repository
        )

        get_delivery_status_handler = GetDeliveryStatusQueryHandler(
            notification_repository=self.notification_repository,
            delivery_service=self.delivery_service,
        )

        get_batch_status_handler = GetBatchStatusQueryHandler(
            batch_repository=self.batch_repository
        )

        list_templates_handler = ListTemplatesQueryHandler(
            template_repository=self.template_repository
        )

        list_scheduled_handler = ListScheduledNotificationsQueryHandler(
            schedule_repository=self.schedule_repository
        )

        get_channel_status_handler = GetChannelStatusQueryHandler(
            channel_service=self.channel_service, metrics_service=self.metrics_service
        )

        get_metrics_handler = GetNotificationMetricsQueryHandler(
            metrics_service=self.metrics_service
        )

        search_notifications_handler = SearchNotificationsQueryHandler(
            notification_repository=self.notification_repository,
            search_service=self.search_service,
        )

        # Register handlers
        self.query_bus.register(get_notification_handler)
        self.query_bus.register(get_template_handler)
        self.query_bus.register(get_preferences_handler)
        self.query_bus.register(get_history_handler)
        self.query_bus.register(get_delivery_status_handler)
        self.query_bus.register(get_batch_status_handler)
        self.query_bus.register(list_templates_handler)
        self.query_bus.register(list_scheduled_handler)
        self.query_bus.register(get_channel_status_handler)
        self.query_bus.register(get_metrics_handler)
        self.query_bus.register(search_notifications_handler)

    def _register_event_handlers(self):
        """Register event handlers for cross-module integration."""
        # Create event handlers
        user_registered_handler = UserRegisteredEventHandler(
            command_bus=self.command_bus, template_repository=self.template_repository
        )

        user_deactivated_handler = UserDeactivatedEventHandler(
            command_bus=self.command_bus, template_repository=self.template_repository
        )

        security_incident_handler = SecurityIncidentDetectedEventHandler(
            command_bus=self.command_bus,
            template_repository=self.template_repository,
            config=self.config,
        )

        compliance_violation_handler = ComplianceViolationEventHandler(
            command_bus=self.command_bus,
            template_repository=self.template_repository,
            config=self.config,
        )

        data_sync_completed_handler = DataSyncCompletedEventHandler(
            command_bus=self.command_bus,
            template_repository=self.template_repository,
            config=self.config,
        )

        # Store handlers for access
        self.event_handlers = {
            "UserRegisteredEvent": user_registered_handler,
            "UserDeactivatedEvent": user_deactivated_handler,
            "SecurityIncidentDetectedEvent": security_incident_handler,
            "ComplianceViolationEvent": compliance_violation_handler,
            "DataSyncCompletedEvent": data_sync_completed_handler,
        }

    def get_event_handler(self, event_type: str):
        """Get event handler for specific event type."""
        return self.event_handlers.get(event_type)

    def get_notification_service(self) -> NotificationService:
        """Get notification service."""
        return self.notification_service

    def get_template_service(self) -> TemplateService:
        """Get template service."""
        return self.template_service

    def get_delivery_service(self) -> DeliveryService:
        """Get delivery service."""
        return self.delivery_service_wrapper

    def get_scheduling_service(self) -> SchedulingService:
        """Get scheduling service."""
        return self.scheduling_service

    def get_preference_service(self) -> PreferenceService:
        """Get preference service."""
        return self.preference_service


# Export main classes and functions
__all__ = [
    "EVENT_HANDLERS",
    "BatchStatusDTO",
    "CancelScheduledNotificationCommand",
    "CancelScheduledNotificationCommandHandler",
    "ChannelStatusDTO",
    "ComplianceViolationEventHandler",
    "CreateTemplateCommand",
    "CreateTemplateCommandHandler",
    "DataSyncCompletedEventHandler",
    "DeliveryReportDTO",
    "DeliveryService",
    "GetBatchStatusQuery",
    "GetBatchStatusQueryHandler",
    "GetChannelStatusQuery",
    "GetChannelStatusQueryHandler",
    "GetDeliveryStatusQuery",
    "GetDeliveryStatusQueryHandler",
    "GetNotificationHistoryQuery",
    "GetNotificationHistoryQueryHandler",
    "GetNotificationMetricsQuery",
    "GetNotificationMetricsQueryHandler",
    # Queries
    "GetNotificationQuery",
    # Query Handlers
    "GetNotificationQueryHandler",
    "GetRecipientPreferencesQuery",
    "GetRecipientPreferencesQueryHandler",
    "GetTemplateQuery",
    "GetTemplateQueryHandler",
    "ListScheduledNotificationsQuery",
    "ListScheduledNotificationsQueryHandler",
    "ListTemplatesQuery",
    "ListTemplatesQueryHandler",
    # Main module
    "NotificationApplicationModule",
    "NotificationHistoryDTO",
    # DTOs
    "NotificationRequestDTO",
    "NotificationResponseDTO",
    # Services
    "NotificationService",
    "PreferenceService",
    "ProcessBatchCommand",
    "ProcessBatchCommandHandler",
    "RecipientPreferencesDTO",
    "RetryNotificationCommand",
    "RetryNotificationCommandHandler",
    "ScheduleNotificationCommand",
    "ScheduleNotificationCommandHandler",
    "ScheduledNotificationDTO",
    "SchedulingService",
    "SearchNotificationsQuery",
    "SearchNotificationsQueryHandler",
    "SecurityIncidentDetectedEventHandler",
    # Commands
    "SendNotificationCommand",
    # Command Handlers
    "SendNotificationCommandHandler",
    "TemplateDTO",
    "TemplateService",
    "UpdateRecipientPreferencesCommand",
    "UpdateRecipientPreferencesCommandHandler",
    "UpdateTemplateCommand",
    "UpdateTemplateCommandHandler",
    "UserDeactivatedEventHandler",
    # Event Handlers
    "UserRegisteredEventHandler",
]
