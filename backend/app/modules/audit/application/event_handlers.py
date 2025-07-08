"""Audit module event handler registration."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.events.types import IEventBus

logger = logging.getLogger(__name__)


def register_audit_event_handlers(event_bus: "IEventBus") -> None:
    """Register audit module event handlers with the event bus.

    This function registers event handlers that listen to events from other modules
    to maintain comprehensive audit trails across the system.

    Args:
        event_bus: The application event bus
    """
    logger.info("Registering cross-module event handlers for Audit module")

    try:
        # Import audit event listeners
        from app.modules.audit.application.event_listeners import (
            IdentityAuditListener,
            IntegrationAuditListener,
            NotificationAuditListener,
            SystemAuditListener,
        )

        # Subscribe to Identity module events
        try:
            from app.modules.identity.domain.events import (
                PermissionGrantedEvent,
                PermissionRevokedEvent,
                RoleAssignedEvent,
                RoleRevokedEvent,
                SessionCreatedEvent,
                SessionInvalidatedEvent,
                UserAuthenticatedEvent,
                UserAuthenticationFailedEvent,
                UserCreatedEvent,
                UserDeletedEvent,
                UserPasswordChangedEvent,
                UserUpdatedEvent,
            )

            # Create listener instance
            identity_listener = IdentityAuditListener()

            # Subscribe to user events
            event_bus.subscribe(UserCreatedEvent, identity_listener.audit_user_created)
            event_bus.subscribe(UserUpdatedEvent, identity_listener.audit_user_updated)
            event_bus.subscribe(UserDeletedEvent, identity_listener.audit_user_deleted)
            event_bus.subscribe(
                UserPasswordChangedEvent, identity_listener.audit_password_changed
            )
            event_bus.subscribe(
                UserAuthenticatedEvent, identity_listener.audit_user_authenticated
            )
            event_bus.subscribe(
                UserAuthenticationFailedEvent,
                identity_listener.audit_authentication_failed,
            )

            # Subscribe to role/permission events
            event_bus.subscribe(
                RoleAssignedEvent, identity_listener.audit_role_assigned
            )
            event_bus.subscribe(RoleRevokedEvent, identity_listener.audit_role_revoked)
            event_bus.subscribe(
                PermissionGrantedEvent, identity_listener.audit_permission_granted
            )
            event_bus.subscribe(
                PermissionRevokedEvent, identity_listener.audit_permission_revoked
            )

            # Subscribe to session events
            event_bus.subscribe(
                SessionCreatedEvent, identity_listener.audit_session_created
            )
            event_bus.subscribe(
                SessionInvalidatedEvent, identity_listener.audit_session_invalidated
            )

            logger.debug("Subscribed to identity module events for auditing")
        except ImportError:
            logger.warning(
                "Identity module events not available for audit subscription"
            )

        # Subscribe to Notification module events
        try:
            from app.modules.notification.domain.events import (
                EmailSentEvent,
                NotificationFailedEvent,
                NotificationSentEvent,
                NotificationTemplateCreatedEvent,
                NotificationTemplateUpdatedEvent,
                PushNotificationSentEvent,
                SmsSentEvent,
            )

            # Create listener instance
            notification_listener = NotificationAuditListener()

            # Subscribe to notification events
            event_bus.subscribe(
                NotificationSentEvent, notification_listener.audit_notification_sent
            )
            event_bus.subscribe(
                NotificationFailedEvent, notification_listener.audit_notification_failed
            )
            event_bus.subscribe(
                NotificationTemplateCreatedEvent,
                notification_listener.audit_template_created,
            )
            event_bus.subscribe(
                NotificationTemplateUpdatedEvent,
                notification_listener.audit_template_updated,
            )
            event_bus.subscribe(EmailSentEvent, notification_listener.audit_email_sent)
            event_bus.subscribe(SmsSentEvent, notification_listener.audit_sms_sent)
            event_bus.subscribe(
                PushNotificationSentEvent, notification_listener.audit_push_sent
            )

            logger.debug("Subscribed to notification module events for auditing")
        except ImportError:
            logger.warning(
                "Notification module events not available for audit subscription"
            )

        # Subscribe to Integration module events
        try:
            from app.modules.integration.domain.events import (
                ApiCallFailedEvent,
                ApiCallMadeEvent,
                DataSyncCompletedEvent,
                DataSyncFailedEvent,
                DataSyncStartedEvent,
                IntegrationCreatedEvent,
                IntegrationDeletedEvent,
                IntegrationUpdatedEvent,
                WebhookFailedEvent,
                WebhookProcessedEvent,
                WebhookReceivedEvent,
            )

            # Create listener instance
            integration_listener = IntegrationAuditListener()

            # Subscribe to webhook events
            event_bus.subscribe(
                WebhookReceivedEvent, integration_listener.audit_webhook_received
            )
            event_bus.subscribe(
                WebhookProcessedEvent, integration_listener.audit_webhook_processed
            )
            event_bus.subscribe(
                WebhookFailedEvent, integration_listener.audit_webhook_failed
            )

            # Subscribe to API events
            event_bus.subscribe(ApiCallMadeEvent, integration_listener.audit_api_call)
            event_bus.subscribe(
                ApiCallFailedEvent, integration_listener.audit_api_failed
            )

            # Subscribe to integration management events
            event_bus.subscribe(
                IntegrationCreatedEvent, integration_listener.audit_integration_created
            )
            event_bus.subscribe(
                IntegrationUpdatedEvent, integration_listener.audit_integration_updated
            )
            event_bus.subscribe(
                IntegrationDeletedEvent, integration_listener.audit_integration_deleted
            )

            # Subscribe to data sync events
            event_bus.subscribe(
                DataSyncStartedEvent, integration_listener.audit_sync_started
            )
            event_bus.subscribe(
                DataSyncCompletedEvent, integration_listener.audit_sync_completed
            )
            event_bus.subscribe(
                DataSyncFailedEvent, integration_listener.audit_sync_failed
            )

            logger.debug("Subscribed to integration module events for auditing")
        except ImportError:
            logger.warning(
                "Integration module events not available for audit subscription"
            )

        # Subscribe to system-wide events
        try:
            from app.core.events.system import (
                ConfigurationChangedEvent,
                CriticalErrorEvent,
                PerformanceThresholdExceededEvent,
                SystemShutdownEvent,
                SystemStartedEvent,
            )

            # Create listener instance
            system_listener = SystemAuditListener()

            # Subscribe to system events
            event_bus.subscribe(
                SystemStartedEvent, system_listener.audit_system_started
            )
            event_bus.subscribe(
                SystemShutdownEvent, system_listener.audit_system_shutdown
            )
            event_bus.subscribe(
                ConfigurationChangedEvent, system_listener.audit_config_changed
            )
            event_bus.subscribe(
                CriticalErrorEvent, system_listener.audit_critical_error
            )
            event_bus.subscribe(
                PerformanceThresholdExceededEvent,
                system_listener.audit_performance_issue,
            )

            logger.debug("Subscribed to system events for auditing")
        except ImportError:
            logger.warning("System events not available for audit subscription")

        logger.info("Audit module cross-module event handlers registered successfully")

    except Exception as e:
        logger.exception(f"Failed to register audit event handlers: {e}")
        raise
