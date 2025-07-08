"""Integration module event handler registration."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.events.types import IEventBus

logger = logging.getLogger(__name__)


def register_integration_event_handlers(event_bus: "IEventBus") -> None:
    """Register integration module event handlers with the event bus.

    This function registers event handlers that listen to events from other modules
    to handle external system integrations and webhook processing.

    Args:
        event_bus: The application event bus
    """
    logger.info("Registering cross-module event handlers for Integration module")

    try:
        # Import integration event listeners
        from app.modules.integration.application.event_listeners import (
            AuditIntegrationListener,
            DataSyncOrchestrator,
            IdentityIntegrationListener,
            NotificationIntegrationListener,
            WebhookProcessor,
        )

        # Subscribe to Identity module events for external system sync
        try:
            from app.modules.identity.domain.events import (
                OrganizationCreatedEvent,
                OrganizationUpdatedEvent,
                RoleAssignedEvent,
                RoleRevokedEvent,
                UserActivatedEvent,
                UserCreatedEvent,
                UserDeactivatedEvent,
                UserDeletedEvent,
                UserUpdatedEvent,
            )

            # Create listener instance
            identity_listener = IdentityIntegrationListener()

            # Subscribe to user events for external sync
            event_bus.subscribe(UserCreatedEvent, identity_listener.sync_user_created)
            event_bus.subscribe(UserUpdatedEvent, identity_listener.sync_user_updated)
            event_bus.subscribe(UserDeletedEvent, identity_listener.sync_user_deleted)
            event_bus.subscribe(
                UserActivatedEvent, identity_listener.sync_user_activated
            )
            event_bus.subscribe(
                UserDeactivatedEvent, identity_listener.sync_user_deactivated
            )

            # Subscribe to role events for external sync
            event_bus.subscribe(RoleAssignedEvent, identity_listener.sync_role_assigned)
            event_bus.subscribe(RoleRevokedEvent, identity_listener.sync_role_revoked)

            # Subscribe to organization events for external sync
            event_bus.subscribe(
                OrganizationCreatedEvent, identity_listener.sync_organization_created
            )
            event_bus.subscribe(
                OrganizationUpdatedEvent, identity_listener.sync_organization_updated
            )

            logger.debug("Subscribed to identity module events for integration sync")
        except ImportError:
            logger.warning(
                "Identity module events not available for integration subscription"
            )

        # Subscribe to Audit module events for compliance reporting
        try:
            from app.modules.audit.domain.events import (
                AuditLogArchivedEvent,
                AuditLogCreatedEvent,
                ComplianceReportGeneratedEvent,
                DataExportCompletedEvent,
                SecurityIncidentReportedEvent,
            )

            # Create listener instance
            audit_listener = AuditIntegrationListener()

            # Subscribe to audit events for external reporting
            event_bus.subscribe(AuditLogCreatedEvent, audit_listener.forward_audit_log)
            event_bus.subscribe(
                ComplianceReportGeneratedEvent, audit_listener.upload_compliance_report
            )
            event_bus.subscribe(
                DataExportCompletedEvent, audit_listener.transfer_exported_data
            )
            event_bus.subscribe(
                SecurityIncidentReportedEvent, audit_listener.report_security_incident
            )
            event_bus.subscribe(
                AuditLogArchivedEvent, audit_listener.sync_archived_logs
            )

            logger.debug("Subscribed to audit module events for integration sync")
        except ImportError:
            logger.warning(
                "Audit module events not available for integration subscription"
            )

        # Subscribe to Notification module events for delivery tracking
        try:
            from app.modules.notification.domain.events import (
                EmailBouncedEvent,
                EmailQueuedEvent,
                EmailSentEvent,
                NotificationPreferencesChangedEvent,
                PushNotificationDeliveredEvent,
                PushNotificationQueuedEvent,
                SmsDeliveredEvent,
                SmsQueuedEvent,
                SmsSentEvent,
            )

            # Create listener instance
            notification_listener = NotificationIntegrationListener()

            # Subscribe to email events for external tracking
            event_bus.subscribe(
                EmailQueuedEvent, notification_listener.track_email_queued
            )
            event_bus.subscribe(EmailSentEvent, notification_listener.track_email_sent)
            event_bus.subscribe(
                EmailBouncedEvent, notification_listener.handle_email_bounce
            )

            # Subscribe to SMS events for external tracking
            event_bus.subscribe(SmsQueuedEvent, notification_listener.track_sms_queued)
            event_bus.subscribe(SmsSentEvent, notification_listener.track_sms_sent)
            event_bus.subscribe(
                SmsDeliveredEvent, notification_listener.track_sms_delivered
            )

            # Subscribe to push notification events
            event_bus.subscribe(
                PushNotificationQueuedEvent, notification_listener.track_push_queued
            )
            event_bus.subscribe(
                PushNotificationDeliveredEvent,
                notification_listener.track_push_delivered,
            )

            # Subscribe to preference changes for external sync
            event_bus.subscribe(
                NotificationPreferencesChangedEvent,
                notification_listener.sync_preferences,
            )

            logger.debug(
                "Subscribed to notification module events for integration tracking"
            )
        except ImportError:
            logger.warning(
                "Notification module events not available for integration subscription"
            )

        # Register webhook processor for incoming webhooks
        try:
            from app.modules.integration.domain.events import (
                IncomingWebhookReceivedEvent,
                WebhookProcessingRequiredEvent,
                WebhookValidationRequiredEvent,
            )

            # Create webhook processor instance
            webhook_processor = WebhookProcessor()

            # Subscribe to webhook events
            event_bus.subscribe(
                IncomingWebhookReceivedEvent, webhook_processor.process_incoming_webhook
            )
            event_bus.subscribe(
                WebhookValidationRequiredEvent, webhook_processor.validate_webhook
            )
            event_bus.subscribe(
                WebhookProcessingRequiredEvent,
                webhook_processor.process_webhook_payload,
            )

            logger.debug("Registered webhook processor")
        except ImportError:
            logger.warning("Webhook events not available for processing")

        # Register data sync orchestrator
        try:
            from app.modules.integration.domain.events import (
                DataSyncRequestedEvent,
                DeltaSyncRequiredEvent,
                FullSyncRequiredEvent,
                ManualSyncRequestedEvent,
                ScheduledSyncTriggeredEvent,
            )

            # Create data sync orchestrator instance
            sync_orchestrator = DataSyncOrchestrator()

            # Subscribe to sync events
            event_bus.subscribe(
                DataSyncRequestedEvent, sync_orchestrator.handle_sync_request
            )
            event_bus.subscribe(
                ScheduledSyncTriggeredEvent, sync_orchestrator.execute_scheduled_sync
            )
            event_bus.subscribe(
                ManualSyncRequestedEvent, sync_orchestrator.execute_manual_sync
            )
            event_bus.subscribe(
                DeltaSyncRequiredEvent, sync_orchestrator.execute_delta_sync
            )
            event_bus.subscribe(
                FullSyncRequiredEvent, sync_orchestrator.execute_full_sync
            )

            logger.debug("Registered data sync orchestrator")
        except ImportError:
            logger.warning("Data sync events not available for orchestration")

        logger.info(
            "Integration module cross-module event handlers registered successfully"
        )

    except Exception as e:
        logger.exception(f"Failed to register integration event handlers: {e}")
        raise
