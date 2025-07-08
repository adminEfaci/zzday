"""Notification event handlers registration."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.cqrs.event_bus import IEventBus

logger = logging.getLogger(__name__)


def _register_identity_events(event_bus: "IEventBus", identity_listener) -> None:
    """Register identity module event handlers."""
    try:
        from app.modules.identity.domain.events import (
            EmailVerificationRequestedEvent,
            EmailVerifiedEvent,
            PasswordResetCompletedEvent,
            PasswordResetRequestedEvent,
            SessionExpiredEvent,
            SuspiciousActivityDetectedEvent,
            TwoFactorDisabledEvent,
            TwoFactorEnabledEvent,
            UserAuthenticatedEvent,
            UserAuthenticationFailedEvent,
            UserCreatedEvent,
            UserLockedOutEvent,
            UserPasswordChangedEvent,
        )

        # Subscribe to user account events
        event_bus.subscribe(
            UserCreatedEvent, identity_listener.send_welcome_notification
        )
        event_bus.subscribe(
            UserPasswordChangedEvent,
            identity_listener.send_password_changed_notification,
        )
        event_bus.subscribe(
            UserAuthenticatedEvent, identity_listener.send_login_notification
        )
        event_bus.subscribe(
            UserAuthenticationFailedEvent,
            identity_listener.send_failed_login_notification,
        )
        event_bus.subscribe(
            UserLockedOutEvent, identity_listener.send_lockout_notification
        )

        # Subscribe to password reset events
        event_bus.subscribe(
            PasswordResetRequestedEvent, identity_listener.send_password_reset_email
        )
        event_bus.subscribe(
            PasswordResetCompletedEvent,
            identity_listener.send_password_reset_confirmation,
        )

        # Subscribe to email verification events
        event_bus.subscribe(
            EmailVerificationRequestedEvent,
            identity_listener.send_verification_email,
        )
        event_bus.subscribe(
            EmailVerifiedEvent, identity_listener.send_verification_confirmation
        )

        # Subscribe to security events
        event_bus.subscribe(
            TwoFactorEnabledEvent, identity_listener.send_2fa_enabled_notification
        )
        event_bus.subscribe(
            TwoFactorDisabledEvent, identity_listener.send_2fa_disabled_notification
        )
        event_bus.subscribe(
            SessionExpiredEvent, identity_listener.send_session_expired_notification
        )
        event_bus.subscribe(
            SuspiciousActivityDetectedEvent, identity_listener.send_security_alert
        )

        logger.debug("Subscribed to identity module events for notifications")
    except ImportError:
        logger.warning(
            "Identity module events not available for notification subscription"
        )


def _register_audit_events(event_bus: "IEventBus", audit_listener) -> None:
    """Register audit module event handlers."""
    try:
        from app.modules.audit.domain.events import (
            AuditLogCreatedEvent,
            ComplianceReportGeneratedEvent,
            SecurityAlertTriggeredEvent,
        )

        event_bus.subscribe(AuditLogCreatedEvent, audit_listener.send_audit_alert)
        event_bus.subscribe(
            SecurityAlertTriggeredEvent, audit_listener.send_security_alert
        )
        event_bus.subscribe(
            ComplianceReportGeneratedEvent, audit_listener.send_compliance_report
        )

        logger.debug("Subscribed to audit module events for notifications")
    except ImportError:
        logger.warning(
            "Audit module events not available for notification subscription"
        )


def _register_integration_events(event_bus: "IEventBus", integration_listener) -> None:
    """Register integration module event handlers."""
    try:
        from app.modules.integration.domain.events import (
            DataSyncCompletedEvent,
            IntegrationConnectedEvent,
            IntegrationDisconnectedEvent,
            IntegrationErrorEvent,
            WebhookReceivedEvent,
        )

        event_bus.subscribe(
            IntegrationConnectedEvent, integration_listener.send_connection_notification
        )
        event_bus.subscribe(
            IntegrationDisconnectedEvent,
            integration_listener.send_disconnection_notification,
        )
        event_bus.subscribe(
            IntegrationErrorEvent, integration_listener.send_error_notification
        )
        event_bus.subscribe(
            DataSyncCompletedEvent, integration_listener.send_sync_completion_notification
        )
        event_bus.subscribe(
            WebhookReceivedEvent, integration_listener.send_webhook_notification
        )

        logger.debug("Subscribed to integration module events for notifications")
    except ImportError:
        logger.warning(
            "Integration module events not available for notification subscription"
        )


def _register_system_events(event_bus: "IEventBus", system_listener) -> None:
    """Register system event handlers."""
    try:
        from app.core.events import (
            ApplicationShutdownEvent,
            ApplicationStartupEvent,
            BackupCompletedEvent,
            BackupFailedEvent,
            ServiceDegradationEvent,
            ServiceRestoredEvent,
            SystemErrorEvent,
            SystemMaintenanceEvent,
        )

        event_bus.subscribe(
            ApplicationStartupEvent, system_listener.send_startup_notification
        )
        event_bus.subscribe(
            ApplicationShutdownEvent, system_listener.send_shutdown_notification
        )
        event_bus.subscribe(
            SystemMaintenanceEvent, system_listener.send_maintenance_notification
        )
        event_bus.subscribe(SystemErrorEvent, system_listener.send_error_notification)
        event_bus.subscribe(
            BackupCompletedEvent, system_listener.send_backup_success_notification
        )
        event_bus.subscribe(
            BackupFailedEvent, system_listener.send_backup_failure_notification
        )
        
        # Subscribe to service status events
        event_bus.subscribe(
            ServiceDegradationEvent, system_listener.send_service_degradation_alert
        )
        event_bus.subscribe(
            ServiceRestoredEvent, system_listener.send_service_restored_notification
        )

        logger.debug("Subscribed to system events for notifications")
    except ImportError:
        logger.warning("System events not available for notification subscription")


def register_notification_event_handlers(event_bus: "IEventBus") -> None:
    """Register notification module event handlers with the event bus.

    This function registers event handlers that listen to events from other modules
    to trigger appropriate notifications.

    Args:
        event_bus: The application event bus
    """
    logger.info("Registering cross-module event handlers for Notification module")

    try:
        # Import notification event listeners
        from app.modules.notification.application.event_listeners import (
            AuditNotificationListener,
            IdentityNotificationListener,
            IntegrationNotificationListener,
            SystemNotificationListener,
        )

        # Create listener instances
        identity_listener = IdentityNotificationListener()
        audit_listener = AuditNotificationListener()
        integration_listener = IntegrationNotificationListener()
        system_listener = SystemNotificationListener()

        # Register event handlers for each module
        _register_identity_events(event_bus, identity_listener)
        _register_audit_events(event_bus, audit_listener)
        _register_integration_events(event_bus, integration_listener)
        _register_system_events(event_bus, system_listener)

        logger.info(
            "Notification module cross-module event handlers registered successfully"
        )

    except Exception as e:
        logger.exception(f"Failed to register notification event handlers: {e}")
        raise