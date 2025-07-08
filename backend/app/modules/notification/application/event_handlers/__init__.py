"""Notification event handlers.

This module contains event handlers that respond to domain events from
other modules, implementing the notification module's integration points.
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.core.cqrs.base import CommandBus
from app.core.logging import get_logger
from app.modules.notification.application.commands import SendNotificationCommand
from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
    TemplateType,
)

logger = get_logger(__name__)

# Constants
LARGE_SYNC_THRESHOLD = 1000


class UserRegisteredEventHandler:
    """Handler for user registration events - sends welcome notifications."""

    def __init__(self, command_bus: CommandBus, template_repository):
        """Initialize handler with dependencies."""
        self.command_bus = command_bus
        self.template_repository = template_repository

    async def handle(self, event) -> None:
        """Handle user registered event.

        Sends welcome email and in-app notification to new users.
        """
        try:
            logger.info(
                "Handling user registered event",
                user_id=str(event.user_id),
                email=event.email,
            )

            # Get welcome email template
            welcome_template = await self.template_repository.find_by_code(
                "welcome_email"
            )

            if welcome_template and welcome_template.is_active:
                # Send welcome email
                email_command = SendNotificationCommand(
                    recipient_id=event.user_id,
                    channel=NotificationChannel.EMAIL,
                    template_code="welcome_email",
                    variables={
                        "user_name": event.full_name or event.username,
                        "email": event.email,
                        "username": event.username,
                        "registration_date": datetime.utcnow().strftime("%Y-%m-%d"),
                        "support_email": "support@ezzday.com",
                        "app_name": "EzzDay",
                    },
                    priority=NotificationPriority.HIGH,
                    metadata={
                        "event_type": "user_registered",
                        "event_id": str(event.metadata.event_id),
                        "correlation_id": str(event.metadata.correlation_id)
                        if event.metadata.correlation_id
                        else None,
                    },
                )

                # Set context from event
                email_command.set_metadata(
                    correlation_id=event.metadata.correlation_id,
                    user_id=event.user_id,
                    source="user_registration",
                )

                await self.command_bus.execute(email_command)

            # Get welcome in-app template
            welcome_in_app_template = await self.template_repository.find_by_code(
                "welcome_in_app"
            )

            if welcome_in_app_template and welcome_in_app_template.is_active:
                # Send welcome in-app notification
                in_app_command = SendNotificationCommand(
                    recipient_id=event.user_id,
                    channel=NotificationChannel.IN_APP,
                    template_code="welcome_in_app",
                    variables={
                        "user_name": event.full_name or event.username,
                        "app_name": "EzzDay",
                        "getting_started_url": "/getting-started",
                        "profile_url": "/profile",
                    },
                    priority=NotificationPriority.NORMAL,
                    metadata={
                        "event_type": "user_registered",
                        "event_id": str(event.metadata.event_id),
                        "correlation_id": str(event.metadata.correlation_id)
                        if event.metadata.correlation_id
                        else None,
                    },
                )

                # Set context from event
                in_app_command.set_metadata(
                    correlation_id=event.metadata.correlation_id,
                    user_id=event.user_id,
                    source="user_registration",
                )

                await self.command_bus.execute(in_app_command)

            logger.info(
                "Successfully sent welcome notifications", user_id=str(event.user_id)
            )

        except Exception as e:
            logger.error(
                "Failed to handle user registered event",
                user_id=str(event.user_id),
                error=str(e),
                exc_info=True,
            )
            # Don't re-raise - this is an event handler


class UserDeactivatedEventHandler:
    """Handler for user deactivation events - sends closure notifications."""

    def __init__(self, command_bus: CommandBus, template_repository):
        """Initialize handler with dependencies."""
        self.command_bus = command_bus
        self.template_repository = template_repository

    async def handle(self, event) -> None:
        """Handle user deactivated event.

        Sends account closure notification to deactivated users.
        """
        try:
            logger.info(
                "Handling user deactivated event",
                user_id=str(event.user_id),
                reason=event.reason,
            )

            # Get account closure template
            closure_template = await self.template_repository.find_by_code(
                "account_closure"
            )

            if closure_template and closure_template.is_active:
                # Send closure notification
                command = SendNotificationCommand(
                    recipient_id=event.user_id,
                    channel=NotificationChannel.EMAIL,
                    template_code="account_closure",
                    variables={
                        "deactivation_reason": event.reason,
                        "deactivated_date": datetime.utcnow().strftime("%Y-%m-%d"),
                        "reactivation_period_days": "30",
                        "support_email": "support@ezzday.com",
                        "data_retention_period_days": "90",
                    },
                    priority=NotificationPriority.HIGH,
                    metadata={
                        "event_type": "user_deactivated",
                        "event_id": str(event.metadata.event_id),
                        "deactivation_reason": event.reason,
                        "deactivated_by": str(event.deactivated_by)
                        if event.deactivated_by
                        else None,
                    },
                )

                # Set context from event
                command.set_metadata(
                    correlation_id=event.metadata.correlation_id,
                    user_id=event.deactivated_by,  # Who performed the action
                    source="user_deactivation",
                )

                await self.command_bus.execute(command)

            logger.info(
                "Successfully sent account closure notification",
                user_id=str(event.user_id),
            )

        except Exception as e:
            logger.error(
                "Failed to handle user deactivated event",
                user_id=str(event.user_id),
                error=str(e),
                exc_info=True,
            )


class SecurityIncidentDetectedEventHandler:
    """Handler for security incident events - alerts security team."""

    def __init__(self, command_bus: CommandBus, template_repository, config):
        """Initialize handler with dependencies."""
        self.command_bus = command_bus
        self.template_repository = template_repository
        self.config = config

    async def handle(self, event) -> None:
        """Handle security incident detected event.

        Sends alert to security team and potentially affected user.
        """
        try:
            logger.warning(
                "Handling security incident detected event",
                incident_id=str(event.incident_id),
                incident_type=event.incident_type,
                severity=event.severity,
                user_id=str(event.user_id) if event.user_id else None,
            )

            # Send alert to security team
            await self._send_security_team_alert(event)

            # Send user notification for high/critical incidents
            if event.severity in ["high", "critical"] and event.user_id:
                await self._send_user_security_alert(event)

            logger.info(
                "Successfully sent security incident notifications",
                incident_id=str(event.incident_id),
            )

        except Exception as e:
            logger.error(
                "Failed to handle security incident event",
                incident_id=str(event.incident_id),
                error=str(e),
                exc_info=True,
            )

    async def _send_security_team_alert(self, event) -> None:
        """Send alert to security team."""
        security_template = await self.template_repository.find_by_code(
            "security_incident_alert"
        )

        if not security_template or not security_template.is_active:
            logger.warning("Security incident alert template not found or inactive")
            return

        # Get security team recipient ID from config
        security_team_id = self.config.get("security_team_recipient_id")
        if not security_team_id:
            logger.warning("Security team recipient ID not configured")
            return

        command = SendNotificationCommand(
            recipient_id=UUID(security_team_id),
            channel=NotificationChannel.EMAIL,
            template_code="security_incident_alert",
            variables={
                "incident_id": str(event.incident_id),
                "incident_type": event.incident_type,
                "severity": event.severity,
                "affected_user_id": str(event.user_id) if event.user_id else "N/A",
                "incident_details": str(event.details),
                "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "investigation_url": f"{self.config.get('admin_base_url', '')}/security/incidents/{event.incident_id}",
            },
            priority=NotificationPriority.URGENT,
            metadata={
                "event_type": "security_incident_detected",
                "event_id": str(event.metadata.event_id),
                "incident_id": str(event.incident_id),
                "severity": event.severity,
            },
        )

        command.set_metadata(
            correlation_id=event.metadata.correlation_id, source="security_monitoring"
        )

        await self.command_bus.execute(command)

    async def _send_user_security_alert(self, event) -> None:
        """Send security alert to affected user."""
        user_template = await self.template_repository.find_by_code(
            "security_alert_user"
        )

        if not user_template or not user_template.is_active:
            return

        command = SendNotificationCommand(
            recipient_id=event.user_id,
            channel=NotificationChannel.EMAIL,
            template_code="security_alert_user",
            variables={
                "incident_type_friendly": self._get_friendly_incident_type(
                    event.incident_type
                ),
                "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "account_url": f"{self.config.get('app_base_url', '')}/account/security",
                "support_email": "security@ezzday.com",
                "recommended_actions": self._get_recommended_actions(
                    event.incident_type
                ),
            },
            priority=NotificationPriority.URGENT,
            metadata={
                "event_type": "security_incident_user_alert",
                "incident_id": str(event.incident_id),
            },
        )

        command.set_metadata(
            correlation_id=event.metadata.correlation_id,
            user_id=event.user_id,
            source="security_monitoring",
        )

        await self.command_bus.execute(command)

    def _get_friendly_incident_type(self, incident_type: str) -> str:
        """Get user-friendly incident type description."""
        friendly_names = {
            "brute_force": "Suspicious login attempts",
            "privilege_escalation": "Unauthorized access attempt",
            "data_breach": "Potential data access",
            "malware": "Malicious software detected",
            "phishing": "Phishing attempt detected",
        }
        return friendly_names.get(
            incident_type, incident_type.replace("_", " ").title()
        )

    def _get_recommended_actions(self, incident_type: str) -> str:
        """Get recommended actions for incident type."""
        actions = {
            "brute_force": "Change your password immediately and enable two-factor authentication.",
            "privilege_escalation": "Review your account permissions and recent activity.",
            "data_breach": "Check your account for unauthorized changes and update your password.",
            "malware": "Run a security scan on your device and update your passwords.",
            "phishing": "Do not click suspicious links and verify any authentication requests.",
        }
        return actions.get(
            incident_type,
            "Review your account security settings and contact support if needed.",
        )


class ComplianceViolationEventHandler:
    """Handler for compliance violation events - notifies compliance officer."""

    def __init__(self, command_bus: CommandBus, template_repository, config):
        """Initialize handler with dependencies."""
        self.command_bus = command_bus
        self.template_repository = template_repository
        self.config = config

    async def handle(self, event) -> None:
        """Handle compliance violation event.

        Sends notification to compliance officer about policy violations.
        """
        try:
            logger.warning(
                "Handling compliance violation event",
                violation_id=str(event.violation_id),
                rule_id=event.rule_id,
                resource_type=event.resource_type,
                user_id=str(event.user_id) if event.user_id else None,
            )

            # Get compliance template
            compliance_template = await self.template_repository.find_by_code(
                "compliance_violation_alert"
            )

            if not compliance_template or not compliance_template.is_active:
                logger.warning(
                    "Compliance violation alert template not found or inactive"
                )
                return

            # Get compliance officer recipient ID from config
            compliance_officer_id = self.config.get("compliance_officer_recipient_id")
            if not compliance_officer_id:
                logger.warning("Compliance officer recipient ID not configured")
                return

            command = SendNotificationCommand(
                recipient_id=UUID(compliance_officer_id),
                channel=NotificationChannel.EMAIL,
                template_code="compliance_violation_alert",
                variables={
                    "violation_id": str(event.violation_id),
                    "rule_id": event.rule_id,
                    "resource_type": event.resource_type,
                    "resource_id": event.resource_id,
                    "violating_user_id": str(event.user_id)
                    if event.user_id
                    else "System",
                    "violation_details": str(event.violation_details),
                    "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "review_url": f"{self.config.get('admin_base_url', '')}/compliance/violations/{event.violation_id}",
                    "policy_url": f"{self.config.get('admin_base_url', '')}/compliance/rules/{event.rule_id}",
                },
                priority=NotificationPriority.HIGH,
                metadata={
                    "event_type": "compliance_violation",
                    "event_id": str(event.metadata.event_id),
                    "violation_id": str(event.violation_id),
                    "rule_id": event.rule_id,
                },
            )

            command.set_metadata(
                correlation_id=event.metadata.correlation_id,
                user_id=event.user_id,
                source="compliance_monitoring",
            )

            await self.command_bus.execute(command)

            logger.info(
                "Successfully sent compliance violation notification",
                violation_id=str(event.violation_id),
            )

        except Exception as e:
            logger.error(
                "Failed to handle compliance violation event",
                violation_id=str(event.violation_id),
                error=str(e),
                exc_info=True,
            )


class DataSyncCompletedEventHandler:
    """Handler for data sync completion events - sends completion reports."""

    def __init__(self, command_bus: CommandBus, template_repository, config):
        """Initialize handler with dependencies."""
        self.command_bus = command_bus
        self.template_repository = template_repository
        self.config = config

    async def handle(self, event) -> None:
        """Handle data sync completed event.

        Sends completion report to administrators and potentially users.
        """
        try:
            logger.info(
                "Handling data sync completed event",
                sync_id=str(event.sync_id),
                integration_id=str(event.integration_id),
                direction=event.direction,
                records_processed=event.records_processed,
                records_failed=event.records_failed,
            )

            # Send admin report for all syncs
            await self._send_admin_sync_report(event)

            # Send user notification for failed syncs or large volumes
            if event.records_failed > 0 or event.records_processed > LARGE_SYNC_THRESHOLD:
                await self._send_user_sync_notification(event)

            logger.info(
                "Successfully sent data sync notifications", sync_id=str(event.sync_id)
            )

        except Exception as e:
            logger.error(
                "Failed to handle data sync completed event",
                sync_id=str(event.sync_id),
                error=str(e),
                exc_info=True,
            )

    async def _send_admin_sync_report(self, event) -> None:
        """Send sync completion report to administrators."""
        admin_template = await self.template_repository.find_by_code(
            "data_sync_admin_report"
        )

        if not admin_template or not admin_template.is_active:
            return

        # Get admin recipient ID from config
        admin_recipient_id = self.config.get("data_admin_recipient_id")
        if not admin_recipient_id:
            return

        # Calculate success rate
        total_records = event.records_processed + event.records_failed
        success_rate = (
            (event.records_processed / total_records * 100)
            if total_records > 0
            else 100
        )

        # Determine status
        if event.records_failed == 0:
            sync_status = "Success"
            status_color = "green"
        elif event.records_failed < event.records_processed:
            sync_status = "Partial Success"
            status_color = "orange"
        else:
            sync_status = "Failed"
            status_color = "red"

        command = SendNotificationCommand(
            recipient_id=UUID(admin_recipient_id),
            channel=NotificationChannel.EMAIL,
            template_code="data_sync_admin_report",
            variables={
                "sync_id": str(event.sync_id),
                "integration_id": str(event.integration_id),
                "sync_direction": event.direction.title(),
                "sync_status": sync_status,
                "status_color": status_color,
                "records_processed": str(event.records_processed),
                "records_failed": str(event.records_failed),
                "success_rate": f"{success_rate:.1f}%",
                "duration_minutes": f"{event.duration_seconds / 60:.1f}",
                "completed_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "sync_details_url": f"{self.config.get('admin_base_url', '')}/integrations/syncs/{event.sync_id}",
            },
            priority=NotificationPriority.NORMAL
            if event.records_failed == 0
            else NotificationPriority.HIGH,
            metadata={
                "event_type": "data_sync_completed",
                "event_id": str(event.metadata.event_id),
                "sync_id": str(event.sync_id),
            },
        )

        command.set_metadata(
            correlation_id=event.metadata.correlation_id, source="data_integration"
        )

        await self.command_bus.execute(command)

    async def _send_user_sync_notification(self, event) -> None:
        """Send sync notification to users when appropriate."""
        # This would need integration with user management to determine
        # which users should be notified based on the integration


# Event handler registry
EVENT_HANDLERS = {
    "UserRegisteredEvent": UserRegisteredEventHandler,
    "UserDeactivatedEvent": UserDeactivatedEventHandler,
    "SecurityIncidentDetectedEvent": SecurityIncidentDetectedEventHandler,
    "ComplianceViolationEvent": ComplianceViolationEventHandler,
    "DataSyncCompletedEvent": DataSyncCompletedEventHandler,
}


def register_notification_event_handlers(event_bus) -> None:
    """Register all notification module event handlers with the event bus."""
    # Initialize and register event handlers
    # This would typically involve registering specific event types
    # with their corresponding handler methods
    # Implementation depends on event bus interface


# Export all handlers
__all__ = [
    "EVENT_HANDLERS",
    "ComplianceViolationEventHandler",
    "DataSyncCompletedEventHandler",
    "SecurityIncidentDetectedEventHandler",
    "UserDeactivatedEventHandler",
    "UserRegisteredEventHandler",
    "register_notification_event_handlers",
]
