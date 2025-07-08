"""Notification sent event handler.

This module handles NotificationSentEvent to create audit trails
for notification delivery tracking and compliance monitoring.
"""

from typing import Any

from ddd_implementation.shared_contracts import NotificationSentEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class NotificationSentEventHandler:
    """
    Event handler for notification sent events.

    Creates audit trails when notifications are successfully sent,
    supporting delivery tracking and compliance requirements.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: NotificationSentEvent) -> None:
        """
        Handle notification sent event.

        Args:
            event: NotificationSentEvent instance
        """
        logger.info(
            "Handling notification sent event",
            notification_id=event.notification_id,
            recipient_id=event.recipient_id,
            channel=event.channel,
            notification_type=event.notification_type,
            success=event.success,
            event_id=event.metadata.event_id,
        )

        try:
            # Create audit trail for notification delivery
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action for notification
                action_type="notification_sent",
                operation="send",
                description=f"Notification sent via {event.channel} to user {event.recipient_id}",
                resource_type="notification",
                resource_id=str(event.notification_id),
                resource_name=f"Notification {event.notification_id}",
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "recipient_id": str(event.recipient_id),
                    "channel": event.channel,
                    "template_id": event.template_id,
                    "delivery_status": event.delivery_status,
                },
                outcome=self._map_delivery_status_to_outcome(event.delivery_status),
                severity=self._calculate_severity(event.channel, event.delivery_status),
                category="communication",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["notification", "communication", f"channel_{event.channel}"],
                custom_fields={
                    "notification_id": str(event.notification_id),
                    "recipient_id": str(event.recipient_id),
                    "channel": event.channel,
                    "template_id": event.template_id,
                    "delivery_status": event.delivery_status,
                    "notification_type": self._determine_notification_type(
                        event.template_id
                    ),
                    "delivery_method": event.channel,
                },
                compliance_tags=["communication_audit", "delivery_tracking"],
            )

            # Create privacy audit trail for personal communications
            if event.channel in ["email", "sms"]:
                await self._create_privacy_audit_trail(event)

            # Create delivery confirmation audit trail for critical notifications
            if self._is_critical_notification(event.template_id):
                await self._create_critical_notification_audit_trail(event)

            logger.info(
                "Notification sent audit trail created successfully",
                notification_id=event.notification_id,
                recipient_id=event.recipient_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for notification sent",
                notification_id=event.notification_id,
                recipient_id=event.recipient_id,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting the notification process

    def _map_delivery_status_to_outcome(self, delivery_status: str) -> str:
        """
        Map delivery status to audit outcome.

        Args:
            delivery_status: Notification delivery status

        Returns:
            Audit outcome
        """
        status_mapping = {
            "delivered": "success",
            "sent": "success",
            "pending": "pending",
            "failed": "failure",
            "bounced": "failure",
            "rejected": "failure",
        }
        return status_mapping.get(delivery_status.lower(), "unknown")

    def _calculate_severity(self, channel: str, delivery_status: str) -> str:
        """
        Calculate severity based on channel and delivery status.

        Args:
            channel: Notification channel
            delivery_status: Delivery status

        Returns:
            Severity level
        """
        if delivery_status.lower() in ["failed", "bounced", "rejected"]:
            return "medium"
        if channel in ["sms", "push"]:
            return "low"  # Real-time channels
        return "low"  # Standard delivery

    def _determine_notification_type(self, template_id: str) -> str:
        """
        Determine notification type from template ID.

        Args:
            template_id: Template identifier

        Returns:
            Notification type
        """
        template_id_lower = template_id.lower()

        if "security" in template_id_lower or "auth" in template_id_lower:
            return "security"
        if "welcome" in template_id_lower or "onboard" in template_id_lower:
            return "onboarding"
        if "reset" in template_id_lower or "password" in template_id_lower:
            return "account_recovery"
        if "verify" in template_id_lower or "confirm" in template_id_lower:
            return "verification"
        if "alert" in template_id_lower or "warning" in template_id_lower:
            return "alert"
        return "general"

    def _is_critical_notification(self, template_id: str) -> bool:
        """
        Check if notification is critical.

        Args:
            template_id: Template identifier

        Returns:
            True if critical notification
        """
        critical_keywords = [
            "security",
            "alert",
            "breach",
            "suspicious",
            "emergency",
            "critical",
            "urgent",
            "violation",
            "locked",
            "suspended",
        ]
        template_id_lower = template_id.lower()
        return any(keyword in template_id_lower for keyword in critical_keywords)

    async def _create_privacy_audit_trail(self, event: Any) -> None:
        """
        Create privacy audit trail for personal communications.

        Args:
            event: NotificationSentEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="personal_data_communication",
                operation="send",
                description=f"Personal communication sent via {event.channel} for privacy tracking",
                resource_type="personal_communication",
                resource_id=str(event.notification_id),
                resource_name=f"Personal communication to {event.recipient_id}",
                outcome=self._map_delivery_status_to_outcome(event.delivery_status),
                severity="low",
                category="privacy",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["privacy", "personal_data", "communication"],
                custom_fields={
                    "data_subject": str(event.recipient_id),
                    "communication_channel": event.channel,
                    "personal_data_processed": True,
                    "purpose": "user_notification",
                    "legal_basis": "legitimate_interest",
                },
                compliance_tags=[
                    "GDPR_Article_6",
                    "personal_data_processing",
                    "communication_audit",
                ],
            )

            logger.debug(
                "Privacy audit trail created for personal communication",
                notification_id=event.notification_id,
            )

        except Exception as e:
            logger.warning(
                "Failed to create privacy audit trail",
                notification_id=event.notification_id,
                error=str(e),
            )

    async def _create_critical_notification_audit_trail(self, event: Any) -> None:
        """
        Create audit trail for critical notifications.

        Args:
            event: NotificationSentEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="critical_notification_sent",
                operation="send",
                description=f"Critical notification sent via {event.channel} - requires delivery confirmation",
                resource_type="critical_notification",
                resource_id=str(event.notification_id),
                resource_name=f"Critical notification {event.notification_id}",
                outcome=self._map_delivery_status_to_outcome(event.delivery_status),
                severity="high",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=[
                    "critical_notification",
                    "security_alert",
                    "urgent_communication",
                ],
                custom_fields={
                    "notification_priority": "critical",
                    "recipient_notification_required": True,
                    "delivery_confirmation_required": True,
                    "security_relevant": True,
                    "template_category": self._determine_notification_type(
                        event.template_id
                    ),
                },
                compliance_tags=[
                    "security_notifications",
                    "incident_communication",
                    "alert_delivery",
                ],
            )

            logger.debug(
                "Critical notification audit trail created",
                notification_id=event.notification_id,
            )

        except Exception as e:
            logger.warning(
                "Failed to create critical notification audit trail",
                notification_id=event.notification_id,
                error=str(e),
            )


__all__ = ["NotificationSentEventHandler"]
