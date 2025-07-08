"""
Multi-Channel Notification Adapter

Production-ready implementation of INotificationService supporting email, SMS, and push.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
    ISMSService,
)


class MultiChannelNotificationAdapter(INotificationService):
    """Multi-channel notification adapter implementation."""

    def __init__(
        self,
        email_service: IEmailService,
        sms_service: ISMSService,
        template_engine=None,
        push_service=None,
    ):
        """Initialize notification adapter.

        Args:
            email_service: Email service implementation
            sms_service: SMS service implementation  
            template_engine: Optional template renderer
            push_service: Optional push notification service
        """
        self._email_service = email_service
        self._sms_service = sms_service
        self._template_engine = template_engine
        self._push_service = push_service
        self._delivery_status = {}

    async def send_email(
        self,
        to: str,
        subject: str,
        template: str,
        data: dict[str, Any],
        priority: str = "normal",
    ) -> str:
        """Send email notification."""
        try:
            message_id = str(uuid4())

            # Render template
            if self._template_engine:
                html_content = await self._template_engine.render(
                    template, data, "html"
                )
                text_content = await self._template_engine.render(
                    template, data, "text"
                )
            else:
                # Simple template substitution
                html_content = self._render_simple_template(template, data)
                text_content = html_content

            # Send via email service
            result = await self._email_service.send_email(
                to=to,
                subject=subject,
                html_content=html_content,
                text_content=text_content,
            )

            # Track delivery
            self._delivery_status[message_id] = {
                "type": "email",
                "to": to,
                "subject": subject,
                "sent_at": datetime.now(UTC).isoformat(),
                "status": "sent",
                "provider_id": result.get("id"),
            }

            logger.info(f"Email sent: {message_id} to {to}")
            return message_id

        except Exception as e:
            logger.error(f"Failed to send email to {to}: {e}")
            raise

    async def send_sms(
        self,
        phone: str,
        message: str,
        template: str | None = None,
    ) -> str:
        """Send SMS notification."""
        try:
            message_id = str(uuid4())

            # Apply template if provided
            if template and self._template_engine:
                message = await self._template_engine.render(
                    template, {"message": message}, "text"
                )

            # Send via SMS service
            result = await self._sms_service.send_sms(to=phone, message=message)

            # Track delivery
            self._delivery_status[message_id] = {
                "type": "sms",
                "to": phone,
                "sent_at": datetime.now(UTC).isoformat(),
                "status": "sent",
                "provider_id": result.get("id"),
            }

            logger.info(f"SMS sent: {message_id} to {phone}")
            return message_id

        except Exception as e:
            logger.error(f"Failed to send SMS to {phone}: {e}")
            raise

    async def send_push_notification(
        self,
        device_tokens: str | list[str],
        title: str,
        body: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send push notification."""
        if not self._push_service:
            logger.warning("Push service not configured")
            return {"status": "disabled", "sent": 0}

        try:
            tokens = (
                [device_tokens]
                if isinstance(device_tokens, str)
                else device_tokens
            )

            result = await self._push_service.send(
                tokens=tokens,
                title=title,
                body=body,
                data=data or {},
            )

            logger.info(f"Push sent to {len(tokens)} devices")
            return result

        except Exception as e:
            logger.error(f"Failed to send push: {e}")
            raise

    async def send_bulk_email(
        self,
        recipients: list[dict[str, Any]],
        template: str,
        common_data: dict[str, Any] | None = None,
    ) -> str:
        """Send bulk email notifications."""
        batch_id = str(uuid4())
        sent = 0
        failed = 0

        for recipient in recipients:
            try:
                data = {**(common_data or {}), **recipient.get("data", {})}
                await self.send_email(
                    to=recipient["email"],
                    subject=recipient.get("subject", "Notification"),
                    template=template,
                    data=data,
                )
                sent += 1
            except Exception as e:
                logger.error(f"Bulk email failed for {recipient['email']}: {e}")
                failed += 1

        logger.info(f"Bulk batch {batch_id}: {sent} sent, {failed} failed")
        return batch_id

    async def get_delivery_status(self, message_id: str) -> dict[str, Any]:
        """Get message delivery status."""
        return self._delivery_status.get(
            message_id, {"status": "not_found"}
        )

    async def handle_delivery_webhook(
        self, provider: str, webhook_data: dict[str, Any]
    ) -> bool:
        """Handle delivery status webhook."""
        try:
            provider_id = webhook_data.get("id")
            status = webhook_data.get("status")

            # Find message by provider ID
            for msg_id, msg_data in self._delivery_status.items():
                if msg_data.get("provider_id") == provider_id:
                    msg_data["status"] = status
                    msg_data["updated_at"] = datetime.now(UTC).isoformat()
                    logger.info(f"Updated status for {msg_id}: {status}")
                    return True

            logger.warning(f"No message found for provider ID: {provider_id}")
            return False

        except Exception as e:
            logger.error(f"Failed to process webhook: {e}")
            return False

    def _render_simple_template(
        self, template: str, data: dict[str, Any]
    ) -> str:
        """Simple template rendering."""
        content = template
        for key, value in data.items():
            content = content.replace(f"{{{{{key}}}}}", str(value))
        return content