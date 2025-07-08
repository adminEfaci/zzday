"""Email channel adapter implementations."""

import re
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiosmtplib
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Attachment,
    Content,
    Email,
    FileContent,
    FileName,
    FileType,
    Mail,
    To,
)

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)

from .email.resend_adapter import ResendEmailAdapter

# Constants
MIN_RETRYABLE_STATUS = 400
MAX_RETRYABLE_STATUS = 500


class EmailChannelAdapter(BaseChannelAdapter):
    """Email channel adapter supporting SMTP, SendGrid, and Resend."""

    SUPPORTED_PROVIDERS = ["smtp", "sendgrid", "resend"]

    def _validate_config(self) -> None:
        """Validate email channel configuration."""
        if self.provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported email provider: {self.provider}")

        # Validate common settings
        required_settings = ["from_email", "from_name"]
        for setting in required_settings:
            if setting not in self.config.settings:
                raise ValueError(f"Missing required setting: {setting}")

        # Validate provider-specific settings
        if self.provider == "smtp":
            self._validate_smtp_config()
        elif self.provider == "sendgrid":
            self._validate_sendgrid_config()
        elif self.provider == "resend":
            self._validate_resend_config()

    def _validate_smtp_config(self) -> None:
        """Validate SMTP configuration."""
        required = ["host", "port"]
        for setting in required:
            if setting not in self.config.settings:
                raise ValueError(f"Missing SMTP setting: {setting}")

        # Validate credentials if not using open relay
        if self.config.settings.get("use_auth", True):
            if "username" not in self.config.credentials:
                raise ValueError("SMTP username required when using authentication")
            if "password" not in self.config.credentials:
                raise ValueError("SMTP password required when using authentication")

    def _validate_sendgrid_config(self) -> None:
        """Validate SendGrid configuration."""
        if "api_key" not in self.config.credentials:
            raise ValueError("SendGrid API key required")

    def _validate_resend_config(self) -> None:
        """Validate Resend configuration."""
        if "api_key" not in self.config.credentials:
            raise ValueError("Resend API key required")

    async def send(self, notification: Notification) -> DeliveryResult:
        """Send email notification."""
        try:
            if self.provider == "smtp":
                return await self._send_smtp(notification)
            if self.provider == "sendgrid":
                return await self._send_sendgrid(notification)
            if self.provider == "resend":
                return await self._send_resend(notification)
            raise ChannelAdapterError(
                f"Unsupported provider: {self.provider}", is_retryable=False
            )
        except ChannelAdapterError:
            raise
        except Exception as e:
            raise ChannelAdapterError(f"Failed to send email: {e!s}", is_retryable=True)

    async def _send_resend(self, notification: Notification) -> DeliveryResult:
        """Send email via Resend using dedicated adapter."""
        # Create a Resend adapter instance and delegate to it
        resend_adapter = ResendEmailAdapter(self.config)
        return await resend_adapter.send(notification)

    async def _send_smtp(self, notification: Notification) -> DeliveryResult:
        """Send email via SMTP."""
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = notification.content.subject or "Notification"
        msg[
            "From"
        ] = f"{self.config.settings['from_name']} <{self.config.settings['from_email']}>"
        msg["To"] = notification.recipient_address.address

        # Add display name if available
        if notification.recipient_address.display_name:
            msg[
                "To"
            ] = f"{notification.recipient_address.display_name} <{notification.recipient_address.address}>"

        # Add text part
        text_part = MIMEText(notification.content.body, "plain")
        msg.attach(text_part)

        # Add HTML part if available
        if notification.content.html_body:
            html_part = MIMEText(notification.content.html_body, "html")
            msg.attach(html_part)

        # Add attachments
        for attachment_data in notification.content.attachments:
            if "content" in attachment_data:
                attachment = MIMEBase("application", "octet-stream")
                attachment.set_payload(attachment_data["content"])
                encoders.encode_base64(attachment)
                attachment.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{attachment_data["filename"]}"',
                )
                msg.attach(attachment)

        # Send via SMTP
        smtp_config = self.config.settings
        use_tls = smtp_config.get("use_tls", True)

        try:
            async with aiosmtplib.SMTP(
                hostname=smtp_config["host"], port=smtp_config["port"], use_tls=use_tls
            ) as smtp:
                if self.config.settings.get("use_auth", True):
                    await smtp.login(
                        self.config.credentials["username"],
                        self.config.credentials["password"],
                    )

                result = await smtp.send_message(msg)

                # Parse SMTP response
                message_id = (
                    result[1].decode()
                    if isinstance(result[1], bytes)
                    else str(result[1])
                )

                return DeliveryResult(
                    status=DeliveryStatus.SENT,
                    provider_message_id=message_id,
                    provider_status="250 OK",
                    delivered_at=datetime.utcnow(),
                    response_data={"smtp_response": str(result)},
                )

        except aiosmtplib.SMTPException as e:
            error_code = getattr(e, "code", None)
            is_retryable = error_code not in [
                550,
                551,
                552,
                553,
                554,
            ]  # Permanent failures

            raise ChannelAdapterError(
                f"SMTP error: {e!s}",
                error_code=str(error_code) if error_code else None,
                is_retryable=is_retryable,
            )

    async def _send_sendgrid(self, notification: Notification) -> DeliveryResult:
        """Send email via SendGrid."""
        try:
            sg = SendGridAPIClient(self.config.credentials["api_key"])

            # Create mail object
            from_email = Email(
                self.config.settings["from_email"], self.config.settings["from_name"]
            )

            to_email = To(
                notification.recipient_address.address,
                notification.recipient_address.display_name,
            )

            subject = notification.content.subject or "Notification"

            # Create content
            mail = Mail(from_email, to_email, subject)

            # Add plain text content
            mail.content = [Content("text/plain", notification.content.body)]

            # Add HTML content if available
            if notification.content.html_body:
                mail.content.append(
                    Content("text/html", notification.content.html_body)
                )

            # Add attachments
            for attachment_data in notification.content.attachments:
                if "content" in attachment_data:
                    attachment = Attachment(
                        FileContent(attachment_data["content"]),
                        FileName(attachment_data["filename"]),
                        FileType(
                            attachment_data.get(
                                "content_type", "application/octet-stream"
                            )
                        ),
                    )
                    mail.attachment = attachment

            # Add custom headers
            if notification.idempotency_key:
                mail.custom_arg = {"idempotency_key": notification.idempotency_key}

            # Send email
            response = sg.send(mail)

            # Extract message ID from headers
            message_id = None
            if hasattr(response, "headers") and "X-Message-Id" in response.headers:
                message_id = response.headers["X-Message-Id"]

            return DeliveryResult(
                status=DeliveryStatus.SENT,
                provider_message_id=message_id,
                provider_status=str(response.status_code),
                delivered_at=datetime.utcnow(),
                response_data={
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
                    if hasattr(response, "headers")
                    else {},
                },
            )

        except Exception as e:
            # Parse SendGrid error
            error_message = str(e)
            error_code = None
            is_retryable = True

            if hasattr(e, "code"):
                error_code = str(e.code)
                # 4xx errors are generally not retryable
                is_retryable = not (MIN_RETRYABLE_STATUS <= e.code < MAX_RETRYABLE_STATUS)

            raise ChannelAdapterError(
                f"SendGrid error: {error_message}",
                error_code=error_code,
                is_retryable=is_retryable,
                provider_response=getattr(e, "body", None),
            )

    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check email delivery status."""
        if self.provider == "sendgrid":
            return await self._check_sendgrid_status(provider_message_id)
        if self.provider == "resend":
            return await self._check_resend_status(provider_message_id)

        # SMTP doesn't support status checking
        return None

    async def _check_resend_status(
        self, provider_message_id: str
    ) -> DeliveryResult | None:
        """Check Resend email status."""
        # Create a Resend adapter instance and delegate to it
        resend_adapter = ResendEmailAdapter(self.config)
        return await resend_adapter.check_status(provider_message_id)

    async def _check_sendgrid_status(
        self, provider_message_id: str
    ) -> DeliveryResult | None:
        """Check SendGrid email status via Activity API."""
        try:
            # Note: This requires additional SendGrid API setup
            # For now, return None as status checking requires webhook setup
            return None
        except Exception:
            return None

    async def validate_address(self, address: str) -> bool:
        """Validate email address format."""
        # Basic email regex validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, address):
            return False

        # Additional validation can be added here
        # - DNS validation
        # - Disposable email check
        # - etc.

        return True

    async def handle_webhook(
        self, webhook_data: dict[str, Any], headers: dict[str, str] | None = None
    ) -> DeliveryResult | None:
        """Handle webhook events for supported providers."""
        if self.provider == "sendgrid":
            return await self._handle_sendgrid_webhook(webhook_data)
        if self.provider == "resend":
            return await self._handle_resend_webhook(webhook_data, headers)

        return None

    async def _handle_sendgrid_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle SendGrid webhook events."""

        event = webhook_data.get("event")
        message_id = webhook_data.get("sg_message_id")

        if not event or not message_id:
            return None

        # Map SendGrid events to delivery status
        status_map = {
            "delivered": DeliveryStatus.DELIVERED,
            "bounce": DeliveryStatus.BOUNCED,
            "deferred": DeliveryStatus.SENT,  # Still in progress
            "dropped": DeliveryStatus.FAILED,
            "spamreport": DeliveryStatus.FAILED,
            "unsubscribe": DeliveryStatus.FAILED,
            "open": DeliveryStatus.DELIVERED,
            "click": DeliveryStatus.READ,
        }

        status = status_map.get(event)
        if not status:
            return None

        return DeliveryResult(
            status=status,
            provider_message_id=message_id,
            provider_status=event,
            delivered_at=datetime.utcnow()
            if status == DeliveryStatus.DELIVERED
            else None,
            response_data=webhook_data,
            error_code=webhook_data.get("reason")
            if status == DeliveryStatus.FAILED
            else None,
            error_message=webhook_data.get("response")
            if status == DeliveryStatus.FAILED
            else None,
            is_retryable=status not in [DeliveryStatus.BOUNCED, DeliveryStatus.FAILED],
        )

    async def _handle_resend_webhook(
        self, webhook_data: dict[str, Any], headers: dict[str, str] | None = None
    ) -> DeliveryResult | None:
        """Handle Resend webhook events."""
        # Create a Resend adapter instance and delegate to it
        resend_adapter = ResendEmailAdapter(self.config)
        webhook_result = await resend_adapter.handle_webhook(webhook_data, headers)

        # Convert WebhookResult to DeliveryResult if successful
        if (
            webhook_result
            and webhook_result.processed
            and webhook_result.delivery_result
        ):
            return DeliveryResult(**webhook_result.delivery_result)

        return None
