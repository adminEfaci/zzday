"""
Email channel adapter for Integration module.

This adapter handles email sending through various providers (SMTP, SendGrid, Resend)
without dependencies on other modules' domain objects.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib
from app.core.logging import get_logger
from app.modules.integration.infrastructure.external.base_adapter import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
    DeliveryStatus,
    NotificationData,
)

logger = get_logger(__name__)

# Constants
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
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

    async def validate_recipient(self, recipient: str) -> bool:
        """Validate email address format."""
        return bool(EMAIL_REGEX.match(recipient))

    async def send(self, notification: NotificationData) -> DeliveryResult:
        """Send email notification."""
        try:
            # Validate recipient
            if not await self.validate_recipient(notification.recipient):
                raise ChannelAdapterError(
                    f"Invalid email address: {notification.recipient}",
                    is_retryable=False
                )

            if self.provider == "smtp":
                return await self._send_smtp(notification)
            elif self.provider == "sendgrid":
                return await self._send_sendgrid(notification)
            elif self.provider == "resend":
                return await self._send_resend(notification)
            else:
                raise ChannelAdapterError(
                    f"Unsupported provider: {self.provider}", 
                    is_retryable=False
                )
        except ChannelAdapterError:
            raise
        except Exception as e:
            logger.exception(
                "Failed to send email",
                provider=self.provider,
                recipient=notification.recipient,
                error=str(e)
            )
            raise ChannelAdapterError(
                f"Failed to send email: {str(e)}", 
                is_retryable=True
            )

    async def _send_smtp(self, notification: NotificationData) -> DeliveryResult:
        """Send email via SMTP."""
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = notification.subject or "Notification"
        msg["From"] = f"{self.config.settings['from_name']} <{self.config.settings['from_email']}>"
        msg["To"] = notification.recipient

        # Add text part
        text_part = MIMEText(notification.content, "plain")
        msg.attach(text_part)

        # Add HTML part if available
        if notification.html_content:
            html_part = MIMEText(notification.html_content, "html")
            msg.attach(html_part)

        # Send via SMTP
        smtp_config = self.config.settings
        use_tls = smtp_config.get("use_tls", True)

        try:
            async with aiosmtplib.SMTP(
                hostname=smtp_config["host"], 
                port=smtp_config["port"], 
                use_tls=use_tls
            ) as smtp:
                if self.config.settings.get("use_auth", True):
                    await smtp.login(
                        self.config.credentials["username"],
                        self.config.credentials["password"]
                    )

                result = await smtp.send_message(msg)

                # Parse SMTP response
                message_id = result[1].decode() if isinstance(result[1], bytes) else str(result[1])

                return DeliveryResult(
                    status=DeliveryStatus.SENT,
                    provider_message_id=message_id,
                    provider_status="250 OK",
                    delivered_at=datetime.utcnow(),
                    response_data={"smtp_response": str(result)}
                )

        except aiosmtplib.SMTPException as e:
            error_code = getattr(e, "code", None)
            # Permanent failures (5xx codes)
            is_retryable = error_code not in [550, 551, 552, 553, 554]

            logger.error(
                "SMTP send failed",
                error=str(e),
                error_code=error_code,
                is_retryable=is_retryable
            )

            raise ChannelAdapterError(
                f"SMTP error: {str(e)}",
                error_code=str(error_code) if error_code else None,
                is_retryable=is_retryable
            )

    async def _send_sendgrid(self, notification: NotificationData) -> DeliveryResult:
        """Send email via SendGrid."""
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail, Email, To, Content

            sg = SendGridAPIClient(self.config.credentials["api_key"])

            # Create mail object
            from_email = Email(
                email=self.config.settings["from_email"],
                name=self.config.settings["from_name"]
            )
            to_email = To(notification.recipient)
            
            # Use HTML content if available, otherwise plain text
            content_type = "text/html" if notification.html_content else "text/plain"
            content_value = notification.html_content or notification.content
            content = Content(content_type, content_value)
            
            mail = Mail(
                from_email=from_email,
                to_emails=to_email,
                subject=notification.subject or "Notification",
                html_content=content
            )

            # Add custom headers if provided
            if notification.metadata.get("headers"):
                for key, value in notification.metadata["headers"].items():
                    mail.add_header(key, value)

            # Send
            response = await sg.send(mail)

            # Parse response
            if response.status_code >= 200 and response.status_code < 300:
                message_id = response.headers.get("X-Message-Id", "")
                
                return DeliveryResult(
                    status=DeliveryStatus.SENT,
                    provider_message_id=message_id,
                    provider_status=str(response.status_code),
                    delivered_at=datetime.utcnow(),
                    response_data={
                        "status_code": response.status_code,
                        "headers": dict(response.headers)
                    }
                )
            else:
                is_retryable = (
                    response.status_code >= MIN_RETRYABLE_STATUS and 
                    response.status_code < MAX_RETRYABLE_STATUS
                )
                
                raise ChannelAdapterError(
                    f"SendGrid error: {response.body}",
                    error_code=str(response.status_code),
                    is_retryable=is_retryable,
                    provider_response={"body": response.body}
                )

        except ImportError:
            raise ChannelAdapterError(
                "SendGrid SDK not installed",
                is_retryable=False
            )
        except Exception as e:
            if isinstance(e, ChannelAdapterError):
                raise
            
            logger.exception(
                "SendGrid send failed",
                error=str(e)
            )
            
            raise ChannelAdapterError(
                f"SendGrid error: {str(e)}",
                is_retryable=True
            )

    async def _send_resend(self, notification: NotificationData) -> DeliveryResult:
        """Send email via Resend."""
        # Use the dedicated Resend adapter
        from .resend_adapter import ResendEmailAdapter
        
        resend_adapter = ResendEmailAdapter(self.config)
        return await resend_adapter.send(notification)

    async def check_status(self, provider_message_id: str) -> Optional[DeliveryResult]:
        """Check delivery status of a sent email."""
        # Most email providers don't support real-time status checks
        # This would need provider-specific implementations
        if self.provider == "sendgrid":
            # SendGrid has a webhook/event API for status updates
            # This would require additional implementation
            pass
        
        return None

    async def health_check(self) -> bool:
        """Check if email service is healthy."""
        try:
            if self.provider == "smtp":
                # Try to connect to SMTP server
                smtp_config = self.config.settings
                async with aiosmtplib.SMTP(
                    hostname=smtp_config["host"],
                    port=smtp_config["port"],
                    timeout=5
                ) as smtp:
                    # Just connecting is enough for health check
                    return True
            
            elif self.provider == "sendgrid":
                # Could make a test API call
                return True
            
            elif self.provider == "resend":
                # Could make a test API call
                return True
                
            return False
            
        except Exception as e:
            logger.warning(
                "Email health check failed",
                provider=self.provider,
                error=str(e)
            )
            return False