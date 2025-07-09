"""Resend email service adapter implementation."""

import base64
import json
import logging
from datetime import datetime
from typing import Any

import httpx

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)

from .resend_client import ResendApiClient, ResendAPIError, ResendRateLimitError
from .resend_types import (
    BulkDeliveryResult,
    ResendAttachment,
    ResendBatchRequest,
    ResendConfiguration,
    ResendEmailAddress,
    ResendEmailRequest,
    ResendEventTypes,
    ResendStatus,
    ScheduleResult,
    SuppressionList,
    WebhookResult,
)
from .resend_webhooks import ResendWebhookManager

logger = logging.getLogger(__name__)


class ResendEmailAdapter(BaseChannelAdapter):
    """Advanced Resend email service adapter.

    Modern email service with excellent deliverability, analytics,
    and developer experience. Supports templates, batching, webhooks,
    scheduling, and comprehensive analytics.

    Features:
    - High-performance async API client
    - Template support with dynamic variables
    - Bulk sending with batch optimization
    - Email scheduling for future delivery
    - Real-time webhooks for delivery tracking
    - Comprehensive analytics and reporting
    - Automatic suppression list management
    - Rate limiting with intelligent backoff
    - Domain verification and reputation management
    """

    SUPPORTED_PROVIDERS = ["resend"]

    def __init__(self, config):
        """Initialize enhanced Resend adapter."""
        super().__init__(config)

        # Initialize API client
        self._api_client: ResendApiClient | None = None

        # Initialize webhook manager
        webhook_secret = self.config.settings.get("webhook_secret")
        self._webhook_manager = ResendWebhookManager(webhook_secret)

        # Configuration
        self._resend_config = self._build_resend_config()

        # Health monitoring
        self._last_health_check: datetime | None = None
        self._health_status = {"status": "unknown"}

    def _validate_config(self) -> None:
        """Validate Resend configuration."""
        if self.provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported provider: {self.provider}")

        # Validate required settings
        required_settings = ["from_email", "from_name"]
        for setting in required_settings:
            if setting not in self.config.settings:
                raise ValueError(f"Missing required setting: {setting}")

        # Validate credentials
        if "api_key" not in self.config.credentials:
            raise ValueError("Resend API key required")

        # Validate email format
        from_email = self.config.settings["from_email"]
        if "@" not in from_email:
            raise ValueError("Invalid from_email format")

        # Validate optional webhook configuration
        webhook_secret = self.config.settings.get("webhook_secret")
        if webhook_secret and len(webhook_secret) < 16:
            logger.warning(
                "Webhook secret should be at least 16 characters for security"
            )

    def _build_resend_config(self) -> ResendConfiguration:
        """Build Resend configuration from adapter config."""
        return ResendConfiguration(
            api_key=self.config.credentials["api_key"],
            from_email=self.config.settings["from_email"],
            from_name=self.config.settings["from_name"],
            webhook_secret=self.config.settings.get("webhook_secret"),
            default_tags=self.config.settings.get("default_tags"),
            rate_limit_per_second=self.config.settings.get("rate_limit_per_second", 10),
            max_retries=self.config.settings.get("max_retries", 3),
            timeout_seconds=self.config.settings.get("timeout_seconds", 30.0),
            enable_analytics=self.config.settings.get("enable_analytics", True),
            enable_click_tracking=self.config.settings.get(
                "enable_click_tracking", True
            ),
            enable_open_tracking=self.config.settings.get("enable_open_tracking", True),
        )

    async def _get_api_client(self) -> ResendApiClient:
        """Get or create API client."""
        if self._api_client is None:
            self._api_client = ResendApiClient(
                api_key=self._resend_config.api_key,
                timeout=self._resend_config.timeout_seconds,
                max_retries=self._resend_config.max_retries,
            )
        return self._api_client

    async def send(self, notification: Notification) -> DeliveryResult:
        """Send email via Resend with enhanced error handling."""
        try:
            # Build email request
            request = self._build_email_request(notification)

            # Get API client
            client = await self._get_api_client()

            # Send email using the client
            async with client:
                response = await client.send_email(request)

            # Convert to delivery result
            return DeliveryResult(
                status=DeliveryStatus.SENT,
                provider_message_id=response.id,
                provider_status="sent",
                delivered_at=response.created_at,
                response_data={
                    "id": response.id,
                    "from": response.from_email,
                    "to": response.to,
                    "subject": response.subject,
                    "created_at": response.created_at.isoformat(),
                },
            )

        except ResendRateLimitError as e:
            raise ChannelAdapterError(
                f"Resend rate limit exceeded: {e!s}",
                error_code="rate_limit",
                is_retryable=True,
            )
        except ResendAPIError as e:
            # Determine if error is retryable based on status code
            is_retryable = e.status_code >= 500 or e.status_code == 429

            raise ChannelAdapterError(
                f"Resend API error: {e.message}",
                error_code=e.error_code,
                is_retryable=is_retryable,
                provider_response=e.response_data,
            )
        except Exception as e:
            logger.exception(f"Unexpected error sending email via Resend: {e}")
            raise ChannelAdapterError(
                f"Resend unexpected error: {e!s}", is_retryable=True
            )

    def _build_email_request(self, notification: Notification) -> ResendEmailRequest:
        """Build Resend email request from notification."""
        # From address
        from_address = ResendEmailAddress(
            email=self.config.settings["from_email"],
            name=self.config.settings["from_name"],
        )

        # To address
        to_addresses = [
            ResendEmailAddress(
                email=notification.recipient_address.address,
                name=notification.recipient_address.display_name,
            )
        ]

        # Build attachments
        attachments = []
        for attachment_data in notification.content.attachments:
            if "content" in attachment_data:
                # Handle base64 content
                content = attachment_data["content"]
                if isinstance(content, str):
                    content = base64.b64decode(content)

                attachments.append(
                    ResendAttachment(
                        filename=attachment_data["filename"],
                        content=content,
                        content_type=attachment_data.get(
                            "content_type", "application/octet-stream"
                        ),
                    )
                )

        # Build tags for tracking
        tags = []
        if notification.idempotency_key:
            tags.append(
                {"name": "idempotency_key", "value": notification.idempotency_key}
            )
        if hasattr(notification, "campaign_id") and notification.campaign_id:
            tags.append({"name": "campaign_id", "value": str(notification.campaign_id)})

        # Custom headers
        headers = {}
        if notification.idempotency_key:
            headers["X-Idempotency-Key"] = notification.idempotency_key

        return ResendEmailRequest(
            from_address=from_address,
            to=to_addresses,
            subject=notification.content.subject or "Notification",
            text=notification.content.body,
            html=notification.content.html_body,
            attachments=attachments if attachments else None,
            tags=tags if tags else None,
            headers=headers if headers else None,
        )

    async def _handle_error_response(self, response: httpx.Response) -> None:
        """Handle error responses from Resend API."""
        try:
            error_data = response.json()
            error_message = error_data.get("message", "Unknown error")
            error_type = error_data.get("type", "unknown")
        except json.JSONDecodeError:
            error_message = response.text or f"HTTP {response.status_code} error"
            error_type = "http_error"

        # Determine if error is retryable
        is_retryable = True
        if response.status_code in [400, 401, 403, 404, 422]:
            is_retryable = False  # Client errors are not retryable
        elif response.status_code in [429]:
            is_retryable = True  # Rate limiting is retryable
        elif response.status_code >= 500:
            is_retryable = True  # Server errors are retryable

        raise ChannelAdapterError(
            f"Resend API error ({response.status_code}): {error_message}",
            error_code=str(response.status_code),
            is_retryable=is_retryable,
            provider_response=error_data if "error_data" in locals() else None,
        )

    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check email delivery status via Resend API."""
        try:
            client = self._get_client()
            response = await client.get(f"/emails/{provider_message_id}")

            if response.status_code == 200:
                data = response.json()
                status = data.get("status", "unknown")

                # Map Resend status to our delivery status
                delivery_status = self._map_resend_status(status)

                return DeliveryResult(
                    status=delivery_status,
                    provider_message_id=provider_message_id,
                    provider_status=status,
                    delivered_at=datetime.utcnow()
                    if delivery_status == DeliveryStatus.DELIVERED
                    else None,
                    response_data=data,
                )
            if response.status_code == 404:
                # Email not found
                return None
            # API error - return None rather than raising
            return None

        except Exception:
            # Return None on any error
            return None

    def _map_resend_status(self, resend_status: str) -> DeliveryStatus:
        """Map Resend status to delivery status."""
        status_map = {
            ResendStatus.QUEUED: DeliveryStatus.SENT,
            ResendStatus.SENT: DeliveryStatus.SENT,
            ResendStatus.DELIVERED: DeliveryStatus.DELIVERED,
            ResendStatus.DELIVERY_DELAYED: DeliveryStatus.SENT,
            ResendStatus.COMPLAINED: DeliveryStatus.FAILED,
            ResendStatus.BOUNCED: DeliveryStatus.BOUNCED,
            ResendStatus.CLICKED: DeliveryStatus.READ,
            ResendStatus.OPENED: DeliveryStatus.READ,
        }

        return status_map.get(resend_status, DeliveryStatus.SENT)

    async def validate_address(self, address: str) -> bool:
        """Validate email address format."""
        # Basic email validation
        import re

        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, address):
            return False

        # Additional validation can be added:
        # - Domain validation
        # - Disposable email detection
        # - etc.

        return True

    async def handle_webhook(
        self, webhook_data: dict[str, Any], headers: dict[str, str] | None = None
    ) -> WebhookResult | None:
        """Handle Resend webhook events with enhanced processing."""
        try:
            # Use webhook manager for comprehensive processing
            if headers:
                # Convert webhook data to bytes for signature validation
                import json

                payload = json.dumps(webhook_data).encode("utf-8")
                result = self._webhook_manager.handle_webhook(payload, headers)
            else:
                # Fallback to basic processing without signature validation
                logger.warning("No headers provided for webhook validation")
                result = self._webhook_manager.processor.process_webhook(
                    json.dumps(webhook_data).encode("utf-8"), {}
                )

            # If webhook processing succeeds, also handle suppression management
            if result and result.processed and result.delivery_result:
                delivery_result = DeliveryResult(**result.delivery_result)

                # Auto-suppress emails for bounces and complaints
                if delivery_result.status in [
                    DeliveryStatus.BOUNCED,
                    DeliveryStatus.FAILED,
                ]:
                    event_data = webhook_data.get("data", {})
                    email_address = event_data.get("email", {}).get("to", [])

                    if (
                        email_address
                        and isinstance(email_address, list)
                        and email_address
                    ):
                        email = email_address[0]
                        try:
                            await self.manage_suppression_list(
                                action="add",
                                email=email,
                                reason=f"auto_suppressed_{delivery_result.status.value}",
                            )
                            logger.info(
                                f"Auto-suppressed email {email} due to {delivery_result.status.value}"
                            )
                        except Exception as e:
                            logger.warning(
                                f"Failed to auto-suppress email {email}: {e}"
                            )

            return result

        except Exception as e:
            logger.exception(f"Webhook handling failed: {e}")
            return WebhookResult(processed=False)

    async def health_check(self) -> dict[str, Any]:
        """Perform comprehensive health check."""
        try:
            # Check if we need to refresh health status
            now = datetime.utcnow()
            if (
                self._last_health_check is None
                or (now - self._last_health_check).seconds > 300
            ):  # 5 minutes cache
                client = await self._get_api_client()
                async with client:
                    health_data = await client.health_check()

                self._health_status = {
                    "status": "healthy"
                    if health_data.get("status") != "unhealthy"
                    else "unhealthy",
                    "provider": "resend",
                    "last_check": now.isoformat(),
                    "api_responsive": True,
                    "features": {
                        "email_sending": True,
                        "batch_sending": True,
                        "template_support": True,
                        "scheduling": True,
                        "analytics": self._resend_config.enable_analytics,
                        "webhooks": self._resend_config.webhook_secret is not None,
                        "suppression_management": True,
                    },
                    "rate_limits": {
                        "configured_limit": self._resend_config.rate_limit_per_second,
                        "remaining": getattr(client, "_rate_limit_remaining", None),
                        "reset_time": getattr(client, "_rate_limit_reset", None),
                    },
                }
                self._last_health_check = now

        except Exception as e:
            self._health_status = {
                "status": "unhealthy",
                "provider": "resend",
                "last_check": datetime.utcnow().isoformat(),
                "api_responsive": False,
                "error": str(e),
            }

        return self._health_status

    def _map_webhook_event(self, event_type: str) -> DeliveryStatus | None:
        """Map webhook event type to delivery status."""
        event_map = {
            ResendEventTypes.EMAIL_SENT: DeliveryStatus.SENT,
            ResendEventTypes.EMAIL_DELIVERED: DeliveryStatus.DELIVERED,
            ResendEventTypes.EMAIL_DELIVERY_DELAYED: DeliveryStatus.SENT,
            ResendEventTypes.EMAIL_COMPLAINED: DeliveryStatus.FAILED,
            ResendEventTypes.EMAIL_BOUNCED: DeliveryStatus.BOUNCED,
            ResendEventTypes.EMAIL_OPENED: DeliveryStatus.READ,
            ResendEventTypes.EMAIL_CLICKED: DeliveryStatus.READ,
        }

        return event_map.get(event_type)

    async def get_quota_info(self) -> dict[str, Any]:
        """Get current quota and usage information."""
        # This would require calling Resend's usage API when available
        # For now, return basic info
        return {
            "provider": "resend",
            "channel": self.channel.value,
            "quota_available": True,
            "features": [
                "html_email",
                "attachments",
                "templates",
                "analytics",
                "webhooks",
                "batch_sending",
            ],
            "rate_limits": self.config.rate_limits,
        }

    async def send_bulk_email(
        self, notifications: list[Notification]
    ) -> BulkDeliveryResult:
        """Send multiple emails using Resend's batch API."""
        try:
            # Build batch request
            email_requests = [
                self._build_email_request(notification)
                for notification in notifications
            ]
            batch_request = ResendBatchRequest(emails=email_requests)

            # Get API client and send batch
            client = await self._get_api_client()
            async with client:
                batch_response = await client.send_batch(batch_request)

            # Process results
            results = []
            successful_count = 0
            failed_count = 0

            for i, email_response in enumerate(batch_response.emails):
                try:
                    result = {
                        "notification_id": str(notifications[i].id),
                        "status": "sent",
                        "provider_message_id": email_response.id,
                        "created_at": email_response.created_at.isoformat(),
                    }
                    results.append(result)
                    successful_count += 1
                except Exception as e:
                    result = {
                        "notification_id": str(notifications[i].id),
                        "status": "failed",
                        "error": str(e),
                    }
                    results.append(result)
                    failed_count += 1

            return BulkDeliveryResult(
                total_count=len(notifications),
                successful_count=successful_count,
                failed_count=failed_count,
                results=results,
                batch_id=batch_response.id,
            )

        except Exception as e:
            logger.exception(f"Bulk email sending failed: {e}")
            raise ChannelAdapterError(f"Bulk sending failed: {e!s}", is_retryable=True)

    async def send_batch(
        self, notifications: list[Notification]
    ) -> list[DeliveryResult]:
        """Send multiple emails efficiently (backwards compatibility)."""
        # Use the new bulk email method but return individual results
        try:
            bulk_result = await self.send_bulk_email(notifications)

            results = []
            for _i, result_data in enumerate(bulk_result.results):
                if result_data["status"] == "sent":
                    results.append(
                        DeliveryResult(
                            status=DeliveryStatus.SENT,
                            provider_message_id=result_data["provider_message_id"],
                            provider_status="sent",
                            delivered_at=datetime.fromisoformat(
                                result_data["created_at"]
                            ),
                            response_data=result_data,
                        )
                    )
                else:
                    results.append(
                        DeliveryResult(
                            status=DeliveryStatus.FAILED,
                            error_message=result_data.get("error", "Unknown error"),
                            is_retryable=True,
                        )
                    )

            return results

        except ChannelAdapterError:
            raise
        except Exception as e:
            # Fallback to sequential sending
            logger.warning(f"Batch sending failed, falling back to sequential: {e}")
            results = []

            for notification in notifications:
                try:
                    result = await self.send(notification)
                    results.append(result)
                except ChannelAdapterError as e:
                    results.append(
                        DeliveryResult(
                            status=DeliveryStatus.FAILED,
                            error_message=str(e),
                            is_retryable=e.is_retryable,
                        )
                    )

            return results

    async def send_template_email(
        self,
        template_id: str,
        variables: dict[str, Any],
        recipients: list[str],
        subject: str | None = None,
    ) -> DeliveryResult:
        """Send email using a Resend template."""
        try:
            client = await self._get_api_client()

            async with client:
                response = await client.send_template_email(
                    template_id=template_id,
                    to=recipients,
                    variables=variables,
                    from_email=self._resend_config.from_email,
                    subject=subject,
                )

            return DeliveryResult(
                status=DeliveryStatus.SENT,
                provider_message_id=response.id,
                provider_status="sent",
                delivered_at=response.created_at,
                response_data={
                    "id": response.id,
                    "template_id": template_id,
                    "variables": variables,
                    "recipients": recipients,
                },
            )

        except Exception as e:
            logger.exception(f"Template email sending failed: {e}")
            raise ChannelAdapterError(
                f"Template sending failed: {e!s}", is_retryable=True
            )

    async def schedule_email(
        self, notification: Notification, send_at: datetime
    ) -> ScheduleResult:
        """Schedule an email for future delivery."""
        try:
            # Build email request
            email_request = self._build_email_request(notification)

            # Get API client and schedule
            client = await self._get_api_client()
            async with client:
                schedule_response = await client.schedule_email(email_request, send_at)

            return ScheduleResult(
                schedule_id=schedule_response.id,
                email_id=schedule_response.email_id,
                send_at=schedule_response.send_at,
                status=schedule_response.status,
            )

        except Exception as e:
            logger.exception(f"Email scheduling failed: {e}")
            raise ChannelAdapterError(f"Scheduling failed: {e!s}", is_retryable=True)

    async def cancel_scheduled_email(self, schedule_id: str) -> bool:
        """Cancel a scheduled email."""
        try:
            client = await self._get_api_client()
            async with client:
                return await client.cancel_scheduled_email(schedule_id)
        except Exception as e:
            logger.exception(f"Canceling scheduled email failed: {e}")
            raise ChannelAdapterError(f"Cancel failed: {e!s}", is_retryable=True)

    async def get_delivery_analytics(
        self, start_date: datetime, end_date: datetime, events: list[str] | None = None
    ) -> dict[str, Any]:
        """Get email delivery analytics for a date range."""
        try:
            client = await self._get_api_client()
            async with client:
                analytics = await client.get_analytics(start_date, end_date, events)

            return {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "total_count": analytics.total_count,
                "analytics": [
                    {"event": item.event, "count": item.count, "date": item.date}
                    for item in analytics.data
                ],
            }

        except Exception as e:
            logger.exception(f"Getting analytics failed: {e}")
            return {
                "error": str(e),
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            }

    async def manage_suppression_list(
        self, action: str, email: str | None = None, reason: str = "user_request"
    ) -> SuppressionList:
        """Manage suppression list entries."""
        try:
            client = await self._get_api_client()

            async with client:
                if action == "add" and email:
                    await client.add_suppression(email, reason)
                elif action == "remove" and email:
                    await client.remove_suppression(email)

                # Get current suppression list
                suppressions = await client.get_suppressions()

            return SuppressionList(entries=suppressions, total_count=len(suppressions))

        except Exception as e:
            logger.exception(f"Suppression list management failed: {e}")
            raise ChannelAdapterError(
                f"Suppression management failed: {e!s}", is_retryable=True
            )

    async def track_delivery(self, message_id: str) -> DeliveryStatus:
        """Track delivery status of a specific message."""
        try:
            result = await self.check_status(message_id)
            return result.status if result else DeliveryStatus.SENT
        except Exception as e:
            logger.exception(f"Delivery tracking failed: {e}")
            return DeliveryStatus.SENT  # Default to sent if tracking fails

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()

    async def cleanup(self):
        """Clean up resources."""
        if self._api_client:
            await self._api_client.close()
            self._api_client = None
