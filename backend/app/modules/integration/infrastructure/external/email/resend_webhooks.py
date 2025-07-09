"""Resend webhook handling and signature validation."""

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Any

from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import DeliveryResult

from .resend_types import ResendEventTypes, ResendWebhookEvent, WebhookResult

logger = logging.getLogger(__name__)


class ResendWebhookValidator:
    """Validates Resend webhook signatures and events."""

    def __init__(self, webhook_secret: str | None = None):
        """Initialize webhook validator.

        Args:
            webhook_secret: Secret for signature validation
        """
        self.webhook_secret = webhook_secret

    def validate_signature(
        self, payload: bytes, signature: str, timestamp: str | None = None
    ) -> bool:
        """Validate webhook signature.

        Args:
            payload: Raw webhook payload
            signature: Signature from webhook headers
            timestamp: Timestamp from webhook headers

        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning(
                "No webhook secret configured, skipping signature validation"
            )
            return True

        try:
            # Extract signature from header (format: "sha256=...")
            if signature.startswith("sha256="):
                provided_signature = signature[7:]
            else:
                provided_signature = signature

            # Compute expected signature
            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            # Compare signatures
            return hmac.compare_digest(expected_signature, provided_signature)

        except Exception as e:
            logger.exception(f"Error validating webhook signature: {e}")
            return False

    def validate_timestamp(self, timestamp: str, tolerance_seconds: int = 300) -> bool:
        """Validate webhook timestamp to prevent replay attacks.

        Args:
            timestamp: Timestamp from webhook headers
            tolerance_seconds: Maximum age of webhook in seconds

        Returns:
            True if timestamp is within tolerance
        """
        try:
            webhook_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            current_time = datetime.utcnow().replace(tzinfo=webhook_time.tzinfo)

            age_seconds = (current_time - webhook_time).total_seconds()
            return abs(age_seconds) <= tolerance_seconds

        except Exception as e:
            logger.exception(f"Error validating webhook timestamp: {e}")
            return False


class ResendWebhookProcessor:
    """Processes Resend webhook events and converts them to delivery results."""

    def __init__(self, validator: ResendWebhookValidator | None = None):
        """Initialize webhook processor.

        Args:
            validator: Webhook validator instance
        """
        self.validator = validator or ResendWebhookValidator()

    def process_webhook(
        self, payload: bytes, headers: dict[str, str]
    ) -> WebhookResult | None:
        """Process incoming webhook.

        Args:
            payload: Raw webhook payload
            headers: Request headers

        Returns:
            Webhook processing result
        """
        try:
            # Validate signature if enabled
            signature = headers.get("resend-signature") or headers.get(
                "x-resend-signature"
            )
            if signature and not self.validator.validate_signature(payload, signature):
                logger.warning("Invalid webhook signature")
                return WebhookResult(processed=False)

            # Validate timestamp if present
            timestamp = headers.get("resend-timestamp") or headers.get(
                "x-resend-timestamp"
            )
            if timestamp and not self.validator.validate_timestamp(timestamp):
                logger.warning("Webhook timestamp outside tolerance")
                return WebhookResult(processed=False)

            # Parse webhook data
            try:
                webhook_data = json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError as e:
                logger.exception(f"Invalid webhook JSON: {e}")
                return WebhookResult(processed=False)

            # Process the event
            return self._process_event(webhook_data)

        except Exception as e:
            logger.exception(f"Error processing webhook: {e}")
            return WebhookResult(processed=False)

    def _process_event(self, webhook_data: dict[str, Any]) -> WebhookResult:
        """Process webhook event data.

        Args:
            webhook_data: Parsed webhook data

        Returns:
            Processing result
        """
        try:
            event = ResendWebhookEvent.from_dict(webhook_data)

            # Extract email ID
            email_data = event.data.get("email", {})
            email_id = email_data.get("id")

            if not email_id:
                logger.warning("No email ID in webhook event")
                return WebhookResult(processed=False)

            # Convert to delivery result
            delivery_result = self._event_to_delivery_result(event)

            if not delivery_result:
                logger.warning(f"Unsupported webhook event type: {event.type}")
                return WebhookResult(processed=False)

            return WebhookResult(
                processed=True,
                email_id=email_id,
                event_type=event.type,
                delivery_result=delivery_result.__dict__,
            )

        except Exception as e:
            logger.exception(f"Error processing webhook event: {e}")
            return WebhookResult(processed=False)

    def _event_to_delivery_result(
        self, event: ResendWebhookEvent
    ) -> DeliveryResult | None:
        """Convert webhook event to delivery result.

        Args:
            event: Webhook event

        Returns:
            Delivery result or None if event type not supported
        """
        # Map event types to delivery status
        status_map = {
            ResendEventTypes.EMAIL_SENT: DeliveryStatus.SENT,
            ResendEventTypes.EMAIL_DELIVERED: DeliveryStatus.DELIVERED,
            ResendEventTypes.EMAIL_DELIVERY_DELAYED: DeliveryStatus.SENT,
            ResendEventTypes.EMAIL_COMPLAINED: DeliveryStatus.FAILED,
            ResendEventTypes.EMAIL_BOUNCED: DeliveryStatus.BOUNCED,
            ResendEventTypes.EMAIL_OPENED: DeliveryStatus.READ,
            ResendEventTypes.EMAIL_CLICKED: DeliveryStatus.READ,
        }

        delivery_status = status_map.get(event.type)
        if not delivery_status:
            return None

        # Extract email data
        email_data = event.data.get("email", {})
        email_id = email_data.get("id")

        # Extract error information for failed deliveries
        error_message = None
        error_code = None
        is_retryable = True

        if delivery_status in [DeliveryStatus.FAILED, DeliveryStatus.BOUNCED]:
            error_info = event.data.get("error", {})
            error_message = error_info.get("message")
            error_code = error_info.get("code")

            # Bounces and complaints are generally not retryable
            is_retryable = delivery_status != DeliveryStatus.BOUNCED

        # Determine delivered timestamp
        delivered_at = None
        if delivery_status == DeliveryStatus.DELIVERED:
            delivered_at = event.created_at

        return DeliveryResult(
            status=delivery_status,
            provider_message_id=email_id,
            provider_status=event.type,
            delivered_at=delivered_at,
            response_data=event.data,
            error_message=error_message,
            error_code=error_code,
            is_retryable=is_retryable,
        )


class ResendWebhookManager:
    """Manages Resend webhook configurations and processing."""

    def __init__(
        self,
        webhook_secret: str | None = None,
        supported_events: list[str] | None = None,
    ):
        """Initialize webhook manager.

        Args:
            webhook_secret: Secret for signature validation
            supported_events: List of supported event types
        """
        self.webhook_secret = webhook_secret
        self.supported_events = supported_events or [
            ResendEventTypes.EMAIL_SENT,
            ResendEventTypes.EMAIL_DELIVERED,
            ResendEventTypes.EMAIL_DELIVERY_DELAYED,
            ResendEventTypes.EMAIL_COMPLAINED,
            ResendEventTypes.EMAIL_BOUNCED,
            ResendEventTypes.EMAIL_OPENED,
            ResendEventTypes.EMAIL_CLICKED,
        ]

        self.validator = ResendWebhookValidator(webhook_secret)
        self.processor = ResendWebhookProcessor(self.validator)

    def handle_webhook(self, payload: bytes, headers: dict[str, str]) -> WebhookResult:
        """Handle incoming webhook with full processing pipeline.

        Args:
            payload: Raw webhook payload
            headers: Request headers

        Returns:
            Webhook processing result
        """
        logger.info("Processing Resend webhook")

        # Process the webhook
        result = self.processor.process_webhook(payload, headers)

        if result and result.processed:
            logger.info(
                f"Successfully processed webhook event: {result.event_type} "
                f"for email: {result.email_id}"
            )
        else:
            logger.warning("Failed to process webhook")

        return result

    def get_webhook_config(self, endpoint_url: str) -> dict[str, Any]:
        """Get webhook configuration for Resend.

        Args:
            endpoint_url: URL where webhooks should be sent

        Returns:
            Webhook configuration dict
        """
        return {
            "endpoint": endpoint_url,
            "events": self.supported_events,
            "secret": self.webhook_secret,
            "active": True,
        }

    def validate_webhook_config(self, config: dict[str, Any]) -> bool:
        """Validate webhook configuration.

        Args:
            config: Webhook configuration

        Returns:
            True if configuration is valid
        """
        required_fields = ["endpoint", "events"]

        for field in required_fields:
            if field not in config:
                logger.error(f"Missing required webhook config field: {field}")
                return False

        # Validate endpoint URL
        endpoint = config["endpoint"]
        if not endpoint.startswith(("http://", "https://")):
            logger.error("Webhook endpoint must be a valid HTTP/HTTPS URL")
            return False

        # Validate events
        events = config["events"]
        if not isinstance(events, list) or not events:
            logger.error("Webhook events must be a non-empty list")
            return False

        # Check for unsupported events
        unsupported_events = set(events) - set(self.supported_events)
        if unsupported_events:
            logger.warning(f"Unsupported webhook events: {unsupported_events}")

        return True


# Webhook event filters
class ResendWebhookFilters:
    """Filters for webhook events based on various criteria."""

    @staticmethod
    def is_delivery_event(event_type: str) -> bool:
        """Check if event is a delivery-related event."""
        delivery_events = [
            ResendEventTypes.EMAIL_SENT,
            ResendEventTypes.EMAIL_DELIVERED,
            ResendEventTypes.EMAIL_DELIVERY_DELAYED,
            ResendEventTypes.EMAIL_BOUNCED,
        ]
        return event_type in delivery_events

    @staticmethod
    def is_engagement_event(event_type: str) -> bool:
        """Check if event is an engagement-related event."""
        engagement_events = [
            ResendEventTypes.EMAIL_OPENED,
            ResendEventTypes.EMAIL_CLICKED,
        ]
        return event_type in engagement_events

    @staticmethod
    def is_failure_event(event_type: str) -> bool:
        """Check if event indicates delivery failure."""
        failure_events = [
            ResendEventTypes.EMAIL_COMPLAINED,
            ResendEventTypes.EMAIL_BOUNCED,
        ]
        return event_type in failure_events

    @staticmethod
    def requires_suppression(event_type: str) -> bool:
        """Check if event requires adding email to suppression list."""
        suppression_events = [
            ResendEventTypes.EMAIL_COMPLAINED,
            ResendEventTypes.EMAIL_BOUNCED,
        ]
        return event_type in suppression_events


# Webhook retry logic
class ResendWebhookRetryHandler:
    """Handles retry logic for failed webhook processing."""

    def __init__(self, max_retries: int = 3, backoff_factor: float = 2.0):
        """Initialize retry handler.

        Args:
            max_retries: Maximum number of retry attempts
            backoff_factor: Exponential backoff factor
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    def should_retry(self, attempt: int, error: Exception) -> bool:
        """Determine if webhook processing should be retried.

        Args:
            attempt: Current attempt number (0-based)
            error: Error that occurred

        Returns:
            True if should retry
        """
        if attempt >= self.max_retries:
            return False

        # Retry on transient errors
        retryable_errors = (ConnectionError, TimeoutError, json.JSONDecodeError)

        return isinstance(error, retryable_errors)

    def get_retry_delay(self, attempt: int) -> float:
        """Get delay before retry attempt.

        Args:
            attempt: Current attempt number (0-based)

        Returns:
            Delay in seconds
        """
        return self.backoff_factor**attempt
