"""Webhook application service.

This module provides the application service for webhook processing,
including signature validation, rate limiting, and event handling.
"""

import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ApplicationError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import WebhookEventDTO, WebhookPayloadDTO
from app.modules.integration.domain.aggregates import WebhookEndpoint
from app.modules.integration.domain.entities import WebhookEvent

logger = get_logger(__name__)


class WebhookService:
    """Application service for webhook management."""

    def __init__(
        self,
        webhook_endpoint_repository: Any,
        webhook_event_repository: Any,
        integration_repository: Any,
        rate_limiter: Any,
        event_publisher: Any,
        retry_service: Any,
    ):
        """Initialize webhook service.

        Args:
            webhook_endpoint_repository: Repository for webhook endpoints
            webhook_event_repository: Repository for webhook events
            integration_repository: Repository for integrations
            rate_limiter: Service for rate limiting
            event_publisher: Event publisher for domain events
            retry_service: Service for retry logic
        """
        self._webhook_endpoint_repository = webhook_endpoint_repository
        self._webhook_event_repository = webhook_event_repository
        self._integration_repository = integration_repository
        self._rate_limiter = rate_limiter
        self._event_publisher = event_publisher
        self._retry_service = retry_service

    async def process_webhook(
        self, endpoint_id: UUID, payload: WebhookPayloadDTO
    ) -> WebhookEventDTO:
        """Process incoming webhook.

        Args:
            endpoint_id: Webhook endpoint ID
            payload: Webhook payload data

        Returns:
            WebhookEventDTO: Created webhook event

        Raises:
            NotFoundError: If endpoint not found
            ValidationError: If validation fails
            ApplicationError: If rate limit exceeded
        """
        logger.info(
            "Processing webhook",
            endpoint_id=endpoint_id,
            method=payload.method.value,
            source_ip=payload.source_ip,
        )

        # Get webhook endpoint
        endpoint = await self._webhook_endpoint_repository.get_by_id(endpoint_id)
        if not endpoint:
            raise NotFoundError(f"Webhook endpoint not found: {endpoint_id}")

        # Check if endpoint is active
        if not endpoint.is_active:
            raise ValidationError("Webhook endpoint is not active")

        # Get integration
        integration = await self._integration_repository.get_by_id(
            endpoint.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {endpoint.integration_id}")

        # Check if integration can receive webhooks
        if not integration.can_receive_webhooks:
            raise ValidationError("Integration cannot receive webhooks")

        # Check rate limit
        rate_limit_key = f"webhook:{endpoint.id}:{payload.source_ip}"
        if not await self._rate_limiter.check_limit(
            rate_limit_key, endpoint.rate_limit
        ):
            logger.warning(
                "Webhook rate limit exceeded",
                endpoint_id=endpoint.id,
                source_ip=payload.source_ip,
            )
            raise ApplicationError("Rate limit exceeded")

        # Validate signature if required
        signature_valid = True
        if endpoint.requires_signature:
            signature_valid = await self._validate_signature(endpoint, payload)

            if not signature_valid:
                logger.warning(
                    "Webhook signature validation failed", endpoint_id=endpoint.id
                )

        # Create webhook event
        webhook_event = WebhookEvent(
            webhook_id=payload.webhook_id,
            endpoint_id=endpoint.id,
            integration_id=integration.id,
            method=payload.method,
            headers=payload.headers,
            body=payload.body,
            query_params=payload.query_params,
            source_ip=payload.source_ip,
            user_agent=payload.user_agent,
            signature_valid=signature_valid,
            event_type=self._extract_event_type(payload.headers, payload.body),
            event_data=payload.body,
        )

        # Save webhook event
        await self._webhook_event_repository.save(webhook_event)

        # Record webhook received
        endpoint.record_webhook_received(signature_valid)
        await self._webhook_endpoint_repository.save(endpoint)

        # Process webhook asynchronously if signature is valid
        if signature_valid:
            await self._process_webhook_async(webhook_event)
        else:
            webhook_event.fail("Invalid signature")
            await self._webhook_event_repository.save(webhook_event)

        logger.info(
            "Webhook processed",
            webhook_id=webhook_event.id,
            event_type=webhook_event.event_type,
            signature_valid=signature_valid,
        )

        return WebhookEventDTO.from_domain(webhook_event)

    async def retry_webhook_event(
        self, event_id: UUID, force_retry: bool = False
    ) -> WebhookEventDTO:
        """Retry processing a failed webhook event.

        Args:
            event_id: Webhook event ID
            force_retry: Force retry even if max attempts reached

        Returns:
            WebhookEventDTO: Updated webhook event

        Raises:
            NotFoundError: If event not found
            ValidationError: If cannot retry
        """
        logger.info("Retrying webhook event", event_id=event_id)

        # Get webhook event
        webhook_event = await self._webhook_event_repository.get_by_id(event_id)
        if not webhook_event:
            raise NotFoundError(f"Webhook event not found: {event_id}")

        # Check if can retry
        if not force_retry and not webhook_event.can_retry:
            raise ValidationError("Webhook event cannot be retried")

        # Reset event status
        webhook_event.retry()
        await self._webhook_event_repository.save(webhook_event)

        # Process webhook
        await self._process_webhook_async(webhook_event)

        logger.info("Webhook event retry initiated", event_id=event_id)

        return WebhookEventDTO.from_domain(webhook_event)

    async def get_webhook_statistics(
        self,
        integration_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get webhook statistics for integration.

        Args:
            integration_id: Integration ID
            start_date: Optional start date
            end_date: Optional end date

        Returns:
            dict[str, Any]: Webhook statistics
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        stats = await self._webhook_event_repository.get_statistics(
            {
                "integration_id": integration_id,
                "start_date": start_date,
                "end_date": end_date,
            }
        )

        return {
            "total_webhooks": stats.get("total_count", 0),
            "successful_webhooks": stats.get("successful_count", 0),
            "failed_webhooks": stats.get("failed_count", 0),
            "pending_webhooks": stats.get("pending_count", 0),
            "average_processing_time_ms": stats.get("avg_processing_time_ms", 0.0),
            "error_rate": stats.get("error_rate", 0.0),
            "most_common_events": stats.get("most_common_events", []),
            "hourly_distribution": stats.get("hourly_distribution", []),
        }

    async def _validate_signature(
        self, endpoint: WebhookEndpoint, payload: WebhookPayloadDTO
    ) -> bool:
        """Validate webhook signature.

        Args:
            endpoint: Webhook endpoint
            payload: Webhook payload

        Returns:
            bool: True if signature is valid
        """
        # Get signature from headers
        signature_header = endpoint.signature_header or "X-Webhook-Signature"
        provided_signature = payload.headers.get(signature_header, "").lower()

        if not provided_signature:
            return False

        # Get signing secret
        signing_secret = endpoint.get_signing_secret()
        if not signing_secret:
            return False

        # Calculate expected signature
        signature_data = payload.get_signature_data()

        # Most webhooks use HMAC-SHA256
        expected_signature = hmac.new(
            signing_secret.encode(), signature_data.encode(), hashlib.sha256
        ).hexdigest()

        # Some webhooks prefix with scheme
        if "=" in provided_signature:
            scheme, signature = provided_signature.split("=", 1)
            return hmac.compare_digest(signature, expected_signature)

        return hmac.compare_digest(provided_signature, expected_signature)

    def _extract_event_type(self, headers: dict[str, str], body: dict[str, Any]) -> str:
        """Extract event type from webhook.

        Args:
            headers: Request headers
            body: Request body

        Returns:
            str: Event type
        """
        # Common header names for event type
        event_headers = [
            "X-Event-Type",
            "X-GitHub-Event",
            "X-Stripe-Event",
            "X-Webhook-Event",
        ]

        for header in event_headers:
            if header in headers:
                return headers[header]

        # Check body for event type
        if "event" in body:
            return body["event"]
        if "type" in body:
            return body["type"]
        if "event_type" in body:
            return body["event_type"]

        return "unknown"

    async def _process_webhook_async(self, webhook_event: WebhookEvent) -> None:
        """Process webhook event asynchronously.

        Args:
            webhook_event: Webhook event to process
        """
        try:
            # Mark as processing
            webhook_event.start_processing()
            await self._webhook_event_repository.save(webhook_event)

            # Process based on event type
            await self._handle_webhook_event(webhook_event)

            # Mark as processed
            webhook_event.complete()
            await self._webhook_event_repository.save(webhook_event)

        except Exception as e:
            logger.exception(
                "Webhook processing failed", webhook_id=webhook_event.id, error=str(e)
            )

            # Mark as failed
            webhook_event.fail(str(e))
            await self._webhook_event_repository.save(webhook_event)

            # Schedule retry if retryable
            if webhook_event.can_retry:
                retry_delay = self._calculate_retry_delay(webhook_event.attempts)
                await self._retry_service.schedule_retry(webhook_event.id, retry_delay)

    async def _handle_webhook_event(self, webhook_event: WebhookEvent) -> None:
        """Handle specific webhook event processing.

        Args:
            webhook_event: Webhook event to handle
        """
        # Publish domain event for other modules to handle
        from app.core.events.types import EventMetadata
        from app.modules.integration.domain.events import WebhookReceivedEvent

        await self._event_publisher.publish(
            WebhookReceivedEvent(
                webhook_id=webhook_event.id,
                integration_id=webhook_event.integration_id,
                event_type=webhook_event.event_type,
                payload=webhook_event.event_data,
                signature_valid=webhook_event.signature_valid,
                metadata=EventMetadata(
                    event_id=UUID.uuid4(),
                    aggregate_id=webhook_event.id,
                    aggregate_type="WebhookEvent",
                    event_type="WebhookReceivedEvent",
                    event_version=1,
                    occurred_at=datetime.utcnow(),
                ),
            )
        )

    def _calculate_retry_delay(self, attempt: int) -> int:
        """Calculate retry delay using exponential backoff.

        Args:
            attempt: Attempt number

        Returns:
            int: Delay in seconds
        """
        # Exponential backoff with jitter: 2^attempt + random(0, attempt)
        import random

        base_delay = 2 ** min(attempt, 6)  # Cap at 64 seconds
        jitter = random.randint(0, attempt)
        return base_delay + jitter
