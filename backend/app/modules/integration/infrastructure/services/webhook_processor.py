"""Webhook event processor service.

This module provides webhook event processing with retry logic.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import IntegrationError
from app.modules.integration.domain.entities import WebhookEvent
from app.modules.integration.domain.enums import WebhookStatus
from app.modules.integration.infrastructure.repositories import (
    WebhookEndpointRepository,
)
from app.modules.integration.infrastructure.services import DataTransformationService

logger = logging.getLogger(__name__)


class WebhookProcessorService:
    """Service for processing webhook events."""

    def __init__(
        self,
        webhook_repo: WebhookEndpointRepository,
        transformation_service: DataTransformationService,
        max_retries: int = 3,
        retry_delay_seconds: int = 60,
        process_callback: Callable | None = None,
    ):
        """Initialize webhook processor."""
        self.webhook_repo = webhook_repo
        self.transformation_service = transformation_service
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        self.process_callback = process_callback

        # Processing queue
        self.processing_queue: asyncio.Queue = asyncio.Queue()
        self._processing = False

        # Metrics
        self.metrics = {
            "total_processed": 0,
            "successful": 0,
            "failed": 0,
            "retried": 0,
        }

    async def process_event(self, event: WebhookEvent) -> dict[str, Any]:
        """Process a single webhook event.

        Args:
            event: Webhook event to process

        Returns:
            Processing result
        """
        try:
            self.metrics["total_processed"] += 1

            # Update status to processing
            event.status = WebhookStatus.PROCESSING
            event.attempts += 1
            event.last_attempt_at = datetime.now(UTC)

            # Get endpoint configuration
            endpoint = await self.webhook_repo.find_by_id(event.endpoint_id)
            if not endpoint:
                raise IntegrationError("Webhook endpoint not found")

            # Validate event type
            if event.event_type not in endpoint.event_types:
                logger.warning(f"Unexpected event type: {event.event_type}")
                event.status = WebhookStatus.FAILED
                event.error_message = "Unexpected event type"
                return {"status": "failed", "reason": "unexpected_event_type"}

            # Process based on event type
            result = await self._process_by_type(event, endpoint)

            # Mark as processed
            event.status = WebhookStatus.PROCESSED
            event.processed_at = datetime.now(UTC)
            event.response_body = result

            self.metrics["successful"] += 1

            # Call process callback if provided
            if self.process_callback:
                await self.process_callback(event, result)

            return result

        except Exception as e:
            logger.error(f"Event processing failed: {e}", exc_info=True)
            self.metrics["failed"] += 1

            # Check if should retry
            if event.attempts < self.max_retries:
                event.status = WebhookStatus.PENDING
                event.next_retry_at = datetime.now(UTC) + timedelta(
                    seconds=self.retry_delay_seconds * event.attempts
                )
                event.error_message = str(e)
                self.metrics["retried"] += 1
            else:
                event.status = WebhookStatus.FAILED
                event.error_message = f"Max retries exceeded: {e!s}"

            raise

    async def _process_by_type(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Process event based on its type."""
        # Route to specific handlers based on event type
        handlers = {
            "user.created": self._handle_user_created,
            "user.updated": self._handle_user_updated,
            "order.placed": self._handle_order_placed,
            "payment.received": self._handle_payment_received,
            # Add more handlers as needed
        }

        handler = handlers.get(event.event_type, self._handle_generic)
        return await handler(event, endpoint)

    async def _handle_user_created(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Handle user created event."""
        # Extract user data
        user_data = event.payload.get("user", {})

        # Transform if needed
        await self.transformation_service.transform_webhook_payload(
            user_data, event.event_type
        )

        # Process user creation
        # Implementation specific

        return {
            "status": "processed",
            "user_id": user_data.get("id"),
            "action": "user_created",
        }

    async def _handle_user_updated(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Handle user updated event."""
        return {"status": "processed", "action": "user_updated"}

    async def _handle_order_placed(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Handle order placed event."""
        return {"status": "processed", "action": "order_placed"}

    async def _handle_payment_received(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Handle payment received event."""
        return {"status": "processed", "action": "payment_received"}

    async def _handle_generic(
        self, event: WebhookEvent, endpoint: Any
    ) -> dict[str, Any]:
        """Handle generic/unknown events."""
        logger.info(f"Generic handler for event type: {event.event_type}")

        return {
            "status": "processed",
            "action": "generic_handler",
            "event_type": event.event_type,
        }

    async def process_pending_events(self) -> int:
        """Process all pending webhook events.

        Returns:
            Number of events processed
        """
        # Get pending events from repository
        # This is simplified - in real implementation would query the repository
        return 0

        # Process events
        # Implementation specific

    async def reprocess_failed_events(
        self, endpoint_id: UUID | None = None, max_age_hours: int = 24
    ) -> int:
        """Reprocess failed events.

        Args:
            endpoint_id: Specific endpoint (all if None)
            max_age_hours: Maximum age of events to reprocess

        Returns:
            Number of events reprocessed
        """
        # Implementation specific
        return 0

    def get_metrics(self) -> dict[str, Any]:
        """Get processor metrics."""
        total = self.metrics["total_processed"]
        return {
            **self.metrics,
            "success_rate": (self.metrics["successful"] / total if total > 0 else 0),
            "failure_rate": (self.metrics["failed"] / total if total > 0 else 0),
            "retry_rate": (self.metrics["retried"] / total if total > 0 else 0),
        }
