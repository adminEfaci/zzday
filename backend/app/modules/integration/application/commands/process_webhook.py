"""Process webhook command and handler.

This module provides the command and handler for processing incoming webhooks
with signature validation and rate limiting.
"""

import hashlib
import hmac
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import ApplicationError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import WebhookEventDTO
from app.modules.integration.domain.aggregates import WebhookEndpoint
from app.modules.integration.domain.entities import WebhookEvent
from app.modules.integration.domain.enums import WebhookMethod

logger = get_logger(__name__)


class ProcessWebhookCommand(Command):
    """Command to process incoming webhook."""

    def __init__(
        self,
        endpoint_id: UUID,
        method: WebhookMethod,
        headers: dict[str, str],
        body: dict[str, Any],
        query_params: dict[str, str] | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ):
        """Initialize process webhook command.

        Args:
            endpoint_id: ID of webhook endpoint
            method: HTTP method
            headers: Request headers
            body: Request body
            query_params: Query parameters
            source_ip: Source IP address
            user_agent: User agent string
        """
        super().__init__()

        self.endpoint_id = endpoint_id
        self.method = method
        self.headers = headers
        self.body = body
        self.query_params = query_params or {}
        self.source_ip = source_ip
        self.user_agent = user_agent

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not isinstance(self.method, WebhookMethod):
            raise ValidationError("method must be a WebhookMethod enum")

        if not isinstance(self.headers, dict):
            raise ValidationError("headers must be a dictionary")

        if not isinstance(self.body, dict):
            raise ValidationError("body must be a dictionary")


class ProcessWebhookCommandHandler(
    CommandHandler[ProcessWebhookCommand, WebhookEventDTO]
):
    """Handler for processing webhooks."""

    def __init__(
        self,
        webhook_endpoint_repository: Any,
        webhook_event_repository: Any,
        integration_repository: Any,
        rate_limiter: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            webhook_endpoint_repository: Repository for webhook endpoints
            webhook_event_repository: Repository for webhook events
            integration_repository: Repository for integrations
            rate_limiter: Rate limiting service
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._webhook_endpoint_repository = webhook_endpoint_repository
        self._webhook_event_repository = webhook_event_repository
        self._integration_repository = integration_repository
        self._rate_limiter = rate_limiter
        self._event_publisher = event_publisher

    async def handle(self, command: ProcessWebhookCommand) -> WebhookEventDTO:
        """Handle process webhook command.

        Args:
            command: Process webhook command

        Returns:
            WebhookEventDTO: Created webhook event

        Raises:
            NotFoundError: If endpoint not found
            ValidationError: If signature validation fails
            ApplicationError: If rate limit exceeded
        """
        logger.info(
            "Processing webhook",
            endpoint_id=command.endpoint_id,
            method=command.method.value,
            source_ip=command.source_ip,
        )

        # Get webhook endpoint
        endpoint = await self._webhook_endpoint_repository.get_by_id(
            command.endpoint_id
        )
        if not endpoint:
            raise NotFoundError(f"Webhook endpoint not found: {command.endpoint_id}")

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
        rate_limit_key = f"webhook:{endpoint.id}:{command.source_ip}"
        if not await self._rate_limiter.check_limit(
            rate_limit_key, endpoint.rate_limit
        ):
            logger.warning(
                "Webhook rate limit exceeded",
                endpoint_id=endpoint.id,
                source_ip=command.source_ip,
            )
            raise ApplicationError("Rate limit exceeded")

        # Validate signature if required
        signature_valid = True
        if endpoint.requires_signature:
            signature_valid = await self._validate_signature(
                endpoint=endpoint,
                method=command.method,
                headers=command.headers,
                body=command.body,
            )

            if not signature_valid:
                logger.warning(
                    "Webhook signature validation failed", endpoint_id=endpoint.id
                )
                # Still create event but mark as invalid

        # Create webhook event
        webhook_event = WebhookEvent(
            webhook_id=UUID.uuid4(),
            endpoint_id=endpoint.id,
            integration_id=integration.id,
            method=command.method,
            headers=command.headers,
            body=command.body,
            query_params=command.query_params,
            source_ip=command.source_ip,
            user_agent=command.user_agent,
            signature_valid=signature_valid,
            event_type=self._extract_event_type(command.headers, command.body),
            event_data=command.body,
        )

        # Save webhook event
        await self._webhook_event_repository.save(webhook_event)

        # Record webhook received
        endpoint.record_webhook_received(signature_valid)
        await self._webhook_endpoint_repository.save(endpoint)

        # Publish domain event
        await self._event_publisher.publish(
            WebhookReceivedEvent(
                webhook_id=webhook_event.id,
                integration_id=integration.id,
                event_type=webhook_event.event_type,
                payload=webhook_event.event_data,
                signature_valid=signature_valid,
                metadata=EventMetadata(
                    event_id=UUID.uuid4(),
                    aggregate_id=webhook_event.id,
                    aggregate_type="WebhookEvent",
                    event_type="WebhookReceivedEvent",
                    event_version=1,
                    occurred_at=datetime.utcnow(),
                    correlation_id=command.correlation_id,
                ),
            )
        )

        logger.info(
            "Webhook processed successfully",
            webhook_id=webhook_event.id,
            event_type=webhook_event.event_type,
            signature_valid=signature_valid,
        )

        return WebhookEventDTO.from_domain(webhook_event)

    async def _validate_signature(
        self,
        endpoint: WebhookEndpoint,
        method: WebhookMethod,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> bool:
        """Validate webhook signature.

        Args:
            endpoint: Webhook endpoint
            method: HTTP method
            headers: Request headers
            body: Request body

        Returns:
            bool: True if signature is valid
        """
        # Get signature from headers
        signature_header = endpoint.signature_header or "X-Webhook-Signature"
        provided_signature = headers.get(signature_header, "").lower()

        if not provided_signature:
            return False

        # Get signing secret
        signing_secret = endpoint.get_signing_secret()
        if not signing_secret:
            return False

        # Calculate expected signature
        import json

        payload = json.dumps(body, sort_keys=True)

        # Most webhooks use HMAC-SHA256
        expected_signature = hmac.new(
            signing_secret.encode(), payload.encode(), hashlib.sha256
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

    @property
    def command_type(self) -> type[ProcessWebhookCommand]:
        """Get command type this handler processes."""
        return ProcessWebhookCommand
