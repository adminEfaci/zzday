"""Webhook-related domain events.

This module provides domain events for webhook processing,
including receipt, validation, and processing tracking.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent, EventMetadata
from app.modules.integration.domain.enums import WebhookMethod


class WebhookReceived(DomainEvent):
    """Event raised when a webhook is received from an external system."""

    def __init__(
        self,
        webhook_id: UUID,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        event_type: str,
        method: WebhookMethod,
        headers: dict[str, str],
        payload: dict[str, Any],
        source_ip: str,
        signature_valid: bool,
        received_at: datetime,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook received event.

        Args:
            webhook_id: ID of the webhook event
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            event_type: Type of webhook event from external system
            method: HTTP method used
            headers: Request headers (sanitized)
            payload: Webhook payload
            source_ip: Source IP address
            signature_valid: Whether signature was valid
            received_at: When webhook was received
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.webhook_id = webhook_id
        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.webhook_event_type = event_type  # Renamed to avoid conflict
        self.method = method
        self.headers = headers
        self.payload = payload
        self.source_ip = source_ip
        self.signature_valid = signature_valid
        self.received_at = received_at

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = webhook_id
            self.metadata.aggregate_type = "WebhookEvent"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.webhook_id:
            raise ValidationError("webhook_id is required")

        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.webhook_event_type:
            raise ValidationError("event_type is required")

        if not isinstance(self.method, WebhookMethod):
            raise ValidationError("method must be a WebhookMethod enum")

        if not isinstance(self.headers, dict):
            raise ValidationError("headers must be a dictionary")

        if not isinstance(self.payload, dict):
            raise ValidationError("payload must be a dictionary")

        if not self.source_ip:
            raise ValidationError("source_ip is required")

        if not isinstance(self.received_at, datetime):
            raise ValidationError("received_at must be a datetime")


class WebhookProcessed(DomainEvent):
    """Event raised when a webhook has been successfully processed."""

    def __init__(
        self,
        webhook_id: UUID,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        processing_time_ms: float,
        actions_taken: list[str],
        entities_affected: dict[str, list[str]],
        processed_at: datetime,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook processed event.

        Args:
            webhook_id: ID of the webhook event
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            processing_time_ms: Processing time in milliseconds
            actions_taken: List of actions performed
            entities_affected: Entities affected by processing
            processed_at: When processing completed
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.webhook_id = webhook_id
        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.processing_time_ms = processing_time_ms
        self.actions_taken = actions_taken
        self.entities_affected = entities_affected
        self.processed_at = processed_at

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = webhook_id
            self.metadata.aggregate_type = "WebhookEvent"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.webhook_id:
            raise ValidationError("webhook_id is required")

        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if self.processing_time_ms < 0:
            raise ValidationError("processing_time_ms cannot be negative")

        if not isinstance(self.actions_taken, list):
            raise ValidationError("actions_taken must be a list")

        if not isinstance(self.entities_affected, dict):
            raise ValidationError("entities_affected must be a dictionary")

        if not isinstance(self.processed_at, datetime):
            raise ValidationError("processed_at must be a datetime")


class WebhookFailed(DomainEvent):
    """Event raised when webhook processing fails."""

    def __init__(
        self,
        webhook_id: UUID,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        error_type: str,
        error_message: str,
        retry_count: int,
        will_retry: bool,
        failed_at: datetime,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook failed event.

        Args:
            webhook_id: ID of the webhook event
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            error_type: Type of error
            error_message: Error message
            retry_count: Number of retry attempts
            will_retry: Whether it will be retried
            failed_at: When processing failed
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.webhook_id = webhook_id
        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.error_type = error_type
        self.error_message = error_message
        self.retry_count = retry_count
        self.will_retry = will_retry
        self.failed_at = failed_at

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = webhook_id
            self.metadata.aggregate_type = "WebhookEvent"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.webhook_id:
            raise ValidationError("webhook_id is required")

        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.error_type:
            raise ValidationError("error_type is required")

        if not self.error_message:
            raise ValidationError("error_message is required")

        if self.retry_count < 0:
            raise ValidationError("retry_count cannot be negative")

        if not isinstance(self.failed_at, datetime):
            raise ValidationError("failed_at must be a datetime")


class WebhookValidationFailed(DomainEvent):
    """Event raised when webhook signature validation fails."""

    def __init__(
        self,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        source_ip: str,
        reason: str,
        headers_received: dict[str, str],
        attempted_at: datetime,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook validation failed event.

        Args:
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            source_ip: Source IP address
            reason: Reason for validation failure
            headers_received: Headers received (sanitized)
            attempted_at: When validation was attempted
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.source_ip = source_ip
        self.reason = reason
        self.headers_received = headers_received
        self.attempted_at = attempted_at

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = endpoint_id
            self.metadata.aggregate_type = "WebhookEndpoint"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.source_ip:
            raise ValidationError("source_ip is required")

        if not self.reason:
            raise ValidationError("reason is required")

        if not isinstance(self.headers_received, dict):
            raise ValidationError("headers_received must be a dictionary")

        if not isinstance(self.attempted_at, datetime):
            raise ValidationError("attempted_at must be a datetime")


class WebhookEndpointActivated(DomainEvent):
    """Event raised when a webhook endpoint is activated."""

    def __init__(
        self,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        endpoint_url: str,
        activated_by: UUID,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook endpoint activated event.

        Args:
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            endpoint_url: URL of the endpoint
            activated_by: User who activated the endpoint
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.endpoint_url = endpoint_url
        self.activated_by = activated_by

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = endpoint_id
            self.metadata.aggregate_type = "WebhookEndpoint"
            self.metadata.user_id = activated_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.endpoint_url:
            raise ValidationError("endpoint_url is required")

        if not self.activated_by:
            raise ValidationError("activated_by is required")


class WebhookEndpointDeactivated(DomainEvent):
    """Event raised when a webhook endpoint is deactivated."""

    def __init__(
        self,
        endpoint_id: UUID,
        integration_id: UUID,
        integration_name: str,
        deactivated_by: UUID,
        reason: str | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize webhook endpoint deactivated event.

        Args:
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            integration_name: Name of the integration
            deactivated_by: User who deactivated the endpoint
            reason: Optional reason for deactivation
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.deactivated_by = deactivated_by
        self.reason = reason

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = endpoint_id
            self.metadata.aggregate_type = "WebhookEndpoint"
            self.metadata.user_id = deactivated_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.deactivated_by:
            raise ValidationError("deactivated_by is required")
