"""Webhook DTOs for application layer.

This module provides data transfer objects for webhook data,
ensuring clean interfaces for webhook processing.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus


@dataclass(frozen=True)
class WebhookPayloadDTO:
    """DTO for webhook payload data."""

    webhook_id: UUID
    integration_id: UUID
    endpoint_id: UUID
    method: WebhookMethod
    headers: dict[str, str]
    body: dict[str, Any]
    query_params: dict[str, str]
    signature: str | None
    timestamp: datetime
    source_ip: str
    user_agent: str | None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "webhook_id": str(self.webhook_id),
            "integration_id": str(self.integration_id),
            "endpoint_id": str(self.endpoint_id),
            "method": self.method.value,
            "headers": self.headers,
            "body": self.body,
            "query_params": self.query_params,
            "signature": self.signature,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
        }

    def get_signature_data(self) -> str:
        """Get data for signature validation."""
        # Concatenate method, timestamp, and body for signature
        import json

        body_str = json.dumps(self.body, sort_keys=True)
        return f"{self.method.value}:{self.timestamp.isoformat()}:{body_str}"


@dataclass(frozen=True)
class WebhookEventDTO:
    """DTO for webhook event data."""

    event_id: UUID
    webhook_id: UUID
    integration_id: UUID
    event_type: str
    event_data: dict[str, Any]
    status: WebhookStatus
    attempts: int
    last_attempt_at: datetime | None
    next_retry_at: datetime | None
    error_message: str | None
    processed_at: datetime | None
    created_at: datetime

    @classmethod
    def from_domain(cls, webhook_event: Any) -> "WebhookEventDTO":
        """Create DTO from domain model."""
        return cls(
            event_id=webhook_event.id,
            webhook_id=webhook_event.webhook_id,
            integration_id=webhook_event.integration_id,
            event_type=webhook_event.event_type,
            event_data=webhook_event.event_data,
            status=webhook_event.status,
            attempts=webhook_event.attempts,
            last_attempt_at=webhook_event.last_attempt_at,
            next_retry_at=webhook_event.next_retry_at,
            error_message=webhook_event.error_message,
            processed_at=webhook_event.processed_at,
            created_at=webhook_event.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": str(self.event_id),
            "webhook_id": str(self.webhook_id),
            "integration_id": str(self.integration_id),
            "event_type": self.event_type,
            "event_data": self.event_data,
            "status": self.status.value,
            "attempts": self.attempts,
            "last_attempt_at": self.last_attempt_at.isoformat()
            if self.last_attempt_at
            else None,
            "next_retry_at": self.next_retry_at.isoformat()
            if self.next_retry_at
            else None,
            "error_message": self.error_message,
            "processed_at": self.processed_at.isoformat()
            if self.processed_at
            else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class WebhookHistoryDTO:
    """DTO for webhook history data."""

    total_webhooks: int
    successful_webhooks: int
    failed_webhooks: int
    pending_webhooks: int
    average_processing_time_ms: float
    webhooks_last_24h: int
    webhooks_last_7d: int
    recent_events: list[WebhookEventDTO]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_webhooks": self.total_webhooks,
            "successful_webhooks": self.successful_webhooks,
            "failed_webhooks": self.failed_webhooks,
            "pending_webhooks": self.pending_webhooks,
            "average_processing_time_ms": self.average_processing_time_ms,
            "webhooks_last_24h": self.webhooks_last_24h,
            "webhooks_last_7d": self.webhooks_last_7d,
            "recent_events": [event.to_dict() for event in self.recent_events],
        }
