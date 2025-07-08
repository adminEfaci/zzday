"""Webhook event entity for tracking received webhooks.

This module provides a comprehensive webhook event entity for managing
the lifecycle of webhook events from receipt to processing.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus


class WebhookEvent(Entity):
    """Entity representing a received webhook event.

    This class manages webhook events from external systems,
    including validation, processing, and retry handling.
    """

    def __init__(
        self,
        endpoint_id: UUID,
        integration_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        method: WebhookMethod,
        source_ip: str,
        signature: str | None = None,
        is_valid_signature: bool = False,
        status: WebhookStatus = WebhookStatus.PENDING,
        retry_count: int = 0,
        max_retries: int = 3,
        processing_errors: list[dict[str, Any]] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize webhook event entity.

        Args:
            endpoint_id: ID of the webhook endpoint
            integration_id: ID of the integration
            event_type: Type of webhook event
            payload: Event payload
            headers: Request headers
            method: HTTP method
            source_ip: Source IP address
            signature: Webhook signature
            is_valid_signature: Whether signature is valid
            status: Current status
            retry_count: Number of retry attempts
            max_retries: Maximum retry attempts
            processing_errors: List of processing errors
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.endpoint_id = endpoint_id
        self.integration_id = integration_id
        self.event_type = self._validate_event_type(event_type)
        self.payload = self._validate_payload(payload)
        self.headers = self._sanitize_headers(headers)

        # Request details
        self.method = method
        self.source_ip = self._validate_ip(source_ip)
        self.signature = signature
        self.is_valid_signature = is_valid_signature

        # Processing state
        self.status = status
        self.retry_count = max(0, retry_count)
        self.max_retries = max(0, max_retries)
        self.processing_errors = processing_errors or []

        # Timestamps
        self.received_at = datetime.now(UTC)
        self.processed_at: datetime | None = None
        self.next_retry_at: datetime | None = None

        # Generate event hash for deduplication
        self._event_hash = self._generate_event_hash()

        # Validate state
        self._validate_entity()

    def _validate_event_type(self, event_type: str) -> str:
        """Validate event type."""
        if not event_type or not event_type.strip():
            raise ValidationError("Event type cannot be empty")

        event_type = event_type.strip()
        if len(event_type) > 100:
            raise ValidationError("Event type cannot exceed 100 characters")

        return event_type

    def _validate_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate and limit payload size."""
        if not isinstance(payload, dict):
            raise ValidationError("Payload must be a dictionary")

        # Check payload size (simplified - real implementation would be more sophisticated)
        payload_str = json.dumps(payload)
        if len(payload_str) > 1_000_000:  # 1MB limit
            raise ValidationError("Payload size exceeds 1MB limit")

        return payload

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize headers, removing sensitive information."""
        if not isinstance(headers, dict):
            raise ValidationError("Headers must be a dictionary")

        # Headers to exclude for security
        sensitive_headers = {
            "authorization",
            "x-api-key",
            "cookie",
            "set-cookie",
            "x-auth-token",
            "x-secret-key",
        }

        sanitized = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in sensitive_headers:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def _validate_ip(self, ip: str) -> str:
        """Validate IP address format."""
        if not ip:
            raise ValidationError("Source IP cannot be empty")

        # Basic IP validation (v4 or v6)
        parts = ip.split(".")
        if len(parts) == 4:
            # IPv4
            try:
                for part in parts:
                    num = int(part)
                    if num < 0 or num > 255:
                        raise ValueError()
            except ValueError:
                raise ValidationError(f"Invalid IPv4 address: {ip}")
        elif ":" in ip:
            # IPv6 - basic check
            if len(ip) > 45:  # Max IPv6 length
                raise ValidationError(f"Invalid IPv6 address: {ip}")
        else:
            raise ValidationError(f"Invalid IP address format: {ip}")

        return ip

    def _generate_event_hash(self) -> str:
        """Generate hash for event deduplication."""
        # Create hash from stable event properties
        hash_data = {
            "endpoint_id": str(self.endpoint_id),
            "event_type": self.event_type,
            "payload": json.dumps(self.payload, sort_keys=True),
            "received_at": self.received_at.isoformat(),
        }

        hash_str = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_str.encode()).hexdigest()

    def _validate_entity(self) -> None:
        """Validate entity state."""
        super()._validate_entity()

        if not self.endpoint_id:
            raise ValidationError("endpoint_id is required")

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not isinstance(self.method, WebhookMethod):
            raise ValidationError("method must be a WebhookMethod enum")

        if not isinstance(self.status, WebhookStatus):
            raise ValidationError("status must be a WebhookStatus enum")

    @property
    def event_hash(self) -> str:
        """Get event hash for deduplication."""
        return self._event_hash

    @property
    def is_processed(self) -> bool:
        """Check if event has been processed."""
        return self.status == WebhookStatus.PROCESSED

    @property
    def is_failed(self) -> bool:
        """Check if event processing failed."""
        return self.status == WebhookStatus.FAILED

    @property
    def can_retry(self) -> bool:
        """Check if event can be retried."""
        return (
            self.status == WebhookStatus.FAILED
            and self.retry_count < self.max_retries
            and self.is_valid_signature
        )

    @property
    def processing_time(self) -> timedelta | None:
        """Get processing time if processed."""
        if not self.processed_at:
            return None
        return self.processed_at - self.received_at

    @property
    def age(self) -> timedelta:
        """Get age of the event."""
        return datetime.now(UTC) - self.received_at

    @property
    def is_expired(self, max_age_hours: int = 24) -> bool:
        """Check if event is too old to process."""
        return self.age > timedelta(hours=max_age_hours)

    def start_processing(self) -> None:
        """Mark event as being processed.

        Raises:
            DomainError: If event cannot be processed
        """
        if self.status == WebhookStatus.PROCESSING:
            raise DomainError("Event is already being processed")

        if self.status == WebhookStatus.PROCESSED:
            raise DomainError("Event has already been processed")

        if not self.is_valid_signature:
            raise DomainError("Cannot process event with invalid signature")

        if self.is_expired():
            raise DomainError("Event is too old to process")

        self.status = WebhookStatus.PROCESSING
        self.mark_modified()

    def complete_processing(self, result: dict[str, Any] | None = None) -> None:
        """Mark event as successfully processed.

        Args:
            result: Optional processing result

        Raises:
            DomainError: If event is not being processed
        """
        if self.status != WebhookStatus.PROCESSING:
            raise DomainError("Event must be in processing state to complete")

        self.status = WebhookStatus.PROCESSED
        self.processed_at = datetime.now(UTC)

        if result:
            self.payload["_processing_result"] = result

        self.mark_modified()

    def fail_processing(
        self, error: str, error_details: dict[str, Any] | None = None
    ) -> None:
        """Mark event as failed.

        Args:
            error: Error message
            error_details: Optional error details

        Raises:
            DomainError: If event is not being processed
        """
        if self.status != WebhookStatus.PROCESSING:
            raise DomainError("Event must be in processing state to fail")

        self.status = WebhookStatus.FAILED
        self.processed_at = datetime.now(UTC)

        # Record error
        error_record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "attempt": self.retry_count + 1,
            "error": error,
            "details": error_details or {},
        }
        self.processing_errors.append(error_record)

        # Calculate next retry time with exponential backoff
        if self.can_retry:
            backoff_seconds = min(300, 30 * (2**self.retry_count))  # Max 5 minutes
            self.next_retry_at = datetime.now(UTC) + timedelta(seconds=backoff_seconds)

        self.mark_modified()

    def retry(self) -> None:
        """Prepare event for retry.

        Raises:
            DomainError: If event cannot be retried
        """
        if not self.can_retry:
            raise DomainError("Event cannot be retried")

        if self.next_retry_at and datetime.now(UTC) < self.next_retry_at:
            raise DomainError("Retry time has not been reached")

        self.status = WebhookStatus.PENDING
        self.retry_count += 1
        self.next_retry_at = None
        self.mark_modified()

    def add_processing_note(
        self, note: str, details: dict[str, Any] | None = None
    ) -> None:
        """Add a processing note.

        Args:
            note: Note text
            details: Optional additional details
        """
        if "_processing_notes" not in self.payload:
            self.payload["_processing_notes"] = []

        self.payload["_processing_notes"].append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "note": note,
                "details": details or {},
            }
        )

        self.mark_modified()

    def get_header(self, name: str, default: str | None = None) -> str | None:
        """Get header value (case-insensitive).

        Args:
            name: Header name
            default: Default value if not found

        Returns:
            Header value or default
        """
        # Case-insensitive header lookup
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return default

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add webhook event specific fields
        data.update(
            {
                "endpoint_id": str(self.endpoint_id),
                "integration_id": str(self.integration_id),
                "event_type": self.event_type,
                "payload": self.payload,
                "headers": self.headers,
                "method": self.method.value,
                "source_ip": self.source_ip,
                "has_signature": bool(self.signature),
                "is_valid_signature": self.is_valid_signature,
                "status": self.status.value,
                "retry_count": self.retry_count,
                "max_retries": self.max_retries,
                "processing_errors": self.processing_errors,
                "received_at": self.received_at.isoformat(),
                "processed_at": self.processed_at.isoformat()
                if self.processed_at
                else None,
                "next_retry_at": self.next_retry_at.isoformat()
                if self.next_retry_at
                else None,
                "event_hash": self.event_hash,
                "is_processed": self.is_processed,
                "is_failed": self.is_failed,
                "can_retry": self.can_retry,
                "age_seconds": int(self.age.total_seconds()),
                "processing_time_seconds": int(self.processing_time.total_seconds())
                if self.processing_time
                else None,
            }
        )

        return data

    def __str__(self) -> str:
        """String representation."""
        return f"WebhookEvent({self.event_type}, {self.status.value}, retry={self.retry_count}/{self.max_retries})"
