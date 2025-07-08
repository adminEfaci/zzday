"""Webhook endpoint aggregate for managing incoming webhooks.

This module provides the WebhookEndpoint aggregate that manages
webhook endpoints, validation, and event processing.
"""

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.entities import WebhookEvent
from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus
from app.modules.integration.domain.errors import WebhookValidationError
from app.modules.integration.domain.events import (
    WebhookEndpointActivated,
    WebhookEndpointDeactivated,
    WebhookFailed,
    WebhookProcessed,
    WebhookReceived,
    WebhookValidationFailed,
)
from app.modules.integration.domain.value_objects import WebhookSignature


class WebhookEndpoint(AggregateRoot):
    """Aggregate root for managing webhook endpoints.

    This class manages webhook endpoints for receiving events from
    external systems, including validation, deduplication, and processing.
    """

    def __init__(
        self,
        integration_id: UUID,
        name: str,
        path: str,
        signature_config: WebhookSignature | None = None,
        allowed_events: list[str] | None = None,
        allowed_methods: list[WebhookMethod] | None = None,
        allowed_ips: list[str] | None = None,
        is_active: bool = True,
        retry_policy: dict[str, Any] | None = None,
        deduplication_window_minutes: int = 60,
        entity_id: UUID | None = None,
    ):
        """Initialize webhook endpoint aggregate.

        Args:
            integration_id: ID of the integration
            name: Endpoint name
            path: URL path for the endpoint
            signature_config: Webhook signature configuration
            allowed_events: List of allowed event types
            allowed_methods: Allowed HTTP methods
            allowed_ips: Allowed source IPs (whitelist)
            is_active: Whether endpoint is active
            retry_policy: Retry configuration
            deduplication_window_minutes: Deduplication window
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.integration_id = integration_id
        self.name = self._validate_name(name)
        self.path = self._validate_path(path)

        # Security configuration
        self.signature_config = signature_config
        self.allowed_events = allowed_events or []
        self.allowed_methods = allowed_methods or [WebhookMethod.POST]
        self.allowed_ips = self._validate_ips(allowed_ips or [])
        self.secret_token = self._generate_secret_token()

        # State
        self.is_active = is_active
        self.retry_policy = retry_policy or self._default_retry_policy()
        self.deduplication_window_minutes = max(
            1, min(1440, deduplication_window_minutes)
        )

        # Statistics
        self.total_received = 0
        self.total_processed = 0
        self.total_failed = 0
        self.last_received_at: datetime | None = None

        # Deduplication tracking (in production, use external cache)
        self._recent_event_hashes: set[str] = set()
        self._hash_timestamps: dict[str, datetime] = {}

        # Child entities (webhook events managed separately)
        self._webhook_event_ids: list[UUID] = []

        # Validate state
        self._validate_aggregate()

    def _validate_name(self, name: str) -> str:
        """Validate endpoint name."""
        if not name or not name.strip():
            raise ValidationError("Endpoint name cannot be empty")

        name = name.strip()
        if len(name) > 100:
            raise ValidationError("Endpoint name cannot exceed 100 characters")

        return name

    def _validate_path(self, path: str) -> str:
        """Validate endpoint path."""
        if not path:
            raise ValidationError("Endpoint path cannot be empty")

        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Basic path validation
        if "//" in path:
            raise ValidationError("Path cannot contain double slashes")

        if " " in path:
            raise ValidationError("Path cannot contain spaces")

        return path

    def _validate_ips(self, ips: list[str]) -> list[str]:
        """Validate IP whitelist."""
        validated = []

        for ip in ips:
            # Basic IP validation (would be more comprehensive in production)
            if not ip:
                continue

            # Support CIDR notation
            if "/" in ip:
                parts = ip.split("/")
                if len(parts) != 2:
                    raise ValidationError(f"Invalid CIDR notation: {ip}")

                try:
                    prefix = int(parts[1])
                    if prefix < 0 or prefix > 32:
                        raise ValidationError(f"Invalid CIDR prefix: {prefix}")
                except ValueError:
                    raise ValidationError(f"Invalid CIDR prefix in: {ip}")

            validated.append(ip)

        return validated

    def _generate_secret_token(self) -> str:
        """Generate secure secret token."""
        return secrets.token_urlsafe(32)

    def _default_retry_policy(self) -> dict[str, Any]:
        """Get default retry policy."""
        return {
            "max_retries": 3,
            "initial_delay_seconds": 60,
            "backoff_factor": 2,
            "max_delay_seconds": 3600,
        }

    def _validate_aggregate(self) -> None:
        """Validate aggregate state."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if self.signature_config and not isinstance(
            self.signature_config, WebhookSignature
        ):
            raise ValidationError(
                "signature_config must be a WebhookSignature instance"
            )

        for method in self.allowed_methods:
            if not isinstance(method, WebhookMethod):
                raise ValidationError("All allowed_methods must be WebhookMethod enums")

    @property
    def endpoint_url(self) -> str:
        """Get the full endpoint URL path."""
        # In production, this would include the base URL
        return f"/webhooks/{self.integration_id}{self.path}"

    @property
    def success_rate(self) -> float:
        """Calculate webhook processing success rate."""
        total_attempts = self.total_processed + self.total_failed
        if total_attempts == 0:
            return 1.0
        return self.total_processed / total_attempts

    @property
    def requires_signature(self) -> bool:
        """Check if endpoint requires signature validation."""
        return self.signature_config is not None

    def receive_webhook(
        self,
        method: WebhookMethod,
        headers: dict[str, str],
        payload: dict[str, Any],
        source_ip: str,
        raw_body: bytes,
    ) -> WebhookEvent:
        """Receive and validate a webhook.

        Args:
            method: HTTP method
            headers: Request headers
            payload: Parsed payload
            source_ip: Source IP address
            raw_body: Raw request body for signature validation

        Returns:
            WebhookEvent: Created webhook event

        Raises:
            WebhookValidationError: If validation fails
            DomainError: If endpoint is not active
        """
        if not self.is_active:
            raise DomainError("Webhook endpoint is not active")

        # Validate method
        if method not in self.allowed_methods:
            self._record_validation_failure(
                source_ip, f"Method {method.value} not allowed", headers
            )
            raise WebhookValidationError(reason=f"Method {method.value} not allowed")

        # Validate source IP
        if self.allowed_ips and not self._is_ip_allowed(source_ip):
            self._record_validation_failure(
                source_ip, f"IP {source_ip} not whitelisted", headers
            )
            raise WebhookValidationError(reason=f"IP {source_ip} not allowed")

        # Extract event type
        event_type = self._extract_event_type(headers, payload)

        # Validate event type
        if self.allowed_events and event_type not in self.allowed_events:
            self._record_validation_failure(
                source_ip, f"Event type {event_type} not allowed", headers
            )
            raise WebhookValidationError(reason=f"Event type {event_type} not allowed")

        # Validate signature
        signature_valid = True
        signature = None

        if self.requires_signature:
            signature_valid = self.signature_config.validate_signature(
                payload=raw_body,
                received_signature=headers.get(self.signature_config.header_name, ""),
                headers=headers,
            )

            if not signature_valid:
                self._record_validation_failure(
                    source_ip, "Invalid webhook signature", headers
                )
                raise WebhookValidationError(reason="Invalid webhook signature")

            signature = headers.get(self.signature_config.header_name)

        # Create webhook event
        webhook_event = WebhookEvent(
            endpoint_id=self.id,
            integration_id=self.integration_id,
            event_type=event_type,
            payload=payload,
            headers=headers,
            method=method,
            source_ip=source_ip,
            signature=signature,
            is_valid_signature=signature_valid,
            status=WebhookStatus.PENDING,
            max_retries=self.retry_policy["max_retries"],
        )

        # Check for duplicates
        if self._is_duplicate(webhook_event):
            raise WebhookValidationError(
                webhook_id=webhook_event.id, reason="Duplicate webhook detected"
            )

        # Record the webhook
        self._record_webhook(webhook_event)

        # Emit event
        self.add_event(
            WebhookReceived(
                webhook_id=webhook_event.id,
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                event_type=event_type,
                method=method,
                headers=webhook_event.headers,  # Already sanitized
                payload=payload,
                source_ip=source_ip,
                signature_valid=signature_valid,
                received_at=webhook_event.received_at,
            )
        )

        return webhook_event

    def process_webhook_success(
        self,
        webhook_id: UUID,
        processing_time_ms: float,
        actions_taken: list[str],
        entities_affected: dict[str, list[str]],
    ) -> None:
        """Record successful webhook processing.

        Args:
            webhook_id: ID of the webhook event
            processing_time_ms: Processing time
            actions_taken: List of actions performed
            entities_affected: Entities affected by processing
        """
        if webhook_id not in self._webhook_event_ids:
            raise DomainError("Webhook event not associated with this endpoint")

        self.total_processed += 1
        self.mark_modified()

        # Emit event
        self.add_event(
            WebhookProcessed(
                webhook_id=webhook_id,
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                processing_time_ms=processing_time_ms,
                actions_taken=actions_taken,
                entities_affected=entities_affected,
                processed_at=datetime.now(UTC),
            )
        )

    def process_webhook_failure(
        self,
        webhook_id: UUID,
        error_type: str,
        error_message: str,
        retry_count: int,
        will_retry: bool,
    ) -> None:
        """Record webhook processing failure.

        Args:
            webhook_id: ID of the webhook event
            error_type: Type of error
            error_message: Error message
            retry_count: Current retry count
            will_retry: Whether it will be retried
        """
        if webhook_id not in self._webhook_event_ids:
            raise DomainError("Webhook event not associated with this endpoint")

        self.total_failed += 1
        self.mark_modified()

        # Emit event
        self.add_event(
            WebhookFailed(
                webhook_id=webhook_id,
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                error_type=error_type,
                error_message=error_message,
                retry_count=retry_count,
                will_retry=will_retry,
                failed_at=datetime.now(UTC),
            )
        )

    def activate(self, user_id: UUID) -> None:
        """Activate the webhook endpoint.

        Args:
            user_id: User activating the endpoint
        """
        if self.is_active:
            return

        self.is_active = True
        self.mark_modified()

        # Emit event
        self.add_event(
            WebhookEndpointActivated(
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                endpoint_url=self.endpoint_url,
                activated_by=user_id,
            )
        )

    def deactivate(self, user_id: UUID, reason: str | None = None) -> None:
        """Deactivate the webhook endpoint.

        Args:
            user_id: User deactivating the endpoint
            reason: Optional deactivation reason
        """
        if not self.is_active:
            return

        self.is_active = False
        self.mark_modified()

        # Emit event
        self.add_event(
            WebhookEndpointDeactivated(
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                deactivated_by=user_id,
                reason=reason,
            )
        )

    def update_signature_config(
        self, signature_config: WebhookSignature | None
    ) -> None:
        """Update signature configuration.

        Args:
            signature_config: New signature configuration (None to disable)
        """
        self.signature_config = signature_config
        self.mark_modified()

    def update_allowed_events(self, allowed_events: list[str]) -> None:
        """Update allowed event types.

        Args:
            allowed_events: New list of allowed events
        """
        self.allowed_events = allowed_events
        self.mark_modified()

    def update_allowed_ips(self, allowed_ips: list[str]) -> None:
        """Update IP whitelist.

        Args:
            allowed_ips: New list of allowed IPs
        """
        self.allowed_ips = self._validate_ips(allowed_ips)
        self.mark_modified()

    def regenerate_secret(self) -> str:
        """Regenerate the secret token.

        Returns:
            str: New secret token
        """
        self.secret_token = self._generate_secret_token()
        self.mark_modified()
        return self.secret_token

    def _extract_event_type(
        self, headers: dict[str, str], payload: dict[str, Any]
    ) -> str:
        """Extract event type from webhook.

        Args:
            headers: Request headers
            payload: Request payload

        Returns:
            str: Event type
        """
        # Try common header names
        event_type_headers = [
            "x-event-type",
            "x-webhook-event",
            "x-github-event",
            "x-stripe-event",
            "x-hook-event",
        ]

        for header in event_type_headers:
            if header in headers:
                return headers[header]
            # Case-insensitive check
            for key, value in headers.items():
                if key.lower() == header:
                    return value

        # Try payload
        if "event_type" in payload:
            return payload["event_type"]
        if "type" in payload:
            return payload["type"]
        if "event" in payload:
            return payload["event"]

        # Default
        return "webhook"

    def _is_ip_allowed(self, source_ip: str) -> bool:
        """Check if source IP is allowed.

        Args:
            source_ip: Source IP to check

        Returns:
            bool: True if allowed
        """
        if not self.allowed_ips:
            return True

        # Simple check - in production would use proper IP/CIDR matching
        for allowed_ip in self.allowed_ips:
            if allowed_ip == source_ip:
                return True

            # Basic CIDR support
            if "/" in allowed_ip:
                # Simplified - real implementation would properly check CIDR
                network = allowed_ip.split("/")[0]
                if source_ip.startswith(network.rsplit(".", 1)[0]):
                    return True

        return False

    def _is_duplicate(self, webhook_event: WebhookEvent) -> bool:
        """Check if webhook is a duplicate.

        Args:
            webhook_event: Webhook event to check

        Returns:
            bool: True if duplicate
        """
        # Clean old hashes
        self._clean_old_hashes()

        event_hash = webhook_event.event_hash

        if event_hash in self._recent_event_hashes:
            return True

        # Add to tracking
        self._recent_event_hashes.add(event_hash)
        self._hash_timestamps[event_hash] = datetime.now(UTC)

        return False

    def _clean_old_hashes(self) -> None:
        """Clean old event hashes outside deduplication window."""
        cutoff = datetime.now(UTC) - timedelta(
            minutes=self.deduplication_window_minutes
        )

        expired_hashes = []
        for hash_value, timestamp in self._hash_timestamps.items():
            if timestamp < cutoff:
                expired_hashes.append(hash_value)

        for hash_value in expired_hashes:
            self._recent_event_hashes.discard(hash_value)
            del self._hash_timestamps[hash_value]

    def _record_webhook(self, webhook_event: WebhookEvent) -> None:
        """Record a received webhook.

        Args:
            webhook_event: Webhook event to record
        """
        self.total_received += 1
        self.last_received_at = webhook_event.received_at
        self._webhook_event_ids.append(webhook_event.id)
        self.mark_modified()

    def _record_validation_failure(
        self, source_ip: str, reason: str, headers: dict[str, str]
    ) -> None:
        """Record a validation failure.

        Args:
            source_ip: Source IP
            reason: Failure reason
            headers: Request headers
        """
        # Emit validation failure event
        self.add_event(
            WebhookValidationFailed(
                endpoint_id=self.id,
                integration_id=self.integration_id,
                integration_name=self.name,
                source_ip=source_ip,
                reason=reason,
                headers_received=self._sanitize_headers_for_event(headers),
                attempted_at=datetime.now(UTC),
            )
        )

    def _sanitize_headers_for_event(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize headers for events."""
        # Remove sensitive headers
        sensitive = {"authorization", "x-api-key", "cookie"}
        sanitized = {}

        for key, value in headers.items():
            if key.lower() in sensitive:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add webhook endpoint specific fields
        data.update(
            {
                "integration_id": str(self.integration_id),
                "name": self.name,
                "path": self.path,
                "endpoint_url": self.endpoint_url,
                "has_signature_config": self.signature_config is not None,
                "signature_algorithm": self.signature_config.algorithm
                if self.signature_config
                else None,
                "allowed_events": self.allowed_events,
                "allowed_methods": [m.value for m in self.allowed_methods],
                "allowed_ips": self.allowed_ips,
                "is_active": self.is_active,
                "retry_policy": self.retry_policy,
                "deduplication_window_minutes": self.deduplication_window_minutes,
                "total_received": self.total_received,
                "total_processed": self.total_processed,
                "total_failed": self.total_failed,
                "success_rate": round(self.success_rate, 3),
                "last_received_at": self.last_received_at.isoformat()
                if self.last_received_at
                else None,
                "webhook_count": len(self._webhook_event_ids),
            }
        )

        return data

    def __str__(self) -> str:
        """String representation."""
        status = "active" if self.is_active else "inactive"
        return f"WebhookEndpoint({self.name}, {self.endpoint_url}, {status})"
