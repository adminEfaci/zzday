"""GraphQL types for Webhook entities.

This module provides GraphQL type definitions for webhook management,
including endpoints, events, payloads, and monitoring.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import (
    ErrorSeverityEnum,
    WebhookEventTypeEnum,
    WebhookMethodEnum,
    WebhookStatusEnum,
)


@strawberry.type
class WebhookHeader:
    """GraphQL type for webhook headers."""

    name: str
    value: str
    is_sensitive: bool = False


@strawberry.type
class WebhookRetryPolicy:
    """GraphQL type for webhook retry policy."""

    max_attempts: int = 3
    initial_delay_seconds: int = 1
    max_delay_seconds: int = 300
    backoff_multiplier: float = 2.0
    retry_on_status_codes: list[int] = strawberry.field(
        default_factory=lambda: [500, 502, 503, 504]
    )


@strawberry.type
class WebhookSecurity:
    """GraphQL type for webhook security configuration."""

    # Signature validation
    signature_enabled: bool = False
    signature_header: str = "X-Webhook-Signature"
    signature_algorithm: str = "sha256"

    # IP allowlist
    ip_allowlist_enabled: bool = False
    allowed_ips: list[str] = strawberry.field(default_factory=list)

    # SSL verification
    verify_ssl: bool = True

    # Authentication
    auth_enabled: bool = False
    auth_type: str = "bearer"  # "bearer", "basic", "api_key"
    auth_header: str = "Authorization"


@strawberry.type
class WebhookEndpoint:
    """GraphQL type for webhook endpoints."""

    endpoint_id: UUID
    integration_id: UUID
    name: str
    url: str
    method: WebhookMethodEnum

    # Configuration
    is_active: bool
    description: str | None = None

    # Headers
    headers: list[WebhookHeader] = strawberry.field(default_factory=list)

    # Security
    security: WebhookSecurity

    # Retry policy
    retry_policy: WebhookRetryPolicy

    # Event filtering
    event_types: list[WebhookEventTypeEnum] = strawberry.field(default_factory=list)
    event_filters: dict[str, Any] = strawberry.field(default_factory=dict)

    # Monitoring
    last_triggered: datetime | None = None
    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0

    # Timestamps
    created_at: datetime
    updated_at: datetime


@strawberry.type
class WebhookPayload:
    """GraphQL type for webhook payloads."""

    # Payload structure
    data: dict[str, Any] = strawberry.field(default_factory=dict)
    metadata: dict[str, Any] = strawberry.field(default_factory=dict)

    # Event information
    event_id: UUID
    event_type: WebhookEventTypeEnum
    event_timestamp: datetime

    # Source information
    source_integration_id: UUID
    source_system: str

    # Payload metadata
    content_type: str = "application/json"
    encoding: str = "utf-8"
    size_bytes: int = 0

    # Validation
    schema_version: str = "1.0"
    is_valid: bool = True
    validation_errors: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class WebhookDeliveryAttempt:
    """GraphQL type for webhook delivery attempts."""

    attempt_id: UUID
    attempt_number: int

    # Request details
    url: str
    method: str
    headers: dict[str, str] = strawberry.field(default_factory=dict)
    body_size: int = 0

    # Response details
    response_status: int | None = None
    response_headers: dict[str, str] = strawberry.field(default_factory=dict)
    response_body: str | None = None
    response_time_ms: int | None = None

    # Status
    status: WebhookStatusEnum
    error_message: str | None = None

    # Timestamps
    started_at: datetime
    completed_at: datetime | None = None

    # Retry information
    will_retry: bool = False
    next_retry_at: datetime | None = None


@strawberry.type
class WebhookEvent:
    """GraphQL type for webhook events."""

    event_id: UUID
    integration_id: UUID
    endpoint_id: UUID

    # Event details
    event_type: WebhookEventTypeEnum
    event_name: str
    description: str | None = None

    # Status
    status: WebhookStatusEnum
    priority: str = "normal"  # "low", "normal", "high", "critical"

    # Payload
    payload: WebhookPayload

    # Delivery
    delivery_attempts: list[WebhookDeliveryAttempt] = strawberry.field(
        default_factory=list
    )

    # Metrics
    total_attempts: int = 0
    successful_delivery: bool = False
    final_status_code: int | None = None
    total_processing_time_ms: int = 0

    # Timestamps
    triggered_at: datetime
    first_attempt_at: datetime | None = None
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None

    # Context
    context: dict[str, Any] = strawberry.field(default_factory=dict)

    @strawberry.field
    def is_terminal(self) -> bool:
        """Check if event is in terminal status."""
        return self.status in [WebhookStatusEnum.PROCESSED, WebhookStatusEnum.FAILED]

    @strawberry.field
    def delivery_success_rate(self) -> float:
        """Calculate delivery success rate for this event."""
        if self.total_attempts == 0:
            return 0.0

        successful_attempts = sum(
            1
            for attempt in self.delivery_attempts
            if attempt.response_status and 200 <= attempt.response_status < 300
        )

        return (successful_attempts / self.total_attempts) * 100


@strawberry.type
class WebhookStatistics:
    """GraphQL type for webhook statistics."""

    integration_id: UUID
    endpoint_id: UUID | None = None
    period_start: datetime
    period_end: datetime

    # Event statistics
    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0
    pending_events: int = 0

    # Delivery statistics
    total_attempts: int = 0
    successful_deliveries: int = 0
    failed_deliveries: int = 0
    retry_attempts: int = 0

    # Performance statistics
    average_delivery_time_ms: float = 0.0
    median_delivery_time_ms: float = 0.0
    p95_delivery_time_ms: float = 0.0

    # Error statistics
    error_rate: float = 0.0
    most_common_errors: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Success rate
    delivery_success_rate: float = 0.0
    event_success_rate: float = 0.0


@strawberry.type
class WebhookType:
    """GraphQL type for Webhook management."""

    integration_id: UUID

    # Endpoints
    endpoints: list[WebhookEndpoint] = strawberry.field(default_factory=list)
    active_endpoints: int = 0

    # Recent events
    recent_events: list[WebhookEvent] = strawberry.field(default_factory=list)

    # Statistics
    statistics: WebhookStatistics

    # Configuration
    global_retry_policy: WebhookRetryPolicy
    global_security: WebhookSecurity

    # Monitoring
    health_check_url: str | None = None
    health_check_interval: int = 300  # 5 minutes
    last_health_check: datetime | None = None
    is_healthy: bool = True

    # Rate limiting
    rate_limit_enabled: bool = False
    max_events_per_minute: int = 100
    current_event_rate: float = 0.0

    @strawberry.field
    def overall_success_rate(self) -> float:
        """Calculate overall webhook success rate."""
        return self.statistics.delivery_success_rate

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if webhooks require attention."""
        return (
            not self.is_healthy
            or self.statistics.error_rate > 10.0
            or self.statistics.delivery_success_rate < 90.0
        )


@strawberry.type
class WebhookEventResult:
    """GraphQL type for webhook event operation results."""

    success: bool = True
    message: str = "Webhook event processed successfully"
    event: WebhookEvent | None = None

    # Processing details
    processing_time_ms: int = 0
    queue_position: int | None = None
    estimated_delivery_time: datetime | None = None


@strawberry.type
class WebhookError:
    """GraphQL type for webhook-specific errors."""

    success: bool = False
    message: str
    error_code: str

    # Webhook-specific details
    endpoint_id: UUID | None = None
    event_id: UUID | None = None
    delivery_attempt_id: UUID | None = None

    # Error classification
    error_type: str  # "configuration", "delivery", "payload", "security"
    severity: ErrorSeverityEnum

    # Technical details
    http_status: int | None = None
    response_body: str | None = None

    # Recovery information
    is_retryable: bool = True
    retry_after: int | None = None
    recovery_suggestions: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    occurred_at: datetime


@strawberry.type
class WebhookDebugInfo:
    """GraphQL type for webhook debugging information."""

    integration_id: UUID
    endpoint_id: UUID | None = None

    # Configuration validation
    configuration_valid: bool = True
    configuration_issues: list[str] = strawberry.field(default_factory=list)

    # Connectivity test
    connectivity_test_passed: bool = True
    connectivity_test_message: str = ""
    connectivity_test_time_ms: int | None = None

    # Security validation
    security_valid: bool = True
    security_issues: list[str] = strawberry.field(default_factory=list)

    # Payload validation
    sample_payload_valid: bool = True
    payload_validation_errors: list[str] = strawberry.field(default_factory=list)

    # Performance analysis
    average_processing_time: float = 0.0
    bottlenecks: list[str] = strawberry.field(default_factory=list)

    # Recommendations
    optimization_suggestions: list[str] = strawberry.field(default_factory=list)

    # Test results
    last_test_time: datetime | None = None
    test_success: bool = True


__all__ = [
    "WebhookDebugInfo",
    "WebhookDeliveryAttempt",
    "WebhookEndpoint",
    "WebhookError",
    "WebhookEvent",
    "WebhookEventResult",
    "WebhookHeader",
    "WebhookPayload",
    "WebhookRetryPolicy",
    "WebhookSecurity",
    "WebhookStatistics",
    "WebhookType",
]
