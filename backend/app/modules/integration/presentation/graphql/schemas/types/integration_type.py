"""GraphQL types for Integration entities.

This module provides GraphQL type definitions for integration-related entities,
including configurations, credentials, and analytics.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import (
    AuthTypeEnum,
    ConnectionStatusEnum,
    IntegrationCapabilityEnum,
    IntegrationTypeEnum,
    RateLimitStrategyEnum,
)


@strawberry.type
class IntegrationCredentials:
    """GraphQL type for integration credentials."""

    credential_id: UUID
    auth_type: AuthTypeEnum
    is_active: bool
    expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    # Sanitized credential info (no sensitive data)
    has_api_key: bool = False
    has_oauth_token: bool = False
    has_refresh_token: bool = False
    needs_refresh: bool = False


@strawberry.type
class RateLimitConfiguration:
    """GraphQL type for rate limit configuration."""

    enabled: bool
    strategy: RateLimitStrategyEnum
    requests_per_period: int
    period_seconds: int
    burst_limit: int | None = None

    # Current usage
    current_usage: int = 0
    remaining_requests: int = 0
    reset_time: datetime | None = None


@strawberry.type
class ApiEndpointConfiguration:
    """GraphQL type for API endpoint configuration."""

    base_url: str
    version: str | None = None
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: int = 1
    verify_ssl: bool = True

    # Health check endpoint
    health_check_path: str | None = None
    health_check_interval: int = 300  # 5 minutes


@strawberry.type
class IntegrationConfiguration:
    """GraphQL type for integration configuration."""

    api_endpoint: ApiEndpointConfiguration
    rate_limit: RateLimitConfiguration | None = None
    capabilities: list[IntegrationCapabilityEnum]

    # Custom configuration fields
    custom_fields: dict[str, Any] = strawberry.field(default_factory=dict)

    # Feature flags
    enable_webhooks: bool = False
    enable_sync: bool = True
    enable_real_time: bool = False
    enable_batch_processing: bool = True


@strawberry.type
class IntegrationMetrics:
    """GraphQL type for integration metrics."""

    # Request metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate: float = 0.0

    # Performance metrics
    average_response_time: float = 0.0
    median_response_time: float = 0.0
    p95_response_time: float = 0.0

    # Rate limiting metrics
    rate_limited_requests: int = 0
    throttled_requests: int = 0

    # Sync metrics
    sync_jobs_count: int = 0
    successful_syncs: int = 0
    failed_syncs: int = 0
    last_sync_time: datetime | None = None

    # Webhook metrics
    webhook_events_received: int = 0
    webhook_events_processed: int = 0
    webhook_failures: int = 0

    # Time period
    period_start: datetime
    period_end: datetime


@strawberry.type
class IntegrationHealth:
    """GraphQL type for integration health status."""

    is_healthy: bool
    is_connected: bool
    needs_attention: bool

    # Health check details
    last_health_check: datetime | None = None
    health_check_failures: int = 0
    consecutive_failures: int = 0

    # Connection status
    connection_status: ConnectionStatusEnum
    connection_established_at: datetime | None = None
    last_successful_request: datetime | None = None

    # Issues
    current_issues: list[str] = strawberry.field(default_factory=list)
    warning_count: int = 0
    error_count: int = 0


@strawberry.type
class IntegrationType:
    """GraphQL type for Integration entity."""

    # Core fields
    integration_id: UUID
    name: str
    description: str | None = None
    integration_type: IntegrationTypeEnum
    system_name: str

    # Ownership
    owner_id: UUID

    # Status
    is_active: bool
    health: IntegrationHealth

    # Configuration
    configuration: IntegrationConfiguration

    # Credentials
    credentials: list[IntegrationCredentials] = strawberry.field(default_factory=list)

    # Metrics
    metrics: IntegrationMetrics

    # Relationships
    sync_job_count: int = 0
    mapping_count: int = 0
    webhook_endpoint_count: int = 0

    # Timestamps
    created_at: datetime
    updated_at: datetime

    # Computed fields
    @strawberry.field
    def can_sync(self) -> bool:
        """Check if integration supports synchronization."""
        return IntegrationCapabilityEnum.SYNC in self.configuration.capabilities

    @strawberry.field
    def can_receive_webhooks(self) -> bool:
        """Check if integration supports webhooks."""
        return IntegrationCapabilityEnum.WEBHOOK in self.configuration.capabilities

    @strawberry.field
    def supports_real_time(self) -> bool:
        """Check if integration supports real-time operations."""
        return IntegrationCapabilityEnum.REAL_TIME in self.configuration.capabilities

    @strawberry.field
    def supports_batch(self) -> bool:
        """Check if integration supports batch operations."""
        return IntegrationCapabilityEnum.BATCH in self.configuration.capabilities

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if integration requires user attention."""
        return (
            self.health.needs_attention
            or self.health.error_count > 0
            or not self.health.is_healthy
        )

    @strawberry.field
    def uptime_percentage(self) -> float:
        """Calculate uptime percentage based on health checks."""
        if self.health.health_check_failures == 0:
            return 100.0

        total_checks = (
            self.health.health_check_failures + 100
        )  # Assume 100 successful checks
        success_rate = (total_checks - self.health.health_check_failures) / total_checks
        return round(success_rate * 100, 2)


@strawberry.type
class IntegrationListItem:
    """GraphQL type for integration list items (summary view)."""

    integration_id: UUID
    name: str
    integration_type: IntegrationTypeEnum
    system_name: str
    status: ConnectionStatusEnum
    is_active: bool
    is_healthy: bool
    needs_attention: bool
    uptime_percentage: float
    last_activity: datetime | None = None
    created_at: datetime


@strawberry.type
class IntegrationError:
    """GraphQL type for integration-specific errors."""

    success: bool = False
    message: str
    error_code: str
    integration_id: UUID | None = None

    # Additional error details
    details: dict[str, Any] = strawberry.field(default_factory=dict)
    suggestions: list[str] = strawberry.field(default_factory=list)

    # Error tracking
    error_id: str | None = None
    timestamp: datetime

    # Recovery information
    is_recoverable: bool = True
    retry_after: int | None = None  # Seconds


@strawberry.type
class IntegrationAnalytics:
    """GraphQL type for integration analytics."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # Usage analytics
    request_volume: list[dict[str, Any]] = strawberry.field(default_factory=list)
    error_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)
    performance_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Health analytics
    uptime_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)
    incident_history: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Sync analytics
    sync_performance: list[dict[str, Any]] = strawberry.field(default_factory=list)
    data_volume_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Summary metrics
    total_requests: int
    average_response_time: float
    error_rate: float
    uptime_percentage: float


@strawberry.type
class IntegrationCapabilityInfo:
    """GraphQL type for integration capability information."""

    capability: IntegrationCapabilityEnum
    is_supported: bool
    is_enabled: bool
    configuration: dict[str, Any] = strawberry.field(default_factory=dict)
    limitations: list[str] = strawberry.field(default_factory=list)
    requirements: list[str] = strawberry.field(default_factory=list)


__all__ = [
    "ApiEndpointConfiguration",
    "IntegrationAnalytics",
    "IntegrationCapabilityInfo",
    "IntegrationConfiguration",
    "IntegrationCredentials",
    "IntegrationError",
    "IntegrationHealth",
    "IntegrationListItem",
    "IntegrationMetrics",
    "IntegrationType",
    "RateLimitConfiguration",
]
