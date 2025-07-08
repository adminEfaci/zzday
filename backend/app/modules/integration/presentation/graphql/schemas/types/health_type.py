"""
GraphQL types for Health Monitoring entities.

This module provides GraphQL type definitions for health monitoring,
diagnostics, metrics, and alert management.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import strawberry

from ..enums import (
    AlertSeverityEnum,
    DiagnosticTypeEnum,
    HealthCheckStatusEnum,
    HealthStatusEnum,
)


@strawberry.type
class HealthCheckResult:
    """GraphQL type for health check results."""

    check_id: UUID
    integration_id: UUID
    check_type: str
    status: HealthCheckStatusEnum
    response_time_ms: int

    # Check details
    endpoint_tested: str | None = None
    http_status_code: int | None = None
    error_message: str | None = None

    # Validation results
    is_reachable: bool = True
    is_authenticated: bool = True
    is_authorized: bool = True

    # Metrics
    latency_ms: int = 0
    timeout_occurred: bool = False
    ssl_valid: bool = True

    # Timestamps
    started_at: datetime
    completed_at: datetime

    # Additional data
    check_details: dict[str, Any] = strawberry.field(default_factory=dict)
    recommendations: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class IntegrationHealthStatus:
    """GraphQL type for integration health status."""

    integration_id: UUID
    overall_status: HealthStatusEnum
    is_healthy: bool
    is_connected: bool
    needs_attention: bool

    # Health scores
    health_score: Decimal  # 0.0 to 1.0
    uptime_percentage: Decimal
    performance_score: Decimal
    reliability_score: Decimal

    # Last health check
    last_health_check: datetime | None = None
    last_successful_check: datetime | None = None
    consecutive_failures: int = 0
    total_checks_today: int = 0
    failed_checks_today: int = 0

    # Current issues
    active_alerts_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    critical_issues: list[str] = strawberry.field(default_factory=list)

    # Performance metrics
    average_response_time_ms: int = 0
    error_rate_percentage: Decimal = Decimal("0.0")

    # Connection status
    connection_established_at: datetime | None = None
    last_successful_operation: datetime | None = None

    # Health trends
    status_trend: str = "stable"  # improving, stable, degrading
    trend_percentage_change: Decimal = Decimal("0.0")

    # Timestamps
    status_updated_at: datetime

    @strawberry.field
    def is_critical(self) -> bool:
        """Check if integration has critical health issues."""
        return self.overall_status == HealthStatusEnum.CRITICAL or self.error_count > 0

    @strawberry.field
    def availability_rating(self) -> str:
        """Get availability rating based on uptime."""
        if self.uptime_percentage >= 99.9:
            return "excellent"
        if self.uptime_percentage >= 99.0:
            return "good"
        if self.uptime_percentage >= 95.0:
            return "fair"
        return "poor"


@strawberry.type
class HealthAlert:
    """GraphQL type for health alerts."""

    alert_id: UUID
    integration_id: UUID
    alert_type: str
    severity: AlertSeverityEnum
    title: str
    description: str

    # Alert status
    is_active: bool = True
    is_acknowledged: bool = False
    is_resolved: bool = False

    # Alert details
    affected_component: str | None = None
    error_code: str | None = None
    error_count: int = 1

    # Resolution
    resolution_steps: list[str] = strawberry.field(default_factory=list)
    estimated_resolution_time: int | None = None  # minutes

    # Timing
    first_occurred_at: datetime
    last_occurred_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None

    # User tracking
    created_by_system: bool = True
    acknowledged_by: UUID | None = None
    resolved_by: UUID | None = None

    # Additional data
    alert_data: dict[str, Any] = strawberry.field(default_factory=dict)
    tags: list[str] = strawberry.field(default_factory=list)

    @strawberry.field
    def duration_minutes(self) -> int:
        """Calculate alert duration in minutes."""
        end_time = self.resolved_at or datetime.now()
        duration = end_time - self.first_occurred_at
        return int(duration.total_seconds() / 60)

    @strawberry.field
    def requires_immediate_attention(self) -> bool:
        """Check if alert requires immediate attention."""
        return (
            self.severity in [AlertSeverityEnum.CRITICAL, AlertSeverityEnum.HIGH]
            and self.is_active
            and not self.is_acknowledged
        )


@strawberry.type
class ServiceDiagnostics:
    """GraphQL type for service diagnostics."""

    integration_id: UUID
    service_name: str
    diagnostic_type: DiagnosticTypeEnum

    # Diagnostic results
    overall_status: HealthStatusEnum
    issues_found: int = 0
    warnings_count: int = 0
    errors_count: int = 0

    # Network diagnostics
    network_connectivity: bool = True
    dns_resolution: bool = True
    ssl_certificate_valid: bool = True
    port_accessibility: bool = True

    # Authentication diagnostics
    credentials_valid: bool = True
    token_expires_at: datetime | None = None
    refresh_token_valid: bool = True

    # API diagnostics
    api_reachable: bool = True
    api_version_supported: bool = True
    rate_limits_status: str = "ok"  # ok, warning, exceeded

    # Performance diagnostics
    response_time_ms: int = 0
    throughput_normal: bool = True
    resource_utilization: Decimal = Decimal("0.0")

    # Configuration diagnostics
    configuration_valid: bool = True
    required_permissions: bool = True
    webhook_endpoints_reachable: bool = True

    # Detailed results
    diagnostic_details: list[dict[str, Any]] = strawberry.field(default_factory=list)
    recommendations: list[str] = strawberry.field(default_factory=list)

    # Timing
    diagnostic_started_at: datetime
    diagnostic_completed_at: datetime

    @strawberry.field
    def diagnostic_duration_ms(self) -> int:
        """Calculate diagnostic duration in milliseconds."""
        duration = self.diagnostic_completed_at - self.diagnostic_started_at
        return int(duration.total_seconds() * 1000)


@strawberry.type
class HealthMetrics:
    """GraphQL type for health metrics over time."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # Availability metrics
    uptime_percentage: Decimal
    downtime_minutes: int = 0
    incident_count: int = 0

    # Performance metrics
    average_response_time_ms: int = 0
    median_response_time_ms: int = 0
    p95_response_time_ms: int = 0
    p99_response_time_ms: int = 0

    # Error metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate_percentage: Decimal = Decimal("0.0")

    # Health check metrics
    total_health_checks: int = 0
    successful_health_checks: int = 0
    failed_health_checks: int = 0

    # Trend data (hourly aggregates)
    hourly_uptime: list[dict[str, Any]] = strawberry.field(default_factory=list)
    hourly_response_times: list[dict[str, Any]] = strawberry.field(default_factory=list)
    hourly_error_rates: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # SLA metrics
    sla_target_percentage: Decimal = Decimal("99.9")
    sla_actual_percentage: Decimal = Decimal("0.0")
    sla_breaches: int = 0

    @strawberry.field
    def is_sla_met(self) -> bool:
        """Check if SLA target is met."""
        return self.sla_actual_percentage >= self.sla_target_percentage


@strawberry.type
class SystemHealthOverview:
    """GraphQL type for system-wide health overview."""

    # Overall system status
    overall_status: HealthStatusEnum
    healthy_integrations: int = 0
    unhealthy_integrations: int = 0
    total_integrations: int = 0

    # System-wide metrics
    average_uptime_percentage: Decimal = Decimal("0.0")
    average_response_time_ms: int = 0
    total_active_alerts: int = 0
    critical_alerts: int = 0

    # Integration status breakdown
    status_breakdown: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Recent incidents
    recent_incidents: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Performance trends
    performance_trend: str = "stable"  # improving, stable, degrading
    trend_change_percentage: Decimal = Decimal("0.0")

    # Resource utilization
    system_load: Decimal = Decimal("0.0")
    memory_usage_percentage: Decimal = Decimal("0.0")
    cpu_usage_percentage: Decimal = Decimal("0.0")

    # Timestamps
    last_updated: datetime

    @strawberry.field
    def health_score(self) -> Decimal:
        """Calculate overall system health score."""
        if self.total_integrations == 0:
            return Decimal("1.0")

        healthy_ratio = Decimal(self.healthy_integrations) / Decimal(
            self.total_integrations
        )
        uptime_factor = self.average_uptime_percentage / Decimal("100.0")

        # Weighted score: 60% healthy ratio, 40% uptime
        return (healthy_ratio * Decimal("0.6")) + (uptime_factor * Decimal("0.4"))

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if system requires immediate attention."""
        return (
            self.critical_alerts > 0
            or self.overall_status == HealthStatusEnum.CRITICAL
            or self.average_uptime_percentage < Decimal("95.0")
        )


@strawberry.type
class HealthIncident:
    """GraphQL type for health incidents."""

    incident_id: UUID
    integration_id: UUID
    title: str
    description: str
    severity: AlertSeverityEnum

    # Incident status
    status: str = "open"  # open, investigating, resolved
    impact: str = "low"  # low, medium, high, critical

    # Timing
    started_at: datetime
    detected_at: datetime
    resolved_at: datetime | None = None

    # Impact assessment
    affected_users: int = 0
    affected_operations: list[str] = strawberry.field(default_factory=list)

    # Resolution
    root_cause: str | None = None
    resolution_summary: str | None = None
    preventive_actions: list[str] = strawberry.field(default_factory=list)

    # Timeline
    timeline_events: list[dict[str, Any]] = strawberry.field(default_factory=list)

    @strawberry.field
    def duration_minutes(self) -> int:
        """Calculate incident duration in minutes."""
        end_time = self.resolved_at or datetime.now()
        duration = end_time - self.started_at
        return int(duration.total_seconds() / 60)


@strawberry.type
class HealthStatistics:
    """GraphQL type for health statistics summary."""

    # Time period
    period_start: datetime
    period_end: datetime

    # Overall statistics
    total_integrations: int = 0
    active_integrations: int = 0
    healthy_integrations: int = 0

    # Health check statistics
    total_health_checks: int = 0
    successful_checks: int = 0
    failed_checks: int = 0

    # Alert statistics
    total_alerts: int = 0
    critical_alerts: int = 0
    resolved_alerts: int = 0

    # Performance statistics
    best_performing_integration: UUID | None = None
    worst_performing_integration: UUID | None = None
    average_system_response_time: int = 0

    # Uptime statistics
    highest_uptime_percentage: Decimal = Decimal("0.0")
    lowest_uptime_percentage: Decimal = Decimal("0.0")
    average_uptime_percentage: Decimal = Decimal("0.0")

    # Trends
    health_trend: str = "stable"
    trend_description: str = "System health is stable"


__all__ = [
    "HealthAlert",
    "HealthCheckResult",
    "HealthIncident",
    "HealthMetrics",
    "HealthStatistics",
    "IntegrationHealthStatus",
    "ServiceDiagnostics",
    "SystemHealthOverview",
]
