"""GraphQL types for Sync entities.

This module provides GraphQL type definitions for data synchronization,
including sync jobs, progress tracking, and results.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import (
    ErrorSeverityEnum,
    SyncDirectionEnum,
    SyncFrequencyEnum,
    SyncStatusEnum,
)


@strawberry.type
class SyncConfiguration:
    """GraphQL type for sync configuration."""

    # Sync behavior
    sync_direction: SyncDirectionEnum
    frequency: SyncFrequencyEnum
    batch_size: int = 100

    # Scheduling
    schedule_enabled: bool = False
    cron_expression: str | None = None
    timezone: str = "UTC"

    # Data filtering
    enable_filtering: bool = False
    filter_expression: str | None = None
    date_range_enabled: bool = False
    start_date: datetime | None = None
    end_date: datetime | None = None

    # Conflict resolution
    conflict_resolution_strategy: str = (
        "source_wins"  # "source_wins", "target_wins", "merge", "manual"
    )
    enable_conflict_detection: bool = True

    # Performance
    parallel_processing: bool = False
    max_parallel_batches: int = 1
    retry_enabled: bool = True
    max_retries: int = 3
    retry_delay_seconds: int = 30

    # Data integrity
    enable_checksums: bool = False
    enable_backup: bool = True
    rollback_on_failure: bool = False


@strawberry.type
class SyncProgress:
    """GraphQL type for sync progress tracking."""

    # Progress metrics
    total_records: int = 0
    processed_records: int = 0
    successful_records: int = 0
    failed_records: int = 0
    skipped_records: int = 0

    # Progress percentage
    completion_percentage: float = 0.0

    # Current batch info
    current_batch: int = 0
    total_batches: int = 0
    current_batch_size: int = 0

    # Timing
    started_at: datetime | None = None
    estimated_completion: datetime | None = None
    elapsed_time_seconds: int = 0
    remaining_time_seconds: int | None = None

    # Performance metrics
    records_per_second: float = 0.0
    average_record_processing_time_ms: float = 0.0

    # Current status
    current_operation: str = "initializing"
    current_record_id: str | None = None

    @strawberry.field
    def is_complete(self) -> bool:
        """Check if sync is complete."""
        return self.processed_records >= self.total_records and self.total_records > 0

    @strawberry.field
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.processed_records == 0:
            return 0.0
        return (self.successful_records / self.processed_records) * 100


@strawberry.type
class SyncConflict:
    """GraphQL type for sync conflicts."""

    conflict_id: UUID
    record_id: str
    field_name: str

    # Conflict details
    source_value: Any
    target_value: Any
    conflict_type: str  # "value_mismatch", "timestamp_conflict", "schema_mismatch"

    # Resolution
    resolution_status: str = "pending"  # "pending", "resolved", "skipped"
    resolution_strategy: str | None = None
    resolved_value: Any | None = None
    resolved_by: UUID | None = None
    resolved_at: datetime | None = None

    # Metadata
    detected_at: datetime
    source_timestamp: datetime | None = None
    target_timestamp: datetime | None = None


@strawberry.type
class SyncError:
    """GraphQL type for sync errors."""

    error_id: UUID
    severity: ErrorSeverityEnum
    error_type: str
    error_code: str
    message: str

    # Error context
    record_id: str | None = None
    field_name: str | None = None
    batch_number: int | None = None

    # Technical details
    exception_type: str | None = None
    stack_trace: str | None = None

    # Recovery information
    is_retryable: bool = True
    retry_count: int = 0
    max_retries: int = 3
    next_retry_at: datetime | None = None

    # Resolution
    is_resolved: bool = False
    resolution_action: str | None = None
    resolved_at: datetime | None = None

    # Timestamps
    occurred_at: datetime


@strawberry.type
class SyncResult:
    """GraphQL type for sync operation results."""

    # Overall result
    success: bool
    message: str

    # Statistics
    total_records: int = 0
    successful_records: int = 0
    failed_records: int = 0
    skipped_records: int = 0

    # Conflicts
    conflicts_detected: int = 0
    conflicts_resolved: int = 0
    conflicts_pending: int = 0

    # Errors
    errors_encountered: int = 0
    critical_errors: int = 0
    recoverable_errors: int = 0

    # Performance
    total_duration_seconds: int = 0
    average_records_per_second: float = 0.0
    peak_memory_usage_mb: float = 0.0

    # Data integrity
    checksum_verified: bool = True
    data_integrity_issues: int = 0

    # Backup information
    backup_created: bool = False
    backup_location: str | None = None


@strawberry.type
class SyncJob:
    """GraphQL type for sync jobs."""

    job_id: UUID
    integration_id: UUID
    name: str
    description: str | None = None

    # Configuration
    configuration: SyncConfiguration

    # Status
    status: SyncStatusEnum
    priority: str = "normal"  # "low", "normal", "high", "urgent"

    # Progress
    progress: SyncProgress

    # Results
    last_result: SyncResult | None = None

    # Error tracking
    errors: list[SyncError] = strawberry.field(default_factory=list)
    conflicts: list[SyncConflict] = strawberry.field(default_factory=list)

    # Scheduling
    next_scheduled_run: datetime | None = None
    last_run: datetime | None = None
    run_count: int = 0

    # Dependencies
    depends_on: list[UUID] = strawberry.field(default_factory=list)
    blocks: list[UUID] = strawberry.field(default_factory=list)

    # Monitoring
    enable_monitoring: bool = True
    alert_thresholds: dict[str, Any] = strawberry.field(default_factory=dict)

    # Timestamps
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @strawberry.field
    def is_running(self) -> bool:
        """Check if sync job is currently running."""
        return self.status == SyncStatusEnum.RUNNING

    @strawberry.field
    def is_scheduled(self) -> bool:
        """Check if sync job is scheduled."""
        return (
            self.configuration.schedule_enabled and self.next_scheduled_run is not None
        )

    @strawberry.field
    def average_runtime_seconds(self) -> float:
        """Calculate average runtime based on history."""
        # This would be calculated from historical data
        return 0.0  # Placeholder

    @strawberry.field
    def success_rate(self) -> float:
        """Calculate success rate based on history."""
        # This would be calculated from historical data
        return 100.0  # Placeholder


@strawberry.type
class SyncJobResult:
    """GraphQL type for sync job operation results."""

    success: bool = True
    message: str = "Sync job operation completed successfully"
    job: SyncJob | None = None

    # Operation details
    operation_type: str  # "create", "update", "start", "stop", "cancel"
    job_id: UUID

    # Scheduling details
    next_run_time: datetime | None = None
    estimated_duration: int | None = None


@strawberry.type
class SyncType:
    """GraphQL type for sync management."""

    integration_id: UUID

    # Active jobs
    active_jobs: list[SyncJob] = strawberry.field(default_factory=list)
    scheduled_jobs: list[SyncJob] = strawberry.field(default_factory=list)

    # Statistics
    total_jobs: int = 0
    running_jobs: int = 0
    failed_jobs: int = 0
    completed_jobs: int = 0

    # Overall metrics
    total_records_synced: int = 0
    total_sync_time_seconds: int = 0
    average_sync_rate: float = 0.0  # records per second

    # Health
    sync_health_score: float = 100.0
    last_successful_sync: datetime | None = None
    consecutive_failures: int = 0

    # Configuration
    global_sync_settings: dict[str, Any] = strawberry.field(default_factory=dict)
    max_concurrent_jobs: int = 5

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if sync system requires attention."""
        return (
            self.consecutive_failures > 3
            or self.failed_jobs > self.completed_jobs
            or self.sync_health_score < 80.0
        )

    @strawberry.field
    def overall_success_rate(self) -> float:
        """Calculate overall sync success rate."""
        if self.total_jobs == 0:
            return 0.0
        return (self.completed_jobs / self.total_jobs) * 100


@strawberry.type
class SyncSchedule:
    """GraphQL type for sync scheduling."""

    schedule_id: UUID
    job_id: UUID

    # Schedule configuration
    cron_expression: str
    timezone: str = "UTC"
    is_active: bool = True

    # Schedule metadata
    description: str | None = None
    created_by: UUID

    # Next runs
    next_run: datetime | None = None
    following_runs: list[datetime] = strawberry.field(default_factory=list)

    # History
    last_run: datetime | None = None
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0

    # Constraints
    max_runtime_seconds: int | None = None
    timeout_action: str = "cancel"  # "cancel", "continue", "retry"

    # Notifications
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_channels: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    created_at: datetime
    updated_at: datetime


@strawberry.type
class SyncAnalytics:
    """GraphQL type for sync analytics."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # Volume analytics
    total_sync_jobs: int = 0
    total_records_processed: int = 0
    data_volume_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Performance analytics
    average_sync_duration: float = 0.0
    throughput_trends: list[dict[str, Any]] = strawberry.field(default_factory=list)
    performance_bottlenecks: list[str] = strawberry.field(default_factory=list)

    # Reliability analytics
    success_rate: float = 100.0
    error_rate: float = 0.0
    failure_patterns: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Resource usage
    peak_memory_usage: float = 0.0
    average_cpu_usage: float = 0.0
    network_usage_gb: float = 0.0

    # Recommendations
    optimization_suggestions: list[str] = strawberry.field(default_factory=list)
    capacity_recommendations: list[str] = strawberry.field(default_factory=list)


__all__ = [
    "SyncAnalytics",
    "SyncConfiguration",
    "SyncConflict",
    "SyncError",
    "SyncJob",
    "SyncJobResult",
    "SyncProgress",
    "SyncResult",
    "SyncSchedule",
    "SyncType",
]
