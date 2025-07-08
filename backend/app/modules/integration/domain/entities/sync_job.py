"""Sync job entity for data synchronization management.

This module provides a comprehensive sync job entity for managing
data synchronization operations between systems.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.enums import SyncDirection, SyncStatus
from app.modules.integration.domain.value_objects import SyncStatusInfo


class SyncJob(Entity):
    """Entity representing a data synchronization job.

    This class manages the lifecycle of data synchronization operations,
    including progress tracking, error handling, and checkpointing.
    """

    def __init__(
        self,
        integration_id: UUID,
        name: str,
        direction: SyncDirection,
        source_config: dict[str, Any],
        target_config: dict[str, Any],
        mapping_ids: list[UUID],
        schedule: str | None = None,
        is_incremental: bool = True,
        batch_size: int = 100,
        timeout_minutes: int = 60,
        retry_policy: dict[str, Any] | None = None,
        filters: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize sync job entity.

        Args:
            integration_id: ID of the integration
            name: Name of the sync job
            direction: Sync direction
            source_config: Source system configuration
            target_config: Target system configuration
            mapping_ids: List of mapping IDs to use
            schedule: Optional cron schedule
            is_incremental: Whether to sync incrementally
            batch_size: Records per batch
            timeout_minutes: Job timeout in minutes
            retry_policy: Retry configuration
            filters: Data filters
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.integration_id = integration_id
        self.name = self._validate_name(name)
        self.direction = direction

        # Configuration
        self.source_config = self._validate_config(source_config, "source")
        self.target_config = self._validate_config(target_config, "target")
        self.mapping_ids = self._validate_mapping_ids(mapping_ids)

        # Scheduling
        self.schedule = self._validate_schedule(schedule) if schedule else None
        self.is_scheduled = bool(schedule)

        # Sync settings
        self.is_incremental = is_incremental
        self.batch_size = self._validate_batch_size(batch_size)
        self.timeout_minutes = self._validate_timeout(timeout_minutes)

        # Policies
        self.retry_policy = retry_policy or self._default_retry_policy()
        self.filters = filters or {}

        # Status tracking
        self.status = SyncStatusInfo.create_pending(direction)
        self.last_run_at: datetime | None = None
        self.next_run_at: datetime | None = None
        self.consecutive_failures = 0

        # Validate state
        self._validate_entity()

    def _validate_name(self, name: str) -> str:
        """Validate sync job name."""
        if not name or not name.strip():
            raise ValidationError("Sync job name cannot be empty")

        name = name.strip()
        if len(name) > 100:
            raise ValidationError("Sync job name cannot exceed 100 characters")

        return name

    def _validate_config(
        self, config: dict[str, Any], config_type: str
    ) -> dict[str, Any]:
        """Validate source/target configuration."""
        if not isinstance(config, dict):
            raise ValidationError(f"{config_type}_config must be a dictionary")

        # Basic required fields
        required_fields = ["resource_type", "resource_name"]
        for field in required_fields:
            if field not in config:
                raise ValidationError(f"{config_type}_config requires '{field}'")

        return config.copy()

    def _validate_mapping_ids(self, mapping_ids: list[UUID]) -> list[UUID]:
        """Validate mapping IDs."""
        if not mapping_ids:
            raise ValidationError("At least one mapping is required")

        if not isinstance(mapping_ids, list):
            raise ValidationError("mapping_ids must be a list")

        # Ensure all are UUIDs
        validated = []
        for mapping_id in mapping_ids:
            if not isinstance(mapping_id, UUID):
                raise ValidationError("All mapping_ids must be UUIDs")
            validated.append(mapping_id)

        return validated

    def _validate_schedule(self, schedule: str) -> str:
        """Validate cron schedule."""
        # Basic validation - full cron validation would be more complex
        parts = schedule.split()
        if len(parts) not in (5, 6):  # Standard cron or with seconds
            raise ValidationError("Invalid cron schedule format")

        return schedule

    def _validate_batch_size(self, batch_size: int) -> int:
        """Validate batch size."""
        if batch_size <= 0:
            raise ValidationError("batch_size must be positive")

        if batch_size > 10000:
            raise ValidationError("batch_size cannot exceed 10000")

        return batch_size

    def _validate_timeout(self, timeout_minutes: int) -> int:
        """Validate timeout."""
        if timeout_minutes <= 0:
            raise ValidationError("timeout_minutes must be positive")

        if timeout_minutes > 1440:  # 24 hours
            raise ValidationError("timeout_minutes cannot exceed 1440 (24 hours)")

        return timeout_minutes

    def _default_retry_policy(self) -> dict[str, Any]:
        """Get default retry policy."""
        return {
            "max_retries": 3,
            "backoff_factor": 2,
            "max_backoff_seconds": 300,
            "retry_on_errors": ["ConnectionError", "TimeoutError", "RateLimitError"],
        }

    def _validate_entity(self) -> None:
        """Validate entity state."""
        super()._validate_entity()

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not isinstance(self.direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")

        if not isinstance(self.status, SyncStatusInfo):
            raise ValidationError("status must be a SyncStatusInfo instance")

    @property
    def is_running(self) -> bool:
        """Check if sync job is currently running."""
        return self.status.is_running

    @property
    def can_run(self) -> bool:
        """Check if sync job can be run."""
        return not self.is_running and self.consecutive_failures < 5

    @property
    def is_overdue(self) -> bool:
        """Check if scheduled job is overdue."""
        if not self.is_scheduled or not self.next_run_at:
            return False

        return datetime.now(UTC) > self.next_run_at

    @property
    def estimated_duration(self) -> timedelta | None:
        """Estimate job duration based on history."""
        if not self.status.duration:
            return None

        # Simple estimation - could be enhanced with historical data
        return self.status.duration

    def start(self, total_records: int | None = None) -> None:
        """Start the sync job.

        Args:
            total_records: Expected total records

        Raises:
            DomainError: If job cannot be started
        """
        if self.is_running:
            raise DomainError("Sync job is already running")

        if not self.can_run:
            raise DomainError("Sync job cannot run due to repeated failures")

        self.status = SyncStatusInfo.create_running(
            direction=self.direction, total_records=total_records or 0
        )

        self.last_run_at = datetime.now(UTC)
        self.mark_modified()

    def update_progress(
        self,
        processed: int | None = None,
        failed: int | None = None,
        skipped: int | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        """Update sync progress.

        Args:
            processed: Processed records (incremental)
            failed: Failed records (incremental)
            skipped: Skipped records (incremental)
            checkpoint: Checkpoint data
        """
        if not self.is_running:
            raise DomainError("Cannot update progress on non-running job")

        self.status = self.status.with_progress(processed, failed, skipped)

        if checkpoint:
            self.status = self.status.with_checkpoint(checkpoint)

        self.mark_modified()

    def complete(self, summary: dict[str, Any] | None = None) -> None:
        """Mark sync job as completed.

        Args:
            summary: Optional completion summary

        Raises:
            DomainError: If job is not running
        """
        if not self.is_running:
            raise DomainError("Cannot complete non-running job")

        completed_at = datetime.now(UTC)
        (completed_at - self.status.started_at).total_seconds()

        self.status = SyncStatusInfo(
            status=SyncStatus.COMPLETED,
            direction=self.direction,
            total_records=self.status.total_records,
            processed_records=self.status.processed_records,
            failed_records=self.status.failed_records,
            skipped_records=self.status.skipped_records,
            started_at=self.status.started_at,
            completed_at=completed_at,
            metrics=summary,
        )

        self.consecutive_failures = 0
        self._update_next_run()
        self.mark_modified()

    def fail(self, error_message: str, can_resume: bool = False) -> None:
        """Mark sync job as failed.

        Args:
            error_message: Error message
            can_resume: Whether job can be resumed

        Raises:
            DomainError: If job is not running
        """
        if not self.is_running:
            raise DomainError("Cannot fail non-running job")

        self.status = SyncStatusInfo(
            status=SyncStatus.FAILED,
            direction=self.direction,
            total_records=self.status.total_records,
            processed_records=self.status.processed_records,
            failed_records=self.status.failed_records,
            skipped_records=self.status.skipped_records,
            started_at=self.status.started_at,
            completed_at=datetime.now(UTC),
            last_error=error_message,
            error_count=self.status.error_count + 1,
            checkpoint=self.status.checkpoint if can_resume else None,
        )

        self.consecutive_failures += 1
        self._update_next_run()
        self.mark_modified()

    def cancel(self) -> None:
        """Cancel running sync job.

        Raises:
            DomainError: If job is not running
        """
        if not self.is_running:
            raise DomainError("Cannot cancel non-running job")

        self.status = SyncStatusInfo(
            status=SyncStatus.CANCELLED,
            direction=self.direction,
            total_records=self.status.total_records,
            processed_records=self.status.processed_records,
            failed_records=self.status.failed_records,
            skipped_records=self.status.skipped_records,
            started_at=self.status.started_at,
            completed_at=datetime.now(UTC),
            checkpoint=self.status.checkpoint,
        )

        self._update_next_run()
        self.mark_modified()

    def reset(self) -> None:
        """Reset sync job to pending state."""
        self.status = SyncStatusInfo.create_pending(self.direction)
        self.consecutive_failures = 0
        self.mark_modified()

    def update_schedule(self, schedule: str | None) -> None:
        """Update job schedule.

        Args:
            schedule: New cron schedule (None to disable)
        """
        if schedule:
            self.schedule = self._validate_schedule(schedule)
            self.is_scheduled = True
            self._update_next_run()
        else:
            self.schedule = None
            self.is_scheduled = False
            self.next_run_at = None

        self.mark_modified()

    def _update_next_run(self) -> None:
        """Update next run time based on schedule."""
        if not self.is_scheduled or not self.schedule:
            self.next_run_at = None
            return

        # Simple implementation - would use proper cron parser in production
        # For now, assume daily schedule
        if self.last_run_at:
            self.next_run_at = self.last_run_at + timedelta(days=1)
        else:
            self.next_run_at = datetime.now(UTC) + timedelta(minutes=1)

    def add_filter(self, field: str, operator: str, value: Any) -> None:
        """Add a filter to the sync job.

        Args:
            field: Field to filter on
            operator: Filter operator
            value: Filter value
        """
        if "conditions" not in self.filters:
            self.filters["conditions"] = []

        self.filters["conditions"].append(
            {"field": field, "operator": operator, "value": value}
        )

        self.mark_modified()

    def clear_filters(self) -> None:
        """Clear all filters."""
        self.filters = {}
        self.mark_modified()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add sync job specific fields
        data.update(
            {
                "integration_id": str(self.integration_id),
                "name": self.name,
                "direction": self.direction.value,
                "source_config": self.source_config,
                "target_config": self.target_config,
                "mapping_ids": [str(mid) for mid in self.mapping_ids],
                "schedule": self.schedule,
                "is_scheduled": self.is_scheduled,
                "is_incremental": self.is_incremental,
                "batch_size": self.batch_size,
                "timeout_minutes": self.timeout_minutes,
                "retry_policy": self.retry_policy,
                "filters": self.filters,
                "status": self.status.to_dict(),
                "last_run_at": self.last_run_at.isoformat()
                if self.last_run_at
                else None,
                "next_run_at": self.next_run_at.isoformat()
                if self.next_run_at
                else None,
                "consecutive_failures": self.consecutive_failures,
                "is_running": self.is_running,
                "can_run": self.can_run,
                "is_overdue": self.is_overdue,
            }
        )

        return data

    def __str__(self) -> str:
        """String representation."""
        return (
            f"SyncJob({self.name}, {self.direction.value}, {self.status.status.value})"
        )
