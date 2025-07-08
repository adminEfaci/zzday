"""Sync status value object for tracking synchronization state.

This module provides comprehensive sync status tracking with
progress monitoring and error handling capabilities.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.integration.domain.enums import SyncDirection
from app.modules.integration.domain.enums import SyncStatus as SyncStatusEnum


class SyncStatusInfo(ValueObject):
    """Value object representing synchronization status information.

    This class encapsulates the current state of a synchronization operation,
    including progress tracking, error information, and performance metrics.
    """

    def __init__(
        self,
        status: SyncStatusEnum,
        direction: SyncDirection,
        total_records: int = 0,
        processed_records: int = 0,
        failed_records: int = 0,
        skipped_records: int = 0,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        last_error: str | None = None,
        error_count: int = 0,
        checkpoint: dict[str, Any] | None = None,
        metrics: dict[str, Any] | None = None,
    ):
        """Initialize sync status information.

        Args:
            status: Current sync status
            direction: Sync direction
            total_records: Total number of records to process
            processed_records: Number of successfully processed records
            failed_records: Number of failed records
            skipped_records: Number of skipped records
            started_at: Sync start time
            completed_at: Sync completion time
            last_error: Last error message
            error_count: Total number of errors
            checkpoint: Checkpoint data for resuming
            metrics: Additional performance metrics

        Raises:
            ValidationError: If status information is invalid
        """
        # Validate status
        if not isinstance(status, SyncStatusEnum):
            raise ValidationError("status must be a SyncStatus enum")
        self.status = status

        # Validate direction
        if not isinstance(direction, SyncDirection):
            raise ValidationError("direction must be a SyncDirection enum")
        self.direction = direction

        # Validate record counts
        if total_records < 0:
            raise ValidationError("total_records cannot be negative")
        if processed_records < 0:
            raise ValidationError("processed_records cannot be negative")
        if failed_records < 0:
            raise ValidationError("failed_records cannot be negative")
        if skipped_records < 0:
            raise ValidationError("skipped_records cannot be negative")

        self.total_records = total_records
        self.processed_records = processed_records
        self.failed_records = failed_records
        self.skipped_records = skipped_records

        # Validate logical constraints
        attempted_records = processed_records + failed_records + skipped_records
        if total_records > 0 and attempted_records > total_records:
            raise ValidationError(
                "Sum of processed, failed, and skipped records cannot exceed total records"
            )

        # Validate timestamps
        if started_at and not isinstance(started_at, datetime):
            raise ValidationError("started_at must be a datetime")
        if started_at and started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=UTC)
        self.started_at = started_at

        if completed_at and not isinstance(completed_at, datetime):
            raise ValidationError("completed_at must be a datetime")
        if completed_at and completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=UTC)
        self.completed_at = completed_at

        # Validate temporal logic
        if started_at and completed_at and completed_at < started_at:
            raise ValidationError("completed_at cannot be before started_at")

        # Validate error information
        self.last_error = last_error
        if error_count < 0:
            raise ValidationError("error_count cannot be negative")
        self.error_count = error_count

        # Store checkpoint and metrics
        self.checkpoint = checkpoint or {}
        self.metrics = metrics or {}

        # Freeze the object
        self._freeze()

    @property
    def is_running(self) -> bool:
        """Check if sync is currently running."""
        return self.status == SyncStatusEnum.RUNNING

    @property
    def is_complete(self) -> bool:
        """Check if sync is complete (success or failure)."""
        return self.status.is_terminal

    @property
    def is_successful(self) -> bool:
        """Check if sync completed successfully."""
        return self.status == SyncStatusEnum.COMPLETED and self.failed_records == 0

    @property
    def has_errors(self) -> bool:
        """Check if sync has any errors."""
        return self.error_count > 0 or self.failed_records > 0

    @property
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_records == 0:
            return 100.0 if self.is_complete else 0.0

        attempted = self.processed_records + self.failed_records + self.skipped_records
        return min(100.0, (attempted / self.total_records) * 100)

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        attempted = self.processed_records + self.failed_records
        if attempted == 0:
            return 100.0 if not self.has_errors else 0.0

        return (self.processed_records / attempted) * 100

    @property
    def duration(self) -> timedelta | None:
        """Calculate sync duration."""
        if not self.started_at:
            return None

        end_time = self.completed_at or datetime.now(UTC)
        return end_time - self.started_at

    @property
    def records_per_second(self) -> float:
        """Calculate processing rate."""
        duration = self.duration
        if not duration or duration.total_seconds() == 0:
            return 0.0

        total_processed = (
            self.processed_records + self.failed_records + self.skipped_records
        )
        return total_processed / duration.total_seconds()

    @property
    def estimated_completion(self) -> datetime | None:
        """Estimate completion time based on current rate."""
        if not self.is_running or self.total_records == 0:
            return None

        rate = self.records_per_second
        if rate == 0:
            return None

        remaining = self.total_records - (
            self.processed_records + self.failed_records + self.skipped_records
        )
        if remaining <= 0:
            return datetime.now(UTC)

        seconds_remaining = remaining / rate
        return datetime.now(UTC) + timedelta(seconds=seconds_remaining)

    def can_resume(self) -> bool:
        """Check if sync can be resumed from checkpoint."""
        return bool(self.checkpoint) and not self.is_running

    def with_progress(
        self,
        processed: int | None = None,
        failed: int | None = None,
        skipped: int | None = None,
    ) -> "SyncStatusInfo":
        """Create new status with updated progress.

        Args:
            processed: New processed count (incremental if positive)
            failed: New failed count (incremental if positive)
            skipped: New skipped count (incremental if positive)

        Returns:
            SyncStatusInfo: New status instance
        """
        new_processed = self.processed_records
        new_failed = self.failed_records
        new_skipped = self.skipped_records

        if processed is not None:
            new_processed = (
                self.processed_records + processed if processed > 0 else processed
            )
        if failed is not None:
            new_failed = self.failed_records + failed if failed > 0 else failed
        if skipped is not None:
            new_skipped = self.skipped_records + skipped if skipped > 0 else skipped

        return SyncStatusInfo(
            status=self.status,
            direction=self.direction,
            total_records=self.total_records,
            processed_records=new_processed,
            failed_records=new_failed,
            skipped_records=new_skipped,
            started_at=self.started_at,
            completed_at=self.completed_at,
            last_error=self.last_error,
            error_count=self.error_count,
            checkpoint=self.checkpoint.copy() if self.checkpoint else None,
            metrics=self.metrics.copy() if self.metrics else None,
        )

    def with_error(self, error_message: str) -> "SyncStatusInfo":
        """Create new status with error information.

        Args:
            error_message: Error message to record

        Returns:
            SyncStatusInfo: New status instance
        """
        return SyncStatusInfo(
            status=self.status,
            direction=self.direction,
            total_records=self.total_records,
            processed_records=self.processed_records,
            failed_records=self.failed_records,
            skipped_records=self.skipped_records,
            started_at=self.started_at,
            completed_at=self.completed_at,
            last_error=error_message,
            error_count=self.error_count + 1,
            checkpoint=self.checkpoint.copy() if self.checkpoint else None,
            metrics=self.metrics.copy() if self.metrics else None,
        )

    def with_checkpoint(self, checkpoint: dict[str, Any]) -> "SyncStatusInfo":
        """Create new status with updated checkpoint.

        Args:
            checkpoint: New checkpoint data

        Returns:
            SyncStatusInfo: New status instance
        """
        return SyncStatusInfo(
            status=self.status,
            direction=self.direction,
            total_records=self.total_records,
            processed_records=self.processed_records,
            failed_records=self.failed_records,
            skipped_records=self.skipped_records,
            started_at=self.started_at,
            completed_at=self.completed_at,
            last_error=self.last_error,
            error_count=self.error_count,
            checkpoint=checkpoint,
            metrics=self.metrics.copy() if self.metrics else None,
        )

    def __str__(self) -> str:
        """Return string representation of sync status."""
        progress = f"{self.progress_percentage:.1f}%"
        rate = (
            f"{self.records_per_second:.1f} rec/s"
            if self.records_per_second > 0
            else "N/A"
        )
        return f"{self.status.value} - {progress} ({self.processed_records}/{self.total_records}) @ {rate}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = {
            "status": self.status.value,
            "direction": self.direction.value,
            "total_records": self.total_records,
            "processed_records": self.processed_records,
            "failed_records": self.failed_records,
            "skipped_records": self.skipped_records,
            "progress_percentage": round(self.progress_percentage, 2),
            "success_rate": round(self.success_rate, 2),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "duration_seconds": self.duration.total_seconds()
            if self.duration
            else None,
            "records_per_second": round(self.records_per_second, 2),
            "has_errors": self.has_errors,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "can_resume": self.can_resume(),
            "checkpoint": self.checkpoint,
            "metrics": self.metrics,
        }

        if self.estimated_completion:
            data["estimated_completion"] = self.estimated_completion.isoformat()

        return data

    @classmethod
    def create_pending(
        cls, direction: SyncDirection, total_records: int = 0
    ) -> "SyncStatusInfo":
        """Create a new pending sync status.

        Args:
            direction: Sync direction
            total_records: Total records to process

        Returns:
            SyncStatusInfo: New pending status
        """
        return cls(
            status=SyncStatusEnum.PENDING,
            direction=direction,
            total_records=total_records,
        )

    @classmethod
    def create_running(
        cls, direction: SyncDirection, total_records: int = 0
    ) -> "SyncStatusInfo":
        """Create a new running sync status.

        Args:
            direction: Sync direction
            total_records: Total records to process

        Returns:
            SyncStatusInfo: New running status
        """
        return cls(
            status=SyncStatusEnum.RUNNING,
            direction=direction,
            total_records=total_records,
            started_at=datetime.now(UTC),
        )
