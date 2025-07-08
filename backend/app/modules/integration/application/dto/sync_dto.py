"""Sync DTOs for application layer.

This module provides data transfer objects for synchronization data,
ensuring clean interfaces for sync operations.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import SyncDirection, SyncStatus


@dataclass(frozen=True)
class SyncStatusDTO:
    """DTO for sync status information."""

    sync_job_id: UUID
    integration_id: UUID
    status: SyncStatus
    direction: SyncDirection
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    total_records: int
    processed_records: int
    failed_records: int
    skipped_records: int
    error_message: str | None
    progress_percentage: float
    estimated_completion: datetime | None

    @classmethod
    def from_domain(cls, sync_job: Any) -> "SyncStatusDTO":
        """Create DTO from domain model."""
        duration = None
        if sync_job.completed_at and sync_job.started_at:
            duration = (sync_job.completed_at - sync_job.started_at).total_seconds()

        progress = 0.0
        if sync_job.total_records > 0:
            progress = (sync_job.processed_records / sync_job.total_records) * 100

        estimated_completion = None
        if sync_job.status == SyncStatus.RUNNING and sync_job.processed_records > 0:
            # Simple estimation based on current rate
            elapsed = (datetime.utcnow() - sync_job.started_at).total_seconds()
            rate = sync_job.processed_records / elapsed
            remaining = sync_job.total_records - sync_job.processed_records
            if rate > 0:
                estimated_seconds = remaining / rate
                estimated_completion = datetime.utcnow() + timedelta(
                    seconds=estimated_seconds
                )

        return cls(
            sync_job_id=sync_job.id,
            integration_id=sync_job.integration_id,
            status=sync_job.status,
            direction=sync_job.direction,
            started_at=sync_job.started_at,
            completed_at=sync_job.completed_at,
            duration_seconds=duration,
            total_records=sync_job.total_records,
            processed_records=sync_job.processed_records,
            failed_records=sync_job.failed_records,
            skipped_records=sync_job.skipped_records,
            error_message=sync_job.error_message,
            progress_percentage=progress,
            estimated_completion=estimated_completion,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sync_job_id": str(self.sync_job_id),
            "integration_id": str(self.integration_id),
            "status": self.status.value,
            "direction": self.direction.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "duration_seconds": self.duration_seconds,
            "total_records": self.total_records,
            "processed_records": self.processed_records,
            "failed_records": self.failed_records,
            "skipped_records": self.skipped_records,
            "error_message": self.error_message,
            "progress_percentage": round(self.progress_percentage, 2),
            "estimated_completion": self.estimated_completion.isoformat()
            if self.estimated_completion
            else None,
        }


@dataclass(frozen=True)
class SyncJobDTO:
    """DTO for sync job data."""

    sync_job_id: UUID
    integration_id: UUID
    mapping_id: UUID
    direction: SyncDirection
    status: SyncStatus
    batch_size: int
    filters: dict[str, Any]
    options: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None
    scheduled_at: datetime | None
    created_by: UUID
    created_at: datetime

    @classmethod
    def from_domain(cls, sync_job: Any) -> "SyncJobDTO":
        """Create DTO from domain model."""
        return cls(
            sync_job_id=sync_job.id,
            integration_id=sync_job.integration_id,
            mapping_id=sync_job.mapping_id,
            direction=sync_job.direction,
            status=sync_job.status,
            batch_size=sync_job.batch_size,
            filters=sync_job.filters,
            options=sync_job.options,
            started_at=sync_job.started_at,
            completed_at=sync_job.completed_at,
            scheduled_at=sync_job.scheduled_at,
            created_by=sync_job.created_by,
            created_at=sync_job.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sync_job_id": str(self.sync_job_id),
            "integration_id": str(self.integration_id),
            "mapping_id": str(self.mapping_id),
            "direction": self.direction.value,
            "status": self.status.value,
            "batch_size": self.batch_size,
            "filters": self.filters,
            "options": self.options,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "scheduled_at": self.scheduled_at.isoformat()
            if self.scheduled_at
            else None,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class SyncResultDTO:
    """DTO for sync operation results."""

    sync_job_id: UUID
    integration_id: UUID
    status: SyncStatus
    total_records: int
    processed_records: int
    created_records: int
    updated_records: int
    deleted_records: int
    failed_records: int
    skipped_records: int
    duration_seconds: float
    error_details: list[dict[str, Any]]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sync_job_id": str(self.sync_job_id),
            "integration_id": str(self.integration_id),
            "status": self.status.value,
            "total_records": self.total_records,
            "processed_records": self.processed_records,
            "created_records": self.created_records,
            "updated_records": self.updated_records,
            "deleted_records": self.deleted_records,
            "failed_records": self.failed_records,
            "skipped_records": self.skipped_records,
            "duration_seconds": self.duration_seconds,
            "error_details": self.error_details,
            "summary": self.summary,
        }
