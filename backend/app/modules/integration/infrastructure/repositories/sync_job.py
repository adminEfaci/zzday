"""Sync job repository implementation.

This module provides the repository for synchronization jobs with
comprehensive query support and progress tracking.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError
from app.core.infrastructure.repositories import BaseRepository
from app.modules.integration.domain.entities import SyncJob
from app.modules.integration.domain.enums import SyncStatus
from app.modules.integration.domain.value_objects import SyncStatus as SyncStatusVO
from app.modules.integration.infrastructure.models import SyncJobModel
from app.core.infrastructure.repository import BaseRepository


class SyncJobRepository(BaseRepository[SyncJob, SyncJobModel]):
    """Repository for managing synchronization jobs."""

    def __init__(self, session: Session):
        """Initialize repository with database session."""
        super().__init__(session, SyncJobModel)

    def _to_domain(self, model: SyncJobModel) -> SyncJob:
        """Convert database model to domain entity."""
        data = model.to_entity_dict()

        # Reconstruct value object
        sync_status = SyncStatusVO(
            status=data.pop("status"),
            started_at=data.pop("started_at"),
            completed_at=data.pop("completed_at"),
            progress_percentage=0,  # Will be calculated
        )

        # Calculate progress
        if data.get("total_records") and data["total_records"] > 0:
            sync_status.progress_percentage = int(
                (data["processed_records"] / data["total_records"]) * 100
            )

        # Create entity
        sync_job = SyncJob(
            integration_id=data.pop("integration_id"),
            name=data.pop("name"),
            direction=data.pop("direction"),
            initiated_by=data.pop("initiated_by"),
            mapping_ids=data.pop("mapping_ids"),
            sync_status=sync_status,
            description=data.pop("description"),
            parameters=data.pop("parameters"),
            filters=data.pop("filters"),
            scheduled_at=data.pop("scheduled_at"),
            entity_id=data.pop("entity_id"),
        )

        # Set progress fields
        sync_job.total_records = data.pop("total_records")
        sync_job.processed_records = data.pop("processed_records")
        sync_job.failed_records = data.pop("failed_records")
        sync_job.skipped_records = data.pop("skipped_records")

        # Set error fields
        sync_job.error_message = data.pop("error_message")
        sync_job.error_details = data.pop("error_details")

        # Set result and metrics
        sync_job.result_summary = data.pop("result_summary")
        sync_job.metrics = data.pop("metrics")
        sync_job.metadata = data.pop("metadata")

        # Set timestamps
        sync_job.created_at = data.pop("created_at")
        sync_job.updated_at = data.pop("updated_at")
        sync_job._version = data.pop("version")

        # Clear modification tracking
        sync_job._modified = False

        return sync_job

    def _to_model(self, entity: SyncJob) -> SyncJobModel:
        """Convert domain entity to database model."""
        data = entity.to_dict()

        # Extract sync status fields
        data["status"] = entity.sync_status.status
        data["started_at"] = entity.sync_status.started_at
        data["completed_at"] = entity.sync_status.completed_at

        # Remove computed fields
        data.pop("sync_status", None)
        computed_fields = [
            "is_complete",
            "is_running",
            "is_failed",
            "can_retry",
            "progress_percentage",
            "success_rate",
            "duration_seconds",
        ]
        for field in computed_fields:
            data.pop(field, None)

        # Map id to entity_id
        data["entity_id"] = data.pop("id")

        return SyncJobModel.from_entity_dict(data)

    async def find_by_id(self, sync_job_id: UUID) -> SyncJob | None:
        """Find sync job by ID."""
        stmt = select(SyncJobModel).where(SyncJobModel.id == sync_job_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_integration(
        self, integration_id: UUID, status: SyncStatus | None = None, limit: int = 50
    ) -> list[SyncJob]:
        """Find sync jobs for an integration."""
        stmt = select(SyncJobModel).where(SyncJobModel.integration_id == integration_id)

        if status:
            stmt = stmt.where(SyncJobModel.status == status)

        stmt = stmt.order_by(SyncJobModel.created_at.desc())
        stmt = stmt.limit(limit)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_status(
        self, status: SyncStatus, integration_id: UUID | None = None
    ) -> list[SyncJob]:
        """Find sync jobs by status."""
        stmt = select(SyncJobModel).where(SyncJobModel.status == status)

        if integration_id:
            stmt = stmt.where(SyncJobModel.integration_id == integration_id)

        stmt = stmt.order_by(SyncJobModel.created_at.desc())

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_pending_scheduled(
        self, cutoff_time: datetime | None = None
    ) -> list[SyncJob]:
        """Find pending sync jobs that should be started."""
        if not cutoff_time:
            cutoff_time = datetime.now(UTC)

        stmt = select(SyncJobModel).where(
            and_(
                SyncJobModel.status == SyncStatus.PENDING,
                or_(
                    SyncJobModel.scheduled_at is None,
                    SyncJobModel.scheduled_at <= cutoff_time,
                ),
            )
        )

        stmt = stmt.order_by(
            SyncJobModel.scheduled_at.asc().nullsfirst(), SyncJobModel.created_at.asc()
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_running_jobs(
        self, integration_id: UUID | None = None
    ) -> list[SyncJob]:
        """Find currently running sync jobs."""
        stmt = select(SyncJobModel).where(SyncJobModel.status == SyncStatus.RUNNING)

        if integration_id:
            stmt = stmt.where(SyncJobModel.integration_id == integration_id)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_stuck_jobs(self, timeout_hours: int = 6) -> list[SyncJob]:
        """Find sync jobs that appear to be stuck."""
        cutoff_time = datetime.now(UTC) - timedelta(hours=timeout_hours)

        stmt = select(SyncJobModel).where(
            and_(
                SyncJobModel.status == SyncStatus.RUNNING,
                SyncJobModel.started_at is not None,
                SyncJobModel.started_at < cutoff_time,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_failed_retryable(self, max_age_hours: int = 24) -> list[SyncJob]:
        """Find failed jobs that can be retried."""
        cutoff_time = datetime.now(UTC) - timedelta(hours=max_age_hours)

        stmt = select(SyncJobModel).where(
            and_(
                SyncJobModel.status == SyncStatus.FAILED,
                SyncJobModel.created_at > cutoff_time,
                # Check if error is retryable (simplified logic)
                or_(
                    SyncJobModel.error_message.like("%timeout%"),
                    SyncJobModel.error_message.like("%temporary%"),
                    SyncJobModel.error_message.like("%network%"),
                ),
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def get_statistics(
        self, integration_id: UUID, days: int = 7
    ) -> dict[str, Any]:
        """Get sync job statistics for an integration."""
        cutoff_date = datetime.now(UTC) - timedelta(days=days)

        # Count by status
        status_counts = {}
        for status in SyncStatus:
            stmt = select(func.count(SyncJobModel.id)).where(
                and_(
                    SyncJobModel.integration_id == integration_id,
                    SyncJobModel.status == status,
                    SyncJobModel.created_at > cutoff_date,
                )
            )
            result = await self._session.execute(stmt)
            status_counts[status.value] = result.scalar() or 0

        # Average duration for completed jobs
        stmt = select(
            func.avg(
                func.extract(
                    "epoch", SyncJobModel.completed_at - SyncJobModel.started_at
                )
            )
        ).where(
            and_(
                SyncJobModel.integration_id == integration_id,
                SyncJobModel.status == SyncStatus.COMPLETED,
                SyncJobModel.created_at > cutoff_date,
                SyncJobModel.completed_at is not None,
                SyncJobModel.started_at is not None,
            )
        )

        result = await self._session.execute(stmt)
        avg_duration = result.scalar()

        # Total records processed
        stmt = select(
            func.sum(SyncJobModel.processed_records),
            func.sum(SyncJobModel.failed_records),
            func.sum(SyncJobModel.skipped_records),
        ).where(
            and_(
                SyncJobModel.integration_id == integration_id,
                SyncJobModel.created_at > cutoff_date,
            )
        )

        result = await self._session.execute(stmt)
        processed, failed, skipped = result.one()

        return {
            "period_days": days,
            "total_jobs": sum(status_counts.values()),
            "status_distribution": status_counts,
            "average_duration_seconds": avg_duration,
            "total_processed_records": processed or 0,
            "total_failed_records": failed or 0,
            "total_skipped_records": skipped or 0,
            "success_rate": (
                status_counts.get(SyncStatus.COMPLETED.value, 0)
                / sum(status_counts.values())
                * 100
                if sum(status_counts.values()) > 0
                else 0
            ),
        }

    async def count_active(self, integration_id: UUID) -> int:
        """Count active (pending/running) sync jobs."""
        stmt = select(func.count(SyncJobModel.id)).where(
            and_(
                SyncJobModel.integration_id == integration_id,
                SyncJobModel.status.in_([SyncStatus.PENDING, SyncStatus.RUNNING]),
            )
        )

        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def update_progress(
        self,
        sync_job_id: UUID,
        processed: int,
        failed: int = 0,
        skipped: int = 0,
        total: int | None = None,
    ) -> None:
        """Update sync job progress."""
        stmt = select(SyncJobModel).where(SyncJobModel.id == sync_job_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Sync job {sync_job_id} not found")

        model.processed_records = processed
        model.failed_records = failed
        model.skipped_records = skipped

        if total is not None:
            model.total_records = total

        model.updated_at = datetime.now(UTC)

        await self._session.flush()

    async def save_with_lock(self, sync_job: SyncJob) -> SyncJob:
        """Save sync job with optimistic locking."""
        model = self._to_model(sync_job)

        if sync_job._version > 1:
            # Update with version check
            stmt = select(SyncJobModel).where(
                and_(
                    SyncJobModel.id == model.id,
                    SyncJobModel.version == sync_job._version - 1,
                )
            )

            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                raise ConflictError("Sync job has been modified by another process")

            # Update fields
            for key, value in model.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)

            existing.version = sync_job._version
            model = existing
        else:
            # New sync job
            self._session.add(model)

        await self._session.flush()
        sync_job._version = model.version
        return sync_job

    async def delete(self, sync_job_id: UUID) -> None:
        """Delete sync job."""
        stmt = select(SyncJobModel).where(SyncJobModel.id == sync_job_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Sync job {sync_job_id} not found")

        await self._session.delete(model)
        await self._session.flush()

    async def cleanup_old_jobs(
        self, days_old: int = 90, keep_failed: bool = True
    ) -> int:
        """Clean up old sync jobs."""
        cutoff_date = datetime.now(UTC) - timedelta(days=days_old)

        stmt = select(SyncJobModel).where(SyncJobModel.created_at < cutoff_date)

        if keep_failed:
            stmt = stmt.where(SyncJobModel.status != SyncStatus.FAILED)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        count = len(models)
        for model in models:
            await self._session.delete(model)

        await self._session.flush()
        return count
