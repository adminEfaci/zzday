"""Repository implementation for NotificationBatch aggregate."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.notification.domain.aggregates.notification_batch import (
    NotificationBatch,
)
from app.modules.notification.domain.enums import BatchStatus, NotificationChannel
from app.modules.notification.infrastructure.models.notification_batch import (
    NotificationBatchModel,
)


class NotificationBatchRepository(
    BaseRepository[NotificationBatch, NotificationBatchModel]
):
    """Repository for managing notification batch persistence."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        super().__init__(session, NotificationBatchModel)

    async def find_pending_batches(
        self, channel: NotificationChannel | None = None, limit: int = 100
    ) -> list[NotificationBatch]:
        """Find batches pending for processing.

        Args:
            channel: Optional channel filter
            limit: Maximum number of results

        Returns:
            List of pending batches
        """
        now = datetime.utcnow()

        stmt = select(self.model_class).where(
            and_(
                self.model_class.status == BatchStatus.CREATED,
                or_(
                    self.model_class.scheduled_for.is_(None),
                    self.model_class.scheduled_for <= now,
                ),
            )
        )

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        stmt = stmt.order_by(
            self.model_class.scheduled_for.asc().nullsfirst(),
            self.model_class.created_at.asc(),
        )
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_by_template(
        self,
        template_id: UUID,
        status: BatchStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NotificationBatch]:
        """Find batches using a specific template.

        Args:
            template_id: Template ID
            status: Optional status filter
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of batches
        """
        stmt = select(self.model_class).where(
            self.model_class.template_id == template_id
        )

        if status:
            stmt = stmt.where(self.model_class.status == status)

        stmt = stmt.order_by(self.model_class.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def update_batch_statistics(
        self,
        batch_id: UUID,
        sent_delta: int = 0,
        delivered_delta: int = 0,
        failed_delta: int = 0,
        cancelled_delta: int = 0,
    ) -> None:
        """Update batch processing statistics.

        Args:
            batch_id: Batch ID
            sent_delta: Change in sent count
            delivered_delta: Change in delivered count
            failed_delta: Change in failed count
            cancelled_delta: Change in cancelled count
        """
        stmt = (
            update(self.model_class)
            .where(self.model_class.id == batch_id)
            .values(
                sent_count=self.model_class.sent_count + sent_delta,
                delivered_count=self.model_class.delivered_count + delivered_delta,
                failed_count=self.model_class.failed_count + failed_delta,
                cancelled_count=self.model_class.cancelled_count + cancelled_delta,
                updated_at=datetime.utcnow(),
            )
        )

        await self.session.execute(stmt)
        await self.session.commit()

    async def get_batch_statistics(
        self,
        start_date: datetime,
        end_date: datetime,
        channel: NotificationChannel | None = None,
    ) -> dict[str, Any]:
        """Get batch processing statistics.

        Args:
            start_date: Start of date range
            end_date: End of date range
            channel: Optional channel filter

        Returns:
            Dictionary with batch statistics
        """
        base_query = select(
            func.count(self.model_class.id).label("total_batches"),
            func.sum(self.model_class.total_notifications).label("total_notifications"),
            func.sum(self.model_class.sent_count).label("total_sent"),
            func.sum(self.model_class.delivered_count).label("total_delivered"),
            func.sum(self.model_class.failed_count).label("total_failed"),
            func.avg(
                func.extract(
                    "epoch", self.model_class.completed_at - self.model_class.started_at
                )
            ).label("avg_processing_time_seconds"),
        ).where(
            and_(
                self.model_class.created_at >= start_date,
                self.model_class.created_at <= end_date,
            )
        )

        if channel:
            base_query = base_query.where(self.model_class.channel == channel)

        result = await self.session.execute(base_query)
        stats = result.one()

        return {
            "total_batches": stats.total_batches or 0,
            "total_notifications": stats.total_notifications or 0,
            "total_sent": stats.total_sent or 0,
            "total_delivered": stats.total_delivered or 0,
            "total_failed": stats.total_failed or 0,
            "success_rate": (
                (stats.total_delivered / stats.total_sent * 100)
                if stats.total_sent and stats.total_sent > 0
                else 0
            ),
            "avg_processing_time_seconds": float(
                stats.avg_processing_time_seconds or 0
            ),
        }

    def _to_entity(self, model: NotificationBatchModel) -> NotificationBatch:
        """Convert database model to domain aggregate.

        Args:
            model: Database model

        Returns:
            Domain aggregate
        """
        if not model:
            return None

        # Create aggregate
        batch = NotificationBatch(
            name=model.name,
            channel=model.channel,
            created_by=model.created_by,
            description=model.description,
            template_id=model.template_id,
            scheduled_for=model.scheduled_for,
            batch_config=model.batch_config,
            entity_id=model.id,
        )

        # Set timestamps
        batch.created_at = model.created_at
        batch.updated_at = model.updated_at
        batch.started_at = model.started_at
        batch.completed_at = model.completed_at

        # Set status
        batch.status = model.status

        # Set statistics
        batch.total_notifications = model.total_notifications
        batch.sent_count = model.sent_count
        batch.delivered_count = model.delivered_count
        batch.failed_count = model.failed_count
        batch.cancelled_count = model.cancelled_count

        # Set error info
        if model.error_summary:
            batch.error_summary = model.error_summary

        # Set metadata
        if model.metadata:
            batch.metadata = model.metadata

        # Clear events
        batch.clear_events()

        return batch

    def _to_model(self, entity: NotificationBatch) -> NotificationBatchModel:
        """Convert domain aggregate to database model.

        Args:
            entity: Domain aggregate

        Returns:
            Database model
        """
        return NotificationBatchModel(
            id=entity.id,
            name=entity.name,
            description=entity.description,
            channel=entity.channel,
            template_id=entity.template_id,
            status=entity.status,
            total_notifications=entity.total_notifications,
            sent_count=entity.sent_count,
            delivered_count=entity.delivered_count,
            failed_count=entity.failed_count,
            cancelled_count=entity.cancelled_count,
            scheduled_for=entity.scheduled_for,
            started_at=entity.started_at,
            completed_at=entity.completed_at,
            batch_config=entity.batch_config,
            error_summary=getattr(entity, "error_summary", None),
            metadata=getattr(entity, "metadata", None),
            created_by=entity.created_by,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
