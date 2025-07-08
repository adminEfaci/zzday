"""Repository implementation for NotificationSchedule entity."""

from datetime import datetime
from typing import Any
from uuid import UUID

from croniter import croniter
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.notification.domain.entities.notification_schedule import (
    NotificationSchedule,
)
from app.modules.notification.domain.enums import NotificationChannel, ScheduleStatus
from app.modules.notification.infrastructure.models.schedule import ScheduleModel


class ScheduleRepository(BaseRepository[NotificationSchedule, ScheduleModel]):
    """Repository for managing notification schedule persistence."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        super().__init__(session, ScheduleModel)

    async def find_active_schedules(
        self, channel: NotificationChannel | None = None, limit: int = 100
    ) -> list[NotificationSchedule]:
        """Find active schedules ready to run.

        Args:
            channel: Optional channel filter
            limit: Maximum number of results

        Returns:
            List of active schedules
        """
        now = datetime.utcnow()

        stmt = select(self.model_class).where(
            and_(
                self.model_class.status == ScheduleStatus.ACTIVE,
                self.model_class.start_date <= now,
                or_(
                    self.model_class.end_date.is_(None), self.model_class.end_date > now
                ),
            )
        )

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        stmt = stmt.order_by(
            self.model_class.next_run_at.asc().nullsfirst(),
            self.model_class.created_at.asc(),
        )
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_schedules_to_run(
        self, as_of: datetime | None = None, limit: int = 100
    ) -> list[NotificationSchedule]:
        """Find schedules that need to run.

        Args:
            as_of: Time to check (defaults to now)
            limit: Maximum number of results

        Returns:
            List of schedules ready to run
        """
        check_time = as_of or datetime.utcnow()

        stmt = select(self.model_class).where(
            and_(
                self.model_class.status == ScheduleStatus.ACTIVE,
                self.model_class.next_run_at <= check_time,
                self.model_class.start_date <= check_time,
                or_(
                    self.model_class.end_date.is_(None),
                    self.model_class.end_date > check_time,
                ),
            )
        )

        stmt = stmt.order_by(self.model_class.next_run_at.asc())
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_by_template(
        self,
        template_id: UUID,
        status: ScheduleStatus | None = None,
        is_recurring: bool | None = None,
    ) -> list[NotificationSchedule]:
        """Find schedules using a template.

        Args:
            template_id: Template ID
            status: Optional status filter
            is_recurring: Optional recurring filter

        Returns:
            List of schedules
        """
        stmt = select(self.model_class).where(
            self.model_class.template_id == template_id
        )

        if status:
            stmt = stmt.where(self.model_class.status == status)

        if is_recurring is not None:
            stmt = stmt.where(self.model_class.is_recurring == is_recurring)

        stmt = stmt.order_by(self.model_class.created_at.desc())

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def update_next_run_time(
        self, schedule_id: UUID, next_run_at: datetime | None = None
    ) -> None:
        """Update schedule's next run time.

        Args:
            schedule_id: Schedule ID
            next_run_at: Next run time (None to calculate from cron)
        """
        if next_run_at is None:
            # Get schedule to calculate next run time
            schedule = await self.find_by_id(schedule_id)
            if not schedule or not schedule.is_recurring:
                return

            # Calculate next run time from cron expression
            if schedule.cron_expression:
                cron = croniter(schedule.cron_expression, datetime.utcnow())
                next_run_at = cron.get_next(datetime)

        stmt = (
            update(self.model_class)
            .where(self.model_class.id == schedule_id)
            .values(next_run_at=next_run_at, updated_at=datetime.utcnow())
        )

        await self.session.execute(stmt)
        await self.session.commit()

    async def record_execution(
        self,
        schedule_id: UUID,
        success: bool,
        error_message: str | None = None,
        sent_count: int = 0,
        delivered_count: int = 0,
        failed_count: int = 0,
    ) -> None:
        """Record schedule execution results.

        Args:
            schedule_id: Schedule ID
            success: Whether execution was successful
            error_message: Error message if failed
            sent_count: Number sent
            delivered_count: Number delivered
            failed_count: Number failed
        """
        now = datetime.utcnow()

        stmt = (
            update(self.model_class)
            .where(self.model_class.id == schedule_id)
            .values(
                last_run_at=now,
                last_run_status="success" if success else "failed",
                last_run_error=error_message,
                occurrences_count=self.model_class.occurrences_count + 1,
                total_sent=self.model_class.total_sent + sent_count,
                total_delivered=self.model_class.total_delivered + delivered_count,
                total_failed=self.model_class.total_failed + failed_count,
                updated_at=now,
            )
        )

        await self.session.execute(stmt)

        # Check if schedule should be completed
        schedule = await self.find_by_id(schedule_id)
        if schedule and (
            schedule.max_occurrences
            and schedule.occurrences_count >= schedule.max_occurrences
        ):
            # Mark as completed
            complete_stmt = (
                update(self.model_class)
                .where(self.model_class.id == schedule_id)
                .values(status=ScheduleStatus.COMPLETED, updated_at=now)
            )
            await self.session.execute(complete_stmt)

        await self.session.commit()

    async def get_schedule_statistics(
        self,
        schedule_id: UUID | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get schedule execution statistics.

        Args:
            schedule_id: Optional specific schedule
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dictionary with statistics
        """
        query = select(
            func.count(self.model_class.id).label("total_schedules"),
            func.count(
                func.nullif(self.model_class.status == ScheduleStatus.ACTIVE, False)
            ).label("active_schedules"),
            func.count(func.nullif(self.model_class.is_recurring is True, False)).label(
                "recurring_schedules"
            ),
            func.sum(self.model_class.occurrences_count).label("total_executions"),
            func.sum(self.model_class.total_sent).label("total_sent"),
            func.sum(self.model_class.total_delivered).label("total_delivered"),
            func.sum(self.model_class.total_failed).label("total_failed"),
        )

        if schedule_id:
            query = query.where(self.model_class.id == schedule_id)

        if start_date:
            query = query.where(self.model_class.created_at >= start_date)

        if end_date:
            query = query.where(self.model_class.created_at <= end_date)

        result = await self.session.execute(query)
        stats = result.one()

        return {
            "total_schedules": stats.total_schedules or 0,
            "active_schedules": stats.active_schedules or 0,
            "recurring_schedules": stats.recurring_schedules or 0,
            "total_executions": stats.total_executions or 0,
            "total_sent": stats.total_sent or 0,
            "total_delivered": stats.total_delivered or 0,
            "total_failed": stats.total_failed or 0,
            "delivery_rate": (
                (stats.total_delivered / stats.total_sent * 100)
                if stats.total_sent and stats.total_sent > 0
                else 0
            ),
        }

    async def expire_old_schedules(self) -> int:
        """Mark expired schedules as expired.

        Returns:
            Number of schedules expired
        """
        now = datetime.utcnow()

        stmt = (
            update(self.model_class)
            .where(
                and_(
                    self.model_class.end_date <= now,
                    self.model_class.status == ScheduleStatus.ACTIVE,
                )
            )
            .values(status=ScheduleStatus.EXPIRED, updated_at=now)
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.rowcount

    def _to_entity(self, model: ScheduleModel) -> NotificationSchedule:
        """Convert database model to domain entity.

        Args:
            model: Database model

        Returns:
            Domain entity
        """
        if not model:
            return None

        # Create entity
        schedule = NotificationSchedule(
            name=model.name,
            template_id=model.template_id,
            channel=model.channel,
            created_by=model.created_by,
            description=model.description,
            cron_expression=model.cron_expression,
            scheduled_at=model.scheduled_at,
            timezone=model.timezone,
            is_recurring=model.is_recurring,
            max_occurrences=model.max_occurrences,
            start_date=model.start_date,
            end_date=model.end_date,
            recipient_query=model.recipient_query,
            recipient_list=model.recipient_list,
            template_variables=model.template_variables,
            entity_id=model.id,
        )

        # Set timestamps
        schedule.created_at = model.created_at
        schedule.updated_at = model.updated_at

        # Set status
        schedule.status = model.status

        # Set execution info
        schedule.occurrences_count = model.occurrences_count
        schedule.last_run_at = model.last_run_at
        schedule.next_run_at = model.next_run_at
        schedule.last_run_status = model.last_run_status
        schedule.last_run_error = model.last_run_error

        # Set statistics
        schedule.total_sent = model.total_sent
        schedule.total_delivered = model.total_delivered
        schedule.total_failed = model.total_failed

        # Set metadata
        if model.metadata:
            schedule.metadata = model.metadata

        return schedule

    def _to_model(self, entity: NotificationSchedule) -> ScheduleModel:
        """Convert domain entity to database model.

        Args:
            entity: Domain entity

        Returns:
            Database model
        """
        return ScheduleModel(
            id=entity.id,
            name=entity.name,
            description=entity.description,
            template_id=entity.template_id,
            channel=entity.channel,
            cron_expression=entity.cron_expression,
            scheduled_at=entity.scheduled_at,
            timezone=entity.timezone,
            is_recurring=entity.is_recurring,
            max_occurrences=entity.max_occurrences,
            occurrences_count=entity.occurrences_count,
            start_date=entity.start_date,
            end_date=entity.end_date,
            recipient_query=entity.recipient_query,
            recipient_list=entity.recipient_list,
            template_variables=entity.template_variables,
            status=entity.status,
            last_run_at=entity.last_run_at,
            next_run_at=entity.next_run_at,
            last_run_status=entity.last_run_status,
            last_run_error=entity.last_run_error,
            total_sent=entity.total_sent,
            total_delivered=entity.total_delivered,
            total_failed=entity.total_failed,
            metadata=getattr(entity, "metadata", None),
            created_by=entity.created_by,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
