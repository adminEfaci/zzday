"""Scheduler service for notification scheduling and recurring notifications."""

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import UUID

from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from croniter import croniter

from app.core.infrastructure.config import settings
from app.modules.notification.domain.enums import ScheduleStatus

# Constants
SCHEDULE_ID_PARTS = 2
CRON_PARTS_COUNT = 5


class SchedulerService:
    """Service for managing notification schedules."""

    def __init__(
        self, redis_url: str | None = None, scheduler: AsyncIOScheduler | None = None
    ):
        """Initialize scheduler service.

        Args:
            redis_url: Redis connection URL for job persistence
            scheduler: Optional pre-configured scheduler
        """
        self.redis_url = redis_url or settings.REDIS_URL

        if scheduler:
            self.scheduler = scheduler
        else:
            self.scheduler = self._create_scheduler()

        self._job_callbacks: dict[str, Callable] = {}

    def _create_scheduler(self) -> AsyncIOScheduler:
        """Create and configure scheduler."""
        # Configure job stores
        jobstores = {}
        if self.redis_url:
            jobstores["default"] = RedisJobStore(
                jobs_key="apscheduler.jobs",
                run_times_key="apscheduler.run_times",
                url=self.redis_url,
            )

        # Configure executors
        executors = {
            "default": AsyncIOExecutor(),
        }

        # Configure job defaults
        job_defaults = {
            "coalesce": True,
            "max_instances": 3,
            "misfire_grace_time": 300,  # 5 minutes
        }

        # Create scheduler
        return AsyncIOScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone="UTC",
        )

    async def start(self) -> None:
        """Start the scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()

    async def shutdown(self) -> None:
        """Shutdown the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)

    async def schedule_notification(
        self,
        schedule_id: UUID,
        notification_callback: Callable,
        scheduled_at: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Schedule a one-time notification.

        Args:
            schedule_id: Schedule ID
            notification_callback: Callback function to execute
            scheduled_at: When to send the notification
            metadata: Optional metadata

        Returns:
            Job ID
        """
        job_id = f"notification_{schedule_id}"

        # Store callback
        self._job_callbacks[job_id] = notification_callback

        # Schedule job
        job = self.scheduler.add_job(
            self._execute_notification,
            "date",
            run_date=scheduled_at,
            id=job_id,
            args=[schedule_id, metadata],
            replace_existing=True,
            misfire_grace_time=300,
        )

        return job.id

    async def schedule_recurring_notification(
        self,
        schedule_id: UUID,
        notification_callback: Callable,
        cron_expression: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        timezone: str = "UTC",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Schedule a recurring notification.

        Args:
            schedule_id: Schedule ID
            notification_callback: Callback function to execute
            cron_expression: Cron expression for recurrence
            start_date: When to start the schedule
            end_date: When to end the schedule
            timezone: Timezone for the schedule
            metadata: Optional metadata

        Returns:
            Job ID
        """
        job_id = f"recurring_{schedule_id}"

        # Validate cron expression
        if not self._validate_cron_expression(cron_expression):
            raise ValueError(f"Invalid cron expression: {cron_expression}")

        # Store callback
        self._job_callbacks[job_id] = notification_callback

        # Parse cron expression to APScheduler format
        cron_fields = self._parse_cron_expression(cron_expression)

        # Schedule job
        job = self.scheduler.add_job(
            self._execute_notification,
            "cron",
            **cron_fields,
            id=job_id,
            args=[schedule_id, metadata],
            start_date=start_date,
            end_date=end_date,
            timezone=timezone,
            replace_existing=True,
            misfire_grace_time=300,
        )

        return job.id

    async def pause_schedule(self, schedule_id: UUID) -> bool:
        """Pause a schedule.

        Args:
            schedule_id: Schedule ID

        Returns:
            True if paused successfully
        """
        job_ids = [f"notification_{schedule_id}", f"recurring_{schedule_id}"]

        paused = False
        for job_id in job_ids:
            job = self.scheduler.get_job(job_id)
            if job:
                job.pause()
                paused = True

        return paused

    async def resume_schedule(self, schedule_id: UUID) -> bool:
        """Resume a paused schedule.

        Args:
            schedule_id: Schedule ID

        Returns:
            True if resumed successfully
        """
        job_ids = [f"notification_{schedule_id}", f"recurring_{schedule_id}"]

        resumed = False
        for job_id in job_ids:
            job = self.scheduler.get_job(job_id)
            if job:
                job.resume()
                resumed = True

        return resumed

    async def cancel_schedule(self, schedule_id: UUID) -> bool:
        """Cancel a schedule.

        Args:
            schedule_id: Schedule ID

        Returns:
            True if cancelled successfully
        """
        job_ids = [f"notification_{schedule_id}", f"recurring_{schedule_id}"]

        cancelled = False
        for job_id in job_ids:
            if self.scheduler.get_job(job_id):
                self.scheduler.remove_job(job_id)
                if job_id in self._job_callbacks:
                    del self._job_callbacks[job_id]
                cancelled = True

        return cancelled

    async def reschedule_notification(
        self, schedule_id: UUID, new_scheduled_at: datetime
    ) -> bool:
        """Reschedule a one-time notification.

        Args:
            schedule_id: Schedule ID
            new_scheduled_at: New schedule time

        Returns:
            True if rescheduled successfully
        """
        job_id = f"notification_{schedule_id}"
        job = self.scheduler.get_job(job_id)

        if job:
            job.reschedule("date", run_date=new_scheduled_at)
            return True

        return False

    async def update_recurring_schedule(
        self,
        schedule_id: UUID,
        cron_expression: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> bool:
        """Update a recurring schedule.

        Args:
            schedule_id: Schedule ID
            cron_expression: New cron expression
            start_date: New start date
            end_date: New end date

        Returns:
            True if updated successfully
        """
        job_id = f"recurring_{schedule_id}"
        job = self.scheduler.get_job(job_id)

        if not job:
            return False

        if cron_expression:
            if not self._validate_cron_expression(cron_expression):
                raise ValueError(f"Invalid cron expression: {cron_expression}")

            cron_fields = self._parse_cron_expression(cron_expression)
            job.reschedule("cron", **cron_fields)

        if start_date:
            job.modify(start_date=start_date)

        if end_date:
            job.modify(end_date=end_date)

        return True

    async def get_schedule_info(self, schedule_id: UUID) -> dict[str, Any] | None:
        """Get information about a schedule.

        Args:
            schedule_id: Schedule ID

        Returns:
            Schedule information if found
        """
        job_ids = [f"notification_{schedule_id}", f"recurring_{schedule_id}"]

        for job_id in job_ids:
            job = self.scheduler.get_job(job_id)
            if job:
                return {
                    "job_id": job.id,
                    "schedule_id": str(schedule_id),
                    "next_run_time": job.next_run_time.isoformat()
                    if job.next_run_time
                    else None,
                    "trigger_type": job.trigger.__class__.__name__.lower().replace(
                        "trigger", ""
                    ),
                    "is_paused": job.next_run_time is None and hasattr(job, "paused"),
                    "start_date": job.start_date.isoformat()
                    if hasattr(job, "start_date") and job.start_date
                    else None,
                    "end_date": job.end_date.isoformat()
                    if hasattr(job, "end_date") and job.end_date
                    else None,
                    "misfire_grace_time": job.misfire_grace_time,
                    "max_instances": job.max_instances,
                }

        return None

    async def get_next_run_time(self, schedule_id: UUID) -> datetime | None:
        """Get next run time for a schedule.

        Args:
            schedule_id: Schedule ID

        Returns:
            Next run time if scheduled
        """
        info = await self.get_schedule_info(schedule_id)
        if info and info["next_run_time"]:
            return datetime.fromisoformat(info["next_run_time"])
        return None

    async def get_all_schedules(
        self, status: ScheduleStatus | None = None
    ) -> list[dict[str, Any]]:
        """Get all active schedules.

        Args:
            status: Optional status filter

        Returns:
            List of schedule information
        """
        schedules = []

        for job in self.scheduler.get_jobs():
            if job.id.startswith(("notification_", "recurring_")):
                # Extract schedule ID
                parts = job.id.split("_", 1)
                if len(parts) == SCHEDULE_ID_PARTS:
                    schedule_type = parts[0]
                    schedule_id = parts[1]

                    info = {
                        "job_id": job.id,
                        "schedule_id": schedule_id,
                        "schedule_type": schedule_type,
                        "next_run_time": job.next_run_time.isoformat()
                        if job.next_run_time
                        else None,
                        "is_paused": job.next_run_time is None,
                    }

                    # Filter by status if specified
                    if status:
                        if (
                            status == ScheduleStatus.ACTIVE and not info["is_paused"]
                        ) or (status == ScheduleStatus.PAUSED and info["is_paused"]):
                            schedules.append(info)
                    else:
                        schedules.append(info)

        return schedules

    async def _execute_notification(
        self, schedule_id: UUID, metadata: dict[str, Any] | None = None
    ) -> None:
        """Execute scheduled notification callback.

        Args:
            schedule_id: Schedule ID
            metadata: Optional metadata
        """
        job_id = None

        # Find the job ID
        for jid in self._job_callbacks:
            if str(schedule_id) in jid:
                job_id = jid
                break

        if job_id and job_id in self._job_callbacks:
            callback = self._job_callbacks[job_id]
            try:
                # Execute callback
                if asyncio.iscoroutinefunction(callback):
                    await callback(schedule_id, metadata)
                else:
                    callback(schedule_id, metadata)
            except Exception as e:
                # Log error
                print(f"Error executing scheduled notification {schedule_id}: {e}")
                # Re-raise to let APScheduler handle retries
                raise

    def _validate_cron_expression(self, expression: str) -> bool:
        """Validate cron expression.

        Args:
            expression: Cron expression

        Returns:
            True if valid
        """
        try:
            croniter(expression)
            return True
        except (ValueError, TypeError, ImportError):
            return False

    def _parse_cron_expression(self, expression: str) -> dict[str, Any]:
        """Parse cron expression to APScheduler format.

        Args:
            expression: Cron expression

        Returns:
            Dictionary with cron fields
        """
        # Parse standard cron expression (minute hour day month day_of_week)
        parts = expression.split()

        if len(parts) != CRON_PARTS_COUNT:
            raise ValueError("Invalid cron expression format")

        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "day_of_week": parts[4],
        }

    async def calculate_next_runs(
        self, cron_expression: str, start_date: datetime | None = None, count: int = 5
    ) -> list[datetime]:
        """Calculate next run times for a cron expression.

        Args:
            cron_expression: Cron expression
            start_date: Start date for calculation
            count: Number of occurrences to calculate

        Returns:
            List of next run times
        """
        if not self._validate_cron_expression(cron_expression):
            raise ValueError(f"Invalid cron expression: {cron_expression}")

        base_time = start_date or datetime.utcnow()
        cron = croniter(cron_expression, base_time)

        run_times = []
        for _ in range(count):
            run_times.append(cron.get_next(datetime))

        return run_times
