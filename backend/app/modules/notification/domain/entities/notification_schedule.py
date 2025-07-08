"""NotificationSchedule entity for managing scheduled notifications.

This entity handles scheduling of notifications for future delivery,
including recurring notifications based on cron expressions or intervals.
"""

import re
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import NotificationChannel, ScheduleStatus
from app.modules.notification.domain.errors import ScheduleError


class NotificationSchedule(Entity):
    """Manages scheduled and recurring notifications.

    This entity handles the scheduling of notifications for future delivery,
    supporting both one-time scheduled notifications and recurring patterns
    using cron expressions or simple intervals.
    """

    def __init__(
        self,
        name: str,
        template_id: UUID,
        recipient_ids: list[UUID],
        channel: NotificationChannel,
        scheduled_at: datetime | None = None,
        recurrence_pattern: str | None = None,
        recurrence_end_date: datetime | None = None,
        timezone: str = "UTC",
        variables: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize notification schedule.

        Args:
            name: Schedule name/description
            template_id: Notification template to use
            recipient_ids: List of recipient IDs
            channel: Notification channel
            scheduled_at: When to send (for one-time)
            recurrence_pattern: Cron expression or interval pattern
            recurrence_end_date: When recurring schedule ends
            timezone: Timezone for scheduling
            variables: Template variables
            metadata: Additional metadata
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Basic fields
        self.name = self._validate_name(name)
        self.template_id = template_id
        self.recipient_ids = self._validate_recipients(recipient_ids)
        self.channel = channel
        self.timezone = timezone
        self.variables = variables or {}
        self.metadata = metadata or {}

        # Scheduling fields
        self.scheduled_at = scheduled_at
        self.recurrence_pattern = recurrence_pattern
        self.recurrence_end_date = recurrence_end_date

        # Validate schedule configuration
        self._validate_schedule_config()

        # Status tracking
        self.status = ScheduleStatus.ACTIVE
        self.last_executed_at: datetime | None = None
        self.next_execution_at: datetime | None = self._calculate_next_execution()

        # Execution tracking
        self.execution_count: int = 0
        self.success_count: int = 0
        self.failure_count: int = 0
        self.execution_history: list[dict[str, Any]] = []

        # Error tracking
        self.last_error: str | None = None
        self.consecutive_failures: int = 0
        self.max_consecutive_failures: int = 5

    def _validate_name(self, name: str) -> str:
        """Validate schedule name."""
        if not name or not name.strip():
            raise ValidationError("Schedule name is required")
        return name.strip()

    def _validate_recipients(self, recipient_ids: list[UUID]) -> list[UUID]:
        """Validate recipient list."""
        if not recipient_ids:
            raise ValidationError("At least one recipient is required")

        # Remove duplicates while preserving order
        seen = set()
        unique_recipients = []
        for recipient_id in recipient_ids:
            if recipient_id not in seen:
                seen.add(recipient_id)
                unique_recipients.append(recipient_id)

        return unique_recipients

    def _validate_schedule_config(self) -> None:
        """Validate schedule configuration."""
        if not self.scheduled_at and not self.recurrence_pattern:
            raise ScheduleError(
                reason="Either scheduled_at or recurrence_pattern must be provided"
            )

        if self.scheduled_at and self.recurrence_pattern:
            raise ScheduleError(
                reason="Cannot specify both scheduled_at and recurrence_pattern"
            )

        # Validate scheduled_at
        if self.scheduled_at and self.scheduled_at <= datetime.utcnow():
            raise ScheduleError(reason="Scheduled time must be in the future")

        # Validate recurrence pattern
        if self.recurrence_pattern:
            self._validate_recurrence_pattern(self.recurrence_pattern)

        # Validate end date
        if self.recurrence_end_date:
            if not self.recurrence_pattern:
                raise ScheduleError(
                    reason="Recurrence end date requires a recurrence pattern"
                )
            if self.recurrence_end_date <= datetime.utcnow():
                raise ScheduleError(reason="Recurrence end date must be in the future")

    def _validate_recurrence_pattern(self, pattern: str) -> None:
        """Validate recurrence pattern format.

        Supports:
        - Simple intervals: "every 1 hour", "every 30 minutes", "every 1 day"
        - Cron expressions: "0 9 * * MON-FRI" (9 AM on weekdays)
        """
        pattern = pattern.strip().lower()

        # Check simple interval pattern
        interval_match = re.match(
            r"^every\s+(\d+)\s+(minute|hour|day|week|month)s?$", pattern
        )
        if interval_match:
            return

        # Check cron pattern (simplified validation)
        cron_parts = pattern.split()
        if len(cron_parts) == 5:
            # Basic cron validation - could be enhanced
            return

        raise ScheduleError(
            reason=f"Invalid recurrence pattern: {pattern}. "
            f"Use 'every N [minute|hour|day|week|month]' or cron expression"
        )

    def _calculate_next_execution(self) -> datetime | None:
        """Calculate next execution time based on schedule configuration."""
        if self.status != ScheduleStatus.ACTIVE:
            return None

        # One-time schedule
        if self.scheduled_at and not self.recurrence_pattern:
            if not self.last_executed_at:
                return self.scheduled_at
            return None  # Already executed

        # Recurring schedule
        if self.recurrence_pattern:
            return self._calculate_next_recurrence()

        return None

    def _calculate_next_recurrence(self) -> datetime | None:
        """Calculate next recurrence based on pattern."""
        if not self.recurrence_pattern:
            return None

        pattern = self.recurrence_pattern.strip().lower()
        now = datetime.utcnow()

        # Parse simple interval
        interval_match = re.match(
            r"^every\s+(\d+)\s+(minute|hour|day|week|month)s?$", pattern
        )
        if interval_match:
            amount = int(interval_match.group(1))
            unit = interval_match.group(2)

            # Calculate base time
            base_time = self.last_executed_at or self.created_at

            # Calculate next execution
            if unit == "minute":
                next_time = base_time + timedelta(minutes=amount)
            elif unit == "hour":
                next_time = base_time + timedelta(hours=amount)
            elif unit == "day":
                next_time = base_time + timedelta(days=amount)
            elif unit == "week":
                next_time = base_time + timedelta(weeks=amount)
            elif unit == "month":
                # Approximate month as 30 days
                next_time = base_time + timedelta(days=30 * amount)
            else:
                return None

            # Ensure next time is in the future
            while next_time <= now:
                if unit == "minute":
                    next_time += timedelta(minutes=amount)
                elif unit == "hour":
                    next_time += timedelta(hours=amount)
                elif unit == "day":
                    next_time += timedelta(days=amount)
                elif unit == "week":
                    next_time += timedelta(weeks=amount)
                elif unit == "month":
                    next_time += timedelta(days=30 * amount)

            # Check end date
            if self.recurrence_end_date and next_time > self.recurrence_end_date:
                return None

            return next_time

        # For cron expressions, would need a cron parser library
        # For now, return None
        return None

    @property
    def is_active(self) -> bool:
        """Check if schedule is active."""
        return self.status.is_executable()

    @property
    def is_recurring(self) -> bool:
        """Check if this is a recurring schedule."""
        return bool(self.recurrence_pattern)

    @property
    def is_expired(self) -> bool:
        """Check if schedule has expired."""
        if self.status == ScheduleStatus.EXPIRED:
            return True

        # Check one-time schedule
        if self.scheduled_at and not self.recurrence_pattern:
            return self.last_executed_at is not None

        # Check recurring schedule end date
        if self.recurrence_end_date:
            return datetime.utcnow() > self.recurrence_end_date

        return False

    @property
    def should_execute_now(self) -> bool:
        """Check if schedule should execute now."""
        if not self.is_active:
            return False

        if not self.next_execution_at:
            return False

        return datetime.utcnow() >= self.next_execution_at

    def execute(self) -> dict[str, Any]:
        """Mark schedule as executed and prepare execution details.

        Returns:
            Execution details for creating notifications
        """
        if not self.should_execute_now:
            raise ScheduleError(
                schedule_id=self.id, reason="Schedule is not ready for execution"
            )

        # Update execution tracking
        self.last_executed_at = datetime.utcnow()
        self.execution_count += 1

        # Calculate next execution for recurring schedules
        if self.is_recurring:
            self.next_execution_at = self._calculate_next_execution()
            if not self.next_execution_at:
                # No more executions
                self.status = ScheduleStatus.COMPLETED
        else:
            # One-time schedule completed
            self.next_execution_at = None
            self.status = ScheduleStatus.COMPLETED

        # Prepare execution details
        execution_details = {
            "schedule_id": self.id,
            "execution_number": self.execution_count,
            "template_id": self.template_id,
            "recipient_ids": self.recipient_ids,
            "channel": self.channel,
            "variables": self.variables,
            "scheduled_for": self.last_executed_at,
            "is_recurring": self.is_recurring,
        }

        self.mark_modified()
        return execution_details

    def record_execution_result(
        self,
        success: bool,
        details: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Record the result of a schedule execution.

        Args:
            success: Whether execution was successful
            details: Execution details (notifications created, etc.)
            error: Error message if failed
        """
        if success:
            self.success_count += 1
            self.consecutive_failures = 0
            self.last_error = None
        else:
            self.failure_count += 1
            self.consecutive_failures += 1
            self.last_error = error

            # Check if too many failures
            if self.consecutive_failures >= self.max_consecutive_failures:
                self.pause(
                    f"Too many consecutive failures ({self.consecutive_failures})"
                )

        # Add to history
        self.execution_history.append(
            {
                "execution_number": self.execution_count,
                "executed_at": self.last_executed_at.isoformat()
                if self.last_executed_at
                else None,
                "success": success,
                "details": details,
                "error": error,
            }
        )

        # Keep only last 100 executions
        if len(self.execution_history) > 100:
            self.execution_history = self.execution_history[-100:]

        self.mark_modified()

    def pause(self, reason: str | None = None) -> None:
        """Pause the schedule.

        Args:
            reason: Reason for pausing
        """
        if self.status.is_final():
            raise ScheduleError(
                schedule_id=self.id,
                reason=f"Cannot pause schedule in {self.status.value} status",
            )

        self.status = ScheduleStatus.PAUSED
        if reason:
            self.add_metadata("pause_reason", reason)
        self.add_metadata("paused_at", datetime.utcnow().isoformat())

        self.mark_modified()

    def resume(self) -> None:
        """Resume a paused schedule."""
        if self.status != ScheduleStatus.PAUSED:
            raise ScheduleError(
                schedule_id=self.id,
                reason=f"Cannot resume schedule in {self.status.value} status",
            )

        # Check if expired
        if self.is_expired:
            self.status = ScheduleStatus.EXPIRED
        else:
            self.status = ScheduleStatus.ACTIVE
            # Recalculate next execution
            self.next_execution_at = self._calculate_next_execution()

        self.add_metadata("resumed_at", datetime.utcnow().isoformat())
        self.mark_modified()

    def cancel(self, reason: str | None = None) -> None:
        """Cancel the schedule.

        Args:
            reason: Cancellation reason
        """
        if self.status.is_final():
            raise ScheduleError(
                schedule_id=self.id,
                reason=f"Cannot cancel schedule in {self.status.value} status",
            )

        self.status = ScheduleStatus.CANCELLED
        self.next_execution_at = None

        if reason:
            self.add_metadata("cancel_reason", reason)
        self.add_metadata("cancelled_at", datetime.utcnow().isoformat())

        self.mark_modified()

    def add_recipient(self, recipient_id: UUID) -> None:
        """Add a recipient to the schedule.

        Args:
            recipient_id: Recipient to add
        """
        if recipient_id not in self.recipient_ids:
            self.recipient_ids.append(recipient_id)
            self.mark_modified()

    def remove_recipient(self, recipient_id: UUID) -> None:
        """Remove a recipient from the schedule.

        Args:
            recipient_id: Recipient to remove
        """
        if recipient_id in self.recipient_ids:
            self.recipient_ids.remove(recipient_id)
            if not self.recipient_ids:
                self.pause("No recipients remaining")
            self.mark_modified()

    def update_variables(self, variables: dict[str, Any]) -> None:
        """Update template variables.

        Args:
            variables: Variables to update/merge
        """
        self.variables.update(variables)
        self.mark_modified()

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to schedule.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
        self.mark_modified()

    def get_execution_stats(self) -> dict[str, Any]:
        """Get execution statistics."""
        success_rate = (
            (self.success_count / self.execution_count * 100)
            if self.execution_count > 0
            else 0
        )

        return {
            "total_executions": self.execution_count,
            "successful_executions": self.success_count,
            "failed_executions": self.failure_count,
            "success_rate": round(success_rate, 2),
            "consecutive_failures": self.consecutive_failures,
            "last_executed_at": (
                self.last_executed_at.isoformat() if self.last_executed_at else None
            ),
            "next_execution_at": (
                self.next_execution_at.isoformat() if self.next_execution_at else None
            ),
            "last_error": self.last_error,
        }

    def __str__(self) -> str:
        """String representation."""
        schedule_type = "Recurring" if self.is_recurring else "One-time"
        return (
            f"NotificationSchedule({self.name}) - "
            f"{schedule_type} - {self.status.value} - "
            f"Recipients: {len(self.recipient_ids)}"
        )
