"""
Notification Scheduling Service Interface

Port for notification scheduling operations including timing,
recurrence, and delivery window management.
"""

from abc import ABC, abstractmethod
from datetime import datetime, time
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.notification.domain.enums import RecurrencePattern


class INotificationSchedulingService(ABC):
    """Port for notification scheduling operations."""
    
    @abstractmethod
    async def schedule_notification(
        self,
        notification_data: dict[str, Any],
        scheduled_for: datetime,
        timezone: str = "UTC"
    ) -> UUID:
        """
        Schedule a notification for future delivery.
        
        Args:
            notification_data: Notification details
            scheduled_for: When to deliver
            timezone: Timezone for scheduling
            
        Returns:
            ID of scheduled notification
            
        Raises:
            InvalidScheduleTimeError: If time is in the past
            SchedulingConflictError: If conflicts with existing schedule
        """
        ...
    
    @abstractmethod
    async def schedule_recurring_notification(
        self,
        notification_data: dict[str, Any],
        pattern: "RecurrencePattern",
        start_date: datetime,
        end_date: datetime | None = None,
        timezone: str = "UTC"
    ) -> UUID:
        """
        Schedule a recurring notification.
        
        Args:
            notification_data: Notification details
            pattern: Recurrence pattern
            start_date: When to start recurrence
            end_date: Optional end date
            timezone: Timezone for scheduling
            
        Returns:
            ID of recurring schedule
            
        Raises:
            InvalidRecurrencePatternError: If pattern is invalid
            InvalidDateRangeError: If date range is invalid
        """
        ...
    
    @abstractmethod
    async def cancel_scheduled_notification(
        self,
        schedule_id: UUID,
        reason: str | None = None
    ) -> bool:
        """
        Cancel a scheduled notification.
        
        Args:
            schedule_id: ID of scheduled notification
            reason: Optional cancellation reason
            
        Returns:
            True if cancelled successfully
            
        Raises:
            ScheduleNotFoundError: If schedule doesn't exist
            AlreadyDeliveredError: If notification was already sent
        """
        ...
    
    @abstractmethod
    async def update_schedule(
        self,
        schedule_id: UUID,
        new_time: datetime,
        timezone: str = "UTC"
    ) -> None:
        """
        Update scheduled delivery time.
        
        Args:
            schedule_id: ID of scheduled notification
            new_time: New delivery time
            timezone: Timezone for new time
            
        Raises:
            ScheduleNotFoundError: If schedule doesn't exist
            InvalidScheduleTimeError: If new time is invalid
        """
        ...
    
    @abstractmethod
    async def calculate_next_delivery_time(
        self,
        pattern: "RecurrencePattern",
        last_delivery: datetime | None,
        timezone: str = "UTC"
    ) -> datetime | None:
        """
        Calculate next delivery time based on pattern.
        
        Args:
            pattern: Recurrence pattern
            last_delivery: Last delivery timestamp
            timezone: Timezone for calculation
            
        Returns:
            Next delivery time or None if no more
        """
        ...
    
    @abstractmethod
    async def apply_delivery_window(
        self,
        scheduled_time: datetime,
        recipient_id: UUID,
        respect_timezone: bool = True
    ) -> datetime:
        """
        Apply recipient's delivery window preferences.
        
        Args:
            scheduled_time: Original scheduled time
            recipient_id: ID of recipient
            respect_timezone: Whether to respect recipient timezone
            
        Returns:
            Adjusted delivery time within window
        """
        ...
    
    @abstractmethod
    async def check_quiet_hours(
        self,
        recipient_id: UUID,
        delivery_time: datetime
    ) -> tuple[bool, datetime | None]:
        """
        Check if delivery time falls within quiet hours.
        
        Args:
            recipient_id: ID of recipient
            delivery_time: Proposed delivery time
            
        Returns:
            Tuple of (is_quiet_hours, suggested_alternative_time)
        """
        ...
    
    @abstractmethod
    async def get_scheduled_notifications(
        self,
        recipient_id: UUID | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        include_recurring: bool = True
    ) -> list[dict[str, Any]]:
        """
        Get scheduled notifications within date range.
        
        Args:
            recipient_id: Optional filter by recipient
            start_date: Optional start date filter
            end_date: Optional end date filter
            include_recurring: Include recurring schedules
            
        Returns:
            List of scheduled notifications
        """
        ...
    
    @abstractmethod
    async def pause_recurring_schedule(
        self,
        schedule_id: UUID,
        until: datetime | None = None
    ) -> None:
        """
        Pause a recurring notification schedule.
        
        Args:
            schedule_id: ID of recurring schedule
            until: Optional resume date
            
        Raises:
            ScheduleNotFoundError: If schedule doesn't exist
            NotRecurringScheduleError: If not a recurring schedule
        """
        ...