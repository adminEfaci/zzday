"""Time range value object.

This module defines the TimeRange value object used for filtering
and querying audit records within specific time periods.
"""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class TimeRange(ValueObject):
    """
    Represents a time range for audit queries and filtering.

    This value object encapsulates a time period with start and end times,
    providing utilities for time-based operations and validations.

    Attributes:
        start_time: Start of the time range (inclusive)
        end_time: End of the time range (exclusive)
        timezone_info: Timezone for the range (defaults to UTC)

    Usage:
        # Specific range
        range = TimeRange(
            start_time=datetime(2024, 1, 1),
            end_time=datetime(2024, 1, 31)
        )

        # Last 24 hours
        range = TimeRange.last_hours(24)

        # This month
        range = TimeRange.current_month()
    """

    def __init__(
        self,
        start_time: datetime,
        end_time: datetime,
        timezone_info: timezone | None = None,
    ):
        """
        Initialize time range.

        Args:
            start_time: Start of the range (inclusive)
            end_time: End of the range (exclusive)
            timezone_info: Optional timezone (defaults to UTC)

        Raises:
            ValidationError: If time range is invalid
        """
        super().__init__()

        # Ensure timezone awareness
        if timezone_info is None:
            timezone_info = UTC

        # Convert to timezone-aware if needed
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone_info)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone_info)

        # Validate time range
        if start_time >= end_time:
            raise ValidationError("Start time must be before end time")
        
        # Validate reasonable duration limits
        duration = end_time - start_time
        max_duration = timedelta(days=3650)  # 10 years max
        if duration > max_duration:
            raise ValidationError("Time range cannot exceed 10 years")
        
        min_duration = timedelta(seconds=1)
        if duration < min_duration:
            raise ValidationError("Time range must be at least 1 second")

        # Set values
        self.start_time = start_time
        self.end_time = end_time
        self.timezone_info = timezone_info

        # Freeze the value object
        self._freeze()

    def duration(self) -> timedelta:
        """Get the duration of the time range."""
        return self.end_time - self.start_time

    def duration_seconds(self) -> float:
        """Get the duration in seconds."""
        return self.duration().total_seconds()

    def duration_hours(self) -> float:
        """Get the duration in hours."""
        return self.duration_seconds() / 3600

    def duration_days(self) -> float:
        """Get the duration in days."""
        return self.duration_seconds() / 86400

    def contains(self, timestamp: datetime) -> bool:
        """
        Check if a timestamp falls within this range.

        Args:
            timestamp: Timestamp to check

        Returns:
            True if timestamp is within range
        """
        # Ensure timezone awareness for comparison
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=self.timezone_info)

        return self.start_time <= timestamp < self.end_time

    def overlaps_with(self, other: "TimeRange") -> bool:
        """
        Check if this range overlaps with another.

        Args:
            other: Another time range

        Returns:
            True if ranges overlap
        """
        return self.start_time < other.end_time and self.end_time > other.start_time

    def intersection(self, other: "TimeRange") -> "TimeRange" | None:
        """
        Get the intersection of this range with another.

        Args:
            other: Another time range

        Returns:
            Intersection range if exists, None otherwise
        """
        if not self.overlaps_with(other):
            return None

        start = max(self.start_time, other.start_time)
        end = min(self.end_time, other.end_time)

        return TimeRange(start, end, self.timezone_info)

    def union(self, other: "TimeRange") -> "TimeRange":
        """
        Get the union of this range with another.

        Args:
            other: Another time range

        Returns:
            Union range covering both ranges
        """
        start = min(self.start_time, other.start_time)
        end = max(self.end_time, other.end_time)

        return TimeRange(start, end, self.timezone_info)

    def split_by_days(self) -> list["TimeRange"]:
        """
        Split the range into daily ranges.

        Returns:
            List of daily time ranges
        """
        ranges = []
        current = self.start_time.replace(hour=0, minute=0, second=0, microsecond=0)

        while current < self.end_time:
            next_day = current + timedelta(days=1)
            range_start = max(current, self.start_time)
            range_end = min(next_day, self.end_time)

            if range_start < range_end:
                ranges.append(TimeRange(range_start, range_end, self.timezone_info))

            current = next_day

        return ranges

    def extend_by(self, duration: timedelta) -> "TimeRange":
        """
        Extend the range by a duration on both sides.

        Args:
            duration: Duration to extend by

        Returns:
            Extended time range
        """
        return TimeRange(
            self.start_time - duration, self.end_time + duration, self.timezone_info
        )

    def shift_by(self, duration: timedelta) -> "TimeRange":
        """
        Shift the entire range by a duration.

        Args:
            duration: Duration to shift by

        Returns:
            Shifted time range
        """
        return TimeRange(
            self.start_time + duration, self.end_time + duration, self.timezone_info
        )

    def to_tuple(self) -> tuple[datetime, datetime]:
        """Get the range as a tuple."""
        return (self.start_time, self.end_time)

    def format_duration(self) -> str:
        """Get a human-readable duration string."""
        total_seconds = self.duration_seconds()

        if total_seconds < 60:
            return f"{int(total_seconds)} seconds"
        if total_seconds < 3600:
            return f"{int(total_seconds / 60)} minutes"
        if total_seconds < 86400:
            return f"{int(total_seconds / 3600)} hours"
        return f"{int(total_seconds / 86400)} days"

    def is_business_hours(self, start_hour: int = 9, end_hour: int = 17) -> bool:
        """Check if the range falls within business hours."""
        start_hour_of_day = self.start_time.hour
        end_hour_of_day = self.end_time.hour
        
        return (
            start_hour_of_day >= start_hour and 
            end_hour_of_day <= end_hour and
            self.start_time.weekday() < 5  # Monday = 0, Sunday = 6
        )

    def is_weekend(self) -> bool:
        """Check if the range falls on a weekend."""
        return self.start_time.weekday() >= 5  # Saturday = 5, Sunday = 6

    def get_business_days_count(self) -> int:
        """Get the number of business days in the range."""
        current = self.start_time.date()
        end_date = self.end_time.date()
        business_days = 0
        
        while current <= end_date:
            if current.weekday() < 5:  # Monday = 0, Friday = 4
                business_days += 1
            current += timedelta(days=1)
        
        return business_days

    def is_recent(self, threshold_hours: int = 24) -> bool:
        """Check if the range is recent (within threshold hours of now)."""
        now = datetime.now(self.timezone_info)
        threshold = timedelta(hours=threshold_hours)
        return (now - self.end_time) <= threshold

    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get atomic values for equality comparison."""
        return (
            self.start_time,
            self.end_time,
            self.timezone_info,
        )

    def __str__(self) -> str:
        """String representation of the time range."""
        return (
            f"{self.start_time.isoformat()} to {self.end_time.isoformat()} "
            f"({self.format_duration()})"
        )

    @classmethod
    def last_hours(cls, hours: int, end_time: datetime | None = None) -> "TimeRange":
        """
        Create a range for the last N hours.

        Args:
            hours: Number of hours
            end_time: End time (defaults to now)

        Returns:
            TimeRange for the last N hours
        """
        if end_time is None:
            end_time = datetime.now(UTC)

        start_time = end_time - timedelta(hours=hours)
        return cls(start_time, end_time)

    @classmethod
    def last_days(cls, days: int, end_time: datetime | None = None) -> "TimeRange":
        """
        Create a range for the last N days.

        Args:
            days: Number of days
            end_time: End time (defaults to now)

        Returns:
            TimeRange for the last N days
        """
        if end_time is None:
            end_time = datetime.now(UTC)

        start_time = end_time - timedelta(days=days)
        return cls(start_time, end_time)

    @classmethod
    def today(cls, timezone_info: timezone | None = None) -> "TimeRange":
        """
        Create a range for today.

        Args:
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange for today
        """
        if timezone_info is None:
            timezone_info = UTC

        now = datetime.now(timezone_info)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)

        return cls(start, end, timezone_info)

    @classmethod
    def current_week(cls, timezone_info: timezone | None = None) -> "TimeRange":
        """
        Create a range for the current week (Monday to Sunday).

        Args:
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange for current week
        """
        if timezone_info is None:
            timezone_info = UTC

        now = datetime.now(timezone_info)
        # Get Monday of current week
        days_since_monday = now.weekday()
        monday = now - timedelta(days=days_since_monday)
        start = monday.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=7)

        return cls(start, end, timezone_info)

    @classmethod
    def current_month(cls, timezone_info: timezone | None = None) -> "TimeRange":
        """
        Create a range for the current month.

        Args:
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange for current month
        """
        if timezone_info is None:
            timezone_info = UTC

        now = datetime.now(timezone_info)
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Calculate first day of next month
        if now.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)

        return cls(start, end, timezone_info)

    @classmethod
    def current_year(cls, timezone_info: timezone | None = None) -> "TimeRange":
        """
        Create a range for the current year.

        Args:
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange for current year
        """
        if timezone_info is None:
            timezone_info = UTC

        now = datetime.now(timezone_info)
        start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end = start.replace(year=start.year + 1)

        return cls(start, end, timezone_info)

    @classmethod
    def last_minutes(cls, minutes: int, end_time: datetime | None = None) -> "TimeRange":
        """
        Create a range for the last N minutes.

        Args:
            minutes: Number of minutes
            end_time: End time (defaults to now)

        Returns:
            TimeRange for the last N minutes
        """
        if end_time is None:
            end_time = datetime.now(UTC)

        start_time = end_time - timedelta(minutes=minutes)
        return cls(start_time, end_time)

    @classmethod
    def business_hours_today(
        cls, 
        start_hour: int = 9, 
        end_hour: int = 17,
        timezone_info: timezone | None = None
    ) -> "TimeRange":
        """
        Create a range for business hours today.

        Args:
            start_hour: Business day start hour (24-hour format)
            end_hour: Business day end hour (24-hour format)
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange for business hours today
        """
        if timezone_info is None:
            timezone_info = UTC

        now = datetime.now(timezone_info)
        start = now.replace(hour=start_hour, minute=0, second=0, microsecond=0)
        end = now.replace(hour=end_hour, minute=0, second=0, microsecond=0)

        return cls(start, end, timezone_info)

    @classmethod
    def from_iso_strings(
        cls, 
        start_iso: str, 
        end_iso: str,
        timezone_info: timezone | None = None
    ) -> "TimeRange":
        """
        Create a range from ISO format strings.

        Args:
            start_iso: Start time in ISO format
            end_iso: End time in ISO format
            timezone_info: Timezone (defaults to UTC)

        Returns:
            TimeRange from ISO strings
        """
        if timezone_info is None:
            timezone_info = UTC

        start_time = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(end_iso.replace('Z', '+00:00'))

        # Ensure timezone awareness
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone_info)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone_info)

        return cls(start_time, end_time, timezone_info)

    @classmethod
    def around_timestamp(
        cls, 
        timestamp: datetime, 
        buffer_minutes: int = 5
    ) -> "TimeRange":
        """
        Create a range around a specific timestamp.

        Args:
            timestamp: Central timestamp
            buffer_minutes: Minutes before and after timestamp

        Returns:
            TimeRange around the timestamp
        """
        buffer = timedelta(minutes=buffer_minutes)
        start_time = timestamp - buffer
        end_time = timestamp + buffer

        return cls(start_time, end_time, timestamp.tzinfo or UTC)


__all__ = ["TimeRange"]
