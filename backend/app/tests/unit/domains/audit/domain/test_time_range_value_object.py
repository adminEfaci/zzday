"""
Comprehensive tests for TimeRange value object.

This module tests the TimeRange value object with complete coverage focusing on:
- Value object immutability
- Time range validation and creation
- Timezone handling and conversions
- Range operations (intersection, union, overlaps)
- Factory methods for common time periods
- Duration calculations and formatting
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.value_objects.time_range import TimeRange


class TestTimeRangeCreation:
    """Test time range creation and initialization."""

    def test_create_time_range_with_timezone_aware_datetimes(self):
        """Test creating time range with timezone-aware datetimes."""
        # Arrange
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)

        # Act
        time_range = TimeRange(start, end)

        # Assert
        assert time_range.start_time == start
        assert time_range.end_time == end
        assert time_range.timezone_info == UTC

    def test_create_time_range_with_naive_datetimes(self):
        """Test creating time range with naive datetimes (auto-converts to UTC)."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0)  # Naive
        end = datetime(2024, 1, 1, 18, 0, 0)  # Naive

        # Act
        time_range = TimeRange(start, end)

        # Assert
        assert time_range.start_time.tzinfo == UTC
        assert time_range.end_time.tzinfo == UTC
        assert time_range.timezone_info == UTC

    def test_create_time_range_with_custom_timezone(self):
        """Test creating time range with custom timezone."""
        # Arrange
        custom_tz = timezone(timedelta(hours=5))  # +05:00
        start = datetime(2024, 1, 1, 12, 0, 0)
        end = datetime(2024, 1, 1, 18, 0, 0)

        # Act
        time_range = TimeRange(start, end, custom_tz)

        # Assert
        assert time_range.start_time.tzinfo == custom_tz
        assert time_range.end_time.tzinfo == custom_tz
        assert time_range.timezone_info == custom_tz

    def test_create_time_range_start_equals_end_raises_error(self):
        """Test that start time equal to end time raises ValidationError."""
        # Arrange
        same_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        # Act & Assert
        with pytest.raises(ValidationError, match="Start time must be before end time"):
            TimeRange(same_time, same_time)

    def test_create_time_range_start_after_end_raises_error(self):
        """Test that start time after end time raises ValidationError."""
        # Arrange
        start = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        # Act & Assert
        with pytest.raises(ValidationError, match="Start time must be before end time"):
            TimeRange(start, end)


class TestTimeRangeImmutability:
    """Test time range value object immutability."""

    def test_time_range_is_frozen_after_creation(self):
        """Test that time range is immutable after creation."""
        # Arrange
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 2, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Act & Assert - Attempting to modify should raise an error
        with pytest.raises(AttributeError):
            time_range.start_time = datetime(2024, 1, 3, tzinfo=UTC)

        with pytest.raises(AttributeError):
            time_range.end_time = datetime(2024, 1, 4, tzinfo=UTC)

        with pytest.raises(AttributeError):
            time_range.new_field = "value"


class TestTimeRangeDuration:
    """Test duration calculations and formatting."""

    def test_duration_calculation(self):
        """Test duration calculation between start and end times."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 30, 45, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Act
        duration = time_range.duration()

        # Assert
        expected_duration = timedelta(hours=6, minutes=30, seconds=45)
        assert duration == expected_duration

    def test_duration_seconds(self):
        """Test duration in seconds."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 12, 5, 30, tzinfo=UTC)  # 5.5 minutes
        time_range = TimeRange(start, end)

        # Act
        duration_seconds = time_range.duration_seconds()

        # Assert
        assert duration_seconds == 330.0  # 5.5 * 60

    def test_duration_hours(self):
        """Test duration in hours."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 15, 30, 0, tzinfo=UTC)  # 3.5 hours
        time_range = TimeRange(start, end)

        # Act
        duration_hours = time_range.duration_hours()

        # Assert
        assert duration_hours == 3.5

    def test_duration_days(self):
        """Test duration in days."""
        # Arrange
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 3, 12, 0, 0, tzinfo=UTC)  # 2.5 days
        time_range = TimeRange(start, end)

        # Act
        duration_days = time_range.duration_days()

        # Assert
        assert duration_days == 2.5

    @pytest.mark.parametrize(
        ("total_seconds", "expected_format"),
        [
            (30, "30 seconds"),
            (90, "1 minutes"),
            (3600, "1 hours"),
            (7200, "2 hours"),
            (86400, "1 days"),
            (172800, "2 days"),
        ],
    )
    def test_format_duration(self, total_seconds, expected_format):
        """Test duration formatting."""
        # Arrange
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = start + timedelta(seconds=total_seconds)
        time_range = TimeRange(start, end)

        # Act
        formatted = time_range.format_duration()

        # Assert
        assert formatted == expected_format


class TestTimeRangeContains:
    """Test timestamp containment checking."""

    def test_contains_timestamp_within_range(self):
        """Test that timestamp within range returns True."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Test various timestamps within range
        test_timestamps = [
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),  # Start (inclusive)
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),  # Middle
            datetime(2024, 1, 1, 17, 59, 59, tzinfo=UTC),  # Just before end
        ]

        # Act & Assert
        for timestamp in test_timestamps:
            assert time_range.contains(timestamp)

    def test_contains_timestamp_outside_range(self):
        """Test that timestamp outside range returns False."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Test various timestamps outside range
        test_timestamps = [
            datetime(2024, 1, 1, 11, 59, 59, tzinfo=UTC),  # Before start
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),  # End (exclusive)
            datetime(2024, 1, 1, 19, 0, 0, tzinfo=UTC),  # After end
        ]

        # Act & Assert
        for timestamp in test_timestamps:
            assert not time_range.contains(timestamp)

    def test_contains_naive_timestamp_auto_converts(self):
        """Test that naive timestamps are auto-converted for comparison."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Act & Assert
        naive_timestamp = datetime(2024, 1, 1, 15, 0, 0)  # Naive, but within range
        assert time_range.contains(naive_timestamp)


class TestTimeRangeOverlaps:
    """Test overlap detection between time ranges."""

    def test_overlaps_with_overlapping_ranges(self):
        """Test overlap detection with overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act & Assert
        assert range1.overlaps_with(range2)
        assert range2.overlaps_with(range1)  # Symmetric

    def test_overlaps_with_non_overlapping_ranges(self):
        """Test overlap detection with non-overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act & Assert
        assert not range1.overlaps_with(range2)
        assert not range2.overlaps_with(range1)  # Symmetric

    def test_overlaps_with_adjacent_ranges(self):
        """Test overlap detection with adjacent ranges (should not overlap)."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),  # Starts where range1 ends
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )

        # Act & Assert
        assert not range1.overlaps_with(range2)  # End is exclusive
        assert not range2.overlaps_with(range1)


class TestTimeRangeIntersection:
    """Test intersection operations between time ranges."""

    def test_intersection_with_overlapping_ranges(self):
        """Test intersection with overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act
        intersection = range1.intersection(range2)

        # Assert
        assert intersection is not None
        assert intersection.start_time == datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC)
        assert intersection.end_time == datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)

    def test_intersection_with_non_overlapping_ranges(self):
        """Test intersection with non-overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act
        intersection = range1.intersection(range2)

        # Assert
        assert intersection is None

    def test_intersection_with_contained_range(self):
        """Test intersection where one range is contained in another."""
        # Arrange
        outer_range = TimeRange(
            datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 20, 0, 0, tzinfo=UTC),
        )
        inner_range = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )

        # Act
        intersection = outer_range.intersection(inner_range)

        # Assert
        assert intersection is not None
        assert intersection.start_time == inner_range.start_time
        assert intersection.end_time == inner_range.end_time


class TestTimeRangeUnion:
    """Test union operations between time ranges."""

    def test_union_with_overlapping_ranges(self):
        """Test union with overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act
        union = range1.union(range2)

        # Assert
        assert union.start_time == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert union.end_time == datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC)

    def test_union_with_non_overlapping_ranges(self):
        """Test union with non-overlapping ranges."""
        # Arrange
        range1 = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC),
        )
        range2 = TimeRange(
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC),
        )

        # Act
        union = range1.union(range2)

        # Assert
        assert union.start_time == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert union.end_time == datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC)


class TestTimeRangeSplitting:
    """Test time range splitting operations."""

    def test_split_by_days_single_day(self):
        """Test splitting a single-day range."""
        # Arrange
        time_range = TimeRange(
            datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )

        # Act
        daily_ranges = time_range.split_by_days()

        # Assert
        assert len(daily_ranges) == 1
        assert daily_ranges[0].start_time == time_range.start_time
        assert daily_ranges[0].end_time == time_range.end_time

    def test_split_by_days_multiple_days(self):
        """Test splitting a multi-day range."""
        # Arrange
        time_range = TimeRange(
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 3, 10, 0, 0, tzinfo=UTC),
        )

        # Act
        daily_ranges = time_range.split_by_days()

        # Assert
        assert len(daily_ranges) == 3

        # First day: from 18:00 to midnight
        assert daily_ranges[0].start_time == datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        assert daily_ranges[0].end_time == datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)

        # Full middle day
        assert daily_ranges[1].start_time == datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)
        assert daily_ranges[1].end_time == datetime(2024, 1, 3, 0, 0, 0, tzinfo=UTC)

        # Last day: from midnight to 10:00
        assert daily_ranges[2].start_time == datetime(2024, 1, 3, 0, 0, 0, tzinfo=UTC)
        assert daily_ranges[2].end_time == datetime(2024, 1, 3, 10, 0, 0, tzinfo=UTC)

    def test_split_by_days_across_midnight(self):
        """Test splitting range that crosses midnight boundary."""
        # Arrange
        time_range = TimeRange(
            datetime(2024, 1, 1, 23, 30, 0, tzinfo=UTC),
            datetime(2024, 1, 2, 1, 30, 0, tzinfo=UTC),
        )

        # Act
        daily_ranges = time_range.split_by_days()

        # Assert
        assert len(daily_ranges) == 2

        # First day: 23:30 to midnight
        assert daily_ranges[0].start_time == datetime(2024, 1, 1, 23, 30, 0, tzinfo=UTC)
        assert daily_ranges[0].end_time == datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)

        # Second day: midnight to 01:30
        assert daily_ranges[1].start_time == datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)
        assert daily_ranges[1].end_time == datetime(2024, 1, 2, 1, 30, 0, tzinfo=UTC)


class TestTimeRangeTransformations:
    """Test time range transformation methods."""

    def test_extend_by(self):
        """Test extending range by duration."""
        # Arrange
        original_range = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )
        extension = timedelta(hours=2)

        # Act
        extended_range = original_range.extend_by(extension)

        # Assert
        assert extended_range.start_time == datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        assert extended_range.end_time == datetime(2024, 1, 1, 20, 0, 0, tzinfo=UTC)

        # Original should remain unchanged
        assert original_range.start_time == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert original_range.end_time == datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)

    def test_shift_by(self):
        """Test shifting range by duration."""
        # Arrange
        original_range = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )
        shift = timedelta(hours=3)

        # Act
        shifted_range = original_range.shift_by(shift)

        # Assert
        assert shifted_range.start_time == datetime(2024, 1, 1, 15, 0, 0, tzinfo=UTC)
        assert shifted_range.end_time == datetime(2024, 1, 1, 21, 0, 0, tzinfo=UTC)

        # Duration should remain the same
        assert shifted_range.duration() == original_range.duration()


class TestTimeRangeUtilityMethods:
    """Test utility and conversion methods."""

    def test_to_tuple(self):
        """Test conversion to tuple."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Act
        tuple_result = time_range.to_tuple()

        # Assert
        assert tuple_result == (start, end)
        assert isinstance(tuple_result, tuple)
        assert len(tuple_result) == 2

    def test_str_representation(self):
        """Test string representation."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)
        time_range = TimeRange(start, end)

        # Act
        string_repr = str(time_range)

        # Assert
        assert "2024-01-01T12:00:00+00:00" in string_repr
        assert "2024-01-01T18:00:00+00:00" in string_repr
        assert "6 hours" in string_repr


class TestTimeRangeFactoryMethods:
    """Test factory methods for common time ranges."""

    def test_last_hours_default_end_time(self):
        """Test last_hours factory method with default end time."""
        # Act
        time_range = TimeRange.last_hours(6)

        # Assert
        duration = time_range.duration_hours()
        assert abs(duration - 6.0) < 0.01  # Allow small timing differences
        assert time_range.end_time.tzinfo == UTC

    def test_last_hours_custom_end_time(self):
        """Test last_hours factory method with custom end time."""
        # Arrange
        end_time = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)

        # Act
        time_range = TimeRange.last_hours(4, end_time)

        # Assert
        assert time_range.end_time == end_time
        assert time_range.start_time == datetime(2024, 1, 1, 14, 0, 0, tzinfo=UTC)
        assert time_range.duration_hours() == 4.0

    def test_last_days_default_end_time(self):
        """Test last_days factory method with default end time."""
        # Act
        time_range = TimeRange.last_days(7)

        # Assert
        duration = time_range.duration_days()
        assert abs(duration - 7.0) < 0.01  # Allow small timing differences
        assert time_range.end_time.tzinfo == UTC

    def test_last_days_custom_end_time(self):
        """Test last_days factory method with custom end time."""
        # Arrange
        end_time = datetime(2024, 1, 8, 0, 0, 0, tzinfo=UTC)

        # Act
        time_range = TimeRange.last_days(3, end_time)

        # Assert
        assert time_range.end_time == end_time
        assert time_range.start_time == datetime(2024, 1, 5, 0, 0, 0, tzinfo=UTC)
        assert time_range.duration_days() == 3.0

    def test_today_default_timezone(self):
        """Test today factory method with default timezone."""
        # Act
        time_range = TimeRange.today()

        # Assert
        assert time_range.timezone_info == UTC
        assert time_range.duration_hours() == 24.0
        assert time_range.start_time.hour == 0
        assert time_range.start_time.minute == 0
        assert time_range.start_time.second == 0

    def test_today_custom_timezone(self):
        """Test today factory method with custom timezone."""
        # Arrange
        custom_tz = timezone(timedelta(hours=5))

        # Act
        time_range = TimeRange.today(custom_tz)

        # Assert
        assert time_range.timezone_info == custom_tz
        assert time_range.start_time.tzinfo == custom_tz
        assert time_range.end_time.tzinfo == custom_tz
        assert time_range.duration_hours() == 24.0

    def test_current_week(self):
        """Test current_week factory method."""
        # Act
        time_range = TimeRange.current_week()

        # Assert
        assert time_range.duration_days() == 7.0
        assert time_range.start_time.weekday() == 0  # Monday
        assert time_range.start_time.hour == 0
        assert time_range.start_time.minute == 0
        assert time_range.timezone_info == UTC

    def test_current_month(self):
        """Test current_month factory method."""
        # Act
        time_range = TimeRange.current_month()

        # Assert
        assert time_range.start_time.day == 1  # First day of month
        assert time_range.start_time.hour == 0
        assert time_range.start_time.minute == 0
        assert time_range.timezone_info == UTC

        # Duration should be at least 28 days (minimum month length)
        assert time_range.duration_days() >= 28


class TestTimeRangeEquality:
    """Test equality and comparison of time ranges."""

    def test_time_ranges_equal_when_same_values(self):
        """Test that time ranges with same values are equal."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)

        range1 = TimeRange(start, end)
        range2 = TimeRange(start, end)

        # Act & Assert
        assert range1 == range2
        assert hash(range1) == hash(range2)

    def test_time_ranges_not_equal_when_different_values(self):
        """Test that time ranges with different values are not equal."""
        # Arrange
        start1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end1 = datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC)

        start2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC)
        end2 = datetime(2024, 1, 2, 18, 0, 0, tzinfo=UTC)

        range1 = TimeRange(start1, end1)
        range2 = TimeRange(start2, end2)

        # Act & Assert
        assert range1 != range2
        assert hash(range1) != hash(range2)


class TestTimeRangeEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_short_duration(self):
        """Test time range with very short duration."""
        # Arrange
        start = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = start + timedelta(microseconds=1)  # 1 microsecond

        # Act
        time_range = TimeRange(start, end)

        # Assert
        assert time_range.duration_seconds() == 0.000001

    def test_very_long_duration(self):
        """Test time range with very long duration."""
        # Arrange
        start = datetime(2000, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 1, tzinfo=UTC)  # 24 years

        # Act
        time_range = TimeRange(start, end)

        # Assert
        assert time_range.duration_days() > 8000  # ~24 years

    def test_cross_year_boundary(self):
        """Test time range crossing year boundary."""
        # Arrange
        start = datetime(2023, 12, 31, 23, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 1, 0, 0, tzinfo=UTC)

        # Act
        time_range = TimeRange(start, end)

        # Assert
        assert time_range.duration_hours() == 2.0
        assert time_range.contains(datetime(2024, 1, 1, 0, 30, 0, tzinfo=UTC))

    def test_leap_year_february(self):
        """Test time range in leap year February."""
        # Arrange - 2024 is a leap year
        start = datetime(2024, 2, 28, tzinfo=UTC)
        end = datetime(2024, 3, 1, tzinfo=UTC)

        # Act
        time_range = TimeRange(start, end)
        daily_ranges = time_range.split_by_days()

        # Assert
        assert time_range.duration_days() == 2.0  # Feb 28, Feb 29
        assert len(daily_ranges) == 2
        assert time_range.contains(datetime(2024, 2, 29, 12, 0, 0, tzinfo=UTC))

    def test_different_timezones_comparison(self):
        """Test comparison of ranges in different timezones."""
        # Arrange
        utc_range = TimeRange(
            datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            datetime(2024, 1, 1, 18, 0, 0, tzinfo=UTC),
        )

        # Same time but different timezone representation
        est_tz = timezone(timedelta(hours=-5))
        est_range = TimeRange(
            datetime(2024, 1, 1, 7, 0, 0, tzinfo=est_tz),  # 12:00 UTC
            datetime(2024, 1, 1, 13, 0, 0, tzinfo=est_tz),  # 18:00 UTC
        )

        # Act & Assert
        assert utc_range.overlaps_with(est_range)
        intersection = utc_range.intersection(est_range)
        assert intersection is not None
