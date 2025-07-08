"""Date/time utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic date/time utilities that follow Domain-Driven Design
principles. All date processors are pure Python classes that can be used across different layers
of the application without tight coupling to any specific framework.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static utility methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

from datetime import UTC, date, datetime, timedelta, timezone

from dateutil import parser
from dateutil.relativedelta import relativedelta
from pytz import timezone as pytz_timezone

from app.core.constants import DEFAULT_TIMEZONE
from app.core.errors import ValidationError

# =====================================================================================
# DATE/TIME PROCESSING CLASSES
# =====================================================================================


class DateParser:
    """Date parsing with multiple format support and rich functionality."""

    def __init__(
        self,
        date_string: str,
        formats: list[str] | None = None,
        default_timezone: str | None = None,
    ):
        """
        Initialize and parse date string.

        Args:
            date_string: Date string to parse
            formats: List of date formats to try
            default_timezone: Default timezone if none specified

        Raises:
            ValidationError: If date string cannot be parsed
        """
        if not date_string or not isinstance(date_string, str):
            raise ValidationError("Date string cannot be empty")

        self.original_string = date_string
        self.formats = formats or []
        self.default_timezone = default_timezone or DEFAULT_TIMEZONE
        self.value = self._parse_date()

    def _parse_date(self) -> datetime:
        """Parse date string to datetime."""
        # Try provided formats first
        for fmt in self.formats:
            try:
                parsed = datetime.strptime(self.original_string, fmt)
                # Add timezone if not present
                if parsed.tzinfo is None:
                    tz = pytz_timezone(self.default_timezone)
                    parsed = tz.localize(parsed)
                return parsed
            except ValueError:
                continue

        # Fall back to dateutil parser
        try:
            parsed = parser.parse(self.original_string)
            # Add timezone if not present
            if parsed.tzinfo is None:
                tz = pytz_timezone(self.default_timezone)
                parsed = tz.localize(parsed)
            return parsed
        except (ValueError, parser.ParserError) as e:
            raise ValidationError(
                f"Could not parse date string '{self.original_string}': {e!s}"
            )

    @staticmethod
    def parse_date(
        date_string: str, formats: list[str] | None = None
    ) -> datetime | None:
        """
        Static method to parse date string.

        Args:
            date_string: Date string to parse
            formats: List of formats to try

        Returns:
            datetime or None if parsing fails
        """
        try:
            parser_obj = DateParser(date_string, formats)
            return parser_obj.value
        except ValidationError:
            return None

    @staticmethod
    def is_valid_date_string(
        date_string: str, formats: list[str] | None = None
    ) -> bool:
        """
        Check if date string is valid.

        Args:
            date_string: Date string to check
            formats: Formats to try

        Returns:
            bool: True if valid
        """
        return DateParser.parse_date(date_string, formats) is not None

    @property
    def is_weekend(self) -> bool:
        """Check if date falls on weekend."""
        return self.value.weekday() >= 5

    def to_iso_string(self) -> str:
        """Convert to ISO format string."""
        return self.value.isoformat()

    def __str__(self) -> str:
        """String representation."""
        return self.value.isoformat()

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, DateParser):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"DateParser('{self.original_string}' -> {self.value.isoformat()})"


class RelativeTimeFormatter:
    """Relative time formatting with rich functionality."""

    def __init__(self, dt: datetime, reference: datetime | None = None):
        """
        Initialize relative time formatter.

        Args:
            dt: Datetime to format
            reference: Reference datetime (default: now UTC)

        Raises:
            ValidationError: If datetime is invalid
        """
        if not isinstance(dt, datetime):
            raise ValidationError("DateTime must be a datetime object")

        self.dt = dt
        self.reference = reference or datetime.now(UTC)

        # Ensure both are timezone aware
        if self.dt.tzinfo is None:
            self.dt = self.dt.replace(tzinfo=UTC)
        if self.reference.tzinfo is None:
            self.reference = self.reference.replace(tzinfo=UTC)

        self.delta = self.reference - self.dt
        self.value = self._format_relative_time()

    def _format_relative_time(self) -> str:
        """Format datetime as relative time."""
        # Future dates
        if self.delta.total_seconds() < 0:
            delta = abs(self.delta)
            suffix = "from now"
        else:
            delta = self.delta
            suffix = "ago"

        # Format based on duration
        seconds = int(delta.total_seconds())

        if seconds < 60:
            return "just now" if suffix == "ago" else "in a moment"

        minutes = seconds // 60
        if minutes < 60:
            unit = "minute" if minutes == 1 else "minutes"
            return f"{minutes} {unit} {suffix}"

        hours = minutes // 60
        if hours < 24:
            unit = "hour" if hours == 1 else "hours"
            return f"{hours} {unit} {suffix}"

        days = hours // 24
        if days < 30:
            unit = "day" if days == 1 else "days"
            return f"{days} {unit} {suffix}"

        months = days // 30
        if months < 12:
            unit = "month" if months == 1 else "months"
            return f"{months} {unit} {suffix}"

        years = months // 12
        unit = "year" if years == 1 else "years"
        return f"{years} {unit} {suffix}"

    @staticmethod
    def format_relative_time(dt: datetime, reference: datetime | None = None) -> str:
        """
        Static method to format relative time.

        Args:
            dt: DateTime to format
            reference: Reference datetime

        Returns:
            str: Relative time string
        """
        try:
            formatter = RelativeTimeFormatter(dt, reference)
            return formatter.value
        except ValidationError:
            return "unknown time"

    @property
    def is_future(self) -> bool:
        """Check if datetime is in the future."""
        return self.delta.total_seconds() < 0

    @property
    def total_days(self) -> float:
        """Get total days difference."""
        return abs(self.delta.total_seconds()) / (24 * 60 * 60)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, RelativeTimeFormatter):
            return False
        return self.dt == other.dt and self.reference == other.reference

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.dt, self.reference))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"RelativeTimeFormatter('{self.value}', {self.total_days:.1f} days)"


class BusinessDaysCalculator:
    """Business days calculation with holiday support and rich functionality."""

    def __init__(
        self, start_date: date, end_date: date, holidays: list[date] | None = None
    ):
        """
        Initialize business days calculator.

        Args:
            start_date: Start date
            end_date: End date
            holidays: List of holiday dates to exclude

        Raises:
            ValidationError: If dates are invalid
        """
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise ValidationError("Start and end dates must be date objects")

        # Swap if start > end
        if start_date > end_date:
            start_date, end_date = end_date, start_date

        self.start_date = start_date
        self.end_date = end_date
        self.holidays = set(holidays or [])
        self.business_days = self._calculate_business_days()

    def _calculate_business_days(self) -> int:
        """Calculate number of business days between dates."""
        business_days = 0
        current = self.start_date

        while current <= self.end_date:
            # Monday = 0, Sunday = 6
            if current.weekday() < 5 and current not in self.holidays:
                business_days += 1
            current += timedelta(days=1)

        return business_days

    @staticmethod
    def get_business_days(
        start_date: date, end_date: date, holidays: list[date] | None = None
    ) -> int:
        """
        Static method to calculate business days.

        Args:
            start_date: Start date
            end_date: End date
            holidays: Holiday dates to exclude

        Returns:
            int: Number of business days
        """
        try:
            calculator = BusinessDaysCalculator(start_date, end_date, holidays)
            return calculator.business_days
        except ValidationError:
            return 0

    @staticmethod
    def is_business_day(check_date: date, holidays: list[date] | None = None) -> bool:
        """
        Check if date is a business day.

        Args:
            check_date: Date to check
            holidays: Holiday dates to exclude

        Returns:
            bool: True if business day
        """
        holidays = set(holidays or [])
        return check_date.weekday() < 5 and check_date not in holidays

    @property
    def total_days(self) -> int:
        """Get total days in range."""
        return (self.end_date - self.start_date).days + 1

    @property
    def weekend_days(self) -> int:
        """Get number of weekend days."""
        weekend_count = 0
        current = self.start_date
        while current <= self.end_date:
            if current.weekday() >= 5:  # Saturday or Sunday
                weekend_count += 1
            current += timedelta(days=1)
        return weekend_count

    def __str__(self) -> str:
        """String representation."""
        return f"{self.business_days} business days"

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, BusinessDaysCalculator):
            return False
        return (
            self.start_date == other.start_date
            and self.end_date == other.end_date
            and self.holidays == other.holidays
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.start_date, self.end_date, tuple(sorted(self.holidays))))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"BusinessDaysCalculator({self.start_date} to {self.end_date}, {self.business_days} days)"


class DateRangeGenerator:
    """Date range generation for common periods with rich functionality."""

    VALID_PERIODS = {
        "today",
        "yesterday",
        "this_week",
        "last_week",
        "this_month",
        "last_month",
        "this_quarter",
        "last_quarter",
        "this_year",
        "last_year",
    }

    def __init__(self, period: str, reference_date: date | None = None):
        """
        Initialize date range generator.

        Args:
            period: Period name (e.g., "this_week", "last_month")
            reference_date: Reference date (default: today)

        Raises:
            ValidationError: If period is invalid
        """
        if period.lower() not in self.VALID_PERIODS:
            raise ValidationError(
                f"Invalid period: {period}. Valid periods: {self.VALID_PERIODS}"
            )

        self.period = period.lower()
        self.reference_date = reference_date or date.today()
        self.start_date, self.end_date = self._get_date_range()

    def _get_date_range(self) -> tuple[datetime, datetime]:
        """Get date range for the specified period."""
        # Convert to datetime for consistency
        ref_dt = datetime.combine(self.reference_date, datetime.min.time())
        ref_dt = ref_dt.replace(tzinfo=pytz_timezone(DEFAULT_TIMEZONE))

        if self.period == "today":
            start = ref_dt
            end = ref_dt.replace(hour=23, minute=59, second=59, microsecond=999999)

        elif self.period == "yesterday":
            start = ref_dt - timedelta(days=1)
            end = start.replace(hour=23, minute=59, second=59, microsecond=999999)

        elif self.period == "this_week":
            # Start on Monday
            days_since_monday = ref_dt.weekday()
            start = ref_dt - timedelta(days=days_since_monday)
            end = start + timedelta(
                days=6, hours=23, minutes=59, seconds=59, microseconds=999999
            )

        elif self.period == "last_week":
            days_since_monday = ref_dt.weekday()
            this_monday = ref_dt - timedelta(days=days_since_monday)
            start = this_monday - timedelta(days=7)
            end = start + timedelta(
                days=6, hours=23, minutes=59, seconds=59, microseconds=999999
            )

        elif self.period == "this_month":
            start = ref_dt.replace(day=1)
            # Last day of month
            next_month = start + relativedelta(months=1)
            end = next_month - timedelta(microseconds=1)

        elif self.period == "last_month":
            first_of_month = ref_dt.replace(day=1)
            start = first_of_month - relativedelta(months=1)
            end = first_of_month - timedelta(microseconds=1)

        elif self.period == "this_quarter":
            quarter = (ref_dt.month - 1) // 3
            start = ref_dt.replace(month=quarter * 3 + 1, day=1)
            # Last day of quarter
            end = start + relativedelta(months=3) - timedelta(microseconds=1)

        elif self.period == "last_quarter":
            quarter = (ref_dt.month - 1) // 3
            this_quarter_start = ref_dt.replace(month=quarter * 3 + 1, day=1)
            start = this_quarter_start - relativedelta(months=3)
            end = this_quarter_start - timedelta(microseconds=1)

        elif self.period == "this_year":
            start = ref_dt.replace(month=1, day=1)
            end = ref_dt.replace(
                month=12, day=31, hour=23, minute=59, second=59, microsecond=999999
            )

        elif self.period == "last_year":
            start = ref_dt.replace(year=ref_dt.year - 1, month=1, day=1)
            end = ref_dt.replace(
                year=ref_dt.year - 1,
                month=12,
                day=31,
                hour=23,
                minute=59,
                second=59,
                microsecond=999999,
            )

        else:
            # Default to today
            start = ref_dt
            end = ref_dt.replace(hour=23, minute=59, second=59, microsecond=999999)

        return start, end

    @staticmethod
    def get_date_range(
        period: str, reference_date: date | None = None
    ) -> tuple[datetime, datetime]:
        """
        Static method to get date range.

        Args:
            period: Period name
            reference_date: Reference date

        Returns:
            Tuple of start and end datetimes
        """
        try:
            generator = DateRangeGenerator(period, reference_date)
            return generator.start_date, generator.end_date
        except ValidationError:
            # Return today as fallback
            ref_dt = datetime.combine(
                reference_date or date.today(), datetime.min.time()
            )
            ref_dt = ref_dt.replace(tzinfo=pytz_timezone(DEFAULT_TIMEZONE))
            end_dt = ref_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            return ref_dt, end_dt

    @property
    def total_days(self) -> int:
        """Get total days in range."""
        return (self.end_date.date() - self.start_date.date()).days + 1

    @property
    def is_current_period(self) -> bool:
        """Check if range includes current date."""
        today = date.today()
        return self.start_date.date() <= today <= self.end_date.date()

    def contains_date(self, check_date: date | datetime) -> bool:
        """
        Check if date falls within range.

        Args:
            check_date: Date to check

        Returns:
            bool: True if date is in range
        """
        if isinstance(check_date, datetime):
            return self.start_date <= check_date <= self.end_date
        return self.start_date.date() <= check_date <= self.end_date.date()

    def __str__(self) -> str:
        """String representation."""
        return f"{self.period}: {self.start_date.date()} to {self.end_date.date()}"

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, DateRangeGenerator):
            return False
        return (
            self.period == other.period and self.reference_date == other.reference_date
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.period, self.reference_date))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"DateRangeGenerator('{self.period}', {self.total_days} days)"


class TimezoneConverter:
    """Timezone conversion with comprehensive functionality."""

    def __init__(self, dt: datetime, from_tz: str | timezone, to_tz: str | timezone):
        """
        Initialize timezone converter.

        Args:
            dt: Datetime to convert
            from_tz: Source timezone
            to_tz: Target timezone

        Raises:
            ValidationError: If conversion fails
        """
        if not isinstance(dt, datetime):
            raise ValidationError("DateTime must be a datetime object")

        self.original_dt = dt
        self.from_tz = self._get_timezone(from_tz)
        self.to_tz = self._get_timezone(to_tz)
        self.value = self._convert_timezone()

    def _get_timezone(self, tz: str | timezone):
        """Get timezone object from string or timezone."""
        if isinstance(tz, str):
            try:
                return pytz_timezone(tz)
            except Exception:
                raise ValidationError(f"Invalid timezone: {tz}")
        return tz

    def _convert_timezone(self) -> datetime:
        """Convert datetime between timezones."""
        dt = self.original_dt

        # Localize if naive
        if dt.tzinfo is None:
            dt = self.from_tz.localize(dt)
        else:
            dt = dt.astimezone(self.from_tz)

        # Convert to target timezone
        return dt.astimezone(self.to_tz)

    @staticmethod
    def convert_timezone(
        dt: datetime, from_tz: str | timezone, to_tz: str | timezone
    ) -> datetime:
        """
        Static method to convert timezone.

        Args:
            dt: DateTime to convert
            from_tz: Source timezone
            to_tz: Target timezone

        Returns:
            datetime: Converted datetime
        """
        try:
            converter = TimezoneConverter(dt, from_tz, to_tz)
            return converter.value
        except ValidationError:
            return dt  # Return original on error

    def __str__(self) -> str:
        """String representation."""
        return self.value.isoformat()

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, TimezoneConverter):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"TimezoneConverter({self.original_dt} -> {self.value})"


class AgeCalculator:
    """Age calculation with rich functionality."""

    def __init__(self, birth_date: date, reference_date: date | None = None):
        """
        Initialize age calculator.

        Args:
            birth_date: Birth date
            reference_date: Reference date for calculation (default: today)

        Raises:
            ValidationError: If dates are invalid
        """
        if not isinstance(birth_date, date):
            raise ValidationError("Birth date must be a date object")

        self.birth_date = birth_date
        self.reference_date = reference_date or date.today()

        if self.birth_date > self.reference_date:
            raise ValidationError("Birth date cannot be in the future")

        self.age_years = self._calculate_age()

    def _calculate_age(self) -> int:
        """Calculate age in years."""
        age = self.reference_date.year - self.birth_date.year

        # Adjust if birthday hasn't occurred this year
        if (self.reference_date.month, self.reference_date.day) < (
            self.birth_date.month,
            self.birth_date.day,
        ):
            age -= 1

        return age

    @staticmethod
    def get_age(birth_date: date, reference_date: date | None = None) -> int:
        """
        Static method to calculate age.

        Args:
            birth_date: Birth date
            reference_date: Reference date

        Returns:
            int: Age in years
        """
        try:
            calculator = AgeCalculator(birth_date, reference_date)
            return calculator.age_years
        except ValidationError:
            return 0

    @property
    def age_days(self) -> int:
        """Get age in days."""
        return (self.reference_date - self.birth_date).days

    @property
    def next_birthday(self) -> date:
        """Get date of next birthday."""
        try:
            next_birthday = self.birth_date.replace(year=self.reference_date.year)
            if next_birthday < self.reference_date:
                next_birthday = next_birthday.replace(year=self.reference_date.year + 1)
        except ValueError:
            # Handle leap year edge case (Feb 29)
            next_birthday = date(self.reference_date.year, 2, 28)
            if next_birthday < self.reference_date:
                next_birthday = date(self.reference_date.year + 1, 2, 28)

        return next_birthday

    @property
    def days_until_birthday(self) -> int:
        """Get days until next birthday."""
        return (self.next_birthday - self.reference_date).days

    def __str__(self) -> str:
        """String representation."""
        return f"{self.age_years} years old"

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, AgeCalculator):
            return False
        return (
            self.birth_date == other.birth_date
            and self.reference_date == other.reference_date
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.birth_date, self.reference_date))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"AgeCalculator({self.birth_date} -> {self.age_years} years, {self.age_days} days)"


# =====================================================================================
# BACKWARD COMPATIBILITY FUNCTIONS (Legacy API)
# =====================================================================================


def parse_date(date_string: str, formats: list[str] | None = None) -> datetime | None:
    """Parse date string to datetime."""
    if not date_string:
        return None

    # Try provided formats first
    if formats:
        for fmt in formats:
            try:
                return datetime.strptime(date_string, fmt)
            except ValueError:
                continue

    # Fall back to dateutil parser
    try:
        return parser.parse(date_string)
    except (ValueError, parser.ParserError):
        return None


def format_relative_time(dt: datetime, reference: datetime | None = None) -> str:
    """Format datetime as relative time (e.g., '2 hours ago')."""
    return RelativeTimeFormatter.format_relative_time(dt, reference)


def get_business_days(
    start_date: date, end_date: date, holidays: list[date] | None = None
) -> int:
    """Calculate number of business days between dates."""
    return BusinessDaysCalculator.get_business_days(start_date, end_date, holidays)


def get_date_range(
    period: str, reference_date: date | None = None
) -> tuple[datetime, datetime]:
    """Get date range for common periods."""
    return DateRangeGenerator.get_date_range(period, reference_date)


def convert_timezone(
    dt: datetime, from_tz: str | timezone, to_tz: str | timezone
) -> datetime:
    """Convert datetime between timezones."""
    return TimezoneConverter.convert_timezone(dt, from_tz, to_tz)


def get_age(birth_date: date, reference_date: date | None = None) -> int:
    """Calculate age in years."""
    return AgeCalculator.get_age(birth_date, reference_date)
