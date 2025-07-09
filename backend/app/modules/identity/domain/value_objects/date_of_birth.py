"""
Date of Birth Value Object

Immutable representation of a person's date of birth with age calculations.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from dateutil.relativedelta import relativedelta

from .base import ValueObject


@dataclass(frozen=True)
class DateOfBirth(ValueObject[date]):
    """Value object representing a person's date of birth."""
    
    value: date
    
    def __post_init__(self):
        """Validate date of birth."""
        # Ensure we have a date object
        if isinstance(self.value, datetime):
            object.__setattr__(self, 'value', self.value.date())
        
        # Validate it's not in the future
        if self.value > date.today():
            raise ValueError("Date of birth cannot be in the future")
        
        # Validate reasonable age (not more than 150 years old)
        min_date = date.today() - timedelta(days=150 * 365)
        if self.value < min_date:
            raise ValueError("Date of birth indicates age over 150 years")
        
        # Validate minimum age for COPPA compliance (US)
        # This is just a check - actual age restrictions should be in business rules
        if self.get_age() < 0:
            raise ValueError("Invalid date of birth")
    
    @classmethod
    def from_string(cls, date_string: str, date_format: str = "%Y-%m-%d") -> 'DateOfBirth':
        """Create from string with specified format."""
        try:
            parsed_date = datetime.strptime(date_string, date_format).date()
            return cls(value=parsed_date)
        except ValueError as e:
            raise ValueError(f"Invalid date format: {e!s}") from e
    
    @classmethod
    def from_components(cls, year: int, month: int, day: int) -> 'DateOfBirth':
        """Create from year, month, day components."""
        try:
            return cls(value=date(year, month, day))
        except ValueError as e:
            raise ValueError(f"Invalid date components: {e!s}") from e
    
    def get_age(self, as_of_date: date | None = None) -> int:
        """Calculate age in years as of a specific date."""
        if as_of_date is None:
            as_of_date = date.today()
        
        # Handle case where as_of_date is before birth date
        if as_of_date < self.value:
            return -1
        
        # Calculate age accounting for birthdays
        age = as_of_date.year - self.value.year
        
        # Adjust if birthday hasn't occurred yet this year
        if (as_of_date.month, as_of_date.day) < (self.value.month, self.value.day):
            age -= 1
        
        return age
    
    def get_age_in_months(self, as_of_date: date | None = None) -> int:
        """Calculate age in months."""
        if as_of_date is None:
            as_of_date = date.today()
        
        if as_of_date < self.value:
            return -1
        
        # Use relativedelta for accurate month calculation
        delta = relativedelta(as_of_date, self.value)
        return delta.years * 12 + delta.months
    
    def get_age_in_days(self, as_of_date: date | None = None) -> int:
        """Calculate age in days."""
        if as_of_date is None:
            as_of_date = date.today()
        
        if as_of_date < self.value:
            return -1
        
        return (as_of_date - self.value).days
    
    def get_next_birthday(self, after_date: date | None = None) -> date:
        """Get the next birthday after a given date."""
        if after_date is None:
            after_date = date.today()
        
        # Get this year's birthday
        try:
            this_year_birthday = date(after_date.year, self.value.month, self.value.day)
        except ValueError:
            # Handle leap year edge case (Feb 29)
            this_year_birthday = date(after_date.year, self.value.month, 28)
        
        # If it's already passed, get next year's
        if this_year_birthday <= after_date:
            try:
                return date(after_date.year + 1, self.value.month, self.value.day)
            except ValueError:
                # Handle leap year edge case
                return date(after_date.year + 1, self.value.month, 28)
        
        return this_year_birthday
    
    def days_until_birthday(self, from_date: date | None = None) -> int:
        """Get days until next birthday."""
        if from_date is None:
            from_date = date.today()
        
        next_birthday = self.get_next_birthday(from_date)
        return (next_birthday - from_date).days
    
    def is_birthday_today(self, check_date: date | None = None) -> bool:
        """Check if today is the birthday."""
        if check_date is None:
            check_date = date.today()
        
        return (self.value.month == check_date.month and 
                self.value.day == check_date.day)
    
    def is_birthday_this_week(self, from_date: date | None = None) -> bool:
        """Check if birthday is within the next 7 days."""
        if from_date is None:
            from_date = date.today()
        
        days_until = self.days_until_birthday(from_date)
        return 0 <= days_until <= 7
    
    def is_birthday_this_month(self, check_date: date | None = None) -> bool:
        """Check if birthday is this month."""
        if check_date is None:
            check_date = date.today()
        
        return self.value.month == check_date.month
    
    def is_adult(self, as_of_date: date | None = None, adult_age: int = 18) -> bool:
        """Check if person is an adult (default 18 years)."""
        return self.get_age(as_of_date) >= adult_age
    
    def is_minor(self, as_of_date: date | None = None, adult_age: int = 18) -> bool:
        """Check if person is a minor."""
        age = self.get_age(as_of_date)
        return 0 <= age < adult_age
    
    def is_senior(self, as_of_date: date | None = None, senior_age: int = 65) -> bool:
        """Check if person is a senior citizen."""
        return self.get_age(as_of_date) >= senior_age
    
    def is_teen(self, as_of_date: date | None = None) -> bool:
        """Check if person is a teenager (13-19)."""
        age = self.get_age(as_of_date)
        return 13 <= age <= 19
    
    def meets_age_requirement(self, min_age: int, as_of_date: date | None = None) -> bool:
        """Check if person meets minimum age requirement."""
        return self.get_age(as_of_date) >= min_age
    
    def get_age_group(self, as_of_date: date | None = None) -> str:
        """Get age group classification."""
        age = self.get_age(as_of_date)
        
        if age < 0:
            return "unborn"
        if age < 1:
            return "infant"
        if age < 3:
            return "toddler"
        if age < 6:
            return "preschool"
        if age < 13:
            return "child"
        if age < 18:
            return "teenager"
        if age < 25:
            return "young_adult"
        if age < 40:
            return "adult"
        if age < 65:
            return "middle_aged"
        return "senior"
    
    def get_zodiac_sign(self) -> str:
        """Get Western zodiac sign."""
        month = self.value.month
        day = self.value.day
        
        if (month == 3 and day >= 21) or (month == 4 and day <= 19):
            return "Aries"
        if (month == 4 and day >= 20) or (month == 5 and day <= 20):
            return "Taurus"
        if (month == 5 and day >= 21) or (month == 6 and day <= 20):
            return "Gemini"
        if (month == 6 and day >= 21) or (month == 7 and day <= 22):
            return "Cancer"
        if (month == 7 and day >= 23) or (month == 8 and day <= 22):
            return "Leo"
        if (month == 8 and day >= 23) or (month == 9 and day <= 22):
            return "Virgo"
        if (month == 9 and day >= 23) or (month == 10 and day <= 22):
            return "Libra"
        if (month == 10 and day >= 23) or (month == 11 and day <= 21):
            return "Scorpio"
        if (month == 11 and day >= 22) or (month == 12 and day <= 21):
            return "Sagittarius"
        if (month == 12 and day >= 22) or (month == 1 and day <= 19):
            return "Capricorn"
        if (month == 1 and day >= 20) or (month == 2 and day <= 18):
            return "Aquarius"
        return "Pisces"
    
    def get_chinese_zodiac(self) -> str:
        """Get Chinese zodiac animal."""
        animals = [
            "Rat", "Ox", "Tiger", "Rabbit", "Dragon", "Snake",
            "Horse", "Goat", "Monkey", "Rooster", "Dog", "Pig"
        ]
        # Chinese zodiac is based on lunar calendar, but we'll use solar year as approximation
        year_index = (self.value.year - 1900) % 12
        return animals[year_index]
    
    def format_full(self) -> str:
        """Format as full date (e.g., January 1, 2000)."""
        return self.value.strftime("%B %d, %Y")
    
    def format_short(self) -> str:
        """Format as short date (e.g., 01/01/2000)."""
        return self.value.strftime("%m/%d/%Y")
    
    def format_iso(self) -> str:
        """Format as ISO date (YYYY-MM-DD)."""
        return self.value.strftime("%Y-%m-%d")
    
    def format_for_display(self, include_age: bool = False, as_of_date: date | None = None) -> str:
        """Format for display with optional age."""
        formatted = self.format_full()
        
        if include_age:
            age = self.get_age(as_of_date)
            formatted += f" (age {age})"
        
        return formatted
    
    def anonymize(self) -> 'DateOfBirth':
        """Create anonymized version (only year)."""
        # Keep only the year for anonymization
        return DateOfBirth(value=date(self.value.year, 1, 1))
    
    def obscure_for_privacy(self) -> str:
        """Obscure for privacy (show only age range)."""
        age = self.get_age()
        
        if age < 18:
            return "Under 18"
        if age < 25:
            return "18-24"
        if age < 35:
            return "25-34"
        if age < 45:
            return "35-44"
        if age < 55:
            return "45-54"
        if age < 65:
            return "55-64"
        return "65+"
    
    def get_privacy_info(self) -> dict:
        """Get privacy-related information."""
        age = self.get_age()
        
        return {
            "is_minor": age < 18,
            "is_coppa_applicable": age < 13,  # US COPPA
            "is_gdpr_child": age < 16,  # EU GDPR
            "requires_parental_consent": age < 13,
            "age_group": self.obscure_for_privacy(),
            "data_retention_years": 7 if age >= 18 else 1  # Example policy
        }
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "date": self.format_iso(),
            "age": self.get_age(),
            "age_group": self.get_age_group(),
            "is_adult": self.is_adult(),
            "days_until_birthday": self.days_until_birthday(),
            "zodiac_sign": self.get_zodiac_sign()
        }
    
    def __str__(self) -> str:
        """String representation."""
        return self.format_iso()
    
    def __eq__(self, other: Any) -> bool:
        """Date equality based on date value."""
        if not isinstance(other, DateOfBirth):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Hash based on date value."""
        return hash(self.value)
    
    def __lt__(self, other: 'DateOfBirth') -> bool:
        """Less than comparison (older dates are "less")."""
        if not isinstance(other, DateOfBirth):
            return NotImplemented
        return self.value < other.value
    
    def __le__(self, other: 'DateOfBirth') -> bool:
        """Less than or equal comparison."""
        if not isinstance(other, DateOfBirth):
            return NotImplemented
        return self.value <= other.value
    
    def __gt__(self, other: 'DateOfBirth') -> bool:
        """Greater than comparison."""
        if not isinstance(other, DateOfBirth):
            return NotImplemented
        return self.value > other.value
    
    def __ge__(self, other: 'DateOfBirth') -> bool:
        """Greater than or equal comparison."""
        if not isinstance(other, DateOfBirth):
            return NotImplemented
        return self.value >= other.value
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"DateOfBirth(value={self.format_iso()}, age={self.get_age()})"