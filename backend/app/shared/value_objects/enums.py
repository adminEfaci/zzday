"""Shared enumerations with enhanced functionality."""

from enum import Enum


class Country(str, Enum):
    """Country codes (ISO 3166-1 alpha-2) with enhanced functionality."""

    CANADA = "CA"
    UNITED_STATES = "US"
    NIGERIA = "NG"
    GHANA = "GH"

    @classmethod
    def from_name(cls, name: str) -> "Country" | None:
        if not name or not isinstance(name, str):
            return None

        name_mapping = {
            "canada": cls.CANADA,
            "ca": cls.CANADA,
            "united states": cls.UNITED_STATES,
            "usa": cls.UNITED_STATES,
            "us": cls.UNITED_STATES,
            "america": cls.UNITED_STATES,
            "nigeria": cls.NIGERIA,
            "ng": cls.NIGERIA,
            "ghana": cls.GHANA,
            "gh": cls.GHANA,
        }
        return name_mapping.get(name.lower())

    @classmethod
    def from_code(cls, code: str) -> "Country" | None:
        if not code or not isinstance(code, str):
            return None
        try:
            return cls(code.upper())
        except ValueError:
            return None

    def get_name(self) -> str:
        names = {
            self.CANADA: "Canada",
            self.UNITED_STATES: "United States",
            self.NIGERIA: "Nigeria",
            self.GHANA: "Ghana",
        }
        return names.get(self, self.value)

    def get_currency(self) -> "Currency" | None:
        currency_mapping = {
            self.CANADA: Currency.CAD,
            self.UNITED_STATES: Currency.USD,
            self.NIGERIA: Currency.NGN,
            self.GHANA: Currency.GHS,
        }
        return currency_mapping.get(self)

    def get_phone_code(self) -> str | None:
        phone_codes = {
            self.CANADA: "+1",
            self.UNITED_STATES: "+1",
            self.NIGERIA: "+234",
            self.GHANA: "+233",
        }
        return phone_codes.get(self)


class Currency(str, Enum):
    CAD = "CAD"  # Canadian Dollar
    USD = "USD"  # US Dollar
    NGN = "NGN"  # Nigerian Naira
    GHS = "GHS"  # Ghanaian Cedi

    def get_name(self) -> str:
        names = {
            self.CAD: "Canadian Dollar",
            self.USD: "US Dollar",
            self.NGN: "Nigerian Naira",
            self.GHS: "Ghanaian Cedi",
        }
        return names.get(self, self.value)

    def get_symbol(self) -> str:
        symbols = {
            self.CAD: "$",
            self.USD: "$",
            self.NGN: "₦",
            self.GHS: "GH₵",
        }
        return symbols.get(self, self.value)

    def get_decimal_places(self) -> int:
        return 2

    @classmethod
    def get_major_currencies(cls) -> list["Currency"]:
        return [cls.USD, cls.CAD, cls.NGN, cls.GHS]


class Language(str, Enum):
    ENGLISH = "en"
    PIDGIN = "pcm"
    IGBO = "ig"
    YORUBA = "yo"
    FRENCH = "fr"
    HAUSA = "ha"

    def get_name(self) -> str:
        names = {
            self.ENGLISH: "English",
            self.PIDGIN: "English Pidgin",
            self.IGBO: "Igbo",
            self.YORUBA: "Yoruba",
            self.FRENCH: "French",
            self.HAUSA: "Hausa",
        }
        return names.get(self, self.value)


class DayOfWeek(int, Enum):
    MONDAY = 1
    TUESDAY = 2
    WEDNESDAY = 3
    THURSDAY = 4
    FRIDAY = 5
    SATURDAY = 6
    SUNDAY = 7

    @property
    def is_weekend(self) -> bool:
        return self in (self.SATURDAY, self.SUNDAY)

    @property
    def is_weekday(self) -> bool:
        return not self.is_weekend

    def get_name(self) -> str:
        names = {
            self.MONDAY: "Monday",
            self.TUESDAY: "Tuesday",
            self.WEDNESDAY: "Wednesday",
            self.THURSDAY: "Thursday",
            self.FRIDAY: "Friday",
            self.SATURDAY: "Saturday",
            self.SUNDAY: "Sunday",
        }
        return names[self]

    def get_short_name(self) -> str:
        short_names = {
            self.MONDAY: "Mon",
            self.TUESDAY: "Tue",
            self.WEDNESDAY: "Wed",
            self.THURSDAY: "Thu",
            self.FRIDAY: "Fri",
            self.SATURDAY: "Sat",
            self.SUNDAY: "Sun",
        }
        return short_names[self]

    @classmethod
    def from_name(cls, name: str) -> "DayOfWeek" | None:
        if not name or not isinstance(name, str):
            return None
        name_mapping = {
            "monday": cls.MONDAY,
            "mon": cls.MONDAY,
            "tuesday": cls.TUESDAY,
            "tue": cls.TUESDAY,
            "tues": cls.TUESDAY,
            "wednesday": cls.WEDNESDAY,
            "wed": cls.WEDNESDAY,
            "thursday": cls.THURSDAY,
            "thu": cls.THURSDAY,
            "thur": cls.THURSDAY,
            "thurs": cls.THURSDAY,
            "friday": cls.FRIDAY,
            "fri": cls.FRIDAY,
            "saturday": cls.SATURDAY,
            "sat": cls.SATURDAY,
            "sunday": cls.SUNDAY,
            "sun": cls.SUNDAY,
        }
        return name_mapping.get(name.lower())

    @classmethod
    def get_weekdays(cls) -> list["DayOfWeek"]:
        return [cls.MONDAY, cls.TUESDAY, cls.WEDNESDAY, cls.THURSDAY, cls.FRIDAY]

    @classmethod
    def get_weekend(cls) -> list["DayOfWeek"]:
        return [cls.SATURDAY, cls.SUNDAY]


class TimeZone(str, Enum):
    UTC = "UTC"
    TORONTO = "America/Toronto"
    MONTREAL = "America/Montreal"
    VANCOUVER = "America/Vancouver"
    HALIFAX = "America/Halifax"  # Maritime region

    LAGOS = "Africa/Lagos"
    ACCRA = "Africa/Accra"

    EST = "America/New_York"
    CST = "America/Chicago"
    MST = "America/Denver"
    PST = "America/Los_Angeles"
    GMT = "Europe/London"
    CET = "Europe/Paris"
    JST = "Asia/Tokyo"
    IST = "Asia/Kolkata"
    AEST = "Australia/Sydney"
    CST_CHINA = "Asia/Shanghai"
    BRT = "America/Sao_Paulo"

    def get_name(self) -> str:
        names = {
            self.UTC: "Coordinated Universal Time",
            self.TORONTO: "Toronto Time (Eastern Time Zone)",
            self.MONTREAL: "Montreal Time (Eastern Time Zone)",
            self.VANCOUVER: "Vancouver Time (Pacific Time Zone)",
            self.HALIFAX: "Halifax Time (Atlantic Time Zone)",
            self.LAGOS: "Lagos Time (West Africa Time)",
            self.ACCRA: "Accra Time (Greenwich Mean Time)",
            self.EST: "Eastern Standard Time (US)",
            self.CST: "Central Standard Time (US)",
            self.MST: "Mountain Standard Time (US)",
            self.PST: "Pacific Standard Time (US)",
            self.GMT: "Greenwich Mean Time",
            self.CET: "Central European Time",
            self.JST: "Japan Standard Time",
            self.IST: "India Standard Time",
            self.AEST: "Australian Eastern Standard Time",
            self.CST_CHINA: "China Standard Time",
            self.BRT: "Brasília Time",
        }
        return names.get(self, self.value)

    def get_offset_hours(self) -> int | None:
        offsets = {
            self.UTC: 0,
            self.TORONTO: -5,
            self.MONTREAL: -5,
            self.VANCOUVER: -8,
            self.HALIFAX: -4,
            self.LAGOS: 1,
            self.ACCRA: 0,
            self.EST: -5,
            self.CST: -6,
            self.MST: -7,
            self.PST: -8,
            self.GMT: 0,
            self.CET: 1,
            self.JST: 9,
            self.IST: 5,
            self.AEST: 10,
            self.CST_CHINA: 8,
            self.BRT: -3,
        }
        return offsets.get(self)

    @classmethod
    def get_us_timezones(cls) -> list["TimeZone"]:
        return [cls.EST, cls.CST, cls.MST, cls.PST]


class Status(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"
    DELETED = "deleted"
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"

    def is_active_state(self) -> bool:
        return self in {self.ACTIVE, self.PUBLISHED}

    def is_inactive_state(self) -> bool:
        return self in {self.INACTIVE, self.SUSPENDED, self.DELETED, self.ARCHIVED}


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"

    def get_numeric_value(self) -> int:
        values = {
            self.LOW: 1,
            self.MEDIUM: 2,
            self.HIGH: 3,
            self.URGENT: 4,
            self.CRITICAL: 5,
        }
        return values[self]

    @classmethod
    def from_numeric(cls, value: int) -> "Priority" | None:
        mapping = {
            1: cls.LOW,
            2: cls.MEDIUM,
            3: cls.HIGH,
            4: cls.URGENT,
            5: cls.CRITICAL,
        }
        return mapping.get(value)
