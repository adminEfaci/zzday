"""Address value object."""

import re

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class Address(ValueObject):
    """Address value object with comprehensive validation and formatting."""

    def __init__(
        self,
        street: str,
        city: str,
        state_province: str,
        postal_code: str,
        country: str = "Canada",
        unit: str | None = None,
    ):
        """
        Initialize and validate address.

        Args:
            street: Street address
            city: City name
            state_province: State or province
            postal_code: Postal/ZIP code
            country: Country name (default: "Canada")
            unit: Optional unit/apartment number

        Raises:
            ValidationError: If any field is invalid
        """
        # Validate required fields
        self.street = self._validate_required_field(street, "Street")
        self.city = self._validate_required_field(city, "City")
        self.state_province = self._validate_required_field(
            state_province, "State/Province"
        )
        self.country = country or "Canada"
        self.unit = unit.strip() if unit else None

        # Validate and format postal code
        self.postal_code = self._validate_postal_code(postal_code, self.country)

    def _validate_required_field(self, value: str, field_name: str) -> str:
        """Validate required field is not empty."""
        if not value or not value.strip():
            raise ValidationError(f"{field_name} cannot be empty")
        return value.strip()

    def _validate_postal_code(self, postal_code: str, country: str) -> str:
        """Validate postal code format based on country."""
        if not postal_code:
            raise ValidationError("Postal code cannot be empty")

        postal_code = postal_code.strip().upper()

        if country == "Canada":
            # Canadian postal code format: A1A 1A1
            pattern = r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$"
            if not re.match(pattern, postal_code):
                raise ValidationError(
                    "Invalid Canadian postal code format (expected: A1A 1A1)"
                )
            # Ensure space in middle
            if len(postal_code) == 6:
                postal_code = f"{postal_code[:3]} {postal_code[3:]}"

        elif country == "United States":
            # US ZIP code format: 12345 or 12345-6789
            pattern = r"^\d{5}(-\d{4})?$"
            if not re.match(pattern, postal_code):
                raise ValidationError(
                    "Invalid US ZIP code format (expected: 12345 or 12345-6789)"
                )

        # Add validation for other countries as needed
        elif country in ["United Kingdom", "UK"]:
            # UK postcode format (simplified)
            pattern = r"^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$"
            if not re.match(pattern, postal_code):
                raise ValidationError("Invalid UK postcode format")

        return postal_code

    @staticmethod
    def validate_postal_code_format(postal_code: str, country: str) -> bool:
        """
        Static method to validate postal code format without creating object.

        Args:
            postal_code: Postal code to validate
            country: Country name

        Returns:
            bool: True if format is valid, False otherwise
        """
        if not postal_code or not isinstance(postal_code, str):
            return False

        postal_code = postal_code.strip().upper()

        try:
            if country == "Canada":
                pattern = r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$"
                return bool(re.match(pattern, postal_code))
            if country == "United States":
                pattern = r"^\d{5}(-\d{4})?$"
                return bool(re.match(pattern, postal_code))
            if country in ["United Kingdom", "UK"]:
                pattern = r"^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$"
                return bool(re.match(pattern, postal_code))
            # Basic validation for other countries
            return len(postal_code.replace(" ", "")) >= 3
        except Exception:
            return False

    def format_single_line(self) -> str:
        """Format as single line."""
        parts = []
        if self.unit:
            parts.append(f"Unit {self.unit}")
        parts.extend(
            [
                self.street,
                self.city,
                self.state_province,
                self.postal_code,
                self.country,
            ]
        )
        return ", ".join(parts)

    def format_multi_line(self) -> str:
        """Format as multiple lines."""
        lines = []
        if self.unit:
            lines.append(f"Unit {self.unit}")
        lines.append(self.street)
        lines.append(f"{self.city}, {self.state_province} {self.postal_code}")
        lines.append(self.country)
        return "\n".join(lines)

    def format_for_country(self, target_country: str | None = None) -> str:
        """Format address according to country-specific conventions."""
        country = target_country or self.country

        if country == "Canada":
            return self.format_multi_line()
        if country == "United States":
            lines = []
            if self.unit:
                lines.append(f"Unit {self.unit}, {self.street}")
            else:
                lines.append(self.street)
            lines.append(f"{self.city}, {self.state_province} {self.postal_code}")
            lines.append(self.country)
            return "\n".join(lines)
        return self.format_multi_line()

    def is_same_location(self, other: "Address") -> bool:
        """Check if addresses represent the same location (ignoring unit)."""
        if not isinstance(other, Address):
            return False

        return (
            self.street.lower() == other.street.lower()
            and self.city.lower() == other.city.lower()
            and self.state_province.lower() == other.state_province.lower()
            and self.postal_code.replace(" ", "") == other.postal_code.replace(" ", "")
            and self.country.lower() == other.country.lower()
        )

    def __str__(self) -> str:
        """String representation."""
        return self.format_single_line()

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, Address):
            return False
        return (
            self.street == other.street
            and self.city == other.city
            and self.state_province == other.state_province
            and self.postal_code == other.postal_code
            and self.country == other.country
            and self.unit == other.unit
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(
            (
                self.street,
                self.city,
                self.state_province,
                self.postal_code,
                self.country,
                self.unit,
            )
        )

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"Address(street='{self.street}', city='{self.city}', "
            f"state_province='{self.state_province}', postal_code='{self.postal_code}', "
            f"country='{self.country}', unit={self.unit!r})"
        )
