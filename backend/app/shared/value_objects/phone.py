"""Phone number value object."""

import re

import phonenumbers
from phonenumbers import NumberParseException

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class PhoneNumber(ValueObject):
    """Phone number value object with international format validation."""

    def __init__(self, number: str, country_code: str = "CA"):
        """
        Initialize and validate phone number.

        Args:
            number: Phone number string
            country_code: ISO country code for parsing (default: "CA")

        Raises:
            ValidationError: If phone number is invalid
        """
        if not number or not number.strip():
            raise ValidationError("Phone number cannot be empty")

        self.country_code = country_code
        self._original_number = number.strip()

        # Validate and normalize
        self.value = self._validate_and_normalize(number, country_code)

        # Store parsed object for format operations
        try:
            self._parsed_number = phonenumbers.parse(self.value, None)
        except NumberParseException:
            # Fallback - this shouldn't happen if validation passed
            self._parsed_number = None

    def _validate_and_normalize(self, number: str, country_code: str) -> str:
        """Validate and normalize phone number."""
        try:
            # Parse phone number
            parsed = phonenumbers.parse(number, country_code)

            # Validate
            if not phonenumbers.is_valid_number(parsed):
                raise ValidationError("Invalid phone number")

            # Format as international E164
            return phonenumbers.format_number(
                parsed,
                phonenumbers.PhoneNumberFormat.E164,
            )
        except NumberParseException as e:
            raise ValidationError(f"Invalid phone number: {e!s}")

    @staticmethod
    def validate_format(number: str) -> bool:
        """
        Static method to validate phone format using regex.

        Args:
            number: Phone number string to validate

        Returns:
            bool: True if format appears valid, False otherwise

        Notes:
            Uses regex pattern matching; no exceptions raised
            Basic format validation only
        """
        if not number or not isinstance(number, str):
            return False

        # Remove all whitespace and common separators for validation
        cleaned = re.sub(r"[\s\-\(\)\.\+]", "", number)

        # Basic regex patterns for phone number validation
        patterns = [
            r"^\d{10}$",  # 10 digits (US/Canada without country code)
            r"^1\d{10}$",  # 11 digits starting with 1 (US/Canada with country code)
            r"^\d{7,15}$",  # International format (7-15 digits)
        ]

        return any(re.match(pattern, cleaned) for pattern in patterns)

    @staticmethod
    def validate_with_library(number: str, country_code: str = "CA") -> bool:
        """
        Static method to validate phone using phonenumbers library.

        Args:
            number: Phone number string to validate
            country_code: ISO country code for parsing

        Returns:
            bool: True if phone number is valid according to library
        """
        if not number:
            return False

        try:
            parsed = phonenumbers.parse(number, country_code)
            return phonenumbers.is_valid_number(parsed)
        except NumberParseException:
            return False

    @property
    def national_format(self) -> str:
        """Get national format of phone number."""
        if not self._parsed_number:
            return self.value
        return phonenumbers.format_number(
            self._parsed_number,
            phonenumbers.PhoneNumberFormat.NATIONAL,
        )

    @property
    def international_format(self) -> str:
        """Get international format of phone number."""
        if not self._parsed_number:
            return self.value
        return phonenumbers.format_number(
            self._parsed_number,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL,
        )

    @property
    def e164_format(self) -> str:
        """Get E164 format of phone number (same as value)."""
        return self.value

    @property
    def country_info(self) -> dict[str, str | None]:
        """Get country information for the phone number."""
        if not self._parsed_number:
            return {
                "country_code": None,
                "region": self.country_code,
                "country_name": "Unknown",
            }

        try:
            region = phonenumbers.region_code_for_number(self._parsed_number)
            country_code = self._parsed_number.country_code
            country_name = phonenumbers.geocoder.description_for_number(
                self._parsed_number, "en"
            )
            return {
                "country_code": country_code,
                "region": region,
                "country_name": country_name or "Unknown",
            }
        except Exception:
            return {
                "country_code": None,
                "region": self.country_code,
                "country_name": "Unknown",
            }

    def mask(
        self, mask_char: str = "*", visible_start: int = 3, visible_end: int = 3
    ) -> str:
        """
        Mask phone number for secure display.

        Args:
            mask_char: Character to use for masking
            visible_start: Number of characters to show at start
            visible_end: Number of characters to show at end

        Returns:
            str: Masked phone number
        """
        if len(self.value) <= visible_start + visible_end:
            return mask_char * len(self.value)

        start = self.value[:visible_start]
        end = self.value[-visible_end:] if visible_end > 0 else ""
        middle_length = len(self.value) - visible_start - visible_end
        middle = mask_char * middle_length

        return start + middle + end

    def is_mobile(self) -> bool:
        """Check if the phone number is a mobile number."""
        if not self._parsed_number:
            return False

        try:
            number_type = phonenumbers.number_type(self._parsed_number)
            return number_type in [
                phonenumbers.PhoneNumberType.MOBILE,
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE,
            ]
        except Exception:
            return False

    def is_valid_for_region(self, region: str) -> bool:
        """
        Check if phone number is valid for a specific region.

        Args:
            region: ISO region code (e.g., "US", "CA")

        Returns:
            bool: True if valid for region, False otherwise
        """
        if not self._parsed_number:
            return False

        try:
            return phonenumbers.is_valid_number_for_region(self._parsed_number, region)
        except Exception:
            return False

    def get_carrier_info(self) -> str | None:
        """Get carrier information for the phone number."""
        if not self._parsed_number:
            return None

        try:
            from phonenumbers import carrier

            return carrier.name_for_number(self._parsed_number, "en")
        except (ImportError, Exception):
            return None

    def __str__(self) -> str:
        """String representation (international format)."""
        return self.international_format

    def __eq__(self, other) -> bool:
        """Check equality based on normalized number."""
        if not isinstance(other, PhoneNumber):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"PhoneNumber('{self._original_number}', country_code='{self.country_code}')"
