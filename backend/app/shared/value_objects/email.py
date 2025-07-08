"""Email address value object."""

import re

from email_validator import EmailNotValidError, validate_email

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class EmailAddress(ValueObject):
    """Email address value object with RFC-compliant validation."""

    def __init__(self, value: str):
        """
        Initialize and validate email address.

        Args:
            value: Email address string

        Raises:
            ValidationError: If email address is invalid
        """
        if not value:
            raise ValidationError("Email address cannot be empty")

        self.value = self._validate_and_normalize(value)

    def _validate_and_normalize(self, email: str) -> str:
        """Validate and normalize email address."""
        try:
            # Validate and normalize using email-validator library
            validation = validate_email(email, check_deliverability=False)
            return validation.email.lower()
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email address: {e!s}")

    @staticmethod
    def validate_format(email: str) -> bool:
        """
        Static method to validate email format using regex.

        Args:
            email: Email address to validate

        Returns:
            bool: True if format appears valid, False otherwise

        Notes:
            Basic regex validation only - doesn't verify deliverability
        """
        if not email or not isinstance(email, str):
            return False

        # Basic email regex pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email.strip()))

    @staticmethod
    def validate_deliverable(email: str) -> bool:
        """
        Static method to validate email deliverability.

        Args:
            email: Email address to validate

        Returns:
            bool: True if email passes deliverability checks

        Notes:
            Uses email-validator library with deliverability checks
        """
        if not email or not isinstance(email, str):
            return False

        try:
            validate_email(email, check_deliverability=True)
            return True
        except EmailNotValidError:
            return False

    @property
    def domain(self) -> str:
        """Extract domain from email."""
        return self.value.split("@")[1]

    @property
    def local_part(self) -> str:
        """Extract local part (username) from email."""
        return self.value.split("@")[0]

    @property
    def is_business_email(self) -> bool:
        """Check if email appears to be a business email (not common free providers)."""
        free_providers = {
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "aol.com",
            "icloud.com",
            "protonmail.com",
            "mail.com",
        }
        return self.domain.lower() not in free_providers

    def mask(
        self, mask_char: str = "*", visible_start: int = 2, visible_end: int = 1
    ) -> str:
        """
        Mask email for secure display.

        Args:
            mask_char: Character to use for masking
            visible_start: Number of characters to show at start of local part
            visible_end: Number of characters to show at end of local part

        Returns:
            str: Masked email address
        """
        local, domain = self.value.split("@")

        if len(local) <= visible_start + visible_end:
            masked_local = mask_char * len(local)
        else:
            start = local[:visible_start]
            end = local[-visible_end:] if visible_end > 0 else ""
            middle_length = len(local) - visible_start - visible_end
            middle = mask_char * middle_length
            masked_local = start + middle + end

        return f"{masked_local}@{domain}"

    def get_suggested_variations(self) -> list[str]:
        """Get common variations of the email address."""
        local, domain = self.value.split("@")

        variations = []

        # Common domain typos
        domain_corrections = {
            "gmail.co": "gmail.com",
            "gmial.com": "gmail.com",
            "gmai.com": "gmail.com",
            "yahooo.com": "yahoo.com",
            "hotmial.com": "hotmail.com",
        }

        if domain in domain_corrections:
            variations.append(f"{local}@{domain_corrections[domain]}")

        return variations

    def is_disposable(self) -> bool:
        """Check if email is from a known disposable email provider."""
        disposable_domains = {
            "10minutemail.com",
            "tempmail.org",
            "guerrillamail.com",
            "mailinator.com",
            "throwaway.email",
            "temp-mail.org",
        }
        return self.domain.lower() in disposable_domains

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, EmailAddress):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"EmailAddress('{self.value}')"
