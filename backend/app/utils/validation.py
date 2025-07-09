"""Validation utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic validation utilities that follow Domain-Driven Design
principles. All validators are pure Python classes that can be used across different layers
of the application without tight coupling to any specific framework.

Enhanced to support both rich validator classes and utility functions for configuration.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static validation methods for pre-validation
- Configuration utility methods for environment loading
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

# Import regex patterns from your existing constants
from app.core.constants import EMAIL_REGEX, PHONE_REGEX, UUID_REGEX
from app.core.errors import ValidationError

# =====================================================================================
# VALIDATION PROTOCOLS AND INTERFACES
# =====================================================================================


class ValidationRule(ABC):
    """Abstract base class for validation rules following DDD principles."""

    @abstractmethod
    def validate(self, value: Any) -> Any:
        """Validate value and return normalized result."""

    @abstractmethod
    def get_error_message(self, value: Any) -> str:
        """Get error message for invalid value."""

    def is_valid(self, value: Any) -> bool:
        """Check if value is valid without raising exceptions."""
        try:
            self.validate(value)
            return True
        except ValidationError:
            return False


# =====================================================================================
# CONFIGURATION VALIDATION UTILITIES
# =====================================================================================


class ConfigValidationUtils:
    """
    Configuration validation utilities for environment loading.

    Provides static methods for validating configuration values with comprehensive
    type checking, format validation, and error handling specifically designed
    for configuration management.
    """

    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")

    @staticmethod
    def validate_string(
        value: Any,
        field_name: str,
        required: bool = True,
        min_length: int = 0,
        max_length: int | None = None,
        pattern: str | None = None,
    ) -> str | None:
        """
        Validate string value with comprehensive checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            min_length: Minimum string length
            max_length: Maximum string length
            pattern: Regular expression pattern to match

        Returns:
            str | None: Validated string value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        str_value = str(value) if not isinstance(value, str) else value

        str_value = str_value.strip()

        if min_length > 0 and len(str_value) < min_length:
            raise ValidationError(
                f"{field_name} must be at least {min_length} characters",
                field=field_name,
            )

        if max_length and len(str_value) > max_length:
            raise ValidationError(
                f"{field_name} must be at most {max_length} characters",
                field=field_name,
            )

        if pattern and not re.match(pattern, str_value):
            raise ValidationError(
                f"{field_name} does not match required pattern", field=field_name
            )

        return str_value

    @staticmethod
    def validate_integer(
        value: Any,
        field_name: str,
        required: bool = True,
        min_value: int | None = None,
        max_value: int | None = None,
    ) -> int | None:
        """
        Validate integer value with range checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            int | None: Validated integer value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValidationError(
                f"{field_name} must be a valid integer", field=field_name
            )

        if min_value is not None and int_value < min_value:
            raise ValidationError(
                f"{field_name} must be at least {min_value}", field=field_name
            )

        if max_value is not None and int_value > max_value:
            raise ValidationError(
                f"{field_name} must be at most {max_value}", field=field_name
            )

        return int_value

    @staticmethod
    def validate_float(
        value: Any,
        field_name: str,
        required: bool = True,
        min_value: float | None = None,
        max_value: float | None = None,
    ) -> float | None:
        """
        Validate float value with range checks.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            float | None: Validated float value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        try:
            float_value = float(value)
        except (ValueError, TypeError):
            raise ValidationError(
                f"{field_name} must be a valid number", field=field_name
            )

        if min_value is not None and float_value < min_value:
            raise ValidationError(
                f"{field_name} must be at least {min_value}", field=field_name
            )

        if max_value is not None and float_value > max_value:
            raise ValidationError(
                f"{field_name} must be at most {max_value}", field=field_name
            )

        return float_value

    @staticmethod
    def validate_boolean(
        value: Any, field_name: str, required: bool = True
    ) -> bool | None:
        """
        Validate boolean value with flexible input handling.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required

        Returns:
            bool | None: Validated boolean value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            value = value.lower().strip()
            if value in ("true", "1", "yes", "on"):
                return True
            if value in ("false", "0", "no", "off"):
                return False
            raise ValidationError(
                f"{field_name} must be a valid boolean value", field=field_name
            )

        if isinstance(value, int):
            return bool(value)

        raise ValidationError(
            f"{field_name} must be a valid boolean value", field=field_name
        )

    @staticmethod
    def validate_enum(
        value: Any, enum_class: type[Enum], field_name: str, required: bool = True
    ) -> Enum | None:
        """
        Validate enum value with case-insensitive matching.

        Args:
            value: Value to validate
            enum_class: Enum class to validate against
            field_name: Field name for error messages
            required: Whether field is required

        Returns:
            Enum | None: Validated enum value

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        if isinstance(value, enum_class):
            return value

        # Try direct enum construction first
        try:
            return enum_class(value)
        except (ValueError, TypeError):
            pass

        # For string values, try name-based lookup
        if isinstance(value, str):
            # Try by name first (case-insensitive)
            value_upper = value.upper()
            for enum_value in enum_class:
                if enum_value.name.upper() == value_upper:
                    return enum_value
            
            # Try exact match by value
            for enum_value in enum_class:
                enum_val = enum_value.value
                if isinstance(enum_val, tuple | list):
                    # For tuple values, use the first element (like LogLevel)
                    enum_val = enum_val[0]
                if enum_val == value:
                    return enum_value

            # Try case-insensitive match by value
            value_lower = value.lower()
            for enum_value in enum_class:
                # Handle case where enum value might be a tuple or other type
                enum_val = enum_value.value
                if isinstance(enum_val, tuple | list):
                    # For tuple values, use the first element (like LogLevel)
                    enum_val = enum_val[0]
                if isinstance(enum_val, str) and enum_val.lower() == value_lower:
                    return enum_value

        valid_values = [str(e.value) for e in enum_class]
        raise ValidationError(
            f"{field_name} must be one of: {', '.join(valid_values)}", field=field_name
        )

    @staticmethod
    def validate_url(
        value: Any,
        field_name: str,
        required: bool = True,
        schemes: list[str] | None = None,
    ) -> str | None:
        """
        Validate URL with scheme checking.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required
            schemes: Allowed URL schemes

        Returns:
            str | None: Validated URL

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        str_value = str(value) if not isinstance(value, str) else value

        str_value = str_value.strip()

        try:
            parsed = urlparse(str_value)

            if not parsed.scheme or not parsed.netloc:
                raise ValidationError(
                    f"{field_name} must be a valid URL", field=field_name
                )

            if schemes and parsed.scheme not in schemes:
                raise ValidationError(
                    f"{field_name} scheme must be one of: {', '.join(schemes)}",
                    field=field_name,
                )

            return str_value

        except Exception:
            raise ValidationError(f"{field_name} must be a valid URL", field=field_name)

    @staticmethod
    def validate_email(
        value: Any, field_name: str, required: bool = True
    ) -> str | None:
        """
        Validate email address format.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            required: Whether field is required

        Returns:
            str | None: Validated email address

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        str_value = str(value) if not isinstance(value, str) else value

        str_value = str_value.strip().lower()

        if not ConfigValidationUtils.EMAIL_PATTERN.match(str_value):
            raise ValidationError(
                f"{field_name} must be a valid email address", field=field_name
            )

        return str_value

    @staticmethod
    def validate_list(
        value: Any,
        field_name: str,
        item_type: type[Any] = str,
        required: bool = True,
        min_items: int = 0,
        max_items: int | None = None,
    ) -> list[Any] | None:
        """
        Validate list with item type checking.

        Args:
            value: Value to validate
            field_name: Field name for error messages
            item_type: Expected type of list items
            required: Whether field is required
            min_items: Minimum number of items
            max_items: Maximum number of items

        Returns:
            list[Any] | None: Validated list

        Raises:
            ValidationError: If validation fails
        """
        if value is None or value == "":
            if required:
                raise ValidationError(f"{field_name} is required", field=field_name)
            return None

        if isinstance(value, str):
            # Handle comma-separated strings
            if value.strip():
                value = [item.strip() for item in value.split(",") if item.strip()]
            else:
                value = []

        if not isinstance(value, list):
            raise ValidationError(f"{field_name} must be a list", field=field_name)

        if len(value) < min_items:
            raise ValidationError(
                f"{field_name} must have at least {min_items} items", field=field_name
            )

        if max_items and len(value) > max_items:
            raise ValidationError(
                f"{field_name} must have at most {max_items} items", field=field_name
            )

        # Validate item types
        validated_items = []
        for i, item in enumerate(value):
            if not isinstance(item, item_type):
                try:
                    item = item_type(item)
                except (ValueError, TypeError):
                    raise ValidationError(
                        f"{field_name}[{i}] must be of type {item_type.__name__}",
                        field=field_name,
                    )
            validated_items.append(item)

        return validated_items


# Alias for easier imports
validate_string = ConfigValidationUtils.validate_string
validate_integer = ConfigValidationUtils.validate_integer
validate_float = ConfigValidationUtils.validate_float
validate_boolean = ConfigValidationUtils.validate_boolean
validate_enum = ConfigValidationUtils.validate_enum
validate_url = ConfigValidationUtils.validate_url
validate_email = ConfigValidationUtils.validate_email
validate_list = ConfigValidationUtils.validate_list


# =====================================================================================
# RICH VALIDATION CLASSES
# =====================================================================================


class UUIDValidator:
    """UUID validation with comprehensive format checking and rich functionality."""

    def __init__(self, value: str):
        """
        Initialize and validate UUID string.

        Args:
            value: UUID string to validate

        Raises:
            ValidationError: If UUID is invalid
        """
        if not value:
            raise ValidationError("UUID cannot be empty")

        self.value = self._validate_and_normalize(value)
        self._uuid_obj = UUID(self.value)

    def _validate_and_normalize(self, uuid_str: str) -> str:
        """Validate and normalize UUID string."""
        if not isinstance(uuid_str, str):
            raise ValidationError("UUID must be a string")

        # Clean up the input
        uuid_str = uuid_str.strip().lower()

        # Check format with regex from constants
        if not UUID_REGEX.match(uuid_str):
            raise ValidationError("Invalid UUID format")

        try:
            # Validate by creating UUID object
            uuid_obj = UUID(uuid_str)
            return str(uuid_obj)
        except ValueError as e:
            raise ValidationError(f"Invalid UUID: {e!s}")

    @staticmethod
    def validate(value: Any) -> UUID:
        """
        Static method to validate and convert to UUID.

        Args:
            value: Value to validate

        Returns:
            UUID: Validated UUID object

        Raises:
            ValidationError: If validation fails
        """
        if isinstance(value, UUID):
            return value
        
        if not isinstance(value, str):
            raise ValidationError("UUID must be a string or UUID instance")
        
        validator = UUIDValidator(value)
        return validator._uuid_obj

    @staticmethod
    def validate_format(uuid_str: str) -> bool:
        """
        Static method to validate UUID format using regex.

        Args:
            uuid_str: UUID string to validate

        Returns:
            bool: True if format appears valid, False otherwise
        """
        if not uuid_str or not isinstance(uuid_str, str):
            return False

        return bool(UUID_REGEX.match(uuid_str.strip().lower()))

    @staticmethod
    def validate_parseable(uuid_str: str) -> bool:
        """
        Static method to validate if UUID is parseable.

        Args:
            uuid_str: UUID string to validate

        Returns:
            bool: True if UUID can be parsed
        """
        if not uuid_str or not isinstance(uuid_str, str):
            return False

        try:
            UUID(uuid_str.strip())
            return True
        except ValueError:
            return False

    @property
    def version(self) -> int | None:
        """Get UUID version."""
        return self._uuid_obj.version

    @property
    def variant(self) -> str:
        """Get UUID variant."""
        return self._uuid_obj.variant

    @property
    def is_nil(self) -> bool:
        """Check if UUID is nil (all zeros)."""
        return self.value == "00000000-0000-0000-0000-000000000000"

    @property
    def bytes(self) -> bytes:
        """Get UUID as bytes."""
        return self._uuid_obj.bytes

    @property
    def as_int(self) -> int:
        """Get UUID as integer."""
        return self._uuid_obj.int

    def to_compact_string(self) -> str:
        """Return UUID without hyphens."""
        return self.value.replace("-", "")

    def to_uppercase(self) -> str:
        """Return UUID in uppercase."""
        return self.value.upper()

    def to_urn(self) -> str:
        """Return UUID as URN."""
        return f"urn:uuid:{self.value}"

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, UUIDValidator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"UUIDValidator('{self.value}')"


# =====================================================================================
# DEPRECATED VALIDATORS - Use app.shared value objects instead
# =====================================================================================

import warnings

class EmailValidator:
    """
    DEPRECATED: Use app.shared.value_objects.EmailAddress instead.
    
    This validator is deprecated in favor of the rich EmailAddress value object
    in app.shared which provides better validation using the email-validator library,
    RFC compliance checking, and proper domain modeling.
    
    Migration:
        # Old usage
        validator = EmailValidator("user@example.com")
        email_str = validator.value
        
        # New usage  
        from app.shared import EmailAddress
        email_obj = EmailAddress("user@example.com")
        email_str = email_obj.value
    """

    def __init__(self, email: str):
        warnings.warn(
            "EmailValidator is deprecated. Use app.shared.EmailAddress instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Delegate to shared EmailAddress for compatibility
        try:
            from app.shared.value_objects.email import EmailAddress
            self._email = EmailAddress(email)
            self.value = self._email.value
        except ImportError:
            # Fallback if shared module not available
            if not email:
                raise ValidationError("Email address cannot be empty")
            if not isinstance(email, str):
                raise ValidationError("Email must be a string")
            email = email.strip().lower()
            if not EMAIL_REGEX.match(email):
                raise ValidationError("Invalid email format")
            self.value = email
            self._email = None

    @staticmethod
    def validate(value: Any) -> str:
        """Static validation method - delegates to EmailAddress."""
        warnings.warn(
            "EmailValidator.validate is deprecated. Use EmailAddress(value).value instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        try:
            from app.shared.value_objects.email import EmailAddress
            return EmailAddress(value).value
        except ImportError:
            # Fallback validation
            if not isinstance(value, str):
                raise ValidationError("Email must be a string")
            validator = EmailValidator(value)
            return validator.value

    @staticmethod
    def validate_format(email: str) -> bool:
        """Static format validation - delegates to EmailAddress."""
        warnings.warn(
            "EmailValidator.validate_format is deprecated. Use EmailAddress.validate_format instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        try:
            from app.shared.value_objects.email import EmailAddress
            return EmailAddress.validate_format(email)
        except ImportError:
            # Fallback validation
            if not email or not isinstance(email, str):
                return False
            return bool(EMAIL_REGEX.match(email.strip().lower()))

    @property
    def domain(self) -> str:
        """Extract domain from email."""
        if self._email:
            return self._email.domain
        return self.value.split("@")[1]

    @property
    def local_part(self) -> str:
        """Extract local part from email.""" 
        if self._email:
            return self._email.local_part
        return self.value.split("@")[0]

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"EmailValidator('{self.value}') [DEPRECATED - Use EmailAddress]"


class PhoneValidator:
    """
    DEPRECATED: Use app.shared.value_objects.PhoneNumber instead.
    
    This validator is deprecated in favor of the rich PhoneNumber value object
    in app.shared which provides better validation using the phonenumbers library,
    international formatting, and proper domain modeling.
    
    Migration:
        # Old usage
        validator = PhoneValidator("+1-416-555-1234", "CA")
        phone_str = validator.value
        
        # New usage
        from app.shared import PhoneNumber  
        phone_obj = PhoneNumber("+1-416-555-1234", "CA")
        phone_str = phone_obj.value
    """

    def __init__(self, phone: str, country_code: str = "CA"):
        warnings.warn(
            "PhoneValidator is deprecated. Use app.shared.PhoneNumber instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Delegate to shared PhoneNumber for compatibility
        try:
            from app.shared.value_objects.phone import PhoneNumber
            self._phone = PhoneNumber(phone, country_code)
            self.value = self._phone.value
            self.country_code = self._phone.country_code
        except ImportError:
            # Fallback if shared module not available
            if not phone:
                raise ValidationError("Phone number cannot be empty")
            self.country_code = country_code.upper()
            self.value = self._basic_validate(phone)
            self._phone = None

    def _basic_validate(self, phone: str) -> str:
        """Basic phone validation fallback."""
        if not isinstance(phone, str):
            raise ValidationError("Phone number must be a string")
        cleaned = re.sub(r"[\s\-\(\)\.]+", "", phone.strip())
        if len(cleaned) < 10:
            raise ValidationError("Phone number too short")
        return cleaned

    @staticmethod
    def validate_format(phone: str) -> bool:
        """Static format validation - delegates to PhoneNumber."""
        warnings.warn(
            "PhoneValidator.validate_format is deprecated. Use PhoneNumber validation instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        try:
            from app.shared.value_objects.phone import PhoneNumber
            PhoneNumber(phone)
            return True
        except (ImportError, ValidationError):
            return False

    @staticmethod
    def clean_phone_number(phone: str) -> str:
        """Clean phone number formatting."""
        warnings.warn(
            "PhoneValidator.clean_phone_number is deprecated.",
            DeprecationWarning,
            stacklevel=2
        )
        if not phone or not isinstance(phone, str):
            return ""
        return re.sub(r"[\s\-\(\)\.]+", "", phone.strip())

    @property
    def digits_only(self) -> str:
        """Get phone number with digits only."""
        return self.value

    def format_display(self, style: str = "standard") -> str:
        """Format phone number for display."""
        if self._phone:
            if style == "international":
                return self._phone.international_format
            return self._phone.national_format
        return self.value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"PhoneValidator('{self.value}', '{self.country_code}') [DEPRECATED - Use PhoneNumber]"


class PasswordValidator:
    """Password validation with comprehensive strength checking and rich functionality."""

    def __init__(
        self,
        password: str,
        min_length: int = 8,
        require_uppercase: bool = False,
        require_lowercase: bool = True,
        require_numbers: bool = False,
        require_special: bool = False,
    ):
        """
        Initialize and validate password.

        Args:
            password: Password string
            min_length: Minimum length requirement
            require_uppercase: Require uppercase letters
            require_lowercase: Require lowercase letters
            require_numbers: Require numbers
            require_special: Require special characters

        Raises:
            ValidationError: If password doesn't meet requirements
        """
        if not password:
            raise ValidationError("Password cannot be empty")

        self.password = password
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_numbers = require_numbers
        self.require_special = require_special

        issues = self._validate_password()
        if issues:
            raise ValidationError(f"Password validation failed: {'; '.join(issues)}")

    def _validate_password(self) -> list[str]:
        """Validate password and return list of issues."""
        issues = []

        if len(self.password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")

        if self.require_uppercase and not any(c.isupper() for c in self.password):
            issues.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not any(c.islower() for c in self.password):
            issues.append("Password must contain at least one lowercase letter")

        if self.require_numbers and not any(c.isdigit() for c in self.password):
            issues.append("Password must contain at least one number")

        if self.require_special and not any(
            c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in self.password
        ):
            issues.append("Password must contain at least one special character")

        return issues

    @staticmethod
    def validate_strength(
        password: str,
        min_length: int = 8,
        require_uppercase: bool = False,
        require_lowercase: bool = True,
        require_numbers: bool = False,
        require_special: bool = False,
    ) -> list[str]:
        """
        Static method to validate password strength.

        Args:
            password: Password to validate
            min_length: Minimum length requirement
            require_uppercase: Require uppercase letters
            require_lowercase: Require lowercase letters
            require_numbers: Require numbers
            require_special: Require special characters

        Returns:
            list[str]: List of validation issues (empty if valid)
        """
        try:
            PasswordValidator(
                password,
                min_length,
                require_uppercase,
                require_lowercase,
                require_numbers,
                require_special,
            )
            return []
        except ValidationError as e:
            return str(e).replace("Password validation failed: ", "").split("; ")

    @staticmethod
    def calculate_strength_score(password: str) -> int:
        """
        Calculate password strength score (0-100).

        Args:
            password: Password to evaluate

        Returns:
            int: Strength score from 0-100
        """
        if not password:
            return 0

        score = 0

        # Length scoring
        if len(password) >= 8:
            score += 25
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 10

        # Character variety scoring
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 15

        # Complexity bonus
        char_types = sum(
            [
                any(c.islower() for c in password),
                any(c.isupper() for c in password),
                any(c.isdigit() for c in password),
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            ]
        )

        if char_types >= 3:
            score += 5

        return min(score, 100)

    @property
    def strength_score(self) -> int:
        """Get password strength score."""
        return self.calculate_strength_score(self.password)

    @property
    def strength_level(self) -> str:
        """Get password strength level description."""
        score = self.strength_score
        if score >= 80:
            return "Very Strong"
        if score >= 60:
            return "Strong"
        if score >= 40:
            return "Medium"
        if score >= 20:
            return "Weak"
        return "Very Weak"

    @property
    def has_uppercase(self) -> bool:
        """Check if password has uppercase letters."""
        return any(c.isupper() for c in self.password)

    @property
    def has_lowercase(self) -> bool:
        """Check if password has lowercase letters."""
        return any(c.islower() for c in self.password)

    @property
    def has_numbers(self) -> bool:
        """Check if password has numbers."""
        return any(c.isdigit() for c in self.password)

    @property
    def has_special(self) -> bool:
        """Check if password has special characters."""
        return any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in self.password)

    def get_feedback(self) -> dict[str, bool | str | int | list[str]]:
        """Get comprehensive password feedback."""
        return {
            "is_valid": len(self._validate_password()) == 0,
            "strength_score": self.strength_score,
            "strength_level": self.strength_level,
            "length": len(self.password),
            "has_uppercase": self.has_uppercase,
            "has_lowercase": self.has_lowercase,
            "has_numbers": self.has_numbers,
            "has_special": self.has_special,
            "issues": self._validate_password(),
        }

    def __str__(self) -> str:
        """String representation (masked)."""
        return "*" * len(self.password)

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, PasswordValidator):
            return False
        return self.password == other.password

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.password)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"PasswordValidator(length={len(self.password)}, strength='{self.strength_level}')"


class URLValidator:
    """URL validation with comprehensive format checking and rich functionality."""

    def __init__(self, url: str):
        """
        Initialize and validate URL.

        Args:
            url: URL string to validate

        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        self.value = self._validate_and_normalize(url)

    def _validate_and_normalize(self, url: str) -> str:
        """Validate and normalize URL."""
        if not isinstance(url, str):
            raise ValidationError("URL must be a string")

        url = url.strip()

        # Basic URL validation
        url_pattern = re.compile(
            r"^https?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )

        if not url_pattern.match(url):
            raise ValidationError("Invalid URL format")

        return url

    @staticmethod
    def validate_format(url: str) -> bool:
        """
        Static method to validate URL format.

        Args:
            url: URL to validate

        Returns:
            bool: True if URL format is valid
        """
        if not url or not isinstance(url, str):
            return False

        url_pattern = re.compile(
            r"^https?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )

        return bool(url_pattern.match(url.strip()))

    @property
    def scheme(self) -> str:
        """Extract scheme from URL."""
        return self.value.split("://")[0]

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
        # Simple domain extraction
        parts = self.value.split("://")[1].split("/")[0].split(":")
        return parts[0]

    @property
    def port(self) -> int | None:
        """Extract port from URL."""
        try:
            parts = self.value.split("://")[1].split("/")[0].split(":")
            if len(parts) > 1:
                return int(parts[1])
        except (IndexError, ValueError):
            pass
        return None

    @property
    def is_secure(self) -> bool:
        """Check if URL uses HTTPS."""
        return self.scheme.lower() == "https"

    @property
    def is_localhost(self) -> bool:
        """Check if URL points to localhost."""
        domain = self.domain.lower()
        return domain in ["localhost", "127.0.0.1", "::1"]

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, URLValidator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"URLValidator('{self.value}')"


class FilenameValidator:
    """Filename validation with sanitization and rich functionality."""

    def __init__(self, filename: str, max_length: int = 255):
        """
        Initialize and validate filename.

        Args:
            filename: Filename to validate
            max_length: Maximum filename length

        Raises:
            ValidationError: If filename is invalid
        """
        if not filename:
            raise ValidationError("Filename cannot be empty")

        self.max_length = max_length
        self.value = self._validate_and_sanitize(filename)

    def _validate_and_sanitize(self, filename: str) -> str:
        """Validate and sanitize filename."""
        if not isinstance(filename, str):
            raise ValidationError("Filename must be a string")

        # Remove path components
        filename = filename.replace("/", "").replace("\\", "")

        if not filename:
            raise ValidationError("Filename cannot be empty after sanitization")

        # Replace problematic characters
        filename = re.sub(r'[<>:"|?*]', "_", filename)

        # Remove control characters
        filename = "".join(c for c in filename if ord(c) >= 32)

        # Limit length
        if len(filename) > self.max_length:
            name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
            if ext:
                max_name_length = self.max_length - len(ext) - 1
                filename = f"{name[:max_name_length]}.{ext}"
            else:
                filename = filename[: self.max_length]

        return filename

    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> str:
        """
        Static method to sanitize filename.

        Args:
            filename: Filename to sanitize
            max_length: Maximum length

        Returns:
            str: Sanitized filename
        """
        try:
            validator = FilenameValidator(filename, max_length)
            return validator.value
        except ValidationError:
            return "invalid_filename"

    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """
        Static method to check if filename is safe.

        Args:
            filename: Filename to check

        Returns:
            bool: True if filename is safe
        """
        try:
            FilenameValidator(filename)
            return True
        except ValidationError:
            return False

    @property
    def name(self) -> str:
        """Get filename without extension."""
        if "." in self.value:
            return self.value.rsplit(".", 1)[0]
        return self.value

    @property
    def extension(self) -> str:
        """Get file extension."""
        if "." in self.value:
            return self.value.rsplit(".", 1)[1]
        return ""

    @property
    def is_hidden(self) -> bool:
        """Check if filename starts with dot (hidden file)."""
        return self.value.startswith(".")

    def change_extension(self, new_extension: str) -> str:
        """
        Change file extension.

        Args:
            new_extension: New extension (without dot)

        Returns:
            str: Filename with new extension
        """
        return f"{self.name}.{new_extension.lstrip('.')}"

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, FilenameValidator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"FilenameValidator('{self.value}')"


# =====================================================================================
# JSON SCHEMA VALIDATION
# =====================================================================================


def validate_json_schema(
    data: dict[str, Any],
    schema: dict[str, Any],
) -> list[str]:
    """
    Validate data against JSON schema.

    Args:
        data: Data to validate
        schema: JSON schema

    Returns:
        list[str]: List of validation errors (empty if valid)
    """
    errors = []

    required_fields = schema.get("required", [])
    properties = schema.get("properties", {})

    # Check required fields
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # Check field types
    for field, value in data.items():
        if field in properties:
            expected_type = properties[field].get("type")
            if expected_type and not _check_type(value, expected_type):
                errors.append(f"Invalid type for {field}: expected {expected_type}")

    return errors


def _check_type(value: Any, expected: str | list[str]) -> bool:
    """Check if value matches expected type."""
    if isinstance(expected, list):
        return any(_check_type(value, t) for t in expected)

    type_map: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }

    expected_type = type_map.get(expected)
    if expected_type:
        return isinstance(value, expected_type)

    return True


# =====================================================================================
# FINANCIAL VALIDATION UTILITIES
# =====================================================================================


class CreditCardValidator:
    """
    Credit card validation utility following DDD principles.
    
    Validates credit card numbers using the Luhn algorithm and provides
    card type detection and formatting capabilities.
    """
    
    CARD_TYPES = {
        "visa": r"^4[0-9]{12}(?:[0-9]{3})?$",
        "mastercard": r"^5[1-5][0-9]{14}$",
        "amex": r"^3[47][0-9]{13}$",
        "discover": r"^6(?:011|5[0-9]{2})[0-9]{12}$",
        "diners": r"^3[0689][0-9]{12}$",
        "jcb": r"^(?:2131|1800|35\d{3})\d{11}$"
    }
    
    def __init__(self, card_number: str):
        """
        Initialize and validate credit card number.
        
        Args:
            card_number: Credit card number to validate
            
        Raises:
            ValidationError: If card number is invalid
        """
        if not card_number:
            raise ValidationError("Credit card number cannot be empty")
            
        self.value = self._validate_and_normalize(card_number)
        self.card_type = self._detect_card_type()
    
    def _validate_and_normalize(self, card_number: str) -> str:
        """Validate and normalize credit card number."""
        if not isinstance(card_number, str):
            raise ValidationError("Credit card number must be a string")
        
        # Remove spaces and dashes
        normalized = re.sub(r'[\s-]', '', card_number)
        
        # Check if only digits
        if not normalized.isdigit():
            raise ValidationError("Credit card number must contain only digits")
        
        # Check length (13-19 digits)
        if len(normalized) < 13 or len(normalized) > 19:
            raise ValidationError("Credit card number must be 13-19 digits long")
        
        # Validate using Luhn algorithm
        if not self._luhn_check(normalized):
            raise ValidationError("Invalid credit card number (failed Luhn check)")
        
        return normalized
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        def luhn_digit(n):
            return sum(divmod(n * 2, 10))
        
        digits = [int(d) for d in card_number]
        checksum = sum(digits[-1::-2]) + sum(luhn_digit(d) for d in digits[-2::-2])
        return checksum % 10 == 0
    
    def _detect_card_type(self) -> str:
        """Detect credit card type based on number pattern."""
        for card_type, pattern in self.CARD_TYPES.items():
            if re.match(pattern, self.value):
                return card_type
        return "unknown"
    
    @staticmethod
    def is_valid_card_number(card_number: str) -> bool:
        """
        Static method to check if card number is valid.
        
        Args:
            card_number: Card number to validate
            
        Returns:
            bool: True if valid
        """
        try:
            CreditCardValidator(card_number)
            return True
        except ValidationError:
            return False
    
    @staticmethod
    def detect_card_type(card_number: str) -> str:
        """
        Static method to detect card type.
        
        Args:
            card_number: Card number to check
            
        Returns:
            str: Card type or "unknown"
        """
        try:
            validator = CreditCardValidator(card_number)
            return validator.card_type
        except ValidationError:
            return "unknown"
    
    @property
    def formatted(self) -> str:
        """Get formatted card number (masked)."""
        if len(self.value) <= 4:
            return self.value
        return f"****-****-****-{self.value[-4:]}"
    
    @property
    def last_four(self) -> str:
        """Get last four digits."""
        return self.value[-4:]
    
    @property
    def first_six(self) -> str:
        """Get first six digits (BIN)."""
        return self.value[:6]
    
    def __str__(self) -> str:
        """String representation (masked)."""
        return self.formatted
    
    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, CreditCardValidator):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"CreditCardValidator(type='{self.card_type}', last_four='{self.last_four}')"


class SSNValidator:
    """
    US Social Security Number validation utility.
    
    Validates SSN format and provides formatting capabilities.
    """
    
    SSN_PATTERN = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
    
    def __init__(self, ssn: str):
        """
        Initialize and validate SSN.
        
        Args:
            ssn: Social Security Number to validate
            
        Raises:
            ValidationError: If SSN is invalid
        """
        if not ssn:
            raise ValidationError("SSN cannot be empty")
            
        self.value = self._validate_and_normalize(ssn)
    
    def _validate_and_normalize(self, ssn: str) -> str:
        """Validate and normalize SSN."""
        if not isinstance(ssn, str):
            raise ValidationError("SSN must be a string")
        
        # Remove spaces and dashes
        normalized = re.sub(r'[\s-]', '', ssn)
        
        # Check if only digits
        if not normalized.isdigit():
            raise ValidationError("SSN must contain only digits")
        
        # Check length
        if len(normalized) != 9:
            raise ValidationError("SSN must be exactly 9 digits")
        
        # Check for invalid patterns
        if normalized == "000000000":
            raise ValidationError("SSN cannot be all zeros")
        
        if normalized[:3] == "000":
            raise ValidationError("SSN area number cannot be 000")
        
        if normalized[3:5] == "00":
            raise ValidationError("SSN group number cannot be 00")
        
        if normalized[5:] == "0000":
            raise ValidationError("SSN serial number cannot be 0000")
        
        return normalized
    
    @staticmethod
    def is_valid_ssn(ssn: str) -> bool:
        """
        Static method to check if SSN is valid.
        
        Args:
            ssn: SSN to validate
            
        Returns:
            bool: True if valid
        """
        try:
            SSNValidator(ssn)
            return True
        except ValidationError:
            return False
    
    @property
    def formatted(self) -> str:
        """Get formatted SSN (XXX-XX-XXXX)."""
        return f"{self.value[:3]}-{self.value[3:5]}-{self.value[5:]}"
    
    @property
    def masked(self) -> str:
        """Get masked SSN (XXX-XX-1234)."""
        return f"XXX-XX-{self.value[-4:]}"
    
    def __str__(self) -> str:
        """String representation (masked)."""
        return self.masked
    
    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, SSNValidator):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"SSNValidator(masked='{self.masked}')"


class IPAddressValidator:
    """
    IP address validation utility supporting both IPv4 and IPv6.
    
    Validates IP address format and provides type detection.
    """
    
    IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    IPV6_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    
    def __init__(self, ip_address: str):
        """
        Initialize and validate IP address.
        
        Args:
            ip_address: IP address to validate
            
        Raises:
            ValidationError: If IP address is invalid
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")
            
        self.value = self._validate_and_normalize(ip_address)
        self.version = self._detect_version()
    
    def _validate_and_normalize(self, ip_address: str) -> str:
        """Validate and normalize IP address."""
        if not isinstance(ip_address, str):
            raise ValidationError("IP address must be a string")
        
        ip_address = ip_address.strip()
        
        # Check IPv4
        if self.IPV4_PATTERN.match(ip_address):
            return ip_address
        
        # Check IPv6 (simplified check)
        if self.IPV6_PATTERN.match(ip_address):
            return ip_address.lower()
        
        # Check compressed IPv6
        if "::" in ip_address:
            parts = ip_address.split("::")
            if len(parts) == 2:
                # Basic IPv6 validation
                return ip_address.lower()
        
        raise ValidationError("Invalid IP address format")
    
    def _detect_version(self) -> int:
        """Detect IP version."""
        if ":" in self.value:
            return 6
        return 4
    
    @staticmethod
    def is_valid_ip(ip_address: str) -> bool:
        """
        Static method to check if IP address is valid.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            bool: True if valid
        """
        try:
            IPAddressValidator(ip_address)
            return True
        except ValidationError:
            return False
    
    @staticmethod
    def get_ip_version(ip_address: str) -> int | None:
        """
        Static method to get IP version.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            int | None: 4 or 6 for IPv4/IPv6, None if invalid
        """
        try:
            validator = IPAddressValidator(ip_address)
            return validator.version
        except ValidationError:
            return None
    
    @property
    def is_ipv4(self) -> bool:
        """Check if IPv4."""
        return self.version == 4
    
    @property
    def is_ipv6(self) -> bool:
        """Check if IPv6."""
        return self.version == 6
    
    @property
    def is_private(self) -> bool:
        """Check if private IP address."""
        if self.is_ipv4:
            parts = [int(x) for x in self.value.split(".")]
            # Private IPv4 ranges
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168)
            )
        return False  # Simplified for IPv6
    
    @property
    def is_loopback(self) -> bool:
        """Check if loopback address."""
        if self.is_ipv4:
            return self.value.startswith("127.")
        else:
            return self.value == "::1"
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, IPAddressValidator):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"IPAddressValidator('{self.value}', version={self.version})"


class OTPValidator:
    """
    One-Time Password validation utility.
    
    Validates OTP format and provides time-based validation.
    """
    
    def __init__(self, otp: str, length: int = 6):
        """
        Initialize and validate OTP.
        
        Args:
            otp: OTP to validate
            length: Expected OTP length (default: 6)
            
        Raises:
            ValidationError: If OTP is invalid
        """
        if not otp:
            raise ValidationError("OTP cannot be empty")
            
        self.length = length
        self.value = self._validate_and_normalize(otp)
    
    def _validate_and_normalize(self, otp: str) -> str:
        """Validate and normalize OTP."""
        if not isinstance(otp, str):
            raise ValidationError("OTP must be a string")
        
        # Remove spaces
        normalized = otp.replace(" ", "").replace("-", "")
        
        # Check if only digits
        if not normalized.isdigit():
            raise ValidationError("OTP must contain only digits")
        
        # Check length
        if len(normalized) != self.length:
            raise ValidationError(f"OTP must be exactly {self.length} digits")
        
        return normalized
    
    @staticmethod
    def is_valid_otp(otp: str, length: int = 6) -> bool:
        """
        Static method to check if OTP is valid.
        
        Args:
            otp: OTP to validate
            length: Expected length
            
        Returns:
            bool: True if valid
        """
        try:
            OTPValidator(otp, length)
            return True
        except ValidationError:
            return False
    
    @property
    def formatted(self) -> str:
        """Get formatted OTP (with spaces every 3 digits for readability)."""
        if self.length == 6:
            return f"{self.value[:3]} {self.value[3:]}"
        return self.value
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, OTPValidator):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"OTPValidator('{self.value}', length={self.length})"


# =====================================================================================
# ENHANCED PHONE NUMBER VALIDATION
# =====================================================================================


class EnhancedPhoneValidator:
    """
    Enhanced phone number validation with international support.
    
    Validates phone numbers with country codes and provides formatting.
    """
    
    # Common country codes and their phone number patterns
    COUNTRY_PATTERNS = {
        "US": r"^(\+1)?[-.\s]?(\([0-9]{3}\))?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$",
        "CA": r"^(\+1)?[-.\s]?(\([0-9]{3}\))?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$",
        "GB": r"^(\+44)?[-.\s]?[0-9]{4}[-.\s]?[0-9]{6}$",
        "AU": r"^(\+61)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{3}$",
    }
    
    def __init__(self, phone_number: str, country_code: str = "US"):
        """
        Initialize and validate phone number.
        
        Args:
            phone_number: Phone number to validate
            country_code: Country code (default: US)
            
        Raises:
            ValidationError: If phone number is invalid
        """
        if not phone_number:
            raise ValidationError("Phone number cannot be empty")
            
        self.country_code = country_code.upper()
        self.value = self._validate_and_normalize(phone_number)
    
    def _validate_and_normalize(self, phone_number: str) -> str:
        """Validate and normalize phone number."""
        if not isinstance(phone_number, str):
            raise ValidationError("Phone number must be a string")
        
        # Remove common formatting
        normalized = re.sub(r'[\s()-.]', '', phone_number)
        
        # Remove country code prefix if present
        if normalized.startswith('+'):
            if self.country_code == "US" and normalized.startswith('+1'):
                normalized = normalized[2:]
            elif self.country_code == "GB" and normalized.startswith('+44'):
                normalized = normalized[3:]
            elif self.country_code == "AU" and normalized.startswith('+61'):
                normalized = normalized[3:]
        
        # Check if only digits
        if not normalized.isdigit():
            raise ValidationError("Phone number must contain only digits")
        
        # Validate based on country
        if self.country_code in ["US", "CA"]:
            if len(normalized) != 10:
                raise ValidationError("US/CA phone numbers must be 10 digits")
            if normalized[0] in ['0', '1']:
                raise ValidationError("US/CA phone numbers cannot start with 0 or 1")
        else:
            # Basic length check for other countries
            if len(normalized) < 7 or len(normalized) > 15:
                raise ValidationError("Phone number must be 7-15 digits")
        
        return normalized
    
    @staticmethod
    def is_valid_phone(phone_number: str, country_code: str = "US") -> bool:
        """
        Static method to check if phone number is valid.
        
        Args:
            phone_number: Phone number to validate
            country_code: Country code
            
        Returns:
            bool: True if valid
        """
        try:
            EnhancedPhoneValidator(phone_number, country_code)
            return True
        except ValidationError:
            return False
    
    @property
    def formatted(self) -> str:
        """Get formatted phone number."""
        if self.country_code in ["US", "CA"]:
            return f"({self.value[:3]}) {self.value[3:6]}-{self.value[6:]}"
        return self.value
    
    @property
    def international(self) -> str:
        """Get international format."""
        country_prefixes = {
            "US": "+1",
            "CA": "+1",
            "GB": "+44",
            "AU": "+61"
        }
        prefix = country_prefixes.get(self.country_code, "+")
        return f"{prefix} {self.value}"
    
    def __str__(self) -> str:
        """String representation."""
        return self.formatted
    
    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        if not isinstance(other, EnhancedPhoneValidator):
            return False
        return self.value == other.value and self.country_code == other.country_code
    
    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.value, self.country_code))
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"EnhancedPhoneValidator('{self.value}', country='{self.country_code}')"
