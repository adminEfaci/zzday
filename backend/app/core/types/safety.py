"""
Type Safety Utilities

Provides mixins and utilities for building type-safe operations and classes.
"""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
U = TypeVar("U")


class TypeSafetyError(Exception):
    """Raised when type safety is violated."""


class TypeSafetyMixin:
    """
    Mixin class that provides type safety utilities.

    Provides methods for safe type conversions, validation,
    and type-aware operations.
    """

    def safe_cast(self, value: Any, target_type: type[T]) -> T | None:
        """
        Safely cast a value to target type.

        Args:
            value: Value to cast
            target_type: Target type

        Returns:
            Casted value or None if cast fails
        """
        try:
            if isinstance(value, target_type):
                return value

            # Try direct casting for basic types
            if target_type in (str, int, float, bool):
                return target_type(value)  # type: ignore

            return None
        except (ValueError, TypeError):
            return None

    def require_type(self, value: Any, expected_type: type[T]) -> T:
        """
        Require a value to be of specific type.

        Args:
            value: Value to check
            expected_type: Required type

        Returns:
            The value if type check passes

        Raises:
            TypeSafetyError: If type check fails
        """
        if not isinstance(value, expected_type):
            raise TypeSafetyError(
                f"Expected {expected_type.__name__}, got {type(value).__name__}"
            )
        return value

    def safe_getattr(
        self, obj: Any, attr: str, default: T, expected_type: type[T]
    ) -> T:
        """
        Safely get attribute with type checking.

        Args:
            obj: Object to get attribute from
            attr: Attribute name
            default: Default value
            expected_type: Expected type of attribute

        Returns:
            Attribute value or default
        """
        try:
            value = getattr(obj, attr, default)
            if isinstance(value, expected_type):
                return value
            return default
        except (AttributeError, TypeError):
            return default

    @contextmanager
    def type_safety_context(self):
        """
        Context manager for type-safe operations.

        Catches and logs type-related errors.
        """
        try:
            yield
        except (TypeError, ValueError, AttributeError) as e:
            logger.warning(f"Type safety violation: {e}")
            raise TypeSafetyError(f"Type safety violation: {e}") from e


class TypeSafeOperation(Generic[T], ABC):
    """
    Abstract base class for type-safe operations.

    Provides a framework for building operations that maintain
    type safety throughout their execution.
    """

    def __init__(self, result_type: type[T]) -> None:
        self.result_type = result_type
        self._errors: list[str] = []

    @abstractmethod
    def execute(self, *args: Any, **kwargs: Any) -> T:
        """
        Execute the operation.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Operation result
        """

    def validate_input(self, value: Any, expected_type: type[U]) -> U:
        """
        Validate input parameter.

        Args:
            value: Value to validate
            expected_type: Expected type

        Returns:
            Validated value

        Raises:
            TypeSafetyError: If validation fails
        """
        if not isinstance(value, expected_type):
            error = f"Input validation failed: expected {expected_type.__name__}, got {type(value).__name__}"
            self._errors.append(error)
            raise TypeSafetyError(error)
        return value

    def validate_result(self, result: Any) -> T:
        """
        Validate operation result.

        Args:
            result: Result to validate

        Returns:
            Validated result

        Raises:
            TypeSafetyError: If validation fails
        """
        if not isinstance(result, self.result_type):
            error = f"Result validation failed: expected {self.result_type.__name__}, got {type(result).__name__}"
            self._errors.append(error)
            raise TypeSafetyError(error)
        return result

    @property
    def errors(self) -> list[str]:
        """Get list of validation errors."""
        return self._errors.copy()

    def clear_errors(self) -> None:
        """Clear validation errors."""
        self._errors.clear()


class TypeGuard:
    """
    Type guard utilities for runtime type checking.
    """

    @staticmethod
    def is_string(value: Any) -> bool:
        """Check if value is a string."""
        return isinstance(value, str)

    @staticmethod
    def is_integer(value: Any) -> bool:
        """Check if value is an integer."""
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def is_float(value: Any) -> bool:
        """Check if value is a float."""
        return isinstance(value, float)

    @staticmethod
    def is_numeric(value: Any) -> bool:
        """Check if value is numeric (int or float)."""
        return isinstance(value, int | float) and not isinstance(value, bool)

    @staticmethod
    def is_boolean(value: Any) -> bool:
        """Check if value is a boolean."""
        return isinstance(value, bool)

    @staticmethod
    def is_list_of(value: Any, item_type: type[T]) -> bool:
        """Check if value is a list of specific type."""
        return isinstance(value, list) and all(
            isinstance(item, item_type) for item in value
        )

    @staticmethod
    def is_dict_of(value: Any, key_type: type[T], value_type: type[U]) -> bool:
        """Check if value is a dict with specific key/value types."""
        return isinstance(value, dict) and all(
            isinstance(k, key_type) and isinstance(v, value_type)
            for k, v in value.items()
        )

    @staticmethod
    def is_optional(value: Any, expected_type: type[T]) -> bool:
        """Check if value is None or of expected type."""
        return value is None or isinstance(value, expected_type)


class TypeConverter:
    """
    Safe type conversion utilities.
    """

    @staticmethod
    def to_string(value: Any, default: str = "") -> str:
        """
        Convert value to string safely.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            String representation of value
        """
        try:
            if value is None:
                return default
            return str(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def to_integer(value: Any, default: int = 0) -> int:
        """
        Convert value to integer safely.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Integer representation of value
        """
        try:
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, str):
                return int(float(value))  # Handle "1.0" -> 1
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def to_float(value: Any, default: float = 0.0) -> float:
        """
        Convert value to float safely.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Float representation of value
        """
        try:
            if isinstance(value, bool):
                return float(value)
            return float(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def to_boolean(value: Any, default: bool = False) -> bool:
        """
        Convert value to boolean safely.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Boolean representation of value
        """
        if value is None:
            return default

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on", "y")

        if isinstance(value, int | float):
            return bool(value)

        return default

    @staticmethod
    def to_datetime(value: Any, default: datetime | None = None) -> datetime | None:
        """
        Convert value to datetime safely.

        Args:
            value: Value to convert
            default: Default value if conversion fails

        Returns:
            Datetime representation of value or default
        """
        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                from datetime import datetime as dt

                # Try common formats
                for fmt in [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d",
                ]:
                    try:
                        return dt.strptime(value, fmt)
                    except ValueError:
                        continue
            except (ValueError, ImportError):
                pass

        return default


class TypeSafeDict(dict):
    """
    Dictionary that enforces type safety for keys and values.
    """

    def __init__(
        self, key_type: type[T], value_type: type[U], data: dict[T, U] | None = None
    ) -> None:
        self.key_type = key_type
        self.value_type = value_type
        super().__init__()

        if data:
            for k, v in data.items():
                self[k] = v

    def __setitem__(self, key: T, value: U) -> None:
        """Set item with type checking."""
        if not isinstance(key, self.key_type):
            raise TypeSafetyError(
                f"Key must be {self.key_type.__name__}, got {type(key).__name__}"
            )

        if not isinstance(value, self.value_type):
            raise TypeSafetyError(
                f"Value must be {self.value_type.__name__}, got {type(value).__name__}"
            )

        super().__setitem__(key, value)

    def update(self, other: dict[T, U]) -> None:  # type: ignore
        """Update with type checking."""
        for key, value in other.items():
            self[key] = value


class TypeSafeList(list):
    """
    List that enforces type safety for items.
    """

    def __init__(self, item_type: type[T], data: list[T] | None = None) -> None:
        self.item_type = item_type
        super().__init__()

        if data:
            for item in data:
                self.append(item)

    def append(self, item: T) -> None:
        """Append item with type checking."""
        if not isinstance(item, self.item_type):
            raise TypeSafetyError(
                f"Item must be {self.item_type.__name__}, got {type(item).__name__}"
            )
        super().append(item)

    def insert(self, index: int, item: T) -> None:
        """Insert item with type checking."""
        if not isinstance(item, self.item_type):
            raise TypeSafetyError(
                f"Item must be {self.item_type.__name__}, got {type(item).__name__}"
            )
        super().insert(index, item)

    def extend(self, items: list[T]) -> None:
        """Extend with type checking."""
        for item in items:
            self.append(item)
