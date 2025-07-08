"""
Runtime Type Validation System

Provides decorators and utilities for runtime type checking to ensure
type safety beyond static analysis.
"""

import functools
import inspect
import logging
from collections.abc import Callable
from typing import (
    Any,
    Protocol,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    runtime_checkable,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


class TypeValidationError(Exception):
    """Raised when runtime type validation fails."""

    def __init__(
        self, message: str, expected_type: type[Any], actual_value: Any
    ) -> None:
        self.expected_type = expected_type
        self.actual_value = actual_value
        super().__init__(message)


class TypeValidator:
    """
    Runtime type validation utility.

    Provides methods for validating function arguments and return values
    against their type annotations at runtime.
    """

    @staticmethod
    def validate_at_runtime(func: F) -> F:
        """
        Decorator that validates function arguments and return type at runtime.

        Args:
            func: Function to validate

        Returns:
            Decorated function with runtime type validation

        Raises:
            TypeValidationError: If validation fails
        """
        signature = inspect.signature(func)
        type_hints = get_type_hints(func)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Bind arguments to parameters
            bound_args = signature.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Validate each argument
            for param_name, value in bound_args.arguments.items():
                if param_name in type_hints:
                    expected_type = type_hints[param_name]
                    if not TypeValidator._is_instance(value, expected_type):
                        raise TypeValidationError(
                            f"Argument '{param_name}' expected {expected_type}, got {type(value).__name__}",
                            expected_type,
                            value,
                        )

            # Call the function
            result = func(*args, **kwargs)

            # Validate return type
            if "return" in type_hints:
                return_type = type_hints["return"]
                if not TypeValidator._is_instance(result, return_type):
                    raise TypeValidationError(
                        f"Return value expected {return_type}, got {type(result).__name__}",
                        return_type,
                        result,
                    )

            return result

        return wrapper  # type: ignore

    @staticmethod
    def check_return_type(value: Any, expected_type: type[T]) -> bool:
        """
        Check if a value matches the expected return type.

        Args:
            value: Value to check
            expected_type: Expected type

        Returns:
            True if value matches type, False otherwise
        """
        return TypeValidator._is_instance(value, expected_type)

    @staticmethod
    def _is_instance(value: Any, expected_type: type[Any]) -> bool:
        """
        Enhanced isinstance check that handles generic types and unions.

        Args:
            value: Value to check
            expected_type: Type to check against

        Returns:
            True if value is instance of expected_type
        """
        # Handle None/Optional
        if value is None:
            return TypeValidator._is_optional_type(expected_type)

        # Handle Union types
        origin = get_origin(expected_type)
        if origin is Union:
            return any(
                TypeValidator._is_instance(value, arg_type)
                for arg_type in get_args(expected_type)
            )

        # Handle generic types
        if origin is not None:
            # For List, Dict, etc.
            if origin in (list, list):
                if not isinstance(value, list):
                    return False
                args = get_args(expected_type)
                if args:
                    return all(
                        TypeValidator._is_instance(item, args[0]) for item in value
                    )
                return True

            if origin in (dict, dict):
                if not isinstance(value, dict):
                    return False
                args = get_args(expected_type)
                if len(args) == 2:
                    key_type, value_type = args
                    return all(
                        TypeValidator._is_instance(k, key_type)
                        and TypeValidator._is_instance(v, value_type)
                        for k, v in value.items()
                    )
                return True

            if origin in (tuple,):
                if not isinstance(value, tuple):
                    return False
                args = get_args(expected_type)
                if args:
                    if len(args) != len(value):
                        return False
                    return all(
                        TypeValidator._is_instance(v, arg_type)
                        for v, arg_type in zip(value, args, strict=False)
                    )
                return True

            # For other generic types, check the origin
            return isinstance(value, origin)

        # Handle regular types
        try:
            return isinstance(value, expected_type)
        except TypeError:
            # Handle special cases like Protocol
            return True

    @staticmethod
    def _is_optional_type(type_hint: type[Any]) -> bool:
        """Check if a type hint represents an Optional type."""
        origin = get_origin(type_hint)
        if origin is Union:
            args = get_args(type_hint)
            return len(args) == 2 and type(None) in args
        return False


def type_checked(func: F) -> F:
    """
    Decorator for runtime type checking.

    Validates function arguments and return value against type annotations.

    Args:
        func: Function to decorate

    Returns:
        Decorated function with type checking
    """
    return TypeValidator.validate_at_runtime(func)


def validate_return_type(value: Any, expected_type: type[T]) -> T:
    """
    Validate and return a value ensuring it matches the expected type.

    Args:
        value: Value to validate
        expected_type: Expected type

    Returns:
        The value if validation passes

    Raises:
        TypeValidationError: If validation fails
    """
    if not TypeValidator.check_return_type(value, expected_type):
        raise TypeValidationError(
            f"Expected {expected_type}, got {type(value).__name__}",
            expected_type,
            value,
        )
    return value


@runtime_checkable
class TypedFunction(Protocol):
    """Protocol for functions with proper type annotations."""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        ...

    @property
    def __annotations__(self) -> dict[str, Any]:
        ...


class TypeRegistry:
    """
    Registry for custom type validators.

    Allows registration of custom validation logic for specific types.
    """

    def __init__(self) -> None:
        self._validators: dict[type[Any], Callable[[Any], bool]] = {}

    def register(self, type_class: type[T], validator: Callable[[Any], bool]) -> None:
        """
        Register a custom validator for a type.

        Args:
            type_class: Type to register validator for
            validator: Validation function
        """
        self._validators[type_class] = validator

    def validate(self, value: Any, expected_type: type[Any]) -> bool:
        """
        Validate a value using registered validators.

        Args:
            value: Value to validate
            expected_type: Expected type

        Returns:
            True if validation passes
        """
        if expected_type in self._validators:
            return self._validators[expected_type](value)
        return TypeValidator._is_instance(value, expected_type)


# Global type registry instance
type_registry = TypeRegistry()


def register_type_validator(
    type_class: type[T],
) -> Callable[[Callable[[Any], bool]], Callable[[Any], bool]]:
    """
    Decorator to register a custom type validator.

    Args:
        type_class: Type to register validator for

    Returns:
        Decorator function
    """

    def decorator(validator: Callable[[Any], bool]) -> Callable[[Any], bool]:
        type_registry.register(type_class, validator)
        return validator

    return decorator
