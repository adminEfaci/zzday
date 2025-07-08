"""
Enhanced Type Hints Utilities

Provides utilities for working with type hints, forward references,
and complex generic types.
"""

import logging
import sys
from typing import (
    Any,
    ForwardRef,
    TypeVar,
    Union,
    get_args,
    get_origin,  # type: ignore
    get_type_hints,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def get_type_hints_extended(
    obj: Any,
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | None = None,
    include_extras: bool = False,
) -> dict[str, Any]:
    """
    Enhanced version of get_type_hints that handles more edge cases.

    Args:
        obj: Object to get type hints from
        globalns: Global namespace for resolving forward references
        localns: Local namespace for resolving forward references
        include_extras: Include typing extras like Annotated

    Returns:
        Dictionary of type hints
    """
    try:
        # Get the object's module for namespace resolution
        if globalns is None and hasattr(obj, "__module__"):
            module = sys.modules.get(obj.__module__)
            if module:
                globalns = getattr(module, "__dict__", {})

        # Use standard get_type_hints with fallback
        try:
            hints = get_type_hints(
                obj, globalns=globalns, localns=localns, include_extras=include_extras
            )
        except (NameError, AttributeError, TypeError):
            # Fallback to raw annotations
            hints = getattr(obj, "__annotations__", {})
            if hints and globalns:
                # Try to resolve forward references manually
                hints = resolve_forward_refs(hints, globalns, localns)

        return hints

    except Exception as e:
        logger.warning(f"Failed to get type hints for {obj}: {e}")
        return {}


def resolve_forward_refs(
    annotations: dict[str, Any],
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Resolve forward references in type annotations.

    Args:
        annotations: Raw annotations dictionary
        globalns: Global namespace
        localns: Local namespace

    Returns:
        Resolved annotations dictionary
    """
    resolved = {}

    for name, annotation in annotations.items():
        try:
            resolved[name] = _resolve_annotation(annotation, globalns, localns)
        except Exception as e:
            logger.debug(
                f"Could not resolve annotation {name}: {annotation}, error: {e}"
            )
            resolved[name] = annotation

    return resolved


def _resolve_annotation(
    annotation: Any,
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | None = None,
) -> Any:
    """
    Resolve a single annotation.

    Args:
        annotation: Annotation to resolve
        globalns: Global namespace
        localns: Local namespace

    Returns:
        Resolved annotation
    """
    # Handle string annotations (forward references)
    if isinstance(annotation, str):
        try:
            # Create a ForwardRef and evaluate it
            ref = ForwardRef(annotation, is_argument=False)
            return ref._evaluate(globalns, localns, frozenset())
            return ref._evaluate(globalns, localns)
        except Exception:
            return annotation

    # Handle ForwardRef objects
    if isinstance(annotation, ForwardRef):
        try:
            return annotation._evaluate(globalns, localns, frozenset())
            return annotation._evaluate(globalns, localns)
        except Exception:
            return annotation

    # Handle generic types
    origin = get_origin(annotation)
    if origin is not None:
        args = get_args(annotation)
        if args:
            resolved_args = tuple(
                _resolve_annotation(arg, globalns, localns) for arg in args
            )
            try:
                return origin[resolved_args]
            except (TypeError, AttributeError):
                return annotation

    return annotation


def is_generic_type(type_hint: Any) -> bool:
    """
    Check if a type hint is a generic type.

    Args:
        type_hint: Type hint to check

    Returns:
        True if generic type
    """
    return get_origin(type_hint) is not None


def is_union_type(type_hint: Any) -> bool:
    """
    Check if a type hint is a Union type.

    Args:
        type_hint: Type hint to check

    Returns:
        True if Union type
    """
    return get_origin(type_hint) is Union


def is_optional_type(type_hint: Any) -> bool:
    """
    Check if a type hint is Optional (Union with None).

    Args:
        type_hint: Type hint to check

    Returns:
        True if Optional type
    """
    origin = get_origin(type_hint)
    if origin is Union:
        args = get_args(type_hint)
        return len(args) == 2 and type(None) in args
    return False


def get_union_args(type_hint: Any) -> tuple[Any, ...]:
    """
    Get arguments of a Union type.

    Args:
        type_hint: Union type hint

    Returns:
        Tuple of union arguments
    """
    if is_union_type(type_hint):
        return get_args(type_hint)
    return ()


def get_optional_inner_type(type_hint: Any) -> Any | None:
    """
    Get the inner type of an Optional type.

    Args:
        type_hint: Optional type hint

    Returns:
        Inner type or None
    """
    if is_optional_type(type_hint):
        args = get_args(type_hint)
        return next((arg for arg in args if arg is not type(None)), None)
    return None


def is_list_type(type_hint: Any) -> bool:
    """
    Check if a type hint is a List type.

    Args:
        type_hint: Type hint to check

    Returns:
        True if List type
    """
    origin = get_origin(type_hint)
    return origin is list or origin is List  # type: ignore


def is_dict_type(type_hint: Any) -> bool:
    """
    Check if a type hint is a Dict type.

    Args:
        type_hint: Type hint to check

    Returns:
        True if Dict type
    """
    origin = get_origin(type_hint)
    return origin is dict or origin is Dict  # type: ignore


def get_list_item_type(type_hint: Any) -> Any | None:
    """
    Get item type of a List type hint.

    Args:
        type_hint: List type hint

    Returns:
        Item type or None
    """
    if is_list_type(type_hint):
        args = get_args(type_hint)
        return args[0] if args else None
    return None


def get_dict_types(type_hint: Any) -> tuple[Any | None, Any | None]:
    """
    Get key and value types of a Dict type hint.

    Args:
        type_hint: Dict type hint

    Returns:
        Tuple of (key_type, value_type)
    """
    if is_dict_type(type_hint):
        args = get_args(type_hint)
        if len(args) >= 2:
            return args[0], args[1]
        if len(args) == 1:
            return args[0], None
    return None, None


def stringify_type(type_hint: Any) -> str:
    """
    Convert a type hint to a readable string.

    Args:
        type_hint: Type hint to stringify

    Returns:
        String representation
    """
    if type_hint is None:
        return "None"

    if isinstance(type_hint, type):
        return type_hint.__name__

    if isinstance(type_hint, str):
        return type_hint

    origin = get_origin(type_hint)
    if origin is not None:
        args = get_args(type_hint)
        if origin is Union:
            if len(args) == 2 and type(None) in args:
                # Optional type
                inner_type = next((arg for arg in args if arg is not type(None)), None)
                return f"{stringify_type(inner_type)} | None"
            # Union type
            arg_strings = [stringify_type(arg) for arg in args]
            return f"{' | '.join(arg_strings)}"

        if args:
            arg_strings = [stringify_type(arg) for arg in args]
            return f"{origin.__name__}[{', '.join(arg_strings)}]"
        return origin.__name__

    # Handle special cases
    if hasattr(type_hint, "__name__"):
        return type_hint.__name__

    return str(type_hint)


def get_class_type_vars(cls: type[Any]) -> dict[str, TypeVar]:
    """
    Get TypeVar definitions from a class.

    Args:
        cls: Class to inspect

    Returns:
        Dictionary of TypeVar names to TypeVar objects
    """
    type_vars = {}

    # Check class parameters
    if hasattr(cls, "__parameters__"):
        for param in cls.__parameters__:
            if isinstance(param, TypeVar):
                type_vars[param.__name__] = param

    # Check class annotations
    for name, annotation in getattr(cls, "__annotations__", {}).items():
        if isinstance(annotation, TypeVar):
            type_vars[name] = annotation

    return type_vars


def substitute_type_vars(type_hint: Any, substitutions: dict[TypeVar, Any]) -> Any:
    """
    Substitute TypeVars in a type hint.

    Args:
        type_hint: Type hint with TypeVars
        substitutions: Mapping of TypeVar to concrete types

    Returns:
        Type hint with substituted types
    """
    # Handle direct TypeVar
    if isinstance(type_hint, TypeVar):
        return substitutions.get(type_hint, type_hint)

    # Handle generic types
    origin = get_origin(type_hint)
    if origin is not None:
        args = get_args(type_hint)
        if args:
            substituted_args = tuple(
                substitute_type_vars(arg, substitutions) for arg in args
            )
            try:
                return origin[substituted_args]
            except (TypeError, AttributeError):
                return type_hint

    return type_hint


def type_check_compatibility(value_type: Any, expected_type: Any) -> bool:
    """
    Check if a value type is compatible with expected type.

    Args:
        value_type: Actual type of value
        expected_type: Expected type

    Returns:
        True if compatible
    """
    # Handle None/Optional
    if value_type is type(None):
        return is_optional_type(expected_type)

    # Handle exact match
    if value_type == expected_type:
        return True

    # Handle inheritance
    try:
        if isinstance(value_type, type) and isinstance(expected_type, type):
            return issubclass(value_type, expected_type)
    except TypeError:
        pass

    # Handle Union types
    if is_union_type(expected_type):
        return any(
            type_check_compatibility(value_type, arg) for arg in get_args(expected_type)
        )

    # Handle generic types
    expected_origin = get_origin(expected_type)
    value_origin = get_origin(value_type)

    if expected_origin is not None and value_origin is not None:
        if expected_origin == value_origin:
            # Check if argument types are compatible
            expected_args = get_args(expected_type)
            value_args = get_args(value_type)

            if len(expected_args) == len(value_args):
                return all(
                    type_check_compatibility(v_arg, e_arg)
                    for v_arg, e_arg in zip(value_args, expected_args, strict=False)
                )

    return False


# Import guards to prevent circular imports
# Fallback for compatibility
List = list  # type: ignore
Dict = dict  # type: ignore
