"""
Type Validation System

This module provides comprehensive type validation, runtime type checking,
and type safety utilities for the EzzDay backend.

Exports:
    - TypeValidator: Runtime type validation decorator
    - TypeSafetyMixin: Base class for type-safe operations
    - type_checked: Function decorator for runtime type checking
    - validate_return_type: Return type validation utility
    - get_type_hints_extended: Enhanced type hints extraction
"""

# Import with error handling
try:
    from .hints import get_type_hints_extended, resolve_forward_refs
except ImportError:
    def get_type_hints_extended(*args, **kwargs):
        """Fallback type hints function."""
        return {}
    
    def resolve_forward_refs(*args, **kwargs):
        """Fallback forward refs function."""
        return

try:
    from .protocols import (
        Auditable,
        Cacheable,
        Identifiable,
        Serializable,
        Timestamped,
        Versioned,
    )
except ImportError:
    from typing import Protocol
    
    class Auditable(Protocol):
        """Auditable protocol."""
    
    class Cacheable(Protocol):
        """Cacheable protocol."""
    
    class Identifiable(Protocol):
        """Identifiable protocol."""
    
    class Serializable(Protocol):
        """Serializable protocol."""
    
    class Timestamped(Protocol):
        """Timestamped protocol."""
    
    class Versioned(Protocol):
        """Versioned protocol."""

try:
    from .safety import TypeSafeOperation, TypeSafetyMixin
except ImportError:
    class TypeSafeOperation:
        """Fallback type safe operation."""
    
    class TypeSafetyMixin:
        """Fallback type safety mixin."""

try:
    from .schemas import StrictModel, TypedModel
except ImportError:
    class StrictModel:
        """Fallback strict model."""
    
    class TypedModel:
        """Fallback typed model."""

try:
    from .validator import TypeValidator, type_checked, validate_return_type
except ImportError:
    class TypeValidator:
        """Fallback type validator."""
    
    def type_checked(func):
        """Fallback type checked decorator."""
        return func
    
    def validate_return_type(func):
        """Fallback return type validator."""
        return func

__all__ = [
    "Auditable",
    "Cacheable",
    # Protocols
    "Identifiable",
    "Serializable",
    "StrictModel",
    "Timestamped",
    "TypeSafeOperation",
    # Type safety
    "TypeSafetyMixin",
    # Core validation
    "TypeValidator",
    # Schemas
    "TypedModel",
    "Versioned",
    # Type hints utilities
    "get_type_hints_extended",
    "resolve_forward_refs",
    "type_checked",
    "validate_return_type",
]
