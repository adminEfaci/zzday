"""Domain primitives following pure Python, framework-agnostic principles.

This module provides the foundational domain modeling primitives for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are completely
independent of any framework (FastAPI, Pydantic, etc.).

Design Principles:
- Pure Python classes with explicit __init__ validation
- Framework-agnostic design for maximum portability
- Rich functionality with comprehensive utility methods
- Clean error handling using custom ValidationError
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
- Domain event handling without framework magic
- Immutable value objects and mutable entities with clear boundaries

Architecture:
- ValueObject: Immutable objects representing domain concepts
- Entity: Mutable objects with identity and lifecycle
- AggregateRoot: Entities that manage domain events and consistency
- DomainService: Stateless domain logic coordinators
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

from app.core.errors import ValidationError

# =====================================================================================
# VALUE OBJECT BASE CLASS
# =====================================================================================


class ValueObject(ABC):
    """
    Base value object following pure Python principles.

    Value objects are immutable objects that are defined entirely by their attributes.
    They have no conceptual identity and are equal when all their attributes are equal.

    Design Features:
    - Immutable by design (no setters, frozen behavior)
    - Framework-agnostic validation in __init__
    - Rich comparison and hashing support
    - Comprehensive string representations
    - Validation utilities for subclasses

    Usage Example:
        class Price(ValueObject):
            def __init__(self, amount: Decimal, currency: str):
                if amount < 0:
                    raise ValidationError("Price cannot be negative")
                self.amount = amount
                self.currency = currency.upper()

            def __str__(self) -> str:
                return f"{self.amount} {self.currency}"
    """

    def __init__(self):
        """Initialize value object. Subclasses should override with specific validation."""
        self._frozen = False
        self._hash_cache = None

    def _freeze(self) -> None:
        """Mark the object as frozen (immutable)."""
        self._frozen = True

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent modification after initialization."""
        if hasattr(self, "_frozen") and self._frozen and name != "_hash_cache":
            raise AttributeError(f"Cannot modify immutable {self.__class__.__name__}")
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent deletion of attributes."""
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError(
                f"Cannot delete attribute from immutable {self.__class__.__name__}"
            )
        super().__delattr__(name)

    def __eq__(self, other: Any) -> bool:
        """
        Check equality based on all attributes.

        Args:
            other: Object to compare with

        Returns:
            bool: True if objects are equal
        """
        if not isinstance(other, self.__class__):
            return False

        # Compare all non-private attributes
        self_attrs = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        other_attrs = {k: v for k, v in other.__dict__.items() if not k.startswith("_")}

        return self_attrs == other_attrs

    def __hash__(self) -> int:
        """
        Return hash based on all attributes.

        Returns:
            int: Hash value for use in sets/dicts
        """
        if self._hash_cache is None:
            # Include only non-private attributes in hash
            values = []
            for key in sorted(self.__dict__.keys()):
                if not key.startswith("_"):
                    value = self.__dict__[key]
                    # Handle unhashable types
                    if isinstance(value, list | dict | set):
                        if isinstance(value, dict):
                            value = tuple(sorted(value.items()))
                        elif isinstance(value, list | set):
                            value = tuple(
                                sorted(value) if isinstance(value, set) else value
                            )
                    values.append((key, value))

            self._hash_cache = hash((self.__class__.__name__, tuple(values)))

        return self._hash_cache

    def __repr__(self) -> str:
        """
        Detailed string representation for debugging.

        Returns:
            str: Detailed representation
        """
        attrs = []
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                attrs.append(f"{key}={value!r}")

        attrs_str = ", ".join(attrs)
        return f"{self.__class__.__name__}({attrs_str})"

    @abstractmethod
    def __str__(self) -> str:
        """String representation. Must be implemented by subclasses."""

    def to_dict(self) -> dict[str, Any]:
        """
        Convert value object to dictionary.

        Returns:
            dict[str, Any]: Dictionary representation
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                if hasattr(value, "to_dict"):
                    result[key] = value.to_dict()
                elif isinstance(value, UUID | datetime):
                    result[key] = str(value)
                else:
                    result[key] = value
        return result

    @classmethod
    def validate_not_empty(cls, value: Any, field_name: str) -> None:
        """
        Utility method to validate that a value is not empty.

        Args:
            value: Value to validate
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If value is empty
        """
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValidationError(f"{field_name} cannot be empty")

    @classmethod
    def validate_type(cls, value: Any, expected_type: type, field_name: str) -> None:
        """
        Utility method to validate value type.

        Args:
            value: Value to validate
            expected_type: Expected type
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If value is wrong type
        """
        if not isinstance(value, expected_type):
            raise ValidationError(
                f"{field_name} must be of type {expected_type.__name__}, got {type(value).__name__}"
            )

    @classmethod
    def validate_in_range(
        cls, value: Any, min_val: Any, max_val: Any, field_name: str
    ) -> None:
        """
        Utility method to validate value is in range.

        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If value is out of range
        """
        if value < min_val or value > max_val:
            raise ValidationError(
                f"{field_name} must be between {min_val} and {max_val}"
            )

    @classmethod
    def validate_length(cls, value: str, min_length: int, max_length: int, field_name: str) -> None:
        """
        Utility method to validate string length.

        Args:
            value: String value to validate
            min_length: Minimum allowed length
            max_length: Maximum allowed length
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If length is invalid
        """
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")

        length = len(value.strip())
        if length < min_length or length > max_length:
            raise ValidationError(
                f"{field_name} length must be between {min_length} and {max_length} characters"
            )

    @classmethod
    def validate_pattern(cls, value: str, pattern: str, field_name: str) -> None:
        """
        Utility method to validate string against regex pattern.

        Args:
            value: String value to validate
            pattern: Regex pattern to match
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If pattern doesn't match
        """
        import re
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")

        if not re.match(pattern, value):
            raise ValidationError(f"{field_name} does not match required pattern")

    @classmethod
    def validate_choices(cls, value: Any, choices: list[Any], field_name: str) -> None:
        """
        Utility method to validate value is in allowed choices.

        Args:
            value: Value to validate
            choices: List of allowed values
            field_name: Name of the field for error messages

        Raises:
            ValidationError: If value not in choices
        """
        if value not in choices:
            raise ValidationError(f"{field_name} must be one of: {', '.join(map(str, choices))}")


# =====================================================================================
# ENTITY BASE CLASS
# =====================================================================================


class Entity(ABC):
    """
    Base entity with identity and lifecycle management.

    Entities are mutable objects with a distinct identity that persists over time.
    They are defined by their identity (ID) rather than their attributes.

    Design Features:
    - Identity-based equality and hashing
    - Automatic timestamp management
    - Framework-agnostic event handling
    - Pure Python validation
    - Rich utility methods

    Usage Example:
        class User(Entity):
            def __init__(self, email: str, name: str, entity_id: UUID = None):
                super().__init__(entity_id)
                self.email = EmailAddress(email).value
                self.name = self._validate_name(name)

            def _validate_name(self, name: str) -> str:
                if not name or len(name) < 2:
                    raise ValidationError("Name must be at least 2 characters")
                return name.strip()
    """

    def __init__(self, entity_id: UUID | None = None):
        """
        Initialize entity with ID and timestamps.

        Args:
            entity_id: Optional UUID for the entity (auto-generated if not provided)
        """
        self.id = entity_id or uuid4()
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at

        # Validate the entity after initialization
        self._validate_entity()

    def _validate_entity(self) -> None:
        """
        Validate entity state. Override in subclasses for specific validation.

        Raises:
            ValidationError: If entity is in invalid state
        """
        if not isinstance(self.id, UUID):
            raise ValidationError("Entity ID must be a UUID")

        if not isinstance(self.created_at, datetime):
            raise ValidationError("Entity created_at must be a datetime")

    def mark_modified(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.utcnow()

    def __eq__(self, other: Any) -> bool:
        """
        Check equality based on entity ID.

        Args:
            other: Object to compare with

        Returns:
            bool: True if entities have same ID and type
        """
        if not isinstance(other, self.__class__):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """
        Return hash based on entity ID.

        Returns:
            int: Hash value for use in sets/dicts
        """
        return hash((self.__class__.__name__, self.id))

    def __repr__(self) -> str:
        """
        String representation for debugging.

        Returns:
            str: Detailed representation
        """
        return f"{self.__class__.__name__}(id={self.id}, created_at={self.created_at})"

    def __str__(self) -> str:
        """
        String representation for display.

        Returns:
            str: Human-readable representation
        """
        return f"{self.__class__.__name__}({self.id})"

    def to_dict(self) -> dict[str, Any]:
        """
        Convert entity to dictionary.

        Returns:
            dict[str, Any]: Dictionary representation
        """
        result = {}
        for key, value in self.__dict__.items():
            if hasattr(value, "to_dict"):
                result[key] = value.to_dict()
            elif isinstance(value, UUID):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

    @property
    def age_seconds(self) -> float:
        """Get age of entity in seconds."""
        return (datetime.utcnow() - self.created_at).total_seconds()

    @property
    def time_since_update_seconds(self) -> float:
        """Get time since last update in seconds."""
        return (datetime.utcnow() - self.updated_at).total_seconds()

    def is_older_than(self, seconds: float) -> bool:
        """Check if entity is older than specified seconds."""
        return self.age_seconds > seconds

    def was_updated_recently(self, seconds: float) -> bool:
        """Check if entity was updated within specified seconds."""
        return self.time_since_update_seconds <= seconds


# =====================================================================================
# AGGREGATE ROOT CLASS
# =====================================================================================


class AggregateRoot(Entity):
    """
    Aggregate root with domain event management.

    Aggregate roots are special entities that serve as the consistency boundary
    for a cluster of related objects. They manage domain events and enforce
    business invariants across the aggregate.

    Design Features:
    - Domain event collection and management
    - Version control for optimistic locking
    - Framework-agnostic event handling
    - Comprehensive state validation
    - Clean event lifecycle management

    Usage Example:
        class Order(AggregateRoot):
            def __init__(self, customer_id: UUID, items: list[OrderItem]):
                super().__init__()
                self.customer_id = customer_id
                self.items = items
                self.status = OrderStatus.PENDING
                self.add_event(OrderCreatedEvent(self.id, customer_id))

            def confirm(self) -> None:
                if self.status != OrderStatus.PENDING:
                    raise DomainError("Only pending orders can be confirmed")
                self.status = OrderStatus.CONFIRMED
                self.add_event(OrderConfirmedEvent(self.id))
    """

    def __init__(self, entity_id: UUID | None = None):
            """
            Initialize aggregate root.

            Args:
                entity_id: Optional UUID for the entity (auto-generated if not provided)
            """
            super().__init__(entity_id)
            self._events = []  # type: list['DomainEvent']
            self._version = 1

    def add_event(self, event: 'DomainEvent') -> None:
        """
        Add a domain event to the aggregate.

        Args:
            event: Domain event to add

        Raises:
            ValidationError: If event is invalid
        """
        from app.core.domain.domain_event import DomainEvent  # Import moved here to avoid circular imports
        if not isinstance(event, DomainEvent):
            raise ValidationError("Event must be a DomainEvent instance")

        self._events.append(event)
        self.mark_modified()

    def clear_events(self) -> list['DomainEvent']:
        """
        Clear and return all uncommitted events.

        Returns:
            list[DomainEvent]: List of events that were cleared
        """
        events = self._events.copy()
        self._events.clear()
        return events

    def get_events(self) -> list['DomainEvent']:
        """
        Get copy of uncommitted events without clearing them.

        Returns:
            list[DomainEvent]: Copy of current events
        """
        return self._events.copy()

    def has_events(self) -> bool:
        """
        Check if aggregate has uncommitted events.

        Returns:
            bool: True if there are uncommitted events
        """
        return len(self._events) > 0

    def event_count(self) -> int:
        """
        Get count of uncommitted events.

        Returns:
            int: Number of uncommitted events
        """
        return len(self._events)

    def increment_version(self) -> None:
        """Increment aggregate version for optimistic locking."""
        self._version += 1
        self.mark_modified()

    def check_version(self, expected_version: int) -> bool:
        """
        Check if aggregate version matches expected version.

        Args:
            expected_version: Expected version number

        Returns:
            bool: True if versions match
        """
        return self._version == expected_version

    def apply_event(self, event: 'DomainEvent') -> None:
        """
        Apply an event to update aggregate state.

        This method should be overridden by subclasses to handle specific events.

        Args:
            event: Domain event to apply
        """
        pass  # Default implementation - subclasses should override

    def replay_events(self, events: list['DomainEvent']) -> None:
        """
        Replay a list of events to rebuild aggregate state.

        Args:
            events: List of events to replay
        """
        for event in events:
            self.apply_event(event)
            self.increment_version()

    @property
    def version(self) -> int:
        """Get current aggregate version."""
        return self._version

    def _validate_entity(self) -> None:
        """Enhanced validation for aggregate roots."""
        super()._validate_entity()

        if not isinstance(self._version, int) or self._version < 1:
            raise ValidationError("Aggregate version must be a positive integer")

        if not isinstance(self._events, list):
            raise ValidationError("Events must be stored in a list")

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"id={self.id}, "
            f"version={self._version}, "
            f"events={len(self._events)}, "
            f"created_at={self.created_at})"
        )


# =====================================================================================
# DOMAIN SERVICE BASE CLASS
# =====================================================================================


class DomainService(ABC):
    """
    Base class for domain services.

    Domain services encapsulate domain logic that doesn't naturally fit within
    a single entity or value object. They are stateless and coordinate operations
    between multiple domain objects.

    Design Features:
    - Stateless design
    - Framework-agnostic implementation
    - Clear dependency injection points
    - Comprehensive error handling
    - Rich logging and monitoring support

    Usage Example:
        class OrderPricingService(DomainService):
            def __init__(self, tax_calculator: TaxCalculator):
                self.tax_calculator = tax_calculator

            def calculate_total_price(self, order: Order) -> Money:
                subtotal = sum(item.price for item in order.items)
                tax = self.tax_calculator.calculate_tax(subtotal, order.shipping_address)
                return subtotal + tax
    """

    def __init__(self):
        """Initialize domain service."""

    @abstractmethod
    def __str__(self) -> str:
        """String representation of the service."""


# =====================================================================================
# SPECIFICATION PATTERN INTEGRATION
# =====================================================================================


# Note: Specification classes are now in app.core.domain.specification module
# Import them from there to avoid duplication


# =====================================================================================
# DOMAIN EVENT BASE CLASS
# =====================================================================================

class DomainEvent(ABC):
    """
    Base domain event class.

    Domain events represent something that happened in the domain
    that domain experts care about.
    """

    def __init__(self):
        """Initialize domain event."""
        from datetime import UTC, datetime
        from uuid import uuid4

        self.event_id = uuid4()
        self.occurred_at = datetime.now(UTC)

    @abstractmethod
    def __str__(self) -> str:
        """String representation of the event."""


# =====================================================================================
# TYPE ALIASES AND EXPORTS
# =====================================================================================

# Type variables for generic specifications
T = TypeVar("T")
EntityT = TypeVar("EntityT", bound=Entity)
AggregateT = TypeVar("AggregateT", bound=AggregateRoot)
ValueObjectT = TypeVar("ValueObjectT", bound=ValueObject)

# Export all public classes
__all__ = [
    "AggregateRoot",
    "AggregateT",
    "DomainEvent",
    "DomainService",
    "Entity",
    "EntityT",
    "ValueObject",
    "ValueObjectT",
]
