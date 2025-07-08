"""
Type Protocols

Defines common protocols and interfaces used throughout the application
for better type safety and documentation.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Protocol, TypeVar, runtime_checkable
from uuid import UUID

T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


@runtime_checkable
class Identifiable(Protocol):
    """Protocol for objects that have an identifier."""

    @property
    def id(self) -> UUID:
        """Get the object's unique identifier."""
        ...


@runtime_checkable
class Timestamped(Protocol):
    """Protocol for objects that have timestamps."""

    @property
    def created_at(self) -> datetime:
        """Get creation timestamp."""
        ...

    @property
    def updated_at(self) -> datetime:
        """Get last update timestamp."""
        ...


@runtime_checkable
class Versioned(Protocol):
    """Protocol for objects that have version tracking."""

    @property
    def version(self) -> int:
        """Get object version."""
        ...

    def increment_version(self) -> None:
        """Increment the version number."""
        ...


@runtime_checkable
class Serializable(Protocol):
    """Protocol for objects that can be serialized."""

    def to_dict(self) -> dict[str, Any]:
        """Convert object to dictionary."""
        ...

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Serializable":
        """Create object from dictionary."""
        ...


@runtime_checkable
class Cacheable(Protocol):
    """Protocol for objects that can be cached."""

    def get_cache_key(self) -> str:
        """Get cache key for the object."""
        ...

    def get_cache_ttl(self) -> int | None:
        """Get cache TTL in seconds."""
        ...


@runtime_checkable
class Auditable(Protocol):
    """Protocol for objects that support audit logging."""

    def get_audit_data(self) -> dict[str, Any]:
        """Get data for audit logging."""
        ...

    def get_audit_type(self) -> str:
        """Get audit event type."""
        ...


@runtime_checkable
class Validatable(Protocol):
    """Protocol for objects that can be validated."""

    def validate(self) -> bool:
        """Validate the object."""
        ...

    def get_validation_errors(self) -> list[str]:
        """Get validation errors."""
        ...


@runtime_checkable
class Comparable(Protocol):
    """Protocol for objects that can be compared."""

    def __eq__(self, other: Any) -> bool:
        """Check equality."""
        ...

    def __lt__(self, other: Any) -> bool:
        """Check less than."""
        ...


@runtime_checkable
class Hashable(Protocol):
    """Protocol for objects that can be hashed."""

    def __hash__(self) -> int:
        """Get hash value."""
        ...


@runtime_checkable
class Copyable(Protocol):
    """Protocol for objects that can be copied."""

    def copy(self) -> "Copyable":
        """Create a shallow copy."""
        ...

    def deep_copy(self) -> "Copyable":
        """Create a deep copy."""
        ...


@runtime_checkable
class Repository(Protocol[T]):
    """Protocol for repository pattern implementation."""

    async def get_by_id(self, id: UUID) -> T | None:
        """Get entity by ID."""
        ...

    async def save(self, entity: T) -> T:
        """Save entity."""
        ...

    async def delete(self, entity: T) -> None:
        """Delete entity."""
        ...

    async def list(self, **filters: Any) -> list[T]:
        """List entities with filters."""
        ...


@runtime_checkable
class UnitOfWork(Protocol):
    """Protocol for Unit of Work pattern."""

    async def __aenter__(self) -> "UnitOfWork":
        """Enter async context."""
        ...

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context."""
        ...

    async def commit(self) -> None:
        """Commit transaction."""
        ...

    async def rollback(self) -> None:
        """Rollback transaction."""
        ...


@runtime_checkable
class EventBus(Protocol):
    """Protocol for event bus implementation."""

    async def publish(self, event: Any) -> None:
        """Publish an event."""
        ...

    def subscribe(self, event_type: type, handler: Any) -> None:
        """Subscribe to events of a type."""
        ...

    def unsubscribe(self, event_type: type, handler: Any) -> None:
        """Unsubscribe from events."""
        ...


@runtime_checkable
class Cache(Protocol[K, V]):
    """Protocol for cache implementation."""

    async def get(self, key: K) -> V | None:
        """Get value by key."""
        ...

    async def set(self, key: K, value: V, ttl: int | None = None) -> None:
        """Set key-value pair."""
        ...

    async def delete(self, key: K) -> bool:
        """Delete key."""
        ...

    async def clear(self) -> None:
        """Clear all keys."""
        ...


@runtime_checkable
class Logger(Protocol):
    """Protocol for logging interface."""

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        ...

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        ...


@runtime_checkable
class Specification(Protocol[T]):
    """Protocol for specification pattern."""

    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies specification."""
        ...

    def and_(self, other: "Specification[T]") -> "Specification[T]":
        """Combine with AND logic."""
        ...

    def or_(self, other: "Specification[T]") -> "Specification[T]":
        """Combine with OR logic."""
        ...

    def not_(self) -> "Specification[T]":
        """Negate specification."""
        ...


@runtime_checkable
class DomainEvent(Protocol):
    """Protocol for domain events."""

    @property
    def event_id(self) -> UUID:
        """Get event ID."""
        ...

    @property
    def event_type(self) -> str:
        """Get event type."""
        ...

    @property
    def occurred_at(self) -> datetime:
        """Get event timestamp."""
        ...

    @property
    def aggregate_id(self) -> UUID:
        """Get aggregate ID that produced the event."""
        ...


@runtime_checkable
class AggregateRoot(Protocol):
    """Protocol for aggregate roots in DDD."""

    @property
    def id(self) -> UUID:
        """Get aggregate ID."""
        ...

    @property
    def version(self) -> int:
        """Get aggregate version."""
        ...

    def get_uncommitted_events(self) -> list[DomainEvent]:
        """Get uncommitted domain events."""
        ...

    def mark_events_as_committed(self) -> None:
        """Mark events as committed."""
        ...


@runtime_checkable
class ValueObject(Protocol):
    """Protocol for value objects in DDD."""

    def __eq__(self, other: Any) -> bool:
        """Value objects are equal if all attributes are equal."""
        ...

    def __hash__(self) -> int:
        """Value objects should be hashable."""
        ...


@runtime_checkable
class Query(Protocol[T]):
    """Protocol for CQRS query interface."""


@runtime_checkable
class QueryHandler(Protocol[T, K]):
    """Protocol for CQRS query handlers."""

    async def handle(self, query: T) -> K:
        """Handle the query."""
        ...


@runtime_checkable
class Command(Protocol):
    """Protocol for CQRS command interface."""


@runtime_checkable
class CommandHandler(Protocol[T]):
    """Protocol for CQRS command handlers."""

    async def handle(self, command: T) -> None:
        """Handle the command."""
        ...


@runtime_checkable
class EventHandler(Protocol[T]):
    """Protocol for event handlers."""

    async def handle(self, event: T) -> None:
        """Handle the event."""
        ...


# Abstract base classes for common patterns
class AbstractEntity(ABC):
    """Abstract base class for entities."""

    def __init__(self, id: UUID) -> None:
        self._id = id

    @property
    def id(self) -> UUID:
        """Get entity ID."""
        return self._id

    def __eq__(self, other: Any) -> bool:
        """Entities are equal if they have the same ID and type."""
        if not isinstance(other, self.__class__):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)


class AbstractValueObject(ABC):
    """Abstract base class for value objects."""

    @abstractmethod
    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get values for equality comparison."""

    def __eq__(self, other: Any) -> bool:
        """Value objects are equal if all atomic values are equal."""
        if not isinstance(other, self.__class__):
            return False
        return self._get_atomic_values() == other._get_atomic_values()

    def __hash__(self) -> int:
        """Hash based on atomic values."""
        return hash(self._get_atomic_values())


class AbstractDomainService(ABC):
    """Abstract base class for domain services."""


class AbstractApplicationService(ABC):
    """Abstract base class for application services."""


class AbstractInfrastructureService(ABC):
    """Abstract base class for infrastructure services."""
