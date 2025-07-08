"""Core domain contracts."""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.domain.specification import Specification

try:
    from app.core.events.types import DomainEvent
except ImportError:
    # Fallback for when events module is not available
    from typing import Any
    DomainEvent = Any

T = TypeVar("T", bound=AggregateRoot)


class IRepository(ABC, Generic[T]):
    """Repository interface with comprehensive CRUD and batch operations."""

    @abstractmethod
    async def get_by_id(self, id: UUID) -> T | None:
        """Get entity by ID."""

    @abstractmethod
    async def get_by_ids(self, ids: list[UUID]) -> list[T]:
        """Get multiple entities by IDs."""

    @abstractmethod
    async def save(self, entity: T) -> None:
        """Save entity."""

    @abstractmethod
    async def save_batch(self, entities: list[T]) -> None:
        """Save multiple entities in a batch."""

    @abstractmethod
    async def delete(self, id: UUID) -> None:
        """Delete entity."""

    @abstractmethod
    async def delete_batch(self, ids: list[UUID]) -> None:
        """Delete multiple entities in a batch."""

    @abstractmethod
    async def exists(self, id: UUID) -> bool:
        """Check if entity exists."""

    @abstractmethod
    async def count(self, specification: Specification[T] | None = None) -> int:
        """Count entities matching specification."""

    @abstractmethod
    async def find_by_specification(
        self,
        specification: Specification[T],
        limit: int | None = None,
        offset: int | None = None,
        order_by: str | None = None,
        ascending: bool = True,
    ) -> list[T]:
        """Find entities matching specification with ordering."""

    @abstractmethod
    async def find_one_by_specification(
        self, specification: Specification[T]
    ) -> T | None:
        """Find single entity matching specification."""


class IUnitOfWork(ABC):
    """Unit of Work interface with event publishing support."""

    @abstractmethod
    async def __aenter__(self) -> "IUnitOfWork":
        """Enter context."""

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context."""

    @abstractmethod
    async def commit(self) -> None:
        """Commit changes and publish events."""

    @abstractmethod
    async def rollback(self) -> None:
        """Rollback changes."""

    @abstractmethod
    def register_new(self, entity: AggregateRoot) -> None:
        """Register new entity for tracking."""

    @abstractmethod
    def register_dirty(self, entity: AggregateRoot) -> None:
        """Register modified entity for tracking."""

    @abstractmethod
    def register_removed(self, entity: AggregateRoot) -> None:
        """Register removed entity for tracking."""

    @abstractmethod
    def collect_events(self) -> list[DomainEvent]:
        """Collect all domain events from tracked aggregates."""


class IEventPublisher(ABC):
    """Event publisher interface with comprehensive publishing capabilities."""

    @abstractmethod
    async def publish(self, events: list[DomainEvent]) -> None:
        """Publish domain events."""

    @abstractmethod
    async def publish_single(self, event: DomainEvent) -> None:
        """Publish single domain event."""

    @abstractmethod
    async def publish_batch(self, event_batches: list[list[DomainEvent]]) -> None:
        """Publish multiple batches of events."""

    @abstractmethod
    async def schedule_publish(
        self, events: list[DomainEvent], delay_seconds: float
    ) -> None:
        """Schedule events for delayed publishing."""

    @abstractmethod
    def can_publish(self, event: DomainEvent) -> bool:
        """Check if event can be published."""


class IRepositoryFactory(ABC):
    """Factory interface for creating repositories."""

    @abstractmethod
    def create_repository(self, entity_type: type[T]) -> IRepository[T]:
        """Create repository for specific entity type."""

    @abstractmethod
    def get_repository(self, entity_type: type[T]) -> IRepository[T]:
        """Get existing repository for entity type."""

    @abstractmethod
    def register_repository(
        self, entity_type: type[T], repository: IRepository[T]
    ) -> None:
        """Register repository for entity type."""
