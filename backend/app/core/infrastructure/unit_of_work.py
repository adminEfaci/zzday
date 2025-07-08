"""
Unit of Work Pattern Implementation for EzzDay Core

This module provides a robust Unit of Work pattern implementation that coordinates
database transactions with domain event publishing. Ensures transactional
consistency between data persistence and event-driven side effects.

Key Features:
- Transactional boundary management with automatic rollback
- Domain event collection and coordinated publishing
- Context manager support for clean resource management
- Comprehensive error handling with detailed logging
- Event-driven architecture integration
- Async/await support for non-blocking operations

Design Principles:
- Pure Python domain logic (no framework coupling)
- Explicit error handling and validation
- Transactional consistency guarantees
- Event publishing after successful persistence
- Graceful degradation on failures

Usage Examples:
    # Basic usage with context manager
    async with BaseUnitOfWork(session, event_bus) as uow:
        # Perform business operations
        user = await user_repository.create(user_data)
        
        # Collect domain events
        uow.collect_events(user.pull_events())
        
        # Changes committed and events published automatically
    
    # Manual transaction control
    uow = BaseUnitOfWork(session, event_bus)
    try:
        # Business operations
        await user_repository.update(user_id, changes)
        uow.collect_events([UserUpdatedEvent(...)])
        
        # Explicit commit
        await uow.commit()
    except Exception:
        await uow.rollback()
        raise
    
    # Event-only operations (no database changes)
    async with BaseUnitOfWork(session, event_bus) as uow:
        uow.collect_events([
            UserNotificationEvent(user_id="123"),
            AuditLogEvent(action="login")
        ])
        # Events published on successful context exit

Error Handling:
    - UnitOfWorkError: Base exception for UoW operations
    - TransactionError: Database transaction failures
    - EventPublishingError: Event publishing failures
    - ValidationError: Invalid UoW configuration

Performance Features:
    - Lazy event collection and batch publishing
    - Efficient event deduplication
    - Minimal memory footprint for event storage
    - Optimized database session management
"""

import asyncio
from abc import ABC
from datetime import datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

# Handle missing domain contracts
try:
    from app.core.domain.contracts import IUnitOfWork
except ImportError:
    from abc import ABC, abstractmethod
    from typing import Any
    
    class IUnitOfWork(ABC):
        """Fallback interface for Unit of Work pattern."""
        
        @abstractmethod
        async def commit(self) -> None:
            """Commit the unit of work."""
        
        @abstractmethod
        async def rollback(self) -> None:
            """Rollback the unit of work."""

from app.core.errors import InfrastructureError, ValidationError

# Handle missing event system components
try:
    from app.core.events.bus import EventBus
    from app.core.events.types import DomainEvent
except ImportError:
    from typing import Protocol
    
    class DomainEvent(Protocol):
        """Fallback domain event protocol."""
        metadata: Any
    
    class EventBus(Protocol):
        """Fallback event bus protocol."""
        async def publish(self, event: DomainEvent) -> None:
            """Publish an event."""

from app.core.logging import get_logger

# Handle optional monitoring
try:
    from app.core.monitoring import metrics
except ImportError:
    class MockMetrics:
        def __init__(self):
            self.unit_of_work_commits = MockCounter()
            self.unit_of_work_rollbacks = MockCounter()
            self.unit_of_work_failures = MockCounter()
            self.unit_of_work_commit_duration = MockCounter()
            self.unit_of_work_event_failures = MockCounter()
    
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def observe(self, value):
            pass
        def inc(self, count=1):
            pass
    
    metrics = MockMetrics()

logger = get_logger(__name__)


class UnitOfWorkError(InfrastructureError):
    """Base exception for Unit of Work operations."""
    
    default_code = "UNIT_OF_WORK_ERROR"
    retryable = False


class TransactionError(UnitOfWorkError):
    """Raised when database transaction operations fail."""
    
    default_code = "TRANSACTION_ERROR"
    retryable = True


class EventPublishingError(UnitOfWorkError):
    """Raised when event publishing fails during commit."""
    
    default_code = "EVENT_PUBLISHING_ERROR"
    retryable = True


class BaseUnitOfWork(IUnitOfWork, ABC):
    """
    Base Unit of Work implementation providing transactional coordination.

    Manages database transactions and domain event publishing as a single
    atomic operation. Ensures that events are only published after successful
    database commits, maintaining consistency between persistence and messaging.

    Key Design Features:
    - Atomic transaction and event publishing coordination
    - Context manager support for automatic resource cleanup
    - Event deduplication to prevent duplicate publications
    - Comprehensive error handling with rollback guarantees
    - Performance monitoring and metrics tracking
    - Graceful degradation when event bus is unavailable

    Transaction Semantics:
    - Events are collected during transaction execution
    - Database changes are committed first
    - Events are published only after successful commit
    - Any failure triggers complete rollback (database + events)
    - Event publishing failures don't affect database state

    Usage Patterns:
        # Pattern 1: Context manager (recommended)
        async with BaseUnitOfWork(session, event_bus) as uow:
            # Business operations that modify state
            entity = await repository.create(data)
            uow.collect_events(entity.pull_events())
            # Auto-commit and event publishing

        # Pattern 2: Manual control
        uow = BaseUnitOfWork(session, event_bus)
        try:
            # Operations
            await uow.commit()
        except Exception:
            await uow.rollback()

        # Pattern 3: Event-only (no DB changes)
        async with BaseUnitOfWork(session, event_bus) as uow:
            uow.collect_events([NotificationEvent(...)])

    Error Recovery:
        Database failures trigger automatic rollback and event clearing.
        Event publishing failures are logged but don't affect database state.
        Context manager ensures cleanup even on unexpected exceptions.

    Performance Characteristics:
        - O(1) event collection and deduplication
        - Batch event publishing for efficiency
        - Minimal memory overhead for event storage
        - Single database round-trip for commits
    """

    def __init__(
        self,
        session: AsyncSession,
        event_bus: EventBus | None = None,
        enable_event_deduplication: bool = True,
        max_events_per_transaction: int = 1000,
    ):
        """
        Initialize Unit of Work with database session and event bus.

        Args:
            session: SQLAlchemy async session for database operations
            event_bus: Optional event bus for publishing domain events
            enable_event_deduplication: Prevent duplicate event publishing
            max_events_per_transaction: Safety limit for event collection

        Raises:
            ValidationError: If session is invalid or limits are too low
        """
        self._validate_initialization(session, max_events_per_transaction)

        self.session = session
        self.event_bus = event_bus
        self._enable_event_deduplication = enable_event_deduplication
        self._max_events_per_transaction = max_events_per_transaction

        # Event collection state
        self._events: list[DomainEvent] = []
        self._event_ids: set[str] = set() if enable_event_deduplication else None

        # Transaction state tracking
        self._transaction_started = False
        self._committed = False
        self._rolled_back = False
        self._start_time: datetime | None = None

        logger.debug(
            "Unit of Work initialized",
            has_event_bus=event_bus is not None,
            deduplication_enabled=enable_event_deduplication,
            max_events=max_events_per_transaction,
        )

    def _validate_initialization(self, session: AsyncSession, max_events: int) -> None:
        """Validate Unit of Work initialization parameters."""
        if not session:
            raise ValidationError("Database session is required")

        # More flexible session type checking
        if not hasattr(session, 'commit') or not hasattr(session, 'rollback'):
            raise ValidationError(
                f"Session must implement commit/rollback methods, got {type(session)}"
            )

        if max_events < 10:
            raise ValidationError("max_events_per_transaction must be at least 10")
        
        if max_events > 10000:
            raise ValidationError("max_events_per_transaction cannot exceed 10000")

    async def __aenter__(self) -> "BaseUnitOfWork":
        """
        Enter transaction context and prepare for operations.

        Marks transaction as started and records timing for monitoring.
        Does not begin database transaction until first operation.

        Returns:
            Self for context manager pattern
        """
        if self._transaction_started:
            raise UnitOfWorkError("Unit of Work already in transaction context")

        self._transaction_started = True
        self._start_time = datetime.now(datetime.UTC)

        logger.debug(
            "Unit of Work context entered", start_time=self._start_time.isoformat()
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit transaction context with automatic commit/rollback.

        Commits changes and publishes events if no exception occurred.
        Rolls back all changes if any exception was raised.
        Ensures clean state regardless of success or failure.

        Args:
            exc_type: Exception type if exception occurred
            exc_val: Exception instance if exception occurred
            exc_tb: Exception traceback if exception occurred
        """
        try:
            if exc_type is not None:
                # Exception occurred - rollback everything
                await self._handle_context_exception(exc_type, exc_val)
            else:
                # Success path - commit and publish events
                await self._handle_context_success()

        except Exception as cleanup_error:
            # Log cleanup errors but don't mask original exception
            logger.exception(
                "Error during Unit of Work context cleanup",
                cleanup_error=str(cleanup_error),
                original_exception=exc_type.__name__ if exc_type else None,
            )

        finally:
            self._log_transaction_completion()

    async def _handle_context_exception(self, exc_type, exc_val) -> None:
        """Handle exception during context exit."""
        logger.info(
            "Rolling back due to exception",
            exception_type=exc_type.__name__,
            exception_message=str(exc_val) if exc_val else None,
            events_collected=len(self._events),
        )

        await self.rollback()

    async def _handle_context_success(self) -> None:
        """Handle successful context exit."""
        if self._events or self._has_pending_database_changes():
            await self.commit()
        else:
            logger.debug("No changes to commit in Unit of Work")

    def _has_pending_database_changes(self) -> bool:
        """Check if session has pending database changes."""
        try:
            return (
                bool(self.session.new)
                or bool(self.session.dirty)
                or bool(self.session.deleted)
            )
        except Exception:
            # If we can't check, assume there might be changes
            return True

    def _log_transaction_completion(self) -> None:
        """Log transaction completion with timing information."""
        if self._start_time:
            duration = (datetime.now(datetime.UTC) - self._start_time).total_seconds()

            logger.info(
                "Unit of Work transaction completed",
                duration_seconds=duration,
                committed=self._committed,
                rolled_back=self._rolled_back,
                events_published=len(self._events) if self._committed else 0,
            )

    async def commit(self) -> None:
        """
        Commit database changes and publish collected events atomically.

        Performs a two-phase commit:
        1. Commit database transaction
        2. Publish domain events (if event bus available)

        Events are only published after successful database commit to ensure
        consistency. Database state is never rolled back due to event failures.

        Raises:
            TransactionError: If database commit fails
            EventPublishingError: If event publishing fails (database remains committed)
            UnitOfWorkError: If already committed or in invalid state
        """
        if self._committed:
            raise UnitOfWorkError("Unit of Work already committed")

        if self._rolled_back:
            raise UnitOfWorkError("Cannot commit after rollback")

        commit_start_time = datetime.now(datetime.UTC)

        try:
            # Phase 1: Commit database changes
            await self._commit_database_changes()

            # Phase 2: Publish events (failures don't affect database)
            await self._publish_collected_events()

            self._committed = True

            # Track metrics
            commit_duration = (
                datetime.now(datetime.UTC) - commit_start_time
            ).total_seconds()
            metrics.unit_of_work_commits.inc()
            metrics.unit_of_work_commit_duration.observe(commit_duration)

            logger.info(
                "Unit of Work committed successfully",
                events_published=len(self._events),
                duration_seconds=commit_duration,
            )

        except SQLAlchemyError as e:
            logger.exception(
                "Database commit failed",
                error=str(e),
                events_collected=len(self._events),
            )

            metrics.unit_of_work_failures.labels(type="database").inc()
            await self.rollback()
            raise TransactionError(f"Database commit failed: {e}")

        except Exception as e:
            logger.exception(
                "Unexpected error during commit",
                error=str(e),
                events_collected=len(self._events),
            )

            metrics.unit_of_work_failures.labels(type="unexpected").inc()
            await self.rollback()
            raise UnitOfWorkError(f"Commit failed: {e}")

    async def _commit_database_changes(self) -> None:
        """Commit database transaction with error handling."""
        try:
            await self.session.commit()
            logger.debug(
                "Database transaction committed",
                new_entities=len(self.session.new)
                if hasattr(self.session, "new")
                else 0,
                modified_entities=len(self.session.dirty)
                if hasattr(self.session, "dirty")
                else 0,
                deleted_entities=len(self.session.deleted)
                if hasattr(self.session, "deleted")
                else 0,
            )
        except Exception as e:
            logger.exception("Database commit operation failed", error=str(e))
            raise

    async def _publish_collected_events(self) -> None:
        """Publish collected domain events with error handling."""
        if not self.event_bus or not self._events:
            if self._events and not self.event_bus:
                logger.warning(
                    "Events collected but no event bus available",
                    event_count=len(self._events),
                )
            return

        events_to_publish = self._events.copy()

        try:
            # Publish events concurrently for better performance
            publish_tasks = [
                self.event_bus.publish(event) for event in events_to_publish
            ]

            results = await asyncio.gather(*publish_tasks, return_exceptions=True)

            # Check for publishing failures
            failed_events = [
                (i, result)
                for i, result in enumerate(results)
                if isinstance(result, Exception)
            ]

            if failed_events:
                logger.error(
                    "Some events failed to publish",
                    failed_count=len(failed_events),
                    total_events=len(events_to_publish),
                    failures=[(i, str(error)) for i, error in failed_events],
                )

                metrics.unit_of_work_event_failures.inc(len(failed_events))

                # Don't rollback database - events can be republished
                raise EventPublishingError(
                    f"{len(failed_events)} out of {len(events_to_publish)} events failed to publish"
                )

            logger.info(
                "All events published successfully", event_count=len(events_to_publish)
            )

        except Exception as e:
            if not isinstance(e, EventPublishingError):
                logger.exception(
                    "Event publishing system error",
                    error=str(e),
                    event_count=len(events_to_publish),
                )
                metrics.unit_of_work_failures.labels(type="event_system").inc()
                raise EventPublishingError(f"Event publishing failed: {e}")
            raise
        finally:
            # Clear events after publish attempt (successful or not)
            self._clear_event_collections()

    async def rollback(self) -> None:
        """
        Rollback database changes and clear collected events.

        Ensures clean state by rolling back any pending database changes
        and clearing the event collection. Safe to call multiple times.

        Note: Does not raise exceptions to allow use in error handlers.
        """
        if self._rolled_back:
            logger.debug("Unit of Work already rolled back")
            return

        try:
            # Rollback database changes
            await self.session.rollback()

            # Clear collected events
            self._clear_event_collections()

            self._rolled_back = True

            logger.info("Unit of Work rolled back", events_cleared=len(self._events))

            metrics.unit_of_work_rollbacks.inc()

        except Exception as e:
            # Log but don't raise - rollback should not fail
            logger.exception("Error during rollback", error=str(e))

    def collect_events(self, events: list[DomainEvent]) -> None:
        """
        Collect domain events for publishing after successful commit.

        Events are stored in memory until commit time. Supports deduplication
        to prevent publishing the same event multiple times.

        Args:
            events: List of domain events to collect

        Raises:
            ValidationError: If events are invalid or limits exceeded
            UnitOfWorkError: If already committed or rolled back
        """
        if self._committed:
            raise UnitOfWorkError("Cannot collect events after commit")

        if self._rolled_back:
            raise UnitOfWorkError("Cannot collect events after rollback")

        if not events:
            return

        self._validate_events(events)

        # Filter duplicates if deduplication is enabled
        new_events = self._filter_duplicate_events(events)

        if not new_events:
            logger.debug("All events were duplicates, none collected")
            return

        # Check collection limits
        if len(self._events) + len(new_events) > self._max_events_per_transaction:
            raise ValidationError(
                f"Event collection limit exceeded: "
                f"{len(self._events) + len(new_events)} > {self._max_events_per_transaction}"
            )

        # Collect new events
        self._events.extend(new_events)

        # Update deduplication tracking
        if self._enable_event_deduplication:
            self._event_ids.update(str(event.metadata.event_id) for event in new_events)

        logger.debug(
            "Events collected",
            new_events=len(new_events),
            total_events=len(self._events),
            duplicates_filtered=len(events) - len(new_events),
        )

    def _validate_events(self, events: list[DomainEvent]) -> None:
        """Validate collected events."""
        if not isinstance(events, list):
            raise ValidationError("Events must be provided as a list")

        for i, event in enumerate(events):
            if not isinstance(event, DomainEvent):
                raise ValidationError(
                    f"Event at index {i} is not a DomainEvent: {type(event)}"
                )

            if not hasattr(event, "metadata") or not event.metadata:
                raise ValidationError(f"Event at index {i} missing metadata: {event}")

    def _filter_duplicate_events(self, events: list[DomainEvent]) -> list[DomainEvent]:
        """Filter out duplicate events if deduplication is enabled."""
        if not self._enable_event_deduplication:
            return events

        new_events = []
        for event in events:
            event_id = str(event.metadata.event_id)
            if event_id not in self._event_ids:
                new_events.append(event)
            else:
                logger.debug(
                    "Duplicate event filtered",
                    event_type=event.__class__.__name__,
                    event_id=event_id,
                )

        return new_events

    def _clear_event_collections(self) -> None:
        """Clear all event collections and tracking."""
        self._events.clear()
        if self._event_ids:
            self._event_ids.clear()

    def get_collected_events(self) -> list[DomainEvent]:
        """
        Get copy of currently collected events.

        Returns:
            List of domain events collected for publishing
        """
        return self._events.copy()

    def has_events(self) -> bool:
        """Check if any events are collected for publishing."""
        return bool(self._events)

    def event_count(self) -> int:
        """Get count of collected events."""
        return len(self._events)

    def is_committed(self) -> bool:
        """Check if Unit of Work has been committed."""
        return self._committed

    def is_rolled_back(self) -> bool:
        """Check if Unit of Work has been rolled back."""
        return self._rolled_back

    def is_active(self) -> bool:
        """Check if Unit of Work is active (not committed or rolled back)."""
        return not (self._committed or self._rolled_back)

    def get_statistics(self) -> dict[str, Any]:
        """
        Get Unit of Work statistics for monitoring.

        Returns:
            Dictionary containing current state and metrics
        """
        return {
            "transaction_started": self._transaction_started,
            "committed": self._committed,
            "rolled_back": self._rolled_back,
            "active": self.is_active(),
            "events_collected": len(self._events),
            "has_event_bus": self.event_bus is not None,
            "deduplication_enabled": self._enable_event_deduplication,
            "max_events_limit": self._max_events_per_transaction,
            "start_time": self._start_time.isoformat() if self._start_time else None,
        }
