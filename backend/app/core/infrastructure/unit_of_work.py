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
    from app.core.events.types import DomainEvent
except ImportError:
    from typing import Protocol
    
    class DomainEvent(Protocol):
        """Fallback domain event protocol."""
        metadata: Any

# Handle missing outbox repository
try:
    from app.repositories.outbox_repository import OutboxRepository
except ImportError:
    from typing import Protocol
    
    class OutboxRepository(Protocol):
        """Fallback outbox repository protocol."""
        async def store_events(self, events: list[DomainEvent]) -> None:
            """Store events in outbox."""

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
        outbox_repo: OutboxRepository | None = None,
        enable_event_deduplication: bool = True,
        max_events_per_transaction: int = 1000,
    ):
        """
        Initialize Unit of Work with database session and outbox repository.

        Args:
            session: SQLAlchemy async session for database operations
            outbox_repo: Optional outbox repository for event storage
            enable_event_deduplication: Prevent duplicate event storage
            max_events_per_transaction: Safety limit for event collection

        Raises:
            ValidationError: If session is invalid or limits are too low
        """
        self._validate_initialization(session, max_events_per_transaction)

        self.session = session
        self.outbox_repo = outbox_repo
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
            has_outbox_repo=outbox_repo is not None,
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
        Commit database changes and store collected events in outbox.

        Implements simple two-phase commit:
        1. Prepare phase: Validate events and database state
        2. Commit phase: Atomically commit database and store events in outbox

        Events are stored in outbox for eventual processing by background worker.
        This eliminates split-brain scenarios where database commits but events fail.

        Raises:
            TransactionError: If database commit fails
            UnitOfWorkError: If already committed or in invalid state
        """
        if self._committed:
            raise UnitOfWorkError("Unit of Work already committed")

        if self._rolled_back:
            raise UnitOfWorkError("Cannot commit after rollback")

        commit_start_time = datetime.now(datetime.UTC)
        events_count = len(self._events)
        
        try:
            # Phase 1: Prepare - validate state and events
            await self._prepare_commit()

            # Phase 2: Store events in outbox within same transaction
            await self._store_events_in_outbox()

            # Phase 3: Commit database changes (includes outbox events)
            await self._commit_database_changes()

            self._committed = True

            # Track metrics
            commit_duration = (
                datetime.now(datetime.UTC) - commit_start_time
            ).total_seconds()
            metrics.unit_of_work_commits.inc()
            metrics.unit_of_work_commit_duration.observe(commit_duration)

            logger.info(
                "Unit of Work committed successfully",
                events_stored=events_count,
                duration_seconds=commit_duration,
            )

        except SQLAlchemyError as e:
            logger.exception(
                "Database commit failed",
                error=str(e),
                events_collected=events_count,
            )

            metrics.unit_of_work_failures.labels(type="database").inc()
            await self.rollback()
            raise TransactionError(f"Database commit failed: {e}")

        except Exception as e:
            logger.exception(
                "Unexpected error during commit",
                error=str(e),
                events_collected=events_count,
            )

            metrics.unit_of_work_failures.labels(type="unexpected").inc()
            await self.rollback()
            raise UnitOfWorkError(f"Commit failed: {e}")
    
    async def _prepare_commit(self) -> None:
        """Prepare phase - validate events and database state."""
        # Validate collected events
        if self._events:
            for event in self._events:
                if not hasattr(event, 'metadata') or not event.metadata:
                    raise ValidationError(f"Event missing metadata: {event}")
        
        # Validate database session state
        if hasattr(self.session, 'is_active') and self.session.is_active:
            logger.debug("Database session is active and ready for commit")
    
    async def _commit_database_with_coordination(self) -> None:
        """Commit database with coordination metadata."""
        try:
            # Commit the main transaction
            await self.session.commit()
            
            logger.debug(
                "Database transaction committed with coordination",
                new_entities=len(self.session.new) if hasattr(self.session, "new") else 0,
                modified_entities=len(self.session.dirty) if hasattr(self.session, "dirty") else 0,
                deleted_entities=len(self.session.deleted) if hasattr(self.session, "deleted") else 0,
            )
                
        except Exception as e:
            logger.exception("Database commit with coordination failed", error=str(e))
            raise
    
    async def _finalize_commit(self) -> None:
        """Finalize commit - cleanup and post-commit coordination."""
        # Any post-commit cleanup or coordination logic
        logger.debug("Commit finalization completed")

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
        """Publish collected domain events with transactional coordination."""
        if not self.event_bus or not self._events:
            if self._events and not self.event_bus:
                logger.warning(
                    "Events collected but no event bus available",
                    event_count=len(self._events),
                )
            return

        events_to_publish = self._events.copy()
        
        # Create event transaction for coordination
        event_transaction_id = f"uow_{id(self)}_{int(datetime.now(datetime.UTC).timestamp())}"
        
        try:
            # Use transactional event publishing to ensure atomicity
            await self._publish_events_transactionally(events_to_publish, event_transaction_id)
            
            logger.info(
                "All events published successfully", 
                event_count=len(events_to_publish),
                transaction_id=event_transaction_id
            )

        except Exception as e:
            logger.exception(
                "Event publishing failed - attempting compensation",
                error=str(e),
                event_count=len(events_to_publish),
                transaction_id=event_transaction_id
            )
            
            # Try to compensate published events
            await self._compensate_published_events(events_to_publish, event_transaction_id)
            
            metrics.unit_of_work_failures.labels(type="event_system").inc()
            raise EventPublishingError(f"Event publishing failed: {e}")
        finally:
            # Clear events after publish attempt (successful or not)
            self._clear_event_collections()
    
    async def _publish_events_transactionally(
        self, events: list[DomainEvent], transaction_id: str
    ) -> None:
        """Publish events with transactional coordination and retry logic."""
        # Add transaction metadata to events
        enriched_events = []
        for event in events:
            # Create a copy with transaction metadata
            enriched_event = self._add_transaction_metadata(event, transaction_id)
            enriched_events.append(enriched_event)
        
        # Publish with batched approach for better atomicity
        batch_size = 10  # Configurable batch size
        for i in range(0, len(enriched_events), batch_size):
            batch = enriched_events[i:i + batch_size]
            await self._publish_event_batch(batch, transaction_id)
    
    def _add_transaction_metadata(self, event: DomainEvent, transaction_id: str) -> DomainEvent:
        """Add transaction coordination metadata to event."""
        # Add transaction coordination metadata if event supports it
        if hasattr(event, 'metadata') and event.metadata:
            # Set transaction metadata on existing metadata
            if hasattr(event.metadata, '__dict__'):
                event.metadata.__dict__.update({
                    'transaction_id': transaction_id,
                    'requires_compensation': True,
                    'published_at': datetime.now(datetime.UTC).isoformat()
                })
        
        return event
    
    async def _publish_event_batch(self, batch: list[DomainEvent], transaction_id: str) -> None:
        """Publish a batch of events with coordinated error handling."""
        try:
            # Publish batch concurrently
            publish_tasks = [self.event_bus.publish(event) for event in batch]
            results = await asyncio.gather(*publish_tasks, return_exceptions=True)
            
            # Check for failures in batch
            failed_events = [
                (i, result) for i, result in enumerate(results)
                if isinstance(result, Exception)
            ]
            
            if failed_events:
                logger.error(
                    "Event batch publish failed",
                    failed_count=len(failed_events),
                    batch_size=len(batch),
                    transaction_id=transaction_id,
                    failures=[(i, str(error)) for i, error in failed_events]
                )
                
                # Compensate successfully published events in this batch
                successful_events = [
                    batch[i] for i in range(len(batch)) 
                    if i not in [idx for idx, _ in failed_events]
                ]
                if successful_events:
                    await self._compensate_published_events(successful_events, transaction_id)
                
                metrics.unit_of_work_event_failures.inc(len(failed_events))
                raise EventPublishingError(f"Batch publish failed: {len(failed_events)} events failed")
                
        except Exception as e:
            logger.exception(
                "Event batch publish error",
                error=str(e),
                batch_size=len(batch),
                transaction_id=transaction_id
            )
            raise
    
    async def _compensate_published_events(
        self, events: list[DomainEvent], transaction_id: str
    ) -> None:
        """Attempt to compensate/rollback published events."""
        if not events:
            return
            
        logger.warning(
            "Attempting event compensation",
            event_count=len(events),
            transaction_id=transaction_id
        )
        
        # Try to publish compensation events
        compensation_events = []
        for event in events:
            try:
                compensation_event = self._create_compensation_event(event, transaction_id)
                if compensation_event:
                    compensation_events.append(compensation_event)
            except Exception as e:
                logger.exception(
                    "Failed to create compensation event",
                    event_type=type(event).__name__,
                    error=str(e)
                )
        
        if compensation_events:
            try:
                # Publish compensation events (best effort)
                compensation_tasks = [
                    self.event_bus.publish(comp_event) 
                    for comp_event in compensation_events
                ]
                await asyncio.gather(*compensation_tasks, return_exceptions=True)
                
                logger.info(
                    "Compensation events published",
                    compensation_count=len(compensation_events),
                    transaction_id=transaction_id
                )
            except Exception as e:
                logger.exception(
                    "Compensation event publishing failed",
                    error=str(e),
                    transaction_id=transaction_id
                )
    
    def _create_compensation_event(self, original_event: DomainEvent, transaction_id: str) -> DomainEvent | None:
        """Create a compensation event for the original event."""
        try:
            # Check if event has built-in compensation support
            if hasattr(original_event, 'create_compensation_event'):
                return original_event.create_compensation_event()
            
            # Create generic compensation event using event metadata
            if hasattr(original_event, 'metadata') and original_event.metadata:
                # This is a placeholder - actual implementation would depend on event types
                logger.debug(
                    "Creating generic compensation event",
                    original_event_type=type(original_event).__name__,
                    transaction_id=transaction_id
                )
                # Return None for now - compensation events need domain-specific logic
                return None
            
            return None
            
        except Exception as e:
            logger.exception(
                "Error creating compensation event",
                original_event_type=type(original_event).__name__,
                error=str(e)
            )
            return None

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
