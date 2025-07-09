"""
Example Integration: Outbox Pattern + Unit of Work

This example shows how the outbox pattern integrates with the Unit of Work
to ensure atomic event-database operations, resolving the split-brain scenario.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.models.outbox_event import OutboxEvent
from app.repositories.outbox_repository import OutboxRepository


class DomainEvent:
    """Base class for domain events."""
    
    def __init__(self, event_type: str, aggregate_id: UUID, event_data: dict[str, Any]):
        self.event_type = event_type
        self.aggregate_id = aggregate_id
        self.event_data = event_data
        self.occurred_at = datetime.now(UTC)


class SimplifiedUnitOfWork:
    """
    Simplified Unit of Work showing outbox integration.
    
    This is an example of how Agent-1 would modify the Unit of Work
    to use the outbox pattern instead of direct event publishing.
    """
    
    def __init__(self, session, outbox_repo: OutboxRepository):
        """
        Initialize Unit of Work with outbox repository.
        
        Args:
            session: Database session
            outbox_repo: Repository for storing events in outbox
        """
        self._session = session
        self._outbox_repo = outbox_repo
        self._events: list[DomainEvent] = []
    
    def add_event(self, event: DomainEvent) -> None:
        """
        Add domain event to be stored in outbox.
        
        Args:
            event: Domain event to store
        """
        self._events.append(event)
    
    async def commit(self) -> None:
        """
        Commit changes and store events atomically.
        
        This is the key integration point - events are stored in the
        same transaction as domain data, ensuring atomicity.
        """
        try:
            # Convert domain events to outbox events
            outbox_events = []
            for event in self._events:
                outbox_event = OutboxEvent(
                    aggregate_id=event.aggregate_id,
                    event_type=event.event_type,
                    event_data=event.event_data
                )
                outbox_events.append(outbox_event)
            
            # Store events in outbox within the same transaction
            if outbox_events:
                await self._outbox_repo.store_events(
                    outbox_events, 
                    outbox_events[0].aggregate_id
                )
            
            # Commit the transaction (both domain data and events)
            await self._session.commit()
            
            # Clear events after successful commit
            self._events.clear()
            
        except Exception as e:
            # Rollback on failure
            await self._session.rollback()
            raise e
    
    async def rollback(self) -> None:
        """Rollback transaction and clear events."""
        await self._session.rollback()
        self._events.clear()


class UserService:
    """
    Example service showing how to use the integrated Unit of Work.
    
    This demonstrates the simplified pattern without complex compensation logic.
    """
    
    def __init__(self, user_repository, unit_of_work: SimplifiedUnitOfWork):
        self._user_repository = user_repository
        self._unit_of_work = unit_of_work
    
    async def create_user(self, user_data: dict[str, Any]) -> UUID:
        """
        Create user with atomic event storage.
        
        Args:
            user_data: User creation data
            
        Returns:
            UUID of created user
        """
        try:
            # Create user entity
            user = await self._user_repository.create(user_data)
            
            # Add domain event
            event = DomainEvent(
                event_type="UserCreated",
                aggregate_id=user.id,
                event_data={
                    "user_id": str(user.id),
                    "email": user.email,
                    "created_at": datetime.now(UTC).isoformat()
                }
            )
            self._unit_of_work.add_event(event)
            
            # Commit atomically (both user and event)
            await self._unit_of_work.commit()
            
            return user.id
            
        except Exception as e:
            # Rollback on any failure
            await self._unit_of_work.rollback()
            raise e


# Example usage demonstrating the integration
async def example_usage():
    """
    Example showing how the outbox pattern resolves split-brain scenarios.
    """
    
    # Setup (normally done by DI container)
    session = get_database_session()  # Mock
    outbox_repo = OutboxRepositoryAdapter(session)
    unit_of_work = SimplifiedUnitOfWork(session, outbox_repo)
    user_service = UserService(user_repository, unit_of_work)
    
    # Create user - this will store user and event atomically
    user_id = await user_service.create_user({
        "email": "user@example.com",
        "name": "John Doe"
    })
    
    # At this point:
    # 1. User is stored in database
    # 2. Event is stored in outbox table
    # 3. Both operations are atomic - either both succeed or both fail
    # 4. No split-brain scenario possible
    
    # Background processor will pick up the event and publish it
    # If publishing fails, the event remains in outbox for retry
    
    print(f"User created with ID: {user_id}")
    print("Event stored in outbox for reliable delivery")


def get_database_session():
    """Mock function to get database session."""


# Benefits of this approach:
# 1. **Atomic Operations**: Events are stored in the same transaction as domain data
# 2. **No Split-Brain**: If database commit fails, events are not stored
# 3. **Reliable Delivery**: Events are guaranteed to be published (with retries)
# 4. **Simplified UoW**: No complex compensation logic needed
# 5. **Eventual Consistency**: Events are published asynchronously but reliably

# What Agent-1 needs to do:
# 1. Remove complex compensation logic from existing Unit of Work
# 2. Replace direct event publishing with outbox event storage
# 3. Ensure events are stored in the same transaction as domain data
# 4. Remove circuit breaker patterns that cause race conditions
# 5. Simplify transaction coordination

# What the background processor handles:
# 1. Polling for unprocessed events
# 2. Publishing events to event bus
# 3. Retry logic with exponential backoff
# 4. Dead letter handling for failed events
# 5. Cleanup of processed events