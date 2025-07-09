# Outbox Pattern Implementation

This directory contains the implementation of the outbox pattern for reliable event delivery in a distributed system. The outbox pattern ensures atomic event-database operations, resolving split-brain scenarios where database commits succeed but event publishing fails.

## 🎯 Problem Solved

**Split-Brain Scenario**: Database commits succeed but event publishing fails, causing data inconsistency.

**Before**: Complex Unit of Work with compensation logic, race conditions, and unreliable event delivery.

**After**: Simple atomic operations with guaranteed event delivery through the outbox pattern.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Domain Layer  │    │ Application     │    │ Infrastructure  │
│                 │    │   Layer         │    │    Layer        │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ OutboxEvent     │◄───┤ OutboxProcessor │◄───┤ OutboxRepository│
│ (Domain Entity) │    │ (Service)       │    │ (Adapter)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                ▲
                                │
                       ┌─────────────────┐
                       │   Event Bus     │
                       │  (Interface)    │
                       └─────────────────┘
```

## 📁 Component Overview

### Core Components

1. **OutboxEvent** (`app/models/outbox_event.py`)
   - Domain entity representing an event to be published
   - Immutable with built-in retry logic
   - Tracks processing state and error messages

2. **OutboxRepository** (`app/repositories/outbox_repository.py`)
   - Interface for outbox event persistence
   - Defines contract for atomic event storage
   - Supports querying and cleanup operations

3. **OutboxRepositoryAdapter** (`app/infrastructure/database/adapters/outbox_repository_adapter.py`)
   - SQLAlchemy implementation of OutboxRepository
   - Handles database operations with proper error handling
   - Supports batch operations and cleanup

4. **OutboxProcessor** (`app/services/outbox_processor.py`)
   - Background service for processing outbox events
   - Implements retry logic with exponential backoff
   - Supports concurrent processing with rate limiting

### Database Schema

```sql
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    error_message TEXT
);
```

## 🚀 Usage

### 1. Store Events in Unit of Work

```python
from app.models.outbox_event import OutboxEvent
from app.repositories.outbox_repository import OutboxRepository

# In your Unit of Work implementation
class SimplifiedUnitOfWork:
    def __init__(self, session, outbox_repo: OutboxRepository):
        self._session = session
        self._outbox_repo = outbox_repo
        self._events = []
    
    def add_event(self, event_type: str, aggregate_id: UUID, event_data: dict):
        event = OutboxEvent(
            aggregate_id=aggregate_id,
            event_type=event_type,
            event_data=event_data
        )
        self._events.append(event)
    
    async def commit(self):
        # Store events in same transaction as domain data
        if self._events:
            await self._outbox_repo.store_events(self._events, self._events[0].aggregate_id)
        
        # Commit transaction (both domain data and events)
        await self._session.commit()
        self._events.clear()
```

### 2. Process Events with Background Service

```python
from app.services.outbox_processor import OutboxProcessor, EventBus
from app.infrastructure.database.adapters.outbox_repository_adapter import OutboxRepositoryAdapter

# Setup
outbox_repo = OutboxRepositoryAdapter(session)
event_bus = YourEventBusImplementation()
processor = OutboxProcessor(outbox_repo, event_bus)

# Start background processing
await processor.start()

# Or process once
await processor.process_events()
```

### 3. Implement Event Bus

```python
from app.services.outbox_processor import EventBus

class YourEventBus(EventBus):
    async def publish(self, event: dict) -> None:
        # Publish to your message broker (RabbitMQ, Redis, etc.)
        await self.message_broker.publish(event)
```

## 🔧 Configuration

### Database Migration

Run the migration to create the outbox_events table:

```bash
alembic upgrade head
```

### Background Processor Settings

```python
processor = OutboxProcessor(
    outbox_repo=outbox_repo,
    event_bus=event_bus,
    batch_size=100,              # Events per batch
    poll_interval=5.0,           # Polling interval in seconds
    max_concurrent_events=10     # Max concurrent processing
)
```

### Retry Policy

```python
from app.services.outbox_processor import RetryPolicy

retry_policy = RetryPolicy(
    base_delay=1.0,              # Base delay in seconds
    max_delay=60.0,              # Maximum delay in seconds
    backoff_multiplier=2.0,      # Exponential backoff multiplier
    jitter=True                  # Add jitter to prevent thundering herd
)
```

## 📊 Benefits

### 1. **Atomic Operations**
- Events stored in same database transaction as domain data
- Either both succeed or both fail - no split-brain scenarios

### 2. **Reliable Delivery**
- Events guaranteed to be published (with retries)
- Failed events remain in outbox for retry
- Dead letter handling for permanently failed events

### 3. **Simplified Architecture**
- No complex compensation logic in Unit of Work
- No circuit breaker patterns causing race conditions
- Clear separation of concerns

### 4. **Operational Benefits**
- Monitoring and metrics for event processing
- Configurable retry policies
- Automatic cleanup of processed events

## 🧪 Testing

### Unit Tests
```bash
# Test domain entity
pytest tests/test_outbox_event.py

# Test repository adapter  
pytest tests/test_outbox_repository_adapter.py

# Test processor service
pytest tests/test_outbox_processor.py
```

### Integration Tests
```bash
# Test full outbox flow
pytest tests/integration/test_outbox_integration.py
```

## 🔍 Monitoring

### Key Metrics
- **Unprocessed Events**: Number of events waiting to be processed
- **Processing Rate**: Events processed per second
- **Retry Rate**: Percentage of events requiring retries
- **Failed Events**: Events that exhausted all retries

### Health Checks
```python
# Check for failed events
failed_events = await processor.get_failed_events()

# Check processing status
is_running = processor.is_running

# Cleanup old events
deleted_count = await processor.cleanup_processed_events(older_than_days=30)
```

## 🔄 Migration from Existing System

### What Agent-1 Needs to Change in Unit of Work

1. **Remove Complex Compensation Logic**
   - Delete `_compensate_published_events` method
   - Remove transaction coordination metadata
   - Simplify event batch processing

2. **Replace Direct Event Publishing**
   - Replace `event_bus.publish()` with `outbox_repo.store_events()`
   - Store events in same transaction as domain data

3. **Simplify Transaction Management**
   - Remove circuit breaker patterns
   - Remove complex retry mechanisms
   - Keep simple commit/rollback logic

### Example Migration

**Before (Complex)**:
```python
async def commit(self):
    try:
        # Complex compensation logic
        await self._compensate_published_events()
        await self._publish_event_batch()
        await self._session.commit()
    except Exception:
        await self._complex_rollback_with_compensation()
```

**After (Simple)**:
```python
async def commit(self):
    try:
        # Store events in outbox
        await self._outbox_repo.store_events(self._events, self._aggregate_id)
        # Commit transaction
        await self._session.commit()
    except Exception:
        await self._session.rollback()
        raise
```

## 📚 Additional Resources

- [Outbox Pattern Documentation](https://microservices.io/patterns/data/transactional-outbox.html)
- [Event-Driven Architecture Best Practices](https://martinfowler.com/articles/201701-event-driven.html)
- [Saga Pattern vs Outbox Pattern](https://blog.bernd-ruecker.com/saga-vs-outbox-pattern-9b8c7d4b3ecc)

## 🤝 Agent Coordination

This implementation is designed to work with Agent-1's Unit of Work modifications:

1. **Agent-1 Responsibility**: Modify Unit of Work to use outbox storage
2. **Agent-2 Responsibility**: Provide outbox infrastructure and processing
3. **Integration Point**: `OutboxRepository.store_events()` method

The outbox pattern provides the foundation for reliable event delivery while Agent-1 focuses on simplifying the Unit of Work implementation.