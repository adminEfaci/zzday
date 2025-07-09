"""
Tests for OutboxEvent domain entity.
"""

import pytest
from datetime import datetime, UTC
from uuid import uuid4

from app.models.outbox_event import OutboxEvent


class TestOutboxEvent:
    """Test suite for OutboxEvent domain entity."""
    
    def test_outbox_event_creation(self):
        """Test creating an OutboxEvent."""
        aggregate_id = uuid4()
        event_data = {"user_id": "123", "action": "created"}
        
        event = OutboxEvent(
            aggregate_id=aggregate_id,
            event_type="UserCreated",
            event_data=event_data
        )
        
        assert event.id is not None
        assert event.aggregate_id == aggregate_id
        assert event.event_type == "UserCreated"
        assert event.event_data == event_data
        assert event.created_at is not None
        assert event.processed_at is None
        assert event.retry_count == 0
        assert event.max_retries == 3
        assert event.error_message is None
    
    def test_outbox_event_with_custom_values(self):
        """Test creating an OutboxEvent with custom values."""
        aggregate_id = uuid4()
        event_id = uuid4()
        created_at = datetime.now(UTC)
        
        event = OutboxEvent(
            id=event_id,
            aggregate_id=aggregate_id,
            event_type="UserUpdated",
            event_data={"name": "John"},
            created_at=created_at,
            max_retries=5
        )
        
        assert event.id == event_id
        assert event.aggregate_id == aggregate_id
        assert event.event_type == "UserUpdated"
        assert event.event_data == {"name": "John"}
        assert event.created_at == created_at
        assert event.max_retries == 5
    
    def test_is_processed_false_when_not_processed(self):
        """Test is_processed returns False when event is not processed."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={}
        )
        
        assert not event.is_processed()
    
    def test_is_processed_true_when_processed(self):
        """Test is_processed returns True when event is processed."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            processed_at=datetime.now(UTC)
        )
        
        assert event.is_processed()
    
    def test_can_retry_true_when_under_max_retries(self):
        """Test can_retry returns True when retry count is under max."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=2,
            max_retries=3
        )
        
        assert event.can_retry()
    
    def test_can_retry_false_when_at_max_retries(self):
        """Test can_retry returns False when retry count equals max."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=3,
            max_retries=3
        )
        
        assert not event.can_retry()
    
    def test_can_retry_false_when_processed(self):
        """Test can_retry returns False when event is processed."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            processed_at=datetime.now(UTC)
        )
        
        assert not event.can_retry()
    
    def test_should_retry_true_when_not_processed_and_can_retry(self):
        """Test should_retry returns True when not processed and can retry."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=1,
            max_retries=3
        )
        
        assert event.should_retry()
    
    def test_should_retry_false_when_processed(self):
        """Test should_retry returns False when processed."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            processed_at=datetime.now(UTC),
            retry_count=1,
            max_retries=3
        )
        
        assert not event.should_retry()
    
    def test_should_retry_false_when_exhausted_retries(self):
        """Test should_retry returns False when retries are exhausted."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=3,
            max_retries=3
        )
        
        assert not event.should_retry()
    
    def test_mark_processed_sets_processed_at(self):
        """Test mark_processed sets processed_at timestamp."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            error_message="Some error"
        )
        
        processed_event = event.mark_processed()
        
        assert processed_event.processed_at is not None
        assert processed_event.error_message is None
        assert processed_event.id == event.id
        assert processed_event.aggregate_id == event.aggregate_id
    
    def test_mark_processed_immutable(self):
        """Test mark_processed doesn't modify original event."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={}
        )
        
        processed_event = event.mark_processed()
        
        assert event.processed_at is None
        assert processed_event.processed_at is not None
        assert event is not processed_event
    
    def test_increment_retry_increments_count(self):
        """Test increment_retry increments retry count."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=1
        )
        
        retried_event = event.increment_retry("Connection failed")
        
        assert retried_event.retry_count == 2
        assert retried_event.error_message == "Connection failed"
        assert retried_event.id == event.id
    
    def test_increment_retry_immutable(self):
        """Test increment_retry doesn't modify original event."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=1
        )
        
        retried_event = event.increment_retry("Connection failed")
        
        assert event.retry_count == 1
        assert event.error_message is None
        assert retried_event.retry_count == 2
        assert retried_event.error_message == "Connection failed"
        assert event is not retried_event
    
    def test_to_domain_event_format(self):
        """Test to_domain_event converts to proper format."""
        event_id = uuid4()
        aggregate_id = uuid4()
        created_at = datetime.now(UTC)
        
        event = OutboxEvent(
            id=event_id,
            aggregate_id=aggregate_id,
            event_type="UserCreated",
            event_data={"user_id": "123", "name": "John"},
            created_at=created_at,
            retry_count=2
        )
        
        domain_event = event.to_domain_event()
        
        assert domain_event == {
            "id": str(event_id),
            "aggregate_id": str(aggregate_id),
            "event_type": "UserCreated",
            "event_data": {"user_id": "123", "name": "John"},
            "created_at": created_at.isoformat(),
            "retry_count": 2
        }
    
    def test_outbox_event_is_frozen(self):
        """Test OutboxEvent is immutable (frozen)."""
        event = OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={}
        )
        
        with pytest.raises(Exception):  # Should raise validation error
            event.retry_count = 5