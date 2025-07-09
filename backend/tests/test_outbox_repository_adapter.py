"""
Tests for OutboxRepositoryAdapter.
"""

from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.core.errors import InfrastructureError
from app.infrastructure.database.adapters.outbox_repository_adapter import (
    OutboxRepositoryAdapter,
)
from app.infrastructure.database.models.outbox_event_model import OutboxEventModel
from app.models.outbox_event import OutboxEvent


@pytest.fixture
def mock_session():
    """Mock SQLAlchemy session."""
    session = Mock()
    session.add = Mock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.exec = AsyncMock()
    session.get = AsyncMock()
    session.delete = AsyncMock()
    return session


@pytest.fixture
def repository(mock_session):
    """OutboxRepositoryAdapter instance with mocked session."""
    return OutboxRepositoryAdapter(mock_session)


@pytest.fixture
def sample_event():
    """Sample OutboxEvent for testing."""
    return OutboxEvent(
        id=uuid4(),
        aggregate_id=uuid4(),
        event_type="UserCreated",
        event_data={"user_id": "123", "name": "John"}
    )


@pytest.fixture
def sample_event_model(sample_event):
    """Sample OutboxEventModel for testing."""
    return OutboxEventModel.from_domain(sample_event)


class TestOutboxRepositoryAdapter:
    """Test suite for OutboxRepositoryAdapter."""
    
    @pytest.mark.asyncio
    async def test_store_events_success(self, repository, mock_session, sample_event):
        """Test successful event storage."""
        events = [sample_event]
        aggregate_id = sample_event.aggregate_id
        
        await repository.store_events(events, aggregate_id)
        
        # Verify session.add was called
        mock_session.add.assert_called_once()
        
        # Verify the added model is correct
        added_model = mock_session.add.call_args[0][0]
        assert isinstance(added_model, OutboxEventModel)
        assert added_model.id == sample_event.id
        assert added_model.aggregate_id == aggregate_id
        assert added_model.event_type == sample_event.event_type
        assert added_model.event_data == sample_event.event_data
    
    @pytest.mark.asyncio
    async def test_store_events_with_different_aggregate_id(self, repository, mock_session, sample_event):
        """Test event storage with different aggregate ID."""
        events = [sample_event]
        different_aggregate_id = uuid4()
        
        await repository.store_events(events, different_aggregate_id)
        
        # Verify the aggregate_id was updated
        added_model = mock_session.add.call_args[0][0]
        assert added_model.aggregate_id == different_aggregate_id
    
    @pytest.mark.asyncio
    async def test_store_events_multiple_events(self, repository, mock_session):
        """Test storing multiple events."""
        aggregate_id = uuid4()
        events = [
            OutboxEvent(
                aggregate_id=aggregate_id,
                event_type="UserCreated",
                event_data={"user_id": "123"}
            ),
            OutboxEvent(
                aggregate_id=aggregate_id,
                event_type="UserUpdated",
                event_data={"user_id": "123", "name": "John"}
            )
        ]
        
        await repository.store_events(events, aggregate_id)
        
        # Verify session.add was called for each event
        assert mock_session.add.call_count == 2
    
    @pytest.mark.asyncio
    async def test_store_events_failure(self, repository, mock_session):
        """Test event storage failure."""
        mock_session.add.side_effect = Exception("Database error")
        
        events = [OutboxEvent(
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={}
        )]
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.store_events(events, uuid4())
        
        assert "Failed to store outbox events" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_get_unprocessed_events_success(self, repository, mock_session, sample_event_model):
        """Test successful retrieval of unprocessed events."""
        # Mock query result
        mock_result = Mock()
        mock_result.all.return_value = [sample_event_model]
        mock_session.exec.return_value = mock_result
        
        events = await repository.get_unprocessed_events(limit=100)
        
        # Verify query was executed
        mock_session.exec.assert_called_once()
        
        # Verify results
        assert len(events) == 1
        assert isinstance(events[0], OutboxEvent)
        assert events[0].id == sample_event_model.id
        assert events[0].event_type == sample_event_model.event_type
    
    @pytest.mark.asyncio
    async def test_get_unprocessed_events_empty(self, repository, mock_session):
        """Test retrieval when no unprocessed events exist."""
        mock_result = Mock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result
        
        events = await repository.get_unprocessed_events()
        
        assert len(events) == 0
    
    @pytest.mark.asyncio
    async def test_get_unprocessed_events_failure(self, repository, mock_session):
        """Test failure when retrieving unprocessed events."""
        mock_session.exec.side_effect = Exception("Database error")
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.get_unprocessed_events()
        
        assert "Failed to get unprocessed events" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_mark_processed_success(self, repository, mock_session, sample_event_model):
        """Test successful marking of event as processed."""
        # Mock finding the event
        mock_result = Mock()
        mock_result.first.return_value = sample_event_model
        mock_session.exec.return_value = mock_result
        
        await repository.mark_processed(sample_event_model.id)
        
        # Verify event was updated
        assert sample_event_model.processed_at is not None
        assert sample_event_model.error_message is None
        
        # Verify session operations
        mock_session.add.assert_called_once_with(sample_event_model)
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_mark_processed_event_not_found(self, repository, mock_session):
        """Test marking processed when event not found."""
        mock_result = Mock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.mark_processed(uuid4())
        
        assert "Event not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_mark_processed_failure(self, repository, mock_session):
        """Test failure when marking event as processed."""
        mock_session.exec.side_effect = Exception("Database error")
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.mark_processed(uuid4())
        
        assert "Failed to mark event as processed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_increment_retry_success(self, repository, mock_session, sample_event_model):
        """Test successful retry increment."""
        # Mock finding the event
        mock_result = Mock()
        mock_result.first.return_value = sample_event_model
        mock_session.exec.return_value = mock_result
        
        original_retry_count = sample_event_model.retry_count
        error_message = "Connection failed"
        
        await repository.increment_retry(sample_event_model.id, error_message)
        
        # Verify event was updated
        assert sample_event_model.retry_count == original_retry_count + 1
        assert sample_event_model.error_message == error_message
        
        # Verify session operations
        mock_session.add.assert_called_once_with(sample_event_model)
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_increment_retry_event_not_found(self, repository, mock_session):
        """Test retry increment when event not found."""
        mock_result = Mock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.increment_retry(uuid4(), "Error message")
        
        assert "Event not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_increment_retry_truncates_long_error(self, repository, mock_session, sample_event_model):
        """Test retry increment truncates long error messages."""
        mock_result = Mock()
        mock_result.first.return_value = sample_event_model
        mock_session.exec.return_value = mock_result
        
        long_error = "x" * 1500  # Longer than 1000 chars
        
        await repository.increment_retry(sample_event_model.id, long_error)
        
        # Verify error message was truncated
        assert len(sample_event_model.error_message) == 1000
        assert sample_event_model.error_message == long_error[:1000]
    
    @pytest.mark.asyncio
    async def test_get_failed_events_success(self, repository, mock_session, sample_event_model):
        """Test successful retrieval of failed events."""
        # Set up failed event
        sample_event_model.retry_count = 3
        sample_event_model.max_retries = 3
        sample_event_model.processed_at = None
        
        mock_result = Mock()
        mock_result.all.return_value = [sample_event_model]
        mock_session.exec.return_value = mock_result
        
        events = await repository.get_failed_events()
        
        assert len(events) == 1
        assert isinstance(events[0], OutboxEvent)
        assert events[0].retry_count == 3
        assert events[0].max_retries == 3
    
    @pytest.mark.asyncio
    async def test_cleanup_processed_events_success(self, repository, mock_session):
        """Test successful cleanup of processed events."""
        # Mock delete result
        mock_result = Mock()
        mock_result.rowcount = 5
        mock_session.exec.return_value = mock_result
        
        deleted_count = await repository.cleanup_processed_events(older_than_days=30)
        
        assert deleted_count == 5
        mock_session.exec.assert_called_once()
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_processed_events_failure(self, repository, mock_session):
        """Test failure during cleanup."""
        mock_session.exec.side_effect = Exception("Database error")
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.cleanup_processed_events()
        
        assert "Failed to cleanup processed events" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_get_events_by_aggregate_success(self, repository, mock_session, sample_event_model):
        """Test successful retrieval of events by aggregate."""
        mock_result = Mock()
        mock_result.all.return_value = [sample_event_model]
        mock_session.exec.return_value = mock_result
        
        events = await repository.get_events_by_aggregate(sample_event_model.aggregate_id)
        
        assert len(events) == 1
        assert isinstance(events[0], OutboxEvent)
        assert events[0].aggregate_id == sample_event_model.aggregate_id
    
    @pytest.mark.asyncio
    async def test_get_events_by_aggregate_failure(self, repository, mock_session):
        """Test failure when retrieving events by aggregate."""
        mock_session.exec.side_effect = Exception("Database error")
        
        with pytest.raises(InfrastructureError) as exc_info:
            await repository.get_events_by_aggregate(uuid4())
        
        assert "Failed to get events by aggregate" in str(exc_info.value)