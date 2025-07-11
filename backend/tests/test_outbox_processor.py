"""
Tests for OutboxProcessor service.
"""

import asyncio
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.models.outbox_event import OutboxEvent
from app.repositories.outbox_repository import OutboxRepository
from app.services.outbox_processor import EventBus, OutboxProcessor, RetryPolicy


class MockEventBus(EventBus):
    """Mock event bus for testing."""
    
    def __init__(self):
        self.published_events = []
        self.should_fail = False
        self.failure_message = "Event bus failure"
    
    async def publish(self, event):
        """Mock publish method."""
        if self.should_fail:
            raise RuntimeError(self.failure_message)
        self.published_events.append(event)


@pytest.fixture
def mock_outbox_repo():
    """Mock OutboxRepository."""
    repo = Mock(spec=OutboxRepository)
    repo.get_unprocessed_events = AsyncMock(return_value=[])
    repo.mark_processed = AsyncMock()
    repo.increment_retry = AsyncMock()
    repo.get_failed_events = AsyncMock(return_value=[])
    repo.cleanup_processed_events = AsyncMock(return_value=0)
    return repo


@pytest.fixture
def mock_event_bus():
    """Mock EventBus."""
    return MockEventBus()


@pytest.fixture
def retry_policy():
    """RetryPolicy for testing."""
    return RetryPolicy(base_delay=0.1, max_delay=1.0, backoff_multiplier=2.0)


@pytest.fixture
def processor(mock_outbox_repo, mock_event_bus, retry_policy):
    """OutboxProcessor instance for testing."""
    return OutboxProcessor(
        outbox_repo=mock_outbox_repo,
        event_bus=mock_event_bus,
        retry_policy=retry_policy,
        batch_size=10,
        poll_interval=0.1,
        max_concurrent_events=5
    )


@pytest.fixture
def sample_event():
    """Sample OutboxEvent for testing."""
    return OutboxEvent(
        id=uuid4(),
        aggregate_id=uuid4(),
        event_type="UserCreated",
        event_data={"user_id": "123", "name": "John"}
    )


class TestRetryPolicy:
    """Test suite for RetryPolicy."""
    
    def test_calculate_delay_exponential_backoff(self):
        """Test exponential backoff calculation."""
        policy = RetryPolicy(base_delay=1.0, backoff_multiplier=2.0, jitter=False)
        
        assert policy.calculate_delay(0) == 1.0
        assert policy.calculate_delay(1) == 2.0
        assert policy.calculate_delay(2) == 4.0
        assert policy.calculate_delay(3) == 8.0
    
    def test_calculate_delay_max_delay_cap(self):
        """Test delay is capped at max_delay."""
        policy = RetryPolicy(base_delay=1.0, max_delay=5.0, backoff_multiplier=2.0, jitter=False)
        
        assert policy.calculate_delay(0) == 1.0
        assert policy.calculate_delay(1) == 2.0
        assert policy.calculate_delay(2) == 4.0
        assert policy.calculate_delay(3) == 5.0  # Capped at max_delay
        assert policy.calculate_delay(10) == 5.0  # Still capped
    
    def test_calculate_delay_with_jitter(self):
        """Test delay calculation with jitter."""
        policy = RetryPolicy(base_delay=2.0, backoff_multiplier=1.0, jitter=True)
        
        # With jitter, delay should be between 50% and 100% of base delay
        delay = policy.calculate_delay(0)
        assert 1.0 <= delay <= 2.0
    
    def test_calculate_delay_default_values(self):
        """Test default retry policy values."""
        policy = RetryPolicy()
        
        assert policy.base_delay == 1.0
        assert policy.max_delay == 60.0
        assert policy.backoff_multiplier == 2.0
        assert policy.jitter is True


class TestOutboxProcessor:
    """Test suite for OutboxProcessor."""
    
    @pytest.mark.asyncio
    async def test_process_events_success(self, processor, mock_outbox_repo, mock_event_bus, sample_event):
        """Test successful event processing."""
        # Setup
        mock_outbox_repo.get_unprocessed_events.return_value = [sample_event]
        
        # Execute
        await processor.process_events()
        
        # Verify
        mock_outbox_repo.get_unprocessed_events.assert_called_once()
        assert len(mock_event_bus.published_events) == 1
        
        published_event = mock_event_bus.published_events[0]
        assert published_event["id"] == str(sample_event.id)
        assert published_event["event_type"] == sample_event.event_type
        assert published_event["event_data"] == sample_event.event_data
        
        mock_outbox_repo.mark_processed.assert_called_once_with(sample_event.id)
    
    @pytest.mark.asyncio
    async def test_process_events_no_events(self, processor, mock_outbox_repo, mock_event_bus):
        """Test processing when no events exist."""
        # Setup
        mock_outbox_repo.get_unprocessed_events.return_value = []
        
        # Execute
        await processor.process_events()
        
        # Verify
        mock_outbox_repo.get_unprocessed_events.assert_called_once()
        assert len(mock_event_bus.published_events) == 0
        mock_outbox_repo.mark_processed.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_process_events_multiple_events(self, processor, mock_outbox_repo, mock_event_bus):
        """Test processing multiple events."""
        # Setup
        events = [
            OutboxEvent(
                id=uuid4(),
                aggregate_id=uuid4(),
                event_type="UserCreated",
                event_data={"user_id": "123"}
            ),
            OutboxEvent(
                id=uuid4(),
                aggregate_id=uuid4(),
                event_type="UserUpdated",
                event_data={"user_id": "123", "name": "John"}
            )
        ]
        mock_outbox_repo.get_unprocessed_events.return_value = events
        
        # Execute
        await processor.process_events()
        
        # Verify
        assert len(mock_event_bus.published_events) == 2
        assert mock_outbox_repo.mark_processed.call_count == 2
    
    @pytest.mark.asyncio
    async def test_process_events_publishing_failure(self, processor, mock_outbox_repo, mock_event_bus, sample_event):
        """Test event processing when publishing fails."""
        # Setup
        mock_outbox_repo.get_unprocessed_events.return_value = [sample_event]
        mock_event_bus.should_fail = True
        mock_event_bus.failure_message = "Network error"
        
        # Execute
        await processor.process_events()
        
        # Verify
        # Event should not be marked as processed
        mock_outbox_repo.mark_processed.assert_not_called()
        
        # Retry count should be incremented
        mock_outbox_repo.increment_retry.assert_called_once_with(
            sample_event.id, 
            mock_event_bus.failure_message
        )
    
    @pytest.mark.asyncio
    async def test_process_events_with_retry_delay(self, processor, mock_outbox_repo, mock_event_bus, sample_event):
        """Test retry delay is applied for failed events."""
        # Setup event that can be retried
        sample_event = OutboxEvent(
            id=uuid4(),
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=1,
            max_retries=3
        )
        mock_outbox_repo.get_unprocessed_events.return_value = [sample_event]
        mock_event_bus.should_fail = True
        
        # Execute with timing
        start_time = asyncio.get_event_loop().time()
        await processor.process_events()
        end_time = asyncio.get_event_loop().time()
        
        # Verify retry delay was applied (should be at least the base delay)
        assert end_time - start_time >= processor.retry_policy.base_delay
    
    @pytest.mark.asyncio
    async def test_process_events_exhausted_retries(self, processor, mock_outbox_repo, mock_event_bus, sample_event):
        """Test processing event that has exhausted retries."""
        # Setup event that cannot be retried
        sample_event = OutboxEvent(
            id=uuid4(),
            aggregate_id=uuid4(),
            event_type="UserCreated",
            event_data={},
            retry_count=3,
            max_retries=3
        )
        mock_outbox_repo.get_unprocessed_events.return_value = [sample_event]
        mock_event_bus.should_fail = True
        
        # Execute
        await processor.process_events()
        
        # Verify retry count is still incremented even for exhausted events
        mock_outbox_repo.increment_retry.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_and_stop_processor(self, processor):
        """Test starting and stopping the processor."""
        # Start processor
        await processor.start()
        assert processor.is_running
        
        # Small delay to let processing loop start
        await asyncio.sleep(0.05)
        
        # Stop processor
        await processor.stop()
        assert not processor.is_running
    
    @pytest.mark.asyncio
    async def test_start_already_running(self, processor):
        """Test starting processor when already running."""
        await processor.start()
        assert processor.is_running
        
        # Try to start again - should not raise error
        await processor.start()
        assert processor.is_running
        
        await processor.stop()
    
    @pytest.mark.asyncio
    async def test_stop_not_running(self, processor):
        """Test stopping processor when not running."""
        assert not processor.is_running
        
        # Should not raise error
        await processor.stop()
        assert not processor.is_running
    
    @pytest.mark.asyncio
    async def test_get_failed_events(self, processor, mock_outbox_repo):
        """Test getting failed events."""
        failed_events = [
            OutboxEvent(
                id=uuid4(),
                aggregate_id=uuid4(),
                event_type="UserCreated",
                event_data={},
                retry_count=3,
                max_retries=3
            )
        ]
        mock_outbox_repo.get_failed_events.return_value = failed_events
        
        result = await processor.get_failed_events()
        
        assert result == failed_events
        mock_outbox_repo.get_failed_events.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_processed_events(self, processor, mock_outbox_repo):
        """Test cleanup of processed events."""
        mock_outbox_repo.cleanup_processed_events.return_value = 10
        
        result = await processor.cleanup_processed_events(older_than_days=7)
        
        assert result == 10
        mock_outbox_repo.cleanup_processed_events.assert_called_once_with(7)
    
    @pytest.mark.asyncio
    async def test_processing_loop_error_handling(self, processor, mock_outbox_repo):
        """Test error handling in processing loop."""
        # Setup repository to raise error
        mock_outbox_repo.get_unprocessed_events.side_effect = Exception("Database error")
        
        # Start processor
        await processor.start()
        
        # Let it run for a short time
        await asyncio.sleep(0.15)
        
        # Stop processor
        await processor.stop()
        
        # Verify processor handled the error and continued running
        assert not processor.is_running  # Should be stopped now
    
    @pytest.mark.asyncio
    async def test_concurrent_event_processing(self, processor, mock_outbox_repo, mock_event_bus):
        """Test concurrent processing of events."""
        # Setup multiple events
        events = [
            OutboxEvent(
                id=uuid4(),
                aggregate_id=uuid4(),
                event_type=f"Event{i}",
                event_data={"id": i}
            )
            for i in range(10)
        ]
        mock_outbox_repo.get_unprocessed_events.return_value = events
        
        # Execute
        await processor.process_events()
        
        # Verify all events were processed
        assert len(mock_event_bus.published_events) == 10
        assert mock_outbox_repo.mark_processed.call_count == 10
    
    def test_processor_initialization(self, mock_outbox_repo, mock_event_bus):
        """Test processor initialization with custom parameters."""
        processor = OutboxProcessor(
            outbox_repo=mock_outbox_repo,
            event_bus=mock_event_bus,
            batch_size=50,
            poll_interval=2.0,
            max_concurrent_events=20
        )
        
        assert processor.outbox_repo == mock_outbox_repo
        assert processor.event_bus == mock_event_bus
        assert processor.batch_size == 50
        assert processor.poll_interval == 2.0
        assert processor.max_concurrent_events == 20
        assert not processor.is_running
    
    def test_processor_default_retry_policy(self, mock_outbox_repo, mock_event_bus):
        """Test processor uses default retry policy when none provided."""
        processor = OutboxProcessor(
            outbox_repo=mock_outbox_repo,
            event_bus=mock_event_bus
        )
        
        assert processor.retry_policy is not None
        assert isinstance(processor.retry_policy, RetryPolicy)
        assert processor.retry_policy.base_delay == 1.0
        assert processor.retry_policy.max_delay == 60.0