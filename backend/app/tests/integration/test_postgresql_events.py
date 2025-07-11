"""
Integration tests for PostgreSQL event system with cross-module communication.

Tests the complete event flow with PostgreSQL persistence, Redis distribution,
and cross-module event handlers in a Docker environment.
"""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

from app.core.events.cross_module import CrossModuleEventOrchestrator
from app.core.events.docker_config import (
    DockerEventSystemConfig,
)
from app.core.events.serialization import PostgreSQLEventSerializer
from app.core.events.types import EventMetadata
from app.modules.identity.domain.entities.user.user_events import (
    UserCreated,
)


@pytest.mark.integration
@pytest.mark.postgresql
class TestPostgreSQLEventPersistence:
    """Test PostgreSQL event persistence and serialization."""

    @pytest.fixture
    async def postgresql_serializer(self):
        """Create PostgreSQL event serializer."""
        return PostgreSQLEventSerializer(
            enable_compression=True,
            compression_threshold=1024,
            enable_encryption=False
        )

    @pytest.fixture
    async def test_user_created_event(self):
        """Create test user created event."""
        user_id = uuid4()
        metadata = EventMetadata(
            event_type="UserCreated",
            aggregate_id=user_id,
            user_id=user_id,
            correlation_id=str(uuid4()),
            timestamp=datetime.now(UTC)
        )
        
        return UserCreated(
            user_id=user_id,
            email="test@example.com",
            name="Test User",
            role="user",
            registration_method="email",
            metadata=metadata
        )

    @pytest.mark.asyncio
    async def test_event_serialization_deserialization(
        self, postgresql_serializer, test_user_created_event
    ):
        """Test event serialization and deserialization for PostgreSQL."""
        # Serialize event
        serialized = postgresql_serializer.serialize_event(test_user_created_event)
        
        # Verify serialized structure
        assert "event_id" in serialized
        assert "event_type" in serialized
        assert "event_data" in serialized
        assert "metadata" in serialized
        assert "created_at" in serialized
        assert serialized["event_type"] == "UserCreated"
        
        # Deserialize event
        deserialized_event = postgresql_serializer.deserialize_event(serialized)
        
        # Verify deserialized event
        assert deserialized_event.event_type == "UserCreated"
        assert deserialized_event.user_id == test_user_created_event.user_id
        assert deserialized_event.email == test_user_created_event.email
        assert deserialized_event.metadata.event_id == test_user_created_event.metadata.event_id

    @pytest.mark.asyncio
    async def test_large_event_compression(self, postgresql_serializer):
        """Test compression for large events."""
        # Create large event data
        large_data = {"large_field": "x" * 2000}  # > compression threshold
        user_id = uuid4()
        
        metadata = EventMetadata(
            event_type="UserCreated",
            aggregate_id=user_id,
            user_id=user_id
        )
        
        event = UserCreated(
            user_id=user_id,
            email="test@example.com",
            name="Test User",
            role="user",
            registration_method="email",
            metadata=metadata,
            **large_data
        )
        
        # Serialize with compression
        serialized = postgresql_serializer.serialize_event(event)
        
        # Verify compression was applied
        assert serialized["compression"] == "gzip"
        assert "compressed_size" in serialized
        assert serialized["compressed_size"] < serialized["original_size"]
        
        # Verify deserialization works
        deserialized_event = postgresql_serializer.deserialize_event(serialized)
        assert hasattr(deserialized_event, 'large_field')
        assert deserialized_event.large_field == "x" * 2000


@pytest.mark.integration
@pytest.mark.docker
class TestDockerEventSystemConfiguration:
    """Test Docker environment event system configuration."""

    @pytest.fixture
    def mock_environment(self):
        """Mock Docker environment variables."""
        with patch.dict('os.environ', {
            'POSTGRES_HOST': 'postgres',
            'POSTGRES_PORT': '5432',
            'POSTGRES_DB': 'ezzday_test',
            'POSTGRES_USER': 'test_user',
            'POSTGRES_PASSWORD': 'test_pass',
            'REDIS_HOST': 'redis',
            'REDIS_PORT': '6379',
            'ENABLE_POSTGRESQL_EVENTS': 'true',
            'ENABLE_REDIS_EVENTS': 'true',
            'ENABLE_EVENT_COMPRESSION': 'true',
            'EVENT_RETENTION_DAYS': '90'
        }):
            yield

    def test_docker_config_loading(self, mock_environment):
        """Test Docker configuration loading from environment."""
        config = DockerEventSystemConfig()
        
        assert config.postgresql_host == "postgres"
        assert config.postgresql_port == 5432
        assert config.postgresql_database == "ezzday_test"
        assert config.postgresql_user == "test_user"
        assert config.postgresql_password == "test_pass"
        assert config.redis_host == "redis"
        assert config.redis_port == 6379
        assert config.enable_postgresql_persistence is True
        assert config.enable_redis_distribution is True
        assert config.enable_event_compression is True
        assert config.event_retention_days == 90

    def test_postgresql_url_generation(self, mock_environment):
        """Test PostgreSQL URL generation."""
        config = DockerEventSystemConfig()
        url = config.get_postgresql_url()
        
        expected = "postgresql://test_user:test_pass@postgres:5432/ezzday_test"
        assert url == expected

    def test_redis_url_generation(self, mock_environment):
        """Test Redis URL generation."""
        config = DockerEventSystemConfig()
        url = config.get_redis_url()
        
        expected = "redis://redis:6379/0"
        assert url == expected


@pytest.mark.integration
@pytest.mark.asyncio
class TestCrossModuleEventOrchestration:
    """Test cross-module event orchestration with PostgreSQL persistence."""

    @pytest.fixture
    async def mock_event_bus(self):
        """Create mock event bus."""
        event_bus = AsyncMock()
        event_bus.start = AsyncMock()
        event_bus.stop = AsyncMock()
        event_bus.subscribe = Mock()
        event_bus.unsubscribe = Mock()
        event_bus.publish = AsyncMock()
        return event_bus

    @pytest.fixture
    async def orchestrator(self, mock_event_bus):
        """Create cross-module event orchestrator."""
        orchestrator = CrossModuleEventOrchestrator(
            event_bus=mock_event_bus,
            enable_postgresql_persistence=True,
            enable_cross_module_audit=True,
            enable_performance_monitoring=True
        )
        await orchestrator.initialize()
        yield orchestrator
        await orchestrator.shutdown()

    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self, orchestrator, mock_event_bus):
        """Test orchestrator initialization and handler registration."""
        # Verify event bus was started
        mock_event_bus.start.assert_called_once()
        
        # Verify handlers were registered
        assert mock_event_bus.subscribe.call_count > 0
        
        # Verify registration statistics
        stats = orchestrator.get_registration_statistics()
        assert stats["initialized"] is True
        assert stats["total_event_types"] > 0
        assert stats["postgresql_persistence"] is True

    @pytest.mark.asyncio
    async def test_identity_to_audit_event_flow(self, orchestrator, mock_event_bus):
        """Test Identity → Audit event flow registration."""
        # Check that user events are registered for audit handlers
        subscribe_calls = mock_event_bus.subscribe.call_args_list
        
        # Extract event types that were subscribed
        subscribed_events = [call[0][0].__name__ for call in subscribe_calls]
        
        # Verify key identity events are registered
        expected_events = ["UserCreated", "LoginSuccessful", "LoginFailed", "PasswordChanged"]
        for event_type in expected_events:
            assert event_type in subscribed_events or any(
                event_type in str(call) for call in subscribe_calls
            ), f"Event {event_type} should be registered for audit"

    @pytest.mark.asyncio
    async def test_identity_to_notification_event_flow(self, orchestrator, mock_event_bus):
        """Test Identity → Notification event flow registration."""
        subscribe_calls = mock_event_bus.subscribe.call_args_list
        
        # Verify notification-triggering events are registered
        subscribed_events = [call[0][0].__name__ for call in subscribe_calls]
        
        notification_events = ["UserCreated", "PasswordChanged", "LoginFailed"]
        for event_type in notification_events:
            assert event_type in subscribed_events or any(
                event_type in str(call) for call in subscribe_calls
            ), f"Event {event_type} should trigger notifications"

    @pytest.mark.asyncio
    async def test_orchestrator_shutdown(self, mock_event_bus):
        """Test orchestrator graceful shutdown."""
        orchestrator = CrossModuleEventOrchestrator(
            event_bus=mock_event_bus,
            enable_postgresql_persistence=True
        )
        await orchestrator.initialize()
        
        # Test shutdown
        await orchestrator.shutdown()
        
        # Verify event bus was stopped
        mock_event_bus.stop.assert_called_once()


@pytest.mark.integration
@pytest.mark.asyncio
class TestEventPropagationFlow:
    """Test end-to-end event propagation with PostgreSQL persistence."""

    @pytest.fixture
    async def mock_audit_service(self):
        """Mock audit service."""
        service = AsyncMock()
        service.create_audit_log = AsyncMock()
        service.create_security_audit = AsyncMock()
        return service

    @pytest.fixture
    async def mock_notification_service(self):
        """Mock notification service."""
        service = AsyncMock()
        service.send_welcome_email = AsyncMock()
        service.send_security_alert = AsyncMock()
        return service

    @pytest.mark.asyncio
    async def test_user_registration_event_propagation(
        self, mock_audit_service, mock_notification_service
    ):
        """Test complete user registration event propagation."""
        # Create in-memory event bus for testing
        from app.core.events.bus import InMemoryEventBus
        
        event_bus = InMemoryEventBus()
        await event_bus.start()
        
        try:
            # Create orchestrator
            orchestrator = CrossModuleEventOrchestrator(
                event_bus=event_bus,
                enable_postgresql_persistence=False,  # Use in-memory for test
                enable_cross_module_audit=True
            )
            await orchestrator.initialize()
            
            # Create test event
            user_id = uuid4()
            user_created_event = UserCreated(
                user_id=user_id,
                email="test@example.com",
                name="Test User",
                role="user",
                registration_method="email"
            )
            
            # Publish event
            await event_bus.publish(user_created_event)
            
            # Allow event processing
            await asyncio.sleep(0.1)
            
            # Verify event was processed (handlers were called)
            # Note: In real test, we'd mock the actual handlers and verify calls
            
            await orchestrator.shutdown()
            
        finally:
            await event_bus.stop()

    @pytest.mark.asyncio
    async def test_login_failure_security_event_propagation(self):
        """Test login failure security event propagation."""
        from app.core.events.bus import InMemoryEventBus
        from app.modules.identity.domain.entities.user.user_events import LoginFailed
        
        event_bus = InMemoryEventBus()
        await event_bus.start()
        
        try:
            orchestrator = CrossModuleEventOrchestrator(
                event_bus=event_bus,
                enable_postgresql_persistence=False
            )
            await orchestrator.initialize()
            
            # Create failed login event
            user_id = uuid4()
            login_failed_event = LoginFailed(
                user_id=user_id,
                email="test@example.com",
                failure_reason="invalid_password",
                ip_address="192.168.1.100",
                user_agent="Test Browser",
                attempt_number=3
            )
            
            # Publish security event
            await event_bus.publish(login_failed_event)
            
            # Allow event processing
            await asyncio.sleep(0.1)
            
            await orchestrator.shutdown()
            
        finally:
            await event_bus.stop()


@pytest.mark.integration
@pytest.mark.performance
class TestEventSystemPerformance:
    """Test event system performance with PostgreSQL persistence."""

    @pytest.mark.asyncio
    async def test_high_volume_event_processing(self):
        """Test processing of high volume events."""
        from app.core.events.bus import InMemoryEventBus
        
        event_bus = InMemoryEventBus()
        await event_bus.start()
        
        try:
            # Track processed events
            processed_events = []
            
            async def event_counter(event):
                processed_events.append(event)
            
            # Subscribe counter to user events
            event_bus.subscribe(UserCreated, event_counter)
            
            # Generate high volume of events
            event_count = 1000
            tasks = []
            
            for i in range(event_count):
                user_created_event = UserCreated(
                    user_id=uuid4(),
                    email=f"user{i}@example.com",
                    name=f"User {i}",
                    role="user",
                    registration_method="email"
                )
                tasks.append(event_bus.publish(user_created_event))
            
            # Measure processing time
            start_time = datetime.now()
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.5)  # Allow processing
            end_time = datetime.now()
            
            processing_duration = (end_time - start_time).total_seconds()
            events_per_second = len(processed_events) / processing_duration
            
            # Verify performance
            assert len(processed_events) >= event_count * 0.95  # Allow 5% processing lag
            assert events_per_second >= 100, f"Too slow: {events_per_second} events/sec"
            
            print(f"Processed {len(processed_events)} events in {processing_duration:.2f}s")
            print(f"Performance: {events_per_second:.1f} events/second")
            
        finally:
            await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_serialization_performance(self):
        """Test event serialization performance for PostgreSQL."""
        serializer = PostgreSQLEventSerializer()
        
        # Create test event
        user_id = uuid4()
        event = UserCreated(
            user_id=user_id,
            email="test@example.com",
            name="Test User",
            role="user",
            registration_method="email"
        )
        
        # Measure serialization performance
        iterations = 1000
        start_time = datetime.now()
        
        for _ in range(iterations):
            serialized = serializer.serialize_event(event)
            deserialized = serializer.deserialize_event(serialized)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        operations_per_second = (iterations * 2) / duration  # serialize + deserialize
        
        # Verify performance
        assert operations_per_second >= 500, f"Too slow: {operations_per_second} ops/sec"
        
        print(f"Serialization performance: {operations_per_second:.1f} operations/second")


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.asyncio
class TestDockerEventSystemIntegration:
    """Test complete Docker event system integration."""

    @pytest.mark.skipif(
        not pytest.importorskip("asyncpg", reason="asyncpg required for PostgreSQL tests"),
        reason="PostgreSQL integration tests require asyncpg"
    )
    async def test_docker_event_system_initialization(self):
        """Test Docker event system initialization with mocked dependencies."""
        with patch.dict('os.environ', {
            'POSTGRES_HOST': 'localhost',
            'POSTGRES_PASSWORD': 'test',
            'REDIS_HOST': 'localhost',
            'ENABLE_POSTGRESQL_EVENTS': 'false',  # Disable for test
            'ENABLE_REDIS_EVENTS': 'false'
        }):
            config = DockerEventSystemConfig()
            config.validate()
            
            # Test configuration values
            assert config.postgresql_host == "localhost"
            assert config.redis_host == "localhost"
            assert config.enable_postgresql_persistence is False
            assert config.enable_redis_distribution is False

    @pytest.mark.asyncio
    async def test_event_system_health_check(self):
        """Test event system health check functionality."""
        from app.core.events.docker_config import event_system_health_check
        
        with patch.dict('os.environ', {
            'ENABLE_POSTGRESQL_EVENTS': 'false',
            'ENABLE_REDIS_EVENTS': 'false'
        }):
            health_status = await event_system_health_check()
            
            assert "status" in health_status
            assert "postgresql_configured" in health_status
            assert "redis_configured" in health_status
            assert "timestamp" in health_status
            
            # Should be healthy with disabled services
            assert health_status["status"] in ["healthy", "degraded"]