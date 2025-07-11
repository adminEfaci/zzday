"""
Tests for Internal Module Adapter Base Class

Tests the base adapter functionality for cross-module communication.
"""

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import Mock

import pytest

from app.core.contracts import (
    ContractCommand,
    ContractEvent,
    ContractQuery,
    ContractRegistry,
    ModuleContract,
)
from app.core.events import EventBus
from app.core.infrastructure.adapters import InternalModuleAdapter


# Test implementations
@dataclass(frozen=True)
class TestEvent(ContractEvent):
    """Test event."""
    data: str


@dataclass
class TestCommand(ContractCommand):
    """Test command."""
    value: int


@dataclass
class TestQuery(ContractQuery):
    """Test query."""
    id: str


class TestContract(ModuleContract):
    """Test module contract."""
    
    @property
    def module_name(self) -> str:
        return "test_module"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {"TestEvent": TestEvent}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {"TestCommand": TestCommand}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {"TestQuery": TestQuery}


class ConcreteAdapter(InternalModuleAdapter):
    """Concrete adapter implementation for testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent_commands = []
        self.sent_queries = []
        self.command_results = {}
        self.query_results = {}
    
    async def _send_command_internal(self, command: ContractCommand) -> Any:
        """Track sent commands and return mock results."""
        self.sent_commands.append(command)
        return self.command_results.get(type(command), {"status": "success"})
    
    async def _send_query_internal(self, query: ContractQuery) -> Any:
        """Track sent queries and return mock results."""
        self.sent_queries.append(query)
        return self.query_results.get(type(query), {"data": "test"})


class TestInternalModuleAdapter:
    """Test InternalModuleAdapter functionality."""
    
    @pytest.fixture
    def event_bus(self):
        """Create a mock event bus."""
        bus = Mock(spec=EventBus)
        bus.subscribe = Mock()
        bus.unsubscribe = Mock()
        return bus
    
    @pytest.fixture
    def contract_registry(self):
        """Create a contract registry with test contract."""
        registry = ContractRegistry()
        registry.register_contract(TestContract())
        return registry
    
    @pytest.fixture
    def adapter(self, event_bus, contract_registry):
        """Create a test adapter."""
        return ConcreteAdapter(
            event_bus=event_bus,
            source_module="source_module",
            target_module="test_module",
            contract_registry=contract_registry,
        )
    
    def test_create_adapter(self, adapter):
        """Test creating an adapter."""
        assert adapter._source_module == "source_module"
        assert adapter._target_module == "test_module"
        assert adapter._initialized is False
        assert adapter._target_contract is None
    
    @pytest.mark.asyncio
    async def test_initialize_adapter(self, adapter, contract_registry):
        """Test initializing an adapter."""
        await adapter.initialize()
        
        assert adapter._initialized is True
        assert adapter._target_contract is not None
        assert adapter._target_contract.module_name == "test_module"
    
    @pytest.mark.asyncio
    async def test_initialize_missing_contract(self, event_bus):
        """Test initializing adapter when target contract is missing."""
        registry = ContractRegistry()  # Empty registry
        
        adapter = ConcreteAdapter(
            event_bus=event_bus,
            source_module="source",
            target_module="missing",
            contract_registry=registry,
        )
        
        with pytest.raises(RuntimeError, match="Contract for module 'missing' not found"):
            await adapter.initialize()
    
    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, adapter):
        """Test that initialization is idempotent."""
        await adapter.initialize()
        target_contract = adapter._target_contract
        
        # Initialize again
        await adapter.initialize()
        
        # Should be the same contract
        assert adapter._target_contract is target_contract
    
    @pytest.mark.asyncio
    async def test_register_event_handler(self, adapter, event_bus):
        """Test registering event handlers."""
        handler = Mock()
        
        adapter.register_event_handler(TestEvent, handler)
        
        assert TestEvent in adapter._event_handlers
        assert adapter._event_handlers[TestEvent] == handler
        
        # Should not subscribe until initialized
        event_bus.subscribe.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_register_event_handler_after_init(self, adapter, event_bus):
        """Test registering event handler after initialization."""
        await adapter.initialize()
        event_bus.subscribe.reset_mock()
        
        handler = Mock()
        adapter.register_event_handler(TestEvent, handler)
        
        # Should subscribe immediately
        event_bus.subscribe.assert_called_once_with(TestEvent, handler)
    
    @pytest.mark.asyncio
    async def test_subscribe_to_events(self, adapter, event_bus):
        """Test subscribing to events during initialization."""
        handler1 = Mock()
        handler2 = Mock()
        
        adapter.register_event_handler(TestEvent, handler1)
        # Register handler for event not in target contract
        @dataclass(frozen=True)
        class OtherEvent(ContractEvent):
            data: str
        
        adapter.register_event_handler(OtherEvent, handler2)
        
        await adapter.initialize()
        
        # Should only subscribe to TestEvent
        event_bus.subscribe.assert_called_once_with(TestEvent, handler1)
    
    @pytest.mark.asyncio
    async def test_send_command(self, adapter):
        """Test sending a command."""
        await adapter.initialize()
        
        command = TestCommand(value=42)
        adapter.command_results[TestCommand] = {"result": "test"}
        
        result = await adapter.send_command(command)
        
        assert result == {"result": "test"}
        assert len(adapter.sent_commands) == 1
        sent_command = adapter.sent_commands[0]
        assert sent_command.value == 42
        assert sent_command.metadata.source_module == "source_module"
        assert sent_command.metadata.target_module == "test_module"
    
    @pytest.mark.asyncio
    async def test_send_invalid_command(self, adapter):
        """Test sending command that doesn't belong to target module."""
        await adapter.initialize()
        
        @dataclass
        class InvalidCommand(ContractCommand):
            data: str
        
        command = InvalidCommand(data="test")
        
        with pytest.raises(ValueError, match="does not belong to test_module"):
            await adapter.send_command(command)
    
    @pytest.mark.asyncio
    async def test_send_query(self, adapter):
        """Test sending a query."""
        await adapter.initialize()
        
        query = TestQuery(id="test-id")
        adapter.query_results[TestQuery] = {"found": True}
        
        result = await adapter.send_query(query)
        
        assert result == {"found": True}
        assert len(adapter.sent_queries) == 1
        sent_query = adapter.sent_queries[0]
        assert sent_query.id == "test-id"
        assert sent_query.metadata.source_module == "source_module"
        assert sent_query.metadata.target_module == "test_module"
    
    @pytest.mark.asyncio
    async def test_send_invalid_query(self, adapter):
        """Test sending query that doesn't belong to target module."""
        await adapter.initialize()
        
        @dataclass
        class InvalidQuery(ContractQuery):
            data: str
        
        query = InvalidQuery(data="test")
        
        with pytest.raises(ValueError, match="does not belong to test_module"):
            await adapter.send_query(query)
    
    @pytest.mark.asyncio
    async def test_auto_initialize_on_send(self, adapter):
        """Test that adapter auto-initializes when sending."""
        assert adapter._initialized is False
        
        command = TestCommand(value=10)
        await adapter.send_command(command)
        
        assert adapter._initialized is True
    
    def test_get_target_contract(self, adapter):
        """Test getting target contract."""
        assert adapter.get_target_contract() is None
        
        asyncio.run(adapter.initialize())
        
        contract = adapter.get_target_contract()
        assert contract is not None
        assert contract.module_name == "test_module"
    
    @pytest.mark.asyncio
    async def test_close_adapter(self, adapter, event_bus):
        """Test closing an adapter."""
        handler = Mock()
        adapter.register_event_handler(TestEvent, handler)
        
        await adapter.initialize()
        event_bus.subscribe.assert_called_once()
        event_bus.unsubscribe.reset_mock()
        
        await adapter.close()
        
        assert adapter._initialized is False
        event_bus.unsubscribe.assert_called_once_with(TestEvent, handler)
    
    @pytest.mark.asyncio
    async def test_close_uninitialized_adapter(self, adapter, event_bus):
        """Test closing an uninitialized adapter."""
        await adapter.close()
        
        # Should not try to unsubscribe
        event_bus.unsubscribe.assert_not_called()