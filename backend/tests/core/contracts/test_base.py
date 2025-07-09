"""
Tests for Contract Base Classes

Tests the foundation of the contract system including
ContractEvent, ContractCommand, ContractQuery, and ModuleContract.
"""

import pytest
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4
from typing import Any

from app.core.contracts.base import (
    ContractEvent,
    ContractCommand,
    ContractQuery,
    ContractMessage,
    MessageMetadata,
    ModuleContract,
)


# Test implementations
@dataclass(frozen=True)
class TestEvent(ContractEvent):
    """Test event implementation."""
    user_id: UUID
    action: str
    timestamp: datetime


@dataclass(frozen=True)
class AnotherTestEvent(ContractEvent):
    """Another test event implementation."""
    data: str


@dataclass
class TestCommand(ContractCommand):
    """Test command implementation."""
    user_id: UUID
    action: str


@dataclass
class TestQuery(ContractQuery):
    """Test query implementation."""
    user_id: UUID
    field: str


class TestModuleContract(ModuleContract):
    """Test module contract implementation."""
    
    @property
    def module_name(self) -> str:
        return "test_module"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {
            "TestEvent": TestEvent,
            "AnotherTestEvent": AnotherTestEvent,
        }
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {
            "TestCommand": TestCommand,
        }
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {
            "TestQuery": TestQuery,
        }


class TestMessageMetadata:
    """Test MessageMetadata functionality."""
    
    def test_create_metadata(self):
        """Test creating message metadata."""
        metadata = MessageMetadata()
        
        assert metadata.message_id is not None
        assert isinstance(metadata.message_id, UUID)
        assert metadata.timestamp is not None
        assert isinstance(metadata.timestamp, datetime)
        assert metadata.correlation_id is None
        assert metadata.causation_id is None
        assert metadata.source_module is None
        assert metadata.target_module is None
    
    def test_create_metadata_with_values(self):
        """Test creating metadata with specific values."""
        message_id = uuid4()
        timestamp = datetime.utcnow()
        correlation_id = str(uuid4())
        causation_id = str(uuid4())
        
        metadata = MessageMetadata(
            message_id=message_id,
            timestamp=timestamp,
            correlation_id=correlation_id,
            causation_id=causation_id,
            source_module="module_a",
            target_module="module_b",
        )
        
        assert metadata.message_id == message_id
        assert metadata.timestamp == timestamp
        assert metadata.correlation_id == correlation_id
        assert metadata.causation_id == causation_id
        assert metadata.source_module == "module_a"
        assert metadata.target_module == "module_b"
    
    def test_metadata_to_dict(self):
        """Test converting metadata to dictionary."""
        metadata = MessageMetadata(
            source_module="test",
            target_module="other",
        )
        
        data = metadata.to_dict()
        
        assert "message_id" in data
        assert "timestamp" in data
        assert data["source_module"] == "test"
        assert data["target_module"] == "other"
        assert data["correlation_id"] is None
        assert data["causation_id"] is None


class TestContractEvent:
    """Test ContractEvent functionality."""
    
    def test_create_event(self):
        """Test creating a contract event."""
        user_id = uuid4()
        timestamp = datetime.utcnow()
        
        event = TestEvent(
            user_id=user_id,
            action="test_action",
            timestamp=timestamp,
        )
        
        assert event.user_id == user_id
        assert event.action == "test_action"
        assert event.timestamp == timestamp
        assert event.metadata is not None
    
    def test_event_is_immutable(self):
        """Test that contract events are immutable."""
        event = TestEvent(
            user_id=uuid4(),
            action="test",
            timestamp=datetime.utcnow(),
        )
        
        with pytest.raises(AttributeError):
            event.action = "changed"
    
    def test_event_with_metadata(self):
        """Test creating event with custom metadata."""
        correlation_id = str(uuid4())
        
        event = TestEvent(
            user_id=uuid4(),
            action="test",
            timestamp=datetime.utcnow(),
        )
        
        event_with_meta = event.with_metadata(
            correlation_id=correlation_id,
            source_module="test_source",
        )
        
        assert event_with_meta.metadata.correlation_id == correlation_id
        assert event_with_meta.metadata.source_module == "test_source"
        assert event_with_meta.user_id == event.user_id
        assert event_with_meta.action == event.action
    
    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        user_id = uuid4()
        timestamp = datetime.utcnow()
        
        event = TestEvent(
            user_id=user_id,
            action="test_action",
            timestamp=timestamp,
        )
        
        data = event.to_dict()
        
        assert "metadata" in data
        assert "data" in data
        assert data["data"]["user_id"] == str(user_id)
        assert data["data"]["action"] == "test_action"
        assert data["data"]["timestamp"] == timestamp.isoformat()


class TestContractCommand:
    """Test ContractCommand functionality."""
    
    def test_create_command(self):
        """Test creating a contract command."""
        user_id = uuid4()
        
        command = TestCommand(
            user_id=user_id,
            action="test_action",
        )
        
        assert command.user_id == user_id
        assert command.action == "test_action"
        assert command.metadata is not None
    
    def test_command_is_mutable(self):
        """Test that contract commands are mutable."""
        command = TestCommand(
            user_id=uuid4(),
            action="test",
        )
        
        # Should be able to modify
        command.action = "changed"
        assert command.action == "changed"
    
    def test_command_with_metadata(self):
        """Test creating command with custom metadata."""
        command = TestCommand(
            user_id=uuid4(),
            action="test",
        )
        
        command_with_meta = command.with_metadata(
            source_module="test_source",
            target_module="test_target",
        )
        
        assert command_with_meta.metadata.source_module == "test_source"
        assert command_with_meta.metadata.target_module == "test_target"
        assert command_with_meta.user_id == command.user_id


class TestContractQuery:
    """Test ContractQuery functionality."""
    
    def test_create_query(self):
        """Test creating a contract query."""
        user_id = uuid4()
        
        query = TestQuery(
            user_id=user_id,
            field="test_field",
        )
        
        assert query.user_id == user_id
        assert query.field == "test_field"
        assert query.metadata is not None
    
    def test_query_with_metadata(self):
        """Test creating query with custom metadata."""
        query = TestQuery(
            user_id=uuid4(),
            field="test",
        )
        
        query_with_meta = query.with_metadata(
            correlation_id=str(uuid4()),
        )
        
        assert query_with_meta.metadata.correlation_id is not None
        assert query_with_meta.user_id == query.user_id


class TestModuleContract:
    """Test ModuleContract functionality."""
    
    def test_contract_properties(self):
        """Test module contract properties."""
        contract = TestModuleContract()
        
        assert contract.module_name == "test_module"
        assert contract.version == "1.0.0"
    
    def test_get_events(self):
        """Test getting contract events."""
        contract = TestModuleContract()
        events = contract.get_events()
        
        assert len(events) == 2
        assert "TestEvent" in events
        assert "AnotherTestEvent" in events
        assert events["TestEvent"] == TestEvent
        assert events["AnotherTestEvent"] == AnotherTestEvent
    
    def test_get_commands(self):
        """Test getting contract commands."""
        contract = TestModuleContract()
        commands = contract.get_commands()
        
        assert len(commands) == 1
        assert "TestCommand" in commands
        assert commands["TestCommand"] == TestCommand
    
    def test_get_queries(self):
        """Test getting contract queries."""
        contract = TestModuleContract()
        queries = contract.get_queries()
        
        assert len(queries) == 1
        assert "TestQuery" in queries
        assert queries["TestQuery"] == TestQuery
    
    def test_validate_event(self):
        """Test validating events belong to contract."""
        contract = TestModuleContract()
        
        # Valid event
        event = TestEvent(
            user_id=uuid4(),
            action="test",
            timestamp=datetime.utcnow(),
        )
        assert contract.validate_event(event) is True
        
        # Invalid event (from different module)
        @dataclass(frozen=True)
        class OtherEvent(ContractEvent):
            data: str
        
        other_event = OtherEvent(data="test")
        assert contract.validate_event(other_event) is False
    
    def test_validate_command(self):
        """Test validating commands belong to contract."""
        contract = TestModuleContract()
        
        # Valid command
        command = TestCommand(
            user_id=uuid4(),
            action="test",
        )
        assert contract.validate_command(command) is True
        
        # Invalid command
        @dataclass
        class OtherCommand(ContractCommand):
            data: str
        
        other_command = OtherCommand(data="test")
        assert contract.validate_command(other_command) is False
    
    def test_validate_query(self):
        """Test validating queries belong to contract."""
        contract = TestModuleContract()
        
        # Valid query
        query = TestQuery(
            user_id=uuid4(),
            field="test",
        )
        assert contract.validate_query(query) is True
        
        # Invalid query
        @dataclass
        class OtherQuery(ContractQuery):
            data: str
        
        other_query = OtherQuery(data="test")
        assert contract.validate_query(other_query) is False
    
    def test_has_event(self):
        """Test checking if contract has event type."""
        contract = TestModuleContract()
        
        assert contract.has_event("TestEvent") is True
        assert contract.has_event("AnotherTestEvent") is True
        assert contract.has_event("NonExistentEvent") is False
    
    def test_has_command(self):
        """Test checking if contract has command type."""
        contract = TestModuleContract()
        
        assert contract.has_command("TestCommand") is True
        assert contract.has_command("NonExistentCommand") is False
    
    def test_has_query(self):
        """Test checking if contract has query type."""
        contract = TestModuleContract()
        
        assert contract.has_query("TestQuery") is True
        assert contract.has_query("NonExistentQuery") is False