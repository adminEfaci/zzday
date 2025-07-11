"""
Tests for Contract Base Classes

Tests the foundation of the contract system including
ContractEvent, ContractCommand, ContractQuery, and ModuleContract.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.core.contracts.base import (
    ContractCommand,
    ContractEvent,
    ContractQuery,
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
    
    def _get_data_dict(self) -> dict:
        return {
            "user_id": str(self.user_id),
            "action": self.action,
            "timestamp": self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            user_id=UUID(data["user_id"]),
            action=data["action"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


@dataclass
class TestCommand(ContractCommand):
    """Test command implementation."""
    user_id: UUID
    action: str
    
    def _get_data_dict(self) -> dict:
        return {
            "user_id": str(self.user_id),
            "action": self.action,
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            user_id=UUID(data["user_id"]),
            action=data["action"],
        )


@dataclass
class TestQuery(ContractQuery):
    """Test query implementation."""
    user_id: UUID
    field: str
    
    def _get_data_dict(self) -> dict:
        return {
            "user_id": str(self.user_id),
            "field": self.field,
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            user_id=UUID(data["user_id"]),
            field=data["field"],
        )


class TestModuleContract(ModuleContract):
    """Test module contract implementation."""
    
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestContractEvent:
    """Test ContractEvent functionality."""
    
    def test_create_event(self):
        """Test creating a contract event."""
        user_id = uuid4()
        timestamp = datetime.now(UTC)
        
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
            timestamp=datetime.now(UTC),
        )
        
        with pytest.raises(AttributeError):
            event.action = "changed"
    
    def test_event_with_metadata(self):
        """Test creating event with custom metadata."""
        correlation_id = str(uuid4())
        
        event = TestEvent(
            user_id=uuid4(),
            action="test",
            timestamp=datetime.now(UTC),
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
        timestamp = datetime.now(UTC)
        
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestModuleContract:
    """Test ModuleContract functionality."""
    
    def test_contract_properties(self):
        """Test module contract properties."""
        contract = TestModuleContract()
        
        assert contract.module_name == "test_module"
        assert contract.version == "1.0.0"
    
    def test_validate_event(self):
        """Test validating events belong to contract."""
        contract = TestModuleContract()
        
        # Valid event
        event = TestEvent(
            user_id=uuid4(),
            action="test",
            timestamp=datetime.now(UTC),
        )
        assert contract.validate_event(event) is True
        
        # Test with another event type that doesn't belong
        @dataclass(frozen=True)
        class OtherEvent(ContractEvent):
            data: str
            
            def _get_data_dict(self) -> dict:
                return {"data": self.data}
            
            @classmethod
            def from_dict(cls, data: dict):
                return cls(data=data["data"])
        
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
            
            def _get_data_dict(self) -> dict:
                return {"data": self.data}
            
            @classmethod
            def from_dict(cls, data: dict):
                return cls(data=data["data"])
        
        other_command = OtherCommand(data="test")
        assert contract.validate_command(other_command) is False
    
    def test_has_event(self):
        """Test checking if contract has event type."""
        contract = TestModuleContract()
        
        assert contract.has_event("TestEvent") is True
        assert contract.has_event("NonExistentEvent") is False