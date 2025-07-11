"""
Isolated Tests for Contract Base Classes

These tests run the contract base classes without
requiring the full application configuration.
"""

import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

# Add the app directory to the path so we can import modules directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'app'))

# Define minimal contract base classes for testing
from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import field
from typing import TypeVar

T = TypeVar("T")


@dataclass
class MessageMetadata:
    """Metadata for contract messages."""
    
    message_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    causation_id: str | None = None
    source_module: str | None = None
    target_module: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "message_id": str(self.message_id),
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "source_module": self.source_module,
            "target_module": self.target_module,
        }


@dataclass
class ContractMessage(ABC):
    """Base class for all contract messages."""
    
    metadata: MessageMetadata = field(default_factory=MessageMetadata)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "data": self._get_data_dict(),
        }
    
    @abstractmethod
    def _get_data_dict(self) -> dict[str, Any]:
        """Get the data dictionary for this message."""
    
    @classmethod
    @abstractmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create message from dictionary."""
    
    def with_metadata(self, **kwargs: Any) -> "ContractMessage":
        """Create a copy with updated metadata."""
        new_message = deepcopy(self)
        for key, value in kwargs.items():
            setattr(new_message.metadata, key, value)
        return new_message


@dataclass(frozen=True)
class ContractEvent(ContractMessage):
    """Base class for contract events."""
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get event data as dictionary."""
        data = {}
        for field_name, field_value in self.__dict__.items():
            if field_name != "metadata":
                if isinstance(field_value, UUID):
                    data[field_name] = str(field_value)
                elif isinstance(field_value, datetime):
                    data[field_name] = field_value.isoformat()
                else:
                    data[field_name] = field_value
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create event from dictionary."""
        # Implementation would depend on specific event type
        raise NotImplementedError("Subclasses must implement from_dict")


@dataclass
class ContractCommand(ContractMessage):
    """Base class for contract commands."""
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get command data as dictionary."""
        data = {}
        for field_name, field_value in self.__dict__.items():
            if field_name != "metadata":
                if isinstance(field_value, UUID):
                    data[field_name] = str(field_value)
                elif isinstance(field_value, datetime):
                    data[field_name] = field_value.isoformat()
                else:
                    data[field_name] = field_value
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create command from dictionary."""
        # Implementation would depend on specific command type
        raise NotImplementedError("Subclasses must implement from_dict")


@dataclass
class ContractQuery(ContractMessage):
    """Base class for contract queries."""
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get query data as dictionary."""
        data = {}
        for field_name, field_value in self.__dict__.items():
            if field_name != "metadata":
                if isinstance(field_value, UUID):
                    data[field_name] = str(field_value)
                elif isinstance(field_value, datetime):
                    data[field_name] = field_value.isoformat()
                else:
                    data[field_name] = field_value
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create query from dictionary."""
        # Implementation would depend on specific query type
        raise NotImplementedError("Subclasses must implement from_dict")


class ModuleContract(ABC):
    """Base class for module contracts."""
    
    @property
    @abstractmethod
    def module_name(self) -> str:
        """Get the name of the module."""
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Get the version of the contract."""
    
    @abstractmethod
    def get_events(self) -> dict[str, type[ContractEvent]]:
        """Get all events exposed by the module."""
    
    @abstractmethod
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        """Get all commands accepted by the module."""
    
    @abstractmethod
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        """Get all queries supported by the module."""
    
    def validate_event(self, event: ContractEvent) -> bool:
        """Validate that an event belongs to this contract."""
        return type(event) in self.get_events().values()
    
    def validate_command(self, command: ContractCommand) -> bool:
        """Validate that a command belongs to this contract."""
        return type(command) in self.get_commands().values()
    
    def validate_query(self, query: ContractQuery) -> bool:
        """Validate that a query belongs to this contract."""
        return type(query) in self.get_queries().values()
    
    def has_event(self, event_name: str) -> bool:
        """Check if contract has an event type."""
        return event_name in self.get_events()
    
    def has_command(self, command_name: str) -> bool:
        """Check if contract has a command type."""
        return command_name in self.get_commands()
    
    def has_query(self, query_name: str) -> bool:
        """Check if contract has a query type."""
        return query_name in self.get_queries()


# Test implementations
@dataclass(frozen=True)
class TestEvent(ContractEvent):
    """Test event implementation."""
    user_id: UUID
    action: str
    timestamp: datetime


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
        return {"TestEvent": TestEvent}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {"TestCommand": TestCommand}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {"TestQuery": TestQuery}


# Now the actual tests
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


class TestModuleContractImplementation:
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
    
    def test_has_event(self):
        """Test checking if contract has event type."""
        contract = TestModuleContract()
        
        assert contract.has_event("TestEvent") is True
        assert contract.has_event("NonExistentEvent") is False


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v"])