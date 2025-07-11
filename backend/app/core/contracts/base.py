"""
Base Contract Classes for Module Communication

Provides the foundation for module contracts that enable proper
module boundaries and prevent direct cross-module dependencies.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

T = TypeVar("T")


@dataclass(frozen=True)
class ContractMetadata:
    """Metadata for contract messages."""
    
    contract_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_module: str = ""
    target_module: str | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    version: str = "1.0"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            "contract_id": str(self.contract_id),
            "timestamp": self.timestamp.isoformat(),
            "source_module": self.source_module,
            "target_module": self.target_module,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "version": self.version,
        }


class ContractMessage(ABC):
    """Base class for all contract messages."""
    
    def __init__(self, metadata: ContractMetadata | None = None):
        self.metadata = metadata or ContractMetadata()
    
    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Convert message to dictionary."""
    
    @classmethod
    @abstractmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create message from dictionary."""
    
    def with_metadata(self, **kwargs: Any) -> "ContractMessage":
        """Create a copy with updated metadata."""
        current_meta = self.metadata.to_dict()
        current_meta.update(kwargs)
        
        # Remove contract_id to generate a new one
        current_meta.pop("contract_id", None)
        
        # Parse timestamp if string
        if isinstance(current_meta.get("timestamp"), str):
            current_meta["timestamp"] = datetime.fromisoformat(current_meta["timestamp"])
            
        new_metadata = ContractMetadata(**current_meta)
        
        # Create a copy of self with new metadata
        import copy
        new_instance = copy.deepcopy(self)
        new_instance.metadata = new_metadata
        return new_instance


@dataclass(frozen=True)
class ContractEvent(ContractMessage):
    """
    Base class for contract events.
    
    Events represent facts that have happened in a module.
    They are immutable and should be named in past tense.
    """
    
    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "data": self._get_data_dict(),
        }
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get event data as dictionary."""
        # Default implementation for dataclasses
        from dataclasses import asdict
        data = asdict(self)
        data.pop("metadata", None)
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create event from dictionary."""
        metadata_data = data.pop("metadata", {})
        
        # Parse timestamp
        if isinstance(metadata_data.get("timestamp"), str):
            metadata_data["timestamp"] = datetime.fromisoformat(metadata_data["timestamp"])
            
        # Parse UUIDs
        if isinstance(metadata_data.get("contract_id"), str):
            metadata_data["contract_id"] = UUID(metadata_data["contract_id"])
            
        metadata = ContractMetadata(**metadata_data)
        
        # Get the actual data
        event_data = data.get("data", data)
        
        # Create instance
        instance = cls(**event_data)
        instance.metadata = metadata
        return instance


@dataclass
class ContractCommand(ContractMessage):
    """
    Base class for contract commands.
    
    Commands represent intentions to change state in a module.
    They are requests that can be accepted or rejected.
    """
    
    def to_dict(self) -> dict[str, Any]:
        """Convert command to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "data": self._get_data_dict(),
        }
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get command data as dictionary."""
        from dataclasses import asdict
        data = asdict(self)
        data.pop("metadata", None)
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create command from dictionary."""
        metadata_data = data.pop("metadata", {})
        
        # Parse timestamp
        if isinstance(metadata_data.get("timestamp"), str):
            metadata_data["timestamp"] = datetime.fromisoformat(metadata_data["timestamp"])
            
        # Parse UUIDs
        if isinstance(metadata_data.get("contract_id"), str):
            metadata_data["contract_id"] = UUID(metadata_data["contract_id"])
            
        metadata = ContractMetadata(**metadata_data)
        
        # Get the actual data
        command_data = data.get("data", data)
        
        # Create instance
        instance = cls(**command_data)
        instance.metadata = metadata
        return instance


@dataclass
class ContractQuery(ContractMessage):
    """
    Base class for contract queries.
    
    Queries represent requests for information from a module.
    They should not change state.
    """
    
    def to_dict(self) -> dict[str, Any]:
        """Convert query to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "data": self._get_data_dict(),
        }
    
    def _get_data_dict(self) -> dict[str, Any]:
        """Get query data as dictionary."""
        from dataclasses import asdict
        data = asdict(self)
        data.pop("metadata", None)
        return data
    
    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create query from dictionary."""
        metadata_data = data.pop("metadata", {})
        
        # Parse timestamp
        if isinstance(metadata_data.get("timestamp"), str):
            metadata_data["timestamp"] = datetime.fromisoformat(metadata_data["timestamp"])
            
        # Parse UUIDs
        if isinstance(metadata_data.get("contract_id"), str):
            metadata_data["contract_id"] = UUID(metadata_data["contract_id"])
            
        metadata = ContractMetadata(**metadata_data)
        
        # Get the actual data
        query_data = data.get("data", data)
        
        # Create instance
        instance = cls(**query_data)
        instance.metadata = metadata
        return instance


class ModuleContract(ABC):
    """
    Base class for module contracts.
    
    Each module should have one contract that defines its public API
    including events, commands, and queries.
    """
    
    @property
    @abstractmethod
    def module_name(self) -> str:
        """Get the module name."""
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Get the contract version."""
    
    @abstractmethod
    def get_events(self) -> dict[str, type[ContractEvent]]:
        """Get all events exposed by this module."""
    
    @abstractmethod
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        """Get all commands accepted by this module."""
    
    @abstractmethod
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        """Get all queries supported by this module."""
    
    def validate_event(self, event: ContractEvent) -> bool:
        """Validate that an event belongs to this contract."""
        event_type = type(event)
        return event_type in self.get_events().values()
    
    def validate_command(self, command: ContractCommand) -> bool:
        """Validate that a command belongs to this contract."""
        command_type = type(command)
        return command_type in self.get_commands().values()
    
    def validate_query(self, query: ContractQuery) -> bool:
        """Validate that a query belongs to this contract."""
        query_type = type(query)
        return query_type in self.get_queries().values()