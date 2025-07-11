"""
Tests for Contract Registry

Tests the contract registry that manages module contracts
and enables contract discovery.
"""

from dataclasses import dataclass

import pytest

from app.core.contracts.base import (
    ContractCommand,
    ContractEvent,
    ContractQuery,
    ModuleContract,
)
from app.core.contracts.registry import ContractRegistry


# Test implementations
@dataclass(frozen=True)
class ModuleAEvent(ContractEvent):
    """Event from Module A."""
    data: str
    
    def _get_data_dict(self) -> dict:
        return {"data": self.data}
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(data=data["data"])


@dataclass
class ModuleACommand(ContractCommand):
    """Command for Module A."""
    value: int
    
    def _get_data_dict(self) -> dict:
        return {"value": self.value}
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(value=data["value"])


class ModuleAContract(ModuleContract):
    """Contract for Module A."""
    
    @property
    def module_name(self) -> str:
        return "module_a"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {"ModuleAEvent": ModuleAEvent}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {"ModuleACommand": ModuleACommand}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {}


@pytest.mark.unit
class TestContractRegistry:
    """Test ContractRegistry functionality."""
    
    def test_create_registry(self):
        """Test creating a new registry."""
        registry = ContractRegistry()
        
        assert registry is not None
        assert len(registry.get_all_contracts()) == 0
    
    def test_register_contract(self):
        """Test registering a module contract."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        
        registry.register_contract(contract_a)
        
        assert len(registry.get_all_contracts()) == 1
        assert registry.get_contract("module_a") == contract_a
    
    def test_register_duplicate_contract(self):
        """Test registering duplicate contracts."""
        registry = ContractRegistry()
        contract_a1 = ModuleAContract()
        contract_a2 = ModuleAContract()
        
        registry.register_contract(contract_a1)
        
        with pytest.raises(ValueError, match="already registered"):
            registry.register_contract(contract_a2)
    
    def test_find_event_contract(self):
        """Test finding contract that owns an event type."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        
        registry.register_contract(contract_a)
        
        # Find contract for ModuleAEvent
        found_contract = registry.find_event_contract(ModuleAEvent)
        assert found_contract == contract_a
        
        # Try to find contract for unknown event
        @dataclass(frozen=True)
        class UnknownEvent(ContractEvent):
            data: str
            
            def _get_data_dict(self) -> dict:
                return {"data": self.data}
            
            @classmethod
            def from_dict(cls, data: dict):
                return cls(data=data["data"])
        
        found_contract = registry.find_event_contract(UnknownEvent)
        assert found_contract is None
    
    def test_is_registered(self):
        """Test checking if a module is registered."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        
        assert registry.is_registered("module_a") is False
        
        registry.register_contract(contract_a)
        
        assert registry.is_registered("module_a") is True
        assert registry.is_registered("module_b") is False
    
    def test_clear_registry(self):
        """Test clearing the registry."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        
        registry.register_contract(contract_a)
        
        assert len(registry.get_all_contracts()) == 1
        
        registry.clear()
        
        assert len(registry.get_all_contracts()) == 0
        assert registry.get_contract("module_a") is None