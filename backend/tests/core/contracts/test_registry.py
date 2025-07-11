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
from app.core.contracts.registry import ContractRegistry, get_contract_registry


# Test implementations
@dataclass(frozen=True)
class ModuleAEvent(ContractEvent):
    """Event from Module A."""
    data: str


@dataclass
class ModuleACommand(ContractCommand):
    """Command for Module A."""
    value: int


@dataclass
class ModuleAQuery(ContractQuery):
    """Query for Module A."""
    id: str


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
        return {"ModuleAQuery": ModuleAQuery}


@dataclass(frozen=True)
class ModuleBEvent(ContractEvent):
    """Event from Module B."""
    info: str


class ModuleBContract(ModuleContract):
    """Contract for Module B."""
    
    @property
    def module_name(self) -> str:
        return "module_b"
    
    @property
    def version(self) -> str:
        return "2.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {"ModuleBEvent": ModuleBEvent}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {}


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
    
    def test_get_contract(self):
        """Test getting contracts by module name."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        contract_b = ModuleBContract()
        
        registry.register_contract(contract_a)
        registry.register_contract(contract_b)
        
        assert registry.get_contract("module_a") == contract_a
        assert registry.get_contract("module_b") == contract_b
        assert registry.get_contract("module_c") is None
    
    def test_get_all_contracts(self):
        """Test getting all registered contracts."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        contract_b = ModuleBContract()
        
        registry.register_contract(contract_a)
        registry.register_contract(contract_b)
        
        contracts = registry.get_all_contracts()
        
        assert len(contracts) == 2
        assert "module_a" in contracts
        assert "module_b" in contracts
        assert contracts["module_a"] == contract_a
        assert contracts["module_b"] == contract_b
    
    def test_find_event_contract(self):
        """Test finding contract that owns an event type."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        contract_b = ModuleBContract()
        
        registry.register_contract(contract_a)
        registry.register_contract(contract_b)
        
        # Find contract for ModuleAEvent
        found_contract = registry.find_event_contract(ModuleAEvent)
        assert found_contract == contract_a
        
        # Find contract for ModuleBEvent
        found_contract = registry.find_event_contract(ModuleBEvent)
        assert found_contract == contract_b
        
        # Try to find contract for unknown event
        @dataclass(frozen=True)
        class UnknownEvent(ContractEvent):
            data: str
        
        found_contract = registry.find_event_contract(UnknownEvent)
        assert found_contract is None
    
    def test_find_command_contract(self):
        """Test finding contract that owns a command type."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        contract_b = ModuleBContract()
        
        registry.register_contract(contract_a)
        registry.register_contract(contract_b)
        
        # Find contract for ModuleACommand
        found_contract = registry.find_command_contract(ModuleACommand)
        assert found_contract == contract_a
        
        # Module B has no commands
        @dataclass
        class UnknownCommand(ContractCommand):
            data: str
        
        found_contract = registry.find_command_contract(UnknownCommand)
        assert found_contract is None
    
    def test_find_query_contract(self):
        """Test finding contract that owns a query type."""
        registry = ContractRegistry()
        contract_a = ModuleAContract()
        
        registry.register_contract(contract_a)
        
        # Find contract for ModuleAQuery
        found_contract = registry.find_query_contract(ModuleAQuery)
        assert found_contract == contract_a
        
        # Try unknown query
        @dataclass
        class UnknownQuery(ContractQuery):
            data: str
        
        found_contract = registry.find_query_contract(UnknownQuery)
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
        contract_b = ModuleBContract()
        
        registry.register_contract(contract_a)
        registry.register_contract(contract_b)
        
        assert len(registry.get_all_contracts()) == 2
        
        registry.clear()
        
        assert len(registry.get_all_contracts()) == 0
        assert registry.get_contract("module_a") is None
        assert registry.get_contract("module_b") is None


class TestGlobalRegistry:
    """Test global registry functionality."""
    
    def test_get_contract_registry(self):
        """Test getting the global registry instance."""
        registry1 = get_contract_registry()
        registry2 = get_contract_registry()
        
        # Should be the same instance
        assert registry1 is registry2
    
    def test_global_registry_persistence(self):
        """Test that global registry persists data."""
        registry = get_contract_registry()
        
        # Clear any existing data
        registry.clear()
        
        # Register a contract
        contract = ModuleAContract()
        registry.register_contract(contract)
        
        # Get registry again and check contract is still there
        new_registry = get_contract_registry()
        assert new_registry.get_contract("module_a") == contract