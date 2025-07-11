"""
Contract Registry for Module Communication

Manages registration and lookup of module contracts,
ensuring proper module boundaries and versioning.
"""

import threading

from app.core.errors import ValidationError

from .base import ContractCommand, ContractEvent, ContractQuery, ModuleContract


class ContractRegistry:
    """
    Central registry for all module contracts.
    
    This registry ensures that modules can discover each other's
    contracts without direct dependencies.
    """
    
    def __init__(self) -> None:
        self._contracts: dict[str, ModuleContract] = {}
        self._lock = threading.RLock()
    
    def register_contract(self, contract: ModuleContract) -> None:
        """
        Register a module contract.
        
        Args:
            contract: The module contract to register
            
        Raises:
            ValidationError: If contract is invalid or already registered
        """
        if not isinstance(contract, ModuleContract):
            raise ValidationError(
                f"Contract must be instance of ModuleContract, got {type(contract)}"
            )
        
        module_name = contract.module_name
        
        with self._lock:
            if module_name in self._contracts:
                existing = self._contracts[module_name]
                if existing.version != contract.version:
                    raise ValidationError(
                        f"Module {module_name} already registered with version "
                        f"{existing.version}, cannot register version {contract.version}"
                    )
                return  # Same version already registered
            
            self._contracts[module_name] = contract
    
    def get_contract(self, module_name: str) -> ModuleContract | None:
        """
        Get a module contract by name.
        
        Args:
            module_name: Name of the module
            
        Returns:
            The module contract or None if not found
        """
        with self._lock:
            return self._contracts.get(module_name)
    
    def get_all_contracts(self) -> dict[str, ModuleContract]:
        """Get all registered contracts."""
        with self._lock:
            return self._contracts.copy()
    
    def find_event_contract(self, event_type: type[ContractEvent]) -> ModuleContract | None:
        """
        Find which contract an event belongs to.
        
        Args:
            event_type: The event type to find
            
        Returns:
            The module contract that defines this event
        """
        with self._lock:
            for contract in self._contracts.values():
                if event_type in contract.get_events().values():
                    return contract
        return None
    
    def find_command_contract(self, command_type: type[ContractCommand]) -> ModuleContract | None:
        """
        Find which contract a command belongs to.
        
        Args:
            command_type: The command type to find
            
        Returns:
            The module contract that defines this command
        """
        with self._lock:
            for contract in self._contracts.values():
                if command_type in contract.get_commands().values():
                    return contract
        return None
    
    def find_query_contract(self, query_type: type[ContractQuery]) -> ModuleContract | None:
        """
        Find which contract a query belongs to.
        
        Args:
            query_type: The query type to find
            
        Returns:
            The module contract that defines this query
        """
        with self._lock:
            for contract in self._contracts.values():
                if query_type in contract.get_queries().values():
                    return contract
        return None
    
    def clear(self) -> None:
        """Clear all registered contracts (mainly for testing)."""
        with self._lock:
            self._contracts.clear()


# Global registry instance
_registry = ContractRegistry()


def get_contract_registry() -> ContractRegistry:
    """Get the global contract registry."""
    return _registry