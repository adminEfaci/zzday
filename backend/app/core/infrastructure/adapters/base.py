"""
Base Internal Module Adapter

Provides the foundation for modules to communicate with each other
through contracts without direct dependencies.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, TypeVar

from app.core.contracts import (
    ContractCommand,
    ContractEvent,
    ContractQuery,
    ContractRegistry,
    ModuleContract,
    get_contract_registry,
)
from app.core.events import IEventBus
from app.core.logging import get_logger

T = TypeVar("T")
logger = get_logger(__name__)


class InternalModuleAdapter(ABC):
    """
    Base class for internal module adapters.
    
    Each module should have adapters for other modules it needs to
    communicate with. These adapters use contracts to ensure proper
    boundaries.
    """
    
    def __init__(
        self,
        event_bus: IEventBus,
        source_module: str,
        target_module: str,
        contract_registry: ContractRegistry | None = None
    ):
        """
        Initialize the adapter.
        
        Args:
            event_bus: The event bus for publishing/subscribing
            source_module: The name of the module using this adapter
            target_module: The name of the module being adapted
            contract_registry: Optional contract registry (uses global if not provided)
        """
        self._event_bus = event_bus
        self._source_module = source_module
        self._target_module = target_module
        self._contract_registry = contract_registry or get_contract_registry()
        self._target_contract: ModuleContract | None = None
        self._event_handlers: dict[type[ContractEvent], Callable] = {}
        self._initialized = False
        
    async def initialize(self) -> None:
        """
        Initialize the adapter.
        
        This should be called during application startup to ensure
        the target module's contract is available.
        """
        if self._initialized:
            return
            
        # Get the target module's contract
        self._target_contract = self._contract_registry.get_contract(self._target_module)
        if not self._target_contract:
            raise RuntimeError(
                f"Contract for module '{self._target_module}' not found. "
                f"Ensure the module is registered before initializing adapters."
            )
        
        # Subscribe to events
        await self._subscribe_to_events()
        
        self._initialized = True
        logger.info(
            f"Initialized adapter: {self._source_module} → {self._target_module}"
        )
    
    async def _subscribe_to_events(self) -> None:
        """Subscribe to contract events from the target module."""
        if not self._target_contract:
            return
            
        # Subscribe to all events we have handlers for
        for event_type, handler in self._event_handlers.items():
            # Only subscribe if the event belongs to our target module
            if event_type in self._target_contract.get_events().values():
                self._event_bus.subscribe(event_type, handler)
                logger.debug(
                    f"Subscribed to {event_type.__name__} from {self._target_module}"
                )
    
    def register_event_handler(
        self,
        event_type: type[ContractEvent],
        handler: Callable[[ContractEvent], Any]
    ) -> None:
        """
        Register a handler for a contract event.
        
        Args:
            event_type: The contract event type to handle
            handler: The handler function (sync or async)
        """
        self._event_handlers[event_type] = handler
        
        # If already initialized, subscribe immediately
        if self._initialized and self._target_contract:
            if event_type in self._target_contract.get_events().values():
                self._event_bus.subscribe(event_type, handler)
    
    async def send_command(self, command: ContractCommand) -> Any:
        """
        Send a command to the target module.
        
        Args:
            command: The contract command to send
            
        Returns:
            The command result
            
        Raises:
            ValueError: If command doesn't belong to target module
        """
        if not self._initialized:
            await self.initialize()
            
        # Validate command belongs to target module
        if not self._target_contract or not self._target_contract.validate_command(command):
            raise ValueError(
                f"Command {type(command).__name__} does not belong to {self._target_module}"
            )
        
        # Set metadata
        command_with_meta = command.with_metadata(
            source_module=self._source_module,
            target_module=self._target_module
        )
        
        # Cast back to ContractCommand type
        command = command_with_meta  # type: ignore
        
        # Send via command bus or direct call
        # This is where you'd integrate with your command handling infrastructure
        return await self._send_command_internal(command)
    
    async def send_query(self, query: ContractQuery) -> Any:
        """
        Send a query to the target module.
        
        Args:
            query: The contract query to send
            
        Returns:
            The query result
            
        Raises:
            ValueError: If query doesn't belong to target module
        """
        if not self._initialized:
            await self.initialize()
            
        # Validate query belongs to target module
        if not self._target_contract or not self._target_contract.validate_query(query):
            raise ValueError(
                f"Query {type(query).__name__} does not belong to {self._target_module}"
            )
        
        # Set metadata
        query_with_meta = query.with_metadata(
            source_module=self._source_module,
            target_module=self._target_module
        )
        
        # Cast back to ContractQuery type
        query = query_with_meta  # type: ignore
        
        # Send via query bus or direct call
        return await self._send_query_internal(query)
    
    @abstractmethod
    async def _send_command_internal(self, command: ContractCommand) -> Any:
        """
        Internal method to send commands.
        
        Subclasses should implement this to integrate with their
        command handling infrastructure.
        """
    
    @abstractmethod
    async def _send_query_internal(self, query: ContractQuery) -> Any:
        """
        Internal method to send queries.
        
        Subclasses should implement this to integrate with their
        query handling infrastructure.
        """
    
    def get_target_contract(self) -> ModuleContract | None:
        """Get the target module's contract."""
        return self._target_contract
    
    async def close(self) -> None:
        """Clean up adapter resources."""
        # Unsubscribe from events
        if self._initialized and self._target_contract:
            for event_type, handler in self._event_handlers.items():
                if event_type in self._target_contract.get_events().values():
                    self._event_bus.unsubscribe(event_type, handler)
        
        self._initialized = False
        logger.info(
            f"Closed adapter: {self._source_module} → {self._target_module}"
        )