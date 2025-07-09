"""
Event Translator for Module Boundaries

Translates between domain events and contract events to maintain
proper module boundaries.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Any

from app.core.contracts import ContractEvent
from app.core.events.types import DomainEvent
from app.core.logging import get_logger

T = TypeVar("T", bound=ContractEvent)
D = TypeVar("D", bound=DomainEvent)

logger = get_logger(__name__)


class EventTranslator(ABC):
    """
    Base class for translating between domain and contract events.
    
    Each module should have an event translator that converts its
    internal domain events to contract events before publishing them
    to other modules.
    """
    
    def __init__(self, source_module: str):
        """
        Initialize the translator.
        
        Args:
            source_module: The name of the module owning this translator
        """
        self._source_module = source_module
        self._domain_to_contract_map: dict[type[DomainEvent], type[ContractEvent]] = {}
        self._contract_to_domain_map: dict[type[ContractEvent], type[DomainEvent]] = {}
        self._initialize_mappings()
    
    @abstractmethod
    def _initialize_mappings(self) -> None:
        """
        Initialize event type mappings.
        
        Subclasses should override this to register their mappings.
        """
    
    def register_mapping(
        self,
        domain_event_type: type[DomainEvent],
        contract_event_type: type[ContractEvent]
    ) -> None:
        """
        Register a mapping between domain and contract events.
        
        Args:
            domain_event_type: The domain event type
            contract_event_type: The contract event type
        """
        self._domain_to_contract_map[domain_event_type] = contract_event_type
        self._contract_to_domain_map[contract_event_type] = domain_event_type
    
    def translate_to_contract(
        self,
        domain_event: DomainEvent
    ) -> ContractEvent | None:
        """
        Translate a domain event to a contract event.
        
        Args:
            domain_event: The domain event to translate
            
        Returns:
            The contract event or None if no mapping exists
        """
        event_type = type(domain_event)
        contract_type = self._domain_to_contract_map.get(event_type)
        
        if not contract_type:
            logger.debug(
                f"No contract mapping for domain event {event_type.__name__}"
            )
            return None
        
        try:
            # Extract data from domain event
            event_data = self._extract_contract_data(domain_event, contract_type)
            
            # Create contract event
            contract_event = contract_type(**event_data)
            
            # Set metadata
            contract_event_with_meta = contract_event.with_metadata(
                source_module=self._source_module,
                correlation_id=getattr(domain_event.metadata, "correlation_id", None),
                causation_id=str(domain_event.metadata.event_id),
            )
            
            # Cast back to ContractEvent type
            contract_event = contract_event_with_meta  # type: ignore
            
            return contract_event
            
        except Exception as e:
            logger.error(
                f"Failed to translate domain event {event_type.__name__} "
                f"to contract event {contract_type.__name__}: {e}"
            )
            return None
    
    def translate_to_domain(
        self,
        contract_event: ContractEvent
    ) -> DomainEvent | None:
        """
        Translate a contract event to a domain event.
        
        Args:
            contract_event: The contract event to translate
            
        Returns:
            The domain event or None if no mapping exists
        """
        event_type = type(contract_event)
        domain_type = self._contract_to_domain_map.get(event_type)
        
        if not domain_type:
            logger.debug(
                f"No domain mapping for contract event {event_type.__name__}"
            )
            return None
        
        try:
            # Extract data from contract event
            event_data = self._extract_domain_data(contract_event, domain_type)
            
            # Create domain event
            domain_event = domain_type(**event_data)
            
            # Preserve correlation ID if available
            if hasattr(domain_event, "metadata") and contract_event.metadata.correlation_id:
                domain_event.metadata.correlation_id = contract_event.metadata.correlation_id
            
            return domain_event
            
        except Exception as e:
            logger.error(
                f"Failed to translate contract event {event_type.__name__} "
                f"to domain event {domain_type.__name__}: {e}"
            )
            return None
    
    @abstractmethod
    def _extract_contract_data(
        self,
        domain_event: DomainEvent,
        contract_type: type[ContractEvent]
    ) -> dict[str, Any]:
        """
        Extract data from domain event for contract event creation.
        
        Args:
            domain_event: The source domain event
            contract_type: The target contract event type
            
        Returns:
            Dictionary of data for contract event constructor
        """
    
    @abstractmethod
    def _extract_domain_data(
        self,
        contract_event: ContractEvent,
        domain_type: type[DomainEvent]
    ) -> dict[str, Any]:
        """
        Extract data from contract event for domain event creation.
        
        Args:
            contract_event: The source contract event
            domain_type: The target domain event type
            
        Returns:
            Dictionary of data for domain event constructor
        """
    
    def can_translate_to_contract(self, domain_event: DomainEvent) -> bool:
        """Check if a domain event can be translated to a contract event."""
        return type(domain_event) in self._domain_to_contract_map
    
    def can_translate_to_domain(self, contract_event: ContractEvent) -> bool:
        """Check if a contract event can be translated to a domain event."""
        return type(contract_event) in self._contract_to_domain_map
    
    def get_contract_type(
        self,
        domain_event_type: type[DomainEvent]
    ) -> type[ContractEvent] | None:
        """Get the contract event type for a domain event type."""
        return self._domain_to_contract_map.get(domain_event_type)
    
    def get_domain_type(
        self,
        contract_event_type: type[ContractEvent]
    ) -> type[DomainEvent] | None:
        """Get the domain event type for a contract event type."""
        return self._contract_to_domain_map.get(contract_event_type)