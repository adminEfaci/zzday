"""
Tests for Event Translator

Tests the event translation system that converts between
domain events and contract events.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.core.contracts import ContractEvent
from app.core.events.types import DomainEvent
from app.core.infrastructure.adapters import EventTranslator


# Test domain events
@dataclass
class UserCreatedDomainEvent(DomainEvent):
    """Domain event for user creation."""
    user_id: UUID
    email: str
    created_at: datetime
    
    @property
    def aggregate_id(self) -> str:
        return str(self.user_id)


@dataclass
class UserUpdatedDomainEvent(DomainEvent):
    """Domain event for user update."""
    user_id: UUID
    field: str
    value: str
    
    @property
    def aggregate_id(self) -> str:
        return str(self.user_id)


# Test contract events
@dataclass(frozen=True)
class UserCreatedContractEvent(ContractEvent):
    """Contract event for user creation."""
    user_id: UUID
    email: str
    created_at: datetime


@dataclass(frozen=True)
class UserUpdatedContractEvent(ContractEvent):
    """Contract event for user update."""
    user_id: UUID
    field: str
    value: str


# Test translator implementation
class TestEventTranslator(EventTranslator):
    """Test event translator implementation."""
    
    def _initialize_mappings(self) -> None:
        """Register test mappings."""
        self.register_mapping(
            UserCreatedDomainEvent,
            UserCreatedContractEvent
        )
        self.register_mapping(
            UserUpdatedDomainEvent,
            UserUpdatedContractEvent
        )
    
    def _extract_contract_data(
        self,
        domain_event: DomainEvent,
        contract_type: type[ContractEvent]
    ) -> dict[str, Any]:
        """Extract data for contract event."""
        if isinstance(domain_event, UserCreatedDomainEvent):
            return {
                "user_id": domain_event.user_id,
                "email": domain_event.email,
                "created_at": domain_event.created_at,
            }
        if isinstance(domain_event, UserUpdatedDomainEvent):
            return {
                "user_id": domain_event.user_id,
                "field": domain_event.field,
                "value": domain_event.value,
            }
        raise ValueError(f"Unknown domain event type: {type(domain_event)}")
    
    def _extract_domain_data(
        self,
        contract_event: ContractEvent,
        domain_type: type[DomainEvent]
    ) -> dict[str, Any]:
        """Extract data for domain event."""
        if isinstance(contract_event, UserCreatedContractEvent):
            return {
                "user_id": contract_event.user_id,
                "email": contract_event.email,
                "created_at": contract_event.created_at,
            }
        if isinstance(contract_event, UserUpdatedContractEvent):
            return {
                "user_id": contract_event.user_id,
                "field": contract_event.field,
                "value": contract_event.value,
            }
        raise ValueError(f"Unknown contract event type: {type(contract_event)}")


class TestEventTranslatorClass:
    """Test EventTranslator functionality."""
    
    @pytest.fixture
    def translator(self):
        """Create a test translator."""
        return TestEventTranslator(source_module="test_module")
    
    def test_create_translator(self, translator):
        """Test creating a translator."""
        assert translator._source_module == "test_module"
        assert len(translator._domain_to_contract_map) == 2
        assert len(translator._contract_to_domain_map) == 2
    
    def test_register_mapping(self, translator):
        """Test registering new mappings."""
        # Create new event types
        @dataclass
        class NewDomainEvent(DomainEvent):
            data: str
            
            @property
            def aggregate_id(self) -> str:
                return "test"
        
        @dataclass(frozen=True)
        class NewContractEvent(ContractEvent):
            data: str
        
        # Register mapping
        translator.register_mapping(NewDomainEvent, NewContractEvent)
        
        assert translator.get_contract_type(NewDomainEvent) == NewContractEvent
        assert translator.get_domain_type(NewContractEvent) == NewDomainEvent
    
    def test_translate_to_contract(self, translator):
        """Test translating domain event to contract event."""
        user_id = uuid4()
        created_at = datetime.utcnow()
        correlation_id = str(uuid4())
        
        # Create domain event with metadata
        domain_event = UserCreatedDomainEvent(
            user_id=user_id,
            email="test@example.com",
            created_at=created_at,
        )
        domain_event.metadata.correlation_id = correlation_id
        
        # Translate
        contract_event = translator.translate_to_contract(domain_event)
        
        assert contract_event is not None
        assert isinstance(contract_event, UserCreatedContractEvent)
        assert contract_event.user_id == user_id
        assert contract_event.email == "test@example.com"
        assert contract_event.created_at == created_at
        
        # Check metadata
        assert contract_event.metadata.source_module == "test_module"
        assert contract_event.metadata.correlation_id == correlation_id
        assert contract_event.metadata.causation_id == str(domain_event.metadata.event_id)
    
    def test_translate_to_contract_no_mapping(self, translator):
        """Test translating unmapped domain event."""
        @dataclass
        class UnmappedEvent(DomainEvent):
            data: str
            
            @property
            def aggregate_id(self) -> str:
                return "test"
        
        domain_event = UnmappedEvent(data="test")
        
        result = translator.translate_to_contract(domain_event)
        
        assert result is None
    
    def test_translate_to_contract_error(self, translator):
        """Test error handling in translation."""
        # Create a domain event but override extract method to fail
        domain_event = UserCreatedDomainEvent(
            user_id=uuid4(),
            email="test@example.com",
            created_at=datetime.utcnow(),
        )
        
        # Patch the extract method to raise an error
        original_extract = translator._extract_contract_data
        translator._extract_contract_data = lambda *args: (_ for _ in ()).throw(ValueError("Test error"))
        
        result = translator.translate_to_contract(domain_event)
        
        assert result is None
        
        # Restore original method
        translator._extract_contract_data = original_extract
    
    def test_translate_to_domain(self, translator):
        """Test translating contract event to domain event."""
        user_id = uuid4()
        correlation_id = str(uuid4())
        
        # Create contract event
        contract_event = UserUpdatedContractEvent(
            user_id=user_id,
            field="name",
            value="John Doe",
        )
        contract_event = contract_event.with_metadata(
            correlation_id=correlation_id,
            source_module="other_module",
        )
        
        # Translate
        domain_event = translator.translate_to_domain(contract_event)
        
        assert domain_event is not None
        assert isinstance(domain_event, UserUpdatedDomainEvent)
        assert domain_event.user_id == user_id
        assert domain_event.field == "name"
        assert domain_event.value == "John Doe"
        
        # Check correlation ID is preserved
        assert domain_event.metadata.correlation_id == correlation_id
    
    def test_translate_to_domain_no_mapping(self, translator):
        """Test translating unmapped contract event."""
        @dataclass(frozen=True)
        class UnmappedContractEvent(ContractEvent):
            data: str
        
        contract_event = UnmappedContractEvent(data="test")
        
        result = translator.translate_to_domain(contract_event)
        
        assert result is None
    
    def test_can_translate_to_contract(self, translator):
        """Test checking if domain event can be translated."""
        domain_event = UserCreatedDomainEvent(
            user_id=uuid4(),
            email="test@example.com",
            created_at=datetime.utcnow(),
        )
        
        assert translator.can_translate_to_contract(domain_event) is True
        
        @dataclass
        class UnknownEvent(DomainEvent):
            data: str
            
            @property
            def aggregate_id(self) -> str:
                return "test"
        
        unknown_event = UnknownEvent(data="test")
        assert translator.can_translate_to_contract(unknown_event) is False
    
    def test_can_translate_to_domain(self, translator):
        """Test checking if contract event can be translated."""
        contract_event = UserCreatedContractEvent(
            user_id=uuid4(),
            email="test@example.com",
            created_at=datetime.utcnow(),
        )
        
        assert translator.can_translate_to_domain(contract_event) is True
        
        @dataclass(frozen=True)
        class UnknownContractEvent(ContractEvent):
            data: str
        
        unknown_event = UnknownContractEvent(data="test")
        assert translator.can_translate_to_domain(unknown_event) is False
    
    def test_get_contract_type(self, translator):
        """Test getting contract type for domain event."""
        assert translator.get_contract_type(UserCreatedDomainEvent) == UserCreatedContractEvent
        assert translator.get_contract_type(UserUpdatedDomainEvent) == UserUpdatedContractEvent
        
        @dataclass
        class UnknownEvent(DomainEvent):
            data: str
            
            @property
            def aggregate_id(self) -> str:
                return "test"
        
        assert translator.get_contract_type(UnknownEvent) is None
    
    def test_get_domain_type(self, translator):
        """Test getting domain type for contract event."""
        assert translator.get_domain_type(UserCreatedContractEvent) == UserCreatedDomainEvent
        assert translator.get_domain_type(UserUpdatedContractEvent) == UserUpdatedDomainEvent
        
        @dataclass(frozen=True)
        class UnknownContractEvent(ContractEvent):
            data: str
        
        assert translator.get_domain_type(UnknownContractEvent) is None