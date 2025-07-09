"""
Integration Tests for Contract System

Tests the complete contract system including registry,
adapters, and event translation working together.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest

from app.core.contracts import (
    ContractCommand,
    ContractEvent,
    ContractQuery,
    ContractRegistry,
    ModuleContract,
)
from app.core.events import EventBus
from app.core.events.types import DomainEvent
from app.core.infrastructure.adapters import EventTranslator, InternalModuleAdapter


# Identity Module Contract and Events
@dataclass(frozen=True)
class UserRegisteredEvent(ContractEvent):
    """User registered contract event."""
    user_id: UUID
    email: str
    username: str
    registered_at: datetime


@dataclass
class RegisterUserCommand(ContractCommand):
    """Register user command."""
    email: str
    username: str
    password: str


@dataclass
class GetUserByIdQuery(ContractQuery):
    """Get user by ID query."""
    user_id: UUID


class IdentityContract(ModuleContract):
    """Identity module contract."""
    
    @property
    def module_name(self) -> str:
        return "identity"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {"UserRegistered": UserRegisteredEvent}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {"RegisterUser": RegisterUserCommand}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {"GetUserById": GetUserByIdQuery}


# Audit Module Contract
@dataclass
class CreateAuditLogCommand(ContractCommand):
    """Create audit log command."""
    action: str
    user_id: UUID
    details: dict[str, Any]


class AuditContract(ModuleContract):
    """Audit module contract."""
    
    @property
    def module_name(self) -> str:
        return "audit"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> dict[str, type[ContractEvent]]:
        return {}
    
    def get_commands(self) -> dict[str, type[ContractCommand]]:
        return {"CreateAuditLog": CreateAuditLogCommand}
    
    def get_queries(self) -> dict[str, type[ContractQuery]]:
        return {}


# Domain Events
@dataclass
class UserRegisteredDomainEvent(DomainEvent):
    """User registered domain event."""
    user_id: UUID
    email: str
    username: str
    registered_at: datetime
    
    @property
    def aggregate_id(self) -> str:
        return str(self.user_id)


# Concrete Implementations
class IdentityEventTranslator(EventTranslator):
    """Event translator for Identity module."""
    
    def _initialize_mappings(self) -> None:
        self.register_mapping(
            UserRegisteredDomainEvent,
            UserRegisteredEvent
        )
    
    def _extract_contract_data(
        self,
        domain_event: DomainEvent,
        contract_type: type[ContractEvent]
    ) -> dict[str, Any]:
        if isinstance(domain_event, UserRegisteredDomainEvent):
            return {
                "user_id": domain_event.user_id,
                "email": domain_event.email,
                "username": domain_event.username,
                "registered_at": domain_event.registered_at,
            }
        raise ValueError(f"Unknown domain event: {type(domain_event)}")
    
    def _extract_domain_data(
        self,
        contract_event: ContractEvent,
        domain_type: type[DomainEvent]
    ) -> dict[str, Any]:
        if isinstance(contract_event, UserRegisteredEvent):
            return {
                "user_id": contract_event.user_id,
                "email": contract_event.email,
                "username": contract_event.username,
                "registered_at": contract_event.registered_at,
            }
        raise ValueError(f"Unknown contract event: {type(contract_event)}")


class AuditIdentityAdapter(InternalModuleAdapter):
    """Adapter for Audit module to communicate with Identity."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit_service = None
        self._setup_handlers()
    
    def set_audit_service(self, audit_service):
        """Set the audit service."""
        self.audit_service = audit_service
    
    def _setup_handlers(self):
        """Set up event handlers."""
        self.register_event_handler(
            UserRegisteredEvent,
            self._handle_user_registered
        )
    
    async def _handle_user_registered(self, event: UserRegisteredEvent):
        """Handle user registered event."""
        if self.audit_service:
            await self.audit_service.log_user_registration(
                user_id=event.user_id,
                email=event.email,
                username=event.username,
                timestamp=event.registered_at,
            )
    
    async def _send_command_internal(self, command: ContractCommand) -> Any:
        """Send command to Identity module."""
        # In real implementation, this would use command bus
        if isinstance(command, RegisterUserCommand):
            return {
                "user_id": uuid4(),
                "status": "success"
            }
        raise NotImplementedError(f"Command {type(command)} not implemented")
    
    async def _send_query_internal(self, query: ContractQuery) -> Any:
        """Send query to Identity module."""
        # In real implementation, this would use query bus
        if isinstance(query, GetUserByIdQuery):
            return {
                "user_id": str(query.user_id),
                "email": "test@example.com",
                "username": "testuser",
                "is_active": True,
            }
        raise NotImplementedError(f"Query {type(query)} not implemented")


class TestContractSystemIntegration:
    """Test the complete contract system integration."""
    
    @pytest.fixture
    def event_bus(self):
        """Create event bus."""
        return EventBus()
    
    @pytest.fixture
    def registry(self):
        """Create and populate contract registry."""
        registry = ContractRegistry()
        registry.clear()  # Clear any existing contracts
        
        # Register contracts
        registry.register_contract(IdentityContract())
        registry.register_contract(AuditContract())
        
        return registry
    
    @pytest.fixture
    def audit_service(self):
        """Create mock audit service."""
        service = Mock()
        service.log_user_registration = AsyncMock()
        return service
    
    @pytest.fixture
    async def adapter(self, event_bus, registry, audit_service):
        """Create and initialize adapter."""
        adapter = AuditIdentityAdapter(
            event_bus=event_bus,
            source_module="audit",
            target_module="identity",
            contract_registry=registry,
        )
        adapter.set_audit_service(audit_service)
        await adapter.initialize()
        return adapter
    
    @pytest.mark.asyncio
    async def test_contract_registry_integration(self, registry):
        """Test contract registry functionality."""
        # Verify contracts are registered
        assert registry.is_registered("identity")
        assert registry.is_registered("audit")
        
        # Find contracts by event/command/query types
        assert registry.find_event_contract(UserRegisteredEvent).module_name == "identity"
        assert registry.find_command_contract(RegisterUserCommand).module_name == "identity"
        assert registry.find_query_contract(GetUserByIdQuery).module_name == "identity"
        assert registry.find_command_contract(CreateAuditLogCommand).module_name == "audit"
    
    @pytest.mark.asyncio
    async def test_adapter_event_subscription(self, adapter, audit_service, event_bus):
        """Test adapter subscribing to events."""
        # Publish a UserRegistered event
        event = UserRegisteredEvent(
            user_id=uuid4(),
            email="newuser@example.com",
            username="newuser",
            registered_at=datetime.utcnow(),
        )
        
        await event_bus.publish(event)
        
        # Verify audit service was called
        audit_service.log_user_registration.assert_called_once()
        call_args = audit_service.log_user_registration.call_args[1]
        assert call_args["user_id"] == event.user_id
        assert call_args["email"] == event.email
        assert call_args["username"] == event.username
    
    @pytest.mark.asyncio
    async def test_adapter_send_query(self, adapter):
        """Test adapter sending queries."""
        user_id = uuid4()
        query = GetUserByIdQuery(user_id=user_id)
        
        result = await adapter.send_query(query)
        
        assert result is not None
        assert result["user_id"] == str(user_id)
        assert result["email"] == "test@example.com"
        assert result["username"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_adapter_send_command(self, adapter):
        """Test adapter sending commands."""
        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="secure123",
        )
        
        result = await adapter.send_command(command)
        
        assert result is not None
        assert result["status"] == "success"
        assert "user_id" in result
    
    @pytest.mark.asyncio
    async def test_event_translation_integration(self, event_bus):
        """Test event translation between domain and contract events."""
        translator = IdentityEventTranslator(source_module="identity")
        
        # Create domain event
        user_id = uuid4()
        domain_event = UserRegisteredDomainEvent(
            user_id=user_id,
            email="test@example.com",
            username="testuser",
            registered_at=datetime.utcnow(),
        )
        
        # Translate to contract event
        contract_event = translator.translate_to_contract(domain_event)
        
        assert contract_event is not None
        assert isinstance(contract_event, UserRegisteredEvent)
        assert contract_event.user_id == user_id
        assert contract_event.metadata.source_module == "identity"
        
        # Translate back to domain event
        domain_event_2 = translator.translate_to_domain(contract_event)
        
        assert domain_event_2 is not None
        assert isinstance(domain_event_2, UserRegisteredDomainEvent)
        assert domain_event_2.user_id == user_id
    
    @pytest.mark.asyncio
    async def test_complete_flow(self, adapter, audit_service, event_bus):
        """Test complete flow from command to event handling."""
        # 1. Send command to register user
        command = RegisterUserCommand(
            email="complete@example.com",
            username="completeuser",
            password="secure123",
        )
        
        result = await adapter.send_command(command)
        assert result["status"] == "success"
        
        # 2. Simulate Identity module publishing event
        event = UserRegisteredEvent(
            user_id=uuid4(),
            email=command.email,
            username=command.username,
            registered_at=datetime.utcnow(),
        )
        
        await event_bus.publish(event)
        
        # 3. Verify Audit module handled the event
        audit_service.log_user_registration.assert_called_once()
        
        # 4. Query user information
        query = GetUserByIdQuery(user_id=event.user_id)
        user_info = await adapter.send_query(query)
        
        assert user_info is not None
        assert user_info["user_id"] == str(event.user_id)
    
    @pytest.mark.asyncio
    async def test_module_isolation(self, registry):
        """Test that modules are properly isolated."""
        identity_contract = registry.get_contract("identity")
        audit_contract = registry.get_contract("audit")
        
        # Verify contracts don't share event/command/query types
        identity_events = set(identity_contract.get_events().values())
        audit_events = set(audit_contract.get_events().values())
        assert identity_events.isdisjoint(audit_events)
        
        identity_commands = set(identity_contract.get_commands().values())
        audit_commands = set(audit_contract.get_commands().values())
        assert identity_commands.isdisjoint(audit_commands)
    
    @pytest.mark.asyncio
    async def test_adapter_lifecycle(self, event_bus, registry, audit_service):
        """Test adapter initialization and cleanup."""
        adapter = AuditIdentityAdapter(
            event_bus=event_bus,
            source_module="audit",
            target_module="identity",
            contract_registry=registry,
        )
        
        # Before initialization
        assert adapter._initialized is False
        assert adapter.get_target_contract() is None
        
        # Initialize
        await adapter.initialize()
        assert adapter._initialized is True
        assert adapter.get_target_contract() is not None
        
        # Close
        await adapter.close()
        assert adapter._initialized is False