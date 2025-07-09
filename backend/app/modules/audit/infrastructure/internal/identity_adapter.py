"""
Identity Module Adapter for Audit Module

This adapter handles all communication with the Identity module
through its contract, replacing direct domain imports.
"""

from typing import Any
from uuid import UUID

from app.core.contracts import ContractCommand, ContractQuery
from app.core.events import IEventBus
from app.core.infrastructure.adapters import InternalModuleAdapter
from app.core.logging import get_logger
from app.modules.identity.application.contracts.identity_contract import (
    GetUserByIdQuery,
    LoginFailedEvent,
    MFADisabledEvent,
    MFAEnabledEvent,
    PasswordChangedEvent,
    RoleAssignedEvent,
    RoleRevokedEvent,
    SecurityAlertEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
    UserDeletedEvent,
    UserLockedOutEvent,
    UserLoggedInEvent,
    UserRegisteredEvent,
)

logger = get_logger(__name__)


class IdentityAdapter(InternalModuleAdapter):
    """
    Adapter for Audit module to communicate with Identity module.
    
    This adapter subscribes to Identity events and provides methods
    to query Identity data, all through the contract interface.
    """
    
    def __init__(self, event_bus: IEventBus):
        """
        Initialize the Identity adapter.
        
        Args:
            event_bus: The event bus for communication
        """
        super().__init__(
            event_bus=event_bus,
            source_module="audit",
            target_module="identity"
        )
        self._audit_service = None  # Will be injected
        self._register_event_handlers()
    
    def set_audit_service(self, audit_service: Any) -> None:
        """
        Set the audit service for handling events.
        
        This uses setter injection to avoid circular dependencies.
        """
        self._audit_service = audit_service
    
    def _register_event_handlers(self) -> None:
        """Register handlers for Identity events."""
        # Login events
        self.register_event_handler(
            UserLoggedInEvent,
            self._handle_user_logged_in
        )
        self.register_event_handler(
            LoginFailedEvent,
            self._handle_login_failed
        )
        self.register_event_handler(
            UserLockedOutEvent,
            self._handle_user_locked_out
        )
        
        # User lifecycle events
        self.register_event_handler(
            UserRegisteredEvent,
            self._handle_user_registered
        )
        self.register_event_handler(
            UserActivatedEvent,
            self._handle_user_activated
        )
        self.register_event_handler(
            UserDeactivatedEvent,
            self._handle_user_deactivated
        )
        self.register_event_handler(
            UserDeletedEvent,
            self._handle_user_deleted
        )
        
        # Security events
        self.register_event_handler(
            PasswordChangedEvent,
            self._handle_password_changed
        )
        self.register_event_handler(
            MFAEnabledEvent,
            self._handle_mfa_enabled
        )
        self.register_event_handler(
            MFADisabledEvent,
            self._handle_mfa_disabled
        )
        
        # Authorization events
        self.register_event_handler(
            RoleAssignedEvent,
            self._handle_role_assigned
        )
        self.register_event_handler(
            RoleRevokedEvent,
            self._handle_role_revoked
        )
        
        # Security alerts
        self.register_event_handler(
            SecurityAlertEvent,
            self._handle_security_alert
        )
    
    async def _handle_user_logged_in(self, event: UserLoggedInEvent) -> None:
        """Handle user login event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserLoggedInEvent")
            return
        
        await self._audit_service.audit_user_login(
            user_id=event.user_id,
            session_id=event.session_id,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            mfa_used=event.mfa_used,
            timestamp=event.logged_in_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_login_failed(self, event: LoginFailedEvent) -> None:
        """Handle failed login event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle LoginFailedEvent")
            return
        
        await self._audit_service.audit_login_failure(
            email=event.email,
            ip_address=event.ip_address,
            reason=event.reason,
            attempt_number=event.attempt_number,
            timestamp=event.failed_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_user_locked_out(self, event: UserLockedOutEvent) -> None:
        """Handle user lockout event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserLockedOutEvent")
            return
        
        await self._audit_service.audit_user_lockout(
            user_id=event.user_id,
            locked_until=event.locked_until,
            reason=event.reason,
            timestamp=event.locked_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_user_registered(self, event: UserRegisteredEvent) -> None:
        """Handle user registration event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserRegisteredEvent")
            return
        
        await self._audit_service.audit_user_registration(
            user_id=event.user_id,
            email=event.email,
            username=event.username,
            timestamp=event.registered_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_user_activated(self, event: UserActivatedEvent) -> None:
        """Handle user activation event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserActivatedEvent")
            return
        
        await self._audit_service.audit_user_activation(
            user_id=event.user_id,
            timestamp=event.activated_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_user_deactivated(self, event: UserDeactivatedEvent) -> None:
        """Handle user deactivation event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserDeactivatedEvent")
            return
        
        await self._audit_service.audit_user_deactivation(
            user_id=event.user_id,
            reason=event.reason,
            deactivated_by=event.deactivated_by,
            timestamp=event.deactivated_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_user_deleted(self, event: UserDeletedEvent) -> None:
        """Handle user deletion event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle UserDeletedEvent")
            return
        
        await self._audit_service.audit_user_deletion(
            user_id=event.user_id,
            deletion_type=event.deletion_type,
            timestamp=event.deleted_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_password_changed(self, event: PasswordChangedEvent) -> None:
        """Handle password change event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle PasswordChangedEvent")
            return
        
        await self._audit_service.audit_password_change(
            user_id=event.user_id,
            change_method=event.change_method,
            timestamp=event.changed_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_mfa_enabled(self, event: MFAEnabledEvent) -> None:
        """Handle MFA enabled event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle MFAEnabledEvent")
            return
        
        await self._audit_service.audit_mfa_enabled(
            user_id=event.user_id,
            mfa_method=event.mfa_method,
            timestamp=event.enabled_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_mfa_disabled(self, event: MFADisabledEvent) -> None:
        """Handle MFA disabled event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle MFADisabledEvent")
            return
        
        await self._audit_service.audit_mfa_disabled(
            user_id=event.user_id,
            mfa_method=event.mfa_method,
            reason=event.reason,
            timestamp=event.disabled_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_role_assigned(self, event: RoleAssignedEvent) -> None:
        """Handle role assignment event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle RoleAssignedEvent")
            return
        
        await self._audit_service.audit_role_assignment(
            user_id=event.user_id,
            role_id=event.role_id,
            role_name=event.role_name,
            assigned_by=event.assigned_by,
            timestamp=event.assigned_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_role_revoked(self, event: RoleRevokedEvent) -> None:
        """Handle role revocation event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle RoleRevokedEvent")
            return
        
        await self._audit_service.audit_role_revocation(
            user_id=event.user_id,
            role_id=event.role_id,
            role_name=event.role_name,
            revoked_by=event.revoked_by,
            timestamp=event.revoked_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def _handle_security_alert(self, event: SecurityAlertEvent) -> None:
        """Handle security alert event."""
        if not self._audit_service:
            logger.warning("Audit service not set, cannot handle SecurityAlertEvent")
            return
        
        await self._audit_service.audit_security_alert(
            user_id=event.user_id,
            alert_type=event.alert_type,
            severity=event.severity,
            details=event.details,
            timestamp=event.triggered_at,
            correlation_id=event.metadata.correlation_id,
        )
    
    async def get_user_info(self, user_id: UUID) -> dict | None:
        """
        Get basic user information from Identity module.
        
        Args:
            user_id: The user ID to query
            
        Returns:
            User information or None if not found
        """
        query = GetUserByIdQuery(user_id=user_id)
        
        try:
            result = await self.send_query(query)
            return result
        except Exception as e:
            logger.error(f"Failed to get user info for {user_id}: {e}")
            return None
    
    async def _send_command_internal(self, command: ContractCommand) -> Any:
        """
        Send command to Identity module.
        
        Currently not implemented as Audit module doesn't send
        commands to Identity module.
        """
        raise NotImplementedError("Audit module does not send commands to Identity")
    
    async def _send_query_internal(self, query: ContractQuery) -> Any:
        """
        Send query to Identity module.
        
        This would integrate with your query bus or direct service calls.
        For now, returns mock data for demonstration.
        """
        # In a real implementation, this would:
        # 1. Use a query bus to route the query
        # 2. Or make a direct service call through dependency injection
        # 3. Or use an HTTP/gRPC client for remote calls
        
        if isinstance(query, GetUserByIdQuery):
            # Mock response for demonstration
            return {
                "user_id": str(query.user_id),
                "email": "user@example.com",
                "username": "user123",
                "is_active": True,
            }
        
        raise NotImplementedError(f"Query type {type(query).__name__} not implemented")