"""
Logout command implementation.

Handles user logout with session cleanup.
"""

from dataclasses import dataclass
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository
from app.modules.identity.application.decorators import (
    audit_action,
    require_auth,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import AuditAction, SessionStatus
from app.modules.identity.domain.events import UserLoggedOut
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    SessionNotFoundError,
)
from app.modules.identity.domain.services import SessionService


@dataclass
class LogoutServiceDependencies:
    """Service dependencies for logout handler."""
    session_repository: ISessionRepository
    session_service: SessionService
    token_blocklist_service: ITokenBlocklistService
    cache_service: ICacheService


@dataclass
class LogoutInfrastructureDependencies:
    """Infrastructure dependencies for logout handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class LogoutCommand(Command[BaseResponse]):
    """Command to logout a user."""
    
    def __init__(
        self,
        user_id: UUID,
        session_id: UUID,
        access_token: str,
        **kwargs
    ):
        self.user_id = user_id
        self.session_id = session_id
        self.access_token = access_token
        self.refresh_token = kwargs.get('refresh_token')
        self.logout_all_sessions = kwargs.get('logout_all_sessions', False)
        self.ip_address = kwargs.get('ip_address')
        self.user_agent = kwargs.get('user_agent')


class LogoutCommandHandler(CommandHandler[LogoutCommand, BaseResponse]):
    """Handler for user logout."""
    
    def __init__(
        self,
        services: LogoutServiceDependencies,
        infrastructure: LogoutInfrastructureDependencies
    ):
        # Service dependencies
        self._session_repository = services.session_repository
        self._session_service = services.session_service
        self._token_blocklist_service = services.token_blocklist_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.LOGOUT,
        resource_type="session",
        resource_id_attr="session_id"
    )
    @require_auth
    async def handle(self, command: LogoutCommand) -> BaseResponse:
        """
        Logout user and cleanup session.
        
        Process:
        1. Validate session exists and belongs to user
        2. Blacklist tokens
        3. Revoke session(s)
        4. Clear caches
        5. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            SessionNotFoundError: If session not found
            InvalidOperationError: If session mismatch
        """
        async with self._unit_of_work:
            # 1. Validate session
            session = await self._session_repository.find_by_id(command.session_id)
            
            if not session:
                raise SessionNotFoundError(f"Session {command.session_id} not found")
            
            if session.user_id != command.user_id:
                raise InvalidOperationError("Session does not belong to user")
            
            if session.status != SessionStatus.ACTIVE:
                # Already logged out
                return BaseResponse(
                    success=True,
                    message="Already logged out"
                )
            
            # 2. Blacklist tokens
            await self._block_tokens(command)
            
            # 3. Handle logout
            if command.logout_all_sessions:
                # Logout from all sessions
                await self._logout_all_sessions(command.user_id)
                sessions_logged_out = await self._count_active_sessions(command.user_id)
                message = f"Logged out from all {sessions_logged_out} sessions"
            else:
                # Logout from current session only
                await self._logout_session(session)
                sessions_logged_out = 1
                message = "Logged out successfully"
            
            # 4. Clear session caches
            await self._clear_session_caches(command.user_id, command.session_id)
            
            # 5. Publish logout event
            await self._event_bus.publish(
                UserLoggedOut(
                    aggregate_id=command.user_id,
                    session_id=command.session_id,
                    logout_all=command.logout_all_sessions,
                    ip_address=command.ip_address,
                    sessions_terminated=sessions_logged_out
                )
            )
            
            # 6. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _block_tokens(self, command: LogoutCommand) -> None:
        """Blacklist access and refresh tokens."""
        # Blacklist access token
        await self._token_blocklist_service.block_token(
            token=command.access_token,
            token_type="access",  # noqa: S106
            expires_in=3600  # 1 hour
        )
        
        # Blacklist refresh token if provided
        if command.refresh_token:
            await self._token_blocklist_service.block_token(
                token=command.refresh_token,
                token_type="refresh",  # noqa: S106
                expires_in=2592000  # 30 days
            )
    
    async def _logout_session(self, session: Session) -> None:
        """Logout a single session."""
        await self._session_service.revoke_session(
            session_id=session.id,
            reason="User logout"
        )
    
    async def _logout_all_sessions(self, user_id: UUID) -> None:
        """Logout all user sessions."""
        active_sessions = await self._session_repository.find_active_by_user(user_id)
        
        for session in active_sessions:
            await self._session_service.revoke_session(
                session_id=session.id,
                reason="User logout from all devices"
            )
    
    async def _count_active_sessions(self, user_id: UUID) -> int:
        """Count active sessions before logout."""
        sessions = await self._session_repository.find_active_by_user(user_id)
        return len(sessions)
    
    async def _clear_session_caches(self, user_id: UUID, session_id: UUID) -> None:
        """Clear session-related caches."""
        cache_keys = [
            f"session:{session_id}",
            f"user_session:{user_id}:{session_id}",
            f"session_permissions:{session_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)