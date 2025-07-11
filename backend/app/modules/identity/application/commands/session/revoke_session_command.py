"""
Revoke session command implementation.

Handles session revocation with authorization checks.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import AuditAction, SessionStatus
from app.modules.identity.domain.events import SessionRevoked
from app.modules.identity.domain.exceptions import (
    SessionNotFoundError,
    UnauthorizedError,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    INotificationService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    SecurityService,
    SessionService,
)


class RevokeSessionCommand(Command[BaseResponse]):
    """Command to revoke a session."""
    
    def __init__(
        self,
        user_id: UUID,
        session_id: UUID,
        reason: str | None = None,
        revoked_by: UUID | None = None,
        ip_address: str | None = None
    ):
        self.user_id = user_id
        self.session_id = session_id
        self.reason = reason
        self.revoked_by = revoked_by or user_id
        self.ip_address = ip_address


class RevokeSessionCommandHandler(CommandHandler[RevokeSessionCommand, BaseResponse]):
    """Handler for session revocation."""
    
    def __init__(
        self,
        session_repository: ISessionRepository,
        session_service: SessionService,
        authorization_service: AuthorizationService,
        security_service: SecurityService,
        token_blocklist_service: ITokenBlocklistService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._session_repository = session_repository
        self._session_service = session_service
        self._authorization_service = authorization_service
        self._security_service = security_service
        self._token_blocklist_service = token_blocklist_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.SESSION_REVOKED,
        resource_type="session",
        resource_id_attr="session_id",
        include_request=True
    )
    @require_auth
    @rate_limit(
        max_requests=10,
        window_seconds=300,
        strategy='user'
    )
    async def handle(self, command: RevokeSessionCommand) -> BaseResponse:
        """
        Revoke a specific session.
        
        Process:
        1. Load session and validate
        2. Check authorization
        3. Revoke session
        4. Block associated tokens
        5. Clear caches
        6. Send notifications
        7. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            SessionNotFoundError: If session not found
            UnauthorizedError: If not authorized
            InvalidOperationError: If already revoked
        """
        async with self._unit_of_work:
            # 1. Load session
            session = await self._session_repository.find_by_id(command.session_id)
            
            if not session:
                raise SessionNotFoundError(f"Session {command.session_id} not found")
            
            # 2. Check if already revoked
            if session.status == SessionStatus.REVOKED:
                return BaseResponse(
                    success=True,
                    message="Session is already revoked"
                )
            
            # 3. Check authorization
            is_own_session = session.user_id == command.user_id
            
            if not is_own_session:
                # Check if user can revoke others' sessions
                can_revoke = await self._authorization_service.has_permission(
                    user_id=command.revoked_by,
                    permission="sessions.revoke_others",
                    resource_type="session",
                    resource_id=str(command.session_id)
                )
                
                if not can_revoke:
                    raise UnauthorizedError(
                        "Not authorized to revoke this session"
                    )
            
            # 4. Revoke the session
            await self._session_service.revoke_session(
                session_id=session.id,
                reason=command.reason or "User requested"
            )
            
            # 5. Block tokens if available
            if session.access_token_jti:
                await self._token_blocklist_service.block_token(
                    token=session.access_token_jti,
                    token_type="access_jti",
                    expires_in=3600  # 1 hour
                )
            
            if session.refresh_token_jti:
                await self._token_blocklist_service.block_token(
                    token=session.refresh_token_jti,
                    token_type="refresh_jti",
                    expires_in=2592000  # 30 days
                )
            
            # 6. Clear session caches
            await self._clear_session_caches(session)
            
            # 7. Check if this was a suspicious revocation
            if not is_own_session or await self._is_suspicious_revocation(session, command):
                await self._handle_suspicious_revocation(session, command)
            
            # 8. Send notification if another user's session
            if not is_own_session:
                await self._notify_session_revoked(
                    user_id=session.user_id,
                    session=session,
                    revoked_by=command.revoked_by,
                    reason=command.reason
                )
            
            # 9. Publish event
            await self._event_bus.publish(
                SessionRevoked(
                    aggregate_id=session.user_id,
                    session_id=session.id,
                    revoked_by=command.revoked_by,
                    reason=command.reason,
                    was_own_session=is_own_session
                )
            )
            
            # 10. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message="Session revoked successfully"
            )
    
    async def _clear_session_caches(self, session: Session) -> None:
        """Clear caches related to the session."""
        cache_keys = [
            f"session:{session.id}",
            f"user_session:{session.user_id}:{session.id}",
            f"session_permissions:{session.id}",
            f"session_risk:{session.id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _is_suspicious_revocation(
        self,
        session: Session,
        command: RevokeSessionCommand
    ) -> bool:
        """Check if revocation seems suspicious."""
        # Check if session was recently created
        session_age = datetime.now(UTC) - session.created_at
        if session_age.total_seconds() < 300:  # Less than 5 minutes
            return True
        
        # Check if from different IP than session
        if command.ip_address and session.ip_address:
            if command.ip_address != session.ip_address:
                return True
        
        return False
    
    async def _handle_suspicious_revocation(
        self,
        session: Session,
        command: RevokeSessionCommand
    ) -> None:
        """Handle suspicious session revocation."""
        await self._security_service.log_security_event(
            user_id=session.user_id,
            event_type="suspicious_session_revocation",
            ip_address=command.ip_address,
            details={
                "session_id": str(session.id),
                "session_ip": session.ip_address,
                "revoked_by": str(command.revoked_by),
                "session_age_seconds": (datetime.now(UTC) - session.created_at).total_seconds()
            }
        )
    
    async def _notify_session_revoked(
        self,
        user_id: UUID,
        session: Session,
        revoked_by: UUID,
        reason: str | None
    ) -> None:
        """Notify user their session was revoked."""
        await self._notification_service.notify_user(
            user_id=user_id,
            message="Your session was revoked by an administrator",
            channel="email",
            priority="high",
            data={
                "session_id": str(session.id),
                "device": session.device_info,
                "location": session.location,
                "reason": reason or "Security policy",
                "action_required": "Please login again if this was unexpected"
            }
        )