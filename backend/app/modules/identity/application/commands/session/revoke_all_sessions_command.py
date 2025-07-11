"""
Revoke all sessions command implementation.

Handles revoking all sessions for a user.
"""

from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import AllSessionsRevoked
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
    PasswordService,
    SecurityService,
    SessionService,
)


class RevokeAllSessionsCommand(Command[BaseResponse]):
    """Command to revoke all user sessions."""
    
    def __init__(
        self,
        user_id: UUID,
        password: str,
        except_current: bool = True,
        current_session_id: UUID | None = None,
        reason: str | None = None,
        ip_address: str | None = None
    ):
        self.user_id = user_id
        self.password = password
        self.except_current = except_current
        self.current_session_id = current_session_id
        self.reason = reason
        self.ip_address = ip_address


class RevokeAllSessionsCommandHandler(CommandHandler[RevokeAllSessionsCommand, BaseResponse]):
    """Handler for revoking all sessions."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        session_service: SessionService,
        password_service: PasswordService,
        security_service: SecurityService,
        token_blocklist_service: ITokenBlocklistService,
        email_service: IEmailService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._session_service = session_service
        self._password_service = password_service
        self._security_service = security_service
        self._token_blocklist_service = token_blocklist_service
        self._email_service = email_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.ALL_SESSIONS_REVOKED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=False  # Don't log password
    )
    @require_auth
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: RevokeAllSessionsCommand) -> BaseResponse:
        """
        Revoke all sessions for a user.
        
        Process:
        1. Verify user password
        2. Get all active sessions
        3. Revoke each session
        4. Blacklist all tokens
        5. Clear caches
        6. Send notification
        7. Publish event
        
        Returns:
            BaseResponse with count of revoked sessions
            
        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If password wrong
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Verify password for security
            is_valid = await self._password_service.verify_password(
                command.password,
                user.password_hash
            )
            
            if not is_valid:
                # Log failed attempt
                await self._log_failed_attempt(user.id, command.ip_address)
                raise InvalidCredentialsError("Invalid password")
            
            # 3. Get all active sessions
            active_sessions = await self._session_repository.find_active_by_user(
                user.id
            )
            
            if not active_sessions:
                return BaseResponse(
                    success=True,
                    message="No active sessions to revoke"
                )
            
            # 4. Process each session
            revoked_count = 0
            sessions_to_revoke = []
            
            for session in active_sessions:
                # Skip current session if requested
                if command.except_current and session.id == command.current_session_id:
                    continue
                
                sessions_to_revoke.append(session)
            
            # 5. Revoke sessions
            for session in sessions_to_revoke:
                await self._revoke_session(session, command.reason)
                revoked_count += 1
            
            # 6. Clear user session caches
            await self._clear_user_session_caches(user.id)
            
            # 7. Send notification
            if revoked_count > 0:
                await self._send_sessions_revoked_notification(
                    user=user,
                    sessions_count=revoked_count,
                    except_current=command.except_current
                )
            
            # 8. Log security event
            await self._security_service.log_security_event(
                user_id=user.id,
                event_type="all_sessions_revoked",
                ip_address=command.ip_address,
                details={
                    "sessions_revoked": revoked_count,
                    "except_current": command.except_current,
                    "reason": command.reason
                }
            )
            
            # 9. Publish event
            await self._event_bus.publish(
                AllSessionsRevoked(
                    aggregate_id=user.id,
                    sessions_count=revoked_count,
                    except_current=command.except_current,
                    reason=command.reason
                )
            )
            
            # 10. Commit transaction
            await self._unit_of_work.commit()
            
            message = f"Revoked {revoked_count} session(s)"
            if command.except_current and command.current_session_id:
                message += " (except current)"
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _log_failed_attempt(
        self,
        user_id: UUID,
        ip_address: str | None
    ) -> None:
        """Log failed password verification."""
        await self._security_service.log_security_event(
            user_id=user_id,
            event_type="revoke_all_sessions_failed",
            ip_address=ip_address,
            details={
                "reason": "invalid_password"
            }
        )
    
    async def _revoke_session(
        self,
        session: Session,
        reason: str | None
    ) -> None:
        """Revoke a single session."""
        # Revoke via service
        await self._session_service.revoke_session(
            session_id=session.id,
            reason=reason or "User revoked all sessions"
        )
        
        # Blacklist tokens
        if session.access_token_jti:
            await self._token_blocklist_service.block_token(
                token=session.access_token_jti,
                token_type="access_jti",
                expires_in=3600
            )
        
        if session.refresh_token_jti:
            await self._token_blocklist_service.block_token(
                token=session.refresh_token_jti,
                token_type="refresh_jti",
                expires_in=2592000
            )
    
    async def _clear_user_session_caches(self, user_id: UUID) -> None:
        """Clear all session caches for user."""
        # Clear pattern-based caches
        cache_patterns = [
            f"session:*:{user_id}",
            f"user_session:{user_id}:*",
            f"active_sessions:{user_id}"
        ]
        
        for pattern in cache_patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _send_sessions_revoked_notification(
        self,
        user: any,
        sessions_count: int,
        except_current: bool
    ) -> None:
        """Send notification about revoked sessions."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="all_sessions_revoked",
                subject="Your sessions have been terminated",
                variables={
                    "username": user.username,
                    "sessions_count": sessions_count,
                    "except_current": except_current,
                    "security_tip": "This action was taken to secure your account.",
                    "action_required": "You'll need to login again on your other devices.",
                    "support_url": "https://app.example.com/support"
                },
                priority="high"
            )
        )