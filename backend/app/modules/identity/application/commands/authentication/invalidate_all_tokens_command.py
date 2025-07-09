"""
Invalidate all tokens command implementation.

Handles invalidating all authentication tokens for a user.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import TokenInvalidationParams
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import InvalidateAllTokensRequest
from app.modules.identity.application.dtos.response import TokenInvalidationResponse
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.enums import AuditAction, SessionStatus
from app.modules.identity.domain.events import AllTokensInvalidated
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidOperationError,
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
from app.modules.identity.domain.services import PasswordService, SecurityService
from app.modules.identity.domain.interfaces.services import (
    ICachePort,
    ITokenBlocklistService,
)


@dataclass
class InvalidateTokensRepositoryDependencies:
    """Repository dependencies for invalidate tokens handler."""
    user_repository: IUserRepository
    session_repository: ISessionRepository


@dataclass
class InvalidateTokensServiceDependencies:
    """Service dependencies for invalidate tokens handler."""
    security_service: SecurityService
    password_service: PasswordService
    token_blocklist_service: ITokenBlocklistService
    email_service: IEmailService
    cache_service: ICacheService


@dataclass
class InvalidateTokensInfrastructureDependencies:
    """Infrastructure dependencies for invalidate tokens handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class InvalidateAllTokensCommand(Command[TokenInvalidationResponse]):
    """Command to invalidate all user tokens."""
    
    def __init__(self, params: TokenInvalidationParams):
        self.params = params
        # Set default initiated_by if not provided
        if self.params.initiated_by is None:
            self.params.initiated_by = params.user_id


class InvalidateAllTokensCommandHandler(CommandHandler[InvalidateAllTokensCommand, TokenInvalidationResponse]):
    """Handler for invalidating all tokens."""
    
    def __init__(
        self,
        repositories: InvalidateTokensRepositoryDependencies,
        services: InvalidateTokensServiceDependencies,
        infrastructure: InvalidateTokensInfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._session_repository = repositories.session_repository
        
        # Service dependencies
        self._security_service = services.security_service
        self._password_service = services.password_service
        self._token_blocklist_service = services.token_blocklist_service
        self._email_service = services.email_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.ALL_TOKENS_INVALIDATED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=False  # Don't log password
    )
    @require_auth
    @validate_request(InvalidateAllTokensRequest)
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: InvalidateAllTokensCommand) -> TokenInvalidationResponse:
        """
        Invalidate all authentication tokens.
        
        Process:
        1. Verify user and password
        2. Get all active sessions
        3. Revoke all sessions
        4. Blacklist all tokens
        5. Invalidate API keys if requested
        6. Clear auth caches
        7. Send notifications
        8. Publish event
        
        Returns:
            TokenInvalidationResponse with details
            
        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If password wrong
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Verify password (if not admin action)
            if command.initiated_by == command.user_id:
                is_valid = await self._password_service.verify_password(
                    command.password,
                    user.password_hash
                )
                
                if not is_valid:
                    await self._log_failed_attempt(user.id, command.ip_address)
                    raise InvalidCredentialsError("Invalid password")
            else:
                # Verify admin has permission
                await self._verify_admin_permission(command.initiated_by, user.id)
            
            # 3. Get all sessions
            all_sessions = await self._session_repository.get_user_sessions(user.id)
            active_sessions = [s for s in all_sessions if s.status == SessionStatus.ACTIVE]
            
            # 4. Revoke all sessions and block tokens
            tokens_invalidated = await self._invalidate_sessions(active_sessions)
            
            # 5. Invalidate API keys if requested
            api_keys_invalidated = 0
            if command.include_api_keys:
                api_keys_invalidated = await self._invalidate_api_keys(user.id)
            
            # 6. Increment token version to invalidate all existing tokens
            user.token_version = (user.token_version or 0) + 1
            user.updated_at = datetime.now(UTC)
            await self._user_repository.update(user)
            
            # 7. Clear all auth caches
            await self._clear_auth_caches(user.id)
            
            # 8. Send notification if requested
            if command.notify_user:
                await self._send_invalidation_notification(
                    user=user,
                    sessions_count=len(active_sessions),
                    api_keys_count=api_keys_invalidated,
                    reason=command.reason
                )
            
            # 9. Log security event
            await self._log_token_invalidation(
                user=user,
                command=command,
                tokens_invalidated=tokens_invalidated,
                api_keys_invalidated=api_keys_invalidated
            )
            
            # 10. Publish event
            await self._event_bus.publish(
                AllTokensInvalidated(
                    aggregate_id=user.id,
                    reason=command.reason,
                    sessions_invalidated=len(active_sessions),
                    api_keys_invalidated=api_keys_invalidated,
                    initiated_by=command.initiated_by,
                    token_version=user.token_version
                )
            )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            return TokenInvalidationResponse(
                sessions_invalidated=len(active_sessions),
                tokens_blocked=tokens_invalidated,
                api_keys_invalidated=api_keys_invalidated,
                new_token_version=user.token_version,
                success=True,
                message=f"All tokens invalidated. {len(active_sessions)} sessions terminated."
            )
    
    async def _verify_admin_permission(
        self,
        admin_id: UUID,
        target_user_id: UUID
    ) -> None:
        """Verify admin has permission to invalidate tokens."""
        # This would check with authorization service
        # For now, just ensure it's not the same user
        if admin_id == target_user_id:
            return
        
        # Would normally check permissions here
        raise InvalidOperationError("Insufficient permissions")
    
    async def _invalidate_sessions(
        self,
        sessions: list[Session]
    ) -> int:
        """Invalidate all sessions and block tokens."""
        tokens_blocked = 0
        
        for session in sessions:
            # Revoke session
            session.revoke("All tokens invalidated")
            await self._session_repository.update(session)
            
            # Blacklist access token
            if session.access_token_jti:
                await self._token_blocklist_service.block_token(
                    token=session.access_token_jti,
                    token_type="access_jti",  # noqa: S106
                    expires_in=3600  # 1 hour
                )
                tokens_blocked += 1
            
            # Blacklist refresh token
            if session.refresh_token_jti:
                await self._token_blocklist_service.block_token(
                    token=session.refresh_token_jti,
                    token_type="refresh_jti",  # noqa: S106
                    expires_in=2592000  # 30 days
                )
                tokens_blocked += 1
        
        return tokens_blocked
    
    async def _invalidate_api_keys(self, user_id: UUID) -> int:
        """Invalidate all API keys for user."""
        # This would interact with an API key service
        # For now, return 0
        return 0
    
    async def _clear_auth_caches(self, user_id: UUID) -> None:
        """Clear all authentication-related caches."""
        cache_patterns = [
            f"session:*:{user_id}",
            f"user_session:{user_id}:*",
            f"active_sessions:{user_id}",
            f"auth_token:{user_id}:*",
            f"refresh_token:{user_id}:*",
            f"api_key:{user_id}:*"
        ]
        
        for pattern in cache_patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _send_invalidation_notification(
        self,
        user: User,
        sessions_count: int,
        api_keys_count: int,
        reason: str
    ) -> None:
        """Send notification about token invalidation."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="tokens_invalidated",
                subject="Security Alert: All tokens have been invalidated",
                variables={
                    "username": user.username,
                    "sessions_count": sessions_count,
                    "api_keys_count": api_keys_count,
                    "reason": reason,
                    "action_required": "You will need to sign in again on all devices",
                    "security_tip": "This action was taken to secure your account",
                    "support_url": "https://app.example.com/support"
                },
                priority="high"
            )
        )
    
    async def _log_failed_attempt(
        self,
        user_id: UUID,
        ip_address: str | None
    ) -> None:
        """Log failed password verification."""
        await self._security_service.log_security_event(
            user_id=user_id,
            event_type="invalidate_tokens_failed",
            ip_address=ip_address,
            details={
                "reason": "invalid_password"
            }
        )
    
    async def _log_token_invalidation(
        self,
        user: User,
        command: InvalidateAllTokensCommand,
        tokens_invalidated: int,
        api_keys_invalidated: int
    ) -> None:
        """Log token invalidation for security."""
        details = {
            "reason": command.reason,
            "sessions_terminated": tokens_invalidated,
            "api_keys_invalidated": api_keys_invalidated,
            "new_token_version": user.token_version,
            "initiated_by": str(command.initiated_by)
        }
        
        if command.initiated_by != user.id:
            details["admin_action"] = True
        
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="all_tokens_invalidated",
            ip_address=command.ip_address,
            details=details
        )