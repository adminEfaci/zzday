"""
Confirm email change command implementation.

Handles confirming email address changes with verification.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import ConfirmEmailChangeRequest
from app.modules.identity.application.dtos.response import EmailChangeResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import EmailChanged
from app.modules.identity.domain.exceptions import (
    DuplicateResourceError,
    InvalidOperationError,
    InvalidTokenError,
)
from app.modules.identity.domain.services import NotificationService, SecurityService
from app.modules.identity.domain.specifications import UserSpecifications


@dataclass
class ConfirmEmailChangeRepositoryDependencies:
    """Repository dependencies for confirm email change handler."""
    user_repository: IUserRepository
    session_repository: ISessionRepository


@dataclass
class ConfirmEmailChangeServiceDependencies:
    """Service dependencies for confirm email change handler."""
    security_service: SecurityService
    notification_service: NotificationService
    email_service: IEmailService
    cache_service: ICacheService


@dataclass
class ConfirmEmailChangeInfrastructureDependencies:
    """Infrastructure dependencies for confirm email change handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class ConfirmEmailChangeCommand(Command[EmailChangeResponse]):
    """Command to confirm email change."""
    
    def __init__(
        self,
        token: str,
        ip_address: str | None = None,
        user_agent: str | None = None
    ):
        self.token = token
        self.ip_address = ip_address
        self.user_agent = user_agent


class ConfirmEmailChangeCommandHandler(CommandHandler[ConfirmEmailChangeCommand, EmailChangeResponse]):
    """Handler for confirming email changes."""
    
    def __init__(
        self,
        repositories: ConfirmEmailChangeRepositoryDependencies,
        services: ConfirmEmailChangeServiceDependencies,
        infrastructure: ConfirmEmailChangeInfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._session_repository = repositories.session_repository
        
        # Service dependencies
        self._security_service = services.security_service
        self._notification_service = services.notification_service
        self._email_service = services.email_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
        
        # Initialize specifications
        self._specifications = UserSpecifications()
    
    @audit_action(
        action=AuditAction.EMAIL_CHANGED,
        resource_type="user",
        include_request=False  # Don't log token
    )
    @validate_request(ConfirmEmailChangeRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='ip'
    )
    async def handle(self, command: ConfirmEmailChangeCommand) -> EmailChangeResponse:
        """
        Confirm email address change.
        
        Process:
        1. Validate token
        2. Load pending change data
        3. Verify user and new email
        4. Check for email conflicts
        5. Apply email change
        6. Invalidate user sessions
        7. Send notifications
        8. Clear caches
        9. Publish event
        
        Returns:
            EmailChangeResponse with new email details
            
        Raises:
            InvalidTokenError: If token invalid
            ExpiredTokenError: If token expired
            DuplicateResourceError: If email taken
        """
        async with self._unit_of_work:
            # 1. Validate token format
            if not self._is_valid_token_format(command.token):
                raise InvalidTokenError("Invalid token format")
            
            # 2. Get pending change data
            change_data = await self._get_pending_change(command.token)
            
            if not change_data:
                raise InvalidTokenError("Invalid or expired token")
            
            # 3. Load user
            user = await self._user_repository.find_by_id(
                UUID(change_data['user_id'])
            )
            
            if not user:
                raise InvalidOperationError("User not found")
            
            # 4. Verify new email not taken
            new_email = change_data['new_email']
            await self._verify_email_available(new_email, user.id)
            
            # 5. Store old email for notifications
            old_email = user.email
            
            # 6. Apply email change
            user.email = new_email
            user.email_verified = True
            user.email_verified_at = datetime.now(UTC)
            user.updated_at = datetime.now(UTC)
            
            await self._user_repository.update(user)
            
            # 7. Invalidate sessions for security
            await self._invalidate_user_sessions(user.id, command)
            
            # 8. Delete pending change
            await self._delete_pending_change(command.token)
            
            # 9. Send notifications
            await self._send_change_notifications(
                user=user,
                old_email=old_email,
                new_email=new_email
            )
            
            # 10. Clear caches
            await self._clear_user_caches(user.id)
            
            # 11. Log security event
            await self._log_email_change(
                user=user,
                old_email=old_email,
                new_email=new_email,
                command=command
            )
            
            # 12. Publish event
            await self._event_bus.publish(
                EmailChanged(
                    aggregate_id=user.id,
                    old_email=old_email,
                    new_email=new_email,
                    verified=True,
                    changed_at=datetime.now(UTC)
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return EmailChangeResponse(
                old_email=old_email,
                new_email=new_email,
                verified=True,
                sessions_invalidated=True,
                success=True,
                message="Email address successfully changed"
            )
    
    def _is_valid_token_format(self, token: str) -> bool:
        """Validate token format."""
        # Basic validation - alphanumeric and length
        if not token or len(token) < 32:
            return False
        
        return token.replace('-', '').isalnum()
    
    async def _get_pending_change(self, token: str) -> dict | None:
        """Get pending email change data."""
        # Try to get from cache
        cache_key = f"pending_email_change_token:{token}"
        change_data = await self._cache_service.get(cache_key)
        
        if not change_data:
            # Try alternate key format (by user)
            # This requires decoding the token first
            try:
                token_data = await self._security_service.verify_token(
                    token=token,
                    purpose='email_change'
                )
                
                if token_data and 'user_id' in token_data:
                    user_cache_key = f"pending_email_change:{token_data['user_id']}"
                    change_data = await self._cache_service.get(user_cache_key)
                    
                    # Verify token matches
                    if change_data and change_data.get('token') != token:
                        return None
            except Exception:
                return None
        
        return change_data
    
    async def _verify_email_available(self, email: str, user_id: UUID) -> None:
        """Verify email is not already in use."""
        existing_spec = self._specifications.with_email(email)
        existing_users = await self._user_repository.find_by_specification(existing_spec)
        
        # Filter out current user
        other_users = [u for u in existing_users if u.id != user_id]
        
        if other_users:
            raise DuplicateResourceError(
                "Email address is already in use"
            )
    
    async def _invalidate_user_sessions(
        self,
        user_id: UUID,
        command: ConfirmEmailChangeCommand
    ) -> None:
        """Invalidate all user sessions for security."""
        sessions = await self._session_repository.find_active_by_user(user_id)
        
        for session in sessions:
            # Check if this is the current session
            is_current = session.ip_address == command.ip_address
            
            if not is_current:
                session.revoke("Email address changed")
                await self._session_repository.update(session)
    
    async def _delete_pending_change(self, token: str) -> None:
        """Delete pending change data."""
        # Delete by token
        await self._cache_service.delete(f"pending_email_change_token:{token}")
        
        # Also try to delete by user if we have the data
        try:
            token_data = await self._security_service.verify_token(
                token=token,
                purpose='email_change'
            )
            
            if token_data and 'user_id' in token_data:
                await self._cache_service.delete(
                    f"pending_email_change:{token_data['user_id']}"
                )
        except Exception:
            pass
    
    async def _send_change_notifications(
        self,
        user: User,
        old_email: str,
        new_email: str
    ) -> None:
        """Send notifications about email change."""
        # Notify old email
        await self._email_service.send_email(
            EmailContext(
                recipient=old_email,
                template="email_changed_notification",
                subject="Your email address has been changed",
                variables={
                    "username": user.username,
                    "new_email": new_email,
                    "changed_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "support_url": "https://app.example.com/support",
                    "security_tip": "If you didn't make this change, contact support immediately"
                },
                priority="high"
            )
        )
        
        # Notify new email
        await self._email_service.send_email(
            EmailContext(
                recipient=new_email,
                template="email_change_welcome",
                subject="Email address confirmed",
                variables={
                    "username": user.username,
                    "old_email": old_email,
                    "account_url": "https://app.example.com/account"
                },
                priority="normal"
            )
        )
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"user_profile:{user_id}",
            f"user_email:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _log_email_change(
        self,
        user: User,
        old_email: str,
        new_email: str,
        command: ConfirmEmailChangeCommand
    ) -> None:
        """Log email change for security."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="email_address_changed",
            ip_address=command.ip_address,
            details={
                "old_email": old_email,
                "new_email": new_email,
                "user_agent": command.user_agent,
                "sessions_invalidated": True
            }
        )