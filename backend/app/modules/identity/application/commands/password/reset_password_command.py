"""
Reset password command implementation.

Handles password reset using a valid token.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IEmailService,
    INotificationService,
    IPasswordHistoryRepository,
    IPasswordResetTokenRepository,
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import ResetPasswordRequest
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import PasswordResetToken, User
from app.modules.identity.domain.enums import (
    AuditAction,
    RiskLevel,
    SecurityEventType,
    TokenStatus,
    UserStatus,
)
from app.modules.identity.domain.events import PasswordReset
from app.modules.identity.domain.exceptions import (
    InvalidTokenError,
    PasswordReuseError,
    SecurityViolationError,
    TokenExpiredError,
    UserNotFoundError,
    WeakPasswordError,
)
from app.modules.identity.domain.services import (
    PasswordService,
    SecurityService,
    SessionService,
)


class ResetPasswordCommand(Command[BaseResponse]):
    """Command to reset password using token."""
    
    def __init__(
        self,
        token: str,
        new_password: str,
        ip_address: str,
        user_agent: str | None = None
    ):
        self.token = token
        self.new_password = new_password
        self.ip_address = ip_address
        self.user_agent = user_agent


class ResetPasswordCommandHandler(CommandHandler[ResetPasswordCommand, BaseResponse]):
    """Handler for password reset."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        password_reset_token_repository: IPasswordResetTokenRepository,
        password_history_repository: IPasswordHistoryRepository,
        session_repository: ISessionRepository,
        password_service: PasswordService,
        session_service: SessionService,
        security_service: SecurityService,
        email_service: IEmailService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._token_repository = password_reset_token_repository
        self._password_history_repository = password_history_repository
        self._session_repository = session_repository
        self._password_service = password_service
        self._session_service = session_service
        self._security_service = security_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_RESET,
        resource_type="user",
        include_request=False  # Don't log password
    )
    @validate_request(ResetPasswordRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='ip'
    )
    async def handle(self, command: ResetPasswordCommand) -> BaseResponse:
        """
        Reset password using valid token.
        
        Process:
        1. Validate reset token
        2. Load user and validate
        3. Validate new password
        4. Check password history
        5. Update password
        6. Invalidate token
        7. Revoke all sessions
        8. Send notifications
        9. Publish event
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            InvalidTokenError: If token invalid
            TokenExpiredError: If token expired
            UserNotFoundError: If user not found
            WeakPasswordError: If password weak
            PasswordReuseError: If password recently used
        """
        async with self._unit_of_work:
            # 1. Find and validate token
            reset_token = await self._token_repository.get_by_token(command.token)
            
            if not reset_token:
                raise InvalidTokenError("Invalid or expired reset token")
            
            # 2. Check token status
            if reset_token.status == TokenStatus.USED:
                # Token reuse attempt - security concern
                await self._handle_token_reuse(reset_token, command)
                raise InvalidTokenError("Reset token has already been used")
            
            if reset_token.status == TokenStatus.INVALIDATED:
                raise InvalidTokenError("Reset token has been invalidated")
            
            if reset_token.expires_at < datetime.now(UTC):
                reset_token.status = TokenStatus.EXPIRED
                await self._token_repository.update(reset_token)
                raise TokenExpiredError("Reset token has expired")
            
            # 3. Load user
            user = await self._user_repository.get_by_id(reset_token.user_id)
            
            if not user:
                raise UserNotFoundError("User not found")
            
            if user.status not in [UserStatus.ACTIVE, UserStatus.PENDING]:
                raise SecurityViolationError(f"Cannot reset password for {user.status.value} account")
            
            # 4. Check IP consistency
            if reset_token.ip_address and command.ip_address != reset_token.ip_address:
                # Different IP - could be legitimate but worth noting
                await self._log_ip_mismatch(user, reset_token, command)
            
            # 5. Validate new password
            validation_result = await self._password_service.validate_password(
                command.new_password,
                username=user.username,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name
            )
            
            if not validation_result.is_valid:
                raise WeakPasswordError(
                    f"Password does not meet requirements: {', '.join(validation_result.issues)}"
                )
            
            # 6. Check password history
            await self._check_password_history(
                user_id=user.id,
                new_password=command.new_password
            )
            
            # 7. Save current password to history
            await self._password_history_repository.add(
                user_id=user.id,
                password_hash=user.password_hash
            )
            
            # 8. Hash and update password
            new_password_hash = await self._password_service.hash_password(
                command.new_password
            )
            
            user.update_password_hash(new_password_hash)
            user.password_changed_at = datetime.now(UTC)
            user.require_password_change = False
            
            # Activate user if pending
            if user.status == UserStatus.PENDING:
                user.activate()
            
            await self._user_repository.update(user)
            
            # 9. Mark token as used
            reset_token.use(command.ip_address)
            await self._token_repository.update(reset_token)
            
            # 10. Revoke all active sessions
            sessions_revoked = await self._revoke_all_sessions(user.id)
            
            # 11. Clear caches
            await self._clear_user_caches(user.id)
            
            # 12. Send confirmation email
            await self._send_reset_confirmation(
                user=user,
                ip_address=command.ip_address,
                sessions_revoked=sessions_revoked
            )
            
            # 13. Publish event
            await self._event_bus.publish(
                PasswordReset(
                    aggregate_id=user.id,
                    reset_by_token=True,
                    ip_address=command.ip_address,
                    sessions_revoked=sessions_revoked
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message="Password reset successfully. Please login with your new password."
            )
    
    async def _handle_token_reuse(
        self,
        token: PasswordResetToken,
        command: ResetPasswordCommand
    ) -> None:
        """Handle potential token reuse attack."""
        user = await self._user_repository.get_by_id(token.user_id)
        
        if user:
            # Log security incident
            await self._security_service.log_security_incident(
                SecurityIncidentContext(
                    incident_type=SecurityEventType.PASSWORD_RESET_TOKEN_REUSE,
                    severity=RiskLevel.HIGH,
                    user_id=user.id,
                    ip_address=command.ip_address,
                    details={
                        "token_id": str(token.id),
                        "original_ip": token.ip_address,
                        "reuse_ip": command.ip_address
                    }
                )
            )
            
            # Notify user
            await self._security_service.notify_security_alert(
                user=user,
                alert_type="password_reset_token_reuse",
                details={
                    "action_taken": "All sessions revoked",
                    "recommendation": "Your reset token was used multiple times. Please secure your email account."
                }
            )
    
    async def _log_ip_mismatch(
        self,
        user: User,
        token: PasswordResetToken,
        command: ResetPasswordCommand
    ) -> None:
        """Log IP address mismatch between request and reset."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type=SecurityEventType.PASSWORD_RESET_IP_MISMATCH,
            ip_address=command.ip_address,
            details={
                "request_ip": token.ip_address,
                "reset_ip": command.ip_address
            }
        )
    
    async def _check_password_history(
        self,
        user_id: UUID,
        new_password: str
    ) -> None:
        """Check if password was recently used."""
        # Get last 5 password hashes
        history = await self._password_history_repository.get_recent(
            user_id=user_id,
            limit=5
        )
        
        # Check each historical password
        for entry in history:
            if await self._password_service.verify_password(
                new_password,
                entry.password_hash
            ):
                raise PasswordReuseError(
                    "This password was recently used. Please choose a different password."
                )
    
    async def _revoke_all_sessions(self, user_id: UUID) -> int:
        """Revoke all user sessions for security."""
        sessions = await self._session_repository.get_active_sessions(user_id)
        
        for session in sessions:
            await self._session_service.revoke_session(
                session_id=session.id,
                reason="Password reset"
            )
        
        return len(sessions)
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"password_history:{user_id}",
            f"sessions:{user_id}",
            f"permissions:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _send_reset_confirmation(
        self,
        user: User,
        ip_address: str,
        sessions_revoked: int
    ) -> None:
        """Send password reset confirmation email."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="password_reset_success",
                subject="Your password has been reset",
                variables={
                    "username": user.username,
                    "reset_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "ip_address": ip_address,
                    "sessions_revoked": sessions_revoked,
                    "login_url": "https://app.example.com/login",
                    "action_required": "If you didn't reset your password, please contact support immediately.",
                    "support_url": "https://app.example.com/support"
                },
                priority="high"
            )
        )