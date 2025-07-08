"""
Change password command implementation.

Handles authenticated password change with validation.
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
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, RiskLevel, SecurityEventType
from app.modules.identity.domain.events import PasswordChanged
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidOperationError,
    PasswordReuseError,
    UserNotFoundError,
    WeakPasswordError,
)
from app.modules.identity.domain.services import (
    PasswordService,
    SecurityService,
    SessionService,
)


class ChangePasswordCommand(Command[BaseResponse]):
    """Command to change user password."""
    
    def __init__(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str,
        logout_other_sessions: bool = True,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None
    ):
        self.user_id = user_id
        self.current_password = current_password
        self.new_password = new_password
        self.logout_other_sessions = logout_other_sessions
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.session_id = session_id


class ChangePasswordCommandHandler(CommandHandler[ChangePasswordCommand, BaseResponse]):
    """Handler for password change."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
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
        action=AuditAction.PASSWORD_CHANGED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=False  # Don't log passwords
    )
    @require_auth
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: ChangePasswordCommand) -> BaseResponse:
        """
        Change user password with comprehensive validation.
        
        Process:
        1. Load and validate user
        2. Verify current password
        3. Validate new password
        4. Check password history
        5. Update password
        6. Handle sessions
        7. Send notifications
        8. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If current password wrong
            WeakPasswordError: If new password weak
            PasswordReuseError: If password recently used
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Verify current password
            is_valid = await self._password_service.verify_password(
                command.current_password,
                user.password_hash
            )
            
            if not is_valid:
                # Log failed attempt
                await self._log_failed_password_change(user, command)
                raise InvalidCredentialsError("Current password is incorrect")
            
            # 3. Check if new password is same as current
            if command.current_password == command.new_password:
                raise InvalidOperationError(
                    "New password must be different from current password"
                )
            
            # 4. Validate new password strength
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
            
            # 5. Check password history
            await self._check_password_history(
                user_id=user.id,
                new_password=command.new_password
            )
            
            # 6. Hash new password
            new_password_hash = await self._password_service.hash_password(
                command.new_password
            )
            
            # 7. Save current password to history
            await self._password_history_repository.add(
                user_id=user.id,
                password_hash=user.password_hash
            )
            
            # 8. Update user password
            user.update_password_hash(new_password_hash)
            user.password_changed_at = datetime.now(UTC)
            user.require_password_change = False
            
            await self._user_repository.update(user)
            
            # 9. Handle sessions
            sessions_revoked = 0
            if command.logout_other_sessions:
                sessions_revoked = await self._revoke_other_sessions(
                    user_id=user.id,
                    current_session_id=command.session_id
                )
            
            # 10. Clear password-related caches
            await self._clear_password_caches(user.id)
            
            # 11. Send notification email
            await self._send_password_change_notification(
                user=user,
                ip_address=command.ip_address,
                sessions_revoked=sessions_revoked
            )
            
            # 12. Check for suspicious activity
            if await self._is_suspicious_password_change(user, command):
                await self._handle_suspicious_activity(user, command)
            
            # 13. Publish event
            await self._event_bus.publish(
                PasswordChanged(
                    aggregate_id=user.id,
                    ip_address=command.ip_address,
                    sessions_revoked=sessions_revoked,
                    require_mfa_reset=False
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            message = "Password changed successfully."
            if sessions_revoked > 0:
                message += f" {sessions_revoked} other session(s) have been logged out."
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _log_failed_password_change(
        self,
        user: User,
        command: ChangePasswordCommand
    ) -> None:
        """Log failed password change attempt."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type=SecurityEventType.FAILED_PASSWORD_CHANGE,
            ip_address=command.ip_address,
            details={
                "user_agent": command.user_agent,
                "reason": "invalid_current_password"
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
    
    async def _revoke_other_sessions(
        self,
        user_id: UUID,
        current_session_id: UUID | None
    ) -> int:
        """Revoke all sessions except current."""
        sessions = await self._session_repository.get_active_sessions(user_id)
        
        revoked_count = 0
        for session in sessions:
            if session.id != current_session_id:
                await self._session_service.revoke_session(
                    session_id=session.id,
                    reason="Password changed"
                )
                revoked_count += 1
        
        return revoked_count
    
    async def _clear_password_caches(self, user_id: UUID) -> None:
        """Clear password-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"password_history:{user_id}",
            f"password_policy:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _send_password_change_notification(
        self,
        user: User,
        ip_address: str | None,
        sessions_revoked: int
    ) -> None:
        """Send password change notification."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="password_changed",
                subject="Your password has been changed",
                variables={
                    "username": user.username,
                    "change_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "ip_address": ip_address or "Unknown",
                    "sessions_revoked": sessions_revoked,
                    "action_required": "If you didn't make this change, please contact support immediately.",
                    "support_url": "https://app.example.com/support"
                },
                priority="high"
            )
        )
    
    async def _is_suspicious_password_change(
        self,
        user: User,
        command: ChangePasswordCommand
    ) -> bool:
        """Check if password change seems suspicious."""
        # Check for rapid password changes
        if user.password_changed_at:
            time_since_last_change = datetime.now(UTC) - user.password_changed_at
            if time_since_last_change.days < 1:
                return True
        
        # Check for unusual location
        if command.ip_address:
            ip_risk = await self._security_service.check_ip_reputation(command.ip_address)
            if ip_risk.risk_score > 0.7:
                return True
        
        return False
    
    async def _handle_suspicious_activity(
        self,
        user: User,
        command: ChangePasswordCommand
    ) -> None:
        """Handle suspicious password change."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_PASSWORD_CHANGE,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                ip_address=command.ip_address,
                details={
                    "user_agent": command.user_agent,
                    "last_change": user.password_changed_at.isoformat() if user.password_changed_at else None
                }
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "Suspicious password change detected",
            {
                "user_id": str(user.id),
                "username": user.username,
                "ip_address": command.ip_address
            }
        )