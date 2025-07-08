"""
Force password reset command implementation.

Handles administrative password reset enforcement.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IEmailService,
    INotificationService,
    IPasswordResetTokenRepository,
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    BulkOperationContext,
    EmailContext,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, ForceResetReason, UserStatus
from app.modules.identity.domain.events import PasswordResetForced
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    SecurityService,
    SessionService,
)


class ForcePasswordResetCommand(Command[BaseResponse]):
    """Command to force password reset for users."""
    
    def __init__(
        self,
        user_ids: list[UUID],
        reason: ForceResetReason,
        details: str | None = None,
        forced_by: UUID | None = None,
        revoke_sessions: bool = True,
        send_notification: bool = True,
        allow_grace_period: bool = False,
        grace_period_hours: int = 24
    ):
        self.user_ids = user_ids
        self.reason = reason
        self.details = details
        self.forced_by = forced_by
        self.revoke_sessions = revoke_sessions
        self.send_notification = send_notification
        self.allow_grace_period = allow_grace_period
        self.grace_period_hours = grace_period_hours


class ForcePasswordResetCommandHandler(CommandHandler[ForcePasswordResetCommand, BaseResponse]):
    """Handler for forcing password resets."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        password_reset_token_repository: IPasswordResetTokenRepository,
        authorization_service: AuthorizationService,
        session_service: SessionService,
        security_service: SecurityService,
        email_service: IEmailService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._token_repository = password_reset_token_repository
        self._authorization_service = authorization_service
        self._session_service = session_service
        self._security_service = security_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_RESET_FORCED,
        resource_type="user",
        include_request=True
    )
    @require_permission(
        permission="users.force_password_reset",
        resource_type="system"
    )
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: ForcePasswordResetCommand) -> BaseResponse:
        """
        Force password reset for specified users.
        
        Process:
        1. Validate users exist and can be reset
        2. Check authorization for bulk operation
        3. Flag users for password reset
        4. Handle sessions based on settings
        5. Send notifications
        6. Log security events
        7. Publish events
        
        Returns:
            BaseResponse with operation summary
            
        Raises:
            UnauthorizedError: If lacks permission
            InvalidOperationError: If invalid users
        """
        async with self._unit_of_work:
            # 1. Validate operation context
            if len(command.user_ids) > 100:
                raise InvalidOperationError(
                    "Cannot force reset for more than 100 users at once"
                )
            
            # 2. Create bulk operation context
            operation_context = BulkOperationContext(
                operation_id=UUID(int=0),  # Generate proper ID
                operation_type="force_password_reset",
                target_ids=command.user_ids,
                parameters={
                    "reason": command.reason.value,
                    "revoke_sessions": command.revoke_sessions,
                    "grace_period": command.allow_grace_period
                },
                actor_id=command.forced_by,
                reason=command.details or f"Administrative action: {command.reason.value}"
            )
            
            # 3. Process each user
            results = {
                "success": [],
                "failed": [],
                "skipped": []
            }
            
            for user_id in command.user_ids:
                try:
                    result = await self._process_user_reset(
                        user_id=user_id,
                        command=command
                    )
                    
                    if result["status"] == "success":
                        results["success"].append(user_id)
                    elif result["status"] == "skipped":
                        results["skipped"].append({
                            "user_id": user_id,
                            "reason": result["reason"]
                        })
                    else:
                        results["failed"].append({
                            "user_id": user_id,
                            "error": result["error"]
                        })
                
                except Exception as e:
                    results["failed"].append({
                        "user_id": user_id,
                        "error": str(e)
                    })
            
            # 4. Log bulk operation
            await self._log_bulk_operation(operation_context, results)
            
            # 5. Send admin notification
            if results["failed"]:
                await self._notify_operation_issues(command, results)
            
            # 6. Publish event
            await self._event_bus.publish(
                PasswordResetForced(
                    user_ids=results["success"],
                    reason=command.reason,
                    forced_by=command.forced_by,
                    total_affected=len(results["success"]),
                    sessions_revoked=command.revoke_sessions
                )
            )
            
            # 7. Commit transaction
            await self._unit_of_work.commit()
            
            # 8. Build response message
            message_parts = [
                f"Password reset forced for {len(results['success'])} user(s)."
            ]
            
            if results["skipped"]:
                message_parts.append(f"{len(results['skipped'])} skipped.")
            
            if results["failed"]:
                message_parts.append(f"{len(results['failed'])} failed.")
            
            return BaseResponse(
                success=True,
                message=" ".join(message_parts)
            )
    
    async def _process_user_reset(
        self,
        user_id: UUID,
        command: ForcePasswordResetCommand
    ) -> dict:
        """Process password reset for a single user."""
        # 1. Load user
        user = await self._user_repository.get_by_id(user_id)
        
        if not user:
            return {
                "status": "failed",
                "error": "User not found"
            }
        
        # 2. Check if can be reset
        if user.status in [UserStatus.DELETED, UserStatus.BANNED]:
            return {
                "status": "skipped",
                "reason": f"User is {user.status.value}"
            }
        
        # 3. Check if already requires reset
        if user.require_password_change and not command.revoke_sessions:
            return {
                "status": "skipped",
                "reason": "Already requires password change"
            }
        
        # 4. Set password reset flag
        user.require_password_change = True
        user.password_reset_required_at = datetime.now(UTC)
        user.password_reset_reason = command.reason.value
        
        if command.allow_grace_period:
            user.password_reset_grace_until = datetime.now(UTC) + \
                timedelta(hours=command.grace_period_hours)
        
        await self._user_repository.update(user)
        
        # 5. Handle sessions
        sessions_revoked = 0
        if command.revoke_sessions and not command.allow_grace_period:
            sessions_revoked = await self._revoke_user_sessions(user.id)
        
        # 6. Invalidate any existing reset tokens
        await self._invalidate_reset_tokens(user.id)
        
        # 7. Clear caches
        await self._clear_user_caches(user.id)
        
        # 8. Send notification
        if command.send_notification:
            await self._send_force_reset_notification(
                user=user,
                reason=command.reason,
                grace_period=command.allow_grace_period,
                grace_hours=command.grace_period_hours if command.allow_grace_period else 0
            )
        
        # 9. Log security event
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="password_reset_forced",
            details={
                "reason": command.reason.value,
                "forced_by": str(command.forced_by),
                "sessions_revoked": sessions_revoked,
                "grace_period": command.allow_grace_period
            }
        )
        
        return {
            "status": "success",
            "sessions_revoked": sessions_revoked
        }
    
    async def _revoke_user_sessions(self, user_id: UUID) -> int:
        """Revoke all active sessions for user."""
        sessions = await self._session_repository.get_active_sessions(user_id)
        
        for session in sessions:
            await self._session_service.revoke_session(
                session_id=session.id,
                reason="Password reset required"
            )
        
        return len(sessions)
    
    async def _invalidate_reset_tokens(self, user_id: UUID) -> None:
        """Invalidate any existing reset tokens."""
        tokens = await self._token_repository.get_active_by_user(user_id)
        
        for token in tokens:
            token.invalidate()
            await self._token_repository.update(token)
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"sessions:{user_id}",
            f"permissions:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _send_force_reset_notification(
        self,
        user: User,
        reason: ForceResetReason,
        grace_period: bool,
        grace_hours: int
    ) -> None:
        """Send forced password reset notification."""
        reason_messages = {
            ForceResetReason.SECURITY_BREACH: "due to a security incident",
            ForceResetReason.POLICY_REQUIREMENT: "to comply with security policy",
            ForceResetReason.SUSPECTED_COMPROMISE: "as your account may be compromised",
            ForceResetReason.PERIODIC_ROTATION: "as part of periodic password rotation",
            ForceResetReason.WEAK_PASSWORD: "because your current password is too weak",
            ForceResetReason.ADMIN_REQUEST: "at the request of an administrator"
        }
        
        template = "password_reset_forced_grace" if grace_period else "password_reset_forced_immediate"
        
        variables = {
            "username": user.username,
            "reason": reason_messages.get(reason, "for security reasons"),
            "action_url": "https://app.example.com/change-password",
            "support_email": "support@example.com"
        }
        
        if grace_period:
            variables["grace_hours"] = grace_hours
            variables["deadline"] = (datetime.now(UTC) + timedelta(hours=grace_hours)).strftime("%Y-%m-%d %H:%M UTC")
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template=template,
                subject="Action Required: Password Reset Required",
                variables=variables,
                priority="high"
            )
        )
    
    async def _log_bulk_operation(
        self,
        context: BulkOperationContext,
        results: dict
    ) -> None:
        """Log bulk operation details."""
        await self._security_service.log_audit_event(
            AuditContext(
                actor_id=context.actor_id,
                action=AuditAction.BULK_PASSWORD_RESET,
                resource_type="users",
                changes={
                    "total_users": len(context.target_ids),
                    "successful": len(results["success"]),
                    "failed": len(results["failed"]),
                    "skipped": len(results["skipped"])
                },
                metadata={
                    "reason": context.parameters.get("reason"),
                    "details": context.reason
                }
            )
        )
    
    async def _notify_operation_issues(
        self,
        command: ForcePasswordResetCommand,
        results: dict
    ) -> None:
        """Notify admins of operation issues."""
        await self._notification_service.notify_admins(
            "Force password reset operation had issues",
            {
                "forced_by": str(command.forced_by),
                "reason": command.reason.value,
                "total_users": len(command.user_ids),
                "failed_count": len(results["failed"]),
                "failed_users": results["failed"][:10]  # First 10 failures
            }
        )