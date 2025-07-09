"""
Deactivate user command implementation.

Handles user account deactivation with security measures.
"""

from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_self_or_permission,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeactivationReason,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import UserDeactivated
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UnauthorizedError,
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


class DeactivateUserCommand(Command[BaseResponse]):
    """Command to deactivate a user account."""
    
    def __init__(
        self,
        user_id: UUID,
        reason: DeactivationReason,
        details: str | None = None,
        deactivated_by: UUID | None = None,
        ip_address: str | None = None,
        immediate: bool = False,
        notify_user: bool = True
    ):
        self.user_id = user_id
        self.reason = reason
        self.details = details
        self.deactivated_by = deactivated_by
        self.ip_address = ip_address
        self.immediate = immediate
        self.notify_user = notify_user


class DeactivateUserCommandHandler(CommandHandler[DeactivateUserCommand, BaseResponse]):
    """Handler for deactivating user accounts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        authorization_service: AuthorizationService,
        session_service: SessionService,
        security_service: SecurityService,
        notification_service: INotificationService,
        email_service: IEmailService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._authorization_service = authorization_service
        self._session_service = session_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._email_service = email_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.USER_DEACTIVATED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    @require_self_or_permission(
        permission="users.deactivate",
        resource_type="user",
        target_user_id_attr="user_id"
    )
    async def handle(self, command: DeactivateUserCommand) -> BaseResponse:
        """
        Deactivate user account with comprehensive cleanup.
        
        Process:
        1. Load and validate user
        2. Check authorization
        3. Validate deactivation reason
        4. Revoke all active sessions
        5. Update user status
        6. Clear caches
        7. Send notifications
        8. Log security event
        9. Publish domain event
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidOperationError: If already deactivated
            UnauthorizedError: If lacks permission
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Check if already deactivated
            if user.status == UserStatus.DEACTIVATED:
                raise InvalidOperationError("User is already deactivated")
            
            # 3. Additional checks for self-deactivation
            is_self_deactivation = command.deactivated_by == command.user_id
            
            if is_self_deactivation:
                # Require additional confirmation for self-deactivation
                if command.reason not in [
                    DeactivationReason.USER_REQUEST,
                    DeactivationReason.PRIVACY_REQUEST
                ]:
                    raise InvalidOperationError(
                        "Invalid reason for self-deactivation"
                    )
            
            # 4. Check for admin deactivation
            if not is_self_deactivation:
                # Ensure admin has higher privileges
                can_deactivate = await self._authorization_service.has_permission(
                    user_id=command.deactivated_by,
                    permission="users.deactivate",
                    resource_type="user",
                    resource_id=str(command.user_id)
                )
                
                if not can_deactivate:
                    raise UnauthorizedError(
                        "Insufficient permissions to deactivate user"
                    )
            
            # 5. Security check for suspicious deactivation
            if command.reason in [
                DeactivationReason.SECURITY_BREACH,
                DeactivationReason.SUSPICIOUS_ACTIVITY
            ]:
                # Log security incident
                await self._security_service.log_security_incident(
                    SecurityIncidentContext(
                        incident_type=SecurityEventType.ACCOUNT_COMPROMISE,
                        severity=RiskLevel.HIGH,
                        user_id=command.user_id,
                        details={
                            "reason": command.reason.value,
                            "details": command.details,
                            "deactivated_by": str(command.deactivated_by)
                        }
                    )
                )
                
                # Immediate action required
                command.immediate = True
            
            # 6. Revoke all active sessions
            active_sessions = await self._session_repository.find_active_by_user(
                user_id=command.user_id
            )
            
            for session in active_sessions:
                await self._session_service.revoke_session(
                    session_id=session.id,
                    reason="Account deactivated"
                )
            
            # 7. Update user status
            user.deactivate(
                reason=command.reason,
                deactivated_by=command.deactivated_by,
                details=command.details
            )
            
            # 8. Clear all user caches
            await self._clear_user_caches(user.id)
            
            # 9. Save changes
            await self._user_repository.update(user)
            
            # 10. Send notifications
            if command.notify_user:
                await self._send_deactivation_notification(
                    user=user,
                    reason=command.reason,
                    is_self=is_self_deactivation
                )
            
            # 11. Notify security team for security-related deactivations
            if command.reason in [
                DeactivationReason.SECURITY_BREACH,
                DeactivationReason.FRAUD_DETECTED,
                DeactivationReason.ABUSE_VIOLATION
            ]:
                await self._notification_service.notify_security_team(
                    "High-risk account deactivation",
                    {
                        "user_id": str(user.id),
                        "username": user.username,
                        "reason": command.reason.value,
                        "details": command.details
                    }
                )
            
            # 12. Publish domain event
            await self._event_bus.publish(
                UserDeactivated(
                    aggregate_id=user.id,
                    reason=command.reason,
                    deactivated_by=command.deactivated_by,
                    immediate=command.immediate
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message=f"User account deactivated successfully. Reason: {command.reason.value}"
            )
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear all caches related to the user."""
        cache_keys = [
            f"user:{user_id}",
            f"profile:{user_id}",
            f"permissions:{user_id}",
            f"roles:{user_id}",
            f"sessions:{user_id}",
            f"security_profile:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _send_deactivation_notification(
        self,
        user: User,
        reason: DeactivationReason,
        is_self: bool
    ) -> None:
        """Send deactivation notification to user."""
        if is_self:
            template = "account_deactivated_self"
            subject = "Your account has been deactivated"
        else:
            template = "account_deactivated_admin"
            subject = "Important: Your account has been deactivated"
        
        reason_messages = {
            DeactivationReason.USER_REQUEST: "at your request",
            DeactivationReason.ADMIN_ACTION: "by an administrator",
            DeactivationReason.INACTIVITY: "due to prolonged inactivity",
            DeactivationReason.TERMS_VIOLATION: "due to terms of service violation",
            DeactivationReason.SECURITY_BREACH: "due to security concerns",
            DeactivationReason.FRAUD_DETECTED: "due to fraudulent activity",
            DeactivationReason.ABUSE_VIOLATION: "due to abuse policy violation",
            DeactivationReason.PRIVACY_REQUEST: "as per your privacy request",
            DeactivationReason.LEGAL_REQUIREMENT: "due to legal requirements",
            DeactivationReason.OTHER: "for administrative reasons"
        }
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template=template,
                subject=subject,
                variables={
                    "username": user.username,
                    "reason": reason_messages.get(reason, "for administrative reasons"),
                    "support_email": "support@example.com",
                    "reactivation_info": "Contact support to reactivate your account"
                },
                priority="high"
            )
        )