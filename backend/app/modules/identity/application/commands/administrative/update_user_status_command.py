"""
Update user status command implementation.

Handles administrative user status changes with comprehensive audit trail.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    AdminContext,
    InfrastructureDependencies,
    ServiceDependencies,
    StatusUpdateConfig,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import UpdateUserStatusRequest
from app.modules.identity.application.dtos.response import UserStatusUpdateResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import (
    UserActivated,
    UserDeactivated,
    UserLocked,
    UserStatusChanged,
    UserSuspended,
    UserTerminated,
)
from app.modules.identity.domain.exceptions import (
    InsufficientPrivilegesError,
    InvalidStatusTransitionError,
    SelfModificationError,
    UnauthorizedError,
    UserNotFoundError,
)


class UpdateUserStatusCommand(Command[UserStatusUpdateResponse]):
    """Command to update user account status."""
    
    def __init__(
        self,
        admin_context: AdminContext,
        status_config: StatusUpdateConfig,
        session_context: dict[str, str]
    ):
        self.admin_context = admin_context
        self.status_config = status_config
        self.session_context = session_context
        
        # For backward compatibility, expose common fields
        self.target_user_id = admin_context.target_user_id
        self.admin_user_id = admin_context.admin_user_id
        self.reason = status_config.reason
        self.new_status = UserStatus(status_config.new_status)
        self.ip_address = session_context.get('ip_address', '')
        self.notify_user = status_config.send_notification
        self.force_logout = session_context.get('force_logout', 'true').lower() == 'true'
        self.effective_date = datetime.now(UTC) if status_config.effective_immediately else None
        self.metadata = {**admin_context.metadata, **status_config.metadata}


class UpdateUserStatusCommandHandler(CommandHandler[UpdateUserStatusCommand, UserStatusUpdateResponse]):
    """Handler for updating user status."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._session_repository = services.session_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._session_service = services.session_service
        self._email_service = services.email_service
        self._notification_service = services.notification_service
        self._audit_service = services.audit_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.USER_STATUS_CHANGED,
        resource_type="user",
        include_request=True,
        include_response=True,
        sensitive_fields=["reason"]
    )
    @validate_request(UpdateUserStatusRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "users.update_status",
        resource_type="user",
        resource_id_param="target_user_id"
    )
    @require_mfa()
    async def handle(self, command: UpdateUserStatusCommand) -> UserStatusUpdateResponse:
        """
        Update user account status with comprehensive validation.
        
        Process:
        1. Validate admin permissions
        2. Check for self-modification
        3. Load target user
        4. Validate status transition
        5. Check security implications
        6. Update user status
        7. Revoke sessions if needed
        8. Send notifications
        9. Publish domain events
        
        Returns:
            UserStatusUpdateResponse with update details
            
        Raises:
            UserNotFoundError: If target user not found
            InvalidStatusTransitionError: If status change invalid
            UnauthorizedError: If lacks permission
            SelfModificationError: If trying to modify own status
            InsufficientPrivilegesError: If target has higher privileges
        """
        async with self._unit_of_work:
            # 1. Prevent self-modification
            if command.target_user_id == command.admin_user_id:
                raise SelfModificationError(
                    "Cannot modify your own account status"
                )
            
            # 2. Load admin user for privilege check
            admin_user = await self._user_repository.get_by_id(command.admin_user_id)
            if not admin_user:
                raise UnauthorizedError("Admin user not found")
            
            # 3. Load target user
            target_user = await self._user_repository.get_by_id(command.target_user_id)
            if not target_user:
                raise UserNotFoundError(
                    f"User with ID {command.target_user_id} not found"
                )
            
            # 4. Check privilege hierarchy
            if not await self._can_modify_user(admin_user, target_user):
                raise InsufficientPrivilegesError(
                    "Cannot modify user with equal or higher privileges"
                )
            
            # 5. Validate status transition
            if not self._is_valid_transition(target_user.status, command.new_status):
                raise InvalidStatusTransitionError(
                    f"Cannot transition from {target_user.status.value} to {command.new_status.value}"
                )
            
            # 6. Check security implications
            await self._check_security_implications(
                target_user,
                command.new_status,
                command.reason
            )
            
            # 7. Store old status for audit
            old_status = target_user.status
            affected_sessions = 0
            
            # 8. Update user status
            target_user.update_status(
                command.new_status,
                command.reason,
                command.admin_user_id
            )
            
            # 9. Handle status-specific actions
            if command.new_status in [UserStatus.SUSPENDED, UserStatus.LOCKED, UserStatus.TERMINATED] and command.force_logout:
                    sessions = await self._session_repository.get_active_sessions(target_user.id)
                    for session in sessions:
                        await self._session_service.revoke_session(session.id)
                        affected_sessions += 1
                
                # Disable all API keys
                # This would involve API key repository
            
            # 10. Save user
            await self._user_repository.update(target_user)
            
            # 11. Send notifications
            notifications_sent = []
            
            if command.notify_user and target_user.email_verified:
                # Email notification
                template = self._get_email_template(command.new_status)
                await self._email_service.send_email(
                    EmailContext(
                        recipient=target_user.email,
                        template=template,
                        subject="Account Status Update",
                        variables={
                            "username": target_user.username,
                            "old_status": old_status.get_display_name(),
                            "new_status": command.new_status.get_display_name(),
                            "reason": command.reason,
                            "effective_date": command.effective_date.isoformat(),
                            "contact_support": command.new_status != UserStatus.TERMINATED
                        }
                    )
                )
                notifications_sent.append("email")
                
                # In-app notification
                await self._notification_service.create_notification(
                    NotificationContext(
                        notification_id=UUID(),
                        recipient_id=target_user.id,
                        notification_type=NotificationType.ACCOUNT_STATUS_CHANGE,
                        channel="in_app",
                        template_id="account_status_change",
                        template_data={
                            "old_status": old_status.value,
                            "new_status": command.new_status.value,
                            "reason": command.reason
                        },
                        priority="high"
                    )
                )
                notifications_sent.append("in_app")
            
            # 12. Publish domain events
            await self._publish_status_event(
                target_user.id,
                old_status,
                command.new_status,
                command.admin_user_id,
                command.reason
            )
            
            # 13. Log security event for critical statuses
            if command.new_status in [UserStatus.LOCKED, UserStatus.TERMINATED]:
                await self._security_service.log_security_incident(
                    SecurityIncidentContext(
                        incident_type=SecurityEventType.ACCOUNT_LOCKED,
                        severity=RiskLevel.MEDIUM,
                        user_id=target_user.id,
                        details={
                            "old_status": old_status.value,
                            "new_status": command.new_status.value,
                            "reason": command.reason,
                            "admin_user_id": str(command.admin_user_id),
                            "forced_logout": command.force_logout,
                            "sessions_revoked": affected_sessions
                        }
                    )
                )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            # 15. Notify security team for terminated accounts
            if command.new_status == UserStatus.TERMINATED:
                await self._notification_service.notify_security_team(
                    "User account terminated",
                    {
                        "user_id": str(target_user.id),
                        "username": target_user.username,
                        "reason": command.reason,
                        "terminated_by": str(command.admin_user_id)
                    }
                )
            
            return UserStatusUpdateResponse(
                user_id=target_user.id,
                old_status=old_status,
                new_status=command.new_status,
                effective_date=command.effective_date,
                reason=command.reason,
                affected_sessions=affected_sessions,
                notifications_sent=notifications_sent,
                message=f"User status updated from {old_status.get_display_name()} to {command.new_status.get_display_name()}"
            )
    
    async def _can_modify_user(self, admin_user: User, target_user: User) -> bool:
        """Check if admin can modify target user based on hierarchy."""
        # Get role hierarchies
        admin_roles = await self._authorization_service.get_user_roles(admin_user.id)
        target_roles = await self._authorization_service.get_user_roles(target_user.id)
        
        # Super admin can modify anyone
        if any(role.name == "super_admin" for role in admin_roles):
            return True
        
        # Cannot modify users with super admin role
        if any(role.name == "super_admin" for role in target_roles):
            return False
        
        # Check role hierarchy levels
        admin_max_level = max(
            (role.get_hierarchy_level() for role in admin_roles),
            default=0
        )
        target_max_level = max(
            (role.get_hierarchy_level() for role in target_roles),
            default=0
        )
        
        return admin_max_level > target_max_level
    
    def _is_valid_transition(self, current: UserStatus, new: UserStatus) -> bool:
        """Validate status transition rules."""
        # Define valid transitions
        valid_transitions = {
            UserStatus.PENDING_VERIFICATION: [
                UserStatus.ACTIVE,
                UserStatus.SUSPENDED,
                UserStatus.TERMINATED
            ],
            UserStatus.ACTIVE: [
                UserStatus.SUSPENDED,
                UserStatus.LOCKED,
                UserStatus.DEACTIVATED,
                UserStatus.TERMINATED
            ],
            UserStatus.SUSPENDED: [
                UserStatus.ACTIVE,
                UserStatus.LOCKED,
                UserStatus.TERMINATED
            ],
            UserStatus.LOCKED: [
                UserStatus.ACTIVE,
                UserStatus.SUSPENDED,
                UserStatus.TERMINATED
            ],
            UserStatus.DEACTIVATED: [
                UserStatus.ACTIVE,
                UserStatus.TERMINATED
            ],
            UserStatus.TERMINATED: []  # Terminal state
        }
        
        return new in valid_transitions.get(current, [])
    
    async def _check_security_implications(
        self,
        user: User,
        new_status: UserStatus,
        reason: str
    ) -> None:
        """Check security implications of status change."""
        # Check for recent suspicious activity
        recent_events = await self._security_service.get_recent_security_events(
            user.id,
            days=7
        )
        
        if recent_events and new_status == UserStatus.ACTIVE:
            # Reactivating user with recent security issues
            high_risk_events = [
                e for e in recent_events
                if e.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            ]
            
            if high_risk_events:
                # Log warning but allow with audit
                await self._audit_service.log_audit_event(
                    AuditContext(
                        actor_id=None,
                        action=AuditAction.SECURITY_ALERT,
                        resource_type="user",
                        resource_id=str(user.id),
                        details={
                            "warning": "Reactivating user with recent security events",
                            "security_events": len(high_risk_events),
                            "reason": reason
                        }
                    )
                )
    
    def _get_email_template(self, status: UserStatus) -> str:
        """Get email template for status change."""
        templates = {
            UserStatus.ACTIVE: "account_activated",
            UserStatus.SUSPENDED: "account_suspended",
            UserStatus.LOCKED: "account_locked",
            UserStatus.DEACTIVATED: "account_deactivated",
            UserStatus.TERMINATED: "account_terminated"
        }
        return templates.get(status, "account_status_changed")
    
    async def _publish_status_event(
        self,
        user_id: UUID,
        old_status: UserStatus,
        new_status: UserStatus,
        changed_by: UUID,
        reason: str
    ) -> None:
        """Publish appropriate domain event for status change."""
        # Base event
        await self._event_bus.publish(
            UserStatusChanged(
                aggregate_id=user_id,
                old_status=old_status,
                new_status=new_status,
                changed_by=changed_by,
                reason=reason
            )
        )
        
        # Specific events
        event_map = {
            UserStatus.SUSPENDED: UserSuspended,
            UserStatus.LOCKED: UserLocked,
            UserStatus.ACTIVE: UserActivated,
            UserStatus.DEACTIVATED: UserDeactivated,
            UserStatus.TERMINATED: UserTerminated
        }
        
        event_class = event_map.get(new_status)
        if event_class:
            await self._event_bus.publish(
                event_class(
                    aggregate_id=user_id,
                    reason=reason,
                    changed_by=changed_by
                )
            )