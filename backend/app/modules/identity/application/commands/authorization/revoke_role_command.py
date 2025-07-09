"""
Revoke role command implementation.

Handles removing roles from users with cascade effects.
"""

from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import RevokeRoleRequest
from app.modules.identity.application.dtos.response import RoleRevocationResponse
from app.modules.identity.domain.entities import Role, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import RoleRevoked
from app.modules.identity.domain.exceptions import (
    HierarchyViolationError,
    InvalidOperationError,
    RoleNotAssignedError,
    RoleNotFoundError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.role_repository import (
    IRoleRepository,
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
from app.modules.identity.domain.services import (
    AuthorizationService,
    SecurityService,
    SessionService,
)


class RevokeRoleCommand(Command[RoleRevocationResponse]):
    """Command to revoke a role from a user."""
    
    def __init__(
        self,
        user_id: UUID,
        role_id: UUID,
        revoked_by: UUID,
        reason: str,
        scope: str | None = None,
        cascade_permissions: bool = True,
        force_revoke: bool = False,
        revoke_sessions: bool = True,
        notify_user: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.user_id = user_id
        self.role_id = role_id
        self.revoked_by = revoked_by
        self.reason = reason
        self.scope = scope
        self.cascade_permissions = cascade_permissions
        self.force_revoke = force_revoke
        self.revoke_sessions = revoke_sessions
        self.notify_user = notify_user
        self.metadata = metadata or {}


class RevokeRoleCommandHandler(CommandHandler[RevokeRoleCommand, RoleRevocationResponse]):
    """Handler for revoking roles from users."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        role_repository: IRoleRepository,
        user_role_repository: IUserRoleRepository,
        session_repository: ISessionRepository,
        authorization_service: AuthorizationService,
        security_service: SecurityService,
        session_service: SessionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._role_repository = role_repository
        self._user_role_repository = user_role_repository
        self._session_repository = session_repository
        self._authorization_service = authorization_service
        self._security_service = security_service
        self._session_service = session_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.ROLE_REVOKED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(RevokeRoleRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "roles.revoke",
        resource_type="role",
        resource_id_param="role_id"
    )
    @require_mfa()
    async def handle(self, command: RevokeRoleCommand) -> RoleRevocationResponse:
        """
        Revoke role from user with cascade handling.
        
        Process:
        1. Validate revoker privileges
        2. Load user and role
        3. Check assignment exists
        4. Validate hierarchy
        5. Check dependencies
        6. Revoke role
        7. Handle cascades
        8. Revoke sessions if needed
        9. Send notifications
        
        Returns:
            RoleRevocationResponse with revocation details
            
        Raises:
            UserNotFoundError: If user not found
            RoleNotFoundError: If role not found
            UnauthorizedError: If lacks permission
            RoleNotAssignedError: If role not assigned
            HierarchyViolationError: If violates hierarchy
        """
        async with self._unit_of_work:
            # 1. Load revoker (admin user)
            revoker = await self._user_repository.find_by_id(command.revoked_by)
            if not revoker:
                raise UnauthorizedError("Revoker not found")
            
            # 2. Load target user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 3. Load role
            role = await self._role_repository.find_by_id(command.role_id)
            if not role:
                raise RoleNotFoundError(f"Role {command.role_id} not found")
            
            # 4. Find assignment
            assignment = await self._user_role_repository.find_by_user_and_role(
                command.user_id,
                command.role_id,
                command.scope
            )
            
            if not assignment or not assignment.is_active:
                raise RoleNotAssignedError(
                    f"User does not have role '{role.name}'"
                    f"{' in scope ' + command.scope if command.scope else ''}"
                )
            
            # 5. Validate hierarchy
            if not command.force_revoke:
                await self._validate_hierarchy(revoker, user, role)
            
            # 6. Check for protected roles
            if role.is_protected and not command.force_revoke:
                raise InvalidOperationError(
                    f"Role '{role.name}' is protected and cannot be revoked"
                )
            
            # 7. Check dependencies
            dependent_permissions = []
            if command.cascade_permissions:
                dependent_permissions = await self._check_dependent_permissions(
                    user.id,
                    role.id
                )
            
            # 8. Store pre-revocation state
            pre_revocation_state = {
                "permissions": await self._authorization_service.find_by_user(user.id),
                "roles": await self._authorization_service.find_by_user(user.id),
                "sessions": await self._session_repository.count_active_by_user(user.id)
            }
            
            # 9. Revoke the role
            assignment.revoke(command.revoked_by, command.reason)
            await self._user_role_repository.update(assignment)
            
            # 10. Handle cascade effects
            cascaded_items = {
                "permissions": [],
                "sessions": 0,
                "child_roles": []
            }
            
            if command.cascade_permissions:
                # Remove permissions that were only granted by this role
                cascaded_items["permissions"] = await self._cascade_permissions(
                    user.id,
                    role.id,
                    dependent_permissions
                )
            
            # 11. Check for child roles that depend on this role
            child_roles = await self._cascade_child_roles(user.id, role.id)
            cascaded_items["child_roles"] = child_roles
            
            # 12. Update user's cached permissions
            await self._authorization_service.refresh_user_permissions(user.id)
            
            # 13. Revoke sessions if requested
            if command.revoke_sessions and role.revoke_sessions_on_removal:
                sessions = await self._session_repository.find_active_by_user(user.id)
                for session in sessions:
                    await self._session_service.revoke_session(
                        session.id,
                        f"Role '{role.name}' revoked"
                    )
                    cascaded_items["sessions"] += 1
            
            # 14. Log security event for high-privilege revocation
            if role.is_high_privilege():
                await self._log_high_privilege_revocation(
                    user,
                    role,
                    revoker,
                    command,
                    cascaded_items
                )
            
            # 15. Send notifications
            if command.notify_user:
                await self._send_revocation_notification(
                    user,
                    role,
                    revoker,
                    command,
                    cascaded_items
                )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                RoleRevoked(
                    aggregate_id=user.id,
                    role_id=role.id,
                    role_name=role.name,
                    revoked_by=revoker.id,
                    reason=command.reason,
                    cascaded_permissions=len(cascaded_items["permissions"]),
                    sessions_revoked=cascaded_items["sessions"]
                )
            )
            
            # 17. Check if user still has required roles
            await self._validate_role_requirements(user.id)
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Post-revocation analysis
            post_revocation_state = {
                "permissions": await self._authorization_service.find_by_user(user.id),
                "roles": await self._authorization_service.find_by_user(user.id),
                "sessions": await self._session_repository.count_active_by_user(user.id)
            }
            
            return RoleRevocationResponse(
                user_id=user.id,
                role_id=role.id,
                role_name=role.name,
                revoked_at=assignment.revoked_at,
                revoked_by=assignment.revoked_by,
                reason=assignment.revocation_reason,
                cascaded_permissions=cascaded_items["permissions"],
                cascaded_roles=[r["name"] for r in cascaded_items["child_roles"]],
                sessions_revoked=cascaded_items["sessions"],
                permissions_before=len(pre_revocation_state["permissions"]),
                permissions_after=len(post_revocation_state["permissions"]),
                message=f"Role '{role.name}' revoked successfully"
            )
    
    async def _validate_hierarchy(
        self,
        revoker: User,
        target_user: User,
        role: Role
    ) -> None:
        """Validate role revocation follows hierarchy rules."""
        # Get revoker's roles
        revoker_roles = await self._authorization_service.find_by_user(revoker.id)
        
        # Check if revoker can revoke this role
        can_revoke = False
        for revoker_role in revoker_roles:
            # Super admin can revoke any role
            if revoker_role.name == "super_admin":
                can_revoke = True
                break
            
            # Check if revoker's role can revoke this role
            if role.id in revoker_role.revokable_roles:
                can_revoke = True
                break
            
            # Check hierarchy level
            if revoker_role.hierarchy_level > role.hierarchy_level:
                can_revoke = True
                break
        
        if not can_revoke:
            raise HierarchyViolationError(
                f"You cannot revoke role '{role.name}' - insufficient privileges"
            )
        
        # Prevent revoking roles from higher-level users
        target_roles = await self._authorization_service.find_by_user(target_user.id)
        target_max_level = max(
            (r.hierarchy_level for r in target_roles),
            default=0
        )
        
        revoker_max_level = max(
            (r.hierarchy_level for r in revoker_roles),
            default=0
        )
        
        if target_max_level >= revoker_max_level > 0:
            # Check if explicitly allowed
            allowed = any(
                role.id in r.revokable_roles
                for r in revoker_roles
            )
            if not allowed:
                raise HierarchyViolationError(
                    "Cannot revoke roles from users at or above your hierarchy level"
                )
    
    async def _check_dependent_permissions(
        self,
        user_id: UUID,
        role_id: UUID
    ) -> list[str]:
        """Check which permissions depend only on this role."""
        # Get all user's roles
        user_roles = await self._authorization_service.find_by_user(user_id)
        other_role_ids = [r.id for r in user_roles if r.id != role_id]
        
        # Get permissions from this role
        role_permissions = await self._authorization_service.find_by_role(role_id)
        role_permission_names = {p.name for p in role_permissions}
        
        # Get permissions from other roles
        other_permissions = set()
        for other_role_id in other_role_ids:
            perms = await self._authorization_service.find_by_role(other_role_id)
            other_permissions.update(p.name for p in perms)
        
        # Find permissions that will be lost
        dependent_permissions = role_permission_names - other_permissions
        
        return list(dependent_permissions)
    
    async def _cascade_permissions(
        self,
        user_id: UUID,
        role_id: UUID,
        dependent_permissions: list[str]
    ) -> list[str]:
        """Remove permissions that were only granted by this role."""
        # Remove directly granted permissions that match
        user_permissions = await self._authorization_service.find_direct_by_user(user_id)
        
        removed_permissions = []
        for permission in user_permissions:
            if permission.name in dependent_permissions:
                # Check if permission was granted as part of this role
                if permission.metadata.get("granted_via_role") == str(role_id):
                    await self._authorization_service.revoke_permission(
                        user_id,
                        permission.id,
                        reason="Cascaded from role revocation"
                    )
                    removed_permissions.append(permission.name)
        
        return removed_permissions
    
    async def _cascade_child_roles(
        self,
        user_id: UUID,
        parent_role_id: UUID
    ) -> list[dict[str, Any]]:
        """Remove child roles that depend on the parent role."""
        user_roles = await self._authorization_service.find_by_user(user_id)
        revoked_child_roles = []
        
        for user_role in user_roles:
            role = await self._role_repository.find_by_id(user_role.id)
            if not role:
                continue
            
            # Check if this role requires the parent role
            if role.prerequisites and parent_role_id in role.prerequisites.get("required_roles", []):
                # Revoke the child role
                assignment = await self._user_role_repository.find_by_user_and_role(
                    user_id,
                    role.id
                )
                if assignment and assignment.is_active:
                    assignment.revoke(
                        self._unit_of_work.current_user_id,
                        f"Cascaded: Parent role '{parent_role_id}' revoked"
                    )
                    await self._user_role_repository.update(assignment)
                    
                    revoked_child_roles.append({
                        "id": str(role.id),
                        "name": role.name
                    })
        
        return revoked_child_roles
    
    async def _validate_role_requirements(self, user_id: UUID) -> None:
        """Ensure user still meets all role requirements."""
        user_roles = await self._authorization_service.find_by_user(user_id)
        
        for user_role in user_roles:
            role = await self._role_repository.find_by_id(user_role.id)
            if not role or not role.prerequisites:
                continue
            
            # Check if prerequisites still met
            required_roles = role.prerequisites.get("required_roles", [])
            user_role_ids = {r.id for r in user_roles}
            
            missing_prerequisites = [
                req_id for req_id in required_roles
                if req_id not in user_role_ids
            ]
            
            if missing_prerequisites:
                # This role no longer meets prerequisites
                # Could auto-revoke or flag for review
                await self._notification_service.create_notification(
                    NotificationContext(
                        notification_id=UUID(),
                        recipient_id=user_id,
                        notification_type=NotificationType.ROLE_REVIEW_REQUIRED,
                        channel="in_app",
                        template_id="role_prerequisites_not_met",
                        template_data={
                            "role_name": role.name,
                            "missing_prerequisites": missing_prerequisites
                        },
                        priority="high"
                    )
                )
    
    async def _log_high_privilege_revocation(
        self,
        user: User,
        role: Role,
        revoker: User,
        command: RevokeRoleCommand,
        cascaded_items: dict[str, Any]
    ) -> None:
        """Log revocation of high-privilege roles."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_PRIVILEGE_REVOKE,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                details={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "revoked_by": str(revoker.id),
                    "revoker_name": revoker.username,
                    "reason": command.reason,
                    "cascaded_permissions": cascaded_items["permissions"],
                    "cascaded_roles": cascaded_items["child_roles"],
                    "sessions_revoked": cascaded_items["sessions"]
                },
                indicators=["high_privilege_revocation"],
                recommended_actions=[
                    "Review revocation justification",
                    "Monitor affected user activities"
                ]
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "High-Privilege Role Revoked",
            {
                "user": user.username,
                "role": role.name,
                "revoked_by": revoker.username,
                "reason": command.reason,
                "impact": {
                    "permissions_removed": len(cascaded_items["permissions"]),
                    "roles_cascaded": len(cascaded_items["child_roles"]),
                    "sessions_revoked": cascaded_items["sessions"]
                }
            }
        )
    
    async def _send_revocation_notification(
        self,
        user: User,
        role: Role,
        revoker: User,
        command: RevokeRoleCommand,
        cascaded_items: dict[str, Any]
    ) -> None:
        """Send notification about role revocation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="role_revoked",
                    subject=f"Role Revoked: {role.name}",
                    variables={
                        "username": user.username,
                        "role_name": role.name,
                        "revoked_by": f"{revoker.first_name} {revoker.last_name}",
                        "reason": command.reason,
                        "permissions_lost": cascaded_items["permissions"],
                        "child_roles_lost": [r["name"] for r in cascaded_items["child_roles"]],
                        "sessions_terminated": cascaded_items["sessions"] > 0,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.ROLE_REVOKED,
                channel="in_app",
                template_id="role_revoked",
                template_data={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "revoked_by": str(revoker.id),
                    "reason": command.reason,
                    "impact_summary": {
                        "permissions": len(cascaded_items["permissions"]),
                        "roles": len(cascaded_items["child_roles"]),
                        "sessions": cascaded_items["sessions"]
                    }
                },
                priority="high"
            )
        )