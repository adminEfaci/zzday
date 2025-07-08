"""
Revoke permission command implementation.

Handles revoking specific permissions from users.
"""

from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CommandHandlerDependencies,
    PermissionRevocationParams,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import RevokePermissionRequest
from app.modules.identity.application.dtos.response import PermissionRevocationResponse
from app.modules.identity.domain.entities import Permission, User, UserPermission
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    PermissionType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import PermissionRevoked
from app.modules.identity.domain.exceptions import (
    CriticalPermissionError,
    PermissionNotAssignedError,
    PermissionNotFoundError,
    UnauthorizedError,
    UserNotFoundError,
)


class RevokePermissionCommand(Command[PermissionRevocationResponse]):
    """Command to revoke a permission from a user."""
    
    def __init__(self, params: PermissionRevocationParams):
        self.params = params
        # Initialize metadata if None
        self.params.metadata = params.metadata or {}


class RevokePermissionCommandHandler(CommandHandler[RevokePermissionCommand, PermissionRevocationResponse]):
    """Handler for revoking permissions from users."""
    
    def __init__(self, dependencies: CommandHandlerDependencies, **kwargs: Any):
        # Repository dependencies
        self._user_repository = dependencies.repositories.user_repository
        self._permission_repository = dependencies.repositories.permission_repository
        self._user_permission_repository = kwargs.get('user_permission_repository')
        self._session_repository = dependencies.repositories.session_repository
        
        # Service dependencies
        self._authorization_service = dependencies.services.authorization_service
        self._security_service = dependencies.services.security_service
        self._session_service = kwargs.get('session_service')
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._email_service = dependencies.services.email_service
        
        # Infrastructure dependencies
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_REVOKED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(RevokePermissionRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "permissions.revoke",
        resource_type="permission",
        resource_id_param="permission_id"
    )
    @require_mfa()
    async def handle(self, command: RevokePermissionCommand) -> PermissionRevocationResponse:
        """
        Revoke permission from user with cascade handling.
        
        Process:
        1. Validate revoker privileges
        2. Load user and permission
        3. Check grant exists
        4. Validate revocation safety
        5. Check dependencies
        6. Revoke permission
        7. Handle cascades
        8. Update caches
        9. Send notifications
        
        Returns:
            PermissionRevocationResponse with revocation details
            
        Raises:
            UserNotFoundError: If user not found
            PermissionNotFoundError: If permission not found
            UnauthorizedError: If lacks permission
            PermissionNotAssignedError: If not assigned
            CriticalPermissionError: If critical permission
        """
        async with self._unit_of_work:
            # 1. Load revoker (admin user)
            revoker = await self._user_repository.get_by_id(command.revoked_by)
            if not revoker:
                raise UnauthorizedError("Revoker not found")
            
            # 2. Load target user
            user = await self._user_repository.get_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 3. Load permission
            permission = await self._permission_repository.get_by_id(command.permission_id)
            if not permission:
                raise PermissionNotFoundError(f"Permission {command.permission_id} not found")
            
            # 4. Find grant
            grant = await self._user_permission_repository.find_by_user_and_permission(
                command.user_id,
                command.permission_id,
                command.resource_type,
                command.resource_id
            )
            
            if not grant or not grant.is_active:
                raise PermissionNotAssignedError(
                    f"User does not have permission '{permission.name}'"
                    f"{' for resource ' + str(command.resource_id) if command.resource_id else ''}"
                )
            
            # 5. Validate revoker can revoke this permission
            await self._validate_revoke_authority(revoker, permission, grant, command)
            
            # 6. Check if permission is critical
            if permission.is_critical and not command.force_revoke:
                raise CriticalPermissionError(
                    f"Permission '{permission.name}' is critical and cannot be revoked without force flag"
                )
            
            # 7. Check for dependent permissions
            dependent_permissions = []
            if command.cascade_dependent:
                dependent_permissions = await self._find_dependent_permissions(
                    user.id,
                    permission
                )
            
            # 8. Check impact on user access
            access_impact = await self._analyze_revocation_impact(
                user.id,
                permission,
                dependent_permissions
            )
            
            # 9. Store pre-revocation state
            pre_revocation_state = {
                "total_permissions": await self._user_permission_repository.count_by_user(user.id),
                "active_sessions": await self._session_repository.count_active_by_user(user.id)
            }
            
            # 10. Revoke the permission
            grant.revoke(command.revoked_by, command.reason)
            await self._user_permission_repository.update(grant)
            
            # 11. Handle cascade effects
            cascaded_items = {
                "permissions": [],
                "sessions": 0
            }
            
            if command.cascade_dependent and dependent_permissions:
                cascaded_items["permissions"] = await self._cascade_dependent_permissions(
                    user.id,
                    dependent_permissions,
                    command
                )
            
            # 12. Update user's cached permissions
            await self._authorization_service.refresh_user_permissions(user.id)
            
            # 13. Revoke sessions if requested
            if command.revoke_sessions and access_impact["requires_reauthentication"]:
                sessions = await self._session_repository.get_active_sessions(user.id)
                for session in sessions:
                    await self._session_service.revoke_session(
                        session.id,
                        f"Permission '{permission.name}' revoked"
                    )
                    cascaded_items["sessions"] += 1
            
            # 14. Log security event for sensitive permissions
            if permission.is_sensitive or permission.type == PermissionType.SYSTEM:
                await self._log_sensitive_revocation(
                    user,
                    permission,
                    revoker,
                    command,
                    cascaded_items
                )
            
            # 15. Send notifications
            if command.notify_user:
                await self._send_revocation_notification(
                    user,
                    permission,
                    revoker,
                    command,
                    {"cascaded_items": cascaded_items, "access_impact": access_impact}
                )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                PermissionRevoked(
                    aggregate_id=user.id,
                    permission_id=permission.id,
                    permission_name=permission.name,
                    revoked_by=revoker.id,
                    reason=command.reason,
                    resource_type=command.resource_type,
                    resource_id=command.resource_id,
                    cascaded_permissions=len(cascaded_items["permissions"]),
                    sessions_revoked=cascaded_items["sessions"]
                )
            )
            
            # 17. Check minimum permission requirements
            await self._validate_minimum_permissions(user.id)
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Post-revocation analysis
            post_revocation_state = {
                "total_permissions": await self._user_permission_repository.count_by_user(user.id),
                "active_sessions": await self._session_repository.count_active_by_user(user.id)
            }
            
            return PermissionRevocationResponse(
                user_id=user.id,
                permission_id=permission.id,
                permission_name=permission.name,
                revoked_at=grant.revoked_at,
                revoked_by=grant.revoked_by,
                reason=grant.revocation_reason,
                resource_type=command.resource_type,
                resource_id=command.resource_id,
                cascaded_permissions=[p["name"] for p in cascaded_items["permissions"]],
                sessions_revoked=cascaded_items["sessions"],
                permissions_before=pre_revocation_state["total_permissions"],
                permissions_after=post_revocation_state["total_permissions"],
                access_impact=access_impact,
                message=f"Permission '{permission.name}' revoked successfully"
            )
    
    async def _validate_revoke_authority(
        self,
        revoker: User,
        permission: Permission,
        grant: UserPermission,
        command: RevokePermissionCommand
    ) -> None:
        """Validate revoker has authority to revoke this permission."""
        # Check if revoker granted it originally
        if grant.granted_by == revoker.id:
            return  # Can always revoke what you granted
        
        # Check if revoker has the permission themselves
        has_permission = await self._authorization_service.has_permission(
            revoker.id,
            permission.name,
            command.resource_type,
            command.resource_id
        )
        
        if not has_permission:
            # Check if revoker has revoke authority through role
            revoker_roles = await self._authorization_service.get_user_roles(revoker.id)
            can_revoke = False
            
            for role in revoker_roles:
                # Super admin can revoke anything
                if role.name == "super_admin":
                    can_revoke = True
                    break
                
                # Check if role can revoke this permission
                if permission.id in role.revokable_permissions:
                    can_revoke = True
                    break
                
                # Check if role has wildcard revoke
                role_permissions = await self._authorization_service.get_role_permissions(role.id)
                for role_perm in role_permissions:
                    if role_perm.name == f"{permission.resource_type}:revoke:*":
                        can_revoke = True
                        break
            
            if not can_revoke:
                raise UnauthorizedError(
                    f"You cannot revoke permission '{permission.name}' - insufficient authority"
                )
    
    async def _find_dependent_permissions(
        self,
        user_id: UUID,
        permission: Permission
    ) -> list[UserPermission]:
        """Find permissions that depend on this permission."""
        dependent_permissions = []
        
        # Get all user permissions
        user_permissions = await self._user_permission_repository.find_by_user(user_id)
        
        for user_perm in user_permissions:
            if not user_perm.is_active:
                continue
            
            perm = await self._permission_repository.get_by_id(user_perm.permission_id)
            if not perm or not perm.prerequisites:
                continue
            
            # Check if this permission is a prerequisite
            required_perms = perm.prerequisites.get("required_permissions", [])
            if permission.name in required_perms:
                dependent_permissions.append(user_perm)
        
        return dependent_permissions
    
    async def _analyze_revocation_impact(
        self,
        user_id: UUID,
        permission: Permission,
        dependent_permissions: list[UserPermission]
    ) -> dict[str, Any]:
        """Analyze the impact of revoking this permission."""
        impact = {
            "critical_functions_lost": [],
            "requires_reauthentication": False,
            "affected_resources": [],
            "severity": "low"
        }
        
        # Check if permission affects authentication
        if permission.resource_type == "auth" or permission.action in ["login", "authenticate"]:
            impact["requires_reauthentication"] = True
            impact["severity"] = "high"
        
        # Check critical functions
        critical_actions = ["delete", "admin", "system", "security"]
        if any(action in permission.action for action in critical_actions):
            impact["critical_functions_lost"].append(permission.name)
            impact["severity"] = "medium" if impact["severity"] == "low" else impact["severity"]
        
        # Add dependent permissions to impact
        for dep_perm in dependent_permissions:
            perm = await self._permission_repository.get_by_id(dep_perm.permission_id)
            if perm:
                impact["critical_functions_lost"].append(perm.name)
        
        # Check affected resources
        if permission.resource_type:
            # Count resources user can no longer access
            resource_count = await self._count_affected_resources(
                user_id,
                permission
            )
            if resource_count > 0:
                impact["affected_resources"].append({
                    "type": permission.resource_type,
                    "count": resource_count
                })
        
        return impact
    
    async def _cascade_dependent_permissions(
        self,
        user_id: UUID,
        dependent_permissions: list[UserPermission],
        command: RevokePermissionCommand
    ) -> list[dict[str, Any]]:
        """Cascade revoke dependent permissions."""
        cascaded = []
        
        for dep_grant in dependent_permissions:
            try:
                # Revoke the dependent permission
                dep_grant.revoke(
                    command.revoked_by,
                    f"Cascaded: Prerequisite permission revoked - {command.reason}"
                )
                await self._user_permission_repository.update(dep_grant)
                
                # Get permission details
                perm = await self._permission_repository.get_by_id(dep_grant.permission_id)
                if perm:
                    cascaded.append({
                        "id": str(perm.id),
                        "name": perm.name
                    })
                    
            except Exception as e:
                # Log but continue with other cascades
                await self._audit_service.log_error(
                    f"Failed to cascade revoke permission {dep_grant.permission_id}: {e!s}"
                )
        
        return cascaded
    
    async def _validate_minimum_permissions(self, user_id: UUID) -> None:
        """Ensure user still has minimum required permissions."""
        # Check if user has at least basic permissions
        basic_permissions = ["profile:read", "settings:read"]
        
        for basic_perm in basic_permissions:
            has_perm = await self._authorization_service.has_permission(
                user_id,
                basic_perm
            )
            
            if not has_perm:
                # User missing basic permissions - flag for review
                await self._notification_service.create_notification(
                    NotificationContext(
                        notification_id=UUID(),
                        recipient_id=user_id,
                        notification_type=NotificationType.PERMISSION_REVIEW_REQUIRED,
                        channel="in_app",
                        template_id="missing_basic_permissions",
                        template_data={
                            "missing_permission": basic_perm
                        },
                        priority="high"
                    )
                )
    
    async def _count_affected_resources(
        self,
        user_id: UUID,
        permission: Permission
    ) -> int:
        """Count resources that will be affected by permission revocation."""
        # This would query the actual resources
        # For now, return a mock count
        return 0
    
    async def _log_sensitive_revocation(
        self,
        user: User,
        permission: Permission,
        revoker: User,
        command: RevokePermissionCommand,
        cascaded_items: dict[str, Any]
    ) -> None:
        """Log revocation of sensitive permissions."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SENSITIVE_PERMISSION_REVOKE,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                details={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "permission_type": permission.type.value,
                    "revoked_by": str(revoker.id),
                    "revoker_name": revoker.username,
                    "reason": command.reason,
                    "resource": f"{command.resource_type}:{command.resource_id}" if command.resource_id else None,
                    "cascaded_permissions": [p["name"] for p in cascaded_items["permissions"]],
                    "sessions_revoked": cascaded_items["sessions"]
                },
                indicators=["sensitive_permission_revocation"],
                recommended_actions=[
                    "Review revocation justification",
                    "Monitor user access attempts"
                ]
            )
        )
        
        # Notify security team for system permissions
        if permission.type == PermissionType.SYSTEM:
            await self._notification_service.notify_security_team(
                "System Permission Revoked",
                {
                    "user": user.username,
                    "permission": permission.name,
                    "revoked_by": revoker.username,
                    "reason": command.reason,
                    "impact": {
                        "cascaded": len(cascaded_items["permissions"]),
                        "sessions": cascaded_items["sessions"]
                    }
                }
            )
    
    async def _send_revocation_notification(
        self,
        user: User,
        permission: Permission,
        revoker: User,
        command: RevokePermissionCommand,
        impact_data: dict[str, Any]
    ) -> None:
        """Send notification about permission revocation."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="permission_revoked",
                    subject=f"Permission Revoked: {permission.name}",
                    variables={
                        "username": user.username,
                        "permission_name": permission.name,
                        "revoked_by": f"{revoker.first_name} {revoker.last_name}",
                        "reason": command.reason,
                        "resource": f"{command.resource_type} {command.resource_id}" if command.resource_id else None,
                        "cascaded_permissions": [p["name"] for p in impact_data["cascaded_items"]["permissions"]],
                        "critical_functions_lost": impact_data["access_impact"]["critical_functions_lost"],
                        "requires_reauth": impact_data["access_impact"]["requires_reauthentication"],
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.PERMISSION_REVOKED,
                channel="in_app",
                template_id="permission_revoked",
                template_data={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "revoked_by": str(revoker.id),
                    "reason": command.reason,
                    "impact_summary": {
                        "cascaded": len(impact_data["cascaded_items"]["permissions"]),
                        "sessions": impact_data["cascaded_items"]["sessions"],
                        "severity": impact_data["access_impact"]["severity"]
                    }
                },
                priority="high" if impact_data["access_impact"]["severity"] == "high" else "medium"
            )
        )