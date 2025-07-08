"""
Grant permission command implementation.

Handles granting specific permissions to users directly.
"""

from datetime import UTC, datetime
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
    PermissionGrantParams,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import GrantPermissionRequest
from app.modules.identity.application.dtos.response import PermissionGrantResponse
from app.modules.identity.domain.entities import Permission, User, UserPermission
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    PermissionType,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import PermissionGranted
from app.modules.identity.domain.exceptions import (
    ConflictingPermissionError,
    InvalidOperationError,
    PermissionAlreadyGrantedError,
    PermissionNotFoundError,
    UnauthorizedError,
    UserNotFoundError,
)


class GrantPermissionCommand(Command[PermissionGrantResponse]):
    """Command to grant a permission to a user."""
    
    def __init__(self, params: PermissionGrantParams, **kwargs: Any):
        self.params = params
        # Initialize empty dicts if None
        self.params.conditions = params.conditions or {}
        self.params.metadata = params.metadata or {}
        # Additional parameters not in base DTO
        self.resource_type = kwargs.get('resource_type')
        self.resource_id = kwargs.get('resource_id')
        self.notify_user = kwargs.get('notify_user', True)
        self.override_conflicts = kwargs.get('override_conflicts', False)


class GrantPermissionCommandHandler(CommandHandler[GrantPermissionCommand, PermissionGrantResponse]):
    """Handler for granting permissions to users."""
    
    def __init__(self, dependencies: CommandHandlerDependencies, **kwargs: Any):
        # Repository dependencies
        self._user_repository = dependencies.repositories.user_repository
        self._permission_repository = dependencies.repositories.permission_repository
        self._user_permission_repository = kwargs.get('user_permission_repository')
        
        # Service dependencies
        self._authorization_service = dependencies.services.authorization_service
        self._security_service = dependencies.services.security_service
        self._validation_service = dependencies.services.validation_service
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._email_service = dependencies.services.email_service
        
        # Infrastructure dependencies
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_GRANTED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(GrantPermissionRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "permissions.grant",
        resource_type="permission",
        resource_id_param="permission_id"
    )
    @require_mfa()
    async def handle(self, command: GrantPermissionCommand) -> PermissionGrantResponse:
        """
        Grant permission to user with validation.
        
        Process:
        1. Validate grantor privileges
        2. Load user and permission
        3. Check for existing grant
        4. Validate conflicts
        5. Check resource access
        6. Create grant
        7. Send notifications
        8. Log if sensitive
        
        Returns:
            PermissionGrantResponse with grant details
            
        Raises:
            UserNotFoundError: If user not found
            PermissionNotFoundError: If permission not found
            UnauthorizedError: If lacks permission
            PermissionAlreadyGrantedError: If already granted
            ConflictingPermissionError: If conflicts exist
        """
        async with self._unit_of_work:
            # 1. Load grantor (admin user)
            grantor = await self._user_repository.get_by_id(command.granted_by)
            if not grantor:
                raise UnauthorizedError("Grantor not found")
            
            # 2. Load target user
            user = await self._user_repository.get_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 3. Load permission
            permission = await self._permission_repository.get_by_id(command.permission_id)
            if not permission:
                raise PermissionNotFoundError(f"Permission {command.permission_id} not found")
            
            # 4. Check if user is active
            if user.status != UserStatus.ACTIVE:
                raise InvalidOperationError(
                    f"Cannot grant permission to user with status: {user.status.value}"
                )
            
            # 5. Check if already granted
            existing = await self._user_permission_repository.find_by_user_and_permission(
                command.user_id,
                command.permission_id,
                command.resource_type,
                command.resource_id
            )
            
            if existing and existing.is_active:
                raise PermissionAlreadyGrantedError(
                    f"User already has permission '{permission.name}'"
                    f"{' for resource ' + str(command.resource_id) if command.resource_id else ''}"
                )
            
            # 6. Validate grantor can grant this permission
            await self._validate_grant_authority(grantor, permission, command)
            
            # 7. Check for conflicting permissions
            if not command.override_conflicts:
                conflicts = await self._check_permission_conflicts(
                    user.id,
                    permission,
                    command.resource_type,
                    command.resource_id
                )
                if conflicts:
                    raise ConflictingPermissionError(
                        f"Permission conflicts with: {', '.join(conflicts)}"
                    )
            
            # 8. Validate resource access if specified
            if command.resource_type and command.resource_id:
                await self._validate_resource_access(
                    grantor,
                    command.resource_type,
                    command.resource_id
                )
            
            # 9. Check permission prerequisites
            if permission.prerequisites:
                await self._check_prerequisites(user, permission)
            
            # 10. Create permission grant
            user_permission = UserPermission(
                user_id=command.user_id,
                permission_id=command.permission_id,
                granted_by=command.granted_by,
                granted_at=datetime.now(UTC),
                expires_at=command.expires_at,
                resource_type=command.resource_type,
                resource_id=command.resource_id,
                reason=command.reason,
                conditions=command.conditions,
                metadata=command.metadata
            )
            
            # 11. Save grant
            await self._user_permission_repository.create(user_permission)
            
            # 12. Update user's cached permissions
            await self._authorization_service.refresh_user_permissions(command.user_id)
            
            # 13. Calculate effective scope
            effective_scope = self._calculate_effective_scope(
                permission,
                command.resource_type,
                command.resource_id
            )
            
            # 14. Send notifications
            if command.notify_user:
                await self._send_grant_notification(
                    user,
                    permission,
                    grantor,
                    command,
                    effective_scope
                )
            
            # 15. Log if sensitive permission
            if permission.is_sensitive or permission.type == PermissionType.SYSTEM:
                await self._log_sensitive_grant(
                    user,
                    permission,
                    grantor,
                    command
                )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                PermissionGranted(
                    aggregate_id=user.id,
                    permission_id=permission.id,
                    permission_name=permission.name,
                    granted_by=grantor.id,
                    resource_type=command.resource_type,
                    resource_id=command.resource_id,
                    expires_at=command.expires_at
                )
            )
            
            # 17. Schedule expiration if needed
            if command.expires_at:
                await self._schedule_permission_expiration(
                    user_permission.id,
                    command.expires_at
                )
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Check for permission escalation
            await self._check_permission_escalation(user.id, permission)
            
            return PermissionGrantResponse(
                grant_id=user_permission.id,
                user_id=user.id,
                permission_id=permission.id,
                permission_name=permission.name,
                permission_type=permission.type,
                granted_at=user_permission.granted_at,
                expires_at=user_permission.expires_at,
                resource_type=user_permission.resource_type,
                resource_id=user_permission.resource_id,
                effective_scope=effective_scope,
                implied_permissions=await self._get_implied_permissions(permission.id),
                message=f"Permission '{permission.name}' granted successfully"
            )
    
    async def _validate_grant_authority(
        self,
        grantor: User,
        permission: Permission,
        command: GrantPermissionCommand
    ) -> None:
        """Validate grantor has authority to grant this permission."""
        # Check if grantor has the permission themselves
        has_permission = await self._authorization_service.has_permission(
            grantor.id,
            permission.name,
            command.resource_type,
            command.resource_id
        )
        
        if not has_permission:
            # Check if grantor has grant authority through role
            grantor_roles = await self._authorization_service.get_user_roles(grantor.id)
            can_grant = False
            
            for role in grantor_roles:
                # Super admin can grant anything
                if role.name == "super_admin":
                    can_grant = True
                    break
                
                # Check if role can grant this permission
                if permission.id in role.grantable_permissions:
                    can_grant = True
                    break
                
                # Check if role has wildcard grant
                role_permissions = await self._authorization_service.get_role_permissions(role.id)
                for role_perm in role_permissions:
                    if role_perm.name == f"{permission.resource_type}:grant:*":
                        can_grant = True
                        break
            
            if not can_grant:
                raise UnauthorizedError(
                    f"You cannot grant permission '{permission.name}' - "
                    "you must have the permission yourself or explicit grant authority"
                )
    
    async def _check_permission_conflicts(
        self,
        user_id: UUID,
        permission: Permission,
        resource_type: str | None,
        resource_id: UUID | None
    ) -> list[str]:
        """Check for conflicting permissions."""
        conflicts = []
        
        # Get user's current permissions
        current_permissions = await self._authorization_service.get_user_permissions(user_id)
        
        # Check mutual exclusions
        if permission.mutually_exclusive_with:
            for current in current_permissions:
                if current.id in permission.mutually_exclusive_with:
                    # Check if same resource scope
                    if resource_type and resource_id:
                        user_perm = await self._user_permission_repository.find_by_user_and_permission(
                            user_id,
                            current.id,
                            resource_type,
                            resource_id
                        )
                        if user_perm and user_perm.is_active:
                            conflicts.append(current.name)
                    else:
                        conflicts.append(current.name)
        
        # Check deny permissions
        for current in current_permissions:
            if current.type == PermissionType.DENY and current.resource_type == permission.resource_type:
                # Deny permissions override allow permissions
                if current.action in (permission.action, "*"):
                    conflicts.append(f"DENY:{current.name}")
        
        return conflicts
    
    async def _validate_resource_access(
        self,
        grantor: User,
        resource_type: str,
        resource_id: UUID
    ) -> None:
        """Validate grantor has access to the resource."""
        # Check if grantor can access the resource
        has_access = await self._authorization_service.has_permission(
            grantor.id,
            f"{resource_type}:read",
            resource_type,
            resource_id
        )
        
        if not has_access:
            # Check ownership
            is_owner = await self._check_resource_ownership(
                grantor.id,
                resource_type,
                resource_id
            )
            
            if not is_owner:
                raise UnauthorizedError(
                    f"You do not have access to {resource_type} {resource_id}"
                )
    
    async def _check_prerequisites(
        self,
        user: User,
        permission: Permission
    ) -> None:
        """Check if user meets permission prerequisites."""
        if not permission.prerequisites:
            return
        
        # Check required permissions
        required_permissions = permission.prerequisites.get("required_permissions", [])
        for req_perm_name in required_permissions:
            has_perm = await self._authorization_service.has_permission(
                user.id,
                req_perm_name
            )
            if not has_perm:
                raise InvalidOperationError(
                    f"User missing prerequisite permission: {req_perm_name}"
                )
        
        # Check account features
        required_features = permission.prerequisites.get("required_features", [])
        user_features = user.metadata.get("features", [])
        missing_features = [f for f in required_features if f not in user_features]
        
        if missing_features:
            raise InvalidOperationError(
                f"User missing required features: {', '.join(missing_features)}"
            )
        
        # Check security requirements
        if permission.prerequisites.get("require_mfa"):
            mfa_enabled = await self._security_service.is_mfa_enabled(user.id)
            if not mfa_enabled:
                raise InvalidOperationError(
                    "Multi-factor authentication required for this permission"
                )
    
    def _calculate_effective_scope(
        self,
        permission: Permission,
        resource_type: str | None,
        resource_id: UUID | None
    ) -> str:
        """Calculate the effective scope of the permission grant."""
        if resource_type and resource_id:
            return f"{resource_type}:{resource_id}"
        if resource_type:
            return f"{resource_type}:*"
        return "global"
    
    async def _get_implied_permissions(self, permission_id: UUID) -> list[str]:
        """Get permissions implied by this permission."""
        permission = await self._permission_repository.get_by_id(permission_id)
        if not permission or not permission.implies:
            return []
        
        implied_names = []
        for implied_id in permission.implies:
            implied_perm = await self._permission_repository.get_by_id(implied_id)
            if implied_perm:
                implied_names.append(implied_perm.name)
        
        return implied_names
    
    async def _check_resource_ownership(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: UUID
    ) -> bool:
        """Check if user owns the resource."""
        # This would be implemented based on resource type
        # For now, return False
        return False
    
    async def _send_grant_notification(
        self,
        user: User,
        permission: Permission,
        grantor: User,
        command: GrantPermissionCommand,
        effective_scope: str
    ) -> None:
        """Send notification about permission grant."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="permission_granted",
                    subject=f"New Permission Granted: {permission.name}",
                    variables={
                        "username": user.username,
                        "permission_name": permission.name,
                        "permission_description": permission.description,
                        "granted_by": f"{grantor.first_name} {grantor.last_name}",
                        "reason": command.reason,
                        "scope": effective_scope,
                        "expires_at": command.expires_at.isoformat() if command.expires_at else None,
                        "resource": f"{command.resource_type} {command.resource_id}" if command.resource_id else None
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.PERMISSION_GRANTED,
                channel="in_app",
                template_id="permission_granted",
                template_data={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "granted_by": str(grantor.id),
                    "scope": effective_scope
                },
                priority="medium"
            )
        )
    
    async def _log_sensitive_grant(
        self,
        user: User,
        permission: Permission,
        grantor: User,
        command: GrantPermissionCommand
    ) -> None:
        """Log grant of sensitive permissions."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SENSITIVE_PERMISSION_GRANT,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                details={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "permission_type": permission.type.value,
                    "granted_by": str(grantor.id),
                    "grantor_name": grantor.username,
                    "reason": command.reason,
                    "resource": f"{command.resource_type}:{command.resource_id}" if command.resource_id else None,
                    "expires_at": command.expires_at.isoformat() if command.expires_at else None
                },
                indicators=["sensitive_permission"],
                recommended_actions=[
                    "Monitor permission usage",
                    "Review grant justification"
                ]
            )
        )
        
        # Notify security team for system permissions
        if permission.type == PermissionType.SYSTEM:
            await self._notification_service.notify_security_team(
                "System Permission Granted",
                {
                    "user": user.username,
                    "permission": permission.name,
                    "granted_by": grantor.username,
                    "reason": command.reason
                }
            )
    
    async def _schedule_permission_expiration(
        self,
        grant_id: UUID,
        expires_at: datetime
    ) -> None:
        """Schedule automatic permission expiration."""
        # This would use a job scheduler to revoke the permission
        # when it expires
    
    async def _check_permission_escalation(
        self,
        user_id: UUID,
        new_permission: Permission
    ) -> None:
        """Check if this grant creates privilege escalation."""
        # Get user's permission count
        permission_count = await self._user_permission_repository.count_by_user(user_id)
        
        # Check for rapid permission accumulation
        recent_grants = await self._user_permission_repository.find_recent_grants(
            user_id,
            days=7
        )
        
        if len(recent_grants) > 10:
            # Flag for review
            await self._security_service.flag_for_review(
                user_id,
                "Rapid permission accumulation detected",
                {
                    "recent_grants": len(recent_grants),
                    "total_permissions": permission_count,
                    "latest_permission": new_permission.name
                }
            )