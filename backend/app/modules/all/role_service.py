"""Role Domain Service

Handles role and permission management with domain logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...entities.role.permission import Permission
from ...entities.role.role import Role
from ...entities.user.user_events import (
    UserRoleAssigned,
    UserRoleRemoved,
    UserPermissionGranted,
    UserPermissionRevoked,
)
from ...enums import PermissionAction, ResourceType
from ...value_objects.permission_scope import PermissionScope


class RoleService:
    """Domain service for role and permission operations."""
    
    @staticmethod
    def assign_role(
        user: User,
        role: Role,
        assigned_by: UUID,
        expires_at: datetime | None = None
    ) -> None:
        """
        Assign a role to a user.
        
        Args:
            user: User aggregate
            role: Role to assign
            assigned_by: ID of user performing assignment
            expires_at: Optional expiration time for the role
        """
        # Initialize roles collection if needed
        if not hasattr(user, '_roles'):
            user._roles = []
        
        # Check if user already has this role
        if any(r.id == role.id for r in user._roles):
            return
        
        # Add role to user
        user._roles.append(role)
        
        # Track role assignment metadata
        if not hasattr(user, 'role_assignments'):
            user.role_assignments = {}
        
        user.role_assignments[str(role.id)] = {
            "assigned_at": datetime.now(UTC),
            "assigned_by": str(assigned_by),
            "expires_at": expires_at.isoformat() if expires_at else None
        }
        
        user.updated_at = datetime.now(UTC)
        
        # Add domain event
        user.add_domain_event(UserRoleAssigned(
            user_id=user.id,
            role_id=role.id,
            role_name=role.name,
            assigned_by=assigned_by,
            expires_at=expires_at
        ))
    
    @staticmethod
    def remove_role(
        user: User,
        role_id: UUID,
        removed_by: UUID,
        reason: str | None = None
    ) -> None:
        """
        Remove a role from a user.
        
        Args:
            user: User aggregate
            role_id: ID of role to remove
            removed_by: ID of user performing removal
            reason: Optional reason for removal
        """
        if not hasattr(user, '_roles'):
            return
        
        # Find and remove role
        role_to_remove = None
        for role in user._roles:
            if role.id == role_id:
                role_to_remove = role
                break
        
        if not role_to_remove:
            return
        
        user._roles.remove(role_to_remove)
        
        # Remove assignment metadata
        if hasattr(user, 'role_assignments'):
            user.role_assignments.pop(str(role_id), None)
        
        user.updated_at = datetime.now(UTC)
        
        # Add domain event
        user.add_domain_event(UserRoleRemoved(
            user_id=user.id,
            role_id=role_id,
            role_name=role_to_remove.name,
            removed_by=removed_by,
            reason=reason
        ))
    
    @staticmethod
    def grant_permission(
        user: User,
        permission: Permission,
        granted_by: UUID,
        scope: PermissionScope | None = None,
        expires_at: datetime | None = None
    ) -> None:
        """
        Grant a specific permission to a user.
        
        Args:
            user: User aggregate
            permission: Permission to grant
            granted_by: ID of user granting permission
            scope: Optional permission scope
            expires_at: Optional expiration time
        """
        # Initialize permissions collection if needed
        if not hasattr(user, '_direct_permissions'):
            user._direct_permissions = []
        
        # Check if user already has this permission
        if any(p.id == permission.id for p in user._direct_permissions):
            return
        
        # Add permission
        user._direct_permissions.append(permission)
        
        # Track permission grant metadata
        if not hasattr(user, 'permission_grants'):
            user.permission_grants = {}
        
        user.permission_grants[str(permission.id)] = {
            "granted_at": datetime.now(UTC),
            "granted_by": str(granted_by),
            "scope": scope.to_dict() if scope else None,
            "expires_at": expires_at.isoformat() if expires_at else None
        }
        
        user.updated_at = datetime.now(UTC)
        
        # Add domain event
        user.add_domain_event(UserPermissionGranted(
            user_id=user.id,
            permission_id=permission.id,
            permission_name=permission.name,
            granted_by=granted_by,
            scope=scope.to_dict() if scope else None,
            expires_at=expires_at
        ))
    
    @staticmethod
    def revoke_permission(
        user: User,
        permission_id: UUID,
        revoked_by: UUID,
        reason: str | None = None
    ) -> None:
        """
        Revoke a specific permission from a user.
        
        Args:
            user: User aggregate
            permission_id: ID of permission to revoke
            revoked_by: ID of user revoking permission
            reason: Optional reason for revocation
        """
        if not hasattr(user, '_direct_permissions'):
            return
        
        # Find and remove permission
        permission_to_remove = None
        for perm in user._direct_permissions:
            if perm.id == permission_id:
                permission_to_remove = perm
                break
        
        if not permission_to_remove:
            return
        
        user._direct_permissions.remove(permission_to_remove)
        
        # Remove grant metadata
        if hasattr(user, 'permission_grants'):
            user.permission_grants.pop(str(permission_id), None)
        
        user.updated_at = datetime.now(UTC)
        
        # Add domain event
        user.add_domain_event(UserPermissionRevoked(
            user_id=user.id,
            permission_id=permission_id,
            permission_name=permission_to_remove.name,
            revoked_by=revoked_by,
            reason=reason
        ))
    
    @staticmethod
    def get_effective_permissions(user: User) -> set[Permission]:
        """
        Get all effective permissions for a user (from roles and direct grants).
        
        Args:
            user: User aggregate
            
        Returns:
            Set of all permissions
        """
        permissions = set()
        
        # Add permissions from roles
        if hasattr(user, '_roles'):
            for role in user._roles:
                if hasattr(role, 'permissions'):
                    permissions.update(role.permissions)
        
        # Add direct permissions
        if hasattr(user, '_direct_permissions'):
            permissions.update(user._direct_permissions)
        
        # Filter out expired permissions
        now = datetime.now(UTC)
        valid_permissions = set()
        
        for perm in permissions:
            # Check if permission is expired
            if hasattr(user, 'permission_grants'):
                grant = user.permission_grants.get(str(perm.id), {})
                expires_at_str = grant.get("expires_at")
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if expires_at < now:
                        continue
            
            valid_permissions.add(perm)
        
        return valid_permissions
    
    @staticmethod
    def has_permission(
        user: User,
        resource: ResourceType,
        action: PermissionAction,
        scope: PermissionScope | None = None
    ) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user: User aggregate
            resource: Resource type
            action: Permission action
            scope: Optional scope to check
            
        Returns:
            True if user has permission
        """
        effective_permissions = RoleService.get_effective_permissions(user)
        
        for perm in effective_permissions:
            # Check resource and action match
            if perm.resource == resource and perm.action == action:
                # If no scope required, permission granted
                if not scope:
                    return True
                
                # Check scope if required
                if hasattr(user, 'permission_grants'):
                    grant = user.permission_grants.get(str(perm.id), {})
                    grant_scope = grant.get("scope")
                    if grant_scope:
                        # Check if grant scope covers requested scope
                        # This is a simplified check - real implementation would be more complex
                        return True
        
        return False
    
    @staticmethod
    def get_user_roles(user: User) -> list[dict[str, Any]]:
        """
        Get user's roles with metadata.
        
        Args:
            user: User aggregate
            
        Returns:
            List of role information
        """
        if not hasattr(user, '_roles'):
            return []
        
        roles = []
        for role in user._roles:
            role_info = {
                "id": str(role.id),
                "name": role.name,
                "description": role.description,
                "is_system": role.is_system,
                "permission_count": len(role.permissions) if hasattr(role, 'permissions') else 0
            }
            
            # Add assignment metadata
            if hasattr(user, 'role_assignments'):
                assignment = user.role_assignments.get(str(role.id), {})
                role_info.update({
                    "assigned_at": assignment.get("assigned_at"),
                    "assigned_by": assignment.get("assigned_by"),
                    "expires_at": assignment.get("expires_at")
                })
            
            roles.append(role_info)
        
        return roles
    
    @staticmethod
    def is_admin(user: User) -> bool:
        """Check if user has admin role."""
        if not hasattr(user, '_roles'):
            return False
        
        admin_role_names = {"admin", "administrator", "super_admin", "superadmin"}
        return any(role.name.lower() in admin_role_names for role in user._roles)
    
    @staticmethod
    def clone_permissions(
        source_user: User,
        target_user: User,
        cloned_by: UUID
    ) -> None:
        """
        Clone all roles and permissions from one user to another.
        
        Args:
            source_user: User to copy from
            target_user: User to copy to
            cloned_by: ID of user performing clone
        """
        # Clone roles
        if hasattr(source_user, '_roles'):
            for role in source_user._roles:
                RoleService.assign_role(target_user, role, cloned_by)
        
        # Clone direct permissions
        if hasattr(source_user, '_direct_permissions'):
            for perm in source_user._direct_permissions:
                # Get scope if available
                scope = None
                if hasattr(source_user, 'permission_grants'):
                    grant = source_user.permission_grants.get(str(perm.id), {})
                    scope_data = grant.get("scope")
                    if scope_data:
                        scope = PermissionScope.from_dict(scope_data)
                
                RoleService.grant_permission(target_user, perm, cloned_by, scope)