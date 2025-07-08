"""
Role and permission mutation resolvers for GraphQL.

This module implements comprehensive role and permission management mutations
including CRUD operations, role assignments, permission assignments, and
hierarchical role management with transaction support and audit logging.
"""

import uuid
from datetime import datetime
from typing import Any

from strawberry import mutation
from strawberry.types import Info

from app.core.cache import get_cache
from app.core.database import get_db_context
from app.core.enums import EventType, PermissionScope, RoleType
from app.core.errors import (
    AuthorizationError,
    BusinessRuleError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.modules.identity.domain.entities import Permission, Role
from app.modules.identity.domain.interfaces import (
    IAuthorizationService,
    IPermissionRepository,
    IRolePermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    IUserRepository,
    IUserRoleRepository,
)
from app.modules.identity.presentation.graphql.types import (
    PermissionCreateInput,
    PermissionResponse,
    PermissionUpdateInput,
    RoleCreateInput,
    RoleResponse,
    RoleUpdateInput,
)

logger = get_logger(__name__)


class RoleMutations:
    """Role and permission management GraphQL mutations."""

    def __init__(
        self,
        role_repository: IRoleRepository,
        permission_repository: IPermissionRepository,
        user_role_repository: IUserRoleRepository,
        role_permission_repository: IRolePermissionRepository,
        user_repository: IUserRepository,
        security_event_repository: ISecurityEventRepository,
        authorization_service: IAuthorizationService
    ):
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.user_role_repository = user_role_repository
        self.role_permission_repository = role_permission_repository
        self.user_repository = user_repository
        self.security_event_repository = security_event_repository
        self.authorization_service = authorization_service
        self.cache = get_cache()
        self.logger = logger
    
    def _raise_insufficient_permissions(self, action: str) -> None:
        """Raise AuthorizationError for insufficient permissions."""
        raise AuthorizationError(f"Insufficient permissions to {action}")
    
    def _raise_role_exists(self) -> None:
        """Raise ConflictError for role already exists."""
        raise ConflictError("Role with this name already exists")
    
    def _raise_role_not_found(self) -> None:
        """Raise NotFoundError for role not found."""
        raise NotFoundError("Role not found")
    
    def _raise_permission_exists(self) -> None:
        """Raise ConflictError for permission already exists."""
        raise ConflictError("Permission with this name already exists")
    
    def _raise_permission_not_found(self) -> None:
        """Raise NotFoundError for permission not found."""
        raise NotFoundError("Permission not found")
    
    def _raise_user_not_found(self) -> None:
        """Raise NotFoundError for user not found."""
        raise NotFoundError("User not found")
    
    def _raise_role_in_use(self) -> None:
        """Raise BusinessRuleError for role in use."""
        raise BusinessRuleError("Cannot delete role that is assigned to users")
    
    def _raise_permission_in_use(self) -> None:
        """Raise BusinessRuleError for permission in use."""
        raise BusinessRuleError("Cannot delete permission that is assigned to roles")
    
    def _raise_cannot_modify_system_role(self) -> None:
        """Raise BusinessRuleError for system role modification."""
        raise BusinessRuleError("Cannot modify system role")
    
    def _raise_role_modified_by_another(self) -> None:
        """Raise ConflictError for concurrent modification."""
        raise ConflictError("Role has been modified by another process")
    
    def _raise_already_assigned(self, entity: str) -> None:
        """Raise ConflictError for already assigned entity."""
        raise ConflictError(f"{entity} already assigned")
    
    def _raise_invalid_hierarchy(self) -> None:
        """Raise BusinessRuleError for invalid role hierarchy."""
        raise BusinessRuleError("Role hierarchy would create a cycle")

    @mutation
    async def create_role(self, info: Info, input: RoleCreateInput) -> RoleResponse:
        """
        Create new role with comprehensive validation.
        
        Args:
            input: Role creation data
            
        Returns:
            RoleResponse with created role data
            
        Raises:
            ValidationError: Invalid input data
            ConflictError: Role already exists
            AuthorizationError: Insufficient permissions
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_create_permission(current_user):
                    self._raise_insufficient_permissions("create role")

                # Validate input
                await self._validate_role_create_input(input)

                # Check if role exists
                existing_role = await self.role_repository.find_by_name(input.name)
                if existing_role:
                    self._raise_role_exists()

                # Create role
                role_data = await self._prepare_role_data(input)
                role = await self.role_repository.create(role_data)

                # Assign initial permissions if provided
                if hasattr(input, 'permission_ids') and input.permission_ids:
                    await self._assign_permissions_to_role(
                        role.id,
                        input.permission_ids,
                        current_user.id
                    )

                # Log role creation
                await self._log_security_event(
                    current_user.id,
                    EventType.ROLE_CREATED,
                    f"Role created: {role.name}",
                    info,
                    metadata={"role_id": role.id, "role_name": role.name}
                )

                # Clear cache
                await self._invalidate_role_cache(role.id)

                await db.commit()

                # Get role with permissions
                role_with_permissions = await self._get_role_with_permissions(role.id)

                return RoleResponse(
                    role=role_with_permissions,
                    permissions=await self._get_role_permissions(role.id)
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Role creation failed: {e!s}")
                raise

    @mutation
    async def update_role(
        self,
        info: Info,
        id: str,
        input: RoleUpdateInput
    ) -> RoleResponse:
        """
        Update existing role with optimistic concurrency control.
        
        Args:
            id: Role ID
            input: Role update data
            
        Returns:
            RoleResponse with updated role data
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_update_permission(current_user):
                    self._raise_insufficient_permissions("update role")

                # Find role
                role = await self.role_repository.find_by_id(id)
                if not role:
                    raise NotFoundError("Role not found")

                # Check system role protection
                if role.is_system_role and not self._can_modify_system_roles(current_user):
                    raise BusinessRuleError("Cannot modify system role")

                # Validate input
                await self._validate_role_update_input(input, role)

                # Check optimistic concurrency
                if hasattr(input, 'version') and input.version != role.version:
                    raise ConflictError("Role has been modified by another process")

                # Update role data
                updated_data = await self._prepare_role_update_data(input, role)

                for key, value in updated_data.items():
                    setattr(role, key, value)

                role.updated_at = datetime.utcnow()
                role.version += 1

                updated_role = await self.role_repository.update(role)

                # Log role update
                await self._log_security_event(
                    current_user.id,
                    EventType.ROLE_UPDATED,
                    f"Role updated: {role.name}",
                    info,
                    metadata={
                        "role_id": role.id,
                        "role_name": role.name,
                        "updated_fields": list(updated_data.keys())
                    }
                )

                # Clear cache
                await self._invalidate_role_cache(role.id)

                await db.commit()

                return RoleResponse(
                    role=updated_role,
                    permissions=await self._get_role_permissions(role.id)
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Role update failed: {e!s}")
                raise

    @mutation
    async def delete_role(self, info: Info, id: str) -> bool:
        """
        Delete role with proper validation and cleanup.
        
        Args:
            id: Role ID
            
        Returns:
            True if role deleted successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_delete_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to delete role")

                # Find role
                role = await self.role_repository.find_by_id(id)
                if not role:
                    raise NotFoundError("Role not found")

                # Check system role protection
                if role.is_system_role:
                    raise BusinessRuleError("Cannot delete system role")

                # Check if role is in use
                user_count = await self.user_role_repository.count_users_with_role(id)
                if user_count > 0:
                    raise BusinessRuleError(
                        f"Cannot delete role that is assigned to {user_count} user(s)"
                    )

                # Delete role permissions
                await self.role_permission_repository.delete_by_role_id(id)

                # Delete role
                await self.role_repository.delete(id)

                # Log role deletion
                await self._log_security_event(
                    current_user.id,
                    EventType.ROLE_DELETED,
                    f"Role deleted: {role.name}",
                    info,
                    metadata={"role_id": role.id, "role_name": role.name}
                )

                # Clear cache
                await self._invalidate_role_cache(id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Role deletion failed: {e!s}")
                raise

    @mutation
    async def assign_role_to_user(
        self,
        info: Info,
        user_id: str,
        role_id: str
    ) -> bool:
        """
        Assign role to user.
        
        Args:
            user_id: User ID
            role_id: Role ID
            
        Returns:
            True if role assigned successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_assign_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to assign roles")

                # Validate user and role
                user = await self.user_repository.find_by_id(user_id)
                if not user:
                    raise NotFoundError("User not found")

                role = await self.role_repository.find_by_id(role_id)
                if not role:
                    raise NotFoundError("Role not found")

                # Check if already assigned
                existing_assignment = await self.user_role_repository.find_by_user_and_role(
                    user_id, role_id
                )
                if existing_assignment:
                    raise ConflictError("Role is already assigned to user")

                # Check role constraints
                await self._validate_role_assignment(user, role)

                # Create user role assignment
                user_role_data = {
                    "id": str(uuid.uuid4()),
                    "user_id": user_id,
                    "role_id": role_id,
                    "assigned_by": current_user.id,
                    "assigned_at": datetime.utcnow(),
                    "is_active": True
                }

                await self.user_role_repository.create(user_role_data)

                # Log role assignment
                await self._log_security_event(
                    user_id,
                    EventType.ROLE_ASSIGNED,
                    f"Role '{role.name}' assigned to user by {current_user.id}",
                    info,
                    metadata={
                        "role_id": role_id,
                        "role_name": role.name,
                        "assigned_by": current_user.id
                    }
                )

                # Clear user permissions cache
                await self._invalidate_user_permissions_cache(user_id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Role assignment failed: {e!s}")
                raise

    @mutation
    async def remove_role_from_user(
        self,
        info: Info,
        user_id: str,
        role_id: str
    ) -> bool:
        """
        Remove role from user.
        
        Args:
            user_id: User ID
            role_id: Role ID
            
        Returns:
            True if role removed successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_assign_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to remove roles")

                # Find user role assignment
                user_role = await self.user_role_repository.find_by_user_and_role(
                    user_id, role_id
                )
                if not user_role:
                    raise NotFoundError("Role assignment not found")

                # Get role for logging
                role = await self.role_repository.find_by_id(role_id)

                # Check if it's a required role
                if role and role.is_default_role:
                    user_roles_count = await self.user_role_repository.count_active_roles_for_user(
                        user_id
                    )
                    if user_roles_count <= 1:
                        raise BusinessRuleError("Cannot remove last default role from user")

                # Remove role assignment
                await self.user_role_repository.delete(user_role.id)

                # Log role removal
                await self._log_security_event(
                    user_id,
                    EventType.ROLE_REMOVED,
                    f"Role '{role.name if role else 'Unknown'}' removed from user by {current_user.id}",
                    info,
                    metadata={
                        "role_id": role_id,
                        "role_name": role.name if role else "Unknown",
                        "removed_by": current_user.id
                    }
                )

                # Clear user permissions cache
                await self._invalidate_user_permissions_cache(user_id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Role removal failed: {e!s}")
                raise

    @mutation
    async def create_permission(
        self,
        info: Info,
        input: PermissionCreateInput
    ) -> PermissionResponse:
        """
        Create new permission.
        
        Args:
            input: Permission creation data
            
        Returns:
            PermissionResponse with created permission
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_permission_create_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to create permission")

                # Validate input
                await self._validate_permission_create_input(input)

                # Check if permission exists
                existing_permission = await self.permission_repository.find_by_name(input.name)
                if existing_permission:
                    raise ConflictError("Permission with this name already exists")

                # Create permission
                permission_data = await self._prepare_permission_data(input)
                permission = await self.permission_repository.create(permission_data)

                # Log permission creation
                await self._log_security_event(
                    current_user.id,
                    EventType.PERMISSION_CREATED,
                    f"Permission created: {permission.name}",
                    info,
                    metadata={
                        "permission_id": permission.id,
                        "permission_name": permission.name
                    }
                )

                # Clear cache
                await self._invalidate_permission_cache(permission.id)

                await db.commit()

                return PermissionResponse(permission=permission)

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Permission creation failed: {e!s}")
                raise

    @mutation
    async def update_permission(
        self,
        info: Info,
        id: str,
        input: PermissionUpdateInput
    ) -> PermissionResponse:
        """
        Update existing permission.
        
        Args:
            id: Permission ID
            input: Permission update data
            
        Returns:
            PermissionResponse with updated permission
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_permission_update_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to update permission")

                # Find permission
                permission = await self.permission_repository.find_by_id(id)
                if not permission:
                    raise NotFoundError("Permission not found")

                # Check system permission protection
                if permission.is_system_permission and not self._can_modify_system_permissions(current_user):
                    raise BusinessRuleError("Cannot modify system permission")

                # Validate input
                await self._validate_permission_update_input(input, permission)

                # Update permission data
                updated_data = await self._prepare_permission_update_data(input)

                for key, value in updated_data.items():
                    setattr(permission, key, value)

                permission.updated_at = datetime.utcnow()

                updated_permission = await self.permission_repository.update(permission)

                # Log permission update
                await self._log_security_event(
                    current_user.id,
                    EventType.PERMISSION_UPDATED,
                    f"Permission updated: {permission.name}",
                    info,
                    metadata={
                        "permission_id": permission.id,
                        "permission_name": permission.name,
                        "updated_fields": list(updated_data.keys())
                    }
                )

                # Clear cache
                await self._invalidate_permission_cache(permission.id)

                await db.commit()

                return PermissionResponse(permission=updated_permission)

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Permission update failed: {e!s}")
                raise

    @mutation
    async def delete_permission(self, info: Info, id: str) -> bool:
        """
        Delete permission with proper validation.
        
        Args:
            id: Permission ID
            
        Returns:
            True if permission deleted successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_permission_delete_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to delete permission")

                # Find permission
                permission = await self.permission_repository.find_by_id(id)
                if not permission:
                    raise NotFoundError("Permission not found")

                # Check system permission protection
                if permission.is_system_permission:
                    raise BusinessRuleError("Cannot delete system permission")

                # Check if permission is in use
                role_count = await self.role_permission_repository.count_roles_with_permission(id)
                if role_count > 0:
                    raise BusinessRuleError(
                        f"Cannot delete permission that is assigned to {role_count} role(s)"
                    )

                # Delete permission
                await self.permission_repository.delete(id)

                # Log permission deletion
                await self._log_security_event(
                    current_user.id,
                    EventType.PERMISSION_DELETED,
                    f"Permission deleted: {permission.name}",
                    info,
                    metadata={
                        "permission_id": permission.id,
                        "permission_name": permission.name
                    }
                )

                # Clear cache
                await self._invalidate_permission_cache(id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Permission deletion failed: {e!s}")
                raise

    @mutation
    async def assign_permission_to_role(
        self,
        info: Info,
        role_id: str,
        permission_id: str
    ) -> bool:
        """
        Assign permission to role.
        
        Args:
            role_id: Role ID
            permission_id: Permission ID
            
        Returns:
            True if permission assigned successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_update_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to assign permissions")

                # Validate role and permission
                role = await self.role_repository.find_by_id(role_id)
                if not role:
                    raise NotFoundError("Role not found")

                permission = await self.permission_repository.find_by_id(permission_id)
                if not permission:
                    raise NotFoundError("Permission not found")

                # Check if already assigned
                existing_assignment = await self.role_permission_repository.find_by_role_and_permission(
                    role_id, permission_id
                )
                if existing_assignment:
                    raise ConflictError("Permission is already assigned to role")

                # Create role permission assignment
                role_permission_data = {
                    "id": str(uuid.uuid4()),
                    "role_id": role_id,
                    "permission_id": permission_id,
                    "assigned_by": current_user.id,
                    "assigned_at": datetime.utcnow()
                }

                await self.role_permission_repository.create(role_permission_data)

                # Log permission assignment
                await self._log_security_event(
                    current_user.id,
                    EventType.PERMISSION_ASSIGNED,
                    f"Permission '{permission.name}' assigned to role '{role.name}'",
                    info,
                    metadata={
                        "role_id": role_id,
                        "role_name": role.name,
                        "permission_id": permission_id,
                        "permission_name": permission.name
                    }
                )

                # Clear role permissions cache
                await self._invalidate_role_cache(role_id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Permission assignment failed: {e!s}")
                raise

    @mutation
    async def remove_permission_from_role(
        self,
        info: Info,
        role_id: str,
        permission_id: str
    ) -> bool:
        """
        Remove permission from role.
        
        Args:
            role_id: Role ID
            permission_id: Permission ID
            
        Returns:
            True if permission removed successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_role_update_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to remove permissions")

                # Find role permission assignment
                role_permission = await self.role_permission_repository.find_by_role_and_permission(
                    role_id, permission_id
                )
                if not role_permission:
                    raise NotFoundError("Permission assignment not found")

                # Get role and permission for logging
                role = await self.role_repository.find_by_id(role_id)
                permission = await self.permission_repository.find_by_id(permission_id)

                # Remove permission assignment
                await self.role_permission_repository.delete(role_permission.id)

                # Log permission removal
                await self._log_security_event(
                    current_user.id,
                    EventType.PERMISSION_REMOVED,
                    f"Permission '{permission.name if permission else 'Unknown'}' removed from role '{role.name if role else 'Unknown'}'",
                    info,
                    metadata={
                        "role_id": role_id,
                        "role_name": role.name if role else "Unknown",
                        "permission_id": permission_id,
                        "permission_name": permission.name if permission else "Unknown"
                    }
                )

                # Clear role permissions cache
                await self._invalidate_role_cache(role_id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Permission removal failed: {e!s}")
                raise

    # Helper methods

    def _has_role_create_permission(self, user) -> bool:
        """Check if user has permission to create roles."""
        return user.has_permission("role:create")

    def _has_role_update_permission(self, user) -> bool:
        """Check if user has permission to update roles."""
        return user.has_permission("role:update")

    def _has_role_delete_permission(self, user) -> bool:
        """Check if user has permission to delete roles."""
        return user.has_permission("role:delete")

    def _has_role_assign_permission(self, user) -> bool:
        """Check if user has permission to assign roles."""
        return user.has_permission("role:assign")

    def _has_permission_create_permission(self, user) -> bool:
        """Check if user has permission to create permissions."""
        return user.has_permission("permission:create")

    def _has_permission_update_permission(self, user) -> bool:
        """Check if user has permission to update permissions."""
        return user.has_permission("permission:update")

    def _has_permission_delete_permission(self, user) -> bool:
        """Check if user has permission to delete permissions."""
        return user.has_permission("permission:delete")

    def _can_modify_system_roles(self, user) -> bool:
        """Check if user can modify system roles."""
        return user.has_permission("system:manage")

    def _can_modify_system_permissions(self, user) -> bool:
        """Check if user can modify system permissions."""
        return user.has_permission("system:manage")

    async def _validate_role_create_input(self, input: RoleCreateInput) -> None:
        """Validate role creation input."""
        if not input.name or len(input.name.strip()) < 2:
            raise ValidationError("Role name must be at least 2 characters")

        if hasattr(input, 'description') and input.description and len(input.description) > 500:
            raise ValidationError("Role description cannot exceed 500 characters")

    async def _validate_role_update_input(self, input: RoleUpdateInput, role: Role) -> None:
        """Validate role update input."""
        if hasattr(input, 'name') and input.name and input.name != role.name:
            existing_role = await self.role_repository.find_by_name(input.name)
            if existing_role:
                raise ConflictError("Role name already in use")

    async def _validate_permission_create_input(self, input: PermissionCreateInput) -> None:
        """Validate permission creation input."""
        if not input.name or len(input.name.strip()) < 2:
            raise ValidationError("Permission name must be at least 2 characters")

        if not input.resource or len(input.resource.strip()) < 2:
            raise ValidationError("Permission resource must be at least 2 characters")

        if not input.action or len(input.action.strip()) < 2:
            raise ValidationError("Permission action must be at least 2 characters")

    async def _validate_permission_update_input(
        self,
        input: PermissionUpdateInput,
        permission: Permission
    ) -> None:
        """Validate permission update input."""
        if hasattr(input, 'name') and input.name:
            if input.name != permission.name:
                existing_permission = await self.permission_repository.find_by_name(input.name)
                if existing_permission:
                    raise ConflictError("Permission name already in use")

    async def _validate_role_assignment(self, user, role: Role) -> None:
        """Validate role assignment constraints."""
        # Check if user already has maximum allowed roles
        user_roles_count = await self.user_role_repository.count_active_roles_for_user(user.id)
        if user_roles_count >= 10:  # Max 10 roles per user
            raise BusinessRuleError("User cannot have more than 10 roles")

        # Check role hierarchy constraints
        if role.role_type == RoleType.ADMIN:
            # Additional checks for admin roles
            if not user.is_verified:
                raise BusinessRuleError("User must be verified to receive admin roles")

    async def _prepare_role_data(self, input: RoleCreateInput) -> dict[str, Any]:
        """Prepare role data for creation."""
        return {
            "id": str(uuid.uuid4()),
            "name": input.name.strip(),
            "description": getattr(input, "description", ""),
            "role_type": getattr(input, "role_type", RoleType.CUSTOM),
            "is_active": getattr(input, "is_active", True),
            "is_system_role": False,
            "is_default_role": getattr(input, "is_default_role", False),
            "created_at": datetime.utcnow(),
            "version": 1
        }

    async def _prepare_role_update_data(self, input: RoleUpdateInput, role: Role) -> dict[str, Any]:
        """Prepare role data for update."""
        data = {}

        if hasattr(input, 'name') and input.name:
            data['name'] = input.name.strip()

        if hasattr(input, 'description'):
            data['description'] = input.description or ""

        if hasattr(input, 'is_active') and input.is_active is not None:
            data['is_active'] = input.is_active

        return data

    async def _prepare_permission_data(self, input: PermissionCreateInput) -> dict[str, Any]:
        """Prepare permission data for creation."""
        return {
            "id": str(uuid.uuid4()),
            "name": input.name.strip(),
            "description": getattr(input, "description", ""),
            "resource": input.resource.strip(),
            "action": input.action.strip(),
            "scope": getattr(input, "scope", PermissionScope.RESOURCE),
            "is_active": getattr(input, "is_active", True),
            "is_system_permission": False,
            "created_at": datetime.utcnow()
        }

    async def _prepare_permission_update_data(self, input: PermissionUpdateInput) -> dict[str, Any]:
        """Prepare permission data for update."""
        data = {}

        if hasattr(input, 'name') and input.name:
            data['name'] = input.name.strip()

        if hasattr(input, 'description'):
            data['description'] = input.description or ""

        if hasattr(input, 'is_active') and input.is_active is not None:
            data['is_active'] = input.is_active

        return data

    async def _assign_permissions_to_role(
        self,
        role_id: str,
        permission_ids: list[str],
        assigned_by: str
    ) -> None:
        """Assign multiple permissions to role."""
        for permission_id in permission_ids:
            # Check if permission exists
            permission = await self.permission_repository.find_by_id(permission_id)
            if not permission:
                continue

            # Check if already assigned
            existing = await self.role_permission_repository.find_by_role_and_permission(
                role_id, permission_id
            )
            if existing:
                continue

            # Create assignment
            role_permission_data = {
                "id": str(uuid.uuid4()),
                "role_id": role_id,
                "permission_id": permission_id,
                "assigned_by": assigned_by,
                "assigned_at": datetime.utcnow()
            }

            await self.role_permission_repository.create(role_permission_data)

    async def _get_role_with_permissions(self, role_id: str) -> Role:
        """Get role with permissions loaded."""
        return await self.role_repository.find_by_id(role_id)

    async def _get_role_permissions(self, role_id: str) -> list[Permission]:
        """Get permissions for role."""
        return await self.permission_repository.find_by_role_id(role_id)

    async def _invalidate_role_cache(self, role_id: str) -> None:
        """Invalidate role cache."""
        cache_keys = [
            f"role:{role_id}",
            f"role_permissions:{role_id}",
            "roles:all",
            "permissions:all"
        ]

        for key in cache_keys:
            await self.cache.delete(key)

    async def _invalidate_permission_cache(self, permission_id: str) -> None:
        """Invalidate permission cache."""
        cache_keys = [
            f"permission:{permission_id}",
            "permissions:all"
        ]

        for key in cache_keys:
            await self.cache.delete(key)

    async def _invalidate_user_permissions_cache(self, user_id: str) -> None:
        """Invalidate user permissions cache."""
        cache_keys = [
            f"user_permissions:{user_id}",
            f"user_roles:{user_id}"
        ]

        for key in cache_keys:
            await self.cache.delete(key)

    async def _log_security_event(
        self,
        user_id: str,
        event_type: EventType,
        description: str,
        info: Info,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """Log security event."""
        event_data = {
            "user_id": user_id,
            "event_type": event_type,
            "description": description,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "metadata": metadata,
            "created_at": datetime.utcnow()
        }

        await self.security_event_repository.create(event_data)
