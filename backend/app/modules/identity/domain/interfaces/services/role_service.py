"""
Role Service Interface

Port for role management operations including creation, assignment,
hierarchy management, and permission inheritance.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.role import Role
    from app.modules.identity.domain.aggregates.permission import Permission


class IRoleService(ABC):
    """Port for role management operations."""
    
    @abstractmethod
    async def create_role(
        self,
        name: str,
        description: str,
        permissions: list[UUID] | None = None,
        parent_role_id: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ) -> "Role":
        """
        Create a new role with optional permissions and hierarchy.
        
        Args:
            name: Unique role name
            description: Role description
            permissions: Optional list of permission IDs
            parent_role_id: Optional parent role for hierarchy
            metadata: Optional role metadata
            
        Returns:
            Created Role aggregate
            
        Raises:
            DuplicateRoleNameError: If role name already exists
            InvalidPermissionError: If any permission ID is invalid
            CircularHierarchyError: If parent would create circular reference
        """
        ...
    
    @abstractmethod
    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID,
        expires_at: datetime | None = None
    ) -> None:
        """
        Assign role to user with optional expiration.
        
        Args:
            user_id: ID of user to assign role to
            role_id: ID of role to assign
            assigned_by: ID of user performing assignment
            expires_at: Optional expiration timestamp
            
        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
            RoleAlreadyAssignedError: If user already has role
        """
        ...
    
    @abstractmethod
    async def revoke_role_from_user(
        self,
        user_id: UUID,
        role_id: UUID,
        revoked_by: UUID,
        reason: str | None = None
    ) -> None:
        """
        Revoke role from user.
        
        Args:
            user_id: ID of user to revoke role from
            role_id: ID of role to revoke
            revoked_by: ID of user performing revocation
            reason: Optional revocation reason
            
        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
            RoleNotAssignedError: If user doesn't have role
        """
        ...
    
    @abstractmethod
    async def add_permission_to_role(
        self,
        role_id: UUID,
        permission_id: UUID,
        added_by: UUID
    ) -> None:
        """
        Add permission to role.
        
        Args:
            role_id: ID of role to add permission to
            permission_id: ID of permission to add
            added_by: ID of user adding permission
            
        Raises:
            RoleNotFoundError: If role doesn't exist
            PermissionNotFoundError: If permission doesn't exist
            PermissionAlreadyInRoleError: If role already has permission
        """
        ...
    
    @abstractmethod
    async def remove_permission_from_role(
        self,
        role_id: UUID,
        permission_id: UUID,
        removed_by: UUID
    ) -> None:
        """
        Remove permission from role.
        
        Args:
            role_id: ID of role to remove permission from
            permission_id: ID of permission to remove
            removed_by: ID of user removing permission
            
        Raises:
            RoleNotFoundError: If role doesn't exist
            PermissionNotFoundError: If permission doesn't exist
            PermissionNotInRoleError: If role doesn't have permission
        """
        ...
    
    @abstractmethod
    async def get_effective_permissions(self, role_id: UUID) -> list["Permission"]:
        """
        Get all effective permissions for role including inherited ones.
        
        Args:
            role_id: ID of role
            
        Returns:
            List of all effective permissions
        """
        ...
    
    @abstractmethod
    async def check_role_hierarchy(
        self,
        parent_role_id: UUID,
        child_role_id: UUID
    ) -> bool:
        """
        Check if one role is ancestor of another in hierarchy.
        
        Args:
            parent_role_id: Potential parent role ID
            child_role_id: Potential child role ID
            
        Returns:
            True if parent is ancestor of child
        """
        ...
    
    @abstractmethod
    async def validate_role_assignment(
        self,
        assigner_id: UUID,
        role_id: UUID
    ) -> bool:
        """
        Validate if user can assign a specific role.
        
        Args:
            assigner_id: ID of user trying to assign role
            role_id: ID of role to be assigned
            
        Returns:
            True if assignment is allowed
        """
        ...