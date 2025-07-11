"""
Group Service Interface

Port for group management operations including creation, membership,
hierarchy, and permission management.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.group import Group
    from app.modules.identity.domain.aggregates.user import User
    from app.modules.identity.domain.aggregates.role import Role


class IGroupService(ABC):
    """Port for group management operations."""
    
    @abstractmethod
    async def create_group(
        self,
        name: str,
        description: str,
        parent_group_id: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ) -> "Group":
        """
        Create a new group with optional parent.
        
        Args:
            name: Unique group name
            description: Group description
            parent_group_id: Optional parent group for hierarchy
            metadata: Optional group metadata
            
        Returns:
            Created Group aggregate
            
        Raises:
            DuplicateGroupNameError: If group name already exists
            GroupNotFoundError: If parent group doesn't exist
            CircularHierarchyError: If parent would create circular reference
        """
        ...
    
    @abstractmethod
    async def add_user_to_group(
        self,
        group_id: UUID,
        user_id: UUID,
        added_by: UUID,
        expires_at: datetime | None = None
    ) -> None:
        """
        Add user to group with optional expiration.
        
        Args:
            group_id: ID of group to add user to
            user_id: ID of user to add
            added_by: ID of user performing addition
            expires_at: Optional membership expiration
            
        Raises:
            GroupNotFoundError: If group doesn't exist
            UserNotFoundError: If user doesn't exist
            UserAlreadyInGroupError: If user is already in group
        """
        ...
    
    @abstractmethod
    async def remove_user_from_group(
        self,
        group_id: UUID,
        user_id: UUID,
        removed_by: UUID,
        reason: str | None = None
    ) -> None:
        """
        Remove user from group.
        
        Args:
            group_id: ID of group to remove user from
            user_id: ID of user to remove
            removed_by: ID of user performing removal
            reason: Optional removal reason
            
        Raises:
            GroupNotFoundError: If group doesn't exist
            UserNotFoundError: If user doesn't exist
            UserNotInGroupError: If user is not in group
        """
        ...
    
    @abstractmethod
    async def assign_role_to_group(
        self,
        group_id: UUID,
        role_id: UUID,
        assigned_by: UUID
    ) -> None:
        """
        Assign role to all group members.
        
        Args:
            group_id: ID of group to assign role to
            role_id: ID of role to assign
            assigned_by: ID of user performing assignment
            
        Raises:
            GroupNotFoundError: If group doesn't exist
            RoleNotFoundError: If role doesn't exist
            RoleAlreadyAssignedToGroupError: If group already has role
        """
        ...
    
    @abstractmethod
    async def revoke_role_from_group(
        self,
        group_id: UUID,
        role_id: UUID,
        revoked_by: UUID
    ) -> None:
        """
        Revoke role from group.
        
        Args:
            group_id: ID of group to revoke role from
            role_id: ID of role to revoke
            revoked_by: ID of user performing revocation
            
        Raises:
            GroupNotFoundError: If group doesn't exist
            RoleNotFoundError: If role doesn't exist
            RoleNotAssignedToGroupError: If group doesn't have role
        """
        ...
    
    @abstractmethod
    async def get_group_members(
        self,
        group_id: UUID,
        include_nested: bool = False
    ) -> list["User"]:
        """
        Get all members of a group.
        
        Args:
            group_id: ID of group
            include_nested: Include members from child groups
            
        Returns:
            List of group members
        """
        ...
    
    @abstractmethod
    async def get_user_groups(
        self,
        user_id: UUID,
        include_inherited: bool = True
    ) -> list["Group"]:
        """
        Get all groups a user belongs to.
        
        Args:
            user_id: ID of user
            include_inherited: Include parent groups
            
        Returns:
            List of groups user belongs to
        """
        ...
    
    @abstractmethod
    async def check_group_membership(
        self,
        user_id: UUID,
        group_id: UUID,
        check_nested: bool = True
    ) -> bool:
        """
        Check if user is member of group.
        
        Args:
            user_id: ID of user
            group_id: ID of group
            check_nested: Check parent groups too
            
        Returns:
            True if user is member of group
        """
        ...
    
    @abstractmethod
    async def merge_groups(
        self,
        source_group_id: UUID,
        target_group_id: UUID,
        merged_by: UUID
    ) -> None:
        """
        Merge one group into another.
        
        Args:
            source_group_id: ID of group to merge from
            target_group_id: ID of group to merge into
            merged_by: ID of user performing merge
            
        Raises:
            GroupNotFoundError: If either group doesn't exist
            CannotMergeSameGroupError: If source and target are same
        """
        ...