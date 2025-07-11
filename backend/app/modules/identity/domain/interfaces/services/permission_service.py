"""
Permission Service Interface

Port for permission management operations including creation, validation,
assignment, and policy evaluation.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.permission import Permission
    from app.modules.identity.domain.aggregates.user import User


class IPermissionService(ABC):
    """Port for permission management operations."""
    
    @abstractmethod
    async def create_permission(
        self,
        resource: str,
        action: str,
        description: str,
        constraints: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> "Permission":
        """
        Create a new permission.
        
        Args:
            resource: Resource identifier (e.g., "user", "document")
            action: Action identifier (e.g., "read", "write", "delete")
            description: Human-readable description
            constraints: Optional constraints for the permission
            metadata: Optional permission metadata
            
        Returns:
            Created Permission aggregate
            
        Raises:
            DuplicatePermissionError: If permission already exists
            InvalidResourceError: If resource is invalid
            InvalidActionError: If action is invalid
        """
        ...
    
    @abstractmethod
    async def check_permission(
        self,
        user: "User",
        resource: str,
        action: str,
        context: dict[str, Any] | None = None
    ) -> bool:
        """
        Check if user has permission for resource and action.
        
        Args:
            user: User to check permission for
            resource: Resource to check access to
            action: Action to perform on resource
            context: Optional context for constraint evaluation
            
        Returns:
            True if user has permission
        """
        ...
    
    @abstractmethod
    async def grant_permission_to_user(
        self,
        user_id: UUID,
        permission_id: UUID,
        granted_by: UUID,
        expires_at: datetime | None = None,
        constraints: dict[str, Any] | None = None
    ) -> None:
        """
        Grant permission directly to user.
        
        Args:
            user_id: ID of user to grant permission to
            permission_id: ID of permission to grant
            granted_by: ID of user granting permission
            expires_at: Optional expiration timestamp
            constraints: Optional additional constraints
            
        Raises:
            UserNotFoundError: If user doesn't exist
            PermissionNotFoundError: If permission doesn't exist
            PermissionAlreadyGrantedError: If user already has permission
        """
        ...
    
    @abstractmethod
    async def revoke_permission_from_user(
        self,
        user_id: UUID,
        permission_id: UUID,
        revoked_by: UUID,
        reason: str | None = None
    ) -> None:
        """
        Revoke permission from user.
        
        Args:
            user_id: ID of user to revoke permission from
            permission_id: ID of permission to revoke
            revoked_by: ID of user revoking permission
            reason: Optional revocation reason
            
        Raises:
            UserNotFoundError: If user doesn't exist
            PermissionNotFoundError: If permission doesn't exist
            PermissionNotGrantedError: If user doesn't have permission
        """
        ...
    
    @abstractmethod
    async def get_user_permissions(
        self,
        user_id: UUID,
        include_role_permissions: bool = True
    ) -> list["Permission"]:
        """
        Get all permissions for a user.
        
        Args:
            user_id: ID of user
            include_role_permissions: Include permissions from roles
            
        Returns:
            List of all user permissions
        """
        ...
    
    @abstractmethod
    async def evaluate_permission_policy(
        self,
        permission: "Permission",
        context: dict[str, Any]
    ) -> bool:
        """
        Evaluate permission constraints against context.
        
        Args:
            permission: Permission with constraints
            context: Context to evaluate against
            
        Returns:
            True if constraints are satisfied
        """
        ...
    
    @abstractmethod
    async def check_resource_ownership(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: UUID
    ) -> bool:
        """
        Check if user owns a specific resource.
        
        Args:
            user_id: ID of user
            resource_type: Type of resource
            resource_id: ID of resource
            
        Returns:
            True if user owns resource
        """
        ...
    
    @abstractmethod
    async def get_permitted_resources(
        self,
        user_id: UUID,
        resource_type: str,
        action: str
    ) -> list[UUID]:
        """
        Get list of resource IDs user can perform action on.
        
        Args:
            user_id: ID of user
            resource_type: Type of resource
            action: Action to check
            
        Returns:
            List of permitted resource IDs
        """
        ...