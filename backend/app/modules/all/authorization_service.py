"""
Authorization Service Interface

Protocol for complex authorization and permission resolution.
"""

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from ...value_objects.permission_result import PermissionResult


class IAuthorizationService(Protocol):
    """Protocol for authorization operations."""
    
    async def check_permission(
        self,
        user_id: UUID,
        permission: str,
        resource: str | None = None,
        resource_owner_id: UUID | None = None
    ) -> "PermissionResult":
        """
        Check if user has permission for resource.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            resource: Resource name (optional)
            resource_owner_id: Resource owner (optional)
            
        Returns:
            PermissionResult value object containing authorization decision
        """
    
    async def get_effective_permissions(self, user_id: UUID) -> set[str]:
        """
        Get all effective permissions for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Set of permission strings
        """
        ...
    
    async def validate_access(
        self,
        user_id: UUID,
        action: str,
        resource: str,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Validate access with business rules.
        
        Args:
            user_id: User identifier
            action: Action being performed
            resource: Target resource
            context: Request context
            
        Returns:
            Dict with access decision and conditions
        """
    
    async def calculate_permission_matrix(
        self,
        user_id: UUID,
        resources: list[str] | None = None
    ) -> dict[str, dict[str, bool]]:
        """
        Calculate permission matrix for user.
        
        Args:
            user_id: User identifier
            resources: Resources to check (optional)
            
        Returns:
            Dict mapping resources to action permissions
        """
    
    async def check_segregation_of_duties(
        self,
        user_id: UUID,
        new_permission: str
    ) -> tuple[bool, str]:
        """
        Check segregation of duties compliance.
        
        Args:
            user_id: User identifier
            new_permission: Permission to validate
            
        Returns:
            Tuple of (is_compliant, reason)
        """
    
    def invalidate_permission_cache(self, user_id: UUID) -> None:
        """
        Invalidate permission cache for user.
        
        Args:
            user_id: User identifier
        """
        ...
