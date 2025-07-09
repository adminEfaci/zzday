"""
User Permission Service

Domain service for complex user permission and role management logic.
"""

from typing import TYPE_CHECKING
from uuid import UUID

from ..enums import AccountType

if TYPE_CHECKING:
    from ..user import User


class UserPermissionService:
    """Domain service for user permission calculations and role management."""
    
    def can_assign_role(self, assigner: 'User', target_user: 'User', role_id: UUID) -> bool:
        """Check if assigner can assign role to target user."""
        # System admins can assign any role
        if assigner.account_type == AccountType.ADMIN:
            return True
        
        # Users can't assign roles to themselves for security
        if assigner.id == target_user.id:
            return False
        
        # Service accounts can't assign roles
        if assigner.account_type == AccountType.SERVICE:
            return False
        
        # Only active users can assign roles
        if not assigner.is_active():
            return False
        
        # Additional business rules based on role hierarchy
        assigner_level = self._get_user_authority_level(assigner)
        target_level = self._get_user_authority_level(target_user)
        
        # Can only assign roles to users with lower authority
        return assigner_level > target_level
    
    def can_grant_permission(self, granter: 'User', target_user: 'User', permission_id: UUID) -> bool:
        """Check if granter can grant permission to target user."""
        # System admins can grant any permission
        if granter.account_type == AccountType.ADMIN:
            return True
        
        # Users can't grant permissions to themselves
        if granter.id == target_user.id:
            return False
        
        # Only active users can grant permissions
        if not granter.is_active():
            return False
        
        # Granter must have the permission themselves (delegation rule)
        if permission_id not in granter._permission_ids:
            return False
        
        return True
    
    def calculate_effective_permissions(self, user: 'User') -> set[str]:
        """Calculate all effective permissions for a user."""
        permissions = set()
        
        # Add permissions from roles (would need role lookup service)
        for role_id in user._role_ids:
            role_permissions = self._get_role_permissions(role_id)
            permissions.update(role_permissions)
        
        # Add direct permissions
        for permission_id in user._permission_ids:
            permission_name = self._get_permission_name(permission_id)
            if permission_name:
                permissions.add(permission_name)
        
        # Account type based permissions
        if user.account_type == AccountType.ADMIN:
            permissions.update(self._get_admin_permissions())
        
        return permissions
    
    def get_role_hierarchy_level(self, user: 'User') -> int:
        """Get user's highest role hierarchy level."""
        if user.account_type == AccountType.ADMIN:
            return 100
        
        if user.account_type == AccountType.SERVICE:
            return 10
        
        # Would need to look up actual roles and their levels
        max_level = 1  # Base user level
        for role_id in user._role_ids:
            role_level = self._get_role_level(role_id)
            max_level = max(max_level, role_level)
        
        return max_level
    
    def validate_role_assignment(self, user: 'User', role_id: UUID) -> tuple[bool, str]:
        """Validate if role can be assigned to user."""
        # Check if user already has role
        if role_id in user._role_ids:
            return False, "User already has this role"
        
        # Check account type compatibility
        if user.account_type == AccountType.GUEST:
            return False, "Guest accounts cannot be assigned roles"
        
        # Check if user is active
        if not user.is_active():
            return False, "Cannot assign roles to inactive users"
        
        # Business rule: Max roles per user
        if len(user._role_ids) >= 10:  # Example limit
            return False, "User has reached maximum role limit"
        
        return True, "Role assignment valid"
    
    def _get_user_authority_level(self, user: 'User') -> int:
        """Get user's authority level for comparison."""
        if user.account_type == AccountType.ADMIN:
            return 1000
        
        return self.get_role_hierarchy_level(user)
    
    def _get_role_permissions(self, role_id: UUID) -> set[str]:
        """Get permissions for a role (would integrate with role service)."""
        # This would integrate with role aggregate/service
        return set()
    
    def _get_permission_name(self, permission_id: UUID) -> str | None:
        """Get permission name by ID (would integrate with permission service)."""
        # This would integrate with permission aggregate/service
        return None
    
    def _get_admin_permissions(self) -> set[str]:
        """Get all admin permissions."""
        return {
            "user_management", "role_management", "permission_management",
            "system_administration", "security_management", "audit_access"
        }
    
    def _get_role_level(self, role_id: UUID) -> int:
        """Get role hierarchy level (would integrate with role service)."""
        # This would integrate with role aggregate/service
        return 1


# Export the service
__all__ = ['UserPermissionService']