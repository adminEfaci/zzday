"""
Group Permission Service

Domain service for complex permission logic that doesn't belong to a single entity.
"""

from typing import TYPE_CHECKING

from ...entities.group.group_constants import GroupPermissionMatrix
from ...entities.group.group_enums import GroupMemberRole

if TYPE_CHECKING:
    from ...entities.group.group_member import GroupMember


class GroupPermissionService:
    """Domain service for group permission calculations."""
    
    def member_has_permission(self, member: 'GroupMember', permission: str) -> bool:
        """Check if member has specific permission."""
        # Check if permission is explicitly denied
        if permission in member.denied_permissions:
            return False
        
        # Check if permission is in custom permissions
        if permission in member.custom_permissions:
            return True
        
        # Check role-based permissions
        role_permissions = GroupPermissionMatrix.get_permissions_for_role(member.role.value)
        return permission in role_permissions
    
    def calculate_effective_permissions(self, member: 'GroupMember') -> set[str]:
        """Calculate all effective permissions for a member."""
        # Start with role-based permissions
        permissions = GroupPermissionMatrix.get_permissions_for_role(member.role.value)
        
        # Add custom permissions
        permissions.update(member.custom_permissions)
        
        # Remove denied permissions
        permissions.difference_update(member.denied_permissions)
        
        return permissions
    
    def can_manage_member(self, managing_member: 'GroupMember', target_member: 'GroupMember') -> bool:
        """Check if one member can manage another member."""
        # Owners can manage everyone except other owners
        if managing_member.is_owner:
            return not target_member.is_owner or managing_member.user_id == target_member.user_id
        
        # Admins can manage non-admins and non-owners
        if managing_member.is_admin:
            return target_member.role not in [GroupMemberRole.OWNER, GroupMemberRole.ADMIN]
        
        # Moderators can manage regular members and guests
        if managing_member.is_moderator:
            return target_member.role in [GroupMemberRole.MEMBER, GroupMemberRole.GUEST]
        
        return False
    
    def get_role_hierarchy_level(self, role: GroupMemberRole) -> int:
        """Get numeric level for role comparison."""
        levels = {
            GroupMemberRole.GUEST: 1,
            GroupMemberRole.MEMBER: 2,
            GroupMemberRole.MODERATOR: 3,
            GroupMemberRole.ADMIN: 4,
            GroupMemberRole.OWNER: 5
        }
        return levels.get(role, 0)
    
    def can_assign_role(self, assigning_member: 'GroupMember', target_role: GroupMemberRole) -> bool:
        """Check if member can assign a specific role."""
        assigning_level = self.get_role_hierarchy_level(assigning_member.role)
        target_level = self.get_role_hierarchy_level(target_role)
        
        # Can only assign roles lower than your own level
        return assigning_level > target_level
    
    def get_manageable_roles(self, member: 'GroupMember') -> list[GroupMemberRole]:
        """Get list of roles this member can assign to others."""
        member_level = self.get_role_hierarchy_level(member.role)
        manageable_roles = []
        
        for role in GroupMemberRole:
            if self.get_role_hierarchy_level(role) < member_level:
                manageable_roles.append(role)
        
        return manageable_roles


# Export the service
__all__ = ['GroupPermissionService']