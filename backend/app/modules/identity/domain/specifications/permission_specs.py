"""
Permission Domain Specifications

Business rule specifications for permission-related operations.
"""


from app.core.infrastructure.specification import Specification

from ..aggregates.user import User
from ..entities.permission import Permission


class HasPermissionSpecification(Specification[User]):
    """Specification for users with specific permission."""
    
    def __init__(self, permission_name: str):
        self.permission_name = permission_name
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has specific permission."""
        return user.has_permission(self.permission_name)


class PermissionScopeSpecification(Specification[Permission]):
    """Specification for permissions with specific scope."""
    
    def __init__(self, scope: str):
        self.scope = scope
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission has specific scope."""
        return (
            hasattr(permission, 'scope') and 
            permission.scope == self.scope
        )


class PermissionInheritanceSpecification(Specification[User]):
    """Specification for users with inherited permissions."""
    
    def __init__(self, permission_name: str):
        self.permission_name = permission_name
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has permission through role inheritance."""
        # Check direct permissions first
        direct_permissions = {p.name for p in user._permissions}
        if self.permission_name in direct_permissions:
            return True
        
        # Check role-based permissions
        for role in user._roles:
            role_permissions = {p.name for p in role.permissions}
            if self.permission_name in role_permissions:
                return True
        
        return False


class SystemPermissionSpecification(Specification[Permission]):
    """Specification for system-level permissions."""
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is system-level."""
        system_prefixes = ['system_', 'admin_', 'super_']
        return any(permission.name.startswith(prefix) for prefix in system_prefixes)


class PermissionByCategorySpecification(Specification[Permission]):
    """Specification for permissions in specific category."""
    
    def __init__(self, category: str):
        self.category = category
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission belongs to category."""
        return (
            hasattr(permission, 'category') and 
            permission.category == self.category
        )


class WildcardPermissionSpecification(Specification[Permission]):
    """Specification for wildcard permissions."""
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is a wildcard permission."""
        return '*' in permission.name


class DeprecatedPermissionSpecification(Specification[Permission]):
    """Specification for deprecated permissions."""
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is deprecated."""
        return (
            hasattr(permission, 'deprecated') and 
            permission.deprecated
        )


class ResourcePermissionSpecification(Specification[Permission]):
    """Specification for resource-specific permissions."""
    
    def __init__(self, resource_type: str):
        self.resource_type = resource_type
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is for specific resource type."""
        return permission.name.startswith(f"{self.resource_type}:")


class ActionPermissionSpecification(Specification[Permission]):
    """Specification for action-specific permissions."""
    
    def __init__(self, action: str):
        self.action = action
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is for specific action."""
        return permission.name.endswith(f":{self.action}")


class TemporaryPermissionSpecification(Specification[Permission]):
    """Specification for temporary permissions."""
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission is temporary."""
        return (
            hasattr(permission, 'expires_at') and 
            permission.expires_at is not None
        )


class ConditionalPermissionSpecification(Specification[Permission]):
    """Specification for conditional permissions."""
    
    def is_satisfied_by(self, permission: Permission) -> bool:
        """Check if permission has conditions."""
        return (
            hasattr(permission, 'conditions') and 
            permission.conditions
        )


class EffectivePermissionSpecification(Specification[User]):
    """Specification for users with effective permissions."""
    
    def __init__(self, permission_names: set[str]):
        self.permission_names = permission_names
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has all specified effective permissions."""
        user_permissions = {p.name for p in user.get_all_permissions()}
        return self.permission_names.issubset(user_permissions)


class ExclusivePermissionSpecification(Specification[User]):
    """Specification for users with mutually exclusive permissions."""
    
    def __init__(self, exclusive_groups: list[set[str]]):
        self.exclusive_groups = exclusive_groups
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user doesn't have conflicting permissions."""
        user_permissions = {p.name for p in user.get_all_permissions()}
        
        for group in self.exclusive_groups:
            intersection = user_permissions.intersection(group)
            if len(intersection) > 1:
                return False  # User has conflicting permissions
        
        return True