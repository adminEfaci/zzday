"""
Role Domain Specifications

Business rule specifications for role-related operations.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.infrastructure.specification import Specification

from ..aggregates.user import User
from ..entities.role import Role


class RoleHierarchySpecification(Specification[Role]):
    """Specification for role hierarchy validation."""
    
    def __init__(self, parent_role: Role):
        self.parent_role = parent_role
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role can be a child of parent role."""
        # Prevent circular hierarchy
        if role.id == self.parent_role.id:
            return False
        
        # Check if parent would create a cycle
        current = self.parent_role
        visited = {role.id}
        
        while hasattr(current, 'parent_role') and current.parent_role:
            if current.parent_role.id in visited:
                return False  # Cycle detected
            visited.add(current.parent_role.id)
            current = current.parent_role
        
        return True


class RoleActiveSpecification(Specification[Role]):
    """Specification for active roles."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role is active."""
        return (
            hasattr(role, 'is_active') and 
            role.is_active and
            not self._is_expired(role)
        )
    
    def _is_expired(self, role: Role) -> bool:
        """Check if role has expired."""
        if not hasattr(role, 'expires_at') or not role.expires_at:
            return False
        return datetime.now(UTC) > role.expires_at


class RolePermissionSpecification(Specification[Role]):
    """Specification for roles with specific permissions."""
    
    def __init__(self, required_permissions: set[str]):
        self.required_permissions = required_permissions
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role has all required permissions."""
        role_permissions = {p.name for p in role.permissions}
        return self.required_permissions.issubset(role_permissions)


class SystemRoleSpecification(Specification[Role]):
    """Specification for system roles."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role is a system role."""
        system_roles = {'admin', 'super_admin', 'system_admin', 'root'}
        return role.name.lower() in system_roles


class RoleByLevelSpecification(Specification[Role]):
    """Specification for roles by authorization level."""
    
    def __init__(self, min_level: int):
        self.min_level = min_level
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role meets minimum authorization level."""
        if not hasattr(role, 'authorization_level'):
            return False
        return role.authorization_level >= self.min_level


class AssignableRoleSpecification(Specification[Role]):
    """Specification for roles that can be assigned."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role can be assigned to users."""
        # System roles might not be assignable
        system_spec = SystemRoleSpecification()
        if system_spec.is_satisfied_by(role):
            return hasattr(role, 'assignable') and role.assignable
        
        # Regular roles are assignable if active
        active_spec = RoleActiveSpecification()
        return active_spec.is_satisfied_by(role)


class TemporaryRoleSpecification(Specification[Role]):
    """Specification for temporary roles."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role is temporary."""
        return (
            hasattr(role, 'expires_at') and 
            role.expires_at is not None
        )


class ConditionalRoleSpecification(Specification[Role]):
    """Specification for conditional roles."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role has conditions for assignment."""
        return (
            hasattr(role, 'assignment_conditions') and 
            role.assignment_conditions
        )


class RoleConflictSpecification(Specification[User]):
    """Specification for detecting role conflicts."""
    
    def __init__(self, conflicting_roles: set[str]):
        self.conflicting_roles = conflicting_roles
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has conflicting roles."""
        user_roles = {r.name for r in user._roles}
        intersection = user_roles.intersection(self.conflicting_roles)
        return len(intersection) <= 1  # At most one conflicting role


class ElevatedRoleSpecification(Specification[Role]):
    """Specification for elevated privilege roles."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role has elevated privileges."""
        elevated_indicators = [
            'admin', 'super', 'root', 'manager', 'supervisor'
        ]
        return any(indicator in role.name.lower() for indicator in elevated_indicators)


class DepartmentRoleSpecification(Specification[Role]):
    """Specification for department-specific roles."""
    
    def __init__(self, department_id: UUID):
        self.department_id = department_id
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role is specific to a department."""
        return (
            hasattr(role, 'department_id') and 
            role.department_id == self.department_id
        )


class InheritableRoleSpecification(Specification[Role]):
    """Specification for roles that can inherit from others."""
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role supports inheritance."""
        return (
            hasattr(role, 'can_inherit') and 
            role.can_inherit
        )


class MaxUsersRoleSpecification(Specification[Role]):
    """Specification for roles with user limits."""
    
    def __init__(self, current_user_count: int):
        self.current_user_count = current_user_count
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role has capacity for more users."""
        if not hasattr(role, 'max_users') or not role.max_users:
            return True  # No limit
        return self.current_user_count < role.max_users


class RoleInUseSpecification(Specification[Role]):
    """Specification for roles currently assigned to users."""
    
    def __init__(self, assigned_user_count: int):
        self.assigned_user_count = assigned_user_count
    
    def is_satisfied_by(self, role: Role) -> bool:
        """Check if role is currently in use."""
        return self.assigned_user_count > 0