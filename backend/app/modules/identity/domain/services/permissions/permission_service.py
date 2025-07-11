"""
Permission Domain Service

Pure domain service for permission logic, validation, and business rules.
Contains only domain logic with no infrastructure dependencies.
"""

from typing import Any, Set
from uuid import UUID

from ...entities.role.permission import Permission
from ...enums import PermissionAction, ResourceType
from ...value_objects.permission_scope import PermissionScope


class PermissionService:
    """Domain service for permission operations and validation."""
    
    @staticmethod
    def validate_permission_hierarchy(
        permission: Permission,
        new_parent: Permission | None
    ) -> None:
        """Validate that permission hierarchy rules are followed."""
        if not new_parent:
            return
        
        if permission.id == new_parent.id:
            raise ValueError("Permission cannot be its own parent")
        
        # Check hierarchy depth
        if new_parent.depth and new_parent.depth >= 9:  # Max depth 10
            raise ValueError("Permission hierarchy too deep (max 10 levels)")
        
        # Check for circular references (simplified - would need full hierarchy in real implementation)
        if hasattr(new_parent, 'parent_id') and new_parent.parent_id == permission.id:
            raise ValueError("Cannot move permission: would create circular reference")
    
    @staticmethod
    def validate_permission_assignment(
        permission: Permission,
        context: dict[str, Any] | None = None
    ) -> None:
        """Validate permission assignment to role/user."""
        context = context or {}
        
        if not permission.is_active:
            raise ValueError("Cannot assign inactive permission")
        
        if hasattr(permission, 'is_dangerous') and permission.is_dangerous:
            if not context.get("confirmed_dangerous", False):
                raise ValueError("Dangerous permission assignment requires explicit confirmation")
        
        if hasattr(permission, 'requires_mfa') and permission.requires_mfa:
            if not context.get("mfa_verified", False):
                raise ValueError("Permission requires MFA verification")
    
    @staticmethod
    def calculate_permission_risk_score(permissions: Set[Permission]) -> float:
        """Calculate risk score for a set of permissions."""
        if not permissions:
            return 0.0
        
        total_risk = 0.0
        
        for permission in permissions:
            risk = 1.0  # Base risk
            
            # Risk factors based on permission attributes
            if hasattr(permission, 'is_dangerous') and permission.is_dangerous:
                risk *= 3.0
            
            if permission.action == PermissionAction.DELETE:
                risk *= 2.0
            elif permission.action in [PermissionAction.CREATE, PermissionAction.UPDATE]:
                risk *= 1.5
            
            # Scope-based risk
            if permission.scope:
                scope_level = PermissionService._get_scope_level(permission.scope)
                if scope_level > 4:
                    risk *= 1.5  # Broader scope = higher risk
            
            # Wildcard permissions are riskier
            if hasattr(permission, 'is_wildcard') and permission.is_wildcard:
                risk *= 2.0
            
            total_risk += risk
        
        return min(total_risk / len(permissions), 10.0)
    
    @staticmethod
    def _get_scope_level(scope: PermissionScope) -> int:
        """Get the hierarchy level of a permission scope."""
        # This would depend on your PermissionScope implementation
        if hasattr(scope, 'get_hierarchy_level'):
            return scope.get_hierarchy_level()
        return 1  # Default level
    
    @staticmethod
    def find_conflicting_permissions(permissions: Set[Permission]) -> list[tuple[Permission, Permission]]:
        """Find permissions that conflict with each other."""
        conflicts = []
        permission_list = list(permissions)
        
        for i, perm1 in enumerate(permission_list):
            for perm2 in permission_list[i+1:]:
                if PermissionService._are_conflicting(perm1, perm2):
                    conflicts.append((perm1, perm2))
        
        return conflicts
    
    @staticmethod
    def _are_conflicting(perm1: Permission, perm2: Permission) -> bool:
        """Check if two permissions conflict."""
        # Same resource and action but different effects
        if (perm1.resource == perm2.resource and 
            perm1.action == perm2.action and
            perm1.is_active != perm2.is_active):
            return True
        
        # Overlapping scopes with different constraints
        if (perm1.scope and perm2.scope and 
            PermissionService._scopes_overlap(perm1.scope, perm2.scope) and
            getattr(perm1, 'constraints', None) != getattr(perm2, 'constraints', None)):
            return True
        
        return False
    
    @staticmethod
    def _scopes_overlap(scope1: PermissionScope, scope2: PermissionScope) -> bool:
        """Check if two permission scopes overlap."""
        if hasattr(scope1, 'overlaps'):
            return scope1.overlaps(scope2)
        # Simplified implementation
        return True
    
    @staticmethod
    def optimize_permission_set(permissions: Set[Permission]) -> Set[Permission]:
        """Optimize permission set by removing redundant permissions."""
        optimized = set()
        permission_list = list(permissions)
        
        for permission in permission_list:
            is_redundant = False
            
            # Check if this permission is implied by any other permission
            for other in permission_list:
                if (permission != other and 
                    PermissionService._implies(other, permission)):
                    is_redundant = True
                    break
            
            if not is_redundant:
                optimized.add(permission)
        
        return optimized
    
    @staticmethod
    def _implies(perm1: Permission, perm2: Permission) -> bool:
        """Check if perm1 implies perm2."""
        if hasattr(perm1, 'implies'):
            return perm1.implies(perm2)
        
        # Simplified implication logic
        # A broader permission implies a more specific one
        if (perm1.resource == perm2.resource and
            perm1.action == PermissionAction.ALL and
            perm2.action != PermissionAction.ALL):
            return True
        
        return False
    
    @staticmethod
    def validate_permission_code(code: str) -> bool:
        """Validate permission code format."""
        if not code or len(code) > 100:
            return False
        
        # Must follow resource.action or resource.subresource.action pattern
        import re
        pattern = r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$'
        return bool(re.match(pattern, code))
    
    @staticmethod
    def generate_permission_hierarchy_path(
        permission: Permission,
        parent: Permission | None = None
    ) -> str:
        """Generate materialized path for permission in hierarchy."""
        if not parent:
            return str(permission.id)
        
        parent_path = getattr(parent, 'path', str(parent.id))
        return f"{parent_path}/{permission.id}"
    
    @staticmethod
    def check_permission_match(
        user_permission: Permission,
        requested_permission_code: str,
        context: dict[str, Any] | None = None
    ) -> bool:
        """Check if user permission matches requested permission."""
        context = context or {}
        
        if not user_permission.is_active:
            return False
        
        # Direct code match
        if hasattr(user_permission, 'code') and user_permission.code == requested_permission_code:
            return PermissionService._evaluate_constraints(user_permission, context)
        
        # Wildcard match
        if hasattr(user_permission, 'is_wildcard') and user_permission.is_wildcard:
            if PermissionService._wildcard_match(user_permission.code, requested_permission_code):
                return PermissionService._evaluate_constraints(user_permission, context)
        
        return False
    
    @staticmethod
    def _wildcard_match(permission_code: str, requested_code: str) -> bool:
        """Check if wildcard permission matches requested code."""
        import re
        # Convert permission code wildcards to regex
        pattern = permission_code.replace('.', r'\.').replace('*', '.*')
        return bool(re.match(f"^{pattern}$", requested_code))
    
    @staticmethod
    def _evaluate_constraints(permission: Permission, context: dict[str, Any]) -> bool:
        """Evaluate permission constraints against context."""
        if not hasattr(permission, 'constraints') or not permission.constraints:
            return True
        
        # Simplified constraint evaluation
        # In a real implementation, this would be more sophisticated
        for constraint_key, constraint_value in permission.constraints.items():
            context_value = context.get(constraint_key)
            if context_value != constraint_value:
                return False
        
        return True
    
    @staticmethod
    def get_effective_permissions(
        direct_permissions: Set[Permission],
        inherited_permissions: Set[Permission] | None = None
    ) -> Set[Permission]:
        """Get effective permissions combining direct and inherited permissions."""
        effective = set(direct_permissions)
        
        if inherited_permissions:
            # Add inherited permissions that are not overridden
            for inherited in inherited_permissions:
                if inherited.is_active:
                    # Check if not overridden by a direct permission
                    overridden = False
                    for direct in direct_permissions:
                        if (direct.resource == inherited.resource and
                            direct.action == inherited.action):
                            overridden = True
                            break
                    
                    if not overridden:
                        effective.add(inherited)
        
        return effective
    
    @staticmethod
    def create_permission_summary(permissions: Set[Permission]) -> dict[str, Any]:
        """Create a summary of permissions for analysis."""
        if not permissions:
            return {
                "total_count": 0,
                "by_resource": {},
                "by_action": {},
                "risk_score": 0.0,
                "has_dangerous": False
            }
        
        by_resource = {}
        by_action = {}
        dangerous_count = 0
        
        for perm in permissions:
            if perm.is_active:
                # Group by resource
                resource = perm.resource.value if perm.resource else "unknown"
                by_resource[resource] = by_resource.get(resource, 0) + 1
                
                # Group by action  
                action = perm.action.value if perm.action else "unknown"
                by_action[action] = by_action.get(action, 0) + 1
                
                # Count dangerous permissions
                if hasattr(perm, 'is_dangerous') and perm.is_dangerous:
                    dangerous_count += 1
        
        risk_score = PermissionService.calculate_permission_risk_score(permissions)
        
        return {
            "total_count": len(permissions),
            "active_count": len([p for p in permissions if p.is_active]),
            "by_resource": by_resource,
            "by_action": by_action,
            "risk_score": risk_score,
            "has_dangerous": dangerous_count > 0,
            "dangerous_count": dangerous_count
        }
