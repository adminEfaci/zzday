"""
Permission Domain Services

Domain services for complex permission operations that span multiple aggregates
or require external dependencies.
"""

import asyncio
import re
from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from ..permission import Permission
from ..role_enums import PermissionType, ResourceType


class IPermissionRepository(ABC):
    """Permission repository interface."""
    
    @abstractmethod
    async def get_by_id(self, permission_id: UUID) -> Permission | None:
        pass
    
    @abstractmethod
    async def get_by_code(self, code: str) -> Permission | None:
        pass
    
    @abstractmethod
    async def get_children(self, parent_id: UUID) -> list[Permission]:
        pass
    
    @abstractmethod
    async def get_descendants(self, parent_id: UUID) -> list[Permission]:
        pass
    
    @abstractmethod
    async def find_by_path_prefix(self, path_prefix: str) -> list[Permission]:
        pass


class PermissionHierarchyService:
    """Service for managing permission hierarchies and relationships."""
    
    def __init__(self, permission_repo: IPermissionRepository):
        self._permission_repo = permission_repo
        self._lock = asyncio.Lock()
        self._hierarchy_cache: dict[UUID, set[UUID]] = {}
        self._cache_lock = asyncio.Lock()
    
    async def validate_hierarchy_move(
        self, 
        permission: Permission, 
        new_parent: Permission | None
    ) -> None:
        """Validate that moving permission to new parent won't create cycles."""
        if not new_parent:
            return
        
        if permission.id == new_parent.id:
            raise ValueError("Permission cannot be its own parent")
        
        # Check if new parent is a descendant of permission
        if await self._is_descendant(new_parent.id, permission.id):
            raise ValueError("Cannot move permission: would create circular reference")
        
        # Check hierarchy depth
        new_depth = new_parent.depth + 1
        if new_depth > 10:
            raise ValueError("Permission hierarchy too deep (max 10 levels)")
    
    async def get_all_descendants(self, permission_id: UUID) -> set[UUID]:
        """Get all descendant permission IDs with caching."""
        async with self._cache_lock:
            if permission_id in self._hierarchy_cache:
                return self._hierarchy_cache[permission_id].copy()
        
        descendants = await self._permission_repo.get_descendants(permission_id)
        descendant_ids = {p.id for p in descendants}
        
        async with self._cache_lock:
            self._hierarchy_cache[permission_id] = descendant_ids
        
        return descendant_ids
    
    async def get_effective_permissions(
        self, 
        permission_ids: set[UUID]
    ) -> set[Permission]:
        """Get effective permissions including inherited ones."""
        effective = set()
        
        for pid in permission_ids:
            permission = await self._permission_repo.get_by_id(pid)
            if permission and permission.is_active:
                effective.add(permission)
                
                # Add descendants if permission implies them
                descendants = await self._permission_repo.get_descendants(pid)
                for desc in descendants:
                    if desc.is_active and permission.implies(desc):
                        effective.add(desc)
        
        return effective
    
    async def rebuild_materialized_paths(self, root_permission_id: UUID) -> None:
        """Rebuild materialized paths for permission subtree with concurrency control."""
        async with self._lock:
            root = await self._permission_repo.get_by_id(root_permission_id)
            if not root:
                return
            
            # Clear cache for this hierarchy
            async with self._cache_lock:
                self._hierarchy_cache.clear()
            
            await self._rebuild_paths_recursive(root, root.path.rsplit('/', 1)[0] if '/' in root.path else "")
    
    async def _is_descendant(self, potential_descendant_id: UUID, ancestor_id: UUID) -> bool:
        """Check if potential_descendant is a descendant of ancestor."""
        descendants = await self.get_all_descendants(ancestor_id)
        return potential_descendant_id in descendants
    
    async def _rebuild_paths_recursive(self, permission: Permission, parent_path: str) -> None:
        """Recursively rebuild paths for permission and its children."""
        new_path = f"{parent_path}/{permission.id}" if parent_path else str(permission.id)
        permission.path = new_path
        
        children = await self._permission_repo.get_children(permission.id)
        for child in children:
            await self._rebuild_paths_recursive(child, new_path)


class PermissionEvaluationService:
    """Service for evaluating permission matches and implications."""
    
    def __init__(self, permission_repo: IPermissionRepository):
        self._permission_repo = permission_repo
        self._evaluation_cache: dict[str, bool] = {}
        self._cache_lock = asyncio.Lock()
        self._max_cache_size = 10000
    
    async def evaluate_permission_request(
        self, 
        user_permissions: set[Permission],
        requested_permission_code: str,
        context: dict[str, Any] | None = None
    ) -> bool:
        """Evaluate if user has permission for requested action with caching."""
        context = context or {}
        
        # Create cache key
        cache_key = self._create_cache_key(user_permissions, requested_permission_code, context)
        
        # Check cache first
        async with self._cache_lock:
            if cache_key in self._evaluation_cache:
                return self._evaluation_cache[cache_key]
        
        # Evaluate permissions
        result = await self._evaluate_permissions_uncached(user_permissions, requested_permission_code, context)
        
        # Cache result
        async with self._cache_lock:
            if len(self._evaluation_cache) >= self._max_cache_size:
                # Simple LRU eviction - remove first item
                first_key = next(iter(self._evaluation_cache))
                del self._evaluation_cache[first_key]
            
            self._evaluation_cache[cache_key] = result
        
        return result
    
    async def _evaluate_permissions_uncached(
        self, 
        user_permissions: set[Permission],
        requested_permission_code: str,
        context: dict[str, Any]
    ) -> bool:
        """Evaluate permissions without caching."""
        for permission in user_permissions:
            if not permission.is_active:
                continue
            
            # Direct match
            if permission.matches(requested_permission_code):
                return permission.evaluate_constraints(context)
            
            # Check for wildcard or hierarchical matches
            if await self._check_hierarchical_match(permission, requested_permission_code):
                return permission.evaluate_constraints(context)
        
        return False
    
    def _create_cache_key(
        self, 
        user_permissions: set[Permission],
        requested_permission_code: str,
        context: dict[str, Any]
    ) -> str:
        """Create cache key for permission evaluation."""
        permission_ids = sorted([str(p.id) for p in user_permissions])
        context_str = str(sorted(context.items())) if context else ""
        return f"{':'.join(permission_ids)}:{requested_permission_code}:{context_str}"
    
    async def find_conflicting_permissions(
        self, 
        permissions: set[Permission]
    ) -> list[tuple[Permission, Permission]]:
        """Find permissions that conflict with each other using concurrent checks."""
        conflicts = []
        permission_list = list(permissions)
        
        # Create tasks for conflict checking
        tasks = []
        for i, perm1 in enumerate(permission_list):
            for perm2 in permission_list[i+1:]:
                tasks.append(self._check_conflict_pair(perm1, perm2))
        
        # Execute conflict checks concurrently
        if tasks:
            results = await asyncio.gather(*tasks)
            
            # Collect conflicts
            task_index = 0
            for i, perm1 in enumerate(permission_list):
                for perm2 in permission_list[i+1:]:
                    if results[task_index]:
                        conflicts.append((perm1, perm2))
                    task_index += 1
        
        return conflicts
    
    async def _check_conflict_pair(self, perm1: Permission, perm2: Permission) -> bool:
        """Check if two permissions conflict."""
        return await self._are_conflicting(perm1, perm2)
    
    async def resolve_permission_implications(
        self, 
        permissions: set[Permission]
    ) -> set[Permission]:
        """Resolve all implied permissions from a set of permissions."""
        resolved = set(permissions)
        
        for permission in permissions:
            if permission.is_wildcard:
                # Find all permissions that match the wildcard
                implied = await self._find_wildcard_matches(permission)
                resolved.update(implied)
        
        return resolved
    
    async def _check_hierarchical_match(
        self, 
        permission: Permission, 
        requested_code: str
    ) -> bool:
        """Check if permission hierarchically matches requested code."""
        # Get all descendants and check if any match
        descendants = await self._permission_repo.get_descendants(permission.id)
        return any(desc.code == requested_code for desc in descendants)
    
    async def _are_conflicting(self, perm1: Permission, perm2: Permission) -> bool:
        """Check if two permissions conflict."""
        # Same resource but different effects
        if (perm1.resource == perm2.resource and 
            perm1.action == perm2.action and
            perm1.is_active != perm2.is_active):
            return True
        
        # Overlapping scopes with different constraints
        return (perm1.scope and perm2.scope and 
                perm1.scope.overlaps(perm2.scope) and
                perm1.constraints != perm2.constraints)
    
    async def _find_wildcard_matches(self, wildcard_permission: Permission) -> set[Permission]:
        """Find all permissions that match a wildcard permission."""
        if not wildcard_permission.is_wildcard:
            return set()
        
        # This would typically query the repository for matching permissions
        # Implementation depends on your storage and indexing strategy
        pattern = wildcard_permission.code.replace('.', r'\.').replace('*', '.*')
        
        # Simplified implementation - in practice, you'd use database queries
        all_permissions = []  # Would come from repository
        matches = set()
        
        for perm in all_permissions:
            if re.match(f"^{pattern}$", perm.code):
                matches.add(perm)
        
        return matches


class PermissionValidationService:
    """Service for validating permission operations."""
    
    def __init__(self, permission_repo: IPermissionRepository):
        self._permission_repo = permission_repo
        self._validation_cache: dict[str, bool] = {}
        self._cache_lock = asyncio.Lock()
        self._max_cache_size = 5000
    
    async def validate_permission_creation(
        self,
        code: str,
        name: str,
        permission_type: PermissionType,
        resource_type: ResourceType,
        parent: Permission | None = None
    ) -> None:
        """Validate permission creation request with caching."""
        # Check cache for code validation
        cache_key = f"code_valid:{code}"
        async with self._cache_lock:
            code_valid = self._validation_cache.get(cache_key)
        
        if code_valid is None:
            # Validate code format
            code_valid = self._is_valid_permission_code(code)
            
            async with self._cache_lock:
                if len(self._validation_cache) >= self._max_cache_size:
                    # Simple LRU eviction
                    first_key = next(iter(self._validation_cache))
                    del self._validation_cache[first_key]
                
                self._validation_cache[cache_key] = code_valid
        
        if not code_valid:
            raise ValueError(f"Invalid permission code format: {code}")
        
        # Check for duplicate code
        existing = await self._permission_repo.get_by_code(code)
        if existing:
            raise ValueError(f"Permission with code '{code}' already exists")
        
        # Validate parent relationship
        if parent:
            if not parent.is_active:
                raise ValueError("Cannot create permission under inactive parent")
            
            if parent.depth >= 9:  # Max depth 10
                raise ValueError("Parent permission hierarchy too deep")
    
    async def validate_permission_assignment(
        self,
        permission: Permission,
        context: dict[str, Any] | None = None
    ) -> None:
        """Validate permission assignment to role/user."""
        context = context or {}
        
        if not permission.is_active:
            raise ValueError("Cannot assign inactive permission")
        
        if permission.is_dangerous and not context.get("confirmed_dangerous", False):
            raise ValueError("Dangerous permission assignment requires explicit confirmation")
        
        if permission.requires_mfa and not context.get("mfa_verified", False):
            raise ValueError("Permission requires MFA verification")
    
    def _is_valid_permission_code(self, code: str) -> bool:
        """Validate permission code format."""
        if not code or len(code) > 100:
            return False
        
        # Must follow resource.action or resource.subresource.action pattern
        pattern = r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$'
        return bool(re.match(pattern, code))


class PermissionPolicyService:
    """Service for permission policy operations."""
    
    def __init__(self, permission_repo: IPermissionRepository):
        self._permission_repo = permission_repo
        self._policy_cache: dict[str, dict[str, Any]] = {}
        self._cache_lock = asyncio.Lock()
        self._max_cache_size = 1000
    
    async def generate_policy_document(
        self, 
        permissions: set[Permission],
        policy_format: str = "json"
    ) -> dict[str, Any]:
        """Generate policy document from permissions."""
        statements = []
        
        for permission in permissions:
            if permission.is_active:
                statements.append(permission.to_policy_statement())
        
        return {
            "version": "1.0",
            "statements": statements,
            "generated_at": "timestamp",
            "format": policy_format
        }
    
    async def optimize_permission_set(
        self, 
        permissions: set[Permission]
    ) -> set[Permission]:
        """Optimize permission set by removing redundant permissions using concurrent checks."""
        optimized = set()
        permission_list = list(permissions)
        
        # Create implication matrix concurrently
        tasks = []
        for i, perm1 in enumerate(permission_list):
            for j, perm2 in enumerate(permission_list):
                if i != j:
                    tasks.append(self._check_implication(perm1, perm2, i, j))
        
        # Execute implication checks concurrently
        if tasks:
            results = await asyncio.gather(*tasks)
            
            # Build implication matrix
            implications = {}
            for result in results:
                if result[2]:  # if implies
                    implications.setdefault(result[0], set()).add(result[1])
        
        # Find non-redundant permissions
        for i, permission in enumerate(permission_list):
            is_redundant = False
            for j, _other in enumerate(permission_list):
                if i != j and j in implications.get(i, set()):
                    is_redundant = True
                    break
            
            if not is_redundant:
                optimized.add(permission)
        
        return optimized
    
    async def _check_implication(self, perm1: Permission, perm2: Permission, i: int, j: int) -> tuple[int, int, bool]:
        """Check if perm1 implies perm2 and return indices."""
        implies = perm1.implies(perm2)
        return (i, j, implies)
    
    async def calculate_permission_risk_score(
        self, 
        permissions: set[Permission]
    ) -> float:
        """Calculate risk score for a set of permissions."""
        total_risk = 0.0
        
        for permission in permissions:
            risk = 1.0  # Base risk
            
            if permission.is_dangerous:
                risk *= 3.0
            
            if permission.is_delete:
                risk *= 2.0
            elif permission.is_write:
                risk *= 1.5
            
            if permission.scope and permission.scope.get_hierarchy_level() > 4:
                risk *= 1.5  # Broader scope = higher risk
            
            if permission.is_wildcard:
                risk *= 2.0
            
            total_risk += risk
        
        return min(total_risk / len(permissions) if permissions else 0.0, 10.0)


# Factory for creating permission services
class PermissionServiceFactory:
    """Factory for creating permission domain services."""
    
    def __init__(self, permission_repo: IPermissionRepository):
        self._permission_repo = permission_repo
        self._service_cache: dict[str, Any] = {}
        self._cache_lock = asyncio.Lock()
    
    async def get_cached_service(self, service_type: str) -> Any:
        """Get cached service instance."""
        async with self._cache_lock:
            return self._service_cache.get(service_type)
    
    async def cache_service(self, service_type: str, service: Any) -> None:
        """Cache service instance."""
        async with self._cache_lock:
            self._service_cache[service_type] = service
    
    def create_hierarchy_service(self) -> PermissionHierarchyService:
        return PermissionHierarchyService(self._permission_repo)
    
    def create_evaluation_service(self) -> PermissionEvaluationService:
        return PermissionEvaluationService(self._permission_repo)
    
    def create_validation_service(self) -> PermissionValidationService:
        return PermissionValidationService(self._permission_repo)
    
    def create_policy_service(self) -> PermissionPolicyService:
        return PermissionPolicyService(self._permission_repo)


# Export all services
__all__ = [
    'IPermissionRepository',
    'PermissionEvaluationService',
    'PermissionHierarchyService',
    'PermissionPolicyService',
    'PermissionServiceFactory',
    'PermissionValidationService'
]