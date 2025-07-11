"""
Authorization Domain Service

Pure domain service coordinating authorization policies with aggregates.
No infrastructure concerns - only business logic.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ...aggregates.user import User
from ...interfaces.repositories.security.role_repository import IRoleRepository
from ...interfaces.repositories.user.user_repository import IUserRepository
from ...interfaces.services.security.authorization_service import IAuthorizationService


@dataclass(frozen=True)
class PermissionCheckResult:
    """Domain value object for permission check results."""
    granted: bool
    reason: str
    required_permissions: list[str]
    missing_permissions: list[str]
    effective_scope: dict[str, Any]
    
    def is_granted(self) -> bool:
        """Check if permission is granted."""
        return self.granted


@dataclass(frozen=True)
class AccessDecision:
    """Domain value object for authorization access decisions."""
    allowed: bool
    reason: str
    conditions: list[str]
    risk_factors: dict[str, Any]
    
    def is_allowed(self) -> bool:
        """Check if access is allowed."""
        return self.allowed


class AuthorizationService(IAuthorizationService):
    """Pure domain service for authorization business logic.
    
    Coordinates permission checking using aggregates and domain rules.
    Application Service handles infrastructure concerns like caching/audit.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        role_repository: IRoleRepository
    ) -> None:
        self._user_repository = user_repository
        self._role_repository = role_repository
    
    async def check_permission(
        self,
        user_id: UUID,
        permission: str,
        resource: str | None = None,
        resource_owner_id: UUID | None = None
    ) -> dict[str, Any]:
        """Check permission using pure domain logic."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return self._permission_denied_result(permission, "User not found")
        
        # Use aggregate method for permission check
        if user.has_direct_permission(permission):
            return self._permission_granted_result(permission, "Direct permission", user)
        
        # Check wildcard permissions through aggregate
        wildcard_match = user.find_wildcard_permission(permission)
        if wildcard_match:
            return self._permission_granted_result(permission, f"Wildcard: {wildcard_match}", user)
        
        # Check resource ownership through domain logic
        if resource_owner_id and user.can_access_owned_resource(resource_owner_id):
            return self._permission_granted_result(permission, "Resource ownership", user)
        
        return self._permission_denied_result(permission, "Permission not found")
    
    async def get_effective_permissions(self, user_id: UUID) -> set[str]:
        """Get effective permissions using domain aggregates."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return set()
        
        # Use aggregate method to get all permissions including roles
        all_permissions = user.get_all_permissions()
        
        # Add role-based permissions through domain coordination
        for role in user.get_roles():
            role_entity = await self._role_repository.get_by_id(role.id)
            if role_entity:
                role_permissions = role_entity.get_permissions()
                all_permissions.extend(role_permissions)
        
        return {perm.name for perm in all_permissions}
    
    async def validate_access(
        self,
        user_id: UUID,
        action: str,
        resource: str,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate access using domain business rules."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return self._access_denied_result("User not found")
        
        # Check basic permission
        permission_name = f"{resource}:{action}"
        if not user.has_permission_for_action(permission_name):
            return self._access_denied_result("Insufficient permissions")
        
        # Apply domain authorization rules
        return self._apply_domain_authorization_rules(
            user, action, resource, context
        )
        
    
    async def calculate_permission_matrix(
        self,
        user_id: UUID,
        resources: list[str] | None = None
    ) -> dict[str, dict[str, bool]]:
        """Calculate permission matrix using aggregate methods."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return {}
        
        # Use domain method to calculate matrix
        default_resources = resources if resources else ["user", "role", "permission", "session", "audit"]
        default_actions = ["create", "read", "update", "delete", "admin"]
        
        matrix = {}
        for resource in default_resources:
            matrix[resource] = {}
            for action in default_actions:
                permission = f"{resource}:{action}"
                matrix[resource][action] = user.has_permission_for_action(permission)
        
        return matrix
    
    async def check_segregation_of_duties(
        self,
        user_id: UUID,
        new_permission: str
    ) -> tuple[bool, str]:
        """Check segregation of duties using domain rules."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return False, "User not found"
        
        # Use domain method for segregation check
        segregation_result = user.check_segregation_of_duties(new_permission)
        
        return segregation_result.is_compliant, segregation_result.reason
    
    def invalidate_permission_cache(self, user_id: UUID) -> None:
        """Cache invalidation handled by Application Service."""
        # Domain service doesn't handle infrastructure concerns
    
    # Pure domain helper methods
    
    def _permission_granted_result(
        self, 
        permission: str, 
        reason: str, 
        user: User
    ) -> dict[str, Any]:
        """Create permission granted result."""
        return {
            "granted": True,
            "reason": reason,
            "required_permissions": [permission],
            "missing_permissions": [],
            "effective_scope": self._get_permission_scope(permission, user)
        }
    
    def _permission_denied_result(
        self, 
        permission: str, 
        reason: str
    ) -> dict[str, Any]:
        """Create permission denied result."""
        return {
            "granted": False,
            "reason": reason,
            "required_permissions": [permission],
            "missing_permissions": [permission],
            "effective_scope": {}
        }
    
    def _access_denied_result(self, reason: str) -> dict[str, Any]:
        """Create access denied result."""
        return {
            "allowed": False,
            "reason": reason,
            "conditions": [],
            "risk_factors": {}
        }
    
    def _apply_domain_authorization_rules(
        self, 
        user: User, 
        action: str, 
        resource: str, 
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Apply domain authorization business rules."""
        
        conditions = []
        risk_factors = {}
        
        # High-risk operation rules
        risk_score = context.get("risk_score", 0.0)
        if risk_score > 0.7 and action in ["delete", "admin", "grant_permission"]:
            if not context.get("mfa_verified", False):
                return {
                    "allowed": False,
                    "reason": "MFA required for high-risk operation",
                    "conditions": ["mfa_required"],
                    "risk_factors": {"risk_score": risk_score}
                }
        
        # Business hours rules for admin actions
        if action in ["admin", "system"] and not self._is_business_hours():
            if not user.has_super_admin_role():
                conditions.append("business_hours_only")
        
        # Device trust requirements
        if action in ["grant_permission", "delete_user"] and not context.get("device_trusted", False):
            conditions.append("trusted_device_required")
        
        # External IP risk factor
        if context.get("ip_address") and not self._is_private_ip(context["ip_address"]):
            risk_factors["external_ip"] = True
        
        return {
            "allowed": True,
            "reason": "Access granted",
            "conditions": conditions,
            "risk_factors": risk_factors
        }
    
    def _get_permission_scope(self, permission: str, user: User) -> dict[str, Any]:
        """Get permission scope using domain logic."""
        scope = {"global": False}
        
        # User-scoped permissions
        if permission.startswith("user:") and not user.has_admin_role():
            scope["user_id"] = str(user.id)
        
        return scope
    
    def _is_business_hours(self) -> bool:
        """Check if current time is business hours."""
        current_hour = datetime.now(UTC).hour
        return 9 <= current_hour <= 17
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private range."""
        private_ranges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.']
        return any(ip_address.startswith(prefix) for prefix in private_ranges)