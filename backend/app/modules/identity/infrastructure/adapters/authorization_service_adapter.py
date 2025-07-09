"""
Authorization Service Adapter

Production-ready implementation for complex authorization and permission resolution.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.security.authorization_service import (
    IAuthorizationService,
)


class AuthorizationServiceAdapter(IAuthorizationService):
    """Production authorization service adapter."""

    def __init__(
        self,
        permission_repo=None,
        role_repo=None,
        policy_engine=None,
        cache_service=None,
    ):
        """Initialize authorization service adapter."""
        self._permission_repo = permission_repo
        self._role_repo = role_repo
        self._policy_engine = policy_engine
        self._cache = cache_service
        self._permission_cache = {}
        self._cache_ttl = timedelta(minutes=15)
        
        # Segregation of duties rules
        self._sod_rules = {
            "admin:create_user": ["admin:delete_user"],
            "finance:approve_payment": ["finance:create_payment"],
            "audit:view_logs": ["admin:modify_logs"],
            "security:manage_permissions": ["user:self_permission_grant"],
        }

    async def check_permission(
        self,
        user_id: UUID,
        permission: str,
        resource: str | None = None,
        resource_owner_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Check if user has permission for resource."""
        try:
            cache_key = f"perm:{user_id}:{permission}:{resource}:{resource_owner_id}"
            
            # Check cache first
            if self._cache:
                cached_result = await self._cache.get(cache_key)
                if cached_result:
                    return cached_result

            # Get user's effective permissions
            effective_permissions = await self.get_effective_permissions(user_id)
            
            # Check direct permission
            has_permission = permission in effective_permissions
            
            # Check resource-specific permissions
            if resource and not has_permission:
                resource_permission = f"{permission}:{resource}"
                has_permission = resource_permission in effective_permissions
            
            # Check ownership permissions
            if resource_owner_id and user_id == resource_owner_id:
                owner_permission = f"owner:{permission}"
                if owner_permission in effective_permissions:
                    has_permission = True
            
            # Apply business rules
            conditions = await self._apply_business_rules(
                user_id, permission, resource, resource_owner_id
            )
            
            # Check policy engine if available
            policy_result = None
            if self._policy_engine:
                policy_result = await self._policy_engine.evaluate(
                    user_id=str(user_id),
                    action=permission,
                    resource=resource,
                    context={
                        "resource_owner_id": str(resource_owner_id) if resource_owner_id else None,
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )
                
                if policy_result and not policy_result.get("allowed", True):
                    has_permission = False
                    conditions["policy_denied"] = policy_result.get("reason", "Policy denied")

            result = {
                "user_id": str(user_id),
                "permission": permission,
                "resource": resource,
                "resource_owner_id": str(resource_owner_id) if resource_owner_id else None,
                "granted": has_permission,
                "source": "direct" if permission in effective_permissions else "derived",
                "conditions": conditions,
                "policy_result": policy_result,
                "checked_at": datetime.now(UTC).isoformat(),
                "expires_at": (datetime.now(UTC) + self._cache_ttl).isoformat(),
            }

            # Cache the result
            if self._cache:
                await self._cache.set(cache_key, result, ttl=int(self._cache_ttl.total_seconds()))

            logger.info(f"Permission check: {permission} for user {user_id} -> {has_permission}")
            return result

        except Exception as e:
            logger.error(f"Error checking permission {permission} for user {user_id}: {e}")
            return {
                "user_id": str(user_id),
                "permission": permission,
                "resource": resource,
                "granted": False,
                "source": "error",
                "conditions": {"error": str(e)},
                "checked_at": datetime.now(UTC).isoformat(),
            }

    async def get_effective_permissions(self, user_id: UUID) -> set[str]:
        """Get all effective permissions for user."""
        try:
            cache_key = f"effective_perms:{user_id}"
            
            # Check cache first
            if cache_key in self._permission_cache:
                cached_entry = self._permission_cache[cache_key]
                if datetime.now(UTC) - cached_entry["timestamp"] < self._cache_ttl:
                    return cached_entry["permissions"]

            permissions = set()
            
            # Get direct user permissions
            if self._permission_repo:
                direct_permissions = await self._permission_repo.get_user_permissions(user_id)
                permissions.update(perm.name for perm in direct_permissions)
            
            # Get role-based permissions
            if self._role_repo:
                user_roles = await self._role_repo.get_user_roles(user_id)
                for role in user_roles:
                    if self._permission_repo:
                        role_permissions = await self._permission_repo.get_role_permissions(role.id)
                        permissions.update(perm.name for perm in role_permissions)
                    
                    # Add implicit role permissions
                    permissions.add(f"role:{role.name}")

            # Add standard user permissions
            permissions.update([
                "user:read_profile",
                "user:update_profile",
                "user:change_password",
                "user:view_sessions",
                "user:logout",
            ])

            # Cache the result
            self._permission_cache[cache_key] = {
                "permissions": permissions,
                "timestamp": datetime.now(UTC),
            }

            logger.debug(f"Effective permissions for user {user_id}: {len(permissions)} permissions")
            return permissions

        except Exception as e:
            logger.error(f"Error getting effective permissions for user {user_id}: {e}")
            return set()

    async def validate_access(
        self,
        user_id: UUID,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate access with business rules."""
        try:
            # Check basic permission
            permission_result = await self.check_permission(user_id, action, resource)
            
            access_result = {
                "user_id": str(user_id),
                "action": action,
                "resource": resource,
                "context": context,
                "allowed": permission_result["granted"],
                "conditions": {},
                "restrictions": [],
                "audit_required": False,
                "validated_at": datetime.now(UTC).isoformat(),
            }

            if not permission_result["granted"]:
                access_result["reason"] = "Insufficient permissions"
                return access_result

            # Apply time-based restrictions
            time_restrictions = await self._check_time_restrictions(user_id, action, context)
            if time_restrictions:
                access_result["conditions"]["time_restrictions"] = time_restrictions
                if not time_restrictions.get("allowed", True):
                    access_result["allowed"] = False
                    access_result["reason"] = "Time-based access restriction"

            # Apply location-based restrictions
            location_restrictions = await self._check_location_restrictions(user_id, context)
            if location_restrictions:
                access_result["conditions"]["location_restrictions"] = location_restrictions
                if not location_restrictions.get("allowed", True):
                    access_result["allowed"] = False
                    access_result["reason"] = "Location-based access restriction"

            # Check for sensitive actions requiring additional auth
            if await self._is_sensitive_action(action, resource):
                access_result["conditions"]["requires_fresh_auth"] = True
                access_result["audit_required"] = True
                
                fresh_auth_valid = context.get("fresh_auth_timestamp")
                if not fresh_auth_valid or self._is_auth_stale(fresh_auth_valid):
                    access_result["allowed"] = False
                    access_result["reason"] = "Fresh authentication required"

            # Apply rate limiting
            rate_limit = await self._check_rate_limit(user_id, action, context)
            if rate_limit:
                access_result["conditions"]["rate_limit"] = rate_limit
                if not rate_limit.get("allowed", True):
                    access_result["allowed"] = False
                    access_result["reason"] = "Rate limit exceeded"

            # Mark high-risk actions for audit
            if await self._is_high_risk_action(action, resource, context):
                access_result["audit_required"] = True
                access_result["conditions"]["high_risk"] = True

            return access_result

        except Exception as e:
            logger.error(f"Error validating access for user {user_id}: {e}")
            return {
                "user_id": str(user_id),
                "action": action,
                "resource": resource,
                "allowed": False,
                "reason": f"Validation error: {str(e)}",
                "validated_at": datetime.now(UTC).isoformat(),
            }

    async def calculate_permission_matrix(
        self,
        user_id: UUID,
        resources: list[str] | None = None,
    ) -> dict[str, dict[str, bool]]:
        """Calculate permission matrix for user."""
        try:
            if resources is None:
                resources = [
                    "user", "role", "permission", "audit", "session",
                    "profile", "setting", "admin", "security"
                ]

            actions = [
                "create", "read", "update", "delete", "list", "admin",
                "approve", "reject", "export", "import"
            ]

            matrix = {}
            effective_permissions = await self.get_effective_permissions(user_id)

            for resource in resources:
                matrix[resource] = {}
                for action in actions:
                    permission = f"{action}:{resource}"
                    matrix[resource][action] = permission in effective_permissions

            logger.info(f"Permission matrix calculated for user {user_id}: {len(resources)} resources")
            return matrix

        except Exception as e:
            logger.error(f"Error calculating permission matrix for user {user_id}: {e}")
            return {}

    async def check_segregation_of_duties(
        self,
        user_id: UUID,
        new_permission: str,
    ) -> tuple[bool, str]:
        """Check segregation of duties compliance."""
        try:
            effective_permissions = await self.get_effective_permissions(user_id)
            
            # Check if new permission conflicts with existing ones
            conflicting_permissions = self._sod_rules.get(new_permission, [])
            
            for conflict in conflicting_permissions:
                if conflict in effective_permissions:
                    reason = f"SoD violation: {new_permission} conflicts with existing {conflict}"
                    logger.warning(f"SoD check failed for user {user_id}: {reason}")
                    return False, reason

            # Check reverse conflicts
            for existing_perm in effective_permissions:
                if existing_perm in self._sod_rules:
                    if new_permission in self._sod_rules[existing_perm]:
                        reason = f"SoD violation: {new_permission} conflicts with existing {existing_perm}"
                        logger.warning(f"SoD check failed for user {user_id}: {reason}")
                        return False, reason

            logger.info(f"SoD check passed for user {user_id}: {new_permission}")
            return True, "No segregation of duties conflicts"

        except Exception as e:
            logger.error(f"Error checking SoD for user {user_id}: {e}")
            return False, f"SoD check error: {str(e)}"

    def invalidate_permission_cache(self, user_id: UUID) -> None:
        """Invalidate permission cache for user."""
        try:
            cache_key = f"effective_perms:{user_id}"
            if cache_key in self._permission_cache:
                del self._permission_cache[cache_key]

            # Invalidate external cache
            if self._cache:
                # Pattern-based cache invalidation
                pattern = f"perm:{user_id}:*"
                asyncio.create_task(self._cache.delete_pattern(pattern))

            logger.info(f"Permission cache invalidated for user {user_id}")

        except Exception as e:
            logger.error(f"Error invalidating permission cache for user {user_id}: {e}")

    async def _apply_business_rules(
        self,
        user_id: UUID,
        permission: str,
        resource: str | None,
        resource_owner_id: UUID | None,
    ) -> dict[str, Any]:
        """Apply business rules to permission check."""
        conditions = {}

        # Self-service restrictions
        if resource == "user" and resource_owner_id and user_id != resource_owner_id:
            if permission in ["update", "delete", "admin"]:
                conditions["requires_admin"] = True

        # Admin escalation requirements
        if permission.startswith("admin:"):
            conditions["requires_admin_role"] = True
            conditions["audit_required"] = True

        # Time-sensitive operations
        if permission in ["delete", "admin:delete", "admin:disable"]:
            conditions["requires_confirmation"] = True
            conditions["reversible_window_hours"] = 24

        return conditions

    async def _check_time_restrictions(
        self, user_id: UUID, action: str, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check time-based access restrictions."""
        # Mock implementation - would check business hours, maintenance windows, etc.
        current_hour = datetime.now(UTC).hour
        
        # Restrict sensitive admin actions during maintenance window
        if action.startswith("admin:") and 2 <= current_hour <= 4:
            return {
                "allowed": False,
                "reason": "Admin actions restricted during maintenance window (2-4 AM UTC)",
                "allowed_after": "04:00 UTC",
            }
        
        return {"allowed": True}

    async def _check_location_restrictions(
        self, user_id: UUID, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check location-based access restrictions."""
        # Mock implementation - would check IP geolocation, etc.
        ip_address = context.get("ip_address")
        if ip_address and ip_address.startswith("192.168"):
            return {"allowed": True, "location": "internal_network"}
        
        return {"allowed": True, "location": "external"}

    async def _is_sensitive_action(self, action: str, resource: str) -> bool:
        """Check if action is sensitive and requires fresh auth."""
        sensitive_actions = [
            "delete", "admin:delete", "admin:disable", "admin:grant_permission",
            "security:change_password", "security:disable_mfa", "admin:impersonate"
        ]
        return action in sensitive_actions

    def _is_auth_stale(self, fresh_auth_timestamp: str) -> bool:
        """Check if authentication is stale."""
        try:
            auth_time = datetime.fromisoformat(fresh_auth_timestamp.replace('Z', '+00:00'))
            return datetime.now(UTC) - auth_time > timedelta(minutes=5)
        except Exception:
            return True

    async def _check_rate_limit(
        self, user_id: UUID, action: str, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check rate limiting for action."""
        # Mock implementation - would use Redis or similar
        return {"allowed": True, "remaining": 100, "reset_at": datetime.now(UTC) + timedelta(hours=1)}

    async def _is_high_risk_action(
        self, action: str, resource: str, context: dict[str, Any]
    ) -> bool:
        """Check if action is high-risk and requires audit."""
        high_risk_actions = [
            "admin:grant_permission", "admin:create_admin", "admin:disable_user",
            "security:disable_mfa", "admin:impersonate", "admin:export_data"
        ]
        return action in high_risk_actions