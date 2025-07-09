"""
Check permission command implementation.

Handles comprehensive permission checking with detailed explanations.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.repositories.permission_repository import IPermissionRepository
from app.modules.identity.domain.interfaces.repositories.role_repository import IRoleRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    cache_result,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import PermissionCheckContext
from app.modules.identity.application.dtos.request import CheckPermissionRequest
from app.modules.identity.application.dtos.response import PermissionCheckResponse
from app.modules.identity.domain.entities import Permission, User
from app.modules.identity.domain.enums import AuditAction, CheckResult, PermissionSource
from app.modules.identity.domain.events import PermissionChecked
from app.modules.identity.domain.exceptions import (
    PermissionNotFoundError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import AuthorizationService, ValidationService


@dataclass
class CheckPermissionOptions:
    """Options for permission checking."""
    resource_type: str | None = None
    resource_id: UUID | None = None
    include_explanation: bool = True
    include_permission_tree: bool = False
    include_role_hierarchy: bool = False
    check_conditions: bool = True
    check_prerequisites: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckPermissionRepositoryDependencies:
    """Repository dependencies for check permission handler."""
    user_repository: IUserRepository
    permission_repository: IPermissionRepository
    role_repository: IRoleRepository
    user_permission_repository: IUserPermissionRepository
    user_role_repository: IUserRoleRepository


@dataclass
class CheckPermissionServiceDependencies:
    """Service dependencies for check permission handler."""
    authorization_service: AuthorizationService
    validation_service: ValidationService
    audit_service: IAuditService
    cache_service: ICacheService


@dataclass
class CheckPermissionInfrastructureDependencies:
    """Infrastructure dependencies for check permission handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class CheckPermissionCommand(Command[PermissionCheckResponse]):
    """Command to check if a user has a specific permission."""
    
    def __init__(
        self,
        user_id: UUID,
        permission_name: str,
        checked_by: UUID | None = None,
        options: CheckPermissionOptions | None = None
    ):
        self.user_id = user_id
        self.permission_name = permission_name
        self.checked_by = checked_by or user_id  # Default to self-check
        self.options = options or CheckPermissionOptions()
        
        # For backward compatibility, expose commonly used options directly
        self.resource_type = self.options.resource_type
        self.resource_id = self.options.resource_id
        self.include_explanation = self.options.include_explanation
        self.include_permission_tree = self.options.include_permission_tree
        self.include_role_hierarchy = self.options.include_role_hierarchy
        self.check_conditions = self.options.check_conditions
        self.check_prerequisites = self.options.check_prerequisites
        self.metadata = self.options.metadata


class CheckPermissionCommandHandler(CommandHandler[CheckPermissionCommand, PermissionCheckResponse]):
    """Handler for checking permissions."""
    
    def __init__(
        self,
        repositories: CheckPermissionRepositoryDependencies,
        services: CheckPermissionServiceDependencies,
        infrastructure: CheckPermissionInfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._permission_repository = repositories.permission_repository
        self._role_repository = repositories.role_repository
        self._user_permission_repository = repositories.user_permission_repository
        self._user_role_repository = repositories.user_role_repository
        
        # Service dependencies
        self._authorization_service = services.authorization_service
        self._validation_service = services.validation_service
        self._audit_service = services.audit_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_CHECKED,
        resource_type="permission",
        include_request=True,
        include_response=True,
        log_when="denied"  # Only log denied checks
    )
    @validate_request(CheckPermissionRequest)
    @rate_limit(
        max_requests=1000,
        window_seconds=3600,
        strategy='user'
    )
    @cache_result(
        ttl_seconds=300,  # Cache for 5 minutes
        key_params=["user_id", "permission_name", "resource_type", "resource_id"]
    )
    async def handle(self, command: CheckPermissionCommand) -> PermissionCheckResponse:
        """
        Check if user has permission with detailed explanation.
        
        Process:
        1. Load user
        2. Find permission definition
        3. Check direct grants
        4. Check role-based permissions
        5. Check implied permissions
        6. Check deny permissions
        7. Evaluate conditions
        8. Check prerequisites
        9. Build explanation
        10. Return result
        
        Returns:
            PermissionCheckResponse with check details
            
        Raises:
            UserNotFoundError: If user not found
            PermissionNotFoundError: If permission not found
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Find permission definition
            permission = await self._permission_repository.find_by_name(command.permission_name)
            if not permission:
                # Check if it's a wildcard permission
                permission = await self._resolve_wildcard_permission(command.permission_name)
                if not permission:
                    raise PermissionNotFoundError(
                        f"Permission '{command.permission_name}' not found"
                    )
            
            # 3. Initialize check context
            check_context = PermissionCheckContext(
                user_id=user.id,
                permission_id=permission.id,
                permission_name=permission.name,
                resource_type=command.resource_type,
                resource_id=command.resource_id,
                checked_at=datetime.now(UTC)
            )
            
            # 4. Check direct grant
            direct_grant = await self._check_direct_grant(
                user.id,
                permission.id,
                command.resource_type,
                command.resource_id
            )
            
            if direct_grant["has_permission"]:
                check_context.sources.append(PermissionSource.DIRECT_GRANT)
                check_context.direct_grant = direct_grant
            
            # 5. Check role-based permissions
            role_grants = await self._check_role_permissions(
                user.id,
                permission.id,
                command.resource_type,
                command.resource_id
            )
            
            if role_grants["has_permission"]:
                check_context.sources.append(PermissionSource.ROLE)
                check_context.role_grants = role_grants["grants"]
            
            # 6. Check implied permissions
            implied_grants = await self._check_implied_permissions(
                user.id,
                permission
            )
            
            if implied_grants["has_permission"]:
                check_context.sources.append(PermissionSource.IMPLIED)
                check_context.implied_grants = implied_grants["grants"]
            
            # 7. Check for deny permissions (overrides allow)
            deny_check = await self._check_deny_permissions(
                user.id,
                permission,
                command.resource_type,
                command.resource_id
            )
            
            if deny_check["is_denied"]:
                check_context.denied = True
                check_context.deny_reason = deny_check["reason"]
                check_context.sources.clear()  # Deny overrides all
            
            # 8. Evaluate conditions if applicable
            if command.check_conditions and check_context.sources and permission.conditions:
                conditions_met = await self._evaluate_conditions(
                    user,
                    permission,
                    command
                )
                if not conditions_met["passed"]:
                    check_context.conditions_failed = True
                    check_context.failed_conditions = conditions_met["failed"]
            
            # 9. Check prerequisites if applicable
            if command.check_prerequisites and check_context.sources and permission.prerequisites:
                prerequisites_met = await self._check_prerequisites(
                    user,
                    permission
                )
                if not prerequisites_met["passed"]:
                    check_context.prerequisites_failed = True
                    check_context.missing_prerequisites = prerequisites_met["missing"]
            
            # 10. Determine final result
            has_permission = (
                len(check_context.sources) > 0 and
                not check_context.denied and
                not check_context.conditions_failed and
                not check_context.prerequisites_failed
            )
            
            check_context.result = CheckResult.GRANTED if has_permission else CheckResult.DENIED
            
            # 11. Build explanation if requested
            explanation = None
            if command.include_explanation:
                explanation = await self._build_explanation(
                    check_context,
                    permission,
                    user
                )
            
            # 12. Build permission tree if requested
            permission_tree = None
            if command.include_permission_tree:
                permission_tree = await self._build_permission_tree(
                    user.id,
                    permission
                )
            
            # 13. Build role hierarchy if requested
            role_hierarchy = None
            if command.include_role_hierarchy:
                role_hierarchy = await self._build_role_hierarchy(user.id)
            
            # 14. Log sensitive permission checks
            if permission.is_sensitive or permission.is_critical:
                await self._log_sensitive_check(
                    user,
                    permission,
                    check_context,
                    command
                )
            
            # 15. Publish event
            await self._event_bus.publish(
                PermissionChecked(
                    aggregate_id=user.id,
                    permission_name=permission.name,
                    resource_type=command.resource_type,
                    resource_id=command.resource_id,
                    result=check_context.result,
                    checked_by=command.checked_by
                )
            )
            
            # 16. Return response
            return PermissionCheckResponse(
                has_permission=has_permission,
                user_id=user.id,
                permission_id=permission.id,
                permission_name=permission.name,
                resource_type=command.resource_type,
                resource_id=command.resource_id,
                result=check_context.result,
                sources=check_context.sources,
                explanation=explanation,
                permission_tree=permission_tree,
                role_hierarchy=role_hierarchy,
                direct_grant=check_context.direct_grant,
                role_grants=check_context.role_grants,
                implied_grants=check_context.implied_grants,
                denied=check_context.denied,
                deny_reason=check_context.deny_reason,
                conditions_failed=check_context.conditions_failed,
                failed_conditions=check_context.failed_conditions,
                prerequisites_failed=check_context.prerequisites_failed,
                missing_prerequisites=check_context.missing_prerequisites,
                checked_at=check_context.checked_at,
                cached=False  # Will be set to True by cache decorator on cache hit
            )
    
    async def _resolve_wildcard_permission(self, permission_name: str) -> Permission | None:
        """Resolve wildcard permissions like 'users:*' or '*:read'."""
        parts = permission_name.split(":")
        if len(parts) < 2:
            return None
        
        resource_type = parts[0]
        action = parts[1]
        
        # Check for exact wildcard permission
        wildcard_permission = await self._permission_repository.find_by_name(permission_name)
        if wildcard_permission:
            return wildcard_permission
        
        # Check for broader wildcards
        if action == "*":
            # Check for resource:* permission
            return await self._permission_repository.find_by_resource_wildcard(resource_type)
        if resource_type == "*":
            # Check for *:action permission
            return await self._permission_repository.find_by_action_wildcard(action)
        
        return None
    
    async def _check_direct_grant(
        self,
        user_id: UUID,
        permission_id: UUID,
        resource_type: str | None,
        resource_id: UUID | None
    ) -> dict[str, Any]:
        """Check if user has direct permission grant."""
        grant = await self._user_permission_repository.find_by_user_and_permission(
            user_id,
            permission_id,
            resource_type,
            resource_id
        )
        
        if grant and grant.is_active:
            # Check expiration
            if grant.expires_at and grant.expires_at < datetime.now(UTC):
                return {"has_permission": False, "reason": "expired"}
            
            return {
                "has_permission": True,
                "grant_id": grant.id,
                "granted_at": grant.granted_at,
                "granted_by": grant.granted_by,
                "expires_at": grant.expires_at,
                "conditions": grant.conditions
            }
        
        return {"has_permission": False}
    
    async def _check_role_permissions(
        self,
        user_id: UUID,
        permission_id: UUID,
        resource_type: str | None,
        resource_id: UUID | None
    ) -> dict[str, Any]:
        """Check if user has permission through roles."""
        result = {
            "has_permission": False,
            "grants": []
        }
        
        # Get user's active roles
        user_roles = await self._user_role_repository.find_active_by_user(user_id)
        
        for user_role in user_roles:
            # Check role expiration
            if user_role.expires_at and user_role.expires_at < datetime.now(UTC):
                continue
            
            # Get role
            role = await self._role_repository.find_by_id(user_role.role_id)
            if not role or not role.is_active:
                continue
            
            # Check if role has permission
            if permission_id in role.permissions:
                result["has_permission"] = True
                result["grants"].append({
                    "role_id": role.id,
                    "role_name": role.name,
                    "role_hierarchy": role.hierarchy_level,
                    "assigned_at": user_role.assigned_at,
                    "scope": user_role.scope
                })
        
        return result
    
    async def _check_implied_permissions(
        self,
        user_id: UUID,
        permission: Permission
    ) -> dict[str, Any]:
        """Check if user has permissions that imply this one."""
        result = {
            "has_permission": False,
            "grants": []
        }
        
        # Get all permissions that imply this one
        implying_permissions = await self._permission_repository.find_implying(permission.id)
        
        for implying_perm in implying_permissions:
            # Check if user has the implying permission
            has_implying = await self._authorization_service.has_permission(
                user_id,
                implying_perm.name
            )
            
            if has_implying:
                result["has_permission"] = True
                result["grants"].append({
                    "permission_id": implying_perm.id,
                    "permission_name": implying_perm.name,
                    "implies": permission.name
                })
        
        return result
    
    async def _check_deny_permissions(
        self,
        user_id: UUID,
        permission: Permission,
        resource_type: str | None,
        resource_id: UUID | None
    ) -> dict[str, Any]:
        """Check for explicit deny permissions."""
        # Find deny permissions for same resource and action
        deny_permissions = await self._permission_repository.find_deny_permissions(
            permission.resource_type,
            permission.action
        )
        
        for deny_perm in deny_permissions:
            # Check if user has the deny permission
            has_deny = await self._authorization_service.has_permission(
                user_id,
                deny_perm.name,
                resource_type,
                resource_id
            )
            
            if has_deny:
                return {
                    "is_denied": True,
                    "reason": f"Explicitly denied by {deny_perm.name}"
                }
        
        return {"is_denied": False}
    
    async def _evaluate_conditions(
        self,
        user: User,
        permission: Permission,
        command: CheckPermissionCommand
    ) -> dict[str, Any]:
        """Evaluate permission conditions."""
        result = {
            "passed": True,
            "failed": []
        }
        
        conditions = permission.conditions
        
        # Time-based conditions
        if "time_restrictions" in conditions:
            time_check = self._check_time_restrictions(conditions["time_restrictions"])
            if not time_check["passed"]:
                result["passed"] = False
                result["failed"].append(time_check["reason"])
        
        # Location-based conditions
        if "location_restrictions" in conditions:
            location_check = await self._check_location_restrictions(
                user,
                conditions["location_restrictions"],
                command.metadata
            )
            if not location_check["passed"]:
                result["passed"] = False
                result["failed"].append(location_check["reason"])
        
        # Attribute-based conditions
        if "required_attributes" in conditions:
            attr_check = self._check_user_attributes(
                user,
                conditions["required_attributes"]
            )
            if not attr_check["passed"]:
                result["passed"] = False
                result["failed"].extend(attr_check["missing"])
        
        return result
    
    async def _check_prerequisites(
        self,
        user: User,
        permission: Permission
    ) -> dict[str, Any]:
        """Check if user meets permission prerequisites."""
        result = {
            "passed": True,
            "missing": []
        }
        
        prerequisites = permission.prerequisites
        
        # Required permissions
        if "required_permissions" in prerequisites:
            for req_perm_name in prerequisites["required_permissions"]:
                has_perm = await self._authorization_service.has_permission(
                    user.id,
                    req_perm_name
                )
                if not has_perm:
                    result["passed"] = False
                    result["missing"].append(f"permission:{req_perm_name}")
        
        # Required features
        if "required_features" in prerequisites:
            user_features = user.metadata.get("features", [])
            for feature in prerequisites["required_features"]:
                if feature not in user_features:
                    result["passed"] = False
                    result["missing"].append(f"feature:{feature}")
        
        # MFA requirement
        if prerequisites.get("require_mfa") and not user.mfa_enabled:
            result["passed"] = False
            result["missing"].append("mfa:enabled")
        
        # Email verification
        if prerequisites.get("require_verified_email") and not user.email_verified:
            result["passed"] = False
            result["missing"].append("email:verified")
        
        return result
    
    def _check_time_restrictions(self, restrictions: dict[str, Any]) -> dict[str, Any]:
        """Check time-based restrictions."""
        now = datetime.now(UTC)
        
        # Business hours check
        if restrictions.get("business_hours_only"):
            hour = now.hour
            if hour < 8 or hour >= 18:  # 8 AM to 6 PM
                return {
                    "passed": False,
                    "reason": "Outside business hours (8 AM - 6 PM UTC)"
                }
        
        # Day of week check
        if "allowed_days" in restrictions:
            day_name = now.strftime("%A").lower()
            if day_name not in restrictions["allowed_days"]:
                return {
                    "passed": False,
                    "reason": f"Not allowed on {day_name}"
                }
        
        return {"passed": True}
    
    async def _check_location_restrictions(
        self,
        user: User,
        restrictions: dict[str, Any],
        metadata: dict[str, Any]
    ) -> dict[str, Any]:
        """Check location-based restrictions."""
        # Get user's current location from metadata
        user_location = metadata.get("location", {})
        
        # Country restrictions
        if "allowed_countries" in restrictions:
            country = user_location.get("country")
            if country not in restrictions["allowed_countries"]:
                return {
                    "passed": False,
                    "reason": f"Access not allowed from {country or 'unknown location'}"
                }
        
        # IP range restrictions
        if "allowed_ip_ranges" in restrictions:
            ip_address = metadata.get("ip_address")
            if not self._is_ip_in_ranges(ip_address, restrictions["allowed_ip_ranges"]):
                return {
                    "passed": False,
                    "reason": "IP address not in allowed range"
                }
        
        return {"passed": True}
    
    def _check_user_attributes(
        self,
        user: User,
        required_attributes: dict[str, Any]
    ) -> dict[str, Any]:
        """Check if user has required attributes."""
        result = {
            "passed": True,
            "missing": []
        }
        
        for attr_name, required_value in required_attributes.items():
            user_value = user.metadata.get(attr_name)
            
            if user_value is None:
                result["passed"] = False
                result["missing"].append(f"Missing attribute: {attr_name}")
            elif isinstance(required_value, list):
                if user_value not in required_value:
                    result["passed"] = False
                    result["missing"].append(
                        f"Attribute {attr_name} must be one of: {', '.join(required_value)}"
                    )
            elif user_value != required_value:
                result["passed"] = False
                result["missing"].append(
                    f"Attribute {attr_name} must be: {required_value}"
                )
        
        return result
    
    def _is_ip_in_ranges(self, ip_address: str, allowed_ranges: list[str]) -> bool:
        """Check if IP address is in allowed ranges."""
        # This would implement IP range checking
        # For now, return True
        return True
    
    async def _build_explanation(
        self,
        context: PermissionCheckContext,
        permission: Permission,
        user: User
    ) -> str:
        """Build human-readable explanation of permission check."""
        explanation_parts = []
        
        # Result summary
        if context.result == CheckResult.GRANTED:
            explanation_parts.append(
                f"✅ User {user.username} HAS permission '{permission.name}'"
            )
        else:
            explanation_parts.append(
                f"❌ User {user.username} DOES NOT HAVE permission '{permission.name}'"
            )
        
        # Permission sources
        if context.sources:
            explanation_parts.append("\nPermission granted through:")
            for source in context.sources:
                if source == PermissionSource.DIRECT_GRANT:
                    explanation_parts.append("  • Direct permission grant")
                elif source == PermissionSource.ROLE:
                    roles = [g["role_name"] for g in context.role_grants]
                    explanation_parts.append(f"  • Roles: {', '.join(roles)}")
                elif source == PermissionSource.IMPLIED:
                    implied = [g["permission_name"] for g in context.implied_grants]
                    explanation_parts.append(f"  • Implied by: {', '.join(implied)}")
        
        # Denial reason
        if context.denied:
            explanation_parts.append(f"\n⛔ {context.deny_reason}")
        
        # Failed conditions
        if context.conditions_failed:
            explanation_parts.append("\n⚠️ Conditions not met:")
            for condition in context.failed_conditions:
                explanation_parts.append(f"  • {condition}")
        
        # Missing prerequisites
        if context.prerequisites_failed:
            explanation_parts.append("\n⚠️ Missing prerequisites:")
            for prereq in context.missing_prerequisites:
                explanation_parts.append(f"  • {prereq}")
        
        return "\n".join(explanation_parts)
    
    async def _build_permission_tree(
        self,
        user_id: UUID,
        permission: Permission
    ) -> dict[str, Any]:
        """Build tree showing how permission is granted."""
        tree = {
            "permission": {
                "id": str(permission.id),
                "name": permission.name,
                "type": permission.type.value
            },
            "paths": []
        }
        
        # Direct grant path
        direct_grant = await self._user_permission_repository.find_by_user_and_permission(
            user_id,
            permission.id
        )
        if direct_grant and direct_grant.is_active:
            tree["paths"].append({
                "type": "direct",
                "grant_id": str(direct_grant.id),
                "granted_at": direct_grant.granted_at.isoformat()
            })
        
        # Role paths
        user_roles = await self._user_role_repository.find_active_by_user(user_id)
        for user_role in user_roles:
            role = await self._role_repository.find_by_id(user_role.role_id)
            if role and permission.id in role.permissions:
                tree["paths"].append({
                    "type": "role",
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "assigned_at": user_role.assigned_at.isoformat()
                })
        
        # Implication paths
        implying_permissions = await self._permission_repository.find_implying(permission.id)
        for implying_perm in implying_permissions:
            if await self._authorization_service.has_permission(user_id, implying_perm.name):
                tree["paths"].append({
                    "type": "implied",
                    "by_permission": implying_perm.name,
                    "permission_id": str(implying_perm.id)
                })
        
        return tree
    
    async def _build_role_hierarchy(self, user_id: UUID) -> dict[str, Any]:
        """Build user's role hierarchy."""
        hierarchy = {
            "user_id": str(user_id),
            "roles": [],
            "max_hierarchy_level": 0
        }
        
        user_roles = await self._user_role_repository.find_active_by_user(user_id)
        
        for user_role in user_roles:
            role = await self._role_repository.find_by_id(user_role.role_id)
            if role:
                role_info = {
                    "id": str(role.id),
                    "name": role.name,
                    "hierarchy_level": role.hierarchy_level,
                    "assigned_at": user_role.assigned_at.isoformat(),
                    "expires_at": user_role.expires_at.isoformat() if user_role.expires_at else None,
                    "scope": user_role.scope,
                    "permission_count": len(role.permissions)
                }
                
                hierarchy["roles"].append(role_info)
                hierarchy["max_hierarchy_level"] = max(
                    hierarchy["max_hierarchy_level"],
                    role.hierarchy_level
                )
        
        # Sort by hierarchy level
        hierarchy["roles"].sort(key=lambda r: r["hierarchy_level"], reverse=True)
        
        return hierarchy
    
    async def _log_sensitive_check(
        self,
        user: User,
        permission: Permission,
        context: PermissionCheckContext,
        command: CheckPermissionCommand
    ) -> None:
        """Log checks for sensitive permissions."""
        await self._audit_service.log_permission_check(
            PermissionCheckContext(
                user_id=user.id,
                permission_id=permission.id,
                permission_name=permission.name,
                resource_type=command.resource_type,
                resource_id=command.resource_id,
                result=context.result,
                sources=context.sources,
                checked_by=command.checked_by,
                checked_at=context.checked_at,
                metadata={
                    "user_status": user.status.value,
                    "permission_critical": permission.is_critical,
                    "permission_sensitive": permission.is_sensitive,
                    "denied": context.denied,
                    "conditions_failed": context.conditions_failed,
                    "prerequisites_failed": context.prerequisites_failed
                }
            )
        )