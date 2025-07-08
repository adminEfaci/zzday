"""
Create role command implementation.

Handles creating new roles with permissions and hierarchy.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CommandHandlerDependencies,
    RoleCreationParams,
)
from app.modules.identity.application.dtos.internal import (
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import CreateRoleRequest
from app.modules.identity.application.dtos.response import RoleResponse
from app.modules.identity.domain.entities import Permission, Role
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    RoleType,
    SecurityEventType,
)
from app.modules.identity.domain.events import RoleCreated
from app.modules.identity.domain.exceptions import (
    DuplicateRoleError,
    HierarchyViolationError,
    InvalidOperationError,
    InvalidPermissionError,
    UnauthorizedError,
)


class CreateRoleCommand(Command[RoleResponse]):
    """Command to create a new role."""
    
    def __init__(self, params: RoleCreationParams, **kwargs: Any):
        self.params = params
        # Normalize name
        self.params.name = params.name.lower().replace(" ", "_")
        # Initialize empty collections if None
        self.params.permissions = params.permissions or []
        self.params.metadata = params.metadata or {}
        self.params.tags = params.tags or []
        
        # Additional parameters not in the base DTO
        self.role_type = kwargs.get('role_type', RoleType.CUSTOM)
        self.hierarchy_level = kwargs.get('hierarchy_level', 0)
        self.max_assignments = kwargs.get('max_assignments')
        self.prerequisites = kwargs.get('prerequisites', {})
        self.grantable_roles = kwargs.get('grantable_roles', [])
        self.grantable_permissions = kwargs.get('grantable_permissions', [])


class CreateRoleCommandHandler(CommandHandler[CreateRoleCommand, RoleResponse]):
    """Handler for creating new roles."""
    
    def __init__(self, dependencies: CommandHandlerDependencies):
        self._role_repository = dependencies.repositories.role_repository
        self._permission_repository = dependencies.repositories.permission_repository
        self._authorization_service = dependencies.services.authorization_service
        self._validation_service = dependencies.services.validation_service
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.ROLE_CREATED,
        resource_type="role",
        include_request=True,
        include_response=True
    )
    @validate_request(CreateRoleRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("roles.create")
    @require_mfa()
    async def handle(self, command: CreateRoleCommand) -> RoleResponse:
        """
        Create new role with validation.
        
        Process:
        1. Validate creator privileges
        2. Check name uniqueness
        3. Validate permissions exist
        4. Validate hierarchy
        5. Check permission compatibility
        6. Create role
        7. Log if high-privilege
        8. Send notifications
        
        Returns:
            RoleResponse with created role details
            
        Raises:
            UnauthorizedError: If lacks permission
            DuplicateRoleError: If role name exists
            InvalidPermissionError: If invalid permissions
            HierarchyViolationError: If hierarchy invalid
        """
        async with self._unit_of_work:
            # 1. Check if role name already exists
            existing = await self._role_repository.find_by_name(command.params.name)
            if existing:
                raise DuplicateRoleError(f"Role with name '{command.params.name}' already exists")
            
            # 2. Validate creator can create roles at this level
            creator_roles = await self._authorization_service.get_user_roles(command.params.created_by)
            await self._validate_hierarchy_creation(
                creator_roles,
                command.hierarchy_level,
                command.params.is_system
            )
            
            # 3. Validate all permissions exist
            validated_permissions = await self._validate_permissions(command.params.permissions)
            
            # 4. Check permission compatibility
            await self._check_permission_compatibility(validated_permissions)
            
            # 5. Validate grantable roles and permissions
            if command.grantable_roles:
                await self._validate_grantable_roles(
                    command.grantable_roles,
                    command.hierarchy_level
                )
            
            if command.grantable_permissions:
                await self._validate_grantable_permissions(
                    command.grantable_permissions,
                    validated_permissions
                )
            
            # 6. Validate prerequisites
            if command.prerequisites:
                await self._validate_prerequisites(command.prerequisites)
            
            # 7. Create the role
            role = Role(
                id=UUID(),
                name=command.params.name,
                display_name=command.params.display_name,
                description=command.params.description,
                role_type=command.role_type,
                hierarchy_level=command.hierarchy_level,
                is_system=command.params.is_system,
                is_default=command.params.is_default,
                is_active=True,
                max_assignments=command.max_assignments,
                prerequisites=command.prerequisites,
                grantable_roles=command.grantable_roles,
                grantable_permissions=command.grantable_permissions,
                created_by=command.params.created_by,
                created_at=datetime.now(UTC),
                metadata=command.params.metadata
            )
            
            # 8. Set permissions
            role.set_permissions(command.params.permissions)
            
            # 9. Save role
            await self._role_repository.create(role)
            
            # 10. Calculate effective permissions
            effective_permissions = await self._calculate_effective_permissions(
                validated_permissions
            )
            
            # 11. Log if high-privilege role
            if self._is_high_privilege_role(role, effective_permissions):
                await self._log_high_privilege_creation(role, command)
            
            # 12. Publish domain event
            await self._event_bus.publish(
                RoleCreated(
                    aggregate_id=role.id,
                    role_name=role.name,
                    role_type=role.role_type,
                    hierarchy_level=role.hierarchy_level,
                    permission_count=len(validated_permissions),
                    created_by=command.params.created_by
                )
            )
            
            # 13. Send notifications
            await self._send_creation_notifications(role, command)
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            # 15. Return response
            return RoleResponse(
                id=role.id,
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                role_type=role.role_type,
                hierarchy_level=role.hierarchy_level,
                is_system=role.is_system,
                is_default=role.is_default,
                is_active=role.is_active,
                permissions=[p.name for p in validated_permissions],
                permission_count=len(validated_permissions),
                effective_permissions=[p["name"] for p in effective_permissions],
                max_assignments=role.max_assignments,
                current_assignments=0,
                grantable_roles=len(role.grantable_roles),
                grantable_permissions=len(role.grantable_permissions),
                created_at=role.created_at,
                created_by=role.created_by,
                message=f"Role '{role.display_name}' created successfully"
            )
    
    async def _validate_hierarchy_creation(
        self,
        creator_roles: list[Role],
        target_level: int,
        is_system: bool
    ) -> None:
        """Validate creator can create roles at target hierarchy level."""
        if is_system:
            # Only super admins can create system roles
            if not any(r.name == "super_admin" for r in creator_roles):
                raise UnauthorizedError("Only super admins can create system roles")
            return
        
        # Get creator's max hierarchy level
        creator_max_level = max(
            (r.hierarchy_level for r in creator_roles),
            default=0
        )
        
        # Cannot create roles at or above own level
        if target_level >= creator_max_level > 0:
            # Check if explicitly allowed
            can_create_at_level = any(
                r.metadata.get("can_create_peer_roles", False)
                for r in creator_roles
            )
            
            if not can_create_at_level:
                raise HierarchyViolationError(
                    f"Cannot create role at hierarchy level {target_level} - "
                    f"your maximum level is {creator_max_level}"
                )
    
    async def _validate_permissions(self, permission_ids: list[UUID]) -> list[Permission]:
        """Validate all permissions exist and are active."""
        permissions = []
        
        for perm_id in permission_ids:
            permission = await self._permission_repository.get_by_id(perm_id)
            
            if not permission:
                raise InvalidPermissionError(f"Permission {perm_id} not found")
            
            if not permission.is_active:
                raise InvalidPermissionError(
                    f"Permission '{permission.name}' is not active"
                )
            
            permissions.append(permission)
        
        return permissions
    
    async def _check_permission_compatibility(
        self,
        permissions: list[Permission]
    ) -> None:
        """Check for permission conflicts and incompatibilities."""
        permission_map = {p.id: p for p in permissions}
        
        for permission in permissions:
            # Check mutual exclusions
            if permission.mutually_exclusive_with:
                conflicts = [
                    permission_map[pid].name
                    for pid in permission.mutually_exclusive_with
                    if pid in permission_map
                ]
                
                if conflicts:
                    raise InvalidOperationError(
                        f"Permission '{permission.name}' conflicts with: {', '.join(conflicts)}"
                    )
            
            # Check for deny permissions with same resource
            for other in permissions:
                if other.id == permission.id:
                    continue
                
                if (other.resource_type == permission.resource_type and
                    other.action == permission.action and
                    other.type != permission.type):
                    raise InvalidOperationError(
                        f"Cannot mix ALLOW and DENY for same action: "
                        f"{permission.name} vs {other.name}"
                    )
    
    async def _validate_grantable_roles(
        self,
        role_ids: list[UUID],
        hierarchy_level: int
    ) -> None:
        """Validate grantable roles exist and hierarchy allows granting."""
        for role_id in role_ids:
            role = await self._role_repository.get_by_id(role_id)
            
            if not role:
                raise InvalidOperationError(f"Grantable role {role_id} not found")
            
            # Cannot grant roles at higher level
            if role.hierarchy_level > hierarchy_level:
                raise HierarchyViolationError(
                    f"Cannot grant role '{role.name}' - "
                    f"it has higher hierarchy level ({role.hierarchy_level})"
                )
    
    async def _validate_grantable_permissions(
        self,
        permission_ids: list[UUID],
        role_permissions: list[Permission]
    ) -> None:
        """Validate grantable permissions exist and role has them."""
        role_perm_ids = {p.id for p in role_permissions}
        
        for perm_id in permission_ids:
            permission = await self._permission_repository.get_by_id(perm_id)
            
            if not permission:
                raise InvalidOperationError(f"Grantable permission {perm_id} not found")
            
            # Role must have the permission to grant it
            if perm_id not in role_perm_ids:
                raise InvalidOperationError(
                    f"Cannot grant permission '{permission.name}' - "
                    "role does not have this permission"
                )
    
    async def _validate_prerequisites(self, prerequisites: dict[str, Any]) -> None:
        """Validate role prerequisites are valid."""
        # Validate required roles exist
        if "required_roles" in prerequisites:
            for role_id in prerequisites["required_roles"]:
                role = await self._role_repository.get_by_id(role_id)
                if not role:
                    raise InvalidOperationError(
                        f"Prerequisite role {role_id} not found"
                    )
        
        # Validate required permissions exist
        if "required_permissions" in prerequisites:
            for perm_name in prerequisites["required_permissions"]:
                permission = await self._permission_repository.find_by_name(perm_name)
                if not permission:
                    raise InvalidOperationError(
                        f"Prerequisite permission '{perm_name}' not found"
                    )
        
        # Validate numeric prerequisites
        numeric_fields = ["min_account_age_days", "min_reputation_score"]
        for field in numeric_fields:
            if field in prerequisites:
                value = prerequisites[field]
                if not isinstance(value, int | float) or value < 0:
                    raise InvalidOperationError(
                        f"Invalid {field}: must be non-negative number"
                    )
    
    async def _calculate_effective_permissions(
        self,
        permissions: list[Permission]
    ) -> list[dict[str, Any]]:
        """Calculate effective permissions including implied ones."""
        effective = []
        seen = set()
        
        # Add direct permissions
        for permission in permissions:
            if permission.id not in seen:
                effective.append({
                    "id": str(permission.id),
                    "name": permission.name,
                    "source": "direct"
                })
                seen.add(permission.id)
        
        # Add implied permissions
        for permission in permissions:
            if permission.implies:
                for implied_id in permission.implies:
                    if implied_id not in seen:
                        implied = await self._permission_repository.get_by_id(implied_id)
                        if implied:
                            effective.append({
                                "id": str(implied.id),
                                "name": implied.name,
                                "source": f"implied_by:{permission.name}"
                            })
                            seen.add(implied_id)
        
        return effective
    
    def _is_high_privilege_role(
        self,
        role: Role,
        effective_permissions: list[dict[str, Any]]
    ) -> bool:
        """Check if role has high privileges."""
        # System roles are always high privilege
        if role.is_system:
            return True
        
        # High hierarchy levels
        if role.hierarchy_level >= 80:
            return True
        
        # Check for sensitive permissions
        sensitive_patterns = [
            "system:", "admin:", "security:", "audit:",
            ":delete", ":grant", ":revoke", ":impersonate"
        ]
        
        for perm in effective_permissions:
            perm_name = perm["name"]
            if any(pattern in perm_name for pattern in sensitive_patterns):
                return True
        
        # Can grant many permissions
        return len(role.grantable_permissions) > 10
    
    async def _log_high_privilege_creation(
        self,
        role: Role,
        command: CreateRoleCommand
    ) -> None:
        """Log creation of high-privilege roles."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_PRIVILEGE_ROLE_CREATED,
                severity=RiskLevel.MEDIUM,
                user_id=command.created_by,
                details={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "role_type": role.role_type.value,
                    "hierarchy_level": role.hierarchy_level,
                    "is_system": role.is_system,
                    "permission_count": len(role.permissions),
                    "grantable_roles": len(role.grantable_roles),
                    "grantable_permissions": len(role.grantable_permissions)
                },
                indicators=["high_privilege_role_creation"],
                recommended_actions=[
                    "Review role permissions",
                    "Monitor role assignments"
                ]
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "High-Privilege Role Created",
            {
                "role_name": role.name,
                "created_by": str(command.created_by),
                "hierarchy_level": role.hierarchy_level,
                "permissions": len(role.permissions)
            }
        )
    
    async def _send_creation_notifications(
        self,
        role: Role,
        command: CreateRoleCommand
    ) -> None:
        """Send notifications about role creation."""
        # Notify administrators
        await self._notification_service.notify_role(
            "administrator",
            NotificationContext(
                notification_id=UUID(),
                recipient_id=None,
                notification_type=NotificationType.ROLE_CREATED,
                channel="in_app",
                template_id="role_created",
                template_data={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "display_name": role.display_name,
                    "created_by": str(command.created_by),
                    "hierarchy_level": role.hierarchy_level,
                    "permission_count": len(role.permissions)
                },
                priority="medium"
            )
        )
        
        # Notify compliance if system role
        if role.is_system:
            await self._notification_service.notify_compliance_team(
                "System Role Created",
                {
                    "role_name": role.name,
                    "permissions": len(role.permissions),
                    "created_by": str(command.created_by)
                }
            )