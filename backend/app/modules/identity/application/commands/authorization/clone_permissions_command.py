"""
Clone permissions command implementation.

Handles cloning permissions from one user to another or from templates.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IEmailService,
    INotificationService,
    IPermissionRepository,
    IRoleRepository,
    ITemplateRepository,
    IUserPermissionRepository,
    IUserRepository,
    IUserRoleRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_approval,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import ClonePermissionsRequest
from app.modules.identity.application.dtos.response import PermissionCloneResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    CloneMode,
    CloneScope,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import PermissionsCloned
from app.modules.identity.domain.exceptions import (
    CloneConflictError,
    InvalidOperationError,
    TemplateNotFoundError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    SecurityService,
    ValidationService,
)


@dataclass
class CloneOptionsConfig:
    """Configuration for clone operation options."""
    clone_mode: CloneMode = CloneMode.MERGE
    clone_scope: CloneScope = CloneScope.ALL
    include_roles: bool = True
    include_direct_permissions: bool = True
    include_conditions: bool = True
    include_expiry: bool = False
    notify_target: bool = True
    dry_run: bool = False


@dataclass
class CloneFilters:
    """Filters for clone operation."""
    permission_filter: list[str] = field(default_factory=list)
    role_filter: list[str] = field(default_factory=list)
    exclude_permissions: list[str] = field(default_factory=list)
    exclude_roles: list[str] = field(default_factory=list)


@dataclass
class CloneMetadata:
    """Metadata for clone operation."""
    reason: str = "Permissions cloned"
    expiry_offset: timedelta | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepositoryDependencies:
    """Repository dependencies for clone handler."""
    user_repository: IUserRepository
    permission_repository: IPermissionRepository
    role_repository: IRoleRepository
    user_permission_repository: IUserPermissionRepository
    user_role_repository: IUserRoleRepository
    template_repository: ITemplateRepository


@dataclass
class ServiceDependencies:
    """Service dependencies for clone handler."""
    authorization_service: AuthorizationService
    validation_service: ValidationService
    security_service: SecurityService
    notification_service: INotificationService
    audit_service: IAuditService
    email_service: IEmailService


@dataclass
class InfrastructureDependencies:
    """Infrastructure dependencies for clone handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class ClonePermissionsCommand(Command[PermissionCloneResponse]):
    """Command to clone permissions between users or from templates."""
    
    def __init__(
        self,
        source_type: str,  # "user" or "template"
        source_id: UUID,
        target_user_id: UUID,
        cloned_by: UUID,
        **kwargs
    ):
        self.source_type = source_type
        self.source_id = source_id
        self.target_user_id = target_user_id
        self.cloned_by = cloned_by
        
        # Extract configuration objects from kwargs
        self.options = kwargs.get('options') or CloneOptionsConfig()
        self.filters = kwargs.get('filters') or CloneFilters()
        self.metadata = kwargs.get('metadata') or CloneMetadata()
        
        # For backward compatibility, expose commonly used options directly
        self.clone_mode = self.options.clone_mode
        self.clone_scope = self.options.clone_scope
        self.include_roles = self.options.include_roles
        self.include_direct_permissions = self.options.include_direct_permissions
        self.include_conditions = self.options.include_conditions
        self.include_expiry = self.options.include_expiry
        self.permission_filter = self.filters.permission_filter
        self.role_filter = self.filters.role_filter
        self.exclude_permissions = self.filters.exclude_permissions
        self.exclude_roles = self.filters.exclude_roles
        self.expiry_offset = self.metadata.expiry_offset
        self.reason = self.metadata.reason
        self.notify_target = self.options.notify_target
        self.dry_run = self.options.dry_run


class ClonePermissionsCommandHandler(CommandHandler[ClonePermissionsCommand, PermissionCloneResponse]):
    """Handler for cloning permissions."""
    
    def __init__(
        self,
        repositories: RepositoryDependencies,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._permission_repository = repositories.permission_repository
        self._role_repository = repositories.role_repository
        self._user_permission_repository = repositories.user_permission_repository
        self._user_role_repository = repositories.user_role_repository
        self._template_repository = repositories.template_repository
        
        # Service dependencies
        self._authorization_service = services.authorization_service
        self._validation_service = services.validation_service
        self._security_service = services.security_service
        self._notification_service = services.notification_service
        self._audit_service = services.audit_service
        self._email_service = services.email_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSIONS_CLONED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(ClonePermissionsRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("permissions.clone")
    @require_mfa()
    @require_approval(
        approval_type="permission_clone",
        condition="high_privilege_clone"
    )
    async def handle(self, command: ClonePermissionsCommand) -> PermissionCloneResponse:
        """
        Clone permissions with comprehensive validation.
        
        Process:
        1. Validate source and target
        2. Load permissions to clone
        3. Check for conflicts
        4. Apply filters
        5. Execute clone operation
        6. Handle mode-specific logic
        7. Send notifications
        8. Log activity
        
        Returns:
            PermissionCloneResponse with clone details
            
        Raises:
            UserNotFoundError: If users not found
            TemplateNotFoundError: If template not found
            UnauthorizedError: If lacks permission
            CloneConflictError: If conflicts detected
        """
        async with self._unit_of_work:
            # 1. Load target user
            target_user = await self._user_repository.get_by_id(command.target_user_id)
            if not target_user:
                raise UserNotFoundError(f"Target user {command.target_user_id} not found")
            
            # 2. Load source data
            source_data = await self._load_source_data(command.source_type, command.source_id)
            
            # 3. Validate clone operation
            await self._validate_clone_operation(
                source_data,
                target_user,
                command
            )
            
            # 4. Get current target state
            current_state = await self._capture_target_state(target_user.id)
            
            # 5. Prepare clone data
            clone_data = await self._prepare_clone_data(
                source_data,
                target_user,
                command
            )
            
            # 6. Check for conflicts
            conflicts = await self._check_conflicts(
                clone_data,
                current_state,
                command
            )
            
            if conflicts["has_conflicts"] and command.clone_mode == CloneMode.STRICT:
                raise CloneConflictError(
                    f"Conflicts detected: {', '.join(conflicts['details'])}"
                )
            
            # 7. If dry run, return preview
            if command.dry_run:
                return await self._generate_preview(
                    clone_data,
                    conflicts,
                    current_state,
                    command
                )
            
            # 8. Execute clone based on mode
            clone_results = await self._execute_clone(
                clone_data,
                target_user,
                current_state,
                command
            )
            
            # 9. Refresh target user permissions
            await self._authorization_service.refresh_user_permissions(target_user.id)
            
            # 10. Calculate changes
            new_state = await self._capture_target_state(target_user.id)
            changes = self._calculate_changes(current_state, new_state)
            
            # 11. Log high-privilege clones
            if await self._is_high_privilege_clone(clone_data):
                await self._log_high_privilege_clone(
                    source_data,
                    target_user,
                    clone_results,
                    command
                )
            
            # 12. Send notifications
            if command.notify_target:
                await self._send_clone_notifications(
                    target_user,
                    clone_results,
                    changes,
                    command
                )
            
            # 13. Publish domain event
            await self._event_bus.publish(
                PermissionsCloned(
                    aggregate_id=target_user.id,
                    source_type=command.source_type,
                    source_id=command.source_id,
                    cloned_by=command.cloned_by,
                    roles_cloned=clone_results["roles_added"],
                    permissions_cloned=clone_results["permissions_added"],
                    clone_mode=command.clone_mode
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            # 15. Return response
            return PermissionCloneResponse(
                target_user_id=target_user.id,
                source_type=command.source_type,
                source_id=command.source_id,
                clone_mode=command.clone_mode,
                clone_scope=command.clone_scope,
                roles_added=clone_results["roles_added"],
                roles_removed=clone_results["roles_removed"],
                permissions_added=clone_results["permissions_added"],
                permissions_removed=clone_results["permissions_removed"],
                conflicts_resolved=len(conflicts["resolved"]),
                total_roles_before=len(current_state["roles"]),
                total_roles_after=len(new_state["roles"]),
                total_permissions_before=len(current_state["permissions"]),
                total_permissions_after=len(new_state["permissions"]),
                dry_run=command.dry_run,
                message="Permissions cloned successfully"
            )
    
    async def _load_source_data(
        self,
        source_type: str,
        source_id: UUID
    ) -> dict[str, Any]:
        """Load data from source (user or template)."""
        source_data = {
            "type": source_type,
            "id": source_id,
            "roles": [],
            "permissions": [],
            "metadata": {}
        }
        
        if source_type == "user":
            # Load from user
            source_user = await self._user_repository.get_by_id(source_id)
            if not source_user:
                raise UserNotFoundError(f"Source user {source_id} not found")
            
            # Get user's roles
            user_roles = await self._user_role_repository.find_active_by_user(source_id)
            for user_role in user_roles:
                role = await self._role_repository.get_by_id(user_role.role_id)
                if role:
                    source_data["roles"].append({
                        "role": role,
                        "assignment": user_role
                    })
            
            # Get user's direct permissions
            user_permissions = await self._user_permission_repository.find_active_by_user(source_id)
            for user_perm in user_permissions:
                permission = await self._permission_repository.get_by_id(user_perm.permission_id)
                if permission:
                    source_data["permissions"].append({
                        "permission": permission,
                        "grant": user_perm
                    })
            
            source_data["metadata"] = {
                "username": source_user.username,
                "display_name": f"{source_user.first_name} {source_user.last_name}"
            }
            
        elif source_type == "template":
            # Load from template
            template = await self._template_repository.get_by_id(source_id)
            if not template:
                raise TemplateNotFoundError(f"Template {source_id} not found")
            
            # Get template roles
            for role_id in template.role_ids:
                role = await self._role_repository.get_by_id(role_id)
                if role:
                    source_data["roles"].append({
                        "role": role,
                        "assignment": None  # No assignment data for templates
                    })
            
            # Get template permissions
            for perm_id in template.permission_ids:
                permission = await self._permission_repository.get_by_id(perm_id)
                if permission:
                    source_data["permissions"].append({
                        "permission": permission,
                        "grant": None  # No grant data for templates
                    })
            
            source_data["metadata"] = {
                "template_name": template.name,
                "template_description": template.description
            }
        
        return source_data
    
    async def _validate_clone_operation(
        self,
        source_data: dict[str, Any],
        target_user: User,
        command: ClonePermissionsCommand
    ) -> None:
        """Validate the clone operation is allowed."""
        # Cannot clone to self
        if command.source_type == "user" and command.source_id == target_user.id:
            raise InvalidOperationError("Cannot clone permissions to same user")
        
        # Check if cloner has permission to grant all source permissions
        for role_data in source_data["roles"]:
            role = role_data["role"]
            can_grant = await self._authorization_service.can_grant_role(
                command.cloned_by,
                role.id
            )
            if not can_grant:
                raise UnauthorizedError(
                    f"You cannot grant role '{role.name}' - insufficient privileges"
                )
        
        for perm_data in source_data["permissions"]:
            permission = perm_data["permission"]
            can_grant = await self._authorization_service.can_grant_permission(
                command.cloned_by,
                permission.id
            )
            if not can_grant:
                raise UnauthorizedError(
                    f"You cannot grant permission '{permission.name}' - insufficient privileges"
                )
        
        # Check target user status
        if target_user.status not in ["ACTIVE", "PENDING"]:
            raise InvalidOperationError(
                f"Cannot clone permissions to user with status: {target_user.status}"
            )
    
    async def _capture_target_state(self, user_id: UUID) -> dict[str, Any]:
        """Capture current state of target user's permissions."""
        state = {
            "roles": [],
            "permissions": [],
            "effective_permissions": []
        }
        
        # Get current roles
        user_roles = await self._user_role_repository.find_active_by_user(user_id)
        state["roles"] = [
            {
                "role_id": ur.role_id,
                "assigned_at": ur.assigned_at,
                "expires_at": ur.expires_at,
                "scope": ur.scope
            }
            for ur in user_roles
        ]
        
        # Get current direct permissions
        user_permissions = await self._user_permission_repository.find_active_by_user(user_id)
        state["permissions"] = [
            {
                "permission_id": up.permission_id,
                "granted_at": up.granted_at,
                "expires_at": up.expires_at,
                "resource_type": up.resource_type,
                "resource_id": up.resource_id
            }
            for up in user_permissions
        ]
        
        # Get effective permissions
        effective_perms = await self._authorization_service.get_user_permissions(user_id)
        state["effective_permissions"] = [p.name for p in effective_perms]
        
        return state
    
    async def _prepare_clone_data(
        self,
        source_data: dict[str, Any],
        target_user: User,
        command: ClonePermissionsCommand
    ) -> dict[str, Any]:
        """Prepare data for cloning with filters applied."""
        clone_data = {
            "roles_to_add": [],
            "roles_to_remove": [],
            "permissions_to_add": [],
            "permissions_to_remove": []
        }
        
        # Filter roles
        if command.include_roles:
            for role_data in source_data["roles"]:
                role = role_data["role"]
                
                # Apply filters
                if command.role_filter and role.name not in command.role_filter:
                    continue
                
                if role.name in command.exclude_roles:
                    continue
                
                # Check scope
                if (command.clone_scope == CloneScope.BASIC and role.hierarchy_level > 50) or (command.clone_scope == CloneScope.ELEVATED and role.hierarchy_level > 80):
                    continue
                
                clone_data["roles_to_add"].append(role_data)
        
        # Filter permissions
        if command.include_direct_permissions:
            for perm_data in source_data["permissions"]:
                permission = perm_data["permission"]
                
                # Apply filters
                if command.permission_filter and permission.name not in command.permission_filter:
                    continue
                
                if permission.name in command.exclude_permissions:
                    continue
                
                # Check scope
                if (command.clone_scope == CloneScope.BASIC and permission.is_critical) or (command.clone_scope == CloneScope.ELEVATED and permission.is_system):
                    continue
                
                clone_data["permissions_to_add"].append(perm_data)
        
        # Handle REPLACE mode - prepare removals
        if command.clone_mode == CloneMode.REPLACE:
            current_state = await self._capture_target_state(target_user.id)
            
            # Mark current roles for removal
            for role_state in current_state["roles"]:
                clone_data["roles_to_remove"].append(role_state["role_id"])
            
            # Mark current permissions for removal
            for perm_state in current_state["permissions"]:
                clone_data["permissions_to_remove"].append(perm_state["permission_id"])
        
        return clone_data
    
    async def _check_conflicts(
        self,
        clone_data: dict[str, Any],
        current_state: dict[str, Any],
        command: ClonePermissionsCommand
    ) -> dict[str, Any]:
        """Check for conflicts between source and target."""
        conflicts = {
            "has_conflicts": False,
            "details": [],
            "resolved": []
        }
        
        # Check role conflicts
        current_role_ids = {r["role_id"] for r in current_state["roles"]}
        
        for role_data in clone_data["roles_to_add"]:
            role = role_data["role"]
            if role.id in current_role_ids:
                conflicts["has_conflicts"] = True
                conflicts["details"].append(f"Role '{role.name}' already assigned")
                
                if command.clone_mode == CloneMode.MERGE:
                    # Skip in merge mode
                    conflicts["resolved"].append(f"Keeping existing role '{role.name}'")
        
        # Check permission conflicts
        current_perm_ids = {p["permission_id"] for p in current_state["permissions"]}
        
        for perm_data in clone_data["permissions_to_add"]:
            permission = perm_data["permission"]
            if permission.id in current_perm_ids:
                conflicts["has_conflicts"] = True
                conflicts["details"].append(f"Permission '{permission.name}' already granted")
                
                if command.clone_mode == CloneMode.MERGE:
                    # Skip in merge mode
                    conflicts["resolved"].append(f"Keeping existing permission '{permission.name}'")
        
        # Check for mutual exclusions
        effective_perms = await self._authorization_service.get_user_permissions(
            command.target_user_id
        )
        effective_perm_ids = {p.id for p in effective_perms}
        
        for perm_data in clone_data["permissions_to_add"]:
            permission = perm_data["permission"]
            if permission.mutually_exclusive_with:
                exclusive_conflicts = [
                    pid for pid in permission.mutually_exclusive_with
                    if pid in effective_perm_ids
                ]
                if exclusive_conflicts:
                    conflicts["has_conflicts"] = True
                    conflicts["details"].append(
                        f"Permission '{permission.name}' conflicts with existing permissions"
                    )
        
        return conflicts
    
    async def _execute_clone(
        self,
        clone_data: dict[str, Any],
        target_user: User,
        current_state: dict[str, Any],
        command: ClonePermissionsCommand
    ) -> dict[str, Any]:
        """Execute the clone operation."""
        results = {
            "roles_added": [],
            "roles_removed": [],
            "permissions_added": [],
            "permissions_removed": [],
            "errors": []
        }
        
        # Remove permissions/roles if REPLACE mode
        if command.clone_mode == CloneMode.REPLACE:
            # Remove roles
            for role_id in clone_data["roles_to_remove"]:
                try:
                    await self._authorization_service.revoke_role_from_user(
                        target_user.id,
                        role_id,
                        command.cloned_by,
                        "Removed during permission clone"
                    )
                    results["roles_removed"].append(str(role_id))
                except Exception as e:
                    results["errors"].append(f"Failed to remove role {role_id}: {e!s}")
            
            # Remove permissions
            for perm_id in clone_data["permissions_to_remove"]:
                try:
                    await self._authorization_service.revoke_permission_from_user(
                        target_user.id,
                        perm_id,
                        command.cloned_by,
                        "Removed during permission clone"
                    )
                    results["permissions_removed"].append(str(perm_id))
                except Exception as e:
                    results["errors"].append(f"Failed to remove permission {perm_id}: {e!s}")
        
        # Add roles
        current_role_ids = {r["role_id"] for r in current_state["roles"]}
        
        for role_data in clone_data["roles_to_add"]:
            role = role_data["role"]
            assignment = role_data["assignment"]
            
            # Skip if already has role (in MERGE mode)
            if role.id in current_role_ids and command.clone_mode == CloneMode.MERGE:
                continue
            
            try:
                # Calculate expiry
                expires_at = None
                if command.include_expiry and assignment and assignment.expires_at:
                    if command.expiry_offset:
                        expires_at = datetime.now(UTC) + command.expiry_offset
                    else:
                        expires_at = assignment.expires_at
                
                # Assign role
                await self._authorization_service.assign_role_to_user(
                    target_user.id,
                    role.id,
                    command.cloned_by,
                    command.reason,
                    scope=assignment.scope if assignment and command.include_conditions else None,
                    expires_at=expires_at
                )
                
                results["roles_added"].append(role.name)
                
            except Exception as e:
                results["errors"].append(f"Failed to add role '{role.name}': {e!s}")
        
        # Add permissions
        current_perm_ids = {p["permission_id"] for p in current_state["permissions"]}
        
        for perm_data in clone_data["permissions_to_add"]:
            permission = perm_data["permission"]
            grant = perm_data["grant"]
            
            # Skip if already has permission (in MERGE mode)
            if permission.id in current_perm_ids and command.clone_mode == CloneMode.MERGE:
                continue
            
            try:
                # Calculate expiry
                expires_at = None
                if command.include_expiry and grant and grant.expires_at:
                    if command.expiry_offset:
                        expires_at = datetime.now(UTC) + command.expiry_offset
                    else:
                        expires_at = grant.expires_at
                
                # Grant permission
                await self._authorization_service.grant_permission_to_user(
                    target_user.id,
                    permission.id,
                    command.cloned_by,
                    command.reason,
                    resource_type=grant.resource_type if grant and command.include_conditions else None,
                    resource_id=grant.resource_id if grant and command.include_conditions else None,
                    conditions=grant.conditions if grant and command.include_conditions else None,
                    expires_at=expires_at
                )
                
                results["permissions_added"].append(permission.name)
                
            except Exception as e:
                results["errors"].append(f"Failed to add permission '{permission.name}': {e!s}")
        
        return results
    
    async def _generate_preview(
        self,
        clone_data: dict[str, Any],
        conflicts: dict[str, Any],
        current_state: dict[str, Any],
        command: ClonePermissionsCommand
    ) -> PermissionCloneResponse:
        """Generate preview of what would be cloned."""
        # Count what would be added/removed
        roles_to_add = [r["role"].name for r in clone_data["roles_to_add"]]
        roles_to_remove = clone_data["roles_to_remove"]
        permissions_to_add = [p["permission"].name for p in clone_data["permissions_to_add"]]
        permissions_to_remove = clone_data["permissions_to_remove"]
        
        return PermissionCloneResponse(
            target_user_id=command.target_user_id,
            source_type=command.source_type,
            source_id=command.source_id,
            clone_mode=command.clone_mode,
            clone_scope=command.clone_scope,
            roles_added=roles_to_add,
            roles_removed=[str(r) for r in roles_to_remove],
            permissions_added=permissions_to_add,
            permissions_removed=[str(p) for p in permissions_to_remove],
            conflicts_resolved=len(conflicts["resolved"]),
            total_roles_before=len(current_state["roles"]),
            total_roles_after=len(current_state["roles"]) + len(roles_to_add) - len(roles_to_remove),
            total_permissions_before=len(current_state["permissions"]),
            total_permissions_after=len(current_state["permissions"]) + len(permissions_to_add) - len(permissions_to_remove),
            dry_run=True,
            message="Clone preview generated (dry run)"
        )
    
    def _calculate_changes(
        self,
        before_state: dict[str, Any],
        after_state: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate what changed between states."""
        before_roles = {r["role_id"] for r in before_state["roles"]}
        after_roles = {r["role_id"] for r in after_state["roles"]}
        
        before_perms = {p["permission_id"] for p in before_state["permissions"]}
        after_perms = {p["permission_id"] for p in after_state["permissions"]}
        
        return {
            "roles_added": list(after_roles - before_roles),
            "roles_removed": list(before_roles - after_roles),
            "permissions_added": list(after_perms - before_perms),
            "permissions_removed": list(before_perms - after_perms),
            "effective_permissions_before": len(before_state["effective_permissions"]),
            "effective_permissions_after": len(after_state["effective_permissions"])
        }
    
    async def _is_high_privilege_clone(self, clone_data: dict[str, Any]) -> bool:
        """Check if clone includes high privilege permissions."""
        # Check for high-level roles
        for role_data in clone_data["roles_to_add"]:
            role = role_data["role"]
            if role.hierarchy_level >= 80 or role.is_system:
                return True
        
        # Check for critical permissions
        for perm_data in clone_data["permissions_to_add"]:
            permission = perm_data["permission"]
            if permission.is_critical or permission.is_system:
                return True
        
        return False
    
    async def _log_high_privilege_clone(
        self,
        source_data: dict[str, Any],
        target_user: User,
        clone_results: dict[str, Any],
        command: ClonePermissionsCommand
    ) -> None:
        """Log cloning of high-privilege permissions."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_PRIVILEGE_CLONE,
                severity=RiskLevel.HIGH,
                user_id=command.cloned_by,
                details={
                    "source_type": command.source_type,
                    "source_id": str(command.source_id),
                    "source_name": source_data["metadata"].get(
                        "username",
                        source_data["metadata"].get("template_name")
                    ),
                    "target_user_id": str(target_user.id),
                    "target_username": target_user.username,
                    "clone_mode": command.clone_mode.value,
                    "roles_added": clone_results["roles_added"],
                    "permissions_added": clone_results["permissions_added"],
                    "reason": command.reason
                },
                indicators=["high_privilege_permission_clone"],
                recommended_actions=[
                    "Review clone justification",
                    "Monitor target user activities",
                    "Verify appropriate access level"
                ]
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "High-Privilege Permission Clone",
            {
                "cloned_by": str(command.cloned_by),
                "target_user": target_user.username,
                "source": source_data["metadata"].get(
                    "username",
                    source_data["metadata"].get("template_name")
                ),
                "high_privilege_items": {
                    "roles": [r for r in clone_results["roles_added"] if "admin" in r.lower()],
                    "permissions": [p for p in clone_results["permissions_added"] if "system" in p or "admin" in p]
                }
            }
        )
    
    async def _send_clone_notifications(
        self,
        target_user: User,
        clone_results: dict[str, Any],
        changes: dict[str, Any],
        command: ClonePermissionsCommand
    ) -> None:
        """Send notifications about permission cloning."""
        # Email notification
        if target_user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=target_user.email,
                    template="permissions_cloned",
                    subject="Your permissions have been updated",
                    variables={
                        "username": target_user.username,
                        "roles_added": clone_results["roles_added"],
                        "permissions_added": clone_results["permissions_added"],
                        "total_new_permissions": changes["effective_permissions_after"] - changes["effective_permissions_before"],
                        "reason": command.reason,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=target_user.id,
                notification_type=NotificationType.PERMISSIONS_CLONED,
                channel="in_app",
                template_id="permissions_cloned",
                template_data={
                    "clone_summary": {
                        "roles_added": len(clone_results["roles_added"]),
                        "permissions_added": len(clone_results["permissions_added"]),
                        "source_type": command.source_type
                    },
                    "reason": command.reason
                },
                priority="high"
            )
        )
        
        # Notify administrators if significant changes
        if len(clone_results["roles_added"]) > 5 or len(clone_results["permissions_added"]) > 10:
            await self._notification_service.notify_role(
                "administrator",
                NotificationContext(
                    notification_id=UUID(),
                    recipient_id=None,
                    notification_type=NotificationType.SIGNIFICANT_PERMISSION_CHANGE,
                    channel="in_app",
                    template_id="significant_clone",
                    template_data={
                        "target_user": target_user.username,
                        "cloned_by": str(command.cloned_by),
                        "changes": changes
                    },
                    priority="medium"
                )
            )