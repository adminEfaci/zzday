"""
Update role command implementation.

Handles updating existing roles with validation and impact analysis.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    INotificationService,
    IPermissionRepository,
    IRoleRepository,
    ISessionRepository,
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
from app.modules.identity.application.dtos.internal import SecurityIncidentContext
from app.modules.identity.application.dtos.request import UpdateRoleRequest
from app.modules.identity.application.dtos.response import RoleUpdateResponse
from app.modules.identity.domain.entities import Permission, Role
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import RolePermissionsChanged, RoleUpdated
from app.modules.identity.domain.exceptions import (
    ImpactThresholdExceededError,
    InvalidOperationError,
    RoleNotFoundError,
    SystemRoleError,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    SessionService,
    ValidationService,
)


class UpdateRoleCommand(Command[RoleUpdateResponse]):
    """Command to update an existing role."""
    
    def __init__(
        self,
        role_id: UUID,
        updated_by: UUID,
        display_name: str | None = None,
        description: str | None = None,
        permissions_to_add: list[UUID] | None = None,
        permissions_to_remove: list[UUID] | None = None,
        hierarchy_level: int | None = None,
        max_assignments: int | None = None,
        prerequisites: dict[str, Any] | None = None,
        grantable_roles: list[UUID] | None = None,
        grantable_permissions: list[UUID] | None = None,
        is_active: bool | None = None,
        force_update: bool = False,
        notify_affected_users: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.role_id = role_id
        self.updated_by = updated_by
        self.display_name = display_name
        self.description = description
        self.permissions_to_add = permissions_to_add or []
        self.permissions_to_remove = permissions_to_remove or []
        self.hierarchy_level = hierarchy_level
        self.max_assignments = max_assignments
        self.prerequisites = prerequisites
        self.grantable_roles = grantable_roles
        self.grantable_permissions = grantable_permissions
        self.is_active = is_active
        self.force_update = force_update
        self.notify_affected_users = notify_affected_users
        self.metadata = metadata


class UpdateRoleCommandHandler(CommandHandler[UpdateRoleCommand, RoleUpdateResponse]):
    """Handler for updating roles."""
    
    def __init__(
        self,
        role_repository: IRoleRepository,
        permission_repository: IPermissionRepository,
        user_role_repository: IUserRoleRepository,
        session_repository: ISessionRepository,
        authorization_service: AuthorizationService,
        validation_service: ValidationService,
        session_service: SessionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._role_repository = role_repository
        self._permission_repository = permission_repository
        self._user_role_repository = user_role_repository
        self._session_repository = session_repository
        self._authorization_service = authorization_service
        self._validation_service = validation_service
        self._session_service = session_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.ROLE_UPDATED,
        resource_type="role",
        include_request=True,
        include_response=True,
        include_changes=True
    )
    @validate_request(UpdateRoleRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "roles.update",
        resource_type="role",
        resource_id_param="role_id"
    )
    @require_mfa()
    @require_approval(
        approval_type="role_update",
        condition="high_impact",
        threshold=100  # Users affected
    )
    async def handle(self, command: UpdateRoleCommand) -> RoleUpdateResponse:
        """
        Update role with comprehensive validation.
        
        Process:
        1. Load role and validate
        2. Check update permissions
        3. Analyze update impact
        4. Validate changes
        5. Apply updates
        6. Refresh affected users
        7. Send notifications
        8. Log significant changes
        
        Returns:
            RoleUpdateResponse with update details
            
        Raises:
            RoleNotFoundError: If role not found
            UnauthorizedError: If lacks permission
            SystemRoleError: If system role
            ImpactThresholdExceededError: If too many affected
        """
        async with self._unit_of_work:
            # 1. Load role
            role = await self._role_repository.get_by_id(command.role_id)
            if not role:
                raise RoleNotFoundError(f"Role {command.role_id} not found")
            
            # 2. Check if system role
            if role.is_system and not command.force_update:
                raise SystemRoleError("Cannot update system role without force flag")
            
            # 3. Store original state
            original_state = self._capture_role_state(role)
            
            # 4. Analyze impact
            impact_analysis = await self._analyze_update_impact(role, command)
            
            # 5. Check impact threshold
            if not command.force_update and impact_analysis["affected_users"] > 1000:
                raise ImpactThresholdExceededError(
                    f"Update would affect {impact_analysis['affected_users']} users. "
                    "Use force_update=True to proceed."
                )
            
            # 6. Validate permission changes
            permissions_added = []
            permissions_removed = []
            
            if command.permissions_to_add:
                permissions_added = await self._validate_permissions_to_add(
                    role,
                    command.permissions_to_add
                )
            
            if command.permissions_to_remove:
                permissions_removed = await self._validate_permissions_to_remove(
                    role,
                    command.permissions_to_remove
                )
            
            # 7. Validate hierarchy change
            if command.hierarchy_level is not None:
                await self._validate_hierarchy_change(
                    role,
                    command.hierarchy_level,
                    command.updated_by
                )
            
            # 8. Apply updates
            changes = {}
            
            if command.display_name is not None:
                changes["display_name"] = (role.display_name, command.display_name)
                role.display_name = command.display_name
            
            if command.description is not None:
                changes["description"] = (role.description, command.description)
                role.description = command.description
            
            if command.hierarchy_level is not None:
                changes["hierarchy_level"] = (role.hierarchy_level, command.hierarchy_level)
                role.hierarchy_level = command.hierarchy_level
            
            if command.max_assignments is not None:
                changes["max_assignments"] = (role.max_assignments, command.max_assignments)
                role.max_assignments = command.max_assignments
            
            if command.prerequisites is not None:
                changes["prerequisites"] = (role.prerequisites, command.prerequisites)
                role.prerequisites = command.prerequisites
            
            if command.grantable_roles is not None:
                changes["grantable_roles"] = (
                    len(role.grantable_roles),
                    len(command.grantable_roles)
                )
                role.grantable_roles = command.grantable_roles
            
            if command.grantable_permissions is not None:
                changes["grantable_permissions"] = (
                    len(role.grantable_permissions),
                    len(command.grantable_permissions)
                )
                role.grantable_permissions = command.grantable_permissions
            
            if command.is_active is not None:
                changes["is_active"] = (role.is_active, command.is_active)
                role.is_active = command.is_active
            
            # 9. Update permissions
            if permissions_added:
                current_perms = set(role.permissions)
                current_perms.update(p.id for p in permissions_added)
                role.set_permissions(list(current_perms))
                changes["permissions_added"] = len(permissions_added)
            
            if permissions_removed:
                current_perms = set(role.permissions)
                current_perms.difference_update(p.id for p in permissions_removed)
                role.set_permissions(list(current_perms))
                changes["permissions_removed"] = len(permissions_removed)
            
            # 10. Update metadata
            role.updated_at = datetime.now(UTC)
            role.updated_by = command.updated_by
            
            if command.metadata:
                role.metadata.update(command.metadata)
            
            # 11. Save role
            await self._role_repository.update(role)
            
            # 12. Refresh permissions for affected users
            affected_user_ids = await self._get_affected_users(role.id)
            
            for user_id in affected_user_ids:
                await self._authorization_service.refresh_user_permissions(user_id)
            
            # 13. Handle session revocation if needed
            sessions_revoked = 0
            if self._requires_session_revocation(changes, permissions_removed):
                sessions_revoked = await self._revoke_affected_sessions(
                    affected_user_ids,
                    role,
                    changes
                )
            
            # 14. Publish events
            await self._event_bus.publish(
                RoleUpdated(
                    aggregate_id=role.id,
                    role_name=role.name,
                    updated_by=command.updated_by,
                    changes=changes,
                    affected_users=len(affected_user_ids)
                )
            )
            
            if permissions_added or permissions_removed:
                await self._event_bus.publish(
                    RolePermissionsChanged(
                        aggregate_id=role.id,
                        role_name=role.name,
                        permissions_added=[p.name for p in permissions_added],
                        permissions_removed=[p.name for p in permissions_removed],
                        affected_users=len(affected_user_ids)
                    )
                )
            
            # 15. Send notifications
            if command.notify_affected_users and affected_user_ids:
                await self._send_update_notifications(
                    role,
                    changes,
                    permissions_added,
                    permissions_removed,
                    affected_user_ids
                )
            
            # 16. Log significant changes
            if self._is_significant_change(changes, permissions_added, permissions_removed):
                await self._log_significant_update(
                    role,
                    original_state,
                    changes,
                    command
                )
            
            # 17. Commit transaction
            await self._unit_of_work.commit()
            
            # 18. Return response
            return RoleUpdateResponse(
                role_id=role.id,
                role_name=role.name,
                changes_made=changes,
                permissions_added=[p.name for p in permissions_added],
                permissions_removed=[p.name for p in permissions_removed],
                affected_users=len(affected_user_ids),
                sessions_revoked=sessions_revoked,
                updated_at=role.updated_at,
                updated_by=role.updated_by,
                message=f"Role '{role.name}' updated successfully"
            )
    
    def _capture_role_state(self, role: Role) -> dict[str, Any]:
        """Capture current role state for comparison."""
        return {
            "display_name": role.display_name,
            "description": role.description,
            "hierarchy_level": role.hierarchy_level,
            "is_active": role.is_active,
            "permissions": list(role.permissions),
            "max_assignments": role.max_assignments,
            "prerequisites": role.prerequisites.copy() if role.prerequisites else {},
            "grantable_roles": list(role.grantable_roles),
            "grantable_permissions": list(role.grantable_permissions)
        }
    
    async def _analyze_update_impact(
        self,
        role: Role,
        command: UpdateRoleCommand
    ) -> dict[str, Any]:
        """Analyze the impact of role updates."""
        impact = {
            "affected_users": 0,
            "critical_permissions_removed": [],
            "hierarchy_impact": False,
            "requires_reauthentication": False,
            "severity": "low"
        }
        
        # Count affected users
        affected_users = await self._user_role_repository.count_users_with_role(role.id)
        impact["affected_users"] = affected_users
        
        # Check permission removals
        if command.permissions_to_remove:
            for perm_id in command.permissions_to_remove:
                permission = await self._permission_repository.get_by_id(perm_id)
                if permission and permission.is_critical:
                    impact["critical_permissions_removed"].append(permission.name)
                    impact["severity"] = "high"
                    impact["requires_reauthentication"] = True
        
        # Check hierarchy changes
        if command.hierarchy_level is not None and command.hierarchy_level != role.hierarchy_level:
            impact["hierarchy_impact"] = True
            impact["severity"] = "medium" if impact["severity"] == "low" else impact["severity"]
        
        # Check deactivation
        if command.is_active is False and role.is_active:
            impact["requires_reauthentication"] = True
            impact["severity"] = "high"
        
        return impact
    
    async def _validate_permissions_to_add(
        self,
        role: Role,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to add."""
        permissions = []
        current_permission_ids = set(role.permissions)
        
        for perm_id in permission_ids:
            # Skip if already has permission
            if perm_id in current_permission_ids:
                continue
            
            permission = await self._permission_repository.get_by_id(perm_id)
            if not permission:
                raise InvalidOperationError(f"Permission {perm_id} not found")
            
            if not permission.is_active:
                raise InvalidOperationError(
                    f"Cannot add inactive permission '{permission.name}'"
                )
            
            permissions.append(permission)
        
        # Check for conflicts with existing permissions
        if permissions:
            await self._check_permission_conflicts(
                role,
                permissions
            )
        
        return permissions
    
    async def _validate_permissions_to_remove(
        self,
        role: Role,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to remove."""
        permissions = []
        current_permission_ids = set(role.permissions)
        
        for perm_id in permission_ids:
            if perm_id not in current_permission_ids:
                continue  # Skip if doesn't have permission
            
            permission = await self._permission_repository.get_by_id(perm_id)
            if permission:
                permissions.append(permission)
        
        return permissions
    
    async def _validate_hierarchy_change(
        self,
        role: Role,
        new_level: int,
        updater_id: UUID
    ) -> None:
        """Validate hierarchy level change."""
        # Cannot change hierarchy of system roles
        if role.is_system:
            raise SystemRoleError("Cannot change hierarchy level of system role")
        
        # Check if updater has sufficient privileges
        updater_roles = await self._authorization_service.get_user_roles(updater_id)
        updater_max_level = max(
            (r.hierarchy_level for r in updater_roles),
            default=0
        )
        
        # Cannot set level higher than own level
        if new_level > updater_max_level:
            raise InvalidOperationError(
                f"Cannot set hierarchy level to {new_level} - "
                f"your maximum level is {updater_max_level}"
            )
        
        # Check impact on existing assignments
        if new_level > role.hierarchy_level:
            # Increasing level - check if any users would violate hierarchy
            assignments = await self._user_role_repository.find_by_role(role.id)
            for assignment in assignments:
                await self._authorization_service.get_user_roles(
                    assignment.user_id
                )
                # This would need more complex validation
    
    async def _check_permission_conflicts(
        self,
        role: Role,
        new_permissions: list[Permission]
    ) -> None:
        """Check for conflicts between new and existing permissions."""
        # Get current permissions
        current_permissions = []
        for perm_id in role.permissions:
            perm = await self._permission_repository.get_by_id(perm_id)
            if perm:
                current_permissions.append(perm)
        
        # Check each new permission
        for new_perm in new_permissions:
            # Check mutual exclusions
            if new_perm.mutually_exclusive_with:
                conflicts = [
                    p.name for p in current_permissions
                    if p.id in new_perm.mutually_exclusive_with
                ]
                if conflicts:
                    raise InvalidOperationError(
                        f"Permission '{new_perm.name}' conflicts with: {', '.join(conflicts)}"
                    )
    
    async def _get_affected_users(self, role_id: UUID) -> list[UUID]:
        """Get list of users affected by role update."""
        assignments = await self._user_role_repository.find_active_by_role(role_id)
        return [assignment.user_id for assignment in assignments]
    
    def _requires_session_revocation(
        self,
        changes: dict[str, Any],
        permissions_removed: list[Permission]
    ) -> bool:
        """Check if changes require session revocation."""
        # Deactivation requires revocation
        if "is_active" in changes and changes["is_active"][1] is False:
            return True
        
        # Significant hierarchy reduction
        if "hierarchy_level" in changes:
            old_level, new_level = changes["hierarchy_level"]
            if new_level < old_level - 20:  # Major demotion
                return True
        
        # Critical permissions removed
        for perm in permissions_removed:
            if perm.is_critical or perm.action in ["login", "authenticate"]:
                return True
        
        return False
    
    async def _revoke_affected_sessions(
        self,
        user_ids: list[UUID],
        role: Role,
        changes: dict[str, Any]
    ) -> int:
        """Revoke sessions for affected users."""
        sessions_revoked = 0
        reason = f"Role '{role.name}' updated - reauthentication required"
        
        for user_id in user_ids:
            sessions = await self._session_repository.get_active_sessions(user_id)
            for session in sessions:
                await self._session_service.revoke_session(session.id, reason)
                sessions_revoked += 1
        
        return sessions_revoked
    
    def _is_significant_change(
        self,
        changes: dict[str, Any],
        permissions_added: list[Permission],
        permissions_removed: list[Permission]
    ) -> bool:
        """Check if changes are significant enough to log."""
        # Hierarchy changes are significant
        if "hierarchy_level" in changes:
            return True
        
        # Active status changes
        if "is_active" in changes:
            return True
        
        # Many permission changes
        if len(permissions_added) + len(permissions_removed) > 5:
            return True
        
        # Critical permission changes
        critical_perms = [
            p for p in permissions_added + permissions_removed
            if p.is_critical or p.is_sensitive
        ]
        return bool(critical_perms)
    
    async def _send_update_notifications(
        self,
        role: Role,
        changes: dict[str, Any],
        permissions_added: list[Permission],
        permissions_removed: list[Permission],
        affected_user_ids: list[UUID]
    ) -> None:
        """Send notifications to affected users."""
        # Batch notifications for efficiency
        notification_data = {
            "role_name": role.name,
            "changes_summary": self._summarize_changes(
                changes,
                permissions_added,
                permissions_removed
            ),
            "requires_action": self._requires_user_action(changes, permissions_removed)
        }
        
        # Send batch notification
        await self._notification_service.send_batch_notification(
            user_ids=affected_user_ids,
            notification_type=NotificationType.ROLE_UPDATED,
            template_id="role_updated",
            template_data=notification_data,
            priority="high" if notification_data["requires_action"] else "medium"
        )
    
    def _summarize_changes(
        self,
        changes: dict[str, Any],
        permissions_added: list[Permission],
        permissions_removed: list[Permission]
    ) -> str:
        """Create human-readable summary of changes."""
        summary_parts = []
        
        if permissions_added:
            summary_parts.append(f"{len(permissions_added)} permissions added")
        
        if permissions_removed:
            summary_parts.append(f"{len(permissions_removed)} permissions removed")
        
        if "hierarchy_level" in changes:
            old_level, new_level = changes["hierarchy_level"]
            if new_level > old_level:
                summary_parts.append("Hierarchy level increased")
            else:
                summary_parts.append("Hierarchy level decreased")
        
        if "is_active" in changes and changes["is_active"][1] is False:
            summary_parts.append("Role deactivated")
        
        return ", ".join(summary_parts) if summary_parts else "Minor updates"
    
    def _requires_user_action(
        self,
        changes: dict[str, Any],
        permissions_removed: list[Permission]
    ) -> bool:
        """Check if users need to take action."""
        # Deactivation requires action
        if "is_active" in changes and changes["is_active"][1] is False:
            return True
        
        # Critical permissions removed
        return any(perm.is_critical for perm in permissions_removed)
    
    async def _log_significant_update(
        self,
        role: Role,
        original_state: dict[str, Any],
        changes: dict[str, Any],
        command: UpdateRoleCommand
    ) -> None:
        """Log significant role updates."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.ROLE_SIGNIFICANT_UPDATE,
                severity=RiskLevel.MEDIUM,
                user_id=command.updated_by,
                details={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "changes": changes,
                    "original_state": original_state,
                    "affected_users": await self._user_role_repository.count_users_with_role(role.id)
                },
                indicators=["significant_role_change"],
                recommended_actions=[
                    "Review role changes",
                    "Monitor affected user activities"
                ]
            )
        )