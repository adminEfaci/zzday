"""
Update permission command implementation.

Handles updating existing permissions with impact analysis.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_approval,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import PermissionUpdateParams
from app.modules.identity.application.dtos.internal import SecurityIncidentContext
from app.modules.identity.application.dtos.request import UpdatePermissionRequest
from app.modules.identity.application.dtos.response import PermissionUpdateResponse
from app.modules.identity.domain.entities import Permission
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import PermissionUpdated
from app.modules.identity.domain.exceptions import (
    ImpactThresholdExceededError,
    InvalidOperationError,
    PermissionNotFoundError,
    SystemPermissionError,
)
from app.modules.identity.domain.interfaces.repositories.permission_repository import (
    IPermissionRepository,
)
from app.modules.identity.domain.interfaces.repositories.role_repository import (
    IRoleRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    INotificationService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
    IUserPermissionRepository,
)
    AuthorizationService,
    SessionService,
    ValidationService,
)


class UpdatePermissionCommand(Command[PermissionUpdateResponse]):
    """Command to update an existing permission."""
    
    def __init__(self, params: PermissionUpdateParams):
        self.params = params
        # Initialize empty lists if None
        self.params.implies_to_add = params.implies_to_add or []
        self.params.implies_to_remove = params.implies_to_remove or []
        self.params.exclusions_to_add = params.exclusions_to_add or []
        self.params.exclusions_to_remove = params.exclusions_to_remove or []


class UpdatePermissionCommandHandler(CommandHandler[UpdatePermissionCommand, PermissionUpdateResponse]):
    """Handler for updating permissions."""
    
    def __init__(
        self,
        permission_repository: IPermissionRepository,
        user_permission_repository: IUserPermissionRepository,
        role_repository: IRoleRepository,
        session_repository: ISessionRepository,
        authorization_service: AuthorizationService,
        validation_service: ValidationService,
        session_service: SessionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._permission_repository = permission_repository
        self._user_permission_repository = user_permission_repository
        self._role_repository = role_repository
        self._session_repository = session_repository
        self._authorization_service = authorization_service
        self._validation_service = validation_service
        self._session_service = session_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_UPDATED,
        resource_type="permission",
        include_request=True,
        include_response=True,
        include_changes=True
    )
    @validate_request(UpdatePermissionRequest)
    @rate_limit(
        max_requests=30,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "permissions.update",
        resource_type="permission",
        resource_id_param="permission_id"
    )
    @require_mfa()
    @require_approval(
        approval_type="permission_update",
        condition="high_impact",
        threshold=500  # Affected entities
    )
    async def handle(self, command: UpdatePermissionCommand) -> PermissionUpdateResponse:
        """
        Update permission with comprehensive validation.
        
        Process:
        1. Load permission and validate
        2. Check update permissions
        3. Analyze update impact
        4. Validate changes
        5. Apply updates
        6. Update dependencies
        7. Refresh affected caches
        8. Send notifications
        9. Log significant changes
        
        Returns:
            PermissionUpdateResponse with update details
            
        Raises:
            PermissionNotFoundError: If permission not found
            UnauthorizedError: If lacks permission
            SystemPermissionError: If system permission
            ImpactThresholdExceededError: If too many affected
        """
        async with self._unit_of_work:
            # 1. Load permission
            permission = await self._permission_repository.find_by_id(command.permission_id)
            if not permission:
                raise PermissionNotFoundError(f"Permission {command.permission_id} not found")
            
            # 2. Check if system permission
            if permission.is_system and not command.force_update:
                raise SystemPermissionError(
                    "Cannot update system permission without force flag"
                )
            
            # 3. Store original state
            original_state = self._capture_permission_state(permission)
            
            # 4. Analyze impact
            impact_analysis = await self._analyze_update_impact(permission, command)
            
            # 5. Check impact threshold
            if not command.force_update and impact_analysis["total_affected"] > 500:
                raise ImpactThresholdExceededError(
                    f"Update would affect {impact_analysis['total_affected']} entities. "
                    "Use force_update=True to proceed."
                )
            
            # 6. Validate implies changes
            implies_added = []
            implies_removed = []
            
            if command.implies_to_add:
                implies_added = await self._validate_implies_to_add(
                    permission,
                    command.implies_to_add
                )
            
            if command.implies_to_remove:
                implies_removed = await self._validate_implies_to_remove(
                    permission,
                    command.implies_to_remove
                )
            
            # 7. Validate exclusion changes
            exclusions_added = []
            exclusions_removed = []
            
            if command.exclusions_to_add:
                exclusions_added = await self._validate_exclusions_to_add(
                    permission,
                    command.exclusions_to_add
                )
            
            if command.exclusions_to_remove:
                exclusions_removed = await self._validate_exclusions_to_remove(
                    permission,
                    command.exclusions_to_remove
                )
            
            # 8. Apply updates
            changes = {}
            
            if command.display_name is not None:
                changes["display_name"] = (permission.display_name, command.display_name)
                permission.display_name = command.display_name
            
            if command.description is not None:
                changes["description"] = (permission.description, command.description)
                permission.description = command.description
            
            if command.is_critical is not None:
                changes["is_critical"] = (permission.is_critical, command.is_critical)
                permission.is_critical = command.is_critical
            
            if command.is_sensitive is not None:
                changes["is_sensitive"] = (permission.is_sensitive, command.is_sensitive)
                permission.is_sensitive = command.is_sensitive
            
            if command.category is not None:
                changes["category"] = (permission.category, command.category)
                permission.category = command.category
            
            if command.tags is not None:
                changes["tags"] = (len(permission.tags), len(command.tags))
                permission.tags = command.tags
            
            if command.prerequisites is not None:
                changes["prerequisites"] = (
                    bool(permission.prerequisites),
                    bool(command.prerequisites)
                )
                permission.prerequisites = command.prerequisites
            
            if command.conditions is not None:
                changes["conditions"] = (
                    bool(permission.conditions),
                    bool(command.conditions)
                )
                permission.conditions = command.conditions
            
            if command.is_active is not None:
                changes["is_active"] = (permission.is_active, command.is_active)
                permission.is_active = command.is_active
            
            # 9. Update implications
            if implies_added:
                current_implies = set(permission.implies)
                current_implies.update(p.id for p in implies_added)
                permission.implies = list(current_implies)
                changes["implies_added"] = len(implies_added)
            
            if implies_removed:
                current_implies = set(permission.implies)
                current_implies.difference_update(p.id for p in implies_removed)
                permission.implies = list(current_implies)
                changes["implies_removed"] = len(implies_removed)
            
            # 10. Update exclusions
            if exclusions_added:
                current_exclusions = set(permission.mutually_exclusive_with)
                current_exclusions.update(p.id for p in exclusions_added)
                permission.mutually_exclusive_with = list(current_exclusions)
                changes["exclusions_added"] = len(exclusions_added)
            
            if exclusions_removed:
                current_exclusions = set(permission.mutually_exclusive_with)
                current_exclusions.difference_update(p.id for p in exclusions_removed)
                permission.mutually_exclusive_with = list(current_exclusions)
                changes["exclusions_removed"] = len(exclusions_removed)
            
            # 11. Update metadata
            permission.updated_at = datetime.now(UTC)
            permission.updated_by = command.updated_by
            
            if command.metadata:
                permission.metadata.update(command.metadata)
            
            # 12. Save permission
            await self._permission_repository.update(permission)
            
            # 13. Update indices
            await self._update_permission_indices(permission, original_state)
            
            # 14. Refresh affected caches
            affected_entities = await self._get_affected_entities(permission.id)
            
            for user_id in affected_entities["users"]:
                await self._authorization_service.refresh_user_permissions(user_id)
            
            # 15. Handle session revocation if needed
            sessions_revoked = 0
            if self._requires_session_revocation(changes):
                sessions_revoked = await self._revoke_affected_sessions(
                    affected_entities["users"],
                    permission,
                    changes
                )
            
            # 16. Publish events
            await self._event_bus.publish(
                PermissionUpdated(
                    aggregate_id=permission.id,
                    permission_name=permission.name,
                    updated_by=command.updated_by,
                    changes=changes,
                    affected_users=len(affected_entities["users"]),
                    affected_roles=len(affected_entities["roles"])
                )
            )
            
            # 17. Send notifications
            if command.notify_affected and affected_entities["users"]:
                await self._send_update_notifications(
                    permission,
                    changes,
                    affected_entities,
                    command
                )
            
            # 18. Log significant changes
            if self._is_significant_change(changes):
                await self._log_significant_update(
                    permission,
                    original_state,
                    changes,
                    command
                )
            
            # 19. Commit transaction
            await self._unit_of_work.commit()
            
            # 20. Return response
            return PermissionUpdateResponse(
                permission_id=permission.id,
                permission_name=permission.name,
                changes_made=changes,
                implies_added=[p.name for p in implies_added],
                implies_removed=[p.name for p in implies_removed],
                exclusions_added=[p.name for p in exclusions_added],
                exclusions_removed=[p.name for p in exclusions_removed],
                affected_users=len(affected_entities["users"]),
                affected_roles=len(affected_entities["roles"]),
                sessions_revoked=sessions_revoked,
                updated_at=permission.updated_at,
                updated_by=permission.updated_by,
                message=f"Permission '{permission.name}' updated successfully"
            )
    
    def _capture_permission_state(self, permission: Permission) -> dict[str, Any]:
        """Capture current permission state for comparison."""
        return {
            "display_name": permission.display_name,
            "description": permission.description,
            "is_critical": permission.is_critical,
            "is_sensitive": permission.is_sensitive,
            "is_active": permission.is_active,
            "category": permission.category,
            "tags": list(permission.tags),
            "implies": list(permission.implies),
            "exclusions": list(permission.mutually_exclusive_with),
            "prerequisites": permission.prerequisites.copy() if permission.prerequisites else {},
            "conditions": permission.conditions.copy() if permission.conditions else {}
        }
    
    async def _analyze_update_impact(
        self,
        permission: Permission,
        command: UpdatePermissionCommand
    ) -> dict[str, Any]:
        """Analyze the impact of permission updates."""
        impact = {
            "affected_users": 0,
            "affected_roles": 0,
            "dependent_permissions": 0,
            "critical_changes": [],
            "requires_reauthentication": False,
            "severity": "low",
            "total_affected": 0
        }
        
        # Count users with this permission
        user_grants = await self._user_permission_repository.count_by_permission(permission.id)
        impact["affected_users"] = user_grants
        
        # Count roles with this permission
        roles_with_permission = await self._role_repository.count_with_permission(permission.id)
        impact["affected_roles"] = roles_with_permission
        
        # Check critical changes
        if command.is_active is False and permission.is_active:
            impact["critical_changes"].append("deactivation")
            impact["requires_reauthentication"] = True
            impact["severity"] = "critical"
        
        if command.is_critical is False and permission.is_critical:
            impact["critical_changes"].append("criticality_downgrade")
            impact["severity"] = "high" if impact["severity"] == "low" else impact["severity"]
        
        # Check implication removals
        if command.implies_to_remove:
            impact["critical_changes"].append("implications_removed")
            impact["severity"] = "medium" if impact["severity"] == "low" else impact["severity"]
        
        # Calculate total affected entities
        impact["total_affected"] = (
            impact["affected_users"] +
            impact["affected_roles"] * 10  # Assume 10 users per role average
        )
        
        return impact
    
    async def _validate_implies_to_add(
        self,
        permission: Permission,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to add as implications."""
        permissions = []
        current_implies = set(permission.implies)
        
        for perm_id in permission_ids:
            # Skip if already implies
            if perm_id in current_implies:
                continue
            
            # Prevent self-implication
            if perm_id == permission.id:
                raise InvalidOperationError("Permission cannot imply itself")
            
            implied_perm = await self._permission_repository.find_by_id(perm_id)
            if not implied_perm:
                raise InvalidOperationError(f"Permission {perm_id} not found")
            
            if not implied_perm.is_active:
                raise InvalidOperationError(
                    f"Cannot imply inactive permission '{implied_perm.name}'"
                )
            
            # Check for circular implications
            if permission.id in implied_perm.implies:
                raise InvalidOperationError(
                    f"Circular implication with permission '{implied_perm.name}'"
                )
            
            permissions.append(implied_perm)
        
        return permissions
    
    async def _validate_implies_to_remove(
        self,
        permission: Permission,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to remove from implications."""
        permissions = []
        current_implies = set(permission.implies)
        
        for perm_id in permission_ids:
            if perm_id not in current_implies:
                continue  # Skip if not implied
            
            implied_perm = await self._permission_repository.find_by_id(perm_id)
            if implied_perm:
                permissions.append(implied_perm)
        
        return permissions
    
    async def _validate_exclusions_to_add(
        self,
        permission: Permission,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to add as exclusions."""
        permissions = []
        current_exclusions = set(permission.mutually_exclusive_with)
        
        for perm_id in permission_ids:
            # Skip if already exclusive
            if perm_id in current_exclusions:
                continue
            
            # Prevent self-exclusion
            if perm_id == permission.id:
                raise InvalidOperationError("Permission cannot exclude itself")
            
            exclusive_perm = await self._permission_repository.find_by_id(perm_id)
            if not exclusive_perm:
                raise InvalidOperationError(f"Permission {perm_id} not found")
            
            permissions.append(exclusive_perm)
        
        return permissions
    
    async def _validate_exclusions_to_remove(
        self,
        permission: Permission,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate permissions to remove from exclusions."""
        permissions = []
        current_exclusions = set(permission.mutually_exclusive_with)
        
        for perm_id in permission_ids:
            if perm_id not in current_exclusions:
                continue  # Skip if not exclusive
            
            exclusive_perm = await self._permission_repository.find_by_id(perm_id)
            if exclusive_perm:
                permissions.append(exclusive_perm)
        
        return permissions
    
    async def _get_affected_entities(self, permission_id: UUID) -> dict[str, list[UUID]]:
        """Get all entities affected by permission update."""
        affected = {
            "users": [],
            "roles": []
        }
        
        # Get users with direct grants
        user_grants = await self._user_permission_repository.find_by_permission(permission_id)
        affected["users"] = [grant.user_id for grant in user_grants if grant.is_active]
        
        # Get roles with this permission
        roles = await self._role_repository.find_with_permission(permission_id)
        affected["roles"] = [role.id for role in roles]
        
        # Get users through roles
        for role_id in affected["roles"]:
            role_users = await self._authorization_service.get_users_with_role(role_id)
            affected["users"].extend(user.id for user in role_users)
        
        # Remove duplicates
        affected["users"] = list(set(affected["users"]))
        
        return affected
    
    async def _update_permission_indices(
        self,
        permission: Permission,
        original_state: dict[str, Any]
    ) -> None:
        """Update search indices for the permission."""
        # Update category index if changed
        if permission.category != original_state["category"]:
            await self._permission_repository.remove_from_category_index(
                original_state["category"],
                permission.id
            )
            await self._permission_repository.add_to_category_index(
                permission.category,
                permission.id
            )
        
        # Update tag indices if changed
        old_tags = set(original_state["tags"])
        new_tags = set(permission.tags)
        
        for tag in old_tags - new_tags:
            await self._permission_repository.remove_from_tag_index(tag, permission.id)
        
        for tag in new_tags - old_tags:
            await self._permission_repository.add_to_tag_index(tag, permission.id)
    
    def _requires_session_revocation(self, changes: dict[str, Any]) -> bool:
        """Check if changes require session revocation."""
        # Deactivation requires revocation
        if "is_active" in changes and changes["is_active"][1] is False:
            return True
        
        # Downgrading criticality
        if "is_critical" in changes and changes["is_critical"][0] and not changes["is_critical"][1]:
            return True
        
        # Major implication removals
        return changes.get("implies_removed", 0) > 3
    
    async def _revoke_affected_sessions(
        self,
        user_ids: list[UUID],
        permission: Permission,
        changes: dict[str, Any]
    ) -> int:
        """Revoke sessions for affected users."""
        sessions_revoked = 0
        reason = f"Permission '{permission.name}' updated - reauthentication required"
        
        for user_id in user_ids:
            sessions = await self._session_repository.find_active_by_user(user_id)
            for session in sessions:
                # Only revoke if user actually uses this permission
                if await self._session_uses_permission(session, permission):
                    await self._session_service.revoke_session(session.id, reason)
                    sessions_revoked += 1
        
        return sessions_revoked
    
    async def _session_uses_permission(self, session: Any, permission: Permission) -> bool:
        """Check if session actively uses the permission."""
        # This would check session activities for permission usage
        # For now, return True for critical permissions
        return permission.is_critical
    
    def _is_significant_change(self, changes: dict[str, Any]) -> bool:
        """Check if changes are significant enough to log."""
        significant_fields = [
            "is_active", "is_critical", "is_sensitive",
            "implies_added", "implies_removed",
            "exclusions_added", "exclusions_removed"
        ]
        
        return any(field in changes for field in significant_fields)
    
    async def _send_update_notifications(
        self,
        permission: Permission,
        changes: dict[str, Any],
        affected_entities: dict[str, list[UUID]],
        command: UpdatePermissionCommand
    ) -> None:
        """Send notifications to affected users."""
        # Prepare notification data
        notification_data = {
            "permission_name": permission.name,
            "changes_summary": self._summarize_changes(changes),
            "requires_action": "is_active" in changes and not changes["is_active"][1]
        }
        
        # Notify affected users
        if affected_entities["users"]:
            await self._notification_service.send_batch_notification(
                user_ids=affected_entities["users"],
                notification_type=NotificationType.PERMISSION_UPDATED,
                template_id="permission_updated",
                template_data=notification_data,
                priority="high" if notification_data["requires_action"] else "medium"
            )
        
        # Notify role administrators
        for role_id in affected_entities["roles"]:
            role = await self._role_repository.find_by_id(role_id)
            if role:
                await self._notification_service.notify_role_admins(
                    role_id,
                    "Permission Updated in Role",
                    {
                        "role_name": role.name,
                        "permission_name": permission.name,
                        "changes": self._summarize_changes(changes)
                    }
                )
    
    def _summarize_changes(self, changes: dict[str, Any]) -> str:
        """Create human-readable summary of changes."""
        summary_parts = []
        
        if "is_active" in changes and not changes["is_active"][1]:
            summary_parts.append("Permission deactivated")
        
        if "is_critical" in changes:
            if changes["is_critical"][1]:
                summary_parts.append("Marked as critical")
            else:
                summary_parts.append("No longer critical")
        
        if changes.get("implies_added", 0) > 0:
            summary_parts.append(f"{changes['implies_added']} implications added")
        
        if changes.get("implies_removed", 0) > 0:
            summary_parts.append(f"{changes['implies_removed']} implications removed")
        
        return ", ".join(summary_parts) if summary_parts else "Configuration updated"
    
    async def _log_significant_update(
        self,
        permission: Permission,
        original_state: dict[str, Any],
        changes: dict[str, Any],
        command: UpdatePermissionCommand
    ) -> None:
        """Log significant permission updates."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.PERMISSION_SIGNIFICANT_UPDATE,
                severity=RiskLevel.MEDIUM,
                user_id=command.updated_by,
                details={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "changes": changes,
                    "original_state": original_state,
                    "affected_entities": await self._get_affected_entities(permission.id)
                },
                indicators=["significant_permission_change"],
                recommended_actions=[
                    "Review permission changes",
                    "Monitor affected user activities"
                ]
            )
        )