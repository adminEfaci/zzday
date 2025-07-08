"""
Delete permission command implementation.

Handles permanent deletion of permissions with comprehensive impact analysis.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_approval,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CommandHandlerDependencies,
    PermissionDeletionParams,
)
from app.modules.identity.application.dtos.internal import (
    BackupContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import DeletePermissionRequest
from app.modules.identity.application.dtos.response import PermissionDeletionResponse
from app.modules.identity.domain.entities import Permission
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import PermissionDeleted
from app.modules.identity.domain.exceptions import (
    DependencyError,
    InvalidOperationError,
    PermissionNotFoundError,
    SystemPermissionError,
)


class DeletePermissionCommand(Command[PermissionDeletionResponse]):
    """Command to delete a permission permanently."""
    
    def __init__(self, params: PermissionDeletionParams):
        self.params = params
        # Initialize metadata if None
        self.params.metadata = params.metadata or {}


class DeletePermissionCommandHandler(CommandHandler[DeletePermissionCommand, PermissionDeletionResponse]):
    """Handler for deleting permissions."""
    
    def __init__(self, dependencies: CommandHandlerDependencies, **kwargs: Any):
        # Repository dependencies
        self._permission_repository = dependencies.repositories.permission_repository
        self._user_permission_repository = kwargs.get('user_permission_repository')
        self._role_repository = dependencies.repositories.role_repository
        self._session_repository = dependencies.repositories.session_repository
        
        # Service dependencies
        self._authorization_service = dependencies.services.authorization_service
        self._validation_service = dependencies.services.validation_service
        self._session_service = kwargs.get('session_service')
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._backup_service = kwargs.get('backup_service')
        
        # Infrastructure dependencies
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_DELETED,
        resource_type="permission",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(DeletePermissionRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("permissions.delete")
    @require_mfa(methods=["totp", "hardware_token"])
    @require_approval(
        approval_type="permission_deletion",
        approvers=["security_team", "compliance_team"],
        min_approvals=2
    )
    async def handle(self, command: DeletePermissionCommand) -> PermissionDeletionResponse:
        """
        Delete permission with comprehensive validation and impact analysis.
        
        Process:
        1. Load permission and validate
        2. Check deletion permissions
        3. Analyze impact
        4. Check dependencies
        5. Create backup
        6. Handle replacements
        7. Remove from roles
        8. Revoke user grants
        9. Delete permission
        10. Clean up references
        11. Refresh caches
        12. Send notifications
        
        Returns:
            PermissionDeletionResponse with deletion details
            
        Raises:
            PermissionNotFoundError: If permission not found
            UnauthorizedError: If lacks permission
            SystemPermissionError: If system permission
            PermissionInUseError: If permission in use
            DependencyError: If has dependencies
        """
        async with self._unit_of_work:
            # Load and validate permission
            permission = await self._validate_permission_for_deletion(command)
            
            # Analyze impact and check dependencies
            impact_analysis = await self._analyze_deletion_impact(permission)
            await self._validate_deletion_impact(impact_analysis, command.force_delete)
            
            dependencies = await self._check_dependencies(permission)
            self._validate_dependencies(dependencies, command.force_delete)
            
            # Create backup if requested
            backup_id = None
            if command.create_backup:
                backup_id = await self._create_permission_backup(permission, impact_analysis)
            
            # Handle pre-deletion tasks
            affected_entities, replacement_results = await self._handle_pre_deletion_tasks(
                permission,
                command
            )
            
            # Delete the permission
            await self._delete_permission(permission, command)
            
            # Handle post-deletion tasks
            sessions_revoked = await self._handle_post_deletion_tasks(
                permission,
                affected_entities,
                command
            )
            
            # Log and notify
            await self._log_permission_deletion(
                permission,
                command,
                impact_analysis,
                backup_id
            )
            
            if command.notify_affected and affected_entities["users"]:
                await self._send_deletion_notifications(
                    permission,
                    affected_entities,
                    replacement_results,
                    command
                )
            
            # 17. Publish domain event
            await self._event_bus.publish(
                PermissionDeleted(
                    aggregate_id=permission.id,
                    permission_name=permission.name,
                    resource_type=permission.resource_type,
                    action=permission.action,
                    deleted_by=command.deleted_by,
                    affected_users=len(affected_entities["users"]),
                    affected_roles=len(affected_entities["roles"]),
                    sessions_revoked=sessions_revoked,
                    backup_created=backup_id is not None
                )
            )
            
            # 18. Clean up orphaned data
            await self._cleanup_orphaned_data(permission.id)
            
            # 19. Commit transaction
            await self._unit_of_work.commit()
            
            # 20. Return response
            return PermissionDeletionResponse(
                permission_id=permission.id,
                permission_name=permission.name,
                deleted_at=permission.deleted_at,
                deleted_by=permission.deleted_by,
                affected_users=len(affected_entities["users"]),
                affected_roles=len(affected_entities["roles"]),
                grants_revoked=impact_analysis["direct_grants"],
                sessions_revoked=sessions_revoked,
                replaced_with=command.replace_with_permission_id,
                backup_id=backup_id,
                dependencies_removed=dependencies["removed"],
                message=f"Permission '{permission.name}' deleted successfully"
            )
    
    async def _analyze_deletion_impact(self, permission: Permission) -> dict[str, Any]:
        """Analyze the impact of deleting this permission."""
        impact = {
            "direct_grants": 0,
            "role_assignments": 0,
            "affected_users": set(),
            "affected_roles": [],
            "dependent_permissions": [],
            "implied_by": [],
            "excluded_by": [],
            "severity": "low",
            "total_affected": 0
        }
        
        # Count direct user grants
        user_grants = await self._user_permission_repository.find_by_permission(permission.id)
        impact["direct_grants"] = len(user_grants)
        impact["affected_users"].update(grant.user_id for grant in user_grants)
        
        # Find roles with this permission
        roles_with_permission = await self._role_repository.find_with_permission(permission.id)
        impact["affected_roles"] = [
            {"id": str(role.id), "name": role.name}
            for role in roles_with_permission
        ]
        
        # Count users affected through roles
        for role in roles_with_permission:
            role_users = await self._authorization_service.get_users_with_role(role.id)
            impact["affected_users"].update(user.id for user in role_users)
        
        # Find permissions that imply this one
        all_permissions = await self._permission_repository.find_all()
        for other_perm in all_permissions:
            if permission.id in other_perm.implies:
                impact["implied_by"].append({
                    "id": str(other_perm.id),
                    "name": other_perm.name
                })
            
            if permission.id in other_perm.mutually_exclusive_with:
                impact["excluded_by"].append({
                    "id": str(other_perm.id),
                    "name": other_perm.name
                })
        
        # Determine severity
        if permission.is_system or permission.is_critical:
            impact["severity"] = "critical"
        elif len(impact["affected_users"]) > 100 or impact["affected_roles"]:
            impact["severity"] = "high"
        elif len(impact["affected_users"]) > 10:
            impact["severity"] = "medium"
        
        impact["total_affected"] = len(impact["affected_users"])
        impact["affected_users"] = list(impact["affected_users"])  # Convert set to list
        
        return impact
    
    async def _check_dependencies(self, permission: Permission) -> dict[str, Any]:
        """Check for permission dependencies."""
        dependencies = {
            "blocking": [],
            "warnings": [],
            "removed": []
        }
        
        # Check if permission is prerequisite for others
        all_permissions = await self._permission_repository.find_all()
        for other_perm in all_permissions:
            if not other_perm.prerequisites:
                continue
            
            required_perms = other_perm.prerequisites.get("required_permissions", [])
            if permission.name in required_perms:
                # Count users with the dependent permission
                grants = await self._user_permission_repository.count_by_permission(other_perm.id)
                if grants > 0:
                    dependencies["blocking"].append(
                        f"Permission '{other_perm.name}' requires this ({grants} users)"
                    )
                else:
                    dependencies["warnings"].append(
                        f"Permission '{other_perm.name}' lists this as prerequisite"
                    )
        
        # Check if roles require this permission
        all_roles = await self._role_repository.find_all()
        for role in all_roles:
            if not role.prerequisites:
                continue
            
            required_perms = role.prerequisites.get("required_permissions", [])
            if permission.name in required_perms:
                dependencies["warnings"].append(
                    f"Role '{role.name}' requires this permission"
                )
        
        return dependencies
    
    async def _create_permission_backup(
        self,
        permission: Permission,
        impact_analysis: dict[str, Any]
    ) -> UUID:
        """Create comprehensive backup before deletion."""
        # Get all permission data
        user_grants = await self._user_permission_repository.find_by_permission(permission.id)
        roles_with_permission = await self._role_repository.find_with_permission(permission.id)
        
        backup_data = {
            "permission": {
                "id": str(permission.id),
                "name": permission.name,
                "display_name": permission.display_name,
                "description": permission.description,
                "resource_type": permission.resource_type,
                "action": permission.action,
                "type": permission.type.value,
                "scope": permission.scope.value,
                "is_system": permission.is_system,
                "is_critical": permission.is_critical,
                "is_sensitive": permission.is_sensitive,
                "category": permission.category,
                "tags": permission.tags,
                "prerequisites": permission.prerequisites,
                "implies": [str(pid) for pid in permission.implies],
                "mutually_exclusive_with": [str(pid) for pid in permission.mutually_exclusive_with],
                "conditions": permission.conditions,
                "metadata": permission.metadata
            },
            "user_grants": [
                {
                    "user_id": str(grant.user_id),
                    "granted_at": grant.granted_at.isoformat(),
                    "granted_by": str(grant.granted_by),
                    "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
                    "resource_type": grant.resource_type,
                    "resource_id": str(grant.resource_id) if grant.resource_id else None,
                    "conditions": grant.conditions
                }
                for grant in user_grants
            ],
            "roles": [
                {
                    "role_id": str(role.id),
                    "role_name": role.name
                }
                for role in roles_with_permission
            ],
            "impact_analysis": impact_analysis,
            "deletion_timestamp": datetime.now(UTC).isoformat()
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.PERMISSION_DELETION,
                resource_type="permission",
                resource_id=permission.id,
                data=backup_data,
                retention_days=365,  # Keep for 1 year
                encrypted=True
            )
        )
        
    
    async def _replace_permission(
        self,
        from_permission_id: UUID,
        to_permission_id: UUID,
        replaced_by: UUID
    ) -> dict[str, Any]:
        """Replace one permission with another."""
        results = {
            "grants_replaced": 0,
            "roles_updated": 0,
            "failed": []
        }
        
        # Validate target permission exists
        target_permission = await self._permission_repository.get_by_id(to_permission_id)
        if not target_permission:
            raise InvalidOperationError(f"Target permission {to_permission_id} not found")
        
        # Replace user grants
        user_grants = await self._user_permission_repository.find_by_permission(from_permission_id)
        for grant in user_grants:
            if not grant.is_active:
                continue
            
            try:
                # Check if user already has target permission
                existing = await self._user_permission_repository.find_by_user_and_permission(
                    grant.user_id,
                    to_permission_id,
                    grant.resource_type,
                    grant.resource_id
                )
                
                if not existing or not existing.is_active:
                    # Grant new permission
                    await self._authorization_service.grant_permission_to_user(
                        grant.user_id,
                        to_permission_id,
                        replaced_by,
                        f"Replaced from deleted permission '{from_permission_id}'"
                    )
                    results["grants_replaced"] += 1
                
            except Exception as e:
                results["failed"].append({
                    "user_id": str(grant.user_id),
                    "error": str(e)
                })
        
        # Replace in roles
        roles_with_permission = await self._role_repository.find_with_permission(from_permission_id)
        for role in roles_with_permission:
            try:
                # Remove old permission
                permissions = list(role.permissions)
                permissions.remove(from_permission_id)
                
                # Add new permission if not already present
                if to_permission_id not in permissions:
                    permissions.append(to_permission_id)
                
                role.set_permissions(permissions)
                await self._role_repository.update(role)
                results["roles_updated"] += 1
                
            except Exception as e:
                results["failed"].append({
                    "role_id": str(role.id),
                    "error": str(e)
                })
        
        return results
    
    async def _get_affected_entities(self, permission_id: UUID) -> dict[str, list[UUID]]:
        """Get all entities affected by permission deletion."""
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
    
    async def _remove_from_roles(self, permission_id: UUID) -> None:
        """Remove permission from all roles."""
        roles_with_permission = await self._role_repository.find_with_permission(permission_id)
        
        for role in roles_with_permission:
            # Remove permission
            permissions = list(role.permissions)
            permissions.remove(permission_id)
            role.set_permissions(permissions)
            
            # Remove from grantable permissions if present
            if permission_id in role.grantable_permissions:
                role.grantable_permissions.remove(permission_id)
            
            await self._role_repository.update(role)
    
    async def _cascade_user_grants(
        self,
        permission_id: UUID,
        deleted_by: UUID
    ) -> None:
        """Revoke all user grants for the permission."""
        user_grants = await self._user_permission_repository.find_by_permission(permission_id)
        
        for grant in user_grants:
            if grant.is_active:
                grant.revoke(
                    deleted_by,
                    "Permission deleted from system"
                )
                await self._user_permission_repository.update(grant)
    
    async def _remove_from_permission_relationships(self, permission_id: UUID) -> None:
        """Remove permission from all implications and exclusions."""
        all_permissions = await self._permission_repository.find_all()
        
        for perm in all_permissions:
            updated = False
            
            # Remove from implications
            if permission_id in perm.implies:
                perm.implies.remove(permission_id)
                updated = True
            
            # Remove from exclusions
            if permission_id in perm.mutually_exclusive_with:
                perm.mutually_exclusive_with.remove(permission_id)
                updated = True
            
            if updated:
                await self._permission_repository.update(perm)
    
    async def _cleanup_orphaned_data(self, permission_id: UUID) -> None:
        """Clean up any orphaned data after permission deletion."""
        # Clean up audit logs older than retention period
        # Clean up cached permissions
        # Clean up any permission-specific configurations
    
    async def _log_permission_deletion(
        self,
        permission: Permission,
        command: DeletePermissionCommand,
        impact_analysis: dict[str, Any],
        backup_id: UUID | None
    ) -> None:
        """Log the permission deletion as a security event."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.PERMISSION_DELETED,
                severity=RiskLevel.HIGH if permission.is_system else RiskLevel.MEDIUM,
                user_id=command.deleted_by,
                details={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "resource_type": permission.resource_type,
                    "action": permission.action,
                    "was_system": permission.is_system,
                    "was_critical": permission.is_critical,
                    "reason": command.reason,
                    "affected_users": impact_analysis["affected_users"],
                    "affected_roles": len(impact_analysis["affected_roles"]),
                    "backup_id": str(backup_id) if backup_id else None,
                    "force_deleted": command.force_delete
                },
                indicators=["permission_deletion"],
                recommended_actions=[
                    "Review deletion justification",
                    "Monitor affected users",
                    "Verify no critical access lost"
                ]
            )
        )
    
    async def _send_deletion_notifications(
        self,
        permission: Permission,
        affected_entities: dict[str, list[UUID]],
        replacement_results: dict[str, Any],
        command: DeletePermissionCommand
    ) -> None:
        """Send notifications about permission deletion."""
        # Prepare notification data
        notification_data = {
            "permission_name": permission.name,
            "deletion_reason": command.reason,
            "action_required": not replacement_results.get("grants_replaced")
        }
        
        if replacement_results.get("grants_replaced"):
            # Get replacement permission info
            replacement_permission = await self._permission_repository.get_by_id(
                command.replace_with_permission_id
            )
            if replacement_permission:
                notification_data["replaced_with"] = replacement_permission.name
        
        # Send batch notification to affected users
        if affected_entities["users"]:
            await self._notification_service.send_batch_notification(
                user_ids=affected_entities["users"],
                notification_type=NotificationType.PERMISSION_DELETED,
                template_id="permission_deleted",
                template_data=notification_data,
                priority="high"
            )
        
        # Notify role administrators
        for role_id in affected_entities["roles"]:
            await self._notification_service.notify_role_admins(
                role_id,
                "Permission Removed from Role",
                {
                    "permission_name": permission.name,
                    "deletion_reason": command.reason,
                    "replaced_with": notification_data.get("replaced_with")
                }
            )
        
        # Notify security team
        if permission.is_critical or permission.is_system:
            await self._notification_service.notify_security_team(
                "Critical Permission Deleted",
                {
                    "permission_name": permission.name,
                    "deleted_by": str(command.deleted_by),
                    "affected_users": len(affected_entities["users"]),
                    "affected_roles": len(affected_entities["roles"])
                }
            )
    
    async def _validate_permission_for_deletion(
        self,
        command: DeletePermissionCommand
    ) -> Permission:
        """Validate permission exists and can be deleted."""
        permission = await self._permission_repository.get_by_id(command.permission_id)
        if not permission:
            raise PermissionNotFoundError(f"Permission {command.permission_id} not found")
        
        if permission.is_system and not command.force_delete:
            raise SystemPermissionError(
                f"Cannot delete system permission '{permission.name}'. "
                "System permissions are required for platform operation."
            )
        
        if permission.is_critical and not command.force_delete:
            raise InvalidOperationError(
                f"Cannot delete critical permission '{permission.name}'. "
                "Use force_delete=True to proceed."
            )
        
        return permission
    
    def _validate_deletion_impact(
        self,
        impact_analysis: dict[str, Any],
        force_delete: bool
    ) -> None:
        """Validate deletion impact is acceptable."""
        if not force_delete and impact_analysis["total_affected"] > 100:
            raise InvalidOperationError(
                f"Permission deletion would affect {impact_analysis['total_affected']} entities. "
                "Use force_delete=True to proceed."
            )
    
    def _validate_dependencies(
        self,
        dependencies: dict[str, Any],
        force_delete: bool
    ) -> None:
        """Validate dependencies allow deletion."""
        if dependencies["blocking"] and not force_delete:
            raise DependencyError(
                f"Permission has blocking dependencies: {', '.join(dependencies['blocking'])}"
            )
    
    async def _handle_pre_deletion_tasks(
        self,
        permission: Permission,
        command: DeletePermissionCommand
    ) -> tuple[dict[str, list[UUID]], dict[str, Any]]:
        """Handle all pre-deletion tasks."""
        # Get affected entities
        affected_entities = await self._get_affected_entities(permission.id)
        
        # Handle replacement if specified
        replacement_results = {}
        if command.replace_with_permission_id:
            replacement_results = await self._replace_permission(
                permission.id,
                command.replace_with_permission_id,
                command.deleted_by
            )
        
        # Remove from roles
        if command.remove_from_roles:
            await self._remove_from_roles(permission.id)
        
        # Revoke user grants
        if command.cascade_grants:
            await self._cascade_user_grants(permission.id, command.deleted_by)
        
        # Remove from implications and exclusions
        await self._remove_from_permission_relationships(permission.id)
        
        return affected_entities, replacement_results
    
    async def _delete_permission(
        self,
        permission: Permission,
        command: DeletePermissionCommand
    ) -> None:
        """Delete the permission."""
        permission.deleted = True
        permission.deleted_at = datetime.now(UTC)
        permission.deleted_by = command.deleted_by
        permission.deletion_reason = command.reason
        
        await self._permission_repository.delete(permission.id)
    
    async def _handle_post_deletion_tasks(
        self,
        permission: Permission,
        affected_entities: dict[str, list[UUID]],
        command: DeletePermissionCommand
    ) -> int:
        """Handle all post-deletion tasks."""
        sessions_revoked = 0
        
        for user_id in affected_entities["users"]:
            await self._authorization_service.refresh_user_permissions(user_id)
            
            # Revoke sessions if critical permission
            if permission.is_critical:
                sessions = await self._session_repository.get_active_sessions(user_id)
                for session in sessions:
                    await self._session_service.revoke_session(
                        session.id,
                        f"Critical permission '{permission.name}' deleted"
                    )
                    sessions_revoked += 1
        
        return sessions_revoked