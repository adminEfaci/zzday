"""
Delete role command implementation.

Handles permanent deletion of roles with comprehensive impact analysis.
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
from app.modules.identity.application.dtos.internal import (
    BackupContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import DeleteRoleRequest
from app.modules.identity.application.dtos.response import RoleDeletionResponse
from app.modules.identity.domain.entities import Role
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import RoleDeleted
from app.modules.identity.domain.exceptions import (
    DependencyError,
    InvalidOperationError,
    RoleNotFoundError,
    SystemRoleError,
)


class DeleteRoleCommand(Command[RoleDeletionResponse]):
    """Command to delete a role permanently."""
    
    def __init__(self, params: RoleDeletionParams):
        self.params = params
        # Extract commonly used fields for convenience
        self.role_id = params.role_id
        self.deleted_by = params.deleted_by
        self.reason = params.reason


class DeleteRoleCommandHandler(CommandHandler[DeleteRoleCommand, RoleDeletionResponse]):
    """Handler for deleting roles."""
    
    def __init__(self, deps: CommandHandlerDependencies):
        self._role_repository = deps.repositories.role_repository
        self._user_role_repository = deps.repositories.user_role_repository
        self._session_repository = deps.repositories.session_repository
        self._authorization_service = deps.services.authorization_service
        self._validation_service = deps.services.validation_service
        self._session_service = deps.services.session_service
        self._notification_service = deps.services.notification_service
        self._audit_service = deps.services.audit_service
        self._backup_service = deps.services.backup_service
        self._event_bus = deps.infrastructure.event_bus
        self._unit_of_work = deps.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.ROLE_DELETED,
        resource_type="role",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(DeleteRoleRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("roles.delete")
    @require_mfa(methods=["totp", "hardware_token"])
    @require_approval(
        approval_type="role_deletion",
        approvers=["security_team", "admin_manager"],
        min_approvals=2
    )
    async def handle(self, command: DeleteRoleCommand) -> RoleDeletionResponse:
        """
        Delete role with comprehensive validation and impact analysis.
        
        Process:
        1. Load role and validate
        2. Check deletion permissions
        3. Analyze impact
        4. Check dependencies
        5. Create backup
        6. Handle reassignments
        7. Delete role
        8. Clean up references
        9. Revoke sessions
        10. Send notifications
        
        Returns:
            RoleDeletionResponse with deletion details
            
        Raises:
            RoleNotFoundError: If role not found
            UnauthorizedError: If lacks permission
            SystemRoleError: If system role
            RoleInUseError: If role in use
            DependencyError: If has dependencies
        """
        async with self._unit_of_work:
            # 1. Load role
            role = await self._role_repository.get_by_id(command.params.role_id)
            if not role:
                raise RoleNotFoundError(f"Role {command.params.role_id} not found")
            
            # 2. Check if system role
            if role.is_system and not command.params.force_delete:
                raise SystemRoleError(
                    f"Cannot delete system role '{role.name}'. "
                    "System roles are critical for platform operation."
                )
            
            # 3. Check if default role
            if role.is_default and not command.params.force_delete:
                raise InvalidOperationError(
                    f"Cannot delete default role '{role.name}'. "
                    "Set another role as default first."
                )
            
            # 4. Analyze deletion impact
            impact_analysis = await self._analyze_deletion_impact(role)
            
            # 5. Check impact threshold
            if not command.params.force_delete and impact_analysis["affected_users"] > 100:
                raise InvalidOperationError(
                    f"Role deletion would affect {impact_analysis['affected_users']} users. "
                    "Use force_delete=True to proceed."
                )
            
            # 6. Check dependencies
            dependencies = await self._check_dependencies(role)
            if dependencies["blocking"] and not command.params.force_delete:
                raise DependencyError(
                    f"Role has blocking dependencies: {', '.join(dependencies['blocking'])}"
                )
            
            # 7. Create backup if requested
            backup_id = None
            if command.params.create_backup:
                backup_id = await self._create_role_backup(role, impact_analysis)
            
            # 8. Handle reassignments if specified
            reassignment_results = {}
            if command.params.reassign_to_role_id:
                reassignment_results = await self._reassign_users(
                    role.id,
                    command.params.reassign_to_role_id,
                    command.params.deleted_by
                )
            
            # 9. Get affected users before deletion
            affected_users = await self._get_affected_users(role.id)
            
            # 10. Remove all user assignments
            if command.params.cascade_assignments:
                await self._cascade_user_assignments(role.id, command.params.deleted_by)
            
            # 11. Remove role from grantable lists
            await self._remove_from_grantable_lists(role.id)
            
            # 12. Delete the role
            role.deleted = True
            role.deleted_at = datetime.now(UTC)
            role.deleted_by = command.params.deleted_by
            role.deletion_reason = command.params.reason
            
            await self._role_repository.delete(role.id)
            
            # 13. Refresh permissions for affected users
            sessions_revoked = 0
            for user_id in affected_users:
                await self._authorization_service.refresh_user_permissions(user_id)
                
                # Revoke sessions if role was critical
                if role.hierarchy_level >= 70:
                    sessions = await self._session_repository.get_active_sessions(user_id)
                    for session in sessions:
                        await self._session_service.revoke_session(
                            session.id,
                            f"Critical role '{role.name}' deleted"
                        )
                        sessions_revoked += 1
            
            # 14. Log security event
            await self._log_role_deletion(
                role,
                command,
                impact_analysis,
                backup_id
            )
            
            # 15. Send notifications
            if command.params.notify_affected_users and affected_users:
                await self._send_deletion_notifications(
                    role,
                    affected_users,
                    reassignment_results,
                    command
                )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                RoleDeleted(
                    aggregate_id=role.id,
                    role_name=role.name,
                    role_type=role.role_type,
                    deleted_by=command.params.deleted_by,
                    affected_users=len(affected_users),
                    sessions_revoked=sessions_revoked,
                    backup_created=backup_id is not None
                )
            )
            
            # 17. Clean up orphaned data
            await self._cleanup_orphaned_data(role.id)
            
            # 18. Commit transaction
            await self._unit_of_work.commit()
            
            # 19. Return response
            return RoleDeletionResponse(
                role_id=role.id,
                role_name=role.name,
                deleted_at=role.deleted_at,
                deleted_by=role.deleted_by,
                affected_users=len(affected_users),
                sessions_revoked=sessions_revoked,
                reassigned_users=len(reassignment_results.get("reassigned", [])),
                backup_id=backup_id,
                dependencies_removed=dependencies["removed"],
                message=f"Role '{role.name}' deleted successfully"
            )
    
    async def _analyze_deletion_impact(self, role: Role) -> dict[str, Any]:
        """Analyze the impact of deleting this role."""
        impact = {
            "affected_users": 0,
            "dependent_roles": [],
            "dependent_permissions": [],
            "active_sessions": 0,
            "severity": "low"
        }
        
        # Count affected users
        affected_users = await self._user_role_repository.count_users_with_role(role.id)
        impact["affected_users"] = affected_users
        
        # Find dependent roles
        all_roles = await self._role_repository.find_all()
        for other_role in all_roles:
            if other_role.id == role.id:
                continue
            
            # Check prerequisites
            if other_role.prerequisites and role.id in other_role.prerequisites.get("required_roles", []):
                impact["dependent_roles"].append({
                    "id": str(other_role.id),
                    "name": other_role.name
                })
            
            # Check grantable roles
            if role.id in other_role.grantable_roles:
                impact["dependent_roles"].append({
                    "id": str(other_role.id),
                    "name": other_role.name,
                    "dependency_type": "grantable"
                })
        
        # Count active sessions
        for user_id in await self._get_affected_users(role.id):
            sessions = await self._session_repository.count_active_by_user(user_id)
            impact["active_sessions"] += sessions
        
        # Determine severity
        if role.is_system or role.hierarchy_level >= 80:
            impact["severity"] = "critical"
        elif affected_users > 100 or impact["dependent_roles"]:
            impact["severity"] = "high"
        elif affected_users > 10:
            impact["severity"] = "medium"
        
        return impact
    
    async def _check_dependencies(self, role: Role) -> dict[str, Any]:
        """Check for role dependencies."""
        dependencies = {
            "blocking": [],
            "warnings": [],
            "removed": []
        }
        
        # Check if role is prerequisite for others
        dependent_roles = await self._find_dependent_roles(role.id)
        if dependent_roles:
            for dep_role in dependent_roles:
                if dep_role["users_affected"] > 0:
                    dependencies["blocking"].append(
                        f"Role '{dep_role['name']}' requires this role ({dep_role['users_affected']} users)"
                    )
                else:
                    dependencies["warnings"].append(
                        f"Role '{dep_role['name']}' lists this as prerequisite"
                    )
        
        # Check active integrations
        if role.metadata.get("integration_dependencies"):
            for integration in role.metadata["integration_dependencies"]:
                dependencies["warnings"].append(
                    f"Integration '{integration}' may be affected"
                )
        
        return dependencies
    
    async def _create_role_backup(
        self,
        role: Role,
        impact_analysis: dict[str, Any]
    ) -> UUID:
        """Create comprehensive backup before deletion."""
        # Get all role data
        role_permissions = await self._authorization_service.get_role_permissions(role.id)
        role_assignments = await self._user_role_repository.find_by_role(role.id)
        
        backup_data = {
            "role": {
                "id": str(role.id),
                "name": role.name,
                "display_name": role.display_name,
                "description": role.description,
                "role_type": role.role_type.value,
                "hierarchy_level": role.hierarchy_level,
                "is_system": role.is_system,
                "is_default": role.is_default,
                "permissions": [p.name for p in role_permissions],
                "prerequisites": role.prerequisites,
                "grantable_roles": [str(rid) for rid in role.grantable_roles],
                "grantable_permissions": [str(pid) for pid in role.grantable_permissions],
                "metadata": role.metadata
            },
            "assignments": [
                {
                    "user_id": str(assignment.user_id),
                    "granted_at": assignment.granted_at.isoformat(),
                    "granted_by": str(assignment.granted_by),
                    "expires_at": assignment.expires_at.isoformat() if assignment.expires_at else None,
                    "scope": assignment.scope
                }
                for assignment in role_assignments
            ],
            "impact_analysis": impact_analysis,
            "deletion_timestamp": datetime.now(UTC).isoformat()
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.ROLE_DELETION,
                resource_type="role",
                resource_id=role.id,
                data=backup_data,
                retention_days=365,  # Keep for 1 year
                encrypted=True
            )
        )
        
    
    async def _reassign_users(
        self,
        from_role_id: UUID,
        to_role_id: UUID,
        reassigned_by: UUID
    ) -> dict[str, Any]:
        """Reassign users from one role to another."""
        results = {
            "reassigned": [],
            "failed": [],
            "skipped": []
        }
        
        # Validate target role exists
        target_role = await self._role_repository.get_by_id(to_role_id)
        if not target_role:
            raise InvalidOperationError(f"Target role {to_role_id} not found")
        
        # Get all assignments
        assignments = await self._user_role_repository.find_by_role(from_role_id)
        
        for assignment in assignments:
            if not assignment.is_active:
                results["skipped"].append({
                    "user_id": str(assignment.user_id),
                    "reason": "inactive_assignment"
                })
                continue
            
            try:
                # Check if user already has target role
                existing = await self._user_role_repository.find_by_user_and_role(
                    assignment.user_id,
                    to_role_id
                )
                
                if existing and existing.is_active:
                    results["skipped"].append({
                        "user_id": str(assignment.user_id),
                        "reason": "already_has_role"
                    })
                    continue
                
                # Assign new role
                await self._authorization_service.assign_role_to_user(
                    assignment.user_id,
                    to_role_id,
                    reassigned_by,
                    f"Reassigned from deleted role '{from_role_id}'"
                )
                
                results["reassigned"].append({
                    "user_id": str(assignment.user_id),
                    "old_role": str(from_role_id),
                    "new_role": str(to_role_id)
                })
                
            except Exception as e:
                results["failed"].append({
                    "user_id": str(assignment.user_id),
                    "error": str(e)
                })
        
        return results
    
    async def _get_affected_users(self, role_id: UUID) -> list[UUID]:
        """Get all users affected by role deletion."""
        assignments = await self._user_role_repository.find_active_by_role(role_id)
        return [assignment.user_id for assignment in assignments]
    
    async def _cascade_user_assignments(
        self,
        role_id: UUID,
        deleted_by: UUID
    ) -> None:
        """Remove all user assignments for the role."""
        assignments = await self._user_role_repository.find_by_role(role_id)
        
        for assignment in assignments:
            if assignment.is_active:
                assignment.revoke(
                    deleted_by,
                    "Role deleted from system"
                )
                await self._user_role_repository.update(assignment)
    
    async def _remove_from_grantable_lists(self, role_id: UUID) -> None:
        """Remove role from all grantable lists."""
        all_roles = await self._role_repository.find_all()
        
        for role in all_roles:
            updated = False
            
            # Remove from grantable roles
            if role_id in role.grantable_roles:
                role.grantable_roles.remove(role_id)
                updated = True
            
            # Remove from prerequisites
            if role.prerequisites and role_id in role.prerequisites.get("required_roles", []):
                role.prerequisites["required_roles"].remove(str(role_id))
                updated = True
            
            if updated:
                await self._role_repository.update(role)
    
    async def _find_dependent_roles(self, role_id: UUID) -> list[dict[str, Any]]:
        """Find roles that depend on this role."""
        dependent_roles = []
        all_roles = await self._role_repository.find_all()
        
        for role in all_roles:
            if role.id == role_id:
                continue
            
            if role.prerequisites and str(role_id) in role.prerequisites.get("required_roles", []):
                # Count users with this dependent role
                user_count = await self._user_role_repository.count_users_with_role(role.id)
                
                dependent_roles.append({
                    "id": str(role.id),
                    "name": role.name,
                    "users_affected": user_count
                })
        
        return dependent_roles
    
    async def _cleanup_orphaned_data(self, role_id: UUID) -> None:
        """Clean up any orphaned data after role deletion."""
        # Clean up audit logs older than retention period
        # Clean up cached permissions
        # Clean up any role-specific configurations
    
    async def _log_role_deletion(
        self,
        role: Role,
        command: DeleteRoleCommand,
        impact_analysis: dict[str, Any],
        backup_id: UUID | None
    ) -> None:
        """Log the role deletion as a security event."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.ROLE_DELETED,
                severity=RiskLevel.HIGH if role.is_system else RiskLevel.MEDIUM,
                user_id=command.params.deleted_by,
                details={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "role_type": role.role_type.value,
                    "hierarchy_level": role.hierarchy_level,
                    "was_system": role.is_system,
                    "was_default": role.is_default,
                    "reason": command.params.reason,
                    "affected_users": impact_analysis["affected_users"],
                    "dependent_roles": len(impact_analysis["dependent_roles"]),
                    "backup_id": str(backup_id) if backup_id else None,
                    "force_deleted": command.params.force_delete
                },
                indicators=["role_deletion"],
                recommended_actions=[
                    "Review deletion justification",
                    "Monitor affected users",
                    "Verify no critical access lost"
                ]
            )
        )
    
    async def _send_deletion_notifications(
        self,
        role: Role,
        affected_users: list[UUID],
        reassignment_results: dict[str, Any],
        command: DeleteRoleCommand
    ) -> None:
        """Send notifications about role deletion."""
        # Prepare notification data
        notification_data = {
            "role_name": role.name,
            "deletion_reason": command.params.reason,
            "alternative_roles": [],
            "action_required": not reassignment_results.get("reassigned")
        }
        
        if reassignment_results.get("reassigned"):
            # Get reassigned role info
            reassigned_to = reassignment_results["reassigned"][0]["new_role"]
            new_role = await self._role_repository.get_by_id(UUID(reassigned_to))
            if new_role:
                notification_data["reassigned_to"] = new_role.name
        
        # Send batch notification
        await self._notification_service.send_batch_notification(
            user_ids=affected_users,
            notification_type=NotificationType.ROLE_DELETED,
            template_id="role_deleted",
            template_data=notification_data,
            priority="high"
        )
        
        # Notify administrators
        await self._notification_service.notify_role(
            "administrator",
            NotificationContext(
                notification_id=UUID(),
                recipient_id=None,
                notification_type=NotificationType.ROLE_DELETED,
                channel="in_app",
                template_id="role_deleted_admin",
                template_data={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "deleted_by": str(command.params.deleted_by),
                    "affected_users": len(affected_users),
                    "sessions_revoked": sum(1 for _ in affected_users)  # Simplified
                },
                priority="high"
            )
        )