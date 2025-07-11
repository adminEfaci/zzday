"""
Merge users command implementation.

Handles merging duplicate user accounts with data preservation.
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
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    MergeConflictResolution,
)
from app.modules.identity.application.dtos.request import MergeUsersRequest
from app.modules.identity.application.dtos.response import MergeUsersResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, UserStatus
from app.modules.identity.domain.events import UsersMerged
from app.modules.identity.domain.exceptions import (
    ConflictError,
    InvalidOperationError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
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
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import DataMigrationService, SecurityService


class MergeUsersCommand(Command[MergeUsersResponse]):
    """Command to merge user accounts."""
    
    def __init__(
        self,
        source_user_id: UUID,
        target_user_id: UUID,
        merge_strategy: str = 'keep_target',
        conflict_resolutions: dict[str, str] | None = None,
        keep_source_as_alias: bool = False,
        notify_users: bool = True,
        performed_by: UUID | None = None,
        reason: str | None = None
    ):
        self.source_user_id = source_user_id
        self.target_user_id = target_user_id
        self.merge_strategy = merge_strategy
        self.conflict_resolutions = conflict_resolutions or {}
        self.keep_source_as_alias = keep_source_as_alias
        self.notify_users = notify_users
        self.performed_by = performed_by
        self.reason = reason


class MergeUsersCommandHandler(CommandHandler[MergeUsersCommand, MergeUsersResponse]):
    """Handler for merging user accounts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        permission_repository: IPermissionRepository,
        role_repository: IRoleRepository,
        audit_repository: IAuditRepository,
        security_service: SecurityService,
        data_migration_service: DataMigrationService,
        email_service: IEmailService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._permission_repository = permission_repository
        self._role_repository = role_repository
        self._audit_repository = audit_repository
        self._security_service = security_service
        self._data_migration_service = data_migration_service
        self._email_service = email_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.USERS_MERGED,
        resource_type="user",
        resource_id_attr="target_user_id",
        include_request=True
    )
    @require_permission(
        permission="users.merge",
        resource_type="system"
    )
    @validate_request(MergeUsersRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: MergeUsersCommand) -> MergeUsersResponse:
        """
        Merge two user accounts.
        
        Process:
        1. Validate both users exist
        2. Check merge eligibility
        3. Detect conflicts
        4. Create merge plan
        5. Execute data migration
        6. Handle authentication data
        7. Update or deactivate source
        8. Send notifications
        9. Clear caches
        10. Publish event
        
        Returns:
            MergeUsersResponse with merge details
            
        Raises:
            UserNotFoundError: If either user not found
            InvalidOperationError: If merge not allowed
            ConflictError: If unresolved conflicts
        """
        async with self._unit_of_work:
            # 1. Load both users
            source_user = await self._user_repository.find_by_id(command.source_user_id)
            target_user = await self._user_repository.find_by_id(command.target_user_id)
            
            if not source_user:
                raise UserNotFoundError(f"Source user {command.source_user_id} not found")
            
            if not target_user:
                raise UserNotFoundError(f"Target user {command.target_user_id} not found")
            
            # 2. Validate merge eligibility
            await self._validate_merge_eligibility(source_user, target_user)
            
            # 3. Detect conflicts
            conflicts = await self._detect_conflicts(source_user, target_user)
            
            # 4. Resolve conflicts
            resolutions = await self._resolve_conflicts(
                conflicts=conflicts,
                strategy=command.merge_strategy,
                manual_resolutions=command.conflict_resolutions
            )
            
            # 5. Create merge plan
            merge_plan = await self._create_merge_plan(
                source_user=source_user,
                target_user=target_user,
                resolutions=resolutions
            )
            
            # 6. Execute merge
            merge_result = await self._execute_merge(
                plan=merge_plan,
                command=command
            )
            
            # 7. Handle source user
            if command.keep_source_as_alias:
                # Keep as alias
                source_user.status = UserStatus.MERGED
                source_user.merged_into = target_user.id
                source_user.merged_at = datetime.now(UTC)
                await self._user_repository.update(source_user)
            else:
                # Deactivate completely
                source_user.status = UserStatus.DEACTIVATED
                source_user.deactivated_at = datetime.now(UTC)
                source_user.deactivation_reason = f"Merged into user {target_user.id}"
                await self._user_repository.update(source_user)
            
            # 8. Update target user
            target_user.updated_at = datetime.now(UTC)
            if 'metadata' not in target_user.__dict__:
                target_user.metadata = {}
            target_user.metadata['merged_users'] = target_user.metadata.get('merged_users', [])
            target_user.metadata['merged_users'].append({
                'user_id': str(source_user.id),
                'username': source_user.username,
                'email': source_user.email,
                'merged_at': datetime.now(UTC).isoformat(),
                'merged_by': str(command.performed_by) if command.performed_by else None
            })
            await self._user_repository.update(target_user)
            
            # 9. Revoke source user sessions
            await self._revoke_all_sessions(source_user.id)
            
            # 10. Send notifications
            if command.notify_users:
                await self._send_merge_notifications(
                    source_user=source_user,
                    target_user=target_user,
                    merge_result=merge_result
                )
            
            # 11. Clear caches
            await self._clear_user_caches(source_user.id)
            await self._clear_user_caches(target_user.id)
            
            # 12. Log detailed merge info
            await self._log_merge_details(
                source_user=source_user,
                target_user=target_user,
                merge_result=merge_result,
                command=command
            )
            
            # 13. Publish event
            await self._event_bus.publish(
                UsersMerged(
                    aggregate_id=target_user.id,
                    source_user_id=source_user.id,
                    target_user_id=target_user.id,
                    data_migrated=merge_result['migrated_items'],
                    conflicts_resolved=len(resolutions),
                    performed_by=command.performed_by,
                    reason=command.reason
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return MergeUsersResponse(
                source_user_id=source_user.id,
                target_user_id=target_user.id,
                merged_data=merge_result['migrated_items'],
                conflicts_resolved=resolutions,
                source_status='alias' if command.keep_source_as_alias else 'deactivated',
                migration_summary=merge_result['summary'],
                success=True,
                message=f"Successfully merged user {source_user.username} into {target_user.username}"
            )
    
    async def _validate_merge_eligibility(
        self,
        source_user: User,
        target_user: User
    ) -> None:
        """Validate if users can be merged."""
        # Can't merge same user
        if source_user.id == target_user.id:
            raise InvalidOperationError("Cannot merge user with itself")
        
        # Can't merge if source is already merged
        if source_user.status == UserStatus.MERGED:
            raise InvalidOperationError(
                "Source user is already merged"
            )
        
        # Can't merge into deleted user
        if target_user.status == UserStatus.DELETED:
            raise InvalidOperationError(
                "Cannot merge into deleted user"
            )
        
        # Check if users are related (e.g., one created the other)
        if hasattr(source_user, 'created_by') and source_user.created_by == target_user.id:
            # Allow merging user into their creator
            pass
        elif hasattr(target_user, 'created_by') and target_user.created_by == source_user.id:
            # Warn about merging creator into created user
            pass
    
    async def _detect_conflicts(
        self,
        source_user: User,
        target_user: User
    ) -> dict[str, Any]:
        """Detect conflicts between users."""
        conflicts = {}
        
        # Email conflict
        if source_user.email and target_user.email:
            if source_user.email != target_user.email:
                conflicts['email'] = {
                    'source': source_user.email,
                    'target': target_user.email,
                    'type': 'different_values'
                }
        
        # Phone conflict
        if source_user.phone and target_user.phone:
            if source_user.phone != target_user.phone:
                conflicts['phone'] = {
                    'source': source_user.phone,
                    'target': target_user.phone,
                    'type': 'different_values'
                }
        
        # Username conflict (for alias)
        conflicts['username'] = {
            'source': source_user.username,
            'target': target_user.username,
            'type': 'unique_constraint'
        }
        
        # Role conflicts
        source_roles = await self._role_repository.find_by_user(source_user.id)
        target_roles = await self._role_repository.find_by_user(target_user.id)
        
        conflicting_roles = []
        for role in source_roles:
            if role.exclusive and any(r.id == role.id for r in target_roles):
                conflicting_roles.append(role.name)
        
        if conflicting_roles:
            conflicts['roles'] = {
                'type': 'exclusive_roles',
                'roles': conflicting_roles
            }
        
        return conflicts
    
    async def _resolve_conflicts(
        self,
        conflicts: dict[str, Any],
        strategy: str,
        manual_resolutions: dict[str, str]
    ) -> list[MergeConflictResolution]:
        """Resolve merge conflicts."""
        resolutions = []
        
        for field, conflict in conflicts.items():
            # Check manual resolution first
            if field in manual_resolutions:
                resolution = manual_resolutions[field]
            # Apply strategy
            elif strategy == 'keep_target':
                resolution = 'target'
            elif strategy == 'keep_source':
                resolution = 'source'
            elif strategy == 'keep_newer':
                # Would need to check timestamps
                resolution = 'target'  # Default to target
            else:
                # No automatic resolution
                raise ConflictError(
                    f"Unresolved conflict for field: {field}"
                )
            
            resolutions.append(
                MergeConflictResolution(
                    field=field,
                    source_value=conflict.get('source'),
                    target_value=conflict.get('target'),
                    resolution=resolution,
                    resolved_value=conflict.get(resolution)
                )
            )
        
        return resolutions
    
    async def _create_merge_plan(
        self,
        source_user: User,
        target_user: User,
        resolutions: list[MergeConflictResolution]
    ) -> dict[str, Any]:
        """Create detailed merge plan."""
        plan = {
            'source_user': source_user,
            'target_user': target_user,
            'resolutions': resolutions,
            'migrations': []
        }
        
        # Plan permission migration
        source_perms = await self._permission_repository.find_by_user(
            source_user.id
        )
        plan['migrations'].append({
            'type': 'permissions',
            'count': len(source_perms),
            'action': 'merge'
        })
        
        # Plan role migration
        source_roles = await self._role_repository.find_by_user(source_user.id)
        plan['migrations'].append({
            'type': 'roles',
            'count': len(source_roles),
            'action': 'merge'
        })
        
        # Plan session handling
        active_sessions = await self._session_repository.find_active_by_user(
            source_user.id
        )
        plan['migrations'].append({
            'type': 'sessions',
            'count': len(active_sessions),
            'action': 'revoke'
        })
        
        # Plan audit log migration
        audit_count = await self._audit_repository.count_user_logs(source_user.id)
        plan['migrations'].append({
            'type': 'audit_logs',
            'count': audit_count,
            'action': 'reassign'
        })
        
        return plan
    
    async def _execute_merge(
        self,
        plan: dict[str, Any],
        command: MergeUsersCommand
    ) -> dict[str, Any]:
        """Execute the merge plan."""
        result = {
            'migrated_items': {},
            'errors': [],
            'summary': {}
        }
        
        source_user = plan['source_user']
        target_user = plan['target_user']
        
        # Migrate permissions
        try:
            perm_count = await self._data_migration_service.migrate_permissions(
                from_user_id=source_user.id,
                to_user_id=target_user.id
            )
            result['migrated_items']['permissions'] = perm_count
        except Exception as e:
            result['errors'].append(f"Permission migration failed: {e!s}")
        
        # Migrate roles
        try:
            role_count = await self._data_migration_service.migrate_roles(
                from_user_id=source_user.id,
                to_user_id=target_user.id,
                skip_exclusive=True
            )
            result['migrated_items']['roles'] = role_count
        except Exception as e:
            result['errors'].append(f"Role migration failed: {e!s}")
        
        # Migrate audit logs
        try:
            audit_count = await self._data_migration_service.reassign_audit_logs(
                from_user_id=source_user.id,
                to_user_id=target_user.id
            )
            result['migrated_items']['audit_logs'] = audit_count
        except Exception as e:
            result['errors'].append(f"Audit log migration failed: {e!s}")
        
        # Create summary
        result['summary'] = {
            'total_items_migrated': sum(result['migrated_items'].values()),
            'errors_encountered': len(result['errors']),
            'merge_timestamp': datetime.now(UTC).isoformat()
        }
        
        return result
    
    async def _revoke_all_sessions(self, user_id: UUID) -> None:
        """Revoke all sessions for a user."""
        sessions = await self._session_repository.find_active_by_user(user_id)
        
        for session in sessions:
            session.revoke("User account merged")
            await self._session_repository.update(session)
    
    async def _send_merge_notifications(
        self,
        source_user: User,
        target_user: User,
        merge_result: dict[str, Any]
    ) -> None:
        """Send notifications about the merge."""
        # Notify source user (if email available)
        if source_user.email:
            await self._email_service.send_email(
                EmailContext(
                    recipient=source_user.email,
                    template="account_merged",
                    subject="Your account has been merged",
                    variables={
                        "source_username": source_user.username,
                        "target_username": target_user.username,
                        "target_email": target_user.email,
                        "support_url": "https://app.example.com/support"
                    },
                    priority="high"
                )
            )
        
        # Notify target user
        await self._email_service.send_email(
            EmailContext(
                recipient=target_user.email,
                template="account_merge_received",
                subject="Account merge completed",
                variables={
                    "target_username": target_user.username,
                    "source_username": source_user.username,
                    "items_migrated": merge_result['summary']['total_items_migrated']
                },
                priority="normal"
            )
        )
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear all caches for a user."""
        patterns = [
            f"user:{user_id}",
            f"user_*:{user_id}",
            f"*:{user_id}:*"
        ]
        
        for pattern in patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _log_merge_details(
        self,
        source_user: User,
        target_user: User,
        merge_result: dict[str, Any],
        command: MergeUsersCommand
    ) -> None:
        """Log detailed merge information."""
        await self._security_service.log_security_event(
            user_id=target_user.id,
            event_type="user_accounts_merged",
            details={
                "source_user_id": str(source_user.id),
                "source_username": source_user.username,
                "target_user_id": str(target_user.id),
                "target_username": target_user.username,
                "performed_by": str(command.performed_by) if command.performed_by else "system",
                "reason": command.reason,
                "items_migrated": merge_result['migrated_items'],
                "errors": merge_result['errors'],
                "keep_as_alias": command.keep_source_as_alias
            }
        )