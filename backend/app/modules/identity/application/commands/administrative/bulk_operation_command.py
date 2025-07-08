"""
Bulk operation command implementation.

Handles batch operations on multiple users with progress tracking and rollback support.
"""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import Enum
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
from app.modules.identity.application.dtos.administrative import (
    BulkOperationConfig,
    InfrastructureDependencies,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    BulkOperationContext,
    OperationResult,
    OperationStatus,
)
from app.modules.identity.application.dtos.request import BulkOperationRequest
from app.modules.identity.application.dtos.response import BulkOperationResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, NotificationType, UserStatus
from app.modules.identity.domain.events import (
    BulkOperationCompleted,
    BulkOperationFailed,
    BulkOperationStarted,
)
from app.modules.identity.domain.exceptions import (
    BulkOperationError,
    InvalidOperationError,
    UnauthorizedError,
    ValidationError,
)


class BulkOperationType(Enum):
    """Types of bulk operations."""
    ACTIVATE_USERS = "activate_users"
    DEACTIVATE_USERS = "deactivate_users"
    SUSPEND_USERS = "suspend_users"
    DELETE_USERS = "delete_users"
    RESET_PASSWORDS = "reset_passwords"
    FORCE_MFA = "force_mfa"
    ASSIGN_ROLE = "assign_role"
    REMOVE_ROLE = "remove_role"
    UPDATE_ATTRIBUTE = "update_attribute"
    SEND_NOTIFICATION = "send_notification"
    EXPORT_DATA = "export_data"
    LOCK_ACCOUNTS = "lock_accounts"


class BulkOperationCommand(Command[BulkOperationResponse]):
    """Command to perform bulk operations on users."""

    def __init__(
        self,
        admin_user_id: UUID,
        bulk_config: BulkOperationConfig
    ):
        self.admin_user_id = admin_user_id
        self.bulk_config = bulk_config
        
        # For backward compatibility, expose common fields
        self.operation_type = BulkOperationType(bulk_config.operation_type)
        self.target_user_ids = bulk_config.target_user_ids
        self.parameters = bulk_config.parameters
        self.reason = bulk_config.reason
        self.dry_run = bulk_config.dry_run
        self.batch_size = min(bulk_config.batch_size, 1000)  # Max batch size
        self.parallel_execution = bulk_config.parallel_execution
        self.stop_on_error = bulk_config.stop_on_error
        self.rollback_on_failure = bulk_config.rollback_on_failure
        self.notify_affected_users = bulk_config.notify_affected_users
        self.schedule_at = bulk_config.schedule_at
        self.metadata = bulk_config.metadata


class BulkOperationCommandHandler(
    CommandHandler[BulkOperationCommand, BulkOperationResponse]
):
    """Handler for bulk operations."""

    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._validation_service = services.validation_service
        self._email_service = services.email_service
        self._notification_service = services.notification_service
        # Note: using audit_repository from services
        self._audit_service = services.audit_repository
        self._cache_service = services.cache_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work

        # Operation handlers mapping
        self._operation_handlers = {
            BulkOperationType.ACTIVATE_USERS: self._activate_users,
            BulkOperationType.DEACTIVATE_USERS: self._deactivate_users,
            BulkOperationType.SUSPEND_USERS: self._suspend_users,
            BulkOperationType.DELETE_USERS: self._delete_users,
            BulkOperationType.RESET_PASSWORDS: self._reset_passwords,
            BulkOperationType.FORCE_MFA: self._force_mfa,
            BulkOperationType.ASSIGN_ROLE: self._assign_role,
            BulkOperationType.REMOVE_ROLE: self._remove_role,
            BulkOperationType.UPDATE_ATTRIBUTE: self._update_attribute,
            BulkOperationType.SEND_NOTIFICATION: self._send_notification,
            BulkOperationType.LOCK_ACCOUNTS: self._lock_accounts
        }

    @audit_action(
        action=AuditAction.BULK_OPERATION,
        resource_type="user",
        include_request=True,
        include_response=True,
        high_priority=True
    )
    @validate_request(BulkOperationRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "users.bulk_operations",
        resource_type="system"
    )
    @require_mfa()
    @require_approval(
        approval_type="bulk_operation",
        threshold=100  # Require approval for >100 users
    )
    async def handle(self, command: BulkOperationCommand) -> BulkOperationResponse:
        """
        Execute bulk operation with comprehensive controls.

        Process:
        1. Validate operation type and parameters
        2. Check permissions for all targets
        3. Create operation context
        4. Execute in batches
        5. Track progress
        6. Handle errors and rollback
        7. Send notifications
        8. Generate report

        Returns:
            BulkOperationResponse with results

        Raises:
            InvalidOperationError: If operation invalid
            UnauthorizedError: If lacks permission
            BulkOperationError: If operation fails
        """
        # 1. Schedule if requested
        if command.schedule_at and command.schedule_at > datetime.now(UTC):
            return await self._schedule_operation(command)

        # 2. Validate operation
        if command.operation_type not in self._operation_handlers:
            raise InvalidOperationError(
                f"Unsupported operation type: {command.operation_type.value}"
            )

        # 3. Create operation context
        operation_id = UUID()
        context = BulkOperationContext(
            operation_id=operation_id,
            operation_type=command.operation_type.value,
            target_ids=command.target_user_ids,
            parameters=command.parameters,
            actor_id=command.admin_user_id,
            reason=command.reason,
            dry_run=command.dry_run,
            batch_size=command.batch_size,
            parallel=command.parallel_execution,
            stop_on_error=command.stop_on_error
        )

        # 4. Initialize tracking
        results = {
            "successful": [],
            "failed": [],
            "skipped": [],
            "errors": []
        }

        start_time = datetime.now(UTC)
        processed_count = 0
        rollback_performed = False

        try:
            # 5. Publish start event
            await self._event_bus.publish(
                BulkOperationStarted(
                    operation_id=operation_id,
                    operation_type=command.operation_type.value,
                    total_targets=len(command.target_user_ids),
                    initiated_by=command.admin_user_id,
                    dry_run=command.dry_run
                )
            )

            # 6. Pre-validate all targets
            if not command.dry_run:
                await self._pre_validate_targets(command)

            # 7. Process in batches
            handler = self._operation_handlers[command.operation_type]

            for batch_start in range(
                0, len(command.target_user_ids), command.batch_size
            ):
                batch_end = min(
                    batch_start + command.batch_size,
                    len(command.target_user_ids)
                )
                batch_ids = command.target_user_ids[batch_start:batch_end]

                # Update progress
                await self._update_progress(
                    operation_id,
                    processed_count,
                    len(command.target_user_ids)
                )

                # Process batch
                if command.parallel_execution and not command.dry_run:
                    batch_results = await self._process_batch_parallel(
                        handler,
                        batch_ids,
                        command,
                        context
                    )
                else:
                    batch_results = await self._process_batch_sequential(
                        handler,
                        batch_ids,
                        command,
                        context
                    )

                # Aggregate results
                results["successful"].extend(batch_results["successful"])
                results["failed"].extend(batch_results["failed"])
                results["skipped"].extend(batch_results["skipped"])
                results["errors"].extend(batch_results["errors"])

                processed_count += len(batch_ids)

                # Check stop condition
                if command.stop_on_error and batch_results["failed"]:
                    break

            # 8. Handle rollback if needed
            if command.rollback_on_failure and results["failed"]:
                if not command.dry_run:
                    await self._rollback_operation(
                        operation_id,
                        results["successful"],
                        command
                    )
                rollback_performed = True
            else:
                rollback_performed = False

            # 9. Send notifications
            if command.notify_affected_users and not command.dry_run:
                await self._send_bulk_notifications(
                    results["successful"],
                    command.operation_type,
                    command.reason
                )

            # 10. Generate summary
            end_time = datetime.now(UTC)
            duration_ms = int((end_time - start_time).total_seconds() * 1000)

            operation_result = OperationResult(
                status=(
                    OperationStatus.COMPLETED if not results["failed"]
                    else OperationStatus.PARTIALLY_COMPLETED
                ),
                success_count=len(results["successful"]),
                failure_count=len(results["failed"]),
                skipped_count=len(results["skipped"]),
                errors=results["errors"],
                duration_ms=duration_ms,
                metadata={
                    "operation_type": command.operation_type.value,
                    "dry_run": command.dry_run,
                    "rollback_performed": rollback_performed
                }
            )
            
            # 11. Publish completion event
            await self._event_bus.publish(
                BulkOperationCompleted(
                    operation_id=operation_id,
                    operation_type=command.operation_type.value,
                    total_processed=processed_count,
                    successful_count=len(results["successful"]),
                    failed_count=len(results["failed"]),
                    duration_ms=duration_ms
                )
            )
            
            # 12. Clear progress cache
            await self._cache_service.delete(f"bulk_op_progress:{operation_id}")
            
            # 13. Create downloadable report
            report_url = await self._generate_operation_report(
                operation_id,
                command,
                results,
                operation_result
            )
            
            return BulkOperationResponse(
                operation_id=operation_id,
                operation_type=command.operation_type.value,
                total_items=len(command.target_user_ids),
                successful=operation_result.success_count,
                failed=operation_result.failure_count,
                skipped=operation_result.skipped_count,
                results=[
                    {
                        "user_id": str(uid),
                        "status": "success",
                        "details": {}
                    } for uid in results["successful"]
                ] + [
                    {
                        "user_id": str(item["user_id"]),
                        "status": "failed",
                        "error": item["error"]
                    } for item in results["failed"]
                ],
                errors=results["errors"],
                completed_at=end_time,
                report_url=report_url,
                message=(
                    f"Bulk operation completed: {operation_result.success_count} "
                    f"successful, "
                    f"{operation_result.failure_count} failed, "
                    f"{operation_result.skipped_count} skipped"
                )
            )
            
        except Exception as e:
            # Publish failure event
            await self._event_bus.publish(
                BulkOperationFailed(
                    operation_id=operation_id,
                    operation_type=command.operation_type.value,
                    error=str(e),
                    processed_count=processed_count
                )
            )
            
            # Clear progress cache
            await self._cache_service.delete(f"bulk_op_progress:{operation_id}")
            
            raise BulkOperationError(
                f"Bulk operation failed: {e!s}",
                operation_id=operation_id,
                processed=processed_count,
                results=results
            ) from e
    
    async def _pre_validate_targets(self, command: BulkOperationCommand) -> None:
        """Pre-validate all target users."""
        # Check if admin can modify all targets
        admin_user = await self._user_repository.get_by_id(command.admin_user_id)
        
        # Load users in batches for validation
        for batch_start in range(0, len(command.target_user_ids), 100):
            batch_end = min(batch_start + 100, len(command.target_user_ids))
            batch_ids = command.target_user_ids[batch_start:batch_end]
            
            users = await self._user_repository.get_many_by_ids(batch_ids)
            
            for user in users:
                # Check hierarchy
                if not await self._can_modify_user(admin_user, user):
                    raise UnauthorizedError(
                        f"Cannot modify user {user.username} - insufficient privileges"
                    )
                
                # Check operation-specific validations
                if (
                    command.operation_type == BulkOperationType.DELETE_USERS
                    and user.id == command.admin_user_id
                ):
                    raise InvalidOperationError("Cannot delete your own account")
    
    async def _process_batch_sequential(
        self,
        handler: Callable,
        user_ids: list[UUID],
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> dict[str, list]:
        """Process batch sequentially."""
        results = {
            "successful": [],
            "failed": [],
            "skipped": [],
            "errors": []
        }
        
        for user_id in user_ids:
            try:
                # Load user
                user = await self._user_repository.get_by_id(user_id)
                if not user:
                    results["skipped"].append(user_id)
                    continue
                
                # Execute operation
                if command.dry_run:
                    # Simulate operation
                    if await self._validate_operation(user, command):
                        results["successful"].append(user_id)
                    else:
                        results["failed"].append({
                            "user_id": user_id,
                            "error": "Validation failed"
                        })
                else:
                    # Real execution
                    await handler(user, command, context)
                    results["successful"].append(user_id)
                    
            except Exception as e:
                results["failed"].append({
                    "user_id": user_id,
                    "error": str(e)
                })
                results["errors"].append({
                    "user_id": str(user_id),
                    "error": str(e),
                    "timestamp": datetime.now(UTC).isoformat()
                })
                
                if command.stop_on_error:
                    break
        
        return results
    
    async def _process_batch_parallel(
        self,
        handler: Callable,
        user_ids: list[UUID],
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> dict[str, list]:
        """Process batch in parallel."""
        results = {
            "successful": [],
            "failed": [],
            "skipped": [],
            "errors": []
        }
        
        # Create tasks
        tasks = []
        for user_id in user_ids:
            task = self._process_single_user(
                handler,
                user_id,
                command,
                context
            )
            tasks.append(task)
        
        # Execute in parallel
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        for user_id, result in zip(user_ids, task_results, strict=False):
            if isinstance(result, Exception):
                results["failed"].append({
                    "user_id": user_id,
                    "error": str(result)
                })
                results["errors"].append({
                    "user_id": str(user_id),
                    "error": str(result),
                    "timestamp": datetime.now(UTC).isoformat()
                })
            elif result == "skipped":
                results["skipped"].append(user_id)
            elif result == "success":
                results["successful"].append(user_id)
            else:
                results["failed"].append({
                    "user_id": user_id,
                    "error": "Unknown result"
                })
        
        return results
    
    async def _process_single_user(
        self,
        handler: Callable,
        user_id: UUID,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> str:
        """Process single user (for parallel execution)."""
        try:
            user = await self._user_repository.get_by_id(user_id)
            if not user:
                return "skipped"
            
            await handler(user, command, context)
        except Exception:
            raise
        else:
            return "success"
    
    # Operation handlers
    async def _activate_users(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Activate user accounts."""
        if user.status == UserStatus.ACTIVE:
            return  # Already active
        
        if user.status not in [UserStatus.DEACTIVATED, UserStatus.SUSPENDED]:
            raise InvalidOperationError(
                f"Cannot activate user with status: {user.status.value}"
            )
        
        user.update_status(UserStatus.ACTIVE, command.reason, command.admin_user_id)
        await self._user_repository.update(user)
    
    async def _deactivate_users(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Deactivate user accounts."""
        if user.status == UserStatus.DEACTIVATED:
            return  # Already deactivated
        
        if user.status != UserStatus.ACTIVE:
            raise InvalidOperationError(
                f"Cannot deactivate user with status: {user.status.value}"
            )
        
        user.update_status(
            UserStatus.DEACTIVATED, command.reason, command.admin_user_id
        )
        await self._user_repository.update(user)
        
        # Revoke sessions
        await self._security_service.revoke_all_sessions(user.id)
    
    async def _suspend_users(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Suspend user accounts."""
        if user.status == UserStatus.SUSPENDED:
            return  # Already suspended
        
        if user.status not in [UserStatus.ACTIVE, UserStatus.PENDING_VERIFICATION]:
            raise InvalidOperationError(
                f"Cannot suspend user with status: {user.status.value}"
            )
        
        user.update_status(UserStatus.SUSPENDED, command.reason, command.admin_user_id)
        await self._user_repository.update(user)
        
        # Revoke sessions
        await self._security_service.revoke_all_sessions(user.id)
    
    async def _reset_passwords(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Force password reset for users."""
        # Set password reset required flag
        user.require_password_change = True
        await self._user_repository.update(user)
        
        # Send password reset email
        reset_token = await self._security_service.generate_password_reset_token(
            user.id
        )
        await self._email_service.send_password_reset_email(
            user.email,
            user.username,
            reset_token,
            command.reason
        )
        
        # Revoke sessions to force re-login
        await self._security_service.revoke_all_sessions(user.id)
    
    async def _force_mfa(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Force MFA enrollment for users."""
        # Set MFA required flag
        user.mfa_required = True
        user.mfa_grace_period_ends = datetime.now(UTC) + timedelta(days=7)
        await self._user_repository.update(user)
        
        # Send MFA enrollment notification
        await self._notification_service.create_notification(
            user_id=user.id,
            type=NotificationType.MFA_REQUIRED,
            title="Multi-Factor Authentication Required",
            message=f"MFA is now required for your account. Reason: {command.reason}",
            priority="high"
        )
    
    async def _assign_role(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Assign role to users."""
        role_name = command.parameters.get("role_name")
        if not role_name:
            raise ValidationError("Role name required for assign_role operation")
        
        await self._authorization_service.assign_role(
            user.id,
            role_name,
            assigned_by=command.admin_user_id,
            reason=command.reason
        )
    
    async def _remove_role(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Remove role from users."""
        role_name = command.parameters.get("role_name")
        if not role_name:
            raise ValidationError("Role name required for remove_role operation")
        
        await self._authorization_service.remove_role(
            user.id,
            role_name,
            removed_by=command.admin_user_id,
            reason=command.reason
        )
    
    async def _update_attribute(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Update user attribute."""
        attribute_name = command.parameters.get("attribute_name")
        attribute_value = command.parameters.get("attribute_value")
        
        if not attribute_name:
            raise ValidationError(
                "Attribute name required for update_attribute operation"
            )
        
        # Validate attribute can be bulk updated
        allowed_attributes = [
            "department", "manager", "location", "timezone",
            "language", "notification_preferences"
        ]
        
        if attribute_name not in allowed_attributes:
            raise ValidationError(
                f"Attribute '{attribute_name}' cannot be bulk updated"
            )
        
        # Update attribute
        setattr(user, attribute_name, attribute_value)
        await self._user_repository.update(user)
    
    async def _send_notification(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Send notification to users."""
        notification_type = command.parameters.get("notification_type")
        title = command.parameters.get("title")
        message = command.parameters.get("message")
        
        if not all([notification_type, title, message]):
            raise ValidationError("Notification type, title, and message required")
        
        await self._notification_service.create_notification(
            user_id=user.id,
            type=notification_type,
            title=title,
            message=message,
            metadata=command.parameters.get("metadata", {})
        )
    
    async def _lock_accounts(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Lock user accounts."""
        if user.status == UserStatus.LOCKED:
            return  # Already locked
        
        user.update_status(UserStatus.LOCKED, command.reason, command.admin_user_id)
        await self._user_repository.update(user)
        
        # Revoke all sessions immediately
        await self._security_service.revoke_all_sessions(user.id)
        
        # Log security event
        await self._security_service.log_security_incident({
            "type": "account_locked",
            "user_id": str(user.id),
            "reason": command.reason,
            "locked_by": str(command.admin_user_id)
        })
    
    async def _delete_users(
        self,
        user: User,
        command: BulkOperationCommand,
        context: BulkOperationContext
    ) -> None:
        """Delete user accounts (soft delete)."""
        # Perform soft delete
        user.delete(deleted_by=command.admin_user_id, reason=command.reason)
        await self._user_repository.update(user)
        
        # Anonymize PII if required
        if command.parameters.get("anonymize_data", True):
            await self._anonymize_user_data(user)
        
        # Revoke all access
        await self._security_service.revoke_all_sessions(user.id)
        await self._authorization_service.revoke_all_permissions(user.id)
    
    async def _validate_operation(
        self,
        user: User,
        command: BulkOperationCommand
    ) -> bool:
        """Validate if operation can be performed on user."""
        # Operation-specific validation
        if command.operation_type == BulkOperationType.ACTIVATE_USERS:
            return user.status in [UserStatus.DEACTIVATED, UserStatus.SUSPENDED]
        
        if command.operation_type == BulkOperationType.DELETE_USERS:
            return user.id != command.admin_user_id
        
        # Add more validation rules as needed
        return True
    
    async def _can_modify_user(self, admin_user: User, target_user: User) -> bool:
        """Check if admin can modify target user."""
        # Similar to other commands
        admin_roles = await self._authorization_service.get_user_roles(admin_user.id)
        target_roles = await self._authorization_service.get_user_roles(target_user.id)
        
        # Super admin can modify anyone
        if any(role.name == "super_admin" for role in admin_roles):
            return True
        
        # Check hierarchy
        admin_max_level = max(
            (role.get_hierarchy_level() for role in admin_roles),
            default=0
        )
        target_max_level = max(
            (role.get_hierarchy_level() for role in target_roles),
            default=0
        )
        
        return admin_max_level > target_max_level
    
    async def _update_progress(
        self,
        operation_id: UUID,
        processed: int,
        total: int
    ) -> None:
        """Update operation progress in cache."""
        progress = {
            "processed": processed,
            "total": total,
            "percentage": round((processed / total) * 100, 2),
            "updated_at": datetime.now(UTC).isoformat()
        }
        
        await self._cache_service.set(
            f"bulk_op_progress:{operation_id}",
            progress,
            ttl=3600  # 1 hour
        )
    
    async def _rollback_operation(
        self,
        operation_id: UUID,
        successful_ids: list[UUID],
        command: BulkOperationCommand
    ) -> None:
        """Rollback successful operations."""
        # Implement rollback logic based on operation type
        # This is a simplified example
        rollback_map = {
            BulkOperationType.ACTIVATE_USERS: UserStatus.DEACTIVATED,
            BulkOperationType.SUSPEND_USERS: UserStatus.ACTIVE,
            BulkOperationType.LOCK_ACCOUNTS: UserStatus.ACTIVE
        }
        
        if command.operation_type in rollback_map:
            for user_id in successful_ids:
                try:
                    user = await self._user_repository.get_by_id(user_id)
                    if user:
                        user.update_status(
                            rollback_map[command.operation_type],
                            f"Rollback: {command.reason}",
                            command.admin_user_id
                        )
                        await self._user_repository.update(user)
                except Exception:
                    # Log rollback failure but continue
                    pass
    
    async def _send_bulk_notifications(
        self,
        user_ids: list[UUID],
        operation_type: BulkOperationType,
        reason: str
    ) -> None:
        """Send notifications to affected users."""
        # Send in batches to avoid overwhelming the notification service
        for batch_start in range(0, len(user_ids), 100):
            batch_end = min(batch_start + 100, len(user_ids))
            batch_ids = user_ids[batch_start:batch_end]
            
            # Create notification tasks
            tasks = []
            for user_id in batch_ids:
                task = self._notification_service.create_notification(
                    user_id=user_id,
                    type=NotificationType.BULK_OPERATION,
                    title=f"Account Update: {operation_type.value}",
                    message=(
                        f"Your account was affected by a bulk operation. Reason: {reason}"
                    ),
                    priority="normal"
                )
                tasks.append(task)
            
            # Send notifications in parallel
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _anonymize_user_data(self, user: User) -> None:
        """Anonymize user PII data."""
        # Generate anonymous identifiers
        anon_id = f"deleted_user_{user.id.hex[:8]}"
        
        user.username = anon_id
        user.email = f"{anon_id}@deleted.local"
        user.first_name = "Deleted"
        user.last_name = "User"
        user.phone_number = None
        
        # Clear other PII fields
        user.metadata = {
            "anonymized": True,
            "anonymized_at": datetime.now(UTC).isoformat()
        }
        
        await self._user_repository.update(user)
    
    async def _generate_operation_report(
        self,
        operation_id: UUID,
        command: BulkOperationCommand,
        results: dict[str, list],
        operation_result: OperationResult
    ) -> str:
        """Generate downloadable operation report."""
        # This would typically generate a CSV/Excel report and upload to storage
        # Returning a mock URL for now
        report_data = {
            "operation_id": str(operation_id),
            "operation_type": command.operation_type.value,
            "initiated_by": str(command.admin_user_id),
            "reason": command.reason,
            "total_targets": len(command.target_user_ids),
            "successful": operation_result.success_count,
            "failed": operation_result.failure_count,
            "skipped": operation_result.skipped_count,
            "duration_ms": operation_result.duration_ms,
            "completed_at": datetime.now(UTC).isoformat(),
            "results": results
        }
        
        # Generate and store report
        report_id = UUID()
        await self._cache_service.set(
            f"bulk_op_report:{report_id}",
            report_data,
            ttl=86400  # 24 hours
        )
        
        return f"https://app.example.com/reports/bulk-operations/{report_id}"
    
    async def _schedule_operation(
        self, command: BulkOperationCommand
    ) -> BulkOperationResponse:
        """Schedule operation for later execution."""
        # This would typically use a job scheduler
        job_id = UUID()
        
        # Store job details
        await self._cache_service.set(
            f"scheduled_bulk_op:{job_id}",
            {
                "command": command.dict(),
                "scheduled_at": command.schedule_at.isoformat(),
                "created_at": datetime.now(UTC).isoformat()
            },
            ttl=int((command.schedule_at - datetime.now(UTC)).total_seconds())
        )
        
        return BulkOperationResponse(
            operation_id=job_id,
            operation_type=command.operation_type.value,
            total_items=len(command.target_user_ids),
            successful=0,
            failed=0,
            skipped=0,
            results=[],
            errors=[],
            message=f"Bulk operation scheduled for {command.schedule_at.isoformat()}"
        )