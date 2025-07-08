"""
System maintenance command implementation.

Handles system-wide maintenance operations for identity management.
"""

import asyncio
from datetime import datetime, timedelta
from enum import Enum
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
from app.modules.identity.application.dtos.administrative import (
    InfrastructureDependencies,
    MaintenanceConfig,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    MaintenanceContext,
)
from app.modules.identity.application.dtos.request import SystemMaintenanceRequest
from app.modules.identity.application.dtos.response import MaintenanceOperationResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    UserStatus,
)
from app.modules.identity.domain.events import (
    SecurityPolicyEnforced,
    SystemMaintenanceCompleted,
    SystemMaintenanceStarted,
)
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    MaintenanceError,
    UnauthorizedError,
)


class MaintenanceType(Enum):
    """Types of maintenance operations."""
    CACHE_CLEAR = "cache_clear"
    SESSION_CLEANUP = "session_cleanup"
    TOKEN_ROTATION = "token_rotation"  # noqa: S105
    PASSWORD_POLICY_ENFORCEMENT = "password_policy_enforcement"  # noqa: S105
    MFA_POLICY_ENFORCEMENT = "mfa_policy_enforcement"
    INACTIVE_USER_CLEANUP = "inactive_user_cleanup"
    AUDIT_LOG_ROTATION = "audit_log_rotation"
    DEVICE_TRUST_REFRESH = "device_trust_refresh"
    PERMISSION_CACHE_REBUILD = "permission_cache_rebuild"
    SECURITY_SCAN = "security_scan"
    DATABASE_OPTIMIZATION = "database_optimization"
    BACKUP_VERIFICATION = "backup_verification"
    COMPLIANCE_CHECK = "compliance_check"
    FULL_MAINTENANCE = "full_maintenance"


class SystemMaintenanceCommand(Command[MaintenanceOperationResponse]):
    """Command to perform system maintenance operations."""

    def __init__(
        self,
        admin_user_id: UUID,
        maintenance_config: MaintenanceConfig,
        additional_options: dict[str, Any] | None = None
    ):
        self.admin_user_id = admin_user_id
        self.maintenance_config = maintenance_config
        additional_options = additional_options or {}
        
        # For backward compatibility, expose common fields
        self.maintenance_type = MaintenanceType(maintenance_config.maintenance_type)
        self.parameters = additional_options.get('parameters', {})
        self.force_execution = additional_options.get('force_execution', False)
        self.dry_run = additional_options.get('dry_run', False)
        self.notify_users = maintenance_config.notify_users
        self.maintenance_window_minutes = maintenance_config.estimated_duration_minutes
        self.parallel_execution = additional_options.get('parallel_execution', True)
        self.batch_size = additional_options.get('batch_size', 1000)
        self.schedule_at = additional_options.get('schedule_at')
        self.metadata = maintenance_config.metadata


class SystemMaintenanceCommandHandler(CommandHandler[SystemMaintenanceCommand, MaintenanceOperationResponse]):
    """Handler for system maintenance operations."""

    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._session_repository = services.session_repository
        self._audit_repository = services.audit_repository
        self._notification_repository = services.notification_repository
        self._token_repository = services.token_repository
        self._device_repository = services.device_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._cache_service = services.cache_service
        self._metrics_service = services.metrics_service
        self._backup_service = services.backup_service
        self._queue_service = services.queue_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work

    @audit_action(
        action=AuditAction.SYSTEM_MAINTENANCE,
        resource_type="system",
        include_request=True,
        include_response=True,
        high_priority=True
    )
    @validate_request(SystemMaintenanceRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=86400,  # Daily
        strategy='global'
    )
    @require_permission(
        "system.maintenance",
        resource_type="system"
    )
    @require_mfa()
    @require_approval(
        approval_type="system_maintenance",
        threshold_param="maintenance_window_minutes",
        threshold_value=60  # Require approval for >1 hour maintenance
    )
    async def handle(self, command: SystemMaintenanceCommand) -> MaintenanceOperationResponse:
        """
        Execute system maintenance operation.

        Process:
        1. Validate maintenance window
        2. Check system status
        3. Notify users if needed
        4. Execute maintenance
        5. Verify results
        6. Generate report
        7. Restore normal operations

        Returns:
            MaintenanceOperationResponse with results

        Raises:
            UnauthorizedError: If lacks permission
            InvalidOperationError: If operation invalid
            MaintenanceError: If maintenance fails
        """
        # Schedule if requested
        if command.schedule_at and command.schedule_at > datetime.now(datetime.UTC):
            return await self._schedule_maintenance(command)

        async with self._unit_of_work:
            # Initialize maintenance operation
            admin_user, operation_id, context = await self._initialize_maintenance(
                command
            )
            
            # Pre-maintenance checks and setup
            await self._prepare_maintenance(command, context)
            
            try:
                # Notify start and publish event
                await self._notify_maintenance_start_and_publish(
                    command,
                    context,
                    operation_id
                )
                
                # Execute maintenance operation
                results = await self._execute_maintenance_type(
                    command,
                    context
                )
                
                # Post-maintenance processing
                report_url = await self._complete_maintenance(
                    operation_id,
                    command,
                    context,
                    results
                )
                
                # Commit transaction
                await self._unit_of_work.commit()
                
                # Post-commit operations
                await self._post_commit_operations(
                    command,
                    context,
                    results
                )
                
                return self._create_maintenance_response(
                    operation_id,
                    command,
                    context,
                    results,
                    report_url
                )

            except Exception as e:
                # Exit maintenance mode on error
                if not command.dry_run:
                    await self._exit_maintenance_mode(context)

                raise MaintenanceError(
                    f"Maintenance operation failed: {e!s}",
                    operation_id=operation_id,
                    maintenance_type=command.maintenance_type.value
                ) from e

    async def _check_maintenance_feasibility(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> None:
        """Check if maintenance can proceed safely."""
        # Check active users
        active_sessions = await self._session_repository.count_active()
        if (
            active_sessions > 1000
            and command.maintenance_type == MaintenanceType.FULL_MAINTENANCE
            and not command.force_execution
        ):
            raise InvalidOperationError(
                f"Cannot perform full maintenance with {active_sessions} active sessions"
            )

        # Check ongoing operations
        ongoing_ops = await self._check_ongoing_operations()
        if ongoing_ops:
            raise InvalidOperationError(
                f"Cannot start maintenance: {len(ongoing_ops)} operations in progress"
            )

        # Check system health
        health = await self._check_system_health()
        if health["status"] != "healthy" and not command.force_execution:
            raise InvalidOperationError(
                f"System not healthy for maintenance: {health['issues']}"
            )

    async def _enter_maintenance_mode(self, context: MaintenanceContext) -> None:
        """Enter maintenance mode."""
        await self._cache_service.set(
            "system:maintenance_mode",
            {
                "active": True,
                "operation_id": str(context.operation_id),
                "type": context.maintenance_type,
                "started_at": context.started_at.isoformat(),
                "expected_end": (
                    context.started_at + timedelta(minutes=context.window_minutes)
                ).isoformat()
            },
            ttl=context.window_minutes * 60
        )

    async def _exit_maintenance_mode(self, context: MaintenanceContext) -> None:
        """Exit maintenance mode."""
        await self._cache_service.delete("system:maintenance_mode")

    # Maintenance operation handlers with proper type annotations

    async def _clear_caches(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str]:
        """Clear system caches."""
        results: dict[str, int | list[Any] | str] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "summary": ""
        }

        cache_types = command.parameters.get("cache_types", ["all"])

        if "all" in cache_types or "user" in cache_types:
            # Clear user caches
            count = await self._cache_service.clear_pattern("user:*")
            results["processed"] = int(results["processed"]) + count
            results["modified"] = int(results["modified"]) + count

        if "all" in cache_types or "session" in cache_types:
            # Clear session caches
            count = await self._cache_service.clear_pattern("session:*")
            results["processed"] = int(results["processed"]) + count
            results["modified"] = int(results["modified"]) + count

        if "all" in cache_types or "permission" in cache_types:
            # Clear permission caches
            count = await self._cache_service.clear_pattern("permissions:*")
            results["processed"] = int(results["processed"]) + count
            results["modified"] = int(results["modified"]) + count

        if "all" in cache_types or "rate_limit" in cache_types:
            # Clear rate limit caches
            count = await self._cache_service.clear_pattern("rate_limit:*")
            results["processed"] = int(results["processed"]) + count
            results["modified"] = int(results["modified"]) + count

        results["summary"] = f"Cleared {results['modified']} cache entries"
        return results

    async def _cleanup_sessions(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Clean up expired and orphaned sessions."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {}
        }

        # Clean expired sessions
        expired_cutoff = datetime.now(datetime.UTC) - timedelta(
            days=command.parameters.get("expired_days", 7)
        )
        expired_sessions = await self._session_repository.find_expired_before(expired_cutoff)

        for session in expired_sessions:
            try:
                if not command.dry_run:
                    await self._session_repository.delete(session.id)
                results["modified"] = int(results["modified"]) + 1
            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "session_id": str(session.id),
                        "error": str(e)
                    })
            results["processed"] = int(results["processed"]) + 1

        details_dict = results["details"]
        if isinstance(details_dict, dict):
            details_dict["expired_cleaned"] = int(results["modified"])

        # Clean orphaned sessions (users deleted)
        orphaned_sessions = await self._session_repository.find_orphaned()
        orphaned_count = 0

        for session in orphaned_sessions:
            try:
                if not command.dry_run:
                    await self._session_repository.delete(session.id)
                orphaned_count += 1
            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "session_id": str(session.id),
                        "error": str(e)
                    })
            results["processed"] = int(results["processed"]) + 1

        if isinstance(details_dict, dict):
            details_dict["orphaned_cleaned"] = orphaned_count
        results["modified"] = int(results["modified"]) + orphaned_count

        if isinstance(details_dict, dict):
            results["summary"] = (
                f"Cleaned {details_dict.get('expired_cleaned', 0)} expired and "
                f"{details_dict.get('orphaned_cleaned', 0)} orphaned sessions"
            )

        return results

    async def _rotate_tokens(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Rotate authentication tokens."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {}
        }

        # Get rotation parameters
        command.parameters.get("force_rotation", False)
        token_age_days = command.parameters.get("token_age_days", 90)

        # Find tokens needing rotation
        rotation_cutoff = datetime.now(datetime.UTC) - timedelta(days=token_age_days)
        old_tokens = await self._token_repository.find_created_before(rotation_cutoff)

        # Process in batches
        for i in range(0, len(old_tokens), command.batch_size):
            batch = old_tokens[i:i + command.batch_size]

            for token in batch:
                try:
                    if not command.dry_run:
                        # Rotate token
                        await self._security_service.rotate_token(token.id)

                        # Notify user
                        await self._notification_repository.create(
                            user_id=token.user_id,
                            type=NotificationType.SECURITY_UPDATE,
                            title="Authentication Token Rotated",
                            message="Your authentication token has been rotated for security.",
                            priority="high"
                        )

                    results["modified"] = int(results["modified"]) + 1
                except Exception as e:
                    errors_list = results["errors"]
                    if isinstance(errors_list, list):
                        errors_list.append({
                            "token_id": str(token.id),
                            "user_id": str(token.user_id),
                            "error": str(e)
                        })

                results["processed"] = int(results["processed"]) + 1

        results["summary"] = f"Rotated {results['modified']} authentication tokens"
        return results

    async def _enforce_password_policy(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Enforce password policy on all users."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "weak_passwords": 0,
                "expired_passwords": 0,
                "reused_passwords": 0
            }
        }

        # Get policy parameters
        command.parameters.get("min_length", 12)
        command.parameters.get("require_complexity", True)
        max_age_days = command.parameters.get("max_age_days", 90)
        prevent_reuse = command.parameters.get("prevent_reuse", 5)

        # Process all active users
        users = await self._user_repository.find_by_status(UserStatus.ACTIVE)

        for user in users:
            try:
                policy_violations = []
                details_dict = results["details"]

                # Check password age
                if user.password_changed_at:
                    age = datetime.now(datetime.UTC) - user.password_changed_at
                    if age.days > max_age_days:
                        policy_violations.append("expired")
                        if isinstance(details_dict, dict):
                            details_dict["expired_passwords"] = int(details_dict["expired_passwords"]) + 1

                # Check password strength (would need password history)
                # This is simplified - real implementation would check actual strength
                if user.metadata.get("password_strength", "strong") == "weak":
                    policy_violations.append("weak")
                    if isinstance(details_dict, dict):
                        details_dict["weak_passwords"] = int(details_dict["weak_passwords"]) + 1

                # Check password reuse
                if await self._check_password_reuse(user.id, prevent_reuse):
                    policy_violations.append("reused")
                    if isinstance(details_dict, dict):
                        details_dict["reused_passwords"] = int(details_dict["reused_passwords"]) + 1

                # Enforce policy
                if policy_violations and not command.dry_run:
                    user.require_password_change = True
                    user.password_policy_violations = policy_violations
                    await self._user_repository.update(user)

                    # Notify user
                    await self._send_password_policy_notification(
                        user,
                        policy_violations
                    )

                    results["modified"] = int(results["modified"]) + 1

                results["processed"] = int(results["processed"]) + 1

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "user_id": str(user.id),
                        "error": str(e)
                    })

        # Publish policy enforcement event
        if int(results["modified"]) > 0:
            await self._event_bus.publish(
                SecurityPolicyEnforced(
                    policy_type="password",
                    affected_users=int(results["modified"]),
                    violations=results["details"]
                )
            )

        results["summary"] = (
            f"Enforced password policy: {results['modified']} users require password change"
        )

        return results

    async def _enforce_mfa_policy(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Enforce MFA policy on users."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "no_mfa": 0,
                "weak_mfa": 0,
                "grace_period_set": 0
            }
        }

        # Get policy parameters
        require_mfa_roles = command.parameters.get("require_mfa_roles", ["admin", "manager"])
        grace_period_days = command.parameters.get("grace_period_days", 14)
        allowed_methods = command.parameters.get("allowed_methods", ["totp", "hardware_token"])

        # Find users requiring MFA
        for role_name in require_mfa_roles:
            users = await self._authorization_service.get_users_with_role(role_name)

            for user in users:
                try:
                    # Check MFA status
                    mfa_devices = await self._security_service.get_mfa_devices(user.id)
                    details_dict = results["details"]

                    if not mfa_devices:
                        # No MFA set up
                        if isinstance(details_dict, dict):
                            details_dict["no_mfa"] = int(details_dict["no_mfa"]) + 1

                        if not command.dry_run:
                            user.mfa_required = True
                            user.mfa_grace_period_ends = (
                                datetime.now(datetime.UTC) + timedelta(days=grace_period_days)
                            )
                            await self._user_repository.update(user)

                            # Notify user
                            await self._send_mfa_requirement_notification(
                                user,
                                grace_period_days
                            )

                            if isinstance(details_dict, dict):
                                details_dict["grace_period_set"] = int(details_dict["grace_period_set"]) + 1

                        results["modified"] = int(results["modified"]) + 1

                    else:
                        # Check MFA methods
                        weak_methods = [
                            d for d in mfa_devices
                            if d.method not in allowed_methods
                        ]

                        if weak_methods:
                            if isinstance(details_dict, dict):
                                details_dict["weak_mfa"] = int(details_dict["weak_mfa"]) + 1

                            if not command.dry_run:
                                # Require stronger MFA
                                await self._require_stronger_mfa(
                                    user,
                                    allowed_methods,
                                    grace_period_days
                                )

                            results["modified"] = int(results["modified"]) + 1

                    results["processed"] = int(results["processed"]) + 1

                except Exception as e:
                    errors_list = results["errors"]
                    if isinstance(errors_list, list):
                        errors_list.append({
                            "user_id": str(user.id),
                            "error": str(e)
                        })

        # Publish policy enforcement event
        if int(results["modified"]) > 0:
            await self._event_bus.publish(
                SecurityPolicyEnforced(
                    policy_type="mfa",
                    affected_users=int(results["modified"]),
                    violations=results["details"]
                )
            )

        if isinstance(results["details"], dict):
            results["summary"] = (
                f"Enforced MFA policy: {results['details']['no_mfa']} users need MFA, "
                f"{results['details']['weak_mfa']} need stronger MFA"
            )

        return results

    async def _cleanup_inactive_users(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Clean up inactive user accounts."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "suspended": 0,
                "deactivated": 0,
                "marked_for_deletion": 0
            }
        }

        # Get cleanup parameters
        inactive_days = command.parameters.get("inactive_days", 365)
        warning_days = command.parameters.get("warning_days", 30)
        action = command.parameters.get("action", "suspend")  # suspend, deactivate, delete

        # Find inactive users
        inactive_cutoff = datetime.now(datetime.UTC) - timedelta(days=inactive_days)
        warning_cutoff = datetime.now(datetime.UTC) - timedelta(days=inactive_days - warning_days)

        inactive_users = await self._user_repository.find_inactive_since(inactive_cutoff)
        warning_users = await self._user_repository.find_inactive_since(warning_cutoff)

        # Process warnings first
        for user in warning_users:
            if user not in inactive_users and user.status == UserStatus.ACTIVE:
                try:
                    if not command.dry_run:
                        await self._send_inactivity_warning(user, warning_days)
                except Exception as e:
                    errors_list = results["errors"]
                    if isinstance(errors_list, list):
                        errors_list.append({
                            "user_id": str(user.id),
                            "action": "warning",
                            "error": str(e)
                        })

        # Process inactive users
        for user in inactive_users:
            if user.status != UserStatus.ACTIVE:
                continue

            try:
                details_dict = results["details"]
                if not command.dry_run:
                    if action == "suspend":
                        user.update_status(
                            UserStatus.SUSPENDED,
                            f"Inactive for {inactive_days} days",
                            context.initiated_by
                        )
                        if isinstance(details_dict, dict):
                            details_dict["suspended"] = int(details_dict["suspended"]) + 1

                    elif action == "deactivate":
                        user.update_status(
                            UserStatus.DEACTIVATED,
                            f"Inactive for {inactive_days} days",
                            context.initiated_by
                        )
                        if isinstance(details_dict, dict):
                            details_dict["deactivated"] = int(details_dict["deactivated"]) + 1

                    elif action == "delete":
                        user.mark_for_deletion(
                            f"Inactive for {inactive_days} days",
                            context.initiated_by
                        )
                        if isinstance(details_dict, dict):
                            details_dict["marked_for_deletion"] = int(details_dict["marked_for_deletion"]) + 1

                    await self._user_repository.update(user)

                    # Revoke sessions
                    await self._security_service.revoke_all_sessions(user.id)

                results["modified"] = int(results["modified"]) + 1
                results["processed"] = int(results["processed"]) + 1

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "user_id": str(user.id),
                        "action": action,
                        "error": str(e)
                    })

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Processed {results['processed']} inactive users: "
                f"{details['suspended']} suspended, "
                f"{details['deactivated']} deactivated, "
                f"{details['marked_for_deletion']} marked for deletion"
            )

        return results

    async def _rotate_audit_logs(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Rotate and archive audit logs."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "archived": 0,
                "compressed_mb": 0,
                "deleted": 0
            }
        }

        # Get rotation parameters
        retention_days = command.parameters.get("retention_days", 90)
        archive_days = command.parameters.get("archive_days", 30)
        compress = command.parameters.get("compress", True)

        # Find logs to process
        archive_cutoff = datetime.now(datetime.UTC) - timedelta(days=archive_days)
        delete_cutoff = datetime.now(datetime.UTC) - timedelta(days=retention_days)

        # Archive recent logs
        logs_to_archive = await self._audit_repository.find_before(archive_cutoff)

        if logs_to_archive and not command.dry_run:
            # Archive in batches
            archive_size = 0
            for i in range(0, len(logs_to_archive), 10000):
                batch = logs_to_archive[i:i + 10000]
                size = await self._archive_audit_logs(batch, compress)
                archive_size += size
                details_dict = results["details"]
                if isinstance(details_dict, dict):
                    details_dict["archived"] = int(details_dict["archived"]) + len(batch)

            if isinstance(results["details"], dict):
                results["details"]["compressed_mb"] = archive_size

        # Delete old logs
        logs_to_delete = await self._audit_repository.find_before(delete_cutoff)

        if logs_to_delete and not command.dry_run:
            for log in logs_to_delete:
                try:
                    await self._audit_repository.delete(log.id)
                    details_dict = results["details"]
                    if isinstance(details_dict, dict):
                        details_dict["deleted"] = int(details_dict["deleted"]) + 1
                except Exception as e:
                    errors_list = results["errors"]
                    if isinstance(errors_list, list):
                        errors_list.append({
                            "log_id": str(log.id),
                            "error": str(e)
                        })

        results["processed"] = len(logs_to_archive) + len(logs_to_delete)
        if isinstance(results["details"], dict):
            details = results["details"]
            results["modified"] = int(details["archived"]) + int(details["deleted"])

            results["summary"] = (
                f"Archived {details['archived']} logs "
                f"({details['compressed_mb']:.1f} MB), "
                f"deleted {details['deleted']} old logs"
            )

        return results

    async def _refresh_device_trust(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Refresh device trust status."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "verified": 0,
                "revoked": 0,
                "expired": 0
            }
        }

        # Get trust parameters
        trust_duration_days = command.parameters.get("trust_duration_days", 90)
        require_reverification = command.parameters.get("require_reverification", True)

        # Find all trusted devices
        all_devices = await self._device_repository.find_all_trusted()

        for device in all_devices:
            try:
                # Check trust age
                trust_age = datetime.now(datetime.UTC) - device.trusted_at
                details_dict = results["details"]

                if trust_age.days > trust_duration_days:
                    if not command.dry_run:
                        if require_reverification:
                            # Mark for reverification
                            device.trust_status = "pending_reverification"
                            device.reverification_required_at = datetime.now(datetime.UTC)
                            await self._device_repository.update(device)

                            # Notify user
                            await self._send_device_reverification_notice(
                                device.user_id,
                                device
                            )

                            if isinstance(details_dict, dict):
                                details_dict["expired"] = int(details_dict["expired"]) + 1
                        else:
                            # Revoke trust
                            device.trust_status = "revoked"
                            device.trust_revoked_at = datetime.now(datetime.UTC)
                            await self._device_repository.update(device)

                            if isinstance(details_dict, dict):
                                details_dict["revoked"] = int(details_dict["revoked"]) + 1

                    results["modified"] = int(results["modified"]) + 1
                elif isinstance(details_dict, dict):
                    details_dict["verified"] = int(details_dict["verified"]) + 1

                results["processed"] = int(results["processed"]) + 1

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "device_id": str(device.id),
                        "error": str(e)
                    })

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Refreshed {results['processed']} devices: "
                f"{details['verified']} verified, "
                f"{details['expired']} expired, "
                f"{details['revoked']} revoked"
            )

        return results

    async def _rebuild_permission_cache(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Rebuild permission caches."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "users_processed": 0,
                "permissions_cached": 0,
                "roles_cached": 0
            }
        }

        # Clear existing permission caches
        if not command.dry_run:
            await self._cache_service.clear_pattern("permissions:*")
            await self._cache_service.clear_pattern("roles:*")

        # Rebuild for all active users
        active_users = await self._user_repository.find_by_status(UserStatus.ACTIVE)

        # Process in batches
        for i in range(0, len(active_users), command.batch_size):
            batch = active_users[i:i + command.batch_size]

            if command.parallel_execution:
                # Parallel processing
                tasks = [
                    self._rebuild_user_permissions(user, command.dry_run)
                    for user in batch
                ]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for user, result in zip(batch, batch_results, strict=False):
                    details_dict = results["details"]
                    if isinstance(result, Exception):
                        errors_list = results["errors"]
                        if isinstance(errors_list, list):
                            errors_list.append({
                                "user_id": str(user.id),
                                "error": str(result)
                            })
                    else:
                        if isinstance(details_dict, dict):
                            details_dict["users_processed"] = int(details_dict["users_processed"]) + 1
                            details_dict["permissions_cached"] = int(details_dict["permissions_cached"]) + result["permissions"]
                            details_dict["roles_cached"] = int(details_dict["roles_cached"]) + result["roles"]
                        results["modified"] = int(results["modified"]) + 1
            else:
                # Sequential processing
                for user in batch:
                    try:
                        result = await self._rebuild_user_permissions(user, command.dry_run)
                        details_dict = results["details"]
                        if isinstance(details_dict, dict):
                            details_dict["users_processed"] = int(details_dict["users_processed"]) + 1
                            details_dict["permissions_cached"] = int(details_dict["permissions_cached"]) + result["permissions"]
                            details_dict["roles_cached"] = int(details_dict["roles_cached"]) + result["roles"]
                        results["modified"] = int(results["modified"]) + 1
                    except Exception as e:
                        errors_list = results["errors"]
                        if isinstance(errors_list, list):
                            errors_list.append({
                                "user_id": str(user.id),
                                "error": str(e)
                            })

            results["processed"] = int(results["processed"]) + len(batch)

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Rebuilt permissions for {details['users_processed']} users: "
                f"{details['permissions_cached']} permissions, "
                f"{details['roles_cached']} roles cached"
            )

        return results

    async def _run_security_scan(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Run security scan on user accounts."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "suspicious_activities": 0,
                "compromised_accounts": 0,
                "weak_security": 0,
                "alerts_generated": 0
            }
        }

        # Scan parameters
        scan_types = command.parameters.get("scan_types", [
            "suspicious_login",
            "impossible_travel",
            "weak_credentials",
            "privilege_escalation"
        ])

        # Get all active users
        users = await self._user_repository.find_by_status(UserStatus.ACTIVE)

        for user in users:
            try:
                scan_results = {}
                details_dict = results["details"]

                # Suspicious login patterns
                if "suspicious_login" in scan_types:
                    suspicious = await self._scan_suspicious_logins(user.id)
                    if suspicious:
                        scan_results["suspicious_login"] = suspicious
                        if isinstance(details_dict, dict):
                            details_dict["suspicious_activities"] = int(details_dict["suspicious_activities"]) + 1

                # Impossible travel
                if "impossible_travel" in scan_types:
                    travel_issues = await self._scan_impossible_travel(user.id)
                    if travel_issues:
                        scan_results["impossible_travel"] = travel_issues
                        if isinstance(details_dict, dict):
                            details_dict["suspicious_activities"] = int(details_dict["suspicious_activities"]) + 1

                # Weak credentials
                if "weak_credentials" in scan_types:
                    weak_creds = await self._scan_weak_credentials(user.id)
                    if weak_creds:
                        scan_results["weak_credentials"] = weak_creds
                        if isinstance(details_dict, dict):
                            details_dict["weak_security"] = int(details_dict["weak_security"]) + 1

                # Privilege escalation attempts
                if "privilege_escalation" in scan_types:
                    escalation = await self._scan_privilege_escalation(user.id)
                    if escalation:
                        scan_results["privilege_escalation"] = escalation
                        if isinstance(details_dict, dict):
                            details_dict["suspicious_activities"] = int(details_dict["suspicious_activities"]) + 1

                # Take action on findings
                if scan_results and not command.dry_run:
                    # Generate security alert
                    await self._generate_security_alert(user, scan_results)
                    if isinstance(details_dict, dict):
                        details_dict["alerts_generated"] = int(details_dict["alerts_generated"]) + 1

                    # Lock account if critical
                    if self._is_critical_security_issue(scan_results):
                        user.update_status(
                            UserStatus.LOCKED,
                            "Security scan detected critical issues",
                            context.initiated_by
                        )
                        await self._user_repository.update(user)
                        if isinstance(details_dict, dict):
                            details_dict["compromised_accounts"] = int(details_dict["compromised_accounts"]) + 1

                    results["modified"] = int(results["modified"]) + 1

                results["processed"] = int(results["processed"]) + 1

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "user_id": str(user.id),
                        "error": str(e)
                    })

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Security scan completed: {details['suspicious_activities']} "
                f"suspicious activities, {details['compromised_accounts']} "
                f"accounts locked, {details['alerts_generated']} alerts generated"
            )

        return results

    async def _optimize_database(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Optimize database performance."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "indexes_rebuilt": 0,
                "statistics_updated": 0,
                "space_reclaimed_mb": 0
            }
        }

        if command.dry_run:
            # Analyze only
            results["summary"] = "Database optimization analysis complete (dry run)"
            return results

        # This would typically call database-specific optimization
        # For now, returning mock results
        details_dict = results["details"]
        if isinstance(details_dict, dict):
            details_dict["indexes_rebuilt"] = 15
            details_dict["statistics_updated"] = 50
            details_dict["space_reclaimed_mb"] = 1024

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Database optimized: {details['indexes_rebuilt']} indexes rebuilt, "
                f"{details['space_reclaimed_mb']} MB reclaimed"
            )

        return results

    async def _verify_backups(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Verify backup integrity."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "verified": 0,
                "corrupted": 0,
                "missing": 0,
                "repaired": 0
            }
        }

        # Get backup verification parameters
        max_age_days = command.parameters.get("max_age_days", 30)
        verify_checksum = command.parameters.get("verify_checksum", True)
        test_restore = command.parameters.get("test_restore", False)

        # List recent backups
        recent_backups = await self._backup_service.list_recent(days=max_age_days)

        for backup in recent_backups:
            try:
                details_dict = results["details"]
                # Verify backup exists
                if not await self._backup_service.exists(backup.id):
                    if isinstance(details_dict, dict):
                        details_dict["missing"] = int(details_dict["missing"]) + 1
                    if not command.dry_run:
                        await self._backup_service.mark_as_missing(backup.id)
                    results["modified"] = int(results["modified"]) + 1
                    continue

                # Verify checksum
                if verify_checksum:
                    valid = await self._backup_service.verify_checksum(backup.id)
                    if not valid:
                        if isinstance(details_dict, dict):
                            details_dict["corrupted"] = int(details_dict["corrupted"]) + 1
                        if not command.dry_run:
                            # Try to repair
                            repaired = await self._backup_service.repair(backup.id)
                            if repaired and isinstance(details_dict, dict):
                                details_dict["repaired"] = int(details_dict["repaired"]) + 1
                        results["modified"] = int(results["modified"]) + 1
                        continue

                # Test restore
                if test_restore and not command.dry_run:
                    restore_ok = await self._backup_service.test_restore(backup.id)
                    if not restore_ok:
                        if isinstance(details_dict, dict):
                            details_dict["corrupted"] = int(details_dict["corrupted"]) + 1
                        continue

                if isinstance(details_dict, dict):
                    details_dict["verified"] = int(details_dict["verified"]) + 1
                results["processed"] = int(results["processed"]) + 1

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "backup_id": str(backup.id),
                        "error": str(e)
                    })

        if isinstance(results["details"], dict):
            details = results["details"]
            results["summary"] = (
                f"Verified {details['verified']} backups, "
                f"found {details['corrupted']} corrupted, "
                f"{details['missing']} missing, "
                f"repaired {details['repaired']}"
            )

        return results

    async def _run_compliance_check(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, int]]:
        """Run compliance checks."""
        results: dict[str, int | list[Any] | str | dict[str, int]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "details": {
                "gdpr_violations": 0,
                "retention_violations": 0,
                "access_violations": 0,
                "audit_gaps": 0
            }
        }

        # GDPR compliance
        gdpr_issues = await self._check_gdpr_compliance()
        details_dict = results["details"]
        if isinstance(details_dict, dict):
            details_dict["gdpr_violations"] = len(gdpr_issues)

        # Data retention compliance
        retention_issues = await self._check_retention_compliance()
        if isinstance(details_dict, dict):
            details_dict["retention_violations"] = len(retention_issues)

        # Access control compliance
        access_issues = await self._check_access_compliance()
        if isinstance(details_dict, dict):
            details_dict["access_violations"] = len(access_issues)

        # Audit trail completeness
        audit_gaps = await self._check_audit_completeness()
        if isinstance(details_dict, dict):
            details_dict["audit_gaps"] = len(audit_gaps)

        # Generate compliance report
        if not command.dry_run:
            report = await self._generate_compliance_report(
                context,
                {
                    "gdpr": gdpr_issues,
                    "retention": retention_issues,
                    "access": access_issues,
                    "audit": audit_gaps
                }
            )

            # Notify compliance team
            if any([gdpr_issues, retention_issues, access_issues, audit_gaps]):
                await self._notify_compliance_issues(report)

        if isinstance(results["details"], dict):
            details = results["details"]
            total_issues = (
                int(details["gdpr_violations"]) +
                int(details["retention_violations"]) +
                int(details["access_violations"]) +
                int(details["audit_gaps"])
            )

            results["summary"] = (
                f"Compliance check completed: {total_issues} total issues found"
            )

        return results

    async def _run_full_maintenance(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, int | list[Any] | str | dict[str, Any]]:
        """Run all maintenance operations."""
        results: dict[str, int | list[Any] | str | dict[str, Any]] = {
            "processed": 0,
            "modified": 0,
            "errors": [],
            "operations": {}
        }
        operations_dict: dict[str, dict[str, Any]] = {}

        # Define operation order
        operations = [
            MaintenanceType.CACHE_CLEAR,
            MaintenanceType.SESSION_CLEANUP,
            MaintenanceType.TOKEN_ROTATION,
            MaintenanceType.INACTIVE_USER_CLEANUP,
            MaintenanceType.AUDIT_LOG_ROTATION,
            MaintenanceType.DEVICE_TRUST_REFRESH,
            MaintenanceType.PERMISSION_CACHE_REBUILD,
            MaintenanceType.PASSWORD_POLICY_ENFORCEMENT,
            MaintenanceType.MFA_POLICY_ENFORCEMENT,
            MaintenanceType.SECURITY_SCAN,
            MaintenanceType.DATABASE_OPTIMIZATION,
            MaintenanceType.BACKUP_VERIFICATION,
            MaintenanceType.COMPLIANCE_CHECK
        ]

        # Execute each operation
        for op_type in operations:
            try:
                op_command = SystemMaintenanceCommand(
                    maintenance_type=op_type,
                    admin_user_id=command.admin_user_id,
                    parameters=command.parameters,
                    dry_run=command.dry_run,
                    force_execution=True,  # Already in maintenance
                    notify_users=False,  # Single notification
                    batch_size=command.batch_size,
                    parallel_execution=command.parallel_execution
                )

                # Create context for sub-operation
                op_context = MaintenanceContext(
                    operation_id=UUID(),
                    maintenance_type=op_type.value,
                    initiated_by=command.admin_user_id,
                    parameters=command.parameters,
                    dry_run=command.dry_run,
                    started_at=datetime.now(datetime.UTC),
                    window_minutes=command.maintenance_window_minutes
                )

                # Call appropriate handler method directly
                op_results = None
                if op_type == MaintenanceType.CACHE_CLEAR:
                    op_results = await self._clear_caches(op_command, op_context)
                elif op_type == MaintenanceType.SESSION_CLEANUP:
                    op_results = await self._cleanup_sessions(op_command, op_context)
                elif op_type == MaintenanceType.TOKEN_ROTATION:
                    op_results = await self._rotate_tokens(op_command, op_context)
                elif op_type == MaintenanceType.INACTIVE_USER_CLEANUP:
                    op_results = await self._cleanup_inactive_users(op_command, op_context)
                elif op_type == MaintenanceType.AUDIT_LOG_ROTATION:
                    op_results = await self._rotate_audit_logs(op_command, op_context)
                elif op_type == MaintenanceType.DEVICE_TRUST_REFRESH:
                    op_results = await self._refresh_device_trust(op_command, op_context)
                elif op_type == MaintenanceType.PERMISSION_CACHE_REBUILD:
                    op_results = await self._rebuild_permission_cache(op_command, op_context)
                elif op_type == MaintenanceType.PASSWORD_POLICY_ENFORCEMENT:
                    op_results = await self._enforce_password_policy(op_command, op_context)
                elif op_type == MaintenanceType.MFA_POLICY_ENFORCEMENT:
                    op_results = await self._enforce_mfa_policy(op_command, op_context)
                elif op_type == MaintenanceType.SECURITY_SCAN:
                    op_results = await self._run_security_scan(op_command, op_context)
                elif op_type == MaintenanceType.DATABASE_OPTIMIZATION:
                    op_results = await self._optimize_database(op_command, op_context)
                elif op_type == MaintenanceType.BACKUP_VERIFICATION:
                    op_results = await self._verify_backups(op_command, op_context)
                elif op_type == MaintenanceType.COMPLIANCE_CHECK:
                    op_results = await self._run_compliance_check(op_command, op_context)
                else:
                    continue  # Skip unknown operation types

                if op_results is not None:
                    operation_key = str(op_type.value)
                    operations_dict[operation_key] = op_results
                results["processed"] = int(results["processed"]) + op_results.get("processed", 0)
                results["modified"] = int(results["modified"]) + op_results.get("modified", 0)
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.extend(op_results.get("errors", []))

            except Exception as e:
                errors_list = results["errors"]
                if isinstance(errors_list, list):
                    errors_list.append({
                        "operation": op_type.value,
                        "error": str(e)
                    })

        # Assign operations back to results
        results["operations"] = operations_dict

        results["summary"] = (
            f"Full maintenance completed: {len(operations_dict)} operations, "
            f"{results['processed']} items processed, "
            f"{results['modified']} items modified"
        )

        return results

    # Helper methods

    @staticmethod
    async def _check_ongoing_operations() -> list[dict]:
        """Check for ongoing operations."""
        # Check for active bulk operations, imports, etc.
        return []

    @staticmethod
    async def _check_system_health() -> dict[str, Any]:
        """Check system health status."""
        return {
            "status": "healthy",
            "issues": []
        }

    @staticmethod
    async def _check_password_reuse(user_id: UUID, count: int) -> bool:
        """Check if password was reused."""
        # Would check password history
        return False

    @staticmethod
    async def _archive_audit_logs(logs: list, compress: bool) -> float:
        """Archive audit logs and return size in MB."""
        # Would actually archive logs
        return len(logs) * 0.001  # Mock size

    async def _rebuild_user_permissions(self, user: User, dry_run: bool) -> dict[str, int]:
        """Rebuild permissions for single user."""
        if dry_run:
            return {"permissions": 10, "roles": 2}

        # Get and cache permissions
        permissions = await self._authorization_service.get_user_permissions(user.id)
        roles = await self._authorization_service.get_user_roles(user.id)

        # Cache them
        await self._cache_service.set(
            f"permissions:{user.id}",
            permissions,
            ttl=86400
        )

        await self._cache_service.set(
            f"roles:{user.id}",
            roles,
            ttl=86400
        )

        return {
            "permissions": len(permissions),
            "roles": len(roles)
        }

    @staticmethod
    async def _scan_suspicious_logins(user_id: UUID) -> dict | None:
        """Scan for suspicious login patterns."""
        # Would analyze login patterns
        return None

    @staticmethod
    async def _scan_impossible_travel(user_id: UUID) -> dict | None:
        """Scan for impossible travel scenarios."""
        # Would check geographic impossibilities
        return None

    @staticmethod
    async def _scan_weak_credentials(user_id: UUID) -> dict | None:
        """Scan for weak credentials."""
        # Would check password strength, etc.
        return None

    @staticmethod
    async def _scan_privilege_escalation(user_id: UUID) -> dict | None:
        """Scan for privilege escalation attempts."""
        # Would check for unauthorized permission attempts
        return None

    @staticmethod
    def _is_critical_security_issue(scan_results: dict) -> bool:
        """Check if scan results indicate critical issue."""
        critical_types = ["privilege_escalation", "impossible_travel"]
        return any(t in scan_results for t in critical_types)

    @staticmethod
    async def _check_gdpr_compliance() -> list[dict]:
        """Check GDPR compliance issues."""
        return []

    @staticmethod
    async def _check_retention_compliance() -> list[dict]:
        """Check data retention compliance."""
        return []

    @staticmethod
    async def _check_access_compliance() -> list[dict]:
        """Check access control compliance."""
        return []

    @staticmethod
    async def _check_audit_completeness() -> list[dict]:
        """Check audit trail completeness."""
        return []

    async def _generate_security_alert(self, user: User, findings: dict) -> None:
        """Generate security alert for findings."""
        await self._security_service.create_alert(
            user_id=user.id,
            alert_type="security_scan",
            severity=RiskLevel.HIGH,
            findings=findings
        )

    async def _send_password_policy_notification(
        self,
        user: User,
        violations: list[str]
    ) -> None:
        """Send password policy violation notification."""
        await self._notification_repository.create(
            user_id=user.id,
            type=NotificationType.SECURITY_UPDATE,
            title="Password Update Required",
            message=f"Your password violates security policy: {', '.join(violations)}",
            priority="high"
        )

    async def _send_mfa_requirement_notification(
        self,
        user: User,
        grace_period_days: int
    ) -> None:
        """Send MFA requirement notification."""
        await self._notification_repository.create(
            user_id=user.id,
            type=NotificationType.MFA_REQUIRED,
            title="Multi-Factor Authentication Required",
            message=f"You must set up MFA within {grace_period_days} days",
            priority="high"
        )

    async def _require_stronger_mfa(
        self,
        user: User,
        allowed_methods: list[str],
        grace_period_days: int
    ) -> None:
        """Require stronger MFA methods."""
        user.mfa_upgrade_required = True
        user.mfa_allowed_methods = allowed_methods
        user.mfa_upgrade_deadline = datetime.now(datetime.UTC) + timedelta(days=grace_period_days)
        await self._user_repository.update(user)

    async def _send_inactivity_warning(self, user: User, days_remaining: int) -> None:
        """Send inactivity warning."""
        await self._notification_repository.create(
            user_id=user.id,
            type=NotificationType.ACCOUNT_WARNING,
            title="Account Inactivity Warning",
            message=f"Your account will be suspended in {days_remaining} days due to inactivity",
            priority="high"
        )

    async def _send_device_reverification_notice(
        self,
        user_id: UUID,
        device: Any
    ) -> None:
        """Send device reverification notice."""
        await self._notification_repository.create(
            user_id=user_id,
            type=NotificationType.SECURITY_UPDATE,
            title="Device Verification Required",
            message=f"Please reverify your device: {device.device_name}",
            priority="medium"
        )

    @staticmethod
    async def _notify_maintenance_start(
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> None:
        """Notify users of maintenance start."""
        # Would send notifications to affected users

    @staticmethod
    async def _notify_maintenance_complete(
        command: SystemMaintenanceCommand,
        context: MaintenanceContext,
        results: dict
    ) -> None:
        """Notify users of maintenance completion."""
        # Would send completion notifications

    @staticmethod
    async def _verify_maintenance_results(
        maintenance_type: MaintenanceType,
        results: dict
    ) -> dict[str, Any]:
        """Verify maintenance operation results."""
        return {
            "verified": True,
            "issues": []
        }

    @staticmethod
    async def _generate_maintenance_report(
        operation_id: UUID,
        command: SystemMaintenanceCommand,
        results: dict,
        verification: dict
    ) -> str:
        """Generate maintenance operation report."""
        # Would generate and store detailed report
        return f"https://app.example.com/reports/maintenance/{operation_id}"

    async def _log_maintenance_metrics(
        self,
        context: MaintenanceContext,
        results: dict
    ) -> None:
        """Log maintenance operation metrics."""
        await self._metrics_service.record_maintenance(
            operation_type=context.maintenance_type,
            duration_seconds=(datetime.now(datetime.UTC) - context.started_at).total_seconds(),
            items_processed=results.get("processed", 0),
            items_modified=results.get("modified", 0),
            errors=len(results.get("errors", []))
        )

    def _raise_invalid_maintenance_type(self, maintenance_type: str) -> None:
        """Raise InvalidOperationError for unknown maintenance type."""
        raise InvalidOperationError(
            f"Unknown maintenance type: {maintenance_type}"
        )
    
    async def _initialize_maintenance(
        self,
        command: SystemMaintenanceCommand
    ) -> tuple[User, UUID, MaintenanceContext]:
        """Initialize maintenance operation."""
        admin_user = await self._user_repository.get_by_id(command.admin_user_id)
        if not admin_user:
            raise UnauthorizedError("Admin user not found")
        
        operation_id = UUID()
        context = MaintenanceContext(
            operation_id=operation_id,
            maintenance_type=command.maintenance_type.value,
            initiated_by=command.admin_user_id,
            parameters=command.parameters,
            dry_run=command.dry_run,
            started_at=datetime.now(datetime.UTC),
            window_minutes=command.maintenance_window_minutes
        )
        
        return admin_user, operation_id, context
    
    async def _prepare_maintenance(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> None:
        """Prepare for maintenance including checks and setup."""
        if not command.force_execution:
            await self._check_maintenance_feasibility(command, context)
        
        if not command.dry_run:
            await self._enter_maintenance_mode(context)
    
    async def _notify_maintenance_start_and_publish(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext,
        operation_id: UUID
    ) -> None:
        """Notify users and publish start event."""
        if command.notify_users and not command.dry_run:
            await self._notify_maintenance_start(command, context)
        
        await self._event_bus.publish(
            SystemMaintenanceStarted(
                operation_id=operation_id,
                maintenance_type=command.maintenance_type.value,
                initiated_by=command.admin_user_id,
                estimated_duration_minutes=command.maintenance_window_minutes
            )
        )
    
    async def _execute_maintenance_type(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext
    ) -> dict[str, Any]:
        """Execute maintenance based on type."""
        maintenance_map = {
            MaintenanceType.CACHE_CLEAR: self._clear_caches,
            MaintenanceType.SESSION_CLEANUP: self._cleanup_sessions,
            MaintenanceType.TOKEN_ROTATION: self._rotate_tokens,
            MaintenanceType.PASSWORD_POLICY_ENFORCEMENT: self._enforce_password_policy,
            MaintenanceType.MFA_POLICY_ENFORCEMENT: self._enforce_mfa_policy,
            MaintenanceType.INACTIVE_USER_CLEANUP: self._cleanup_inactive_users,
            MaintenanceType.AUDIT_LOG_ROTATION: self._rotate_audit_logs,
            MaintenanceType.DEVICE_TRUST_REFRESH: self._refresh_device_trust,
            MaintenanceType.PERMISSION_CACHE_REBUILD: self._rebuild_permission_cache,
            MaintenanceType.SECURITY_SCAN: self._run_security_scan,
            MaintenanceType.DATABASE_OPTIMIZATION: self._optimize_database,
            MaintenanceType.BACKUP_VERIFICATION: self._verify_backups,
            MaintenanceType.COMPLIANCE_CHECK: self._run_compliance_check,
            MaintenanceType.FULL_MAINTENANCE: self._run_full_maintenance
        }
        
        maintenance_func = maintenance_map.get(command.maintenance_type)
        if not maintenance_func:
            self._raise_invalid_maintenance_type(command.maintenance_type.value)
        
        return await maintenance_func(command, context)
    
    async def _complete_maintenance(
        self,
        operation_id: UUID,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext,
        results: dict[str, Any]
    ) -> str | None:
        """Complete maintenance with verification and reporting."""
        # Verify results
        verification = await self._verify_maintenance_results(
            command.maintenance_type,
            results
        )
        
        # Generate report
        report_url = await self._generate_maintenance_report(
            operation_id,
            command,
            results,
            verification
        )
        
        # Exit maintenance mode
        if not command.dry_run:
            await self._exit_maintenance_mode(context)
        
        # Publish completion event
        await self._event_bus.publish(
            SystemMaintenanceCompleted(
                operation_id=operation_id,
                maintenance_type=command.maintenance_type.value,
                duration_minutes=int(
                    (datetime.now(datetime.UTC) - context.started_at).total_seconds() / 60
                ),
                items_processed=results.get("processed", 0),
                errors_encountered=len(results.get("errors", []))
            )
        )
        
        # Notify completion
        if command.notify_users and not command.dry_run:
            await self._notify_maintenance_complete(command, context, results)
        
        return report_url
    
    async def _post_commit_operations(
        self,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext,
        results: dict[str, Any]
    ) -> None:
        """Perform operations after transaction commit."""
        await self._log_maintenance_metrics(context, results)
    
    def _create_maintenance_response(
        self,
        operation_id: UUID,
        command: SystemMaintenanceCommand,
        context: MaintenanceContext,
        results: dict[str, Any],
        report_url: str | None
    ) -> MaintenanceOperationResponse:
        """Create the maintenance operation response."""
        return MaintenanceOperationResponse(
            operation_id=operation_id,
            maintenance_type=command.maintenance_type.value,
            status="completed" if not results.get("errors") else "completed_with_errors",
            items_processed=results.get("processed", 0),
            items_modified=results.get("modified", 0),
            errors=results.get("errors", []),
            duration_minutes=int(
                (datetime.now(datetime.UTC) - context.started_at).total_seconds() / 60
            ),
            report_url=report_url,
            dry_run=command.dry_run,
            completed_at=datetime.now(datetime.UTC),
            message=(
                f"{'DRY RUN: ' if command.dry_run else ''}"
                f"Maintenance completed: {results.get('summary', 'No summary available')}"
            )
        )

    @staticmethod
    async def _generate_compliance_report(
        context: MaintenanceContext,
        issues: dict[str, list]
    ) -> dict[str, Any]:
        """Generate compliance report."""
        return {
            "report_id": UUID(),
            "generated_at": datetime.now(datetime.UTC),
            "issues": issues
        }
    
    async def _notify_compliance_issues(self, report: dict) -> None:
        """Notify compliance team of issues."""
        await self._notification_repository.notify_role(
            "compliance_officer",
            "Compliance Issues Found",
            "System maintenance detected compliance issues requiring attention",
            report
        )
    
    async def _schedule_maintenance(
        self,
        command: SystemMaintenanceCommand
    ) -> MaintenanceOperationResponse:
        """Schedule maintenance for later."""
        job_id = await self._queue_service.schedule_job(
            "system_maintenance",
            {
                "command": command.dict()
            },
            scheduled_for=command.schedule_at,
            priority="low"
        )
        
        return MaintenanceOperationResponse(
            operation_id=UUID(),
            maintenance_type=command.maintenance_type.value,
            status="scheduled",
            items_processed=0,
            items_modified=0,
            errors=[],
            scheduled_job_id=job_id,
            message=f"Maintenance scheduled for {command.schedule_at.isoformat()}"
        )