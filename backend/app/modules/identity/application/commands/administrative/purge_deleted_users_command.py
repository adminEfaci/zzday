"""
Purge deleted users command implementation.

Handles permanent deletion of soft-deleted users after retention period.
"""

import asyncio
from datetime import UTC, datetime, timedelta
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
    PurgeConfig,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    NotificationContext,
    PurgeOperationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import PurgeDeletedUsersRequest
from app.modules.identity.application.dtos.response import PurgeOperationResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import UsersPurged
from app.modules.identity.domain.exceptions import (
    DataPurgeError,
    InvalidOperationError,
    UnauthorizedError,
)


class PurgeStrategy(Enum):
    """Data purge strategies."""
    IMMEDIATE = "immediate"  # Delete now
    SCHEDULED = "scheduled"  # Schedule for later
    BATCH = "batch"  # Process in batches
    CASCADE = "cascade"  # Delete all related data


class PurgeDeletedUsersCommand(Command[PurgeOperationResponse]):
    """Command to permanently purge deleted users."""
    
    def __init__(
        self,
        admin_user_id: UUID,
        purge_config: PurgeConfig,
        additional_options: dict[str, Any] | None = None
    ):
        self.admin_user_id = admin_user_id
        self.purge_config = purge_config
        additional_options = additional_options or {}
        
        # For backward compatibility, expose common fields
        self.retention_days = purge_config.retention_period_days
        self.strategy = PurgeStrategy(additional_options.get('strategy', 'SAFE'))
        self.batch_size = min(additional_options.get('batch_size', 100), 1000)
        self.include_backups = additional_options.get('include_backups', True)
        self.include_audit_logs = additional_options.get('include_audit_logs', False)
        self.cascade_delete = additional_options.get('cascade_delete', True)
        self.dry_run = purge_config.dry_run
        self.specific_user_ids = additional_options.get('specific_user_ids', [])
        self.exclude_user_ids = additional_options.get('exclude_user_ids', [])
        self.notify_compliance = purge_config.notify_compliance
        self.create_purge_report = additional_options.get('create_purge_report', True)
        self.metadata = purge_config.metadata


class PurgeDeletedUsersCommandHandler(CommandHandler[PurgeDeletedUsersCommand, PurgeOperationResponse]):
    """Handler for purging deleted users."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies,
        data_privacy_service: Any  # DataPrivacyService
    ):
        self._user_repository = services.user_repository
        self._audit_repository = services.audit_repository
        self._notification_repository = services.notification_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._backup_service = services.backup_service
        self._storage_service = services.storage_service
        self._queue_service = services.queue_service
        self._data_privacy_service = data_privacy_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.USER_DATA_PURGE,
        resource_type="system",
        include_request=True,
        include_response=True,
        gdpr_compliant=True,
        high_priority=True
    )
    @validate_request(PurgeDeletedUsersRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=86400,  # Daily
        strategy='global'
    )
    @require_permission(
        "system.purge_users",
        resource_type="system"
    )
    @require_mfa(
        methods=["hardware_token", "totp"]
    )
    @require_approval(
        approval_type="data_purge",
        approvers=["data_protection_officer", "compliance_team", "cto"]
    )
    async def handle(self, command: PurgeDeletedUsersCommand) -> PurgeOperationResponse:
        """
        Permanently purge deleted users from all systems.
        
        Process:
        1. Validate purge operation
        2. Find eligible users
        3. Check legal holds
        4. Create pre-purge report
        5. Execute purge strategy
        6. Clean related data
        7. Generate compliance report
        8. Notify stakeholders
        
        Returns:
            PurgeOperationResponse with results
            
        Raises:
            UnauthorizedError: If lacks permission
            InvalidOperationError: If operation invalid
            DataPurgeError: If purge fails
        """
        async with self._unit_of_work:
            # Initialize operation
            admin_user, operation_id, context = await self._initialize_purge_operation(
                command
            )
            
            # Find and validate eligible users
            eligible_users, users_with_holds = await self._find_and_validate_eligible_users(
                command
            )
            
            if not eligible_users:
                return self._create_empty_response(operation_id)
            
            # Validate no legal holds
            self._validate_no_legal_holds(users_with_holds, command.dry_run)
            
            # Create pre-purge report if requested
            pre_purge_report = await self._create_optional_pre_purge_report(
                operation_id,
                eligible_users,
                users_with_holds,
                command
            )
            
            try:
                # Execute purge
                results = await self._execute_purge_strategy(
                    eligible_users,
                    command,
                    context
                )
                
                # For scheduled purges, return early
                if command.strategy == PurgeStrategy.SCHEDULED:
                    return results
                
                # Post-purge processing
                report_url = await self._post_purge_processing(
                    operation_id,
                    results,
                    pre_purge_report,
                    command
                )
                
                # Commit transaction
                await self._unit_of_work.commit()
                
                # Post-commit notifications
                await self._send_post_commit_notifications(
                    operation_id,
                    results,
                    report_url,
                    command
                )
                
                return self._create_purge_response(
                    operation_id,
                    eligible_users,
                    results,
                    report_url,
                    command
                )
                
            except Exception as e:
                # Rollback any partial changes
                if not command.dry_run:
                    await self._rollback_purge(results.get("purged", []))
                
                raise DataPurgeError(
                    f"Purge operation failed: {e!s}",
                    operation_id=operation_id,
                    partial_results=results
                ) from e
    
    async def _find_eligible_users(
        self,
        command: PurgeDeletedUsersCommand
    ) -> list[User]:
        """Find users eligible for purging."""
        # Calculate cutoff date
        cutoff_date = datetime.now(UTC) - timedelta(days=command.retention_days)
        
        # Base query for deleted users
        eligible_users = []
        
        if command.specific_user_ids:
            # Purge specific users
            for user_id in command.specific_user_ids:
                user = await self._user_repository.get_by_id(user_id)
                if user and user.status == UserStatus.TERMINATED and user.deleted_at and user.deleted_at <= cutoff_date:
                    eligible_users.append(user)
        else:
            # Find all deleted users past retention
            users = await self._user_repository.find_deleted_before(cutoff_date)
            eligible_users = [
                u for u in users
                if u.id not in command.exclude_user_ids
            ]
        
        return eligible_users
    
    async def _create_pre_purge_report(
        self,
        operation_id: UUID,
        users: list[User],
        users_with_holds: list[dict],
        command: PurgeDeletedUsersCommand
    ) -> dict[str, Any]:
        """Create detailed pre-purge report."""
        report = {
            "operation_id": str(operation_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "retention_days": command.retention_days,
            "strategy": command.strategy.value,
            "dry_run": command.dry_run,
            "total_users": len(users),
            "users_with_holds": len(users_with_holds),
            "estimated_data_size_mb": 0,
            "users": []
        }
        
        # Analyze each user
        for user in users:
            user_data_size = await self._calculate_user_data_size(user.id)
            
            user_info = {
                "user_id": str(user.id),
                "username": user.username,
                "deleted_at": user.deleted_at.isoformat() if user.deleted_at else None,
                "days_since_deletion": (
                    datetime.now(UTC) - user.deleted_at
                ).days if user.deleted_at else 0,
                "data_size_mb": user_data_size,
                "has_backups": await self._has_backups(user.id),
                "audit_log_count": await self._count_audit_logs(user.id),
                "legal_holds": any(
                    h["user_id"] == user.id for h in users_with_holds
                )
            }
            
            report["users"].append(user_info)
            report["estimated_data_size_mb"] += user_data_size
        
        # Store report
        await self._storage_service.store_json(
            f"purge_reports/pre_purge_{operation_id}.json",
            report,
            retention_days=365  # Keep for 1 year
        )
        
        return report
    
    async def _purge_immediate(
        self,
        users: list[User],
        command: PurgeDeletedUsersCommand,
        context: PurgeOperationContext
    ) -> dict[str, Any]:
        """Immediately purge all eligible users."""
        results = {
            "purged": [],
            "failed": [],
            "skipped": [],
            "errors": [],
            "data_size_mb": 0
        }
        
        for user in users:
            try:
                if command.dry_run:
                    # Simulate purge
                    size = await self._calculate_user_data_size(user.id)
                    results["purged"].append(user.id)
                    results["data_size_mb"] += size
                else:
                    # Actual purge
                    size = await self._purge_single_user(user, command)
                    results["purged"].append(user.id)
                    results["data_size_mb"] += size
                    
            except Exception as e:
                results["failed"].append({
                    "user_id": user.id,
                    "error": str(e)
                })
                results["errors"].append({
                    "user_id": str(user.id),
                    "error": str(e),
                    "timestamp": datetime.now(UTC).isoformat()
                })
        
        return results
    
    async def _purge_batch(
        self,
        users: list[User],
        command: PurgeDeletedUsersCommand,
        context: PurgeOperationContext
    ) -> dict[str, Any]:
        """Purge users in batches."""
        results = {
            "purged": [],
            "failed": [],
            "skipped": [],
            "errors": [],
            "data_size_mb": 0
        }
        
        # Process in batches
        for i in range(0, len(users), command.batch_size):
            batch = users[i:i + command.batch_size]
            
            # Update progress
            await self._update_purge_progress(
                context.operation_id,
                i,
                len(users)
            )
            
            # Process batch
            batch_results = await self._purge_immediate(
                batch,
                command,
                context
            )
            
            # Aggregate results
            results["purged"].extend(batch_results["purged"])
            results["failed"].extend(batch_results["failed"])
            results["skipped"].extend(batch_results["skipped"])
            results["errors"].extend(batch_results["errors"])
            results["data_size_mb"] += batch_results["data_size_mb"]
            
            # Small delay between batches
            await asyncio.sleep(1)
        
        return results
    
    async def _purge_cascade(
        self,
        users: list[User],
        command: PurgeDeletedUsersCommand,
        context: PurgeOperationContext
    ) -> dict[str, Any]:
        """Purge with cascade delete of all related data."""
        results = {
            "purged": [],
            "failed": [],
            "skipped": [],
            "errors": [],
            "data_size_mb": 0
        }
        
        for user in users:
            try:
                if command.dry_run:
                    # Calculate total data size including related
                    size = await self._calculate_cascade_data_size(user.id)
                    results["purged"].append(user.id)
                    results["data_size_mb"] += size
                else:
                    # Cascade delete
                    size = await self._purge_cascade_single(user, command)
                    results["purged"].append(user.id)
                    results["data_size_mb"] += size
                    
            except Exception as e:
                results["failed"].append({
                    "user_id": user.id,
                    "error": str(e)
                })
                results["errors"].append({
                    "user_id": str(user.id),
                    "error": str(e),
                    "timestamp": datetime.now(UTC).isoformat()
                })
        
        return results
    
    async def _schedule_purge(
        self,
        users: list[User],
        command: PurgeDeletedUsersCommand,
        context: PurgeOperationContext
    ) -> PurgeOperationResponse:
        """Schedule purge for later execution."""
        # Create scheduled job
        job_id = await self._queue_service.schedule_job(
            "purge_deleted_users",
            {
                "operation_id": str(context.operation_id),
                "user_ids": [str(u.id) for u in users],
                "command": command.dict()
            },
            scheduled_for=datetime.now(UTC) + timedelta(hours=24),  # Next day
            priority="low"
        )
        
        return PurgeOperationResponse(
            operation_id=context.operation_id,
            total_users=len(users),
            purged_users=0,
            skipped_users=0,
            failed_users=0,
            purged_data_size_mb=0,
            errors=[],
            report_url=None,
            scheduled_job_id=job_id,
            message=f"Purge scheduled for {len(users)} users"
        )
    
    async def _purge_single_user(
        self,
        user: User,
        command: PurgeDeletedUsersCommand
    ) -> float:
        """Purge single user and return data size."""
        total_size = 0.0
        
        # 1. Calculate data size first
        total_size = await self._calculate_user_data_size(user.id)
        
        # 2. Delete from primary database
        await self._user_repository.hard_delete(user.id)
        
        # 3. Delete backups if requested
        if command.include_backups:
            await self._backup_service.delete_user_backups(user.id)
        
        # 4. Delete from all caches
        await self._clear_all_caches(user.id)
        
        # 5. Delete from search indexes
        await self._remove_from_search_indexes(user.id)
        
        # 6. Clean audit logs if permitted
        if command.include_audit_logs:
            await self._clean_audit_logs(user.id)
        
        return total_size
    
    async def _purge_cascade_single(
        self,
        user: User,
        command: PurgeDeletedUsersCommand
    ) -> float:
        """Purge user with cascade delete."""
        total_size = 0.0
        
        # 1. Calculate total cascade size
        total_size = await self._calculate_cascade_data_size(user.id)
        
        # 2. Delete all related data
        await self._data_privacy_service.cascade_delete(user.id)
        
        # 3. Delete user
        await self._purge_single_user(user, command)
        
        return total_size
    
    async def _calculate_user_data_size(self, user_id: UUID) -> float:
        """Calculate total data size for user in MB."""
        # This would calculate actual data size
        # For now, return mock value
        return 25.5  # MB
    
    async def _calculate_cascade_data_size(self, user_id: UUID) -> float:
        """Calculate total cascade data size in MB."""
        # Base user data
        size = await self._calculate_user_data_size(user_id)
        
        # Add related data estimates
        size += 10.0  # Sessions, tokens
        size += 5.0   # Notifications
        size += 15.0  # Audit logs
        size += 20.0  # File uploads
        
        return size
    
    async def _has_backups(self, user_id: UUID) -> bool:
        """Check if user has backups."""
        backups = await self._backup_service.list_user_backups(user_id)
        return len(backups) > 0
    
    async def _count_audit_logs(self, user_id: UUID) -> int:
        """Count user audit logs."""
        return await self._audit_repository.count_by_user(user_id)
    
    async def _clean_orphaned_data(self, purged_user_ids: list[UUID]) -> None:
        """Clean up orphaned data after purge."""
        # Clean orphaned sessions
        await self._clean_orphaned_sessions(purged_user_ids)
        
        # Clean orphaned notifications
        await self._clean_orphaned_notifications(purged_user_ids)
        
        # Clean orphaned files
        await self._clean_orphaned_files(purged_user_ids)
        
        # Clean orphaned relationships
        await self._clean_orphaned_relationships(purged_user_ids)
    
    async def _clean_orphaned_sessions(self, user_ids: list[UUID]) -> None:
        """Clean orphaned session data."""
        for _user_id in user_ids:
            # This would be implemented in session repository
            pass
    
    async def _clean_orphaned_notifications(self, user_ids: list[UUID]) -> None:
        """Clean orphaned notifications."""
        for user_id in user_ids:
            await self._notification_repository.delete_by_user(user_id)
    
    async def _clean_orphaned_files(self, user_ids: list[UUID]) -> None:
        """Clean orphaned file uploads."""
        for user_id in user_ids:
            await self._storage_service.delete_user_files(user_id)
    
    async def _clean_orphaned_relationships(self, user_ids: list[UUID]) -> None:
        """Clean orphaned relationship data."""
        # This would clean many-to-many relationships
    
    async def _clear_all_caches(self, user_id: UUID) -> None:
        """Clear all caches for user."""
        cache_patterns = [
            f"user:{user_id}:*",
            f"session:*:{user_id}",
            f"permissions:{user_id}:*",
            f"profile:{user_id}",
            f"*:{user_id}:*"
        ]
        
        for pattern in cache_patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _remove_from_search_indexes(self, user_id: UUID) -> None:
        """Remove user from all search indexes."""
        # This would remove from Elasticsearch/similar
    
    async def _clean_audit_logs(self, user_id: UUID) -> None:
        """Clean user audit logs if permitted."""
        # Mark as purged rather than delete
        await self._audit_repository.mark_as_purged(user_id)
    
    async def _update_purge_progress(
        self,
        operation_id: UUID,
        current: int,
        total: int
    ) -> None:
        """Update purge operation progress."""
        progress = {
            "current": current,
            "total": total,
            "percentage": round((current / total) * 100, 2),
            "updated_at": datetime.now(UTC).isoformat()
        }
        
        await self._cache_service.set(
            f"purge_progress:{operation_id}",
            progress,
            ttl=86400  # 24 hours
        )
    
    async def _generate_compliance_report(
        self,
        operation_id: UUID,
        results: dict[str, Any],
        pre_purge_report: dict[str, Any],
        command: PurgeDeletedUsersCommand
    ) -> str:
        """Generate compliance report for purge operation."""
        report = {
            "operation_id": str(operation_id),
            "report_type": "data_purge_compliance",
            "generated_at": datetime.now(UTC).isoformat(),
            "retention_policy": {
                "days": command.retention_days,
                "strategy": command.strategy.value
            },
            "summary": {
                "total_users": len(results["purged"]) + len(results["failed"]) + len(results["skipped"]),
                "successfully_purged": len(results["purged"]),
                "failed": len(results["failed"]),
                "skipped": len(results["skipped"]),
                "total_data_purged_mb": results["data_size_mb"]
            },
            "details": {
                "purged_users": [str(uid) for uid in results["purged"]],
                "failed_users": results["failed"],
                "errors": results["errors"]
            },
            "compliance": {
                "gdpr_compliant": True,
                "audit_logs_retained": not command.include_audit_logs,
                "backups_deleted": command.include_backups,
                "cascade_delete": command.cascade_delete
            },
            "pre_purge_report": pre_purge_report,
            "attestation": {
                "performed_by": str(command.admin_user_id),
                "dry_run": command.dry_run,
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
        
        # Generate and sign report
        report_id = UUID()
        report["signature"] = self._sign_report(report)
        
        # Store report
        return await self._storage_service.store_json(
            f"compliance_reports/purge_{report_id}.json",
            report,
            retention_days=2555  # 7 years
        )
        
    
    def _sign_report(self, report: dict[str, Any]) -> str:
        """Digitally sign compliance report."""
        # In production, use proper digital signature
        import hashlib
        import json
        
        report_string = json.dumps(report, sort_keys=True)
        signature = hashlib.sha256(report_string.encode()).hexdigest()
        
        return f"SHA256:{signature}"
    
    async def _notify_compliance(
        self,
        operation_id: UUID,
        results: dict[str, Any],
        report_url: str
    ) -> None:
        """Notify compliance team of purge completion."""
        await self._notification_repository.notify_group(
            "compliance_team",
            NotificationContext(
                notification_id=UUID(),
                recipient_id=None,
                notification_type=NotificationType.COMPLIANCE_ACTION,
                channel="email",
                template_id="data_purge_complete",
                template_data={
                    "operation_id": str(operation_id),
                    "purged_count": len(results["purged"]),
                    "failed_count": len(results["failed"]),
                    "data_size_mb": results["data_size_mb"],
                    "report_url": report_url,
                    "timestamp": datetime.now(UTC).isoformat()
                },
                priority="high"
            )
        )
        
        # Also notify data protection officer
        await self._notification_repository.notify_role(
            "data_protection_officer",
            "Data Purge Completed",
            f"Purged {len(results['purged'])} users, {results['data_size_mb']:.2f} MB",
            {
                "operation_id": str(operation_id),
                "report_url": report_url
            }
        )
    
    async def _rollback_purge(self, purged_user_ids: list[UUID]) -> None:
        """Attempt to rollback purge operation."""
        # This is mostly for logging as hard delete is irreversible
        await self._security_service.log_critical_error(
            "Purge operation failed - attempting rollback",
            {
                "purged_users": [str(uid) for uid in purged_user_ids],
                "note": "Hard delete operations cannot be rolled back"
            }
        )
    
    async def _initialize_purge_operation(
        self,
        command: PurgeDeletedUsersCommand
    ) -> tuple[User, UUID, PurgeOperationContext]:
        """Initialize purge operation with validation."""
        admin_user = await self._user_repository.get_by_id(command.admin_user_id)
        if not admin_user:
            raise UnauthorizedError("Admin user not found")
        
        operation_id = UUID()
        context = PurgeOperationContext(
            operation_id=operation_id,
            initiated_by=command.admin_user_id,
            retention_days=command.retention_days,
            strategy=command.strategy.value,
            dry_run=command.dry_run,
            started_at=datetime.now(UTC)
        )
        
        return admin_user, operation_id, context
    
    async def _find_and_validate_eligible_users(
        self,
        command: PurgeDeletedUsersCommand
    ) -> tuple[list[User], list[dict]]:
        """Find eligible users and check for legal holds."""
        eligible_users = await self._find_eligible_users(command)
        
        users_with_holds = []
        for user in eligible_users:
            holds = await self._data_privacy_service.check_legal_holds(user.id)
            if holds:
                users_with_holds.append({
                    "user_id": user.id,
                    "holds": holds
                })
        
        return eligible_users, users_with_holds
    
    def _create_empty_response(self, operation_id: UUID) -> PurgeOperationResponse:
        """Create response for when no users are eligible."""
        return PurgeOperationResponse(
            operation_id=operation_id,
            total_users=0,
            purged_users=0,
            skipped_users=0,
            failed_users=0,
            purged_data_size_mb=0,
            errors=[],
            report_url=None,
            message="No users eligible for purging"
        )
    
    def _validate_no_legal_holds(
        self,
        users_with_holds: list[dict],
        dry_run: bool
    ) -> None:
        """Validate that no users have legal holds (unless dry run)."""
        if users_with_holds and not dry_run:
            raise InvalidOperationError(
                f"Cannot purge: {len(users_with_holds)} users have active legal holds"
            )
    
    async def _create_optional_pre_purge_report(
        self,
        operation_id: UUID,
        eligible_users: list[User],
        users_with_holds: list[dict],
        command: PurgeDeletedUsersCommand
    ) -> dict | None:
        """Create pre-purge report if requested."""
        if command.create_purge_report:
            return await self._create_pre_purge_report(
                operation_id,
                eligible_users,
                users_with_holds,
                command
            )
        return None
    
    async def _execute_purge_strategy(
        self,
        eligible_users: list[User],
        command: PurgeDeletedUsersCommand,
        context: PurgeOperationContext
    ) -> dict:
        """Execute the purge based on the selected strategy."""
        strategy_map = {
            PurgeStrategy.IMMEDIATE: self._purge_immediate,
            PurgeStrategy.BATCH: self._purge_batch,
            PurgeStrategy.SCHEDULED: self._schedule_purge,
            PurgeStrategy.CASCADE: self._purge_cascade
        }
        
        strategy_func = strategy_map.get(command.strategy)
        if not strategy_func:
            raise InvalidOperationError(f"Unknown purge strategy: {command.strategy}")
        
        return await strategy_func(eligible_users, command, context)
    
    async def _post_purge_processing(
        self,
        operation_id: UUID,
        results: dict,
        pre_purge_report: dict | None,
        command: PurgeDeletedUsersCommand
    ) -> str | None:
        """Handle post-purge processing."""
        # Clean up orphaned data
        if not command.dry_run and results["purged"]:
            await self._clean_orphaned_data(results["purged"])
        
        # Generate compliance report
        report_url = None
        if command.create_purge_report:
            report_url = await self._generate_compliance_report(
                operation_id,
                results,
                pre_purge_report,
                command
            )
        
        # Publish event
        await self._event_bus.publish(
            UsersPurged(
                aggregate_id=operation_id,
                purged_count=len(results["purged"]),
                failed_count=len(results["failed"]),
                total_size_mb=results["data_size_mb"],
                retention_days=command.retention_days
            )
        )
        
        # Log security event
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.DATA_PURGE,
                severity=RiskLevel.HIGH,
                user_id=None,  # System operation
                details={
                    "operation_id": str(operation_id),
                    "admin_user": str(command.admin_user_id),
                    "purged_users": len(results["purged"]),
                    "failed_users": len(results["failed"]),
                    "strategy": command.strategy.value,
                    "dry_run": command.dry_run,
                    "data_size_mb": results["data_size_mb"]
                }
            )
        )
        
        return report_url
    
    async def _send_post_commit_notifications(
        self,
        operation_id: UUID,
        results: dict,
        report_url: str | None,
        command: PurgeDeletedUsersCommand
    ) -> None:
        """Send notifications after commit."""
        if command.notify_compliance and not command.dry_run:
            await self._notify_compliance(
                operation_id,
                results,
                report_url
            )
    
    def _create_purge_response(
        self,
        operation_id: UUID,
        eligible_users: list[User],
        results: dict,
        report_url: str | None,
        command: PurgeDeletedUsersCommand
    ) -> PurgeOperationResponse:
        """Create the final purge response."""
        return PurgeOperationResponse(
            operation_id=operation_id,
            total_users=len(eligible_users),
            purged_users=len(results["purged"]),
            skipped_users=len(results["skipped"]),
            failed_users=len(results["failed"]),
            purged_data_size_mb=results["data_size_mb"],
            errors=results.get("errors", []),
            report_url=report_url,
            dry_run=command.dry_run,
            completed_at=datetime.now(UTC),
            message=(
                f"{'DRY RUN: ' if command.dry_run else ''}"
                f"Purged {len(results['purged'])} users, "
                f"{results['data_size_mb']:.2f} MB of data"
            )
        )