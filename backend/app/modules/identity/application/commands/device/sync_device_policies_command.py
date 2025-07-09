"""
Sync device policies command implementation.

Handles synchronizing and applying security policies to devices.
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
    AuditContext,
    EmailContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import SyncDevicePoliciesRequest
from app.modules.identity.application.dtos.response import DevicePolicySyncResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    PolicyEnforcementLevel,
    PolicyScope,
    PolicySyncStatus,
    PolicyType,
    SyncMode,
)
from app.modules.identity.domain.events import DevicePoliciesSynced
from app.modules.identity.domain.exceptions import (
    DeviceNotFoundError,
    PolicyConflictError,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
    IComplianceRepository,
    IDeviceManagementService,
    IDevicePolicyRepository,
    IPolicyTemplateRepository,
)
    ComplianceService,
    DeviceSecurityService,
    PolicyService,
    ValidationService,
)


class SyncDevicePoliciesCommand(Command[DevicePolicySyncResponse]):
    """Command to sync and apply device policies."""
    
    def __init__(
        self,
        device_id: UUID | None = None,
        user_id: UUID | None = None,
        policy_ids: list[UUID] | None = None,
        sync_mode: SyncMode = SyncMode.INCREMENTAL,
        policy_scope: PolicyScope = PolicyScope.ALL,
        enforcement_level: PolicyEnforcementLevel = PolicyEnforcementLevel.ENFORCE,
        force_sync: bool = False,
        validate_compliance: bool = True,
        notify_on_changes: bool = True,
        create_backup: bool = True,
        dry_run: bool = False,
        initiated_by: UUID | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.user_id = user_id
        self.policy_ids = policy_ids or []
        self.sync_mode = sync_mode
        self.policy_scope = policy_scope
        self.enforcement_level = enforcement_level
        self.force_sync = force_sync
        self.validate_compliance = validate_compliance
        self.notify_on_changes = notify_on_changes
        self.create_backup = create_backup
        self.dry_run = dry_run
        self.initiated_by = initiated_by
        self.reason = reason or "Policy synchronization"
        self.metadata = metadata or {}


class SyncDevicePoliciesCommandHandler(CommandHandler[SyncDevicePoliciesCommand, DevicePolicySyncResponse]):
    """Handler for syncing device policies."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        device_policy_repository: IDevicePolicyRepository,
        policy_template_repository: IPolicyTemplateRepository,
        compliance_repository: IComplianceRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        policy_service: PolicyService,
        compliance_service: ComplianceService,
        device_management_service: IDeviceManagementService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._device_policy_repository = device_policy_repository
        self._policy_template_repository = policy_template_repository
        self._compliance_repository = compliance_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._policy_service = policy_service
        self._compliance_service = compliance_service
        self._device_management_service = device_management_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_POLICIES_SYNCED,
        resource_type="device_policy",
        include_request=True,
        include_response=True,
        include_changes=True
    )
    @validate_request(SyncDevicePoliciesRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.sync_policies")
    async def handle(self, command: SyncDevicePoliciesCommand) -> DevicePolicySyncResponse:
        """
        Sync device policies with comprehensive validation and compliance.
        
        Process:
        1. Determine target devices for policy sync
        2. Load current policies and templates
        3. Calculate policy changes and conflicts
        4. Validate policy compliance
        5. Create backup of current policies if requested
        6. Apply policies based on enforcement level
        7. Update device policy assignments
        8. Validate post-sync compliance
        9. Send notifications if changes made
        10. Log policy sync operations
        
        Returns:
            DevicePolicySyncResponse with sync operation details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If sync not authorized
            PolicySyncFailedException: If sync fails
            PolicyConflictError: If policy conflicts detected
            ComplianceViolationError: If compliance violated
        """
        async with self._unit_of_work:
            # 1. Determine target devices
            target_devices = await self._determine_target_devices(command)
            
            if not target_devices:
                raise DeviceNotFoundError("No devices found matching sync criteria")
            
            # 2. Load users for devices
            user_ids = list({device.user_id for device in target_devices})
            users = {
                user.id: user
                for user in await self._user_repository.find_by_ids(user_ids)
            }
            
            # 3. Load applicable policies
            applicable_policies = await self._load_applicable_policies(
                target_devices,
                users,
                command
            )
            
            # 4. Calculate sync operations for each device
            sync_operations = []
            for device in target_devices:
                user = users[device.user_id]
                device_sync_op = await self._calculate_device_sync_operation(
                    device,
                    user,
                    applicable_policies,
                    command
                )
                sync_operations.append(device_sync_op)
            
            # 5. Validate sync operations for conflicts
            conflict_analysis = await self._analyze_policy_conflicts(sync_operations)
            if conflict_analysis["has_conflicts"] and not command.force_sync:
                raise PolicyConflictError(
                    f"Policy conflicts detected: {', '.join(conflict_analysis['conflicts'])}"
                )
            
            # 6. Create backups if requested
            backup_ids = []
            if command.create_backup and not command.dry_run:
                for device in target_devices:
                    backup_id = await self._create_policy_backup(device, command)
                    backup_ids.append(backup_id)
            
            # 7. Execute sync operations (unless dry run)
            sync_results = []
            if not command.dry_run:
                for sync_op in sync_operations:
                    result = await self._execute_device_policy_sync(sync_op, command)
                    sync_results.append(result)
            else:
                # For dry run, simulate the results
                sync_results = [self._simulate_sync_result(op) for op in sync_operations]
            
            # 8. Validate post-sync compliance
            compliance_results = []
            if command.validate_compliance and not command.dry_run:
                for device in target_devices:
                    compliance_result = await self._validate_device_compliance(
                        device,
                        users[device.user_id]
                    )
                    compliance_results.append(compliance_result)
            
            # 9. Send notifications for significant changes
            notifications_sent = []
            if command.notify_on_changes and not command.dry_run:
                changes_made = any(result["changes_made"] for result in sync_results)
                if changes_made:
                    notifications_sent = await self._send_policy_sync_notifications(
                        target_devices,
                        users,
                        sync_results,
                        command
                    )
            
            # 10. Log sync operations
            if not command.dry_run:
                await self._log_policy_sync_operations(
                    target_devices,
                    users,
                    sync_results,
                    command
                )
            
            # 11. Publish domain event
            if not command.dry_run:
                await self._event_bus.publish(
                    DevicePoliciesSynced(
                        device_ids=[device.id for device in target_devices],
                        user_ids=list(user_ids),
                        policies_synced=sum(len(result["policies_applied"]) for result in sync_results),
                        sync_mode=command.sync_mode,
                        enforcement_level=command.enforcement_level,
                        initiated_by=command.initiated_by,
                        compliance_validated=command.validate_compliance
                    )
                )
            
            # 12. Commit transaction
            if not command.dry_run:
                await self._unit_of_work.commit()
            
            # 13. Calculate summary statistics
            len(target_devices)
            total_policies_applied = sum(len(result["policies_applied"]) for result in sync_results)
            total_policies_removed = sum(len(result["policies_removed"]) for result in sync_results)
            devices_with_changes = sum(1 for result in sync_results if result["changes_made"])
            
            # 14. Return response
            return DevicePolicySyncResponse(
                target_devices=len(target_devices),
                devices_synced=devices_with_changes,
                policies_applied=total_policies_applied,
                policies_removed=total_policies_removed,
                sync_mode=command.sync_mode,
                enforcement_level=command.enforcement_level,
                conflicts_detected=conflict_analysis["has_conflicts"],
                conflicts=conflict_analysis["conflicts"],
                compliance_validated=command.validate_compliance,
                compliance_violations=sum(
                    len(comp.get("violations", [])) for comp in compliance_results
                ),
                backups_created=len(backup_ids),
                backup_ids=backup_ids,
                notifications_sent=notifications_sent,
                dry_run=command.dry_run,
                sync_results=sync_results,
                initiated_by=command.initiated_by,
                synced_at=datetime.now(UTC),
                message=f"Policy sync {'simulated' if command.dry_run else 'completed'} successfully"
            )
    
    async def _determine_target_devices(
        self,
        command: SyncDevicePoliciesCommand
    ) -> list[Device]:
        """Determine which devices to sync policies for."""
        if command.device_id:
            # Sync specific device
            device = await self._device_repository.find_by_id(command.device_id)
            return [device] if device else []
        
        if command.user_id:
            # Sync all devices for specific user
            return await self._device_repository.find_active_by_user(command.user_id)
        
        # Sync all active devices (admin operation)
        return await self._device_repository.find_all_active()
    
    async def _load_applicable_policies(
        self,
        devices: list[Device],
        users: dict[UUID, User],
        command: SyncDevicePoliciesCommand
    ) -> dict[str, Any]:
        """Load all policies applicable to the devices."""
        # Get all unique device types and user groups
        device_types = list({device.device_type for device in devices})
        user_groups = []
        for user in users.values():
            user_groups.extend(user.metadata.get("groups", []))
        user_groups = list(set(user_groups))
        
        # Load policies based on scope
        if command.policy_scope == PolicyScope.ALL:
            policies = await self._device_policy_repository.find_all_active()
        elif command.policy_scope == PolicyScope.SECURITY:
            policies = await self._device_policy_repository.find_by_type(PolicyType.SECURITY)
        elif command.policy_scope == PolicyScope.COMPLIANCE:
            policies = await self._device_policy_repository.find_by_type(PolicyType.COMPLIANCE)
        else:
            policies = await self._device_policy_repository.find_by_ids(command.policy_ids)
        
        # Filter policies applicable to the devices
        applicable_policies = []
        for policy in policies:
            if await self._policy_service.is_policy_applicable(
                policy,
                device_types,
                user_groups
            ):
                applicable_policies.append(policy)
        
        return {
            "policies": applicable_policies,
            "device_types": device_types,
            "user_groups": user_groups
        }
    
    async def _calculate_device_sync_operation(
        self,
        device: Device,
        user: User,
        applicable_policies: dict[str, Any],
        command: SyncDevicePoliciesCommand
    ) -> dict[str, Any]:
        """Calculate sync operation for a specific device."""
        # Get current device policies
        current_policies = await self._device_policy_repository.find_by_device(device.id)
        current_policy_ids = {policy.id for policy in current_policies}
        
        # Determine which policies should be applied
        should_apply_policies = []
        for policy in applicable_policies["policies"]:
            if await self._policy_service.should_apply_policy_to_device(
                policy,
                device,
                user
            ):
                should_apply_policies.append(policy)
        
        should_apply_policy_ids = {policy.id for policy in should_apply_policies}
        
        # Calculate changes
        policies_to_add = should_apply_policy_ids - current_policy_ids
        policies_to_remove = current_policy_ids - should_apply_policy_ids
        policies_to_update = current_policy_ids & should_apply_policy_ids
        
        # Check for policy updates (version changes)
        policies_to_update_actual = []
        for policy in should_apply_policies:
            if policy.id in policies_to_update:
                current_policy = next(p for p in current_policies if p.id == policy.id)
                if policy.version > current_policy.version:
                    policies_to_update_actual.append(policy.id)
        
        return {
            "device_id": device.id,
            "user_id": user.id,
            "device": device,
            "user": user,
            "current_policies": current_policies,
            "should_apply_policies": should_apply_policies,
            "policies_to_add": list(policies_to_add),
            "policies_to_remove": list(policies_to_remove),
            "policies_to_update": policies_to_update_actual,
            "changes_needed": bool(policies_to_add or policies_to_remove or policies_to_update_actual)
        }
    
    async def _analyze_policy_conflicts(
        self,
        sync_operations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Analyze potential policy conflicts across devices."""
        conflicts = []
        
        for sync_op in sync_operations:
            device = sync_op["device"]
            policies_to_apply = sync_op["should_apply_policies"]
            
            # Check for conflicts within device policies
            device_conflicts = await self._policy_service.detect_policy_conflicts(
                policies_to_apply
            )
            
            if device_conflicts:
                conflicts.extend([
                    f"Device {device.device_name}: {conflict}"
                    for conflict in device_conflicts
                ])
        
        return {
            "has_conflicts": bool(conflicts),
            "conflicts": conflicts,
            "analysis_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _create_policy_backup(
        self,
        device: Device,
        command: SyncDevicePoliciesCommand
    ) -> UUID:
        """Create backup of current device policies."""
        current_policies = await self._device_policy_repository.find_by_device(device.id)
        
        backup_data = {
            "device_id": str(device.id),
            "device_name": device.device_name,
            "backup_timestamp": datetime.now(UTC).isoformat(),
            "backup_reason": "policy_sync_backup",
            "sync_operation": {
                "sync_mode": command.sync_mode.value,
                "enforcement_level": command.enforcement_level.value,
                "initiated_by": str(command.initiated_by),
                "reason": command.reason
            },
            "policies": [
                {
                    "id": str(policy.id),
                    "name": policy.name,
                    "type": policy.type.value,
                    "version": policy.version,
                    "configuration": policy.configuration,
                    "applied_at": policy.applied_at.isoformat() if policy.applied_at else None
                }
                for policy in current_policies
            ]
        }
        
        return await self._device_policy_repository.create_backup(backup_data)
    
    async def _execute_device_policy_sync(
        self,
        sync_operation: dict[str, Any],
        command: SyncDevicePoliciesCommand
    ) -> dict[str, Any]:
        """Execute policy sync for a single device."""
        device = sync_operation["device"]
        sync_operation["user"]
        
        policies_applied = []
        policies_removed = []
        errors = []
        
        try:
            # Remove policies that should no longer be applied
            for policy_id in sync_operation["policies_to_remove"]:
                try:
                    await self._device_policy_repository.remove_policy_from_device(
                        device.id,
                        policy_id
                    )
                    policies_removed.append(policy_id)
                except Exception as e:
                    errors.append(f"Failed to remove policy {policy_id}: {e!s}")
            
            # Add new policies
            for policy_id in sync_operation["policies_to_add"]:
                try:
                    policy = next(
                        p for p in sync_operation["should_apply_policies"]
                        if p.id == policy_id
                    )
                    
                    await self._device_policy_repository.apply_policy_to_device(
                        device.id,
                        policy.id,
                        command.enforcement_level
                    )
                    
                    # Apply policy configuration to device if supported
                    if command.enforcement_level == PolicyEnforcementLevel.ENFORCE:
                        await self._apply_policy_to_device(device, policy)
                    
                    policies_applied.append(policy_id)
                    
                except Exception as e:
                    errors.append(f"Failed to apply policy {policy_id}: {e!s}")
            
            # Update existing policies
            for policy_id in sync_operation["policies_to_update"]:
                try:
                    policy = next(
                        p for p in sync_operation["should_apply_policies"]
                        if p.id == policy_id
                    )
                    
                    await self._device_policy_repository.update_policy_on_device(
                        device.id,
                        policy.id,
                        policy.version
                    )
                    
                    # Re-apply updated policy configuration
                    if command.enforcement_level == PolicyEnforcementLevel.ENFORCE:
                        await self._apply_policy_to_device(device, policy)
                    
                    policies_applied.append(policy_id)
                    
                except Exception as e:
                    errors.append(f"Failed to update policy {policy_id}: {e!s}")
            
            # Update device sync metadata
            device.metadata.update({
                "policy_sync": {
                    "last_sync": datetime.now(UTC).isoformat(),
                    "sync_mode": command.sync_mode.value,
                    "enforcement_level": command.enforcement_level.value,
                    "policies_count": len(policies_applied) + len(sync_operation["current_policies"]) - len(policies_removed),
                    "initiated_by": str(command.initiated_by),
                    "errors": errors
                }
            })
            
            await self._device_repository.update(device)
            
            return {
                "device_id": device.id,
                "status": PolicySyncStatus.SUCCESS if not errors else PolicySyncStatus.PARTIAL_SUCCESS,
                "policies_applied": policies_applied,
                "policies_removed": policies_removed,
                "changes_made": bool(policies_applied or policies_removed),
                "errors": errors,
                "sync_timestamp": datetime.now(UTC).isoformat()
            }
            
        except Exception as e:
            return {
                "device_id": device.id,
                "status": PolicySyncStatus.FAILED,
                "policies_applied": policies_applied,
                "policies_removed": policies_removed,
                "changes_made": bool(policies_applied or policies_removed),
                "errors": [*errors, f"Sync failed: {e!s}"],
                "sync_timestamp": datetime.now(UTC).isoformat()
            }
    
    async def _apply_policy_to_device(
        self,
        device: Device,
        policy: Any
    ) -> None:
        """Apply policy configuration directly to device."""
        try:
            await self._device_management_service.apply_policy_configuration(
                device.id,
                policy.configuration
            )
        except Exception as e:
            # Log but don't fail the sync operation
            await self._audit_service.log_warning(
                f"Failed to apply policy configuration to device {device.id}: {e!s}"
            )
    
    def _simulate_sync_result(
        self,
        sync_operation: dict[str, Any]
    ) -> dict[str, Any]:
        """Simulate sync result for dry run."""
        return {
            "device_id": sync_operation["device_id"],
            "status": PolicySyncStatus.SIMULATED,
            "policies_applied": sync_operation["policies_to_add"] + sync_operation["policies_to_update"],
            "policies_removed": sync_operation["policies_to_remove"],
            "changes_made": sync_operation["changes_needed"],
            "errors": [],
            "sync_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _validate_device_compliance(
        self,
        device: Device,
        user: User
    ) -> dict[str, Any]:
        """Validate device compliance after policy sync."""
        return await self._compliance_service.validate_device_compliance(
            device,
            user
        )
    
    async def _send_policy_sync_notifications(
        self,
        devices: list[Device],
        users: dict[UUID, User],
        sync_results: list[dict[str, Any]],
        command: SyncDevicePoliciesCommand
    ) -> list[str]:
        """Send notifications about policy sync changes."""
        notifications_sent = []
        
        # Group devices by user
        devices_by_user = {}
        for device in devices:
            user_id = device.user_id
            if user_id not in devices_by_user:
                devices_by_user[user_id] = []
            devices_by_user[user_id].append(device)
        
        # Send notifications to each affected user
        for user_id, user_devices in devices_by_user.items():
            user = users[user_id]
            
            # Check if any devices had changes
            user_device_ids = [device.id for device in user_devices]
            user_results = [
                result for result in sync_results
                if result["device_id"] in user_device_ids and result["changes_made"]
            ]
            
            if user_results:
                # In-app notification
                await self._notification_service.create_notification(
                    NotificationContext(
                        notification_id=UUID(),
                        recipient_id=user_id,
                        notification_type=NotificationType.DEVICE_POLICIES_UPDATED,
                        channel="in_app",
                        template_id="device_policies_updated",
                        template_data={
                            "devices_affected": len(user_results),
                            "policies_changed": sum(
                                len(result["policies_applied"]) + len(result["policies_removed"])
                                for result in user_results
                            ),
                            "sync_mode": command.sync_mode.value,
                            "initiated_by_admin": command.initiated_by != user_id
                        },
                        priority="medium"
                    )
                )
                notifications_sent.append(f"in_app_{user_id}")
                
                # Email notification for significant changes
                total_changes = sum(
                    len(result["policies_applied"]) + len(result["policies_removed"])
                    for result in user_results
                )
                
                if total_changes >= 5 and user.email_verified:  # Significant changes threshold
                    await self._email_service.send_email(
                        EmailContext(
                            recipient=user.email,
                            template="device_policies_major_update",
                            subject="Device Security Policies Updated",
                            variables={
                                "username": user.username,
                                "devices_affected": len(user_results),
                                "policies_changed": total_changes,
                                "sync_mode": command.sync_mode.value,
                                "initiated_by_admin": command.initiated_by != user_id,
                                "manage_devices_link": "https://app.example.com/settings/devices"
                            }
                        )
                    )
                    notifications_sent.append(f"email_{user_id}")
        
        return notifications_sent
    
    async def _log_policy_sync_operations(
        self,
        devices: list[Device],
        users: dict[UUID, User],
        sync_results: list[dict[str, Any]],
        command: SyncDevicePoliciesCommand
    ) -> None:
        """Log policy sync operations for audit."""
        # Log overall sync operation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.DEVICE_POLICIES_SYNCED,
                actor_id=command.initiated_by,
                resource_type="device_policy",
                details={
                    "sync_mode": command.sync_mode.value,
                    "enforcement_level": command.enforcement_level.value,
                    "policy_scope": command.policy_scope.value,
                    "devices_targeted": len(devices),
                    "devices_changed": sum(1 for result in sync_results if result["changes_made"]),
                    "total_policies_applied": sum(len(result["policies_applied"]) for result in sync_results),
                    "total_policies_removed": sum(len(result["policies_removed"]) for result in sync_results),
                    "errors_occurred": sum(len(result["errors"]) for result in sync_results),
                    "reason": command.reason
                },
                risk_level="medium"
            )
        )
        
        # Log individual device operations with significant changes
        for result in sync_results:
            if result["changes_made"] and (result["policies_applied"] or result["policies_removed"]):
                device = next(d for d in devices if d.id == result["device_id"])
                user = users[device.user_id]
                
                await self._audit_service.log_action(
                    AuditContext(
                        action=AuditAction.DEVICE_POLICY_APPLIED,
                        actor_id=command.initiated_by,
                        target_user_id=user.id,
                        resource_type="device",
                        resource_id=device.id,
                        details={
                            "device_name": device.device_name,
                            "policies_applied": result["policies_applied"],
                            "policies_removed": result["policies_removed"],
                            "sync_status": result["status"],
                            "errors": result["errors"],
                            "admin_action": command.initiated_by != user.id
                        },
                        risk_level="low"
                    )
                )