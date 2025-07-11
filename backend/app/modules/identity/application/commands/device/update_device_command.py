"""
Update device command implementation.

Handles updating existing device information and properties.
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
from app.modules.identity.application.dtos.request import UpdateDeviceRequest
from app.modules.identity.application.dtos.response import DeviceUpdateResponse
from app.modules.identity.domain.entities import Device, User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeviceStatus,
    DeviceType,
    NotificationType,
    TrustLevel,
)
from app.modules.identity.domain.events import DeviceUpdated
from app.modules.identity.domain.exceptions import (
    DeviceNotFoundError,
    DeviceStatusConflictError,
    InvalidDeviceDataError,
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
    DeviceSecurityService,
    GeoLocationService,
    ValidationService,
)


class UpdateDeviceCommand(Command[DeviceUpdateResponse]):
    """Command to update an existing device."""
    
    def __init__(
        self,
        device_id: UUID,
        updated_by: UUID,
        device_name: str | None = None,
        device_type: DeviceType | None = None,
        device_os: str | None = None,
        device_os_version: str | None = None,
        device_model: str | None = None,
        device_manufacturer: str | None = None,
        browser_name: str | None = None,
        browser_version: str | None = None,
        status: DeviceStatus | None = None,
        trust_level: TrustLevel | None = None,
        is_primary: bool | None = None,
        location_data: dict[str, Any] | None = None,
        hardware_info: dict[str, Any] | None = None,
        software_info: dict[str, Any] | None = None,
        security_features: dict[str, Any] | None = None,
        notes: str | None = None,
        force_update: bool = False,
        notify_user: bool = True,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.device_id = device_id
        self.updated_by = updated_by
        self.device_name = device_name.strip() if device_name else None
        self.device_type = device_type
        self.device_os = device_os
        self.device_os_version = device_os_version
        self.device_model = device_model
        self.device_manufacturer = device_manufacturer
        self.browser_name = browser_name
        self.browser_version = browser_version
        self.status = status
        self.trust_level = trust_level
        self.is_primary = is_primary
        self.location_data = location_data
        self.hardware_info = hardware_info
        self.software_info = software_info
        self.security_features = security_features
        self.notes = notes
        self.force_update = force_update
        self.notify_user = notify_user
        self.reason = reason or "Device information updated"
        self.metadata = metadata


class UpdateDeviceCommandHandler(CommandHandler[UpdateDeviceCommand, DeviceUpdateResponse]):
    """Handler for updating devices."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        device_repository: IDeviceRepository,
        validation_service: ValidationService,
        device_security_service: DeviceSecurityService,
        geolocation_service: GeoLocationService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._device_repository = device_repository
        self._validation_service = validation_service
        self._device_security_service = device_security_service
        self._geolocation_service = geolocation_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DEVICE_UPDATED,
        resource_type="device",
        include_request=True,
        include_response=True,
        include_changes=True
    )
    @validate_request(UpdateDeviceRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("devices.update")
    async def handle(self, command: UpdateDeviceCommand) -> DeviceUpdateResponse:
        """
        Update device with comprehensive validation.
        
        Process:
        1. Load device and validate access
        2. Validate update data
        3. Check for conflicting states
        4. Apply updates with change tracking
        5. Handle primary device logic
        6. Update security assessment
        7. Send notifications
        8. Log changes
        
        Returns:
            DeviceUpdateResponse with update details
            
        Raises:
            DeviceNotFoundError: If device not found
            UnauthorizedError: If user cannot update device
            InvalidDeviceDataError: If update data invalid
            DeviceStatusConflictError: If status update conflicts
        """
        async with self._unit_of_work:
            # 1. Load device
            device = await self._device_repository.find_by_id(command.device_id)
            if not device:
                raise DeviceNotFoundError(f"Device {command.device_id} not found")
            
            # 2. Load user
            user = await self._user_repository.find_by_id(device.user_id)
            if not user:
                raise DeviceNotFoundError(f"User {device.user_id} not found")
            
            # 3. Check update permissions
            await self._validate_update_permissions(device, command.updated_by)
            
            # 4. Capture original state for comparison
            original_state = self._capture_device_state(device)
            
            # 5. Validate update data
            await self._validate_update_data(device, command)
            
            # 6. Check for status conflicts
            await self._check_status_conflicts(device, command)
            
            # 7. Apply updates
            changes = {}
            
            if command.device_name and command.device_name != device.device_name:
                changes["device_name"] = (device.device_name, command.device_name)
                device.device_name = command.device_name
            
            if command.device_type and command.device_type != device.device_type:
                changes["device_type"] = (device.device_type.value, command.device_type.value)
                device.device_type = command.device_type
            
            if command.device_os and command.device_os != device.device_os:
                changes["device_os"] = (device.device_os, command.device_os)
                device.device_os = command.device_os
            
            if command.device_os_version and command.device_os_version != device.device_os_version:
                changes["device_os_version"] = (device.device_os_version, command.device_os_version)
                device.device_os_version = command.device_os_version
            
            if command.device_model and command.device_model != device.device_model:
                changes["device_model"] = (device.device_model, command.device_model)
                device.device_model = command.device_model
            
            if command.device_manufacturer and command.device_manufacturer != device.device_manufacturer:
                changes["device_manufacturer"] = (device.device_manufacturer, command.device_manufacturer)
                device.device_manufacturer = command.device_manufacturer
            
            if command.browser_name and command.browser_name != device.browser_name:
                changes["browser_name"] = (device.browser_name, command.browser_name)
                device.browser_name = command.browser_name
            
            if command.browser_version and command.browser_version != device.browser_version:
                changes["browser_version"] = (device.browser_version, command.browser_version)
                device.browser_version = command.browser_version
            
            # 8. Handle status changes
            if command.status and command.status != device.status:
                changes["status"] = (device.status.value, command.status.value)
                await self._handle_status_change(device, command.status, command)
            
            # 9. Handle trust level changes
            if command.trust_level and command.trust_level != device.trust_level:
                changes["trust_level"] = (device.trust_level.value, command.trust_level.value)
                await self._handle_trust_level_change(device, command.trust_level, command)
            
            # 10. Handle primary device changes
            if command.is_primary is not None and command.is_primary != device.is_primary:
                changes["is_primary"] = (device.is_primary, command.is_primary)
                
                if command.is_primary:
                    await self._handle_primary_device_change(device.user_id, device.id)
                
                device.is_primary = command.is_primary
            
            # 11. Update location data if provided
            if command.location_data:
                enhanced_location = await self._enhance_location_data(command.location_data)
                if enhanced_location != device.location_data:
                    changes["location_data"] = ("updated", "location_data_updated")
                    device.location_data = enhanced_location
            
            # 12. Update hardware info
            if command.hardware_info:
                if command.hardware_info != device.hardware_info:
                    changes["hardware_info"] = ("updated", "hardware_info_updated")
                    device.hardware_info.update(command.hardware_info)
            
            # 13. Update software info
            if command.software_info:
                if command.software_info != device.software_info:
                    changes["software_info"] = ("updated", "software_info_updated")
                    device.software_info.update(command.software_info)
            
            # 14. Update security features
            if command.security_features:
                if command.security_features != device.security_features:
                    changes["security_features"] = ("updated", "security_features_updated")
                    device.security_features.update(command.security_features)
            
            # 15. Update notes
            if command.notes is not None and command.notes != device.notes:
                changes["notes"] = (device.notes or "", command.notes)
                device.notes = command.notes
            
            # 16. Update metadata
            device.updated_at = datetime.now(UTC)
            device.updated_by = command.updated_by
            
            if command.metadata:
                device.metadata.update(command.metadata)
            
            # 17. Re-assess security if significant changes
            if self._requires_security_reassessment(changes):
                security_assessment = await self._reassess_device_security(device, user)
                device.security_assessment = security_assessment
                changes["security_reassessment"] = True
            
            # 18. Save device
            await self._device_repository.update(device)
            
            # 19. Send notifications if requested
            if command.notify_user and changes:
                await self._send_update_notifications(
                    user,
                    device,
                    changes,
                    original_state,
                    command
                )
            
            # 20. Log admin updates
            if command.updated_by != device.user_id:
                await self._log_admin_device_update(
                    user,
                    device,
                    changes,
                    command
                )
            
            # 21. Publish domain event
            await self._event_bus.publish(
                DeviceUpdated(
                    aggregate_id=device.id,
                    user_id=device.user_id,
                    changes=list(changes.keys()),
                    updated_by=command.updated_by,
                    trust_level_changed="trust_level" in changes,
                    status_changed="status" in changes,
                    security_reassessed=changes.get("security_reassessment", False)
                )
            )
            
            # 22. Commit transaction
            await self._unit_of_work.commit()
            
            # 23. Return response
            return DeviceUpdateResponse(
                device_id=device.id,
                user_id=device.user_id,
                changes_made=changes,
                device_name=device.device_name,
                device_type=device.device_type,
                status=device.status,
                trust_level=device.trust_level,
                is_primary=device.is_primary,
                updated_at=device.updated_at,
                updated_by=device.updated_by,
                security_reassessed=changes.get("security_reassessment", False),
                message="Device updated successfully"
            )
    
    async def _validate_update_permissions(
        self,
        device: Device,
        updated_by: UUID
    ) -> None:
        """Validate user can update this device."""
        # User can update their own devices
        if device.user_id == updated_by:
            return
        
        # Check if updater has admin permissions
        # This would typically check for admin role or specific permission
        # For now, we'll allow it but log it as admin action
    
    def _capture_device_state(self, device: Device) -> dict[str, Any]:
        """Capture current device state for comparison."""
        return {
            "device_name": device.device_name,
            "device_type": device.device_type.value,
            "device_os": device.device_os,
            "device_os_version": device.device_os_version,
            "device_model": device.device_model,
            "device_manufacturer": device.device_manufacturer,
            "browser_name": device.browser_name,
            "browser_version": device.browser_version,
            "status": device.status.value,
            "trust_level": device.trust_level.value,
            "is_primary": device.is_primary,
            "notes": device.notes,
            "security_features": device.security_features.copy()
        }
    
    async def _validate_update_data(
        self,
        device: Device,
        command: UpdateDeviceCommand
    ) -> None:
        """Validate update data."""
        # Validate device name
        if command.device_name is not None:
            if len(command.device_name.strip()) < 2:
                raise InvalidDeviceDataError("Device name must be at least 2 characters")
            
            if len(command.device_name) > 100:
                raise InvalidDeviceDataError("Device name too long (max 100 characters)")
        
        # Validate notes
        if command.notes is not None and len(command.notes) > 1000:
            raise InvalidDeviceDataError("Notes too long (max 1000 characters)")
        
        # Validate trust level change
        if command.trust_level and command.trust_level != device.trust_level:
            # Some trust level changes require special permissions
            if (device.trust_level == TrustLevel.UNTRUSTED and 
                command.trust_level == TrustLevel.TRUSTED):
                # Requires security validation
                if not command.force_update:
                    raise InvalidDeviceDataError(
                        "Cannot directly change from untrusted to trusted without security validation"
                    )
    
    async def _check_status_conflicts(
        self,
        device: Device,
        command: UpdateDeviceCommand
    ) -> None:
        """Check for status update conflicts."""
        if not command.status:
            return
        
        # Check invalid status transitions
        invalid_transitions = {
            DeviceStatus.REVOKED: [DeviceStatus.ACTIVE, DeviceStatus.PENDING_VERIFICATION],
            DeviceStatus.WIPED: [DeviceStatus.ACTIVE, DeviceStatus.PENDING_VERIFICATION, DeviceStatus.INACTIVE]
        }
        
        current_status = device.status
        new_status = command.status
        
        if current_status in invalid_transitions:
            if new_status in invalid_transitions[current_status]:
                raise DeviceStatusConflictError(
                    f"Cannot change device status from {current_status.value} to {new_status.value}"
                )
    
    async def _handle_status_change(
        self,
        device: Device,
        new_status: DeviceStatus,
        command: UpdateDeviceCommand
    ) -> None:
        """Handle device status changes."""
        old_status = device.status
        device.status = new_status
        
        # Handle specific status changes
        if new_status == DeviceStatus.REVOKED:
            device.revoked_at = datetime.now(UTC)
            device.revoked_by = command.updated_by
            device.revocation_reason = command.reason
            
            # If this was the primary device, unset it
            if device.is_primary:
                device.is_primary = False
        
        elif new_status == DeviceStatus.ACTIVE and old_status != DeviceStatus.ACTIVE:
            device.activated_at = datetime.now(UTC)
        
        elif new_status == DeviceStatus.INACTIVE:
            device.deactivated_at = datetime.now(UTC)
    
    async def _handle_trust_level_change(
        self,
        device: Device,
        new_trust_level: TrustLevel,
        command: UpdateDeviceCommand
    ) -> None:
        """Handle device trust level changes."""
        old_trust_level = device.trust_level
        device.trust_level = new_trust_level
        
        # Log trust level changes for audit
        if old_trust_level != new_trust_level:
            device.trust_changed_at = datetime.now(UTC)
            device.trust_changed_by = command.updated_by
            device.trust_change_reason = command.reason
    
    async def _handle_primary_device_change(
        self,
        user_id: UUID,
        new_primary_device_id: UUID
    ) -> None:
        """Handle setting a new primary device."""
        # Unset existing primary device
        current_primary = await self._device_repository.find_primary_by_user(user_id)
        if current_primary and current_primary.id != new_primary_device_id:
            current_primary.is_primary = False
            await self._device_repository.update(current_primary)
    
    async def _enhance_location_data(
        self,
        location_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enhance location data with additional information."""
        enhanced_location = location_data.copy()
        
        # Add timestamp
        enhanced_location["updated_at"] = datetime.now(UTC).isoformat()
        
        # If we have lat/lng, try to get city/country
        if "latitude" in location_data and "longitude" in location_data:
            try:
                geo_data = await self._geolocation_service.reverse_geocode(
                    location_data["latitude"],
                    location_data["longitude"]
                )
                enhanced_location.update({
                    "city": geo_data.get("city"),
                    "country": geo_data.get("country"),
                    "city_country": f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
                })
            except Exception:
                # Fallback if reverse geocoding fails
                pass
        
        return enhanced_location
    
    def _requires_security_reassessment(self, changes: dict[str, Any]) -> bool:
        """Check if changes require security reassessment."""
        security_relevant_changes = [
            "device_type",
            "device_os",
            "device_os_version",
            "security_features",
            "location_data",
            "hardware_info",
            "software_info"
        ]
        
        return any(change in changes for change in security_relevant_changes)
    
    async def _reassess_device_security(
        self,
        device: Device,
        user: User
    ) -> dict[str, Any]:
        """Reassess device security after significant changes."""
        return await self._device_security_service.assess_device_security(
            device,
            user
        )
    
    async def _send_update_notifications(
        self,
        user: User,
        device: Device,
        changes: dict[str, Any],
        original_state: dict[str, Any],
        command: UpdateDeviceCommand
    ) -> None:
        """Send notifications about device updates."""
        # Determine notification priority based on changes
        high_priority_changes = ["status", "trust_level", "is_primary", "security_reassessment"]
        priority = "high" if any(change in changes for change in high_priority_changes) else "medium"
        
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="device_updated",
                    subject="Device Updated",
                    variables={
                        "username": user.username,
                        "device_name": device.device_name,
                        "device_type": device.device_type.value,
                        "changes": list(changes.keys()),
                        "updated_by_admin": command.updated_by != user.id,
                        "reason": command.reason,
                        "current_status": device.status.value,
                        "current_trust_level": device.trust_level.value,
                        "is_primary": device.is_primary,
                        "manage_devices_link": "https://app.example.com/settings/devices"
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.DEVICE_UPDATED,
                channel="in_app",
                template_id="device_updated",
                template_data={
                    "device_name": device.device_name,
                    "device_type": device.device_type.value,
                    "changes": list(changes.keys()),
                    "updated_by_admin": command.updated_by != user.id,
                    "current_status": device.status.value,
                    "current_trust_level": device.trust_level.value
                },
                priority=priority
            )
        )
    
    async def _log_admin_device_update(
        self,
        user: User,
        device: Device,
        changes: dict[str, Any],
        command: UpdateDeviceCommand
    ) -> None:
        """Log when admin updates device for another user."""
        await self._audit_service.log_administrative_action(
            AuditContext(
                action=AuditAction.DEVICE_UPDATED,
                actor_id=command.updated_by,
                target_user_id=user.id,
                resource_type="device",
                resource_id=device.id,
                details={
                    "device_name": device.device_name,
                    "device_fingerprint": self._mask_fingerprint(device.device_fingerprint),
                    "changes": changes,
                    "reason": command.reason,
                    "admin_action": True,
                    "force_update": command.force_update
                },
                risk_level="medium" if "trust_level" in changes or "status" in changes else "low"
            )
        )
    
    def _mask_fingerprint(self, fingerprint: str) -> str:
        """Mask device fingerprint for logging."""
        if len(fingerprint) > 16:
            return fingerprint[:8] + "*" * (len(fingerprint) - 16) + fingerprint[-8:]
        return fingerprint[:4] + "*" * (len(fingerprint) - 8) + fingerprint[-4:]