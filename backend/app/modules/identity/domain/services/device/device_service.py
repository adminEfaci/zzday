"""
Device Management Service

Handles device registration, trust management, and device lifecycle operations.
"""

from typing import Any
from uuid import UUID

from ...aggregates.device_registration import DeviceRegistration
from ...enums import DevicePlatform, DeviceType
from ...errors import DeviceNotFoundError, DeviceTrustViolationError
from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.contracts.notification_contract import INotificationContract
from ...interfaces.repositories.device_repository import IDeviceRepository
from ...interfaces.services.security.device_service import IDeviceService
from ...rules.device_trust_policy import DeviceTrustPolicy
from ...rules.risk_policy import RiskAssessmentPolicy


class DeviceService(IDeviceService):
    """Service for device management operations."""
    
    def __init__(
        self,
        device_repository: IDeviceRepository,
        audit_contract: IAuditContract,
        notification_contract: INotificationContract,
        device_trust_policy: DeviceTrustPolicy,
        risk_assessment_policy: RiskAssessmentPolicy
    ):
        self._device_repository = device_repository
        self._audit_contract = audit_contract
        self._notification_contract = notification_contract
        self._device_trust_policy = device_trust_policy
        self._risk_assessment_policy = risk_assessment_policy
    
    async def register_device(
        self,
        user_id: UUID,
        device_info: dict[str, Any]
    ) -> UUID:
        """Register new device with validation and risk assessment."""
        
        # Validate device info
        self._validate_device_info(device_info)
        
        # Check device limits
        user_devices = await self._device_repository.get_by_user_id(user_id)
        policy_check = self._device_trust_policy.validate(
            trusted_devices=user_devices,
            is_new_device=True
        )
        
        if policy_check and self._device_trust_policy.has_blocking_violations(policy_check):
            raise DeviceTrustViolationError("Device registration violates trust policy")
        
        # Create device registration entity
        device = DeviceRegistration.create(
            user_id=user_id,
            device_id=device_info['device_id'],
            device_name=device_info['device_name'],
            device_type=DeviceType(device_info['device_type']),
            fingerprint=device_info['fingerprint'],
            platform=DevicePlatform(device_info['platform']),
            push_token=device_info.get('push_token'),
            app_version=device_info.get('app_version'),
            os_version=device_info.get('os_version')
        )
        
        # Assess risk for new device
        risk_score, risk_details = self._assess_device_risk(device_info, user_id)
        
        # Save device
        await self._device_repository.save(device)
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="device_registered",
            user_id=user_id,
            details={
                "device_id": str(device.id),
                "device_name": device.device_name,
                "device_type": device.device_type.value,
                "risk_score": risk_score,
                "risk_details": risk_details
            }
        )
        
        # Send notification if high risk
        if risk_score >= 0.7:
            await self._notification_contract.send_notification(
                user_id=user_id,
                notification_type="security_alert",
                content={
                    "title": "New Device Registered",
                    "message": f"A new device '{device.device_name}' was registered with high risk score.",
                    "device_info": device.get_device_info(),
                    "risk_score": risk_score
                }
            )
        
        return device.id
    
    async def trust_device(
        self,
        device_id: UUID,
        trust_duration: int | None = None
    ) -> None:
        """Mark device as trusted with policy validation."""
        
        device = await self._device_repository.get_by_id(device_id)
        if not device:
            raise DeviceNotFoundError(f"Device {device_id} not found")
        
        # Validate trust policy
        user_devices = await self._device_repository.get_by_user_id(device.user_id)
        policy_check = self._device_trust_policy.validate(
            device_id=str(device_id),
            trusted_devices=[d.to_dict() for d in user_devices],
            is_new_device=False,
            mfa_completed=True  # Assume MFA was completed for trust operation
        )
        
        if policy_check and self._device_trust_policy.has_blocking_violations(policy_check):
            raise DeviceTrustViolationError("Device trust violates policy")
        
        # Trust the device
        device.trust(trust_duration_days=trust_duration or 30)
        await self._device_repository.save(device)
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="device_trusted",
            user_id=device.user_id,
            details={
                "device_id": str(device_id),
                "device_name": device.device_name,
                "trust_duration": trust_duration or 30
            }
        )
    
    async def is_device_trusted(self, device_id: UUID) -> bool:
        """Check if device is currently trusted."""
        
        device = await self._device_repository.get_by_id(device_id)
        if not device:
            return False
        
        return device.is_trusted()
    
    async def revoke_device_trust(self, device_id: UUID) -> bool:
        """Revoke device trust and notify user."""
        
        device = await self._device_repository.get_by_id(device_id)
        if not device:
            return False
        
        # Revoke trust
        device.untrust()
        await self._device_repository.save(device)
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="device_trust_revoked",
            user_id=device.user_id,
            details={
                "device_id": str(device_id),
                "device_name": device.device_name,
                "reason": "manual_revocation"
            }
        )
        
        # Notify user
        await self._notification_contract.send_notification(
            user_id=device.user_id,
            notification_type="security_alert",
            content={
                "title": "Device Trust Revoked",
                "message": f"Trust for device '{device.device_name}' has been revoked.",
                "device_info": device.get_device_info()
            }
        )
        
        return True
    
    async def get_user_devices(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get all devices for a user with status information."""
        
        devices = await self._device_repository.get_by_user_id(user_id)
        
        device_list = []
        for device in devices:
            device_info = device.get_device_info()
            
            # Add trust status details
            trust_status = self._device_trust_policy.check_device_trust(
                device_id=str(device.id),
                trusted_devices=[d.to_dict() for d in devices],
                last_verification=device.last_seen
            )
            
            device_info.update({
                "trust_status": trust_status,
                "should_cleanup": device.should_cleanup(),
                "needs_reverification": self._device_trust_policy.should_reverify(device.last_seen)
            })
            
            device_list.append(device_info)
        
        return device_list
    
    async def update_device_info(
        self,
        device_id: UUID,
        device_info: dict[str, Any]
    ) -> bool:
        """Update device information and check for suspicious changes."""
        
        device = await self._device_repository.get_by_id(device_id)
        if not device:
            return False
        
        # Check for suspicious fingerprint changes
        old_fingerprint = device.fingerprint
        if 'fingerprint' in device_info and device_info['fingerprint'] != old_fingerprint:
            # Log suspicious activity
            await self._audit_contract.log_event(
                event_type="device_fingerprint_changed",
                user_id=device.user_id,
                details={
                    "device_id": str(device_id),
                    "old_fingerprint": old_fingerprint,
                    "new_fingerprint": device_info['fingerprint'],
                    "device_name": device.device_name
                }
            )
            
            # Update fingerprint (this will untrust the device automatically)
            device.update_fingerprint(device_info['fingerprint'])
        
        # Update other device info
        device.update_info(
            device_name=device_info.get('device_name'),
            push_token=device_info.get('push_token'),
            app_version=device_info.get('app_version'),
            os_version=device_info.get('os_version')
        )
        
        await self._device_repository.save(device)
        return True
    
    async def cleanup_inactive_devices(self, user_id: UUID, inactive_days: int = 90) -> int:
        """Clean up devices that haven't been seen for specified days."""
        
        devices = await self._device_repository.get_by_user_id(user_id)
        cleanup_count = 0
        
        for device in devices:
            if device.should_cleanup(inactive_days):
                await self._device_repository.delete(device.id)
                cleanup_count += 1
                
                # Log cleanup
                await self._audit_contract.log_event(
                    event_type="device_cleaned_up",
                    user_id=user_id,
                    details={
                        "device_id": str(device.id),
                        "device_name": device.device_name,
                        "days_inactive": device.get_days_since_last_seen(),
                        "cleanup_threshold": inactive_days
                    }
                )
        
        return cleanup_count
    
    def _validate_device_info(self, device_info: dict[str, Any]) -> None:
        """Validate required device information."""
        
        required_fields = ['device_id', 'device_name', 'device_type', 'fingerprint', 'platform']
        
        for field in required_fields:
            if field not in device_info or not device_info[field]:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate enums
        try:
            DeviceType(device_info['device_type'])
            DevicePlatform(device_info['platform'])
        except ValueError as e:
            raise ValueError(f"Invalid device type or platform: {e}") from e
    
    def _assess_device_risk(self, device_info: dict[str, Any], user_id: UUID) -> tuple[float, dict[str, Any]]:
        """Assess risk level for device registration."""
        
        # Simulate risk assessment context
        risk_context = {
            'is_new_device': True,
            'device_type': device_info['device_type'],
            'platform': device_info['platform'],
            'user_id': user_id,
            'account_age_days': 30  # Would come from user service
        }
        
        # Detect risk factors
        risk_factors = self._risk_assessment_policy.detect_risk_factors(risk_context)
        
        # Calculate risk score
        risk_score, risk_details = self._risk_assessment_policy.calculate_risk_score(
            risk_factors, risk_context
        )
        
        return risk_score, risk_details