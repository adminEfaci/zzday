"""
MFA Domain Service

Handles multi-factor authentication operations.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...entities.admin.mfa_device import MfaDevice
from ...entities.user.user_events import (
    BackupCodeGenerated,
    BackupCodeUsed,
    UserMFADisabled,
    UserMFAEnabled,
)
from ...enums import MFAMethod


class MFAService:
    """Domain service for MFA operations."""
    
    @staticmethod
    def enable_mfa(
        user: User,
        method: MFAMethod,
        device_name: str = None
    ) -> MfaDevice:
        """Enable MFA for user with specified method."""
        # Check if method already enabled
        existing_devices = getattr(user, '_mfa_devices', [])
        for device in existing_devices:
            if device.method == method and device.is_active:
                return device
        
        # Create new MFA device
        device = MfaDevice.create(
            user_id=user.id,
            name=device_name or f"{method.value} Device",
            method=method
        )
        
        # Add device to user's collection
        if not hasattr(user, '_mfa_devices'):
            user._mfa_devices = []
        user._mfa_devices.append(device)
        
        # Update user state
        user.mfa_enabled = True
        user._regenerate_security_stamp()
        user._touch()
        
        # Add domain event
        user.add_domain_event(UserMFAEnabled(
            user_id=user.id,
            mfa_method=method.value
        ))
        
        return device
    
    @staticmethod
    def disable_mfa(user: User) -> None:
        """Disable all MFA for user."""
        # Deactivate all MFA devices
        if hasattr(user, '_mfa_devices'):
            for device in user._mfa_devices:
                device.deactivate()
        
        # Update user state
        user.mfa_enabled = False
        user._regenerate_security_stamp()
        user._touch()
        
        # Add domain event
        user.add_domain_event(UserMFADisabled(
            user_id=user.id
        ))
    
    @staticmethod
    def generate_backup_codes(user: User, count: int = 10) -> list[str]:
        """Generate MFA backup codes."""
        # Clear existing backup codes
        if not hasattr(user, 'backup_codes'):
            user.backup_codes = []
        else:
            user.backup_codes.clear()
        
        # Generate new codes
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('0123456789') for _ in range(8))
            # Store hash of code
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            user.backup_codes.append(code_hash)
            codes.append(code)
        
        # Update user state
        user.backup_codes_generated_at = datetime.now(UTC)
        user._touch()
        
        # Add domain event
        user.add_domain_event(BackupCodeGenerated(
            user_id=user.id,
            code_count=count,
            generated_by=user.id,
            expires_at=datetime.now(UTC) + timedelta(days=365)
        ))
        
        return codes
    
    @staticmethod
    def verify_mfa_code(user: User, code: str) -> bool:
        """Verify MFA code (TOTP or backup)."""
        # First try backup codes
        if code.replace('-', '').isdigit() and len(code.replace('-', '')) == 8:
            return MFAService._use_backup_code(user, code)
        
        # Then try active MFA devices
        if hasattr(user, '_mfa_devices'):
            for device in user._mfa_devices:
                if device.is_active and device.verify_code(code):
                    device.update_last_used()
                    return True
        
        return False
    
    @staticmethod
    def _use_backup_code(user: User, code: str) -> bool:
        """Use MFA backup code."""
        if not hasattr(user, 'backup_codes') or not user.backup_codes:
            return False
        
        # Hash the provided code
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Check if code exists
        if code_hash not in user.backup_codes:
            return False
        
        # Remove used code
        user.backup_codes.remove(code_hash)
        user._touch()
        
        # Add domain event
        user.add_domain_event(BackupCodeUsed(
            user_id=user.id,
            code_hash=code_hash,
            used_at=datetime.now(UTC),
            remaining_codes=len(user.backup_codes),
            ip_address=""  # Would be passed in from context
        ))
        
        return True
    
    @staticmethod
    def add_trusted_device(
        user: User,
        device_fingerprint: str,
        device_name: str = None
    ) -> None:
        """Add a trusted device for the user."""
        from ...entities.device.device_registration import DeviceRegistration
        from ...enums import DevicePlatform, DeviceType
        
        # Initialize registered devices collection if needed
        if not hasattr(user, '_registered_devices'):
            user._registered_devices = []
        
        # Check if device already registered
        existing_device = next(
            (d for d in user._registered_devices if d.device_id == device_fingerprint),
            None
        )
        
        if existing_device:
            existing_device.trust()
        else:
            # Register new device
            device = DeviceRegistration.create(
                user_id=user.id,
                device_id=device_fingerprint,
                device_name=device_name or f"Device {len(user._registered_devices) + 1}",
                device_type=DeviceType.UNKNOWN,
                fingerprint=device_fingerprint,
                platform=DevicePlatform.UNKNOWN
            )
            device.trust()
            user._registered_devices.append(device)
        
        user._touch()
    
    @staticmethod
    def get_active_mfa_devices(user: User) -> list[MfaDevice]:
        """Get all active MFA devices for user."""
        if not hasattr(user, '_mfa_devices'):
            return []
        
        return [d for d in user._mfa_devices if d.is_active]
    
    @staticmethod
    def get_primary_mfa_device(user: User) -> MfaDevice | None:
        """Get primary MFA device for user."""
        devices = MFAService.get_active_mfa_devices(user)
        
        # First look for explicitly marked primary
        for device in devices:
            if device.is_primary:
                return device
        
        # Return first active device if no primary
        return devices[0] if devices else None
    
    @staticmethod
    def set_primary_mfa_device(user: User, device_id: UUID) -> None:
        """Set a device as primary MFA device."""
        if not hasattr(user, '_mfa_devices'):
            raise ValueError("No MFA devices configured")
        
        target_device = None
        for device in user._mfa_devices:
            if device.id == device_id:
                target_device = device
            else:
                device.is_primary = False
        
        if not target_device:
            raise ValueError("MFA device not found")
        
        if not target_device.verified:
            raise ValueError("Device must be verified before setting as primary")
        
        target_device.is_primary = True
        user._touch()