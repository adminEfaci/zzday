"""
MFA Domain Service

Pure domain service for multi-factor authentication business logic implementing IMFAService.
Contains only domain logic with no infrastructure dependencies.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...aggregates.mfa_device import MfaDevice
from ...aggregates.device_registration import DeviceRegistration
from ...entities.user.user_events import (
    BackupCodeGenerated,
    BackupCodeUsed,
    UserMFADisabled,
    UserMFAEnabled,
)
from ...enums import DevicePlatform, DeviceType, MfaMethod
from ...interfaces.services.mfa.mfa_service import IMFAService


class MFAService:
    """Pure domain service for MFA operations."""
    
    @staticmethod
    def enable_mfa(
        user: User,
        method: MfaMethod,
        device_name: str = None
    ) -> MfaDevice:
        """Enable MFA for user with specified method."""
        # Check if method already enabled
        existing_devices = getattr(user, '_mfa_devices', [])
        for device in existing_devices:
            if device.method == method and device.is_active:
                return device
        
        # Validate business rules
        if len(existing_devices) >= 5:  # Max 5 MFA devices
            raise ValueError("Maximum number of MFA devices reached")
        
        # Create new MFA device
        device = MfaDevice.create(
            user_id=user.id,
            name=device_name or f"{method.value} Device {len(existing_devices) + 1}",
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
            mfa_method=method.value,
            device_id=device.id
        ))
        
        return device
    
    @staticmethod
    def disable_mfa(user: User, device_id: UUID = None) -> None:
        """Disable MFA for user (specific device or all)."""
        if not hasattr(user, '_mfa_devices'):
            return
        
        if device_id:
            # Disable specific device
            device = next((d for d in user._mfa_devices if d.id == device_id), None)
            if device:
                device.deactivate()
        else:
            # Disable all MFA devices
            for device in user._mfa_devices:
                device.deactivate()
            
            # Update user state only if disabling all
            user.mfa_enabled = False
            user._regenerate_security_stamp()
        
        user._touch()
        
        # Add domain event
        user.add_domain_event(UserMFADisabled(
            user_id=user.id,
            device_id=device_id
        ))
    
    @staticmethod
    def generate_backup_codes(user: User, count: int = 10) -> list[str]:
        """Generate MFA backup codes."""
        if count < 5 or count > 20:
            raise ValueError("Backup code count must be between 5 and 20")
        
        # Clear existing backup codes
        if not hasattr(user, 'backup_codes'):
            user.backup_codes = []
        else:
            user.backup_codes.clear()
        
        # Generate new codes
        codes = []
        for _ in range(count):
            # Generate 8-digit code
            code = ''.join(secrets.choice('0123456789') for _ in range(8))
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            
            # Store hash of code (without formatting)
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            user.backup_codes.append(code_hash)
            codes.append(formatted_code)
        
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
        if not code or not code.strip():
            return False
        
        # Clean the code
        clean_code = code.replace('-', '').replace(' ', '')
        
        # Try backup codes first (8 digits)
        if clean_code.isdigit() and len(clean_code) == 8:
            return MFAService._use_backup_code(user, clean_code)
        
        # Try TOTP codes (6 digits)
        if clean_code.isdigit() and len(clean_code) == 6:
            return MFAService._verify_totp_code(user, clean_code)
        
        return False
    
    @staticmethod
    def _verify_totp_code(user: User, code: str) -> bool:
        """Verify TOTP code against active MFA devices."""
        if not hasattr(user, '_mfa_devices'):
            return False
        
        for device in user._mfa_devices:
            if device.is_active and device.method == MfaMethod.TOTP:
                if device.verify_code(code):
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
        if not device_fingerprint:
            raise ValueError("Device fingerprint is required")
        
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
            # Validate device limit
            if len(user._registered_devices) >= 20:  # Max 20 trusted devices
                raise ValueError("Maximum number of trusted devices reached")
            
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
            if getattr(device, 'is_primary', False):
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
                # Unset other devices as primary
                if hasattr(device, 'is_primary'):
                    device.is_primary = False
        
        if not target_device:
            raise ValueError("MFA device not found")
        
        if not target_device.is_active:
            raise ValueError("Cannot set inactive device as primary")
        
        if hasattr(target_device, 'verified') and not target_device.verified:
            raise ValueError("Device must be verified before setting as primary")
        
        target_device.is_primary = True
        user._touch()
    
    @staticmethod
    def validate_mfa_setup(user: User) -> dict[str, any]:
        """Validate user's MFA setup and return status."""
        devices = MFAService.get_active_mfa_devices(user)
        
        status = {
            "has_mfa": len(devices) > 0,
            "device_count": len(devices),
            "has_backup_codes": hasattr(user, 'backup_codes') and len(user.backup_codes) > 0,
            "backup_codes_count": len(getattr(user, 'backup_codes', [])),
            "has_primary_device": MFAService.get_primary_mfa_device(user) is not None,
            "methods": [device.method.value for device in devices],
            "recommendations": []
        }
        
        # Generate recommendations
        if not status["has_mfa"]:
            status["recommendations"].append("Enable multi-factor authentication for better security")
        
        if status["has_mfa"] and not status["has_backup_codes"]:
            status["recommendations"].append("Generate backup codes for account recovery")
        
        if status["has_mfa"] and not status["has_primary_device"]:
            status["recommendations"].append("Set a primary MFA device")
        
        if status["backup_codes_count"] > 0 and status["backup_codes_count"] < 5:
            status["recommendations"].append("Generate new backup codes (running low)")
        
        return status
    
    @staticmethod
    def calculate_mfa_strength(user: User) -> float:
        """Calculate MFA strength score (0.0 to 1.0)."""
        if not hasattr(user, '_mfa_devices'):
            return 0.0
        
        active_devices = MFAService.get_active_mfa_devices(user)
        if not active_devices:
            return 0.0
        
        strength = 0.0
        
        # Base score for having MFA
        strength += 0.3
        
        # Device diversity bonus
        methods = {device.method for device in active_devices}
        if MfaMethod.TOTP in methods:
            strength += 0.3
        if MfaMethod.SMS in methods:
            strength += 0.2
        if MfaMethod.EMAIL in methods:
            strength += 0.1
        
        # Backup codes bonus
        if hasattr(user, 'backup_codes') and user.backup_codes:
            strength += 0.2
        
        # Multiple devices bonus
        if len(active_devices) > 1:
            strength += 0.1
        
        return min(1.0, strength)
