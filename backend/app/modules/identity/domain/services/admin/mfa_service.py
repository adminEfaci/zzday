"""
Multi-Factor Authentication Domain Service

MFA device management, code generation, and verification using existing utilities.
"""

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.security import generate_token, generate_verification_code
from app.utils.crypto import (
    generate_random_string,
    mask_sensitive_data,
)

from ...enums import MfaDeviceStatus, MfaMethod
from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.contracts.notification_contract import INotificationContract
from ...interfaces.repositories.user.mfa_device_repository import IMFADeviceRepository
from ...interfaces.repositories.user.user_repository import IUserRepository
from ...interfaces.services.authentication.mfa_service import IMFAService
from ...interfaces.services.infrastructure.cache_port import ICachePort
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort


@dataclass
class MFADeviceInfo:
    """MFA device information."""
    id: str
    method: str
    name: str
    is_primary: bool
    last_used_at: str | None
    backup_codes_remaining: int
    is_locked: bool


class MFAService(IMFAService):
    """Domain service for multi-factor authentication."""
    
    def __init__(
        self,
        mfa_device_repository: IMFADeviceRepository,
        user_repository: IUserRepository,
        audit_contract: IAuditContract,
        notification_contract: INotificationContract,
        configuration_port: IConfigurationPort,
        cache_port: ICachePort
    ) -> None:
        self._mfa_device_repository = mfa_device_repository
        self._user_repository = user_repository
        self._audit_contract = audit_contract
        self._notification_contract = notification_contract
        self._config = configuration_port
        self._cache = cache_port
    
    async def generate_totp_secret(self, user_id: UUID) -> dict[str, Any]:
        """Generate TOTP secret for user."""
        
        # Validate input
        if not user_id:
            raise ValueError("User ID is required")
        
        # Get configuration
        config = await self._config.get_mfa_settings()
        issuer_name = config.get('issuer_name', 'EzzDay')
        max_devices = config.get('max_devices_per_user', 5)
        
        # Get user for email
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Check device limits
        existing_devices = await self._mfa_device_repository.get_by_user_id(user_id)
        if len(existing_devices) >= max_devices:
            raise ValueError(f"Maximum {max_devices} MFA devices allowed")
        
        # Generate secret and codes using existing utilities
        secret = self._generate_totp_secret()
        backup_codes = self._generate_backup_codes()
        qr_code = self._generate_totp_qr_code(user.email.value, secret, issuer_name)
        
        # Create device in pending state
        device_id = UUID(generate_token(16))
        device_data = {
            'id': device_id,
            'user_id': user_id,
            'name': f"TOTP - {datetime.utcnow().strftime('%Y-%m-%d')}",
            'method': MfaMethod.TOTP,
            'secret': secret,
            'backup_codes': backup_codes,
            'status': MfaDeviceStatus.PENDING_VERIFICATION
        }
        
        await self._mfa_device_repository.save(device_data)
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="mfa_device_setup_initiated",
            user_id=user_id,
            details={
                "device_id": str(device_id),
                "method": MfaMethod.TOTP.value,
                "device_name": device_data['name']
            }
        )
        
        return {
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        }
    
    async def verify_totp_code(self, user_id: UUID, code: str) -> bool:
        """Verify TOTP code."""
        
        # Validate inputs
        if not user_id or not code:
            return False
        
        if not code.isdigit() or len(code) != 6:
            return False
        
        # Get user's TOTP devices
        devices = await self._mfa_device_repository.get_by_user_id_and_method(
            user_id, MfaMethod.TOTP
        )
        
        active_devices = [d for d in devices if d.status == MfaDeviceStatus.ACTIVE]
        
        if not active_devices:
            await self._log_mfa_failure(user_id, "no_active_totp_devices", MfaMethod.TOTP)
            return False
        
        # Try each active device
        for device in active_devices:
            if await self._verify_device_totp_code(device, code):
                await self._handle_mfa_success(user_id, device)
                return True
        
        # Log failed verification
        await self._log_mfa_failure(user_id, "invalid_totp_code", MfaMethod.TOTP, len(active_devices))
        return False
    
    async def generate_backup_codes(self, user_id: UUID, count: int = 10) -> list[str]:
        """Generate backup codes."""
        
        # Validate inputs
        if not user_id:
            raise ValueError("User ID is required")
        
        if count < 1 or count > 20:
            raise ValueError("Backup code count must be between 1 and 20")
        
        # Get user's devices
        devices = await self._mfa_device_repository.get_by_user_id(user_id)
        active_devices = [d for d in devices if d.status == MfaDeviceStatus.ACTIVE]
        
        if not active_devices:
            raise ValueError("No active MFA devices found")
        
        # Generate new backup codes using crypto utility
        backup_codes = self._generate_backup_codes(count)
        
        # Update all active devices with new backup codes
        for device in active_devices:
            await self._mfa_device_repository.update_backup_codes(device.id, backup_codes)
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="mfa_backup_codes_generated",
            user_id=user_id,
            details={
                "count": count,
                "device_count": len(active_devices)
            }
        )
        
        return backup_codes
    
    async def verify_backup_code(self, user_id: UUID, code: str) -> bool:
        """Verify and consume backup code."""
        
        # Validate inputs
        if not user_id or not code:
            return False
        
        # Validate backup code format (XXXX-XXXX)
        if not self._is_valid_backup_code_format(code):
            return False
        
        # Get user's devices
        devices = await self._mfa_device_repository.get_by_user_id(user_id)
        active_devices = [d for d in devices if d.status == MfaDeviceStatus.ACTIVE]
        
        for device in active_devices:
            if await self._use_backup_code(device, code):
                await self._handle_backup_code_success(user_id, device)
                return True
        
        # Log failed backup code attempt
        await self._audit_contract.log_event(
            event_type="mfa_backup_code_failed",
            user_id=user_id,
            details={
                "reason": "invalid_backup_code",
                "device_count": len(active_devices)
            }
        )
        
        return False
    
    async def send_sms_code(
        self, 
        user_id: UUID, 
        phone: str,
        purpose: str = "login"
    ) -> str:
        """Send SMS verification code."""
        
        # Validate inputs
        if not user_id or not phone:
            raise ValueError("User ID and phone number are required")
        
        # Generate code using existing security utility
        code = generate_verification_code(6)
        code_id = generate_token(16)
        
        # Store code in cache with expiration
        cache_data = await self._create_verification_cache_data(
            code, user_id, phone, purpose, "sms"
        )
        
        config = await self._config.get_mfa_settings()
        expiry_minutes = config.get('sms_code_expiry_minutes', 5)
        
        await self._cache.set(
            f"mfa_sms:{code_id}", 
            cache_data, 
            expiry_seconds=expiry_minutes * 60
        )
        
        # Send SMS through notification contract
        message = f"Your {purpose} code is: {code}. Valid for {expiry_minutes} minutes."
        await self._notification_contract.send_sms(
            phone_number=phone,
            message=message
        )
        
        # Log audit event with masked phone
        await self._audit_contract.log_event(
            event_type="mfa_sms_code_sent",
            user_id=user_id,
            details={
                "code_id": code_id,
                "phone_masked": mask_sensitive_data(phone, 4),
                "purpose": purpose
            }
        )
        
        return code_id
    
    async def verify_sms_code(self, code_id: str, code: str) -> bool:
        """Verify SMS code."""
        
        # Validate inputs
        if not code_id or not code:
            return False
        
        return await self._verify_cached_code("sms", code_id, code)
    
    async def send_email_code(
        self, 
        user_id: UUID, 
        email: str,
        purpose: str = "login"
    ) -> str:
        """Send email verification code."""
        
        # Validate inputs
        if not user_id or not email:
            raise ValueError("User ID and email are required")
        
        # Generate code
        code = generate_verification_code(6)
        code_id = generate_token(16)
        
        # Store code in cache
        cache_data = await self._create_verification_cache_data(
            code, user_id, email, purpose, "email"
        )
        
        config = await self._config.get_mfa_settings()
        expiry_minutes = config.get('email_code_expiry_minutes', 10)
        
        await self._cache.set(
            f"mfa_email:{code_id}", 
            cache_data, 
            expiry_seconds=expiry_minutes * 60
        )
        
        # Send email through notification contract
        await self._notification_contract.send_email(
            email_address=email,
            subject=f"Your {purpose} verification code",
            body=f"Your verification code is: {code}\n\nThis code will expire in {expiry_minutes} minutes."
        )
        
        # Log audit event
        await self._audit_contract.log_event(
            event_type="mfa_email_code_sent",
            user_id=user_id,
            details={
                "code_id": code_id,
                "email": email,
                "purpose": purpose
            }
        )
        
        return code_id
    
    async def verify_email_code(self, code_id: str, code: str) -> bool:
        """Verify email code."""
        
        # Validate inputs
        if not code_id or not code:
            return False
        
        return await self._verify_cached_code("email", code_id, code)
    
    async def get_available_methods(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get available MFA methods for user."""
        
        if not user_id:
            return []
        
        devices = await self._mfa_device_repository.get_by_user_id(user_id)
        active_devices = [d for d in devices if d.status == MfaDeviceStatus.ACTIVE]
        
        methods = []
        for device in active_devices:
            device_info = MFADeviceInfo(
                id=str(device.id),
                method=device.method.value,
                name=device.name,
                is_primary=device.is_primary,
                last_used_at=device.last_used_at.isoformat() if device.last_used_at else None,
                backup_codes_remaining=len([c for c in device.backup_codes if c]),
                is_locked=device.is_locked()
            )
            
            methods.append({
                "id": device_info.id,
                "method": device_info.method,
                "name": device_info.name,
                "is_primary": device_info.is_primary,
                "last_used_at": device_info.last_used_at,
                "backup_codes_remaining": device_info.backup_codes_remaining,
                "is_locked": device_info.is_locked
            })
        
        return methods
    
    # Private helper methods
    
    def _generate_totp_secret(self) -> str:
        """Generate TOTP secret using crypto utilities."""
        # Generate 160-bit secret (20 bytes) using secure random
        secret_bytes = base64.b64decode(generate_token(20))
        return base64.b32encode(secret_bytes).decode('ascii')
    
    def _generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate backup codes using crypto utilities."""
        codes = []
        for _ in range(count):
            # Generate code with format: XXXX-XXXX using secure random
            part1 = generate_random_string(4, "0123456789")
            part2 = generate_random_string(4, "0123456789")
            codes.append(f"{part1}-{part2}")
        return codes
    
    def _generate_totp_qr_code(self, email: str, secret: str, issuer: str) -> str | None:
        """Generate QR code for TOTP setup."""
        try:
            import io

            import qrcode
            
            # Generate provisioning URL
            url = (
                f"otpauth://totp/{issuer}:{email}"
                f"?secret={secret}"
                f"&issuer={issuer}"
                f"&algorithm=SHA1"
                f"&digits=6"
                f"&period=30"
            )
            
            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            # Create image
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
        except ImportError:
            # If qrcode library not available, return None
            return None
    
    async def _verify_device_totp_code(self, device: dict[str, Any], code: str) -> bool:
        """Verify TOTP code for specific device."""
        try:
            # Decode secret
            key = base64.b32decode(device['secret'])
            
            # Get current time window (30-second periods)
            current_time = int(time.time() // 30)
            
            # Check current and adjacent windows (for clock skew)
            for time_offset in [-1, 0, 1]:
                time_counter = (current_time + time_offset).to_bytes(8, byteorder='big')
                
                # Generate HMAC
                hmac_hash = hmac.new(key, time_counter, hashlib.sha1).digest()
                
                # Dynamic truncation
                offset = hmac_hash[-1] & 0xf
                code_int = int.from_bytes(hmac_hash[offset:offset+4], byteorder='big')
                code_int &= 0x7fffffff
                code_int %= 1000000  # 6 digits
                
                # Compare with provided code
                if f"{code_int:06d}" == code:
                    return True
            
            return False
        except Exception:
            return False
    
    async def _use_backup_code(self, device: dict[str, Any], code: str) -> bool:
        """Use backup code for device."""
        backup_codes = device.get('backup_codes', [])
        
        if code in backup_codes:
            # Remove used code
            backup_codes.remove(code)
            await self._mfa_device_repository.update_backup_codes(device['id'], backup_codes)
            return True
        
        return False
    
    async def _create_verification_cache_data(
        self, 
        code: str, 
        user_id: UUID, 
        contact: str, 
        purpose: str, 
        method: str
    ) -> dict[str, Any]:
        """Create cache data for verification codes."""
        return {
            "code": code,
            "user_id": str(user_id),
            "contact": contact,
            "purpose": purpose,
            "method": method,
            "created_at": datetime.utcnow().isoformat()
        }
    
    async def _verify_cached_code(self, method: str, code_id: str, code: str) -> bool:
        """Verify cached verification code."""
        cache_key = f"mfa_{method}:{code_id}"
        cache_data = await self._cache.get(cache_key)
        
        if not cache_data:
            return False
        
        user_id = UUID(cache_data["user_id"])
        
        if cache_data["code"] == code:
            # Remove used code
            await self._cache.delete(cache_key)
            
            # Log successful verification
            await self._audit_contract.log_event(
                event_type=f"mfa_{method}_verification_success",
                user_id=user_id,
                details={
                    "code_id": code_id,
                    "purpose": cache_data["purpose"]
                }
            )
            
            return True
        
        # Log failed verification
        await self._audit_contract.log_event(
            event_type=f"mfa_{method}_verification_failed",
            user_id=user_id,
            details={
                "code_id": code_id,
                "reason": "invalid_code"
            }
        )
        
        return False
    
    async def _handle_mfa_success(self, user_id: UUID, device: dict[str, Any]) -> None:
        """Handle successful MFA verification."""
        # Update device last used
        await self._mfa_device_repository.update_last_used(device.id)
        
        # Log successful verification
        await self._audit_contract.log_event(
            event_type="mfa_verification_success",
            user_id=user_id,
            details={
                "device_id": str(device.id),
                "method": device.method.value,
                "device_name": device.name
            }
        )
    
    async def _handle_backup_code_success(self, user_id: UUID, device: dict[str, Any]) -> None:
        """Handle successful backup code use."""
        # Log successful backup code use
        await self._audit_contract.log_event(
            event_type="mfa_backup_code_used",
            user_id=user_id,
            details={
                "device_id": str(device.id),
                "device_name": device.name,
                "risk_indicator": "backup_code_usage"
            }
        )
        
        # Send security notification
        await self._notification_contract.send_notification(
            user_id=user_id,
            notification_type="security_alert",
            content={
                "title": "Backup Code Used",
                "message": "A backup code was used to access your account.",
                "device_name": device.name,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    async def _log_mfa_failure(
        self, 
        user_id: UUID, 
        reason: str, 
        method: MfaMethod, 
        device_count: int | None = None
    ) -> None:
        """Log MFA verification failure."""
        details = {
            "reason": reason,
            "method": method.value
        }
        
        if device_count is not None:
            details["device_count"] = device_count
        
        await self._audit_contract.log_event(
            event_type="mfa_verification_failed",
            user_id=user_id,
            details=details
        )
    
    def _is_valid_backup_code_format(self, code: str) -> bool:
        """Check if code matches backup code format (XXXX-XXXX)."""
        import re
        return bool(re.match(r'^\d{4}-\d{4}$', code))