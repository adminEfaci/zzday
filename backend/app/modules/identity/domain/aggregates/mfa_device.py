"""
MFA Device Aggregate

Represents a multi-factor authentication device aggregate for a user.
"""

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from ...entities.user.user_events import BackupCodeGenerated, BackupCodeUsed, MFAEnabled
from ...shared.base_entity import IdentityAggregate, SecurityValidationMixin
from ..enums import MFAMethod
from ..events import (
    MFACodeVerificationFailed,
    MFADeviceCreated,
    MFADeviceDisabled,
    MFADeviceVerified,
)


# Create missing value object classes locally
@dataclass(frozen=True)
class BackupCode:
    value: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_used: bool = False
    used_at: datetime | None = None
    
    @classmethod
    def generate(cls) -> 'BackupCode':
        import secrets
        return cls(value=secrets.token_hex(8))
    
    def mark_as_used(self) -> None:
        object.__setattr__(self, 'is_used', True)
        object.__setattr__(self, 'used_at', datetime.now(UTC))
    
    def hash(self) -> str:
        import hashlib
        return hashlib.sha256(self.value.encode()).hexdigest()

@dataclass(frozen=True)
class DeviceName:
    value: str
    
    def __post_init__(self):
        if not self.value or len(self.value.strip()) < 2:
            raise ValueError("Device name must be at least 2 characters")

@dataclass(frozen=True)
class MFASecret:
    value: str
    algorithm: str = "sha1"
    
    @classmethod
    def generate_totp(cls) -> 'MFASecret':
        import secrets
        secret = secrets.token_urlsafe(32)
        return cls(value=secret, algorithm="sha1")
    
    @classmethod
    def generate(cls) -> 'MFASecret':
        import secrets
        return cls(value=secrets.token_urlsafe(32))


@dataclass
class MFADevice(IdentityAggregate, SecurityValidationMixin):
    """MFA device aggregate for two-factor authentication."""
    
    id: UUID
    user_id: UUID
    method: MFAMethod
    device_name: DeviceName
    secret: MFASecret
    backup_codes: list[BackupCode] = field(default_factory=list)
    verified: bool = False
    is_primary: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_used: datetime | None = None
    failed_attempts: int = 0
    locked_until: datetime | None = None
    
    # Method-specific attributes
    phone_number: str | None = None  # For SMS method
    email: str | None = None  # For email method
    credential_id: str | None = None  # For hardware key method
    
    def _validate_entity(self) -> None:
        """Validate MFA device business rules."""
        # Validate secret format
        if self.secret.value:
            self.validate_token_format(self.secret.value, "MFA secret")
        
        # Emit creation event
        self.add_domain_event(MFADeviceCreated(
            device_id=self.id,
            user_id=self.user_id,
            method=self.method.value,
            device_name=self.device_name.value,
            verified=self.verified
        ))
    
    @classmethod
    def create(
        cls,
        user_id: UUID,
        method: MFAMethod,
        device_name: str | DeviceName,
        generate_backup_codes: bool = True
    ) -> 'MFADevice':
        """Create a new MFA device."""
        # Generate secret based on device type
        if method == MFAMethod.TOTP:
            # Generate TOTP secret using value object
            secret = MFASecret.generate_totp()
        elif method == MFAMethod.SMS:
            # For SMS, create empty secret
            secret = MFASecret(value="", algorithm="sms")
        else:
            # Generate generic secret
            secret = MFASecret.generate()
        
        # Ensure device_name is a DeviceName value object
        if isinstance(device_name, str):
            device_name_obj = DeviceName(value=device_name)
        else:
            device_name_obj = device_name
        
        device = cls(
            id=uuid4(),
            user_id=user_id,
            method=method,
            device_name=device_name_obj,
            secret=secret,
            created_at=datetime.now(UTC)
        )
        
        # Generate backup codes if requested
        if generate_backup_codes:
            device.generate_backup_codes()
        
        return device
    
    @staticmethod
    def _generate_totp_secret() -> str:
        """Generate a base32 secret for TOTP."""
        # Generate 20 bytes (160 bits) of random data
        random_bytes = secrets.token_bytes(20)
        
        # Base32 alphabet
        base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        
        # Convert to base32
        secret = ""
        for i in range(0, len(random_bytes), 5):
            # Take 5 bytes and convert to 8 base32 characters
            chunk = random_bytes[i:i+5]
            
            # Pad with zeros if necessary
            while len(chunk) < 5:
                chunk += b'\x00'
            
            # Convert to integer
            value = int.from_bytes(chunk, 'big')
            
            # Extract 8 5-bit values
            for j in range(8):
                index = (value >> (35 - j * 5)) & 0x1F
                secret += base32_chars[index]
        
        return secret[:32]  # Return 32 characters
    
    def verify_code(self, code: str) -> bool:
        """Verify an MFA code."""
        if self.is_locked():
            return False
        
        # Implementation would vary by device type
        # For TOTP, would use pyotp or similar
        # For SMS, would check against sent code
        # This is a placeholder
        is_valid = self._verify_code_internal(code)
        
        if is_valid:
            self.failed_attempts = 0
            self.last_used = datetime.now(UTC)
            
            if not self.verified:
                self.verified = True
                
                self.add_domain_event(MFADeviceVerified(
                    device_id=self.id,
                    user_id=self.user_id,
                    method=self.method.value,
                    verified_at=datetime.now(UTC)
                ))
                
                self.add_domain_event(MFAEnabled(
                    user_id=self.user_id,
                    device_id=self.id,
                    device_type=self.method.value,
                    device_name=self.device_name.value,
                    enabled_at=datetime.now(UTC)
                ))
        else:
            self.failed_attempts += 1
            
            # Emit failed verification event
            self.add_domain_event(MFACodeVerificationFailed(
                device_id=self.id,
                user_id=self.user_id,
                failed_attempts=self.failed_attempts,
                timestamp=datetime.now(UTC)
            ))
            
            # Lock after 5 failed attempts
            if self.failed_attempts >= 5:
                self.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        
        return is_valid
    
    def _verify_code_internal(self, code: str) -> bool:
        """Internal code verification logic."""
        # Basic verification logic based on method type
        if self.method == MFAMethod.TOTP:
            # For TOTP, check if code is 6 digits
            # In production, would use pyotp library to verify against secret
            return len(code) == 6 and code.isdigit()
        if self.method == MFAMethod.SMS:
            # For SMS, would check against stored code sent to phone
            # This is a simplified check
            return len(code) == 6 and code.isdigit()
        if self.method == MFAMethod.EMAIL:
            # For email, would check against stored code sent to email
            return len(code) == 6 and code.isdigit()
        # For other methods, basic validation
        return len(code) >= 6
    
    def generate_backup_codes(self, count: int = 8) -> list[str]:
        """Generate backup codes."""
        self.backup_codes = []
        
        for _ in range(count):
            # Generate backup code using value object
            backup_code = BackupCode.generate()
            self.backup_codes.append(backup_code)
        
        self.add_domain_event(BackupCodeGenerated(
            user_id=self.user_id,
            code_count=count,
            generated_by=self.user_id,
            expires_at=datetime.now(UTC) + timedelta(days=365)
        ))
        
        # Return the string values for external use
        return [code.value for code in self.backup_codes]
    
    def use_backup_code(self, code: str) -> bool:
        """Use a backup code."""
        # Find the backup code that matches
        matching_code = None
        for backup_code in self.backup_codes:
            if backup_code.value == code:
                matching_code = backup_code
                break
        
        if matching_code and not matching_code.is_used:
            # Mark as used and remove from list
            matching_code.mark_as_used()
            self.backup_codes.remove(matching_code)
            self.last_used = datetime.now(UTC)
            
            remaining = len(self.backup_codes)
            
            self.add_domain_event(BackupCodeUsed(
                user_id=self.user_id,
                code_hash=matching_code.hash(),
                used_at=datetime.now(UTC),
                remaining_codes=remaining,
                ip_address=""  # Would be passed in
            ))
            
            return True
        
        return False
    
    def set_as_primary(self) -> None:
        """Set device as primary."""
        if not self.verified:
            raise ValueError("Device must be verified before setting as primary")
        
        self.is_primary = True
    
    @property
    def is_active(self) -> bool:
        """Check if device is active."""
        if self.locked_until and self.locked_until > datetime.now(UTC):
            return False
        
        return self.verified
    
    def deactivate(self) -> None:
        """Deactivate MFA device."""
        self.verified = False
        self.is_primary = False
    
    def update_last_used(self) -> None:
        """Update last used timestamp."""
        self.last_used = datetime.now(UTC)
        self.failed_attempts = 0  # Reset failed attempts on successful use
    
    def disable(self) -> None:
        """Disable the MFA device."""
        was_verified = self.verified
        
        self.verified = False
        self.is_primary = False
        self.backup_codes = []
        self.touch()
        
        if was_verified:
            self.add_domain_event(MFADeviceDisabled(
                device_id=self.id,
                user_id=self.user_id,
                method=self.method.value,
                disabled_at=datetime.now(UTC)
            ))
    
    def is_locked(self) -> bool:
        """Check if device is locked."""
        if self.locked_until is None:
            return False
        
        return datetime.now(UTC) < self.locked_until
    
    def get_remaining_backup_codes(self) -> int:
        """Get count of remaining backup codes."""
        return len(self.backup_codes)
    
    def needs_backup_codes(self) -> bool:
        """Check if device needs new backup codes."""
        return len(self.backup_codes) < 3
    
    def get_device_info(self) -> dict[str, Any]:
        """Get device information for display."""
        return {
            "id": str(self.id),
            "method": self.method.get_display_name(),
            "device_name": self.device_name.value,
            "verified": self.verified,
            "is_primary": self.is_primary,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "backup_codes_remaining": len(self.backup_codes),
            "is_locked": self.is_locked()
        }
    
    def unlock(self, unlocked_by: UUID | None = None) -> None:
        """Manually unlock a locked device."""
        if not self.is_locked():
            return
        
        self.locked_until = None
        self.failed_attempts = 0
        
        # Add unlock event if needed
        self.add_domain_event({
            "type": "MFADeviceUnlocked",
            "device_id": self.id,
            "user_id": self.user_id,
            "unlocked_by": unlocked_by or self.user_id,
            "unlocked_at": datetime.now(UTC)
        })
    
    def rotate_secret(self) -> str:
        """Rotate the device secret for enhanced security."""
        if self.method not in [MFAMethod.TOTP]:
            raise ValueError(f"Secret rotation not supported for {self.method.value}")
        
        self.secret = MFASecret.generate_totp()
        
        # Emit secret rotated event
        self.add_domain_event({
            "type": "MFASecretRotated",
            "device_id": self.id,
            "user_id": self.user_id,
            "method": self.method.value,
            "rotated_at": datetime.now(UTC)
        })
        
        return self.secret.value
    
    def calculate_trust_score(self) -> float:
        """Calculate device trust score based on usage patterns."""
        score = 1.0
        
        # Factor 1: Verification status
        if not self.verified:
            score *= 0.5
        
        # Factor 2: Usage frequency
        if self.last_used:
            days_since_use = (datetime.now(UTC) - self.last_used).days
            if days_since_use > 30:
                score *= 0.8
            elif days_since_use > 90:
                score *= 0.6
        else:
            score *= 0.7
        
        # Factor 3: Failed attempts
        if self.failed_attempts > 0:
            score *= max(0.5, 1.0 - (self.failed_attempts * 0.1))
        
        # Factor 4: Device age
        device_age_days = (datetime.now(UTC) - self.created_at).days
        if device_age_days > 180:
            score *= 1.1  # Bonus for long-standing devices
        elif device_age_days < 7:
            score *= 0.9  # Slight penalty for very new devices
        
        # Factor 5: Primary device bonus
        if self.is_primary:
            score *= 1.2
        
        return min(1.0, max(0.0, score))
    
    def should_require_reverification(self) -> bool:
        """Check if device should be reverified based on security policy."""
        # Require reverification if not used for 90 days
        if self.last_used:
            days_inactive = (datetime.now(UTC) - self.last_used).days
            if days_inactive > 90:
                return True
        
        # Require reverification if trust score is low
        if self.calculate_trust_score() < 0.5:
            return True
        
        # Require reverification after multiple failed attempts
        return self.failed_attempts >= 3
    
    def update_phone_number(self, new_phone: str, verified_by: UUID) -> None:
        """Update phone number for SMS device."""
        if self.method != MFAMethod.SMS:
            raise ValueError("Phone number can only be updated for SMS devices")
        
        old_phone = self.phone_number
        self.phone_number = new_phone
        self.verified = False  # Require reverification with new number
        
        self.add_domain_event({
            "type": "MFAPhoneNumberUpdated",
            "device_id": self.id,
            "user_id": self.user_id,
            "old_phone": old_phone,
            "new_phone": new_phone,
            "updated_by": verified_by,
            "updated_at": datetime.now(UTC)
        })
    
    def update_email(self, new_email: str, verified_by: UUID) -> None:
        """Update email for email-based MFA device."""
        if self.method != MFAMethod.EMAIL:
            raise ValueError("Email can only be updated for email devices")
        
        old_email = self.email
        self.email = new_email
        self.verified = False  # Require reverification with new email
        
        self.add_domain_event({
            "type": "MFAEmailUpdated",
            "device_id": self.id,
            "user_id": self.user_id,
            "old_email": old_email,
            "new_email": new_email,
            "updated_by": verified_by,
            "updated_at": datetime.now(UTC)
        })
    
    def can_be_primary(self) -> bool:
        """Check if device can be set as primary based on business rules."""
        if not self.verified:
            return False
        
        if self.is_locked():
            return False
        
        # SMS and Email methods might not be allowed as primary
        # depending on security policy
        if self.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            # Could check organization policy here
            pass
        
        return True
    
    def estimate_time_until_unlock(self) -> timedelta | None:
        """Get estimated time until device is unlocked."""
        if not self.is_locked() or not self.locked_until:
            return None
        
        remaining = self.locked_until - datetime.now(UTC)
        return remaining if remaining > timedelta(0) else timedelta(0)
    
    def regenerate_single_backup_code(self, old_code: str) -> str | None:
        """Regenerate a single used backup code."""
        # Find and remove the used code
        for i, code in enumerate(self.backup_codes):
            if code.value == old_code and code.is_used:
                self.backup_codes.pop(i)
                new_code = BackupCode.generate()
                self.backup_codes.append(new_code)
                
                self.add_domain_event({
                    "type": "BackupCodeRegenerated",
                    "device_id": self.id,
                    "user_id": self.user_id,
                    "regenerated_at": datetime.now(UTC)
                })
                
                return new_code.value
        
        return None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "method": self.method.value,
            "device_name": self.device_name.value,
            "secret": self.secret,  # Should be encrypted in storage
            "backup_codes": self.backup_codes,  # Should be hashed in storage
            "verified": self.verified,
            "is_primary": self.is_primary,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "trust_score": self.calculate_trust_score()
        }