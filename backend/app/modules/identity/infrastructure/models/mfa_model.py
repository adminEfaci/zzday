"""
MFA Device Model

SQLModel definition for MFA device persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.modules.identity.domain.entities.admin.mfa_device import (
    BackupCode,
    DeviceName,
    MFADevice,
    MFASecret,
)
from app.modules.identity.domain.enums import MFAMethod as MfaMethod


class BackupCodeModel(SQLModel, table=True):
    """Backup code persistence model."""
    
    __tablename__ = "mfa_backup_codes"
    
    # Identity
    id: UUID = Field(primary_key=True)
    device_id: UUID = Field(index=True)
    code_hash: str = Field(index=True)  # Hashed backup code
    
    # Status
    is_used: bool = Field(default=False, index=True)
    used_at: datetime | None = Field(default=None)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(index=True)
    
    @classmethod
    def from_backup_code(cls, device_id: UUID, code: BackupCode, expires_at: datetime) -> "BackupCodeModel":
        """Create model from backup code value object."""
        return cls(
            id=UUID(),  # Generate new ID for the database record
            device_id=device_id,
            code_hash=code.hash(),
            is_used=code.is_used,
            used_at=code.used_at,
            created_at=code.created_at,
            expires_at=expires_at
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "device_id": str(self.device_id),
            "is_used": self.is_used,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }


class MFADeviceModel(SQLModel, table=True):
    """MFA device persistence model."""
    
    __tablename__ = "mfa_devices"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    
    # Device details
    method: str = Field(index=True)
    device_name: str
    secret: str  # Encrypted secret
    secret_algorithm: str = Field(default="sha1")
    
    # Status
    verified: bool = Field(default=False, index=True)
    is_primary: bool = Field(default=False, index=True)
    is_enabled: bool = Field(default=True, index=True)
    
    # Security tracking
    failed_attempts: int = Field(default=0)
    locked_until: datetime | None = Field(default=None)
    
    # Method-specific data
    phone_number: str | None = Field(default=None)  # For SMS method
    email_address: str | None = Field(default=None)  # For email method
    device_info: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))  # For push notifications
    
    # Recovery codes (separate table for better security and performance)
    recovery_codes_generated: bool = Field(default=False)
    recovery_codes_count: int = Field(default=0)
    
    # Activity tracking
    last_used: datetime | None = Field(default=None, index=True)
    verification_count: int = Field(default=0)
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    verified_at: datetime | None = Field(default=None)
    disabled_at: datetime | None = Field(default=None)
    
    @classmethod
    def from_domain(cls, device: MFADevice) -> "MFADeviceModel":
        """Create model from domain entity."""
        # Extract method-specific data
        phone_number = None
        email_address = None
        device_info = {}
        
        if device.method == MfaMethod.SMS:
            phone_number = device.metadata.get("phone_number") if hasattr(device, "metadata") else None
        elif device.method == MfaMethod.EMAIL:
            email_address = device.metadata.get("email_address") if hasattr(device, "metadata") else None
        elif device.method == MfaMethod.PUSH_NOTIFICATION:
            device_info = device.metadata.get("device_info", {}) if hasattr(device, "metadata") else {}
        
        return cls(
            id=device.id,
            user_id=device.user_id,
            method=device.method.value if isinstance(device.method, MfaMethod) else device.method,
            device_name=device.device_name.value if hasattr(device.device_name, 'value') else str(device.device_name),
            secret=device.secret.value if hasattr(device.secret, 'value') else str(device.secret),
            secret_algorithm=device.secret.algorithm if hasattr(device.secret, 'algorithm') else "sha1",
            verified=device.verified,
            is_primary=device.is_primary,
            is_enabled=device.is_active() if hasattr(device, 'is_active') else True,
            failed_attempts=device.failed_attempts,
            locked_until=device.locked_until,
            phone_number=phone_number,
            email_address=email_address,
            device_info=device_info,
            recovery_codes_generated=len(device.backup_codes) > 0,
            recovery_codes_count=len(device.backup_codes),
            last_used=device.last_used,
            verification_count=getattr(device, 'verification_count', 0),
            metadata=getattr(device, 'metadata', {}),
            created_at=device.created_at,
            updated_at=datetime.now(UTC),
            verified_at=getattr(device, 'verified_at', None),
            disabled_at=getattr(device, 'disabled_at', None)
        )
    
    def to_domain(self) -> MFADevice:
        """Convert to domain entity."""
        # Handle enums
        method = MfaMethod(self.method) if self.method else MfaMethod.TOTP
        
        # Create value objects
        device_name_obj = DeviceName(value=self.device_name)
        secret_obj = MFASecret(value=self.secret, algorithm=self.secret_algorithm)
        
        # Create device instance
        device = MFADevice(
            id=self.id,
            user_id=self.user_id,
            method=method,
            device_name=device_name_obj,
            secret=secret_obj,
            backup_codes=[],  # Will be loaded separately from BackupCodeModel
            verified=self.verified,
            is_primary=self.is_primary,
            created_at=self.created_at,
            last_used=self.last_used,
            failed_attempts=self.failed_attempts,
            locked_until=self.locked_until
        )
        
        # Add metadata based on method
        if hasattr(device, 'metadata'):
            if self.phone_number and method == MfaMethod.SMS:
                device.metadata['phone_number'] = self.phone_number
            elif self.email_address and method == MfaMethod.EMAIL:
                device.metadata['email_address'] = self.email_address
            elif self.device_info and method == MfaMethod.PUSH_NOTIFICATION:
                device.metadata['device_info'] = self.device_info
        
        return device
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "method": self.method,
            "device_name": self.device_name,
            "verified": self.verified,
            "is_primary": self.is_primary,
            "is_enabled": self.is_enabled,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "phone_number": self.phone_number,
            "email_address": self.email_address,
            "device_info": self.device_info,
            "recovery_codes_count": self.recovery_codes_count,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "verification_count": self.verification_count,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None
        }


class RecoveryCodeModel(SQLModel, table=True):
    """Recovery code persistence model (separate from backup codes for enhanced security)."""
    
    __tablename__ = "mfa_recovery_codes"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    code_hash: str = Field(index=True)  # Hashed recovery code
    
    # Status
    is_used: bool = Field(default=False, index=True)
    used_at: datetime | None = Field(default=None)
    used_for_device_id: UUID | None = Field(default=None)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(index=True)
    
    @classmethod
    def from_code(cls, user_id: UUID, code_hash: str, expires_at: datetime) -> "RecoveryCodeModel":
        """Create model from recovery code."""
        return cls(
            id=UUID(),
            user_id=user_id,
            code_hash=code_hash,
            is_used=False,
            created_at=datetime.now(UTC),
            expires_at=expires_at
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "is_used": self.is_used,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "used_for_device_id": str(self.used_for_device_id) if self.used_for_device_id else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }