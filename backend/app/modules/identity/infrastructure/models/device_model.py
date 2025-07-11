"""
Device Registration Model

SQLModel definition for device registration persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.modules.identity.domain.entities.device.device_registration import (
    DeviceRegistration,
)
from app.modules.identity.domain.enums import DevicePlatform, DeviceType


class DeviceRegistrationModel(SQLModel, table=True):
    """Device registration persistence model."""
    
    __tablename__ = "device_registrations"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    device_id: str = Field(index=True)  # Unique device identifier
    device_name: str
    device_type: str = Field(index=True)
    fingerprint: str = Field(index=True)
    platform: str = Field(index=True)
    
    # Trust and security
    trusted: bool = Field(default=False, index=True)
    trust_expires_at: datetime | None = Field(default=None)
    
    # Device information
    push_token: str | None = Field(default=None)
    app_version: str | None = Field(default=None)
    os_version: str | None = Field(default=None)
    
    # Activity tracking
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    @classmethod
    def from_domain(cls, device: DeviceRegistration) -> "DeviceRegistrationModel":
        """Create model from domain entity."""
        return cls(
            id=device.id,
            user_id=device.user_id,
            device_id=device.device_id,
            device_name=device.device_name,
            device_type=device.device_type.value if isinstance(device.device_type, DeviceType) else device.device_type,
            fingerprint=device.fingerprint,
            platform=device.platform.value if isinstance(device.platform, DevicePlatform) else device.platform,
            trusted=device.trusted,
            trust_expires_at=device.trust_expires_at,
            push_token=device.push_token,
            app_version=device.app_version,
            os_version=device.os_version,
            last_seen=device.last_seen,
            metadata=device.metadata,
            created_at=device.created_at,
            updated_at=datetime.now(UTC),
        )
    
    def to_domain(self) -> DeviceRegistration:
        """Convert to domain entity."""
        # Handle enums
        device_type = DeviceType(self.device_type) if self.device_type else DeviceType.UNKNOWN
        platform = DevicePlatform(self.platform) if self.platform else DevicePlatform.UNKNOWN
        
        # Create device registration instance
        device = DeviceRegistration(
            id=self.id,
            user_id=self.user_id,
            device_id=self.device_id,
            device_name=self.device_name,
            device_type=device_type,
            fingerprint=self.fingerprint,
            platform=platform,
            trusted=self.trusted,
            trust_expires_at=self.trust_expires_at,
            last_seen=self.last_seen,
            push_token=self.push_token,
            app_version=self.app_version,
            os_version=self.os_version,
            created_at=self.created_at,
            metadata=self.metadata or {},
        )
        
        return device
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "fingerprint": self.fingerprint,
            "platform": self.platform,
            "trusted": self.trusted,
            "trust_expires_at": self.trust_expires_at.isoformat() if self.trust_expires_at else None,
            "push_token": self.push_token,
            "app_version": self.app_version,
            "os_version": self.os_version,
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }