"""
Device Registration Entity

Represents a registered device for trust and tracking.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

# No value object imports needed - using primitives
from ..enums import DevicePlatform, DeviceType
from ..events import DeviceRegistered, DeviceTrusted, DeviceUntrusted
from .shared.base_entity import IdentityEntity, SecurityValidationMixin


@dataclass
class DeviceRegistration(IdentityEntity, SecurityValidationMixin):
    """Device registration entity for device trust management."""

    id: UUID
    user_id: UUID
    device_id: str  # Unique device identifier
    device_name: str
    device_type: DeviceType
    fingerprint: str  # Store fingerprint as string
    platform: DevicePlatform
    trusted: bool = False
    trust_expires_at: datetime | None = None
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    push_token: str | None = None
    app_version: str | None = None
    os_version: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def _validate_entity(self) -> None:
        """Validate device registration business rules."""
        if not self.device_id:
            raise ValueError("Device ID is required")

        if not self.device_name or not self.device_name.strip():
            raise ValueError("Device name is required")

        # Validate fingerprint format
        if self.fingerprint:
            self.validate_token_format(self.fingerprint, "device fingerprint")

        # Add registration event
        self.add_domain_event(DeviceRegistered(
            user_id=self.user_id,
            device_id=self.id,
            device_name=self.device_name,
            device_type=self.device_type.value,
            fingerprint=self.fingerprint,
            trusted=self.trusted
        ))

    @classmethod
    def create(
        cls,
        user_id: UUID,
        device_id: str,
        device_name: str,
        device_type: DeviceType,
        fingerprint: str,
        platform: DevicePlatform,
        push_token: str | None = None,
        app_version: str | None = None,
        os_version: str | None = None
    ) -> 'DeviceRegistration':
        """Create a new device registration."""
        return cls(
            id=uuid4(),
            user_id=user_id,
            device_id=device_id,
            device_name=device_name,
            device_type=device_type,
            fingerprint=fingerprint,
            platform=platform,
            push_token=push_token,
            app_version=app_version,
            os_version=os_version,
            created_at=datetime.now(UTC),
            last_seen=datetime.now(UTC)
        )

    def trust(self, trusted_by: UUID | None = None, trust_duration_days: int = 30) -> None:
        """Mark device as trusted."""
        if self.trusted and self.trust_expires_at and self.trust_expires_at > datetime.now(UTC):
            return  # Already trusted and not expired

        self.trusted = True
        self.trust_expires_at = datetime.now(UTC) + timedelta(days=trust_duration_days)

        self.add_domain_event(DeviceTrusted(
            user_id=self.user_id,
            device_id=self.id,
            trusted_by=trusted_by,
            trust_method="user_confirmation"
        ))

    def untrust(self) -> None:
        """Remove device trust."""
        was_trusted = self.trusted
        
        self.trusted = False
        self.trust_expires_at = None
        self.touch()
        
        if was_trusted:
            self.add_domain_event(DeviceUntrusted(
                user_id=self.user_id,
                device_id=self.id,
                untrusted_at=datetime.now(UTC)
            ))

    def is_trusted(self) -> bool:
        """Check if device is currently trusted."""
        if not self.trusted:
            return False

        if self.trust_expires_at and self.trust_expires_at < datetime.now(UTC):
            # Trust expired
            self.trusted = False
            self.trust_expires_at = None
            return False

        return True

    def update_info(
        self,
        device_name: str | None = None,
        push_token: str | None = None,
        app_version: str | None = None,
        os_version: str | None = None
    ) -> None:
        """Update device information."""
        if device_name is not None:
            self.device_name = device_name

        if push_token is not None:
            self.push_token = push_token

        if app_version is not None:
            self.app_version = app_version

        if os_version is not None:
            self.os_version = os_version

        self.last_seen = datetime.now(UTC)

    def update_fingerprint(self, new_fingerprint: str) -> None:
        """Update device fingerprint."""
        # Check if fingerprint changed significantly
        if self.fingerprint != new_fingerprint:
            # Fingerprint changed - untrust device for security
            self.untrust()

        self.fingerprint = new_fingerprint
        self.last_seen = datetime.now(UTC)

    def build_push_notification_data(self, notification: dict[str, Any]) -> dict[str, Any]:
        """
        Build notification data for sending to the device.
        Raises ValueError or PermissionError if data is incomplete or device is untrusted.
        """
        if not self.push_token:
            raise ValueError("Device is missing a push token.")
        if not self.is_trusted():
            raise PermissionError("Device is not trusted.")
        return {
            "token": self.push_token,
            "platform": self.platform.value,
            "device_type": self.device_type.value,
            "notification": notification
        }

    def get_days_since_last_seen(self) -> int:
        """Get days since device was last seen."""
        delta = datetime.now(UTC) - self.last_seen
        return delta.days

    def should_cleanup(self, inactive_days: int = 90) -> bool:
        """Check if device should be cleaned up due to inactivity."""
        return self.get_days_since_last_seen() > inactive_days

    def get_device_info(self) -> dict[str, Any]:
        """Get device information for display."""
        return {
            "id": str(self.id),
            "device_name": self.device_name,
            "device_type": self.device_type.get_display_name(),
            "platform": self.platform.get_display_name(),
            "trusted": self.is_trusted(),
            "last_seen": self.last_seen.isoformat(),
            "days_since_seen": self.get_days_since_last_seen(),
            "app_version": self.app_version,
            "os_version": self.os_version,
            "has_push_token": bool(self.push_token)
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type.value,
            "fingerprint": self.fingerprint,
            "platform": self.platform.value,
            "trusted": self.trusted,
            "trust_expires_at": self.trust_expires_at.isoformat() if self.trust_expires_at else None,
            "last_seen": self.last_seen.isoformat(),
            "push_token": self.push_token,
            "app_version": self.app_version,
            "os_version": self.os_version,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }
