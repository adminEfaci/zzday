"""MFA-related domain events."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .base import IdentityDomainEvent


class MFADeviceCreated(IdentityDomainEvent):
    """Event raised when an MFA device is created."""
    device_id: UUID
    user_id: UUID
    method: str
    device_name: str
    verified: bool

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFADeviceVerified(IdentityDomainEvent):
    """Event raised when an MFA device is verified."""
    device_id: UUID
    user_id: UUID
    method: str
    verified_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFADeviceDisabled(IdentityDomainEvent):
    """Event raised when an MFA device is disabled."""
    device_id: UUID
    user_id: UUID
    method: str
    disabled_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFACodeVerificationFailed(IdentityDomainEvent):
    """Event raised when MFA code verification fails."""
    device_id: UUID
    user_id: UUID
    failed_attempts: int
    timestamp: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class DeviceRegistered(IdentityDomainEvent):
    """Event raised when a device is registered."""
    device_id: UUID
    user_id: UUID
    device_name: str
    device_type: str
    fingerprint: str
    trusted: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class DeviceTrusted(IdentityDomainEvent):
    """Event raised when a device is marked as trusted."""
    device_id: UUID
    user_id: UUID
    trusted_by: UUID | None = None
    trust_method: str = Field(default="user_confirmation")

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class DeviceUntrusted(IdentityDomainEvent):
    """Event raised when a device is untrusted."""
    user_id: UUID
    device_id: UUID
    untrusted_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)