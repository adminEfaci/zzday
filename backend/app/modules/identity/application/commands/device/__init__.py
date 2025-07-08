"""
Device management commands module.

This module contains all commands for managing user devices,
device trust levels, and device-based security policies.
"""

from .analyze_device_risk_command import (
    AnalyzeDeviceRiskCommand,
    AnalyzeDeviceRiskCommandHandler,
)
from .quarantine_device_command import (
    QuarantineDeviceCommand,
    QuarantineDeviceCommandHandler,
)
from .register_device_command import RegisterDeviceCommand, RegisterDeviceCommandHandler
from .revoke_device_command import RevokeDeviceCommand, RevokeDeviceCommandHandler
from .sync_device_policies_command import (
    SyncDevicePoliciesCommand,
    SyncDevicePoliciesCommandHandler,
)
from .track_device_location_command import (
    TrackDeviceLocationCommand,
    TrackDeviceLocationCommandHandler,
)
from .trust_device_command import TrustDeviceCommand, TrustDeviceCommandHandler
from .untrust_device_command import UntrustDeviceCommand, UntrustDeviceCommandHandler
from .update_device_command import UpdateDeviceCommand, UpdateDeviceCommandHandler
from .wipe_device_command import WipeDeviceCommand, WipeDeviceCommandHandler

__all__ = [
    # Analyze Device Risk
    "AnalyzeDeviceRiskCommand",
    "AnalyzeDeviceRiskCommandHandler",
    # Quarantine Device
    "QuarantineDeviceCommand",
    "QuarantineDeviceCommandHandler",
    # Register Device
    "RegisterDeviceCommand",
    "RegisterDeviceCommandHandler",
    # Revoke Device
    "RevokeDeviceCommand",
    "RevokeDeviceCommandHandler",
    # Sync Device Policies
    "SyncDevicePoliciesCommand",
    "SyncDevicePoliciesCommandHandler",
    # Track Device Location
    "TrackDeviceLocationCommand",
    "TrackDeviceLocationCommandHandler",
    # Trust Device
    "TrustDeviceCommand",
    "TrustDeviceCommandHandler",
    # Untrust Device
    "UntrustDeviceCommand",
    "UntrustDeviceCommandHandler",
    # Update Device  
    "UpdateDeviceCommand",
    "UpdateDeviceCommandHandler",
    # Wipe Device
    "WipeDeviceCommand",
    "WipeDeviceCommandHandler",
]