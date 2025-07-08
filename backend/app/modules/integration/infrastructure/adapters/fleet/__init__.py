"""Fleet management adapter implementations."""

from .fleet_base_adapter import BaseFleetAdapter, FleetAdapterError
from .fleet_types import (
    AlertSeverity,
    Driver,
    DriverStatus,
    FleetAlert,
    FleetSummary,
    Location,
    Route,
    TelematicsData,
    Vehicle,
    VehicleStatus,
)
from .geotab_adapter import GeotabAdapter
from .samsara_adapter import SamsaraAdapter

__all__ = [
    "AlertSeverity",
    "BaseFleetAdapter",
    "Driver",
    "DriverStatus",
    "FleetAdapterError",
    "FleetAlert",
    "FleetSummary",
    "GeotabAdapter",
    "Location",
    "Route",
    "SamsaraAdapter",
    "TelematicsData",
    "Vehicle",
    "VehicleStatus",
]
