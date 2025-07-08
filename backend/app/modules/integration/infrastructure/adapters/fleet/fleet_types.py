"""Common types and models for fleet management integrations."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class VehicleStatus(Enum):
    """Vehicle status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    OUT_OF_SERVICE = "out_of_service"


class DriverStatus(Enum):
    """Driver status enumeration."""

    AVAILABLE = "available"
    DRIVING = "driving"
    ON_DUTY = "on_duty"
    OFF_DUTY = "off_duty"
    BREAK = "break"


class AlertSeverity(Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Location:
    """Geographic location model."""

    latitude: float
    longitude: float
    address: str | None = None
    timestamp: datetime | None = None
    accuracy: float | None = None  # In meters

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "address": self.address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "accuracy": self.accuracy,
        }


@dataclass
class Vehicle:
    """Vehicle model."""

    id: str
    name: str
    license_plate: str
    vin: str | None = None
    make: str | None = None
    model: str | None = None
    year: int | None = None
    status: VehicleStatus = VehicleStatus.ACTIVE
    current_location: Location | None = None
    odometer: float | None = None  # In kilometers
    fuel_level: float | None = None  # Percentage
    engine_hours: float | None = None
    last_updated: datetime | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "license_plate": self.license_plate,
            "vin": self.vin,
            "make": self.make,
            "model": self.model,
            "year": self.year,
            "status": self.status.value,
            "current_location": self.current_location.to_dict()
            if self.current_location
            else None,
            "odometer": self.odometer,
            "fuel_level": self.fuel_level,
            "engine_hours": self.engine_hours,
            "last_updated": self.last_updated.isoformat()
            if self.last_updated
            else None,
            "metadata": self.metadata or {},
        }


@dataclass
class Driver:
    """Driver model."""

    id: str
    name: str
    license_number: str | None = None
    phone: str | None = None
    email: str | None = None
    status: DriverStatus = DriverStatus.OFF_DUTY
    current_vehicle_id: str | None = None
    current_location: Location | None = None
    hours_this_week: float | None = None
    last_updated: datetime | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "license_number": self.license_number,
            "phone": self.phone,
            "email": self.email,
            "status": self.status.value,
            "current_vehicle_id": self.current_vehicle_id,
            "current_location": self.current_location.to_dict()
            if self.current_location
            else None,
            "hours_this_week": self.hours_this_week,
            "last_updated": self.last_updated.isoformat()
            if self.last_updated
            else None,
            "metadata": self.metadata or {},
        }


@dataclass
class Route:
    """Route model."""

    id: str
    name: str
    start_location: Location
    end_location: Location
    waypoints: list[Location]
    estimated_duration: int | None = None  # In minutes
    estimated_distance: float | None = None  # In kilometers
    vehicle_id: str | None = None
    driver_id: str | None = None
    status: str = "planned"
    created_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "start_location": self.start_location.to_dict(),
            "end_location": self.end_location.to_dict(),
            "waypoints": [wp.to_dict() for wp in self.waypoints],
            "estimated_duration": self.estimated_duration,
            "estimated_distance": self.estimated_distance,
            "vehicle_id": self.vehicle_id,
            "driver_id": self.driver_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "metadata": self.metadata or {},
        }


@dataclass
class FleetAlert:
    """Fleet alert model."""

    id: str
    type: str
    severity: AlertSeverity
    message: str
    vehicle_id: str | None = None
    driver_id: str | None = None
    location: Location | None = None
    timestamp: datetime | None = None
    acknowledged: bool = False
    resolved: bool = False
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "message": self.message,
            "vehicle_id": self.vehicle_id,
            "driver_id": self.driver_id,
            "location": self.location.to_dict() if self.location else None,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
            "metadata": self.metadata or {},
        }


@dataclass
class TelematicsData:
    """Telematics data model."""

    vehicle_id: str
    timestamp: datetime
    location: Location
    speed: float | None = None  # km/h
    heading: float | None = None  # degrees
    rpm: int | None = None
    fuel_level: float | None = None  # percentage
    engine_temperature: float | None = None  # celsius
    odometer: float | None = None  # kilometers
    engine_hours: float | None = None
    harsh_braking: bool = False
    harsh_acceleration: bool = False
    speeding: bool = False
    idle_time: int | None = None  # seconds
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vehicle_id": self.vehicle_id,
            "timestamp": self.timestamp.isoformat(),
            "location": self.location.to_dict(),
            "speed": self.speed,
            "heading": self.heading,
            "rpm": self.rpm,
            "fuel_level": self.fuel_level,
            "engine_temperature": self.engine_temperature,
            "odometer": self.odometer,
            "engine_hours": self.engine_hours,
            "harsh_braking": self.harsh_braking,
            "harsh_acceleration": self.harsh_acceleration,
            "speeding": self.speeding,
            "idle_time": self.idle_time,
            "metadata": self.metadata or {},
        }


@dataclass
class FleetSummary:
    """Fleet summary statistics."""

    total_vehicles: int
    active_vehicles: int
    total_drivers: int
    active_drivers: int
    total_distance_today: float  # kilometers
    total_fuel_consumed_today: float  # liters
    active_alerts: int
    maintenance_due: int
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_vehicles": self.total_vehicles,
            "active_vehicles": self.active_vehicles,
            "total_drivers": self.total_drivers,
            "active_drivers": self.active_drivers,
            "total_distance_today": self.total_distance_today,
            "total_fuel_consumed_today": self.total_fuel_consumed_today,
            "active_alerts": self.active_alerts,
            "maintenance_due": self.maintenance_due,
            "timestamp": self.timestamp.isoformat(),
        }
