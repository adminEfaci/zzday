"""GraphQL types for Fleet management entities.

This module provides GraphQL type definitions for fleet management integration,
including vehicles, drivers, routes, and tracking.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import FleetProviderEnum


@strawberry.type
class FleetLocation:
    """GraphQL type for fleet location data."""

    latitude: float
    longitude: float
    altitude: float | None = None
    accuracy: float | None = None  # meters
    heading: float | None = None  # degrees
    speed: float | None = None  # km/h

    # Address information
    address: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None

    # Geofence information
    geofences: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    recorded_at: datetime
    received_at: datetime | None = None


@strawberry.type
class FleetVehicle:
    """GraphQL type for fleet vehicles."""

    vehicle_id: UUID
    external_id: str  # ID from fleet provider
    integration_id: UUID

    # Vehicle details
    name: str
    make: str | None = None
    model: str | None = None
    year: int | None = None
    vin: str | None = None
    license_plate: str | None = None

    # Status
    is_active: bool = True
    is_online: bool = False
    last_seen: datetime | None = None

    # Current location
    current_location: FleetLocation | None = None

    # Vehicle metrics
    odometer_km: float | None = None
    fuel_level_percentage: float | None = None
    engine_hours: float | None = None

    # Driver assignment
    current_driver_id: UUID | None = None
    current_driver_name: str | None = None

    # Maintenance
    next_maintenance_km: float | None = None
    next_maintenance_date: datetime | None = None
    maintenance_alerts: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    created_at: datetime
    updated_at: datetime
    last_location_update: datetime | None = None


@strawberry.type
class FleetDriver:
    """GraphQL type for fleet drivers."""

    driver_id: UUID
    external_id: str
    integration_id: UUID

    # Driver details
    name: str
    email: str | None = None
    phone: str | None = None
    employee_id: str | None = None
    license_number: str | None = None
    license_expiry: datetime | None = None

    # Status
    is_active: bool = True
    is_on_duty: bool = False
    duty_status: str = "off_duty"  # "off_duty", "on_duty", "driving", "sleeper"

    # Current assignment
    current_vehicle_id: UUID | None = None
    current_location: FleetLocation | None = None

    # Performance metrics
    total_driving_hours: float = 0.0
    total_distance_km: float = 0.0
    safety_score: float | None = None
    fuel_efficiency_score: float | None = None

    # Hours of service
    hours_today: float = 0.0
    hours_this_week: float = 0.0
    available_hours: float = 0.0
    next_required_break: datetime | None = None

    # Violations and alerts
    violations: list[str] = strawberry.field(default_factory=list)
    alerts: list[str] = strawberry.field(default_factory=list)

    # Timestamps
    created_at: datetime
    updated_at: datetime
    last_activity: datetime | None = None


@strawberry.type
class FleetRoute:
    """GraphQL type for fleet routes."""

    route_id: UUID
    vehicle_id: UUID
    driver_id: UUID | None = None

    # Route details
    name: str
    description: str | None = None
    start_location: FleetLocation
    end_location: FleetLocation
    waypoints: list[FleetLocation] = strawberry.field(default_factory=list)

    # Route metrics
    total_distance_km: float
    estimated_duration_minutes: int
    actual_duration_minutes: int | None = None

    # Status
    status: str = "planned"  # "planned", "in_progress", "completed", "cancelled"
    progress_percentage: float = 0.0
    current_waypoint: int = 0

    # Timestamps
    planned_start: datetime
    planned_end: datetime
    actual_start: datetime | None = None
    actual_end: datetime | None = None

    # Tracking
    tracking_points: list[FleetLocation] = strawberry.field(default_factory=list)
    deviations: list[dict[str, Any]] = strawberry.field(default_factory=list)
    stops: list[dict[str, Any]] = strawberry.field(default_factory=list)


@strawberry.type
class FleetEvent:
    """GraphQL type for fleet events."""

    event_id: UUID
    vehicle_id: UUID | None = None
    driver_id: UUID | None = None

    # Event details
    event_type: str
    severity: str = "info"  # "info", "warning", "critical"
    title: str
    description: str

    # Location context
    location: FleetLocation | None = None

    # Event data
    data: dict[str, Any] = strawberry.field(default_factory=dict)

    # Status
    is_acknowledged: bool = False
    acknowledged_by: UUID | None = None
    acknowledged_at: datetime | None = None

    # Resolution
    is_resolved: bool = False
    resolution: str | None = None
    resolved_at: datetime | None = None

    # Timestamps
    occurred_at: datetime
    reported_at: datetime


@strawberry.type
class FleetGeofence:
    """GraphQL type for fleet geofences."""

    geofence_id: UUID
    integration_id: UUID

    # Geofence details
    name: str
    description: str | None = None
    type: str = "circle"  # "circle", "polygon"

    # Geographic definition
    center_latitude: float | None = None
    center_longitude: float | None = None
    radius_meters: float | None = None
    polygon_points: list[dict[str, float]] = strawberry.field(default_factory=list)

    # Rules
    entry_alerts_enabled: bool = True
    exit_alerts_enabled: bool = True
    speed_limit_kmh: float | None = None
    allowed_hours: str | None = None  # JSON string

    # Monitoring
    vehicles_inside: list[UUID] = strawberry.field(default_factory=list)
    recent_entries: list[dict[str, Any]] = strawberry.field(default_factory=list)
    recent_exits: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Status
    is_active: bool = True

    # Timestamps
    created_at: datetime
    updated_at: datetime


@strawberry.type
class FleetAnalytics:
    """GraphQL type for fleet analytics."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # Fleet overview
    total_vehicles: int = 0
    active_vehicles: int = 0
    total_drivers: int = 0
    active_drivers: int = 0

    # Usage metrics
    total_distance_km: float = 0.0
    total_driving_hours: float = 0.0
    average_utilization: float = 0.0

    # Efficiency metrics
    average_fuel_efficiency: float = 0.0
    fuel_cost_total: float = 0.0
    maintenance_cost_total: float = 0.0

    # Safety metrics
    total_violations: int = 0
    accident_count: int = 0
    safety_score: float = 100.0

    # Performance trends
    utilization_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)
    efficiency_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)
    safety_trend: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Top performers
    top_drivers: list[dict[str, Any]] = strawberry.field(default_factory=list)
    most_efficient_vehicles: list[dict[str, Any]] = strawberry.field(
        default_factory=list
    )

    # Recommendations
    optimization_suggestions: list[str] = strawberry.field(default_factory=list)
    maintenance_recommendations: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class FleetType:
    """GraphQL type for fleet management."""

    integration_id: UUID
    provider: FleetProviderEnum

    # Fleet overview
    total_vehicles: int = 0
    active_vehicles: int = 0
    online_vehicles: int = 0

    # Drivers
    total_drivers: int = 0
    active_drivers: int = 0
    on_duty_drivers: int = 0

    # Current data
    vehicles: list[FleetVehicle] = strawberry.field(default_factory=list)
    drivers: list[FleetDriver] = strawberry.field(default_factory=list)
    active_routes: list[FleetRoute] = strawberry.field(default_factory=list)

    # Recent activity
    recent_events: list[FleetEvent] = strawberry.field(default_factory=list)

    # Geofences
    geofences: list[FleetGeofence] = strawberry.field(default_factory=list)

    # Analytics
    analytics: FleetAnalytics

    # Configuration
    tracking_interval_seconds: int = 30
    event_types_monitored: list[str] = strawberry.field(default_factory=list)

    # Last sync information
    last_sync: datetime | None = None
    sync_status: str = "idle"  # "idle", "syncing", "error"

    @strawberry.field
    def vehicle_utilization_rate(self) -> float:
        """Calculate vehicle utilization rate."""
        if self.total_vehicles == 0:
            return 0.0
        return (self.active_vehicles / self.total_vehicles) * 100

    @strawberry.field
    def driver_utilization_rate(self) -> float:
        """Calculate driver utilization rate."""
        if self.total_drivers == 0:
            return 0.0
        return (self.on_duty_drivers / self.total_drivers) * 100

    @strawberry.field
    def fleet_health_score(self) -> float:
        """Calculate overall fleet health score."""
        # This would be calculated based on various metrics
        base_score = 100.0

        # Deduct for offline vehicles
        if self.active_vehicles > 0:
            offline_penalty = (
                (self.active_vehicles - self.online_vehicles) / self.active_vehicles
            ) * 20
            base_score -= offline_penalty

        # Add other health factors here
        return max(0.0, min(100.0, base_score))


@strawberry.type
class FleetError:
    """GraphQL type for fleet-specific errors."""

    success: bool = False
    message: str
    error_code: str

    # Fleet-specific details
    vehicle_id: UUID | None = None
    driver_id: UUID | None = None
    provider: FleetProviderEnum | None = None

    # API-specific details
    provider_error_code: str | None = None
    provider_error_message: str | None = None

    # Data sync details
    sync_operation: str | None = None
    failed_records: int = 0

    # Recovery information
    retry_available: bool = True
    retry_after: int | None = None

    # Timestamps
    occurred_at: datetime


__all__ = [
    "FleetAnalytics",
    "FleetDriver",
    "FleetError",
    "FleetEvent",
    "FleetGeofence",
    "FleetLocation",
    "FleetRoute",
    "FleetType",
    "FleetVehicle",
]
