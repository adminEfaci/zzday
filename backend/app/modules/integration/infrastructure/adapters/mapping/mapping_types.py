"""Common types and models for mapping and routing integrations."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class RouteProfile(Enum):
    """Route optimization profile."""

    DRIVING = "driving"
    WALKING = "walking"
    CYCLING = "cycling"
    DRIVING_TRAFFIC = "driving-traffic"
    TRUCK = "truck"


class TrafficCondition(Enum):
    """Traffic condition levels."""

    UNKNOWN = "unknown"
    FREE_FLOW = "free_flow"
    LIGHT = "light"
    MODERATE = "moderate"
    HEAVY = "heavy"
    SEVERE = "severe"


class GeocodeType(Enum):
    """Geocoding result types."""

    ADDRESS = "address"
    POI = "poi"
    INTERSECTION = "intersection"
    POSTCODE = "postcode"
    LOCALITY = "locality"


@dataclass
class Coordinate:
    """Geographic coordinate pair."""

    latitude: float
    longitude: float

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {"latitude": self.latitude, "longitude": self.longitude}

    def to_list(self) -> list[float]:
        """Convert to [longitude, latitude] list (GeoJSON format)."""
        return [self.longitude, self.latitude]


@dataclass
class BoundingBox:
    """Geographic bounding box."""

    southwest: Coordinate
    northeast: Coordinate

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "southwest": self.southwest.to_dict(),
            "northeast": self.northeast.to_dict(),
        }


@dataclass
class Address:
    """Structured address information."""

    formatted_address: str
    street_number: str | None = None
    street_name: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    country_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "formatted_address": self.formatted_address,
            "street_number": self.street_number,
            "street_name": self.street_name,
            "city": self.city,
            "state": self.state,
            "postal_code": self.postal_code,
            "country": self.country,
            "country_code": self.country_code,
        }


@dataclass
class GeocodeResult:
    """Geocoding result."""

    coordinate: Coordinate
    address: Address
    confidence: float
    type: GeocodeType
    bounding_box: BoundingBox | None = None
    place_id: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "coordinate": self.coordinate.to_dict(),
            "address": self.address.to_dict(),
            "confidence": self.confidence,
            "type": self.type.value,
            "bounding_box": self.bounding_box.to_dict() if self.bounding_box else None,
            "place_id": self.place_id,
            "metadata": self.metadata or {},
        }


@dataclass
class RouteStep:
    """Individual step in a route."""

    instruction: str
    distance: float  # In meters
    duration: int  # In seconds
    start_coordinate: Coordinate
    end_coordinate: Coordinate
    maneuver: str | None = None
    street_name: str | None = None
    geometry: list[Coordinate] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "instruction": self.instruction,
            "distance": self.distance,
            "duration": self.duration,
            "start_coordinate": self.start_coordinate.to_dict(),
            "end_coordinate": self.end_coordinate.to_dict(),
            "maneuver": self.maneuver,
            "street_name": self.street_name,
            "geometry": [coord.to_dict() for coord in self.geometry]
            if self.geometry
            else None,
        }


@dataclass
class RouteSegment:
    """Segment of a route between waypoints."""

    start_coordinate: Coordinate
    end_coordinate: Coordinate
    distance: float  # In meters
    duration: int  # In seconds
    steps: list[RouteStep]
    traffic_condition: TrafficCondition = TrafficCondition.UNKNOWN
    traffic_duration: int | None = None  # Duration with traffic

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start_coordinate": self.start_coordinate.to_dict(),
            "end_coordinate": self.end_coordinate.to_dict(),
            "distance": self.distance,
            "duration": self.duration,
            "traffic_condition": self.traffic_condition.value,
            "traffic_duration": self.traffic_duration,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class Route:
    """Complete route information."""

    origin: Coordinate
    destination: Coordinate
    waypoints: list[Coordinate]
    segments: list[RouteSegment]
    total_distance: float  # In meters
    total_duration: int  # In seconds
    profile: RouteProfile
    overview_geometry: list[Coordinate]
    traffic_duration: int | None = None
    departure_time: datetime | None = None
    arrival_time: datetime | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "origin": self.origin.to_dict(),
            "destination": self.destination.to_dict(),
            "waypoints": [wp.to_dict() for wp in self.waypoints],
            "segments": [seg.to_dict() for seg in self.segments],
            "total_distance": self.total_distance,
            "total_duration": self.total_duration,
            "profile": self.profile.value,
            "overview_geometry": [coord.to_dict() for coord in self.overview_geometry],
            "traffic_duration": self.traffic_duration,
            "departure_time": self.departure_time.isoformat()
            if self.departure_time
            else None,
            "arrival_time": self.arrival_time.isoformat()
            if self.arrival_time
            else None,
            "metadata": self.metadata or {},
        }


@dataclass
class DistanceMatrix:
    """Distance matrix between multiple points."""

    origins: list[Coordinate]
    destinations: list[Coordinate]
    distances: list[list[float]]  # In meters, [origin_index][destination_index]
    durations: list[list[int]]  # In seconds, [origin_index][destination_index]
    profile: RouteProfile
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "origins": [origin.to_dict() for origin in self.origins],
            "destinations": [dest.to_dict() for dest in self.destinations],
            "distances": self.distances,
            "durations": self.durations,
            "profile": self.profile.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class MapTile:
    """Map tile information."""

    x: int
    y: int
    z: int  # Zoom level
    format: str  # png, jpg, webp, etc.
    url: str
    size: int = 512  # Tile size in pixels

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "format": self.format,
            "url": self.url,
            "size": self.size,
        }


@dataclass
class TrafficInfo:
    """Real-time traffic information."""

    coordinate: Coordinate
    speed: float  # km/h
    free_flow_speed: float  # km/h
    current_travel_time: int  # seconds
    free_flow_travel_time: int  # seconds
    confidence: float
    road_closure: bool = False
    incident_type: str | None = None
    last_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "coordinate": self.coordinate.to_dict(),
            "speed": self.speed,
            "free_flow_speed": self.free_flow_speed,
            "current_travel_time": self.current_travel_time,
            "free_flow_travel_time": self.free_flow_travel_time,
            "confidence": self.confidence,
            "road_closure": self.road_closure,
            "incident_type": self.incident_type,
            "last_updated": self.last_updated.isoformat()
            if self.last_updated
            else None,
        }


@dataclass
class PlaceInfo:
    """Place information from search."""

    place_id: str
    name: str
    coordinate: Coordinate
    address: Address
    category: str | None = None
    phone: str | None = None
    website: str | None = None
    rating: float | None = None
    opening_hours: list[str] | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "place_id": self.place_id,
            "name": self.name,
            "coordinate": self.coordinate.to_dict(),
            "address": self.address.to_dict(),
            "category": self.category,
            "phone": self.phone,
            "website": self.website,
            "rating": self.rating,
            "opening_hours": self.opening_hours,
            "metadata": self.metadata or {},
        }


@dataclass
class OptimizedRoute:
    """Optimized route for multiple waypoints."""

    optimized_order: list[int]  # Indices of waypoints in optimal order
    route: Route
    optimization_time: float  # Time taken to optimize in seconds
    savings: dict[str, float]  # Distance/time savings vs. original order

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "optimized_order": self.optimized_order,
            "route": self.route.to_dict(),
            "optimization_time": self.optimization_time,
            "savings": self.savings,
        }
