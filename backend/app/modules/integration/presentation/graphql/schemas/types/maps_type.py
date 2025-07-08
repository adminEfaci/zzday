"""GraphQL types for Maps service entities.

This module provides GraphQL type definitions for maps service integration,
including geocoding, routing, and location services.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..enums import MapsProviderEnum


@strawberry.type
class Location:
    """GraphQL type for geographic locations."""

    latitude: float
    longitude: float
    altitude: float | None = None
    accuracy: float | None = None  # meters

    # Address components
    street_number: str | None = None
    street_name: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    country_code: str | None = None

    # Formatted address
    formatted_address: str | None = None

    # Additional metadata
    place_id: str | None = None  # Provider-specific place identifier
    place_type: str | None = None  # "address", "poi", "business", etc.
    confidence_score: float | None = None  # 0.0 to 1.0

    @strawberry.field
    def coordinates(self) -> str:
        """Get coordinates as comma-separated string."""
        return f"{self.latitude},{self.longitude}"


@strawberry.type
class Bounds:
    """GraphQL type for geographic bounds."""

    northeast_lat: float
    northeast_lng: float
    southwest_lat: float
    southwest_lng: float

    @strawberry.field
    def center(self) -> Location:
        """Calculate center point of bounds."""
        center_lat = (self.northeast_lat + self.southwest_lat) / 2
        center_lng = (self.northeast_lng + self.southwest_lng) / 2
        return Location(latitude=center_lat, longitude=center_lng)


@strawberry.type
class RouteStep:
    """GraphQL type for route steps."""

    step_number: int
    instruction: str
    distance_meters: float
    duration_seconds: int

    # Location information
    start_location: Location
    end_location: Location

    # Polyline for step
    polyline: str | None = None

    # Maneuver information
    maneuver: str | None = None  # "turn-left", "turn-right", "straight", etc.

    @strawberry.field
    def distance_km(self) -> float:
        """Get distance in kilometers."""
        return self.distance_meters / 1000

    @strawberry.field
    def duration_minutes(self) -> float:
        """Get duration in minutes."""
        return self.duration_seconds / 60


@strawberry.type
class Route:
    """GraphQL type for routes."""

    route_id: UUID
    integration_id: UUID

    # Route details
    name: str | None = None
    summary: str

    # Locations
    origin: Location
    destination: Location
    waypoints: list[Location] = strawberry.field(default_factory=list)

    # Route metrics
    total_distance_meters: float
    total_duration_seconds: int

    # Route steps
    steps: list[RouteStep] = strawberry.field(default_factory=list)

    # Geometry
    polyline: str | None = None  # Encoded polyline
    bounds: Bounds | None = None

    # Route options
    avoid_tolls: bool = False
    avoid_highways: bool = False
    avoid_ferries: bool = False
    vehicle_type: str = "car"  # "car", "truck", "motorcycle", "bicycle", "walking"

    # Traffic information
    traffic_duration_seconds: int | None = None
    traffic_conditions: str = "unknown"  # "light", "moderate", "heavy", "unknown"

    # Alternative routes
    is_primary: bool = True
    alternative_routes: list["Route"] = strawberry.field(default_factory=list)

    # Timestamps
    calculated_at: datetime
    expires_at: datetime | None = None

    @strawberry.field
    def total_distance_km(self) -> float:
        """Get total distance in kilometers."""
        return self.total_distance_meters / 1000

    @strawberry.field
    def total_duration_minutes(self) -> float:
        """Get total duration in minutes."""
        return self.total_duration_seconds / 60

    @strawberry.field
    def traffic_delay_minutes(self) -> float:
        """Calculate traffic delay in minutes."""
        if not self.traffic_duration_seconds:
            return 0.0
        delay_seconds = self.traffic_duration_seconds - self.total_duration_seconds
        return max(0.0, delay_seconds / 60)


@strawberry.type
class GeocodingResult:
    """GraphQL type for geocoding results."""

    query: str
    locations: list[Location] = strawberry.field(default_factory=list)

    # Result metadata
    total_results: int = 0
    confidence_threshold: float = 0.8

    # Provider information
    provider: MapsProviderEnum
    provider_request_id: str | None = None

    # Performance
    response_time_ms: int = 0

    # Timestamps
    requested_at: datetime

    @strawberry.field
    def best_match(self) -> Location | None:
        """Get the best matching location."""
        if not self.locations:
            return None

        # Return location with highest confidence or first result
        best = max(
            self.locations, key=lambda loc: loc.confidence_score or 0.0, default=None
        )
        return best or self.locations[0]


@strawberry.type
class DistanceMatrix:
    """GraphQL type for distance matrix calculations."""

    origins: list[Location] = strawberry.field(default_factory=list)
    destinations: list[Location] = strawberry.field(default_factory=list)

    # Distance matrix data (row = origin, column = destination)
    distances_meters: list[list[float | None]] = strawberry.field(default_factory=list)
    durations_seconds: list[list[int | None]] = strawberry.field(default_factory=list)

    # Traffic-adjusted durations
    traffic_durations_seconds: list[list[int | None]] = strawberry.field(
        default_factory=list
    )

    # Options used
    vehicle_type: str = "car"
    avoid_tolls: bool = False
    avoid_highways: bool = False

    # Metadata
    provider: MapsProviderEnum
    calculated_at: datetime

    @strawberry.field
    def distance_km_matrix(self) -> list[list[float | None]]:
        """Get distance matrix in kilometers."""
        return [
            [(distance / 1000) if distance is not None else None for distance in row]
            for row in self.distances_meters
        ]

    @strawberry.field
    def duration_minutes_matrix(self) -> list[list[float | None]]:
        """Get duration matrix in minutes."""
        return [
            [(duration / 60) if duration is not None else None for duration in row]
            for row in self.durations_seconds
        ]


@strawberry.type
class PlaceDetails:
    """GraphQL type for place details."""

    place_id: str
    name: str
    location: Location

    # Place information
    place_types: list[str] = strawberry.field(default_factory=list)
    business_status: str | None = None
    phone_number: str | None = None
    website: str | None = None
    rating: float | None = None
    total_ratings: int | None = None

    # Opening hours
    is_open_now: bool | None = None
    opening_hours: list[str] = strawberry.field(default_factory=list)

    # Reviews
    reviews: list[dict[str, Any]] = strawberry.field(default_factory=list)

    # Photos
    photo_urls: list[str] = strawberry.field(default_factory=list)

    # Additional details
    price_level: int | None = None  # 0-4 scale
    wheelchair_accessible: bool | None = None

    # Provider information
    provider: MapsProviderEnum
    provider_url: str | None = None

    # Timestamps
    retrieved_at: datetime


@strawberry.type
class MapsConfiguration:
    """GraphQL type for maps service configuration."""

    # Default settings
    default_vehicle_type: str = "car"
    default_route_options: dict[str, bool] = strawberry.field(default_factory=dict)

    # Geocoding settings
    geocoding_language: str = "en"
    geocoding_region: str | None = None
    geocoding_confidence_threshold: float = 0.8

    # Routing settings
    routing_optimize: bool = True
    routing_alternatives: bool = True
    routing_traffic: bool = True

    # Caching settings
    cache_geocoding_results: bool = True
    cache_routing_results: bool = True
    cache_ttl_minutes: int = 60

    # Rate limiting
    rate_limit_per_minute: int = 60
    burst_limit: int = 10


@strawberry.type
class MapsUsageStatistics:
    """GraphQL type for maps usage statistics."""

    integration_id: UUID
    period_start: datetime
    period_end: datetime

    # API usage
    geocoding_requests: int = 0
    routing_requests: int = 0
    places_requests: int = 0
    distance_matrix_requests: int = 0

    # Performance metrics
    average_response_time_ms: float = 0.0
    success_rate: float = 100.0
    error_rate: float = 0.0

    # Cost tracking
    estimated_cost: float = 0.0
    cost_per_request: float = 0.0

    # Usage patterns
    peak_usage_hour: int = 12
    usage_by_hour: list[int] = strawberry.field(default_factory=list)

    # Most requested locations
    top_geocoded_addresses: list[str] = strawberry.field(default_factory=list)
    top_route_origins: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class MapsType:
    """GraphQL type for maps service management."""

    integration_id: UUID
    provider: MapsProviderEnum

    # Service status
    is_active: bool = True
    is_healthy: bool = True
    last_health_check: datetime | None = None

    # Configuration
    configuration: MapsConfiguration

    # Current limits and usage
    daily_quota: int | None = None
    daily_usage: int = 0
    rate_limit_remaining: int = 60

    # Recent activity
    recent_geocoding_requests: list[GeocodingResult] = strawberry.field(
        default_factory=list
    )
    recent_routing_requests: list[Route] = strawberry.field(default_factory=list)

    # Statistics
    daily_statistics: MapsUsageStatistics
    monthly_statistics: MapsUsageStatistics

    # Cache statistics
    cache_hit_rate: float = 0.0
    cached_items_count: int = 0

    # Provider-specific features
    supported_features: list[str] = strawberry.field(default_factory=list)

    # Last sync information
    last_sync: datetime | None = None
    sync_status: str = "idle"  # "idle", "syncing", "error"

    @strawberry.field
    def daily_quota_usage(self) -> float:
        """Calculate daily quota usage percentage."""
        if not self.daily_quota:
            return 0.0
        return (self.daily_usage / self.daily_quota) * 100

    @strawberry.field
    def requires_attention(self) -> bool:
        """Check if maps service requires attention."""
        return (
            not self.is_healthy
            or (self.daily_quota and self.daily_quota_usage() > 90)
            or self.daily_statistics.error_rate > 5.0
        )

    @strawberry.field
    def cost_efficiency_score(self) -> float:
        """Calculate cost efficiency score based on usage patterns."""
        if self.daily_statistics.geocoding_requests == 0:
            return 100.0

        # This would implement actual cost efficiency calculation
        return 85.0  # Placeholder


@strawberry.type
class MapsError:
    """GraphQL type for maps service errors."""

    success: bool = False
    message: str
    error_code: str

    # Maps-specific details
    request_type: str  # "geocoding", "routing", "places", "distance_matrix"
    query: str | None = None

    # Provider details
    provider: MapsProviderEnum | None = None
    provider_error_code: str | None = None
    provider_error_message: str | None = None

    # Location context
    coordinates: str | None = None
    address: str | None = None

    # Rate limiting details
    quota_exceeded: bool = False
    rate_limit_exceeded: bool = False
    retry_after: int | None = None

    # Recovery information
    alternative_providers: list[MapsProviderEnum] = strawberry.field(
        default_factory=list
    )

    # Timestamps
    occurred_at: datetime


__all__ = [
    "Bounds",
    "DistanceMatrix",
    "GeocodingResult",
    "Location",
    "MapsConfiguration",
    "MapsError",
    "MapsType",
    "MapsUsageStatistics",
    "PlaceDetails",
    "Route",
    "RouteStep",
]
