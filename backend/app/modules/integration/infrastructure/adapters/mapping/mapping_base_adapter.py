"""Base adapter interface for mapping and routing services."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from .mapping_types import (
    BoundingBox,
    Coordinate,
    DistanceMatrix,
    GeocodeResult,
    MapTile,
    OptimizedRoute,
    PlaceInfo,
    Route,
    RouteProfile,
    TrafficInfo,
)


class MappingAdapterError(Exception):
    """Base exception for mapping adapter errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        is_retryable: bool = True,
        provider_response: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.is_retryable = is_retryable
        self.provider_response = provider_response


class BaseMappingAdapter(ABC):
    """Base class for mapping and routing service adapters."""

    def __init__(self, config: dict[str, Any]):
        """Initialize mapping adapter.

        Args:
            config: Configuration dictionary containing:
                - credentials: API keys, tokens, etc.
                - settings: Provider-specific settings
                - rate_limits: Rate limiting configuration
        """
        self.config = config
        self.credentials = config.get("credentials", {})
        self.settings = config.get("settings", {})
        self.rate_limits = config.get("rate_limits", {})
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate configuration.

        Raises:
            ValueError: If configuration is invalid
        """

    # Geocoding
    @abstractmethod
    async def geocode(
        self, address: str, country: str | None = None, limit: int | None = None
    ) -> list[GeocodeResult]:
        """Geocode an address to coordinates.

        Args:
            address: Address string to geocode
            country: Country code to limit search (ISO 3166-1 alpha-2)
            limit: Maximum number of results to return

        Returns:
            List of geocoding results
        """

    @abstractmethod
    async def reverse_geocode(
        self, coordinate: Coordinate, language: str | None = None
    ) -> list[GeocodeResult]:
        """Reverse geocode coordinates to addresses.

        Args:
            coordinate: Coordinate to reverse geocode
            language: Language code for results (ISO 639-1)

        Returns:
            List of reverse geocoding results
        """

    # Routing
    @abstractmethod
    async def calculate_route(
        self,
        origin: Coordinate,
        destination: Coordinate,
        waypoints: list[Coordinate] | None = None,
        profile: RouteProfile = RouteProfile.DRIVING,
        departure_time: datetime | None = None,
        alternatives: bool = False,
    ) -> list[Route]:
        """Calculate route between points.

        Args:
            origin: Starting coordinate
            destination: Ending coordinate
            waypoints: Optional intermediate waypoints
            profile: Route profile (driving, walking, etc.)
            departure_time: Departure time for traffic-aware routing
            alternatives: Whether to return alternative routes

        Returns:
            List of routes (primary + alternatives if requested)
        """

    @abstractmethod
    async def optimize_route(
        self,
        origin: Coordinate,
        destinations: list[Coordinate],
        return_to_origin: bool = False,
        profile: RouteProfile = RouteProfile.DRIVING,
    ) -> OptimizedRoute:
        """Optimize route for multiple destinations.

        Args:
            origin: Starting coordinate
            destinations: List of destinations to visit
            return_to_origin: Whether to return to starting point
            profile: Route profile

        Returns:
            Optimized route with waypoint order
        """

    @abstractmethod
    async def calculate_distance_matrix(
        self,
        origins: list[Coordinate],
        destinations: list[Coordinate],
        profile: RouteProfile = RouteProfile.DRIVING,
        departure_time: datetime | None = None,
    ) -> DistanceMatrix:
        """Calculate distance matrix between multiple points.

        Args:
            origins: List of origin coordinates
            destinations: List of destination coordinates
            profile: Route profile
            departure_time: Departure time for traffic-aware calculations

        Returns:
            Distance matrix with distances and durations
        """

    # Map Services
    async def get_map_tile(
        self,
        x: int,
        y: int,
        z: int,
        style: str = "streets",
        format: str = "png",
        size: int = 512,
    ) -> MapTile | None:
        """Get map tile.

        Args:
            x: Tile X coordinate
            y: Tile Y coordinate
            z: Zoom level
            style: Map style
            format: Image format
            size: Tile size in pixels

        Returns:
            Map tile information if supported
        """
        # Default implementation returns None (not supported)
        return None

    # Traffic Services
    async def get_traffic_info(
        self, coordinates: list[Coordinate], radius: float | None = None
    ) -> list[TrafficInfo]:
        """Get real-time traffic information.

        Args:
            coordinates: List of coordinates to check
            radius: Search radius in meters

        Returns:
            List of traffic information if supported
        """
        # Default implementation returns empty list (not supported)
        return []

    # Places
    async def search_places(
        self,
        query: str,
        coordinate: Coordinate | None = None,
        radius: float | None = None,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[PlaceInfo]:
        """Search for places.

        Args:
            query: Search query
            coordinate: Center coordinate for search
            radius: Search radius in meters
            category: Place category filter
            limit: Maximum number of results

        Returns:
            List of places if supported
        """
        # Default implementation returns empty list (not supported)
        return []

    async def get_place_details(self, place_id: str) -> PlaceInfo | None:
        """Get detailed information about a place.

        Args:
            place_id: Place identifier

        Returns:
            Place details if supported
        """
        # Default implementation returns None (not supported)
        return None

    # Utility Methods
    def calculate_distance(self, coord1: Coordinate, coord2: Coordinate) -> float:
        """Calculate great circle distance between two coordinates.

        Args:
            coord1: First coordinate
            coord2: Second coordinate

        Returns:
            Distance in meters
        """
        import math

        # Haversine formula
        lat1, lon1 = math.radians(coord1.latitude), math.radians(coord1.longitude)
        lat2, lon2 = math.radians(coord2.latitude), math.radians(coord2.longitude)

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        # Earth's radius in meters
        R = 6371000

        return R * c

    def calculate_bearing(self, coord1: Coordinate, coord2: Coordinate) -> float:
        """Calculate bearing from coord1 to coord2.

        Args:
            coord1: Starting coordinate
            coord2: Ending coordinate

        Returns:
            Bearing in degrees (0-360)
        """
        import math

        lat1, lon1 = math.radians(coord1.latitude), math.radians(coord1.longitude)
        lat2, lon2 = math.radians(coord2.latitude), math.radians(coord2.longitude)

        dlon = lon2 - lon1

        y = math.sin(dlon) * math.cos(lat2)
        x = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(
            lat2
        ) * math.cos(dlon)

        bearing = math.atan2(y, x)
        bearing = math.degrees(bearing)
        return (bearing + 360) % 360

    def point_in_bounding_box(
        self, coordinate: Coordinate, bounding_box: BoundingBox
    ) -> bool:
        """Check if coordinate is within bounding box.

        Args:
            coordinate: Coordinate to check
            bounding_box: Bounding box to check against

        Returns:
            True if coordinate is within bounding box
        """
        return (
            bounding_box.southwest.latitude
            <= coordinate.latitude
            <= bounding_box.northeast.latitude
            and bounding_box.southwest.longitude
            <= coordinate.longitude
            <= bounding_box.northeast.longitude
        )

    # Health Check
    async def health_check(self) -> dict[str, Any]:
        """Check adapter health status.

        Returns:
            Health status dictionary
        """
        try:
            # Try a simple geocoding request to test connectivity
            results = await self.geocode("New York, NY", limit=1)

            return {
                "status": "healthy",
                "provider": self.__class__.__name__,
                "timestamp": datetime.utcnow().isoformat(),
                "test_result": "geocoding_successful",
                "result_count": len(results),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": self.__class__.__name__,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
                "test_result": "geocoding_failed",
            }

    # Rate Limiting
    def _handle_rate_limit(self, response_headers: dict[str, str]) -> None:
        """Handle rate limiting based on response headers.

        Args:
            response_headers: HTTP response headers
        """
        # Default implementation - can be overridden

    def _sanitize_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Sanitize response to remove sensitive data.

        Args:
            response: Raw API response

        Returns:
            Sanitized response
        """
        # Remove common sensitive fields
        sensitive_fields = [
            "api_key",
            "secret",
            "token",
            "password",
            "authorization",
            "x-api-key",
            "bearer",
        ]

        sanitized = response.copy()
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = "[REDACTED]"
            # Also check nested fields
            for key in list(sanitized.keys()):
                if isinstance(sanitized[key], dict):
                    sanitized[key] = self._sanitize_response(sanitized[key])

        return sanitized
