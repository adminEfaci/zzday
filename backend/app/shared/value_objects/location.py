"""Location/GPS value objects."""

import math
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class Location(ValueObject):
    """GPS location value object with validation and distance calculations."""

    def __init__(
        self,
        latitude: float,
        longitude: float,
        accuracy: float | None = None,
        altitude: float | None = None,
    ):
        """
        Initialize and validate GPS location.

        Args:
            latitude: Latitude in decimal degrees (-90 to 90)
            longitude: Longitude in decimal degrees (-180 to 180)
            accuracy: GPS accuracy in meters (optional)
            altitude: Altitude in meters (optional)

        Raises:
            ValidationError: If coordinates are invalid
        """
        self.latitude = self._validate_latitude(latitude)
        self.longitude = self._validate_longitude(longitude)
        self.accuracy = self._validate_positive_value(accuracy, "accuracy")
        self.altitude = altitude  # Can be negative (below sea level)

    def _validate_latitude(self, latitude: float) -> float:
        """Validate latitude range."""
        if not isinstance(latitude, int | float):
            raise ValidationError("Latitude must be a number")

        if not -90 <= latitude <= 90:
            raise ValidationError("Latitude must be between -90 and 90 degrees")

        return float(latitude)

    def _validate_longitude(self, longitude: float) -> float:
        """Validate longitude range."""
        if not isinstance(longitude, int | float):
            raise ValidationError("Longitude must be a number")

        if not -180 <= longitude <= 180:
            raise ValidationError("Longitude must be between -180 and 180 degrees")

        return float(longitude)

    def _validate_positive_value(
        self, value: float | None, field_name: str
    ) -> float | None:
        """Validate positive values."""
        if value is None:
            return None

        if not isinstance(value, int | float):
            raise ValidationError(f"{field_name} must be a number")

        if value < 0:
            raise ValidationError(f"{field_name} must be positive")

        return float(value)

    @staticmethod
    def validate_coordinates(latitude: float, longitude: float) -> bool:
        """
        Static method to validate coordinate ranges.

        Args:
            latitude: Latitude to validate
            longitude: Longitude to validate

        Returns:
            bool: True if coordinates are valid
        """
        try:
            return (
                isinstance(latitude, int | float)
                and isinstance(longitude, int | float)
                and -90 <= latitude <= 90
                and -180 <= longitude <= 180
            )
        except (TypeError, ValueError):
            return False

    def distance_to(self, other: "Location", unit: str = "meters") -> float:
        """
        Calculate distance to another location using Haversine formula.

        Args:
            other: Another Location object
            unit: Distance unit ("meters", "kilometers", "miles")

        Returns:
            float: Distance in specified unit

        Raises:
            ValidationError: If unit is invalid
        """
        if not isinstance(other, Location):
            raise ValidationError("Can only calculate distance to another Location")

        # Earth radius in different units
        earth_radius = {
            "meters": 6371000,
            "kilometers": 6371,
            "miles": 3959,
            "km": 6371,
            "mi": 3959,
            "m": 6371000,
        }

        if unit not in earth_radius:
            raise ValidationError(
                f"Invalid unit: {unit}. Use 'meters', 'kilometers', or 'miles'"
            )

        R = earth_radius[unit]

        # Convert to radians
        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(other.latitude), math.radians(other.longitude)

        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.asin(math.sqrt(a))

        return R * c

    def bearing_to(self, other: "Location") -> float:
        """
        Calculate initial bearing to another location.

        Args:
            other: Another Location object

        Returns:
            float: Bearing in degrees (0-360)
        """
        if not isinstance(other, Location):
            raise ValidationError("Can only calculate bearing to another Location")

        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(other.latitude), math.radians(other.longitude)

        dlon = lon2 - lon1

        y = math.sin(dlon) * math.cos(lat2)
        x = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(
            lat2
        ) * math.cos(dlon)

        bearing = math.atan2(y, x)
        bearing = math.degrees(bearing)
        return (bearing + 360) % 360

    def is_within_radius(
        self, center: "Location", radius: float, unit: str = "meters"
    ) -> bool:
        """
        Check if this location is within a radius of another location.

        Args:
            center: Center location
            radius: Radius distance
            unit: Distance unit

        Returns:
            bool: True if within radius
        """
        distance = self.distance_to(center, unit)
        return distance <= radius

    def normalize_longitude(self) -> "Location":
        """
        Normalize longitude to -180 to 180 range.

        Returns:
            Location: New location with normalized longitude
        """
        normalized_lon = ((self.longitude + 180) % 360) - 180
        return Location(
            latitude=self.latitude,
            longitude=normalized_lon,
            accuracy=self.accuracy,
            altitude=self.altitude,
        )

    def to_tuple(self) -> tuple[float, float]:
        """Convert to (latitude, longitude) tuple."""
        return (self.latitude, self.longitude)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "latitude": self.latitude,
            "longitude": self.longitude,
        }
        if self.accuracy is not None:
            result["accuracy"] = self.accuracy
        if self.altitude is not None:
            result["altitude"] = self.altitude
        return result

    def to_geojson(self) -> dict[str, Any]:
        """
        Convert to GeoJSON point format.

        Returns:
            dict: GeoJSON Point object
        """
        coordinates = [self.longitude, self.latitude]
        if self.altitude is not None:
            coordinates.append(self.altitude)

        geojson = {
            "type": "Point",
            "coordinates": coordinates,
        }

        if self.accuracy is not None:
            geojson["properties"] = {"accuracy": self.accuracy}

        return geojson

    def format_dms(self, precision: int = 2) -> str:
        """
        Format as degrees, minutes, seconds.

        Args:
            precision: Decimal places for seconds

        Returns:
            str: DMS formatted string
        """

        def to_dms(decimal: float, is_lat: bool) -> str:
            direction = ""
            if is_lat:
                direction = "N" if decimal >= 0 else "S"
            else:
                direction = "E" if decimal >= 0 else "W"

            decimal = abs(decimal)
            degrees = int(decimal)
            minutes = int((decimal - degrees) * 60)
            seconds = ((decimal - degrees) * 60 - minutes) * 60

            return f"{degrees}°{minutes}'{seconds:.{precision}f}\"{direction}"

        lat_dms = to_dms(self.latitude, True)
        lon_dms = to_dms(self.longitude, False)

        return f"{lat_dms} {lon_dms}"

    def format_decimal(self, precision: int = 6) -> str:
        """
        Format as decimal degrees.

        Args:
            precision: Decimal places

        Returns:
            str: Decimal formatted string
        """
        return f"{self.latitude:.{precision}f}, {self.longitude:.{precision}f}"

    def format_utm(self) -> str:
        """
        Format as UTM coordinates (simplified).

        Returns:
            str: UTM zone and approximate coordinates

        Note:
            This is a simplified UTM calculation for display purposes
        """
        # Calculate UTM zone
        zone = int((self.longitude + 180) / 6) + 1
        hemisphere = "N" if self.latitude >= 0 else "S"

        return f"UTM Zone {zone}{hemisphere}"

    def get_timezone_offset(self) -> float:
        """
        Get approximate timezone offset based on longitude.

        Returns:
            float: Approximate UTC offset in hours

        Note:
            This is a rough approximation and doesn't account for
            political timezone boundaries or DST
        """
        return round(self.longitude / 15.0)

    def __str__(self) -> str:
        """String representation."""
        return self.format_decimal()

    def __eq__(self, other) -> bool:
        """Check equality with small tolerance for floating point precision."""
        if not isinstance(other, Location):
            return False

        tolerance = 1e-6  # About 10cm precision
        return (
            abs(self.latitude - other.latitude) < tolerance
            and abs(self.longitude - other.longitude) < tolerance
            and self.accuracy == other.accuracy
            and self.altitude == other.altitude
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        # Round to avoid floating point precision issues
        lat = round(self.latitude, 6)
        lon = round(self.longitude, 6)
        return hash((lat, lon, self.accuracy, self.altitude))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"Location(latitude={self.latitude}, longitude={self.longitude}, "
            f"accuracy={self.accuracy}, altitude={self.altitude})"
        )
