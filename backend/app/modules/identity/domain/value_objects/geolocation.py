"""
Geolocation Value Object

Immutable representation of geographic coordinates and location data.
"""

import math
from dataclasses import dataclass
from typing import Any

from .base import ValueObject


@dataclass(frozen=True)
class Geolocation(ValueObject[tuple[float, float]]):
    """Value object representing a geographic location."""
    
    latitude: float
    longitude: float
    altitude: float | None = None  # meters above sea level
    accuracy: float | None = None  # accuracy radius in meters
    heading: float | None = None  # direction of travel in degrees (0-360)
    speed: float | None = None  # speed in meters per second
    
    def __post_init__(self):
        """Validate coordinates."""
        # Validate latitude (-90 to 90)
        if not -90 <= self.latitude <= 90:
            raise ValueError("Latitude must be between -90 and 90 degrees")
        
        # Validate longitude (-180 to 180)
        if not -180 <= self.longitude <= 180:
            raise ValueError("Longitude must be between -180 and 180 degrees")
        
        # Normalize longitude to -180 to 180 range
        if self.longitude > 180:
            object.__setattr__(self, 'longitude', self.longitude - 360)
        elif self.longitude < -180:
            object.__setattr__(self, 'longitude', self.longitude + 360)
        
        # Validate optional fields
        if self.altitude is not None:
            # Mount Everest is ~8,849m, Mariana Trench is ~-11,000m
            if not -15000 <= self.altitude <= 15000:
                raise ValueError("Altitude seems unrealistic")
        
        if self.accuracy is not None and self.accuracy < 0:
            raise ValueError("Accuracy cannot be negative")
        
        if self.heading is not None and not 0 <= self.heading <= 360:
            raise ValueError("Heading must be between 0 and 360 degrees")
        
        if self.speed is not None and self.speed < 0:
            raise ValueError("Speed cannot be negative")
    
    @classmethod
    def from_degrees_minutes_seconds(
        cls,
        lat_degrees: int,
        lat_minutes: int,
        lat_seconds: float,
        lat_direction: str,
        lon_degrees: int,
        lon_minutes: int,
        lon_seconds: float,
        lon_direction: str
    ) -> 'Geolocation':
        """Create from DMS (Degrees, Minutes, Seconds) format."""
        # Convert DMS to decimal degrees
        lat = lat_degrees + lat_minutes / 60 + lat_seconds / 3600
        if lat_direction.upper() == 'S':
            lat = -lat
        
        lon = lon_degrees + lon_minutes / 60 + lon_seconds / 3600
        if lon_direction.upper() == 'W':
            lon = -lon
        
        return cls(latitude=lat, longitude=lon)
    
    @classmethod
    def from_string(cls, coord_string: str) -> 'Geolocation':
        """
        Parse from common string formats:
        - "40.7128,-74.0060"
        - "40.7128° N, 74.0060° W"
        - "40°42'46.0\"N 74°00'21.6\"W"
        """
        # Simple decimal format
        if ',' in coord_string and '°' not in coord_string:
            parts = coord_string.split(',')
            if len(parts) == 2:
                try:
                    return cls(
                        latitude=float(parts[0].strip()),
                        longitude=float(parts[1].strip())
                    )
                except ValueError as e:
                    raise ValueError(f"Invalid coordinate format: {coord_string}") from e
        
        # Handle other formats...
        raise ValueError(f"Unable to parse coordinates: {coord_string}")
    
    def to_degrees_minutes_seconds(self) -> tuple[str, str]:
        """Convert to DMS format."""
        def decimal_to_dms(decimal: float, is_longitude: bool) -> str:
            """Convert decimal degrees to DMS string."""
            direction = ''
            if is_longitude:
                direction = 'E' if decimal >= 0 else 'W'
            else:
                direction = 'N' if decimal >= 0 else 'S'
            
            decimal = abs(decimal)
            degrees = int(decimal)
            minutes_decimal = (decimal - degrees) * 60
            minutes = int(minutes_decimal)
            seconds = (minutes_decimal - minutes) * 60
            
            return f"{degrees}°{minutes}'{seconds:.1f}\"{direction}"
        
        lat_dms = decimal_to_dms(self.latitude, False)
        lon_dms = decimal_to_dms(self.longitude, True)
        
        return (lat_dms, lon_dms)
    
    def distance_to(self, other: 'Geolocation', unit: str = 'meters') -> float:
        """
        Calculate distance to another location using Haversine formula.
        Units: 'meters', 'kilometers', 'miles', 'nautical_miles'
        """
        # Earth's radius in meters
        R = 6371000
        
        # Convert to radians
        lat1_rad = math.radians(self.latitude)
        lat2_rad = math.radians(other.latitude)
        delta_lat = math.radians(other.latitude - self.latitude)
        delta_lon = math.radians(other.longitude - self.longitude)
        
        # Haversine formula
        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        distance_meters = R * c
        
        # Convert units
        if unit == 'meters':
            return distance_meters
        if unit == 'kilometers':
            return distance_meters / 1000
        if unit == 'miles':
            return distance_meters / 1609.344
        if unit == 'nautical_miles':
            return distance_meters / 1852
        raise ValueError(f"Unknown unit: {unit}")
    
    def bearing_to(self, other: 'Geolocation') -> float:
        """Calculate bearing (direction) to another location in degrees."""
        lat1_rad = math.radians(self.latitude)
        lat2_rad = math.radians(other.latitude)
        lon1_rad = math.radians(self.longitude)
        lon2_rad = math.radians(other.longitude)
        
        delta_lon = lon2_rad - lon1_rad
        
        x = math.sin(delta_lon) * math.cos(lat2_rad)
        y = (math.cos(lat1_rad) * math.sin(lat2_rad) -
             math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(delta_lon))
        
        bearing_rad = math.atan2(x, y)
        bearing_deg = math.degrees(bearing_rad)
        
        # Normalize to 0-360 range
        return (bearing_deg + 360) % 360
    
    def midpoint_to(self, other: 'Geolocation') -> 'Geolocation':
        """Calculate midpoint between this location and another."""
        lat1_rad = math.radians(self.latitude)
        lat2_rad = math.radians(other.latitude)
        lon1_rad = math.radians(self.longitude)
        lon2_rad = math.radians(other.longitude)
        
        delta_lon = lon2_rad - lon1_rad
        
        bx = math.cos(lat2_rad) * math.cos(delta_lon)
        by = math.cos(lat2_rad) * math.sin(delta_lon)
        
        lat_mid_rad = math.atan2(
            math.sin(lat1_rad) + math.sin(lat2_rad),
            math.sqrt((math.cos(lat1_rad) + bx) ** 2 + by ** 2)
        )
        
        lon_mid_rad = lon1_rad + math.atan2(by, math.cos(lat1_rad) + bx)
        
        return Geolocation(
            latitude=math.degrees(lat_mid_rad),
            longitude=math.degrees(lon_mid_rad)
        )
    
    def is_within_radius(self, center: 'Geolocation', radius_meters: float) -> bool:
        """Check if this location is within a radius of a center point."""
        return self.distance_to(center, 'meters') <= radius_meters
    
    def get_bounding_box(self, radius_meters: float) -> dict[str, float]:
        """
        Get bounding box coordinates for a radius around this point.
        Returns dict with north, south, east, west boundaries.
        """
        # Approximate degrees per meter at this latitude
        lat_rad = math.radians(self.latitude)
        meters_per_degree_lat = 111320.0
        meters_per_degree_lon = 111320.0 * math.cos(lat_rad)
        
        delta_lat = radius_meters / meters_per_degree_lat
        delta_lon = radius_meters / meters_per_degree_lon
        
        return {
            'north': self.latitude + delta_lat,
            'south': self.latitude - delta_lat,
            'east': self.longitude + delta_lon,
            'west': self.longitude - delta_lon
        }
    
    def get_timezone_estimate(self) -> str:
        """Estimate timezone based on longitude (rough approximation)."""
        # This is a very rough estimate - production should use a timezone database
        offset_hours = round(self.longitude / 15)
        
        if offset_hours == 0:
            return "UTC"
        if offset_hours > 0:
            return f"UTC+{offset_hours}"
        return f"UTC{offset_hours}"
    
    def get_cardinal_direction(self) -> str:
        """Get cardinal direction from heading."""
        if self.heading is None:
            return "unknown"
        
        directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                     "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
        
        index = round(self.heading / 22.5) % 16
        return directions[index]
    
    def format_decimal(self, precision: int = 6) -> str:
        """Format as decimal degrees."""
        return f"{self.latitude:.{precision}f}, {self.longitude:.{precision}f}"
    
    def format_dms(self) -> str:
        """Format as degrees, minutes, seconds."""
        lat_dms, lon_dms = self.to_degrees_minutes_seconds()
        return f"{lat_dms} {lon_dms}"
    
    def format_geo_uri(self) -> str:
        """Format as geo: URI for mapping applications."""
        uri = f"geo:{self.latitude},{self.longitude}"
        
        if self.altitude is not None:
            uri += f",{self.altitude}"
        
        if self.accuracy is not None:
            uri += f";u={self.accuracy}"
        
        return uri
    
    def format_google_maps_url(self) -> str:
        """Format as Google Maps URL."""
        return f"https://www.google.com/maps?q={self.latitude},{self.longitude}"
    
    def format_openstreetmap_url(self) -> str:
        """Format as OpenStreetMap URL."""
        return f"https://www.openstreetmap.org/?mlat={self.latitude}&mlon={self.longitude}#map=15/{self.latitude}/{self.longitude}"
    
    def anonymize(self, precision_km: float = 10.0) -> 'Geolocation':
        """
        Create anonymized version by reducing precision.
        Default reduces to ~10km precision.
        """
        # Round to reduce precision
        scale = precision_km / 111.0  # Approximate km per degree
        
        return Geolocation(
            latitude=round(self.latitude / scale) * scale,
            longitude=round(self.longitude / scale) * scale,
            altitude=None,  # Remove altitude
            accuracy=precision_km * 1000,  # Set accuracy to anonymization level
            heading=None,  # Remove heading
            speed=None  # Remove speed
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "formatted": self.format_decimal(),
            "dms": self.format_dms()
        }
        
        if self.altitude is not None:
            data["altitude"] = self.altitude
        
        if self.accuracy is not None:
            data["accuracy"] = self.accuracy
        
        if self.heading is not None:
            data["heading"] = self.heading
            data["cardinal_direction"] = self.get_cardinal_direction()
        
        if self.speed is not None:
            data["speed_ms"] = self.speed
            data["speed_kmh"] = self.speed * 3.6
            data["speed_mph"] = self.speed * 2.237
        
        return data
    
    def __str__(self) -> str:
        """String representation."""
        return self.format_decimal()
    
    def __eq__(self, other: Any) -> bool:
        """Geolocation equality with precision tolerance."""
        if not isinstance(other, Geolocation):
            return False
        
        # Use small tolerance for floating point comparison
        tolerance = 1e-6  # About 0.1 meters
        return (
            abs(self.latitude - other.latitude) < tolerance and
            abs(self.longitude - other.longitude) < tolerance
        )
    
    def __hash__(self) -> int:
        """Hash based on rounded coordinates."""
        # Round to 6 decimal places for consistent hashing
        return hash((round(self.latitude, 6), round(self.longitude, 6)))
    
    def __repr__(self) -> str:
        """Debug representation."""
        parts = [f"lat={self.latitude:.6f}", f"lon={self.longitude:.6f}"]
        
        if self.accuracy is not None:
            parts.append(f"±{self.accuracy:.0f}m")
        
        return f"Geolocation({', '.join(parts)})"