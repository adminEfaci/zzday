"""Utility functions for mapping and routing operations."""

import math
import re
from datetime import datetime, timedelta
from typing import Any

from .mapping_types import Address, BoundingBox, Coordinate, Route, TrafficCondition


class GeoUtils:
    """Geographic utility functions."""

    # Earth's radius in meters
    EARTH_RADIUS = 6371000

    @staticmethod
    def calculate_distance(coord1: Coordinate, coord2: Coordinate) -> float:
        """Calculate great circle distance between two coordinates using Haversine formula.

        Args:
            coord1: First coordinate
            coord2: Second coordinate

        Returns:
            Distance in meters
        """
        lat1, lon1 = math.radians(coord1.latitude), math.radians(coord1.longitude)
        lat2, lon2 = math.radians(coord2.latitude), math.radians(coord2.longitude)

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return GeoUtils.EARTH_RADIUS * c

    @staticmethod
    def calculate_bearing(coord1: Coordinate, coord2: Coordinate) -> float:
        """Calculate bearing from coord1 to coord2.

        Args:
            coord1: Starting coordinate
            coord2: Ending coordinate

        Returns:
            Bearing in degrees (0-360)
        """
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

    @staticmethod
    def point_in_circle(center: Coordinate, point: Coordinate, radius: float) -> bool:
        """Check if point is within circular area.

        Args:
            center: Center coordinate
            point: Point to check
            radius: Radius in meters

        Returns:
            True if point is within radius
        """
        distance = GeoUtils.calculate_distance(center, point)
        return distance <= radius

    @staticmethod
    def point_in_bounding_box(point: Coordinate, bounding_box: BoundingBox) -> bool:
        """Check if point is within bounding box.

        Args:
            point: Point to check
            bounding_box: Bounding box to check against

        Returns:
            True if point is within bounding box
        """
        return (
            bounding_box.southwest.latitude
            <= point.latitude
            <= bounding_box.northeast.latitude
            and bounding_box.southwest.longitude
            <= point.longitude
            <= bounding_box.northeast.longitude
        )

    @staticmethod
    def create_bounding_box_from_center(
        center: Coordinate, radius: float
    ) -> BoundingBox:
        """Create bounding box from center point and radius.

        Args:
            center: Center coordinate
            radius: Radius in meters

        Returns:
            Bounding box
        """
        # Approximate degrees per meter
        lat_offset = radius / 111000  # 1 degree latitude ≈ 111km
        lon_offset = radius / (111000 * math.cos(math.radians(center.latitude)))

        southwest = Coordinate(
            latitude=center.latitude - lat_offset,
            longitude=center.longitude - lon_offset,
        )
        northeast = Coordinate(
            latitude=center.latitude + lat_offset,
            longitude=center.longitude + lon_offset,
        )

        return BoundingBox(southwest=southwest, northeast=northeast)

    @staticmethod
    def get_route_bounds(route: Route) -> BoundingBox:
        """Get bounding box for route geometry.

        Args:
            route: Route to analyze

        Returns:
            Bounding box containing the route
        """
        if not route.overview_geometry:
            # Fall back to origin and destination
            lats = [route.origin.latitude, route.destination.latitude]
            lons = [route.origin.longitude, route.destination.longitude]
        else:
            lats = [coord.latitude for coord in route.overview_geometry]
            lons = [coord.longitude for coord in route.overview_geometry]

        southwest = Coordinate(latitude=min(lats), longitude=min(lons))
        northeast = Coordinate(latitude=max(lats), longitude=max(lons))

        return BoundingBox(southwest=southwest, northeast=northeast)

    @staticmethod
    def simplify_coordinates(
        coordinates: list[Coordinate], tolerance: float = 0.0001
    ) -> list[Coordinate]:
        """Simplify coordinate list using Douglas-Peucker algorithm.

        Args:
            coordinates: List of coordinates to simplify
            tolerance: Simplification tolerance in degrees

        Returns:
            Simplified coordinate list
        """
        if len(coordinates) <= 2:
            return coordinates

        # Find the point with maximum distance from line between first and last
        max_distance = 0
        max_index = 0

        first = coordinates[0]
        last = coordinates[-1]

        for i in range(1, len(coordinates) - 1):
            distance = GeoUtils._point_to_line_distance(coordinates[i], first, last)
            if distance > max_distance:
                max_distance = distance
                max_index = i

        # If max distance is greater than tolerance, recursively simplify
        if max_distance > tolerance:
            # Recursive call for both parts
            left_part = GeoUtils.simplify_coordinates(
                coordinates[: max_index + 1], tolerance
            )
            right_part = GeoUtils.simplify_coordinates(
                coordinates[max_index:], tolerance
            )

            # Combine results (remove duplicate middle point)
            return left_part[:-1] + right_part
        # All points are within tolerance, return just endpoints
        return [first, last]

    @staticmethod
    def _point_to_line_distance(
        point: Coordinate, line_start: Coordinate, line_end: Coordinate
    ) -> float:
        """Calculate perpendicular distance from point to line segment.

        Args:
            point: Point to measure distance from
            line_start: Start of line segment
            line_end: End of line segment

        Returns:
            Distance in degrees (approximate)
        """
        # Convert to simple 2D coordinates for calculation
        x0, y0 = point.longitude, point.latitude
        x1, y1 = line_start.longitude, line_start.latitude
        x2, y2 = line_end.longitude, line_end.latitude

        # Calculate distance using point-to-line formula
        numerator = abs((y2 - y1) * x0 - (x2 - x1) * y0 + x2 * y1 - y2 * x1)
        denominator = math.sqrt((y2 - y1) ** 2 + (x2 - x1) ** 2)

        if denominator == 0:
            # Line segment is a point, return distance to that point
            return math.sqrt((x0 - x1) ** 2 + (y0 - y1) ** 2)

        return numerator / denominator


class AddressUtils:
    """Address parsing and formatting utilities."""

    @staticmethod
    def parse_address(address_string: str) -> Address:
        """Parse address string into components.

        Args:
            address_string: Address string to parse

        Returns:
            Address object with parsed components
        """
        # This is a basic parser - real-world implementation would be more sophisticated
        parts = [part.strip() for part in address_string.split(",")]

        address = Address(formatted_address=address_string)

        if len(parts) >= 1:
            # Try to extract street number and name from first part
            street_match = re.match(r"^(\d+)\s+(.+)$", parts[0])
            if street_match:
                address.street_number = street_match.group(1)
                address.street_name = street_match.group(2)
            else:
                address.street_name = parts[0]

        if len(parts) >= 2:
            address.city = parts[1]

        if len(parts) >= 3:
            # Try to parse state and postal code
            state_postal = parts[2].strip()
            state_postal_match = re.match(
                r"^([A-Za-z\s]+)\s+(\d{5}(?:-\d{4})?)$", state_postal
            )
            if state_postal_match:
                address.state = state_postal_match.group(1).strip()
                address.postal_code = state_postal_match.group(2)
            else:
                address.state = state_postal

        if len(parts) >= 4:
            address.country = parts[3]

        return address

    @staticmethod
    def format_address(address: Address, style: str = "full") -> str:
        """Format address components into string.

        Args:
            address: Address object to format
            style: Formatting style ("full", "short", "postal")

        Returns:
            Formatted address string
        """
        if style == "full":
            return address.formatted_address or str(address)
        if style == "short":
            parts = []
            if address.street_name:
                parts.append(address.street_name)
            if address.city:
                parts.append(address.city)
            return ", ".join(parts)
        if style == "postal":
            parts = []
            if address.city:
                parts.append(address.city)
            if address.state:
                parts.append(address.state)
            if address.postal_code:
                parts.append(address.postal_code)
            return " ".join(parts)
        return str(address)

    @staticmethod
    def normalize_address(address: Address) -> Address:
        """Normalize address components.

        Args:
            address: Address to normalize

        Returns:
            Normalized address
        """
        return Address(
            formatted_address=address.formatted_address,
            street_number=address.street_number,
            street_name=AddressUtils._normalize_street_name(address.street_name),
            city=AddressUtils._title_case(address.city),
            state=AddressUtils._normalize_state(address.state),
            postal_code=AddressUtils._normalize_postal_code(address.postal_code),
            country=AddressUtils._title_case(address.country),
            country_code=address.country_code.upper() if address.country_code else None,
        )

    @staticmethod
    def _normalize_street_name(street_name: str | None) -> str | None:
        """Normalize street name."""
        if not street_name:
            return None

        # Common abbreviations
        abbreviations = {
            r"\bSt\.?\b": "Street",
            r"\bAve\.?\b": "Avenue",
            r"\bBlvd\.?\b": "Boulevard",
            r"\bDr\.?\b": "Drive",
            r"\bRd\.?\b": "Road",
            r"\bLn\.?\b": "Lane",
            r"\bCt\.?\b": "Court",
            r"\bPl\.?\b": "Place",
        }

        normalized = street_name.title()
        for abbrev, full in abbreviations.items():
            normalized = re.sub(abbrev, full, normalized, flags=re.IGNORECASE)

        return normalized

    @staticmethod
    def _normalize_state(state: str | None) -> str | None:
        """Normalize state name."""
        if not state:
            return None

        # US state abbreviations
        state_abbrevs = {
            "AL": "Alabama",
            "AK": "Alaska",
            "AZ": "Arizona",
            "AR": "Arkansas",
            "CA": "California",
            "CO": "Colorado",
            "CT": "Connecticut",
            "DE": "Delaware",
            "FL": "Florida",
            "GA": "Georgia",
            "HI": "Hawaii",
            "ID": "Idaho",
            "IL": "Illinois",
            "IN": "Indiana",
            "IA": "Iowa",
            "KS": "Kansas",
            "KY": "Kentucky",
            "LA": "Louisiana",
            "ME": "Maine",
            "MD": "Maryland",
            "MA": "Massachusetts",
            "MI": "Michigan",
            "MN": "Minnesota",
            "MS": "Mississippi",
            "MO": "Missouri",
            "MT": "Montana",
            "NE": "Nebraska",
            "NV": "Nevada",
            "NH": "New Hampshire",
            "NJ": "New Jersey",
            "NM": "New Mexico",
            "NY": "New York",
            "NC": "North Carolina",
            "ND": "North Dakota",
            "OH": "Ohio",
            "OK": "Oklahoma",
            "OR": "Oregon",
            "PA": "Pennsylvania",
            "RI": "Rhode Island",
            "SC": "South Carolina",
            "SD": "South Dakota",
            "TN": "Tennessee",
            "TX": "Texas",
            "UT": "Utah",
            "VT": "Vermont",
            "VA": "Virginia",
            "WA": "Washington",
            "WV": "West Virginia",
            "WI": "Wisconsin",
            "WY": "Wyoming",
        }

        state_upper = state.upper()
        if state_upper in state_abbrevs:
            return state_abbrevs[state_upper]

        return state.title()

    @staticmethod
    def _normalize_postal_code(postal_code: str | None) -> str | None:
        """Normalize postal code."""
        if not postal_code:
            return None

        # Remove spaces and ensure proper formatting
        cleaned = re.sub(r"\s+", "", postal_code)

        # US ZIP code format
        if re.match(r"^\d{5}$", cleaned):
            return cleaned
        if re.match(r"^\d{9}$", cleaned):
            return f"{cleaned[:5]}-{cleaned[5:]}"

        # Canadian postal code format
        if re.match(r"^[A-Za-z]\d[A-Za-z]\d[A-Za-z]\d$", cleaned):
            return f"{cleaned[:3].upper()} {cleaned[3:].upper()}"

        return postal_code.upper()

    @staticmethod
    def _title_case(text: str | None) -> str | None:
        """Convert text to title case."""
        if not text:
            return None
        return text.title()


class RouteUtils:
    """Route analysis and optimization utilities."""

    @staticmethod
    def calculate_route_metrics(route: Route) -> dict[str, Any]:
        """Calculate comprehensive route metrics.

        Args:
            route: Route to analyze

        Returns:
            Dictionary of route metrics
        """
        metrics = {
            "total_distance_km": route.total_distance / 1000.0,
            "total_duration_minutes": route.total_duration / 60.0,
            "average_speed_kmh": 0.0,
            "number_of_segments": len(route.segments),
            "number_of_waypoints": len(route.waypoints),
            "has_traffic_data": False,
            "traffic_delay_minutes": 0.0,
            "efficiency_score": 0.0,
        }

        # Calculate average speed
        if route.total_duration > 0:
            metrics["average_speed_kmh"] = (route.total_distance / 1000.0) / (
                route.total_duration / 3600.0
            )

        # Check for traffic data
        if route.traffic_duration:
            metrics["has_traffic_data"] = True
            traffic_delay = route.traffic_duration - route.total_duration
            metrics["traffic_delay_minutes"] = traffic_delay / 60.0

        # Calculate efficiency score (simplified)
        if route.total_distance > 0:
            direct_distance = GeoUtils.calculate_distance(
                route.origin, route.destination
            )
            metrics["efficiency_score"] = direct_distance / route.total_distance

        return metrics

    @staticmethod
    def get_route_instructions(route: Route) -> list[str]:
        """Extract turn-by-turn instructions from route.

        Args:
            route: Route to extract instructions from

        Returns:
            List of instruction strings
        """
        instructions = []

        for _i, segment in enumerate(route.segments):
            for _j, step in enumerate(segment.steps):
                instruction = step.instruction

                # Add distance and duration info
                distance_km = step.distance / 1000.0
                step.duration / 60.0

                if distance_km >= 1.0:
                    distance_str = f"{distance_km:.1f} km"
                else:
                    distance_str = f"{step.distance:.0f} m"

                full_instruction = f"{instruction} ({distance_str})"
                instructions.append(full_instruction)

        return instructions

    @staticmethod
    def estimate_fuel_consumption(
        route: Route, vehicle_efficiency: float = 8.0  # L/100km
    ) -> dict[str, float]:
        """Estimate fuel consumption for route.

        Args:
            route: Route to analyze
            vehicle_efficiency: Vehicle fuel efficiency in L/100km

        Returns:
            Fuel consumption estimates
        """
        distance_km = route.total_distance / 1000.0
        base_consumption = distance_km * (vehicle_efficiency / 100.0)

        # Adjust for traffic conditions
        traffic_multiplier = 1.0
        for segment in route.segments:
            if segment.traffic_condition == TrafficCondition.HEAVY:
                traffic_multiplier += 0.3
            elif segment.traffic_condition == TrafficCondition.MODERATE:
                traffic_multiplier += 0.15
            elif segment.traffic_condition == TrafficCondition.LIGHT:
                traffic_multiplier += 0.05

        traffic_multiplier = traffic_multiplier / len(route.segments)

        return {
            "base_consumption_liters": base_consumption,
            "traffic_adjusted_liters": base_consumption * traffic_multiplier,
            "estimated_cost_usd": base_consumption
            * traffic_multiplier
            * 1.50,  # Assume $1.50/L
        }

    @staticmethod
    def find_nearest_waypoint(
        coordinate: Coordinate, waypoints: list[Coordinate]
    ) -> tuple[int, float]:
        """Find nearest waypoint to given coordinate.

        Args:
            coordinate: Reference coordinate
            waypoints: List of waypoints to search

        Returns:
            Tuple of (index, distance) of nearest waypoint
        """
        if not waypoints:
            return -1, float("inf")

        min_distance = float("inf")
        min_index = -1

        for i, waypoint in enumerate(waypoints):
            distance = GeoUtils.calculate_distance(coordinate, waypoint)
            if distance < min_distance:
                min_distance = distance
                min_index = i

        return min_index, min_distance


class CoordinateConverter:
    """Coordinate system conversion utilities."""

    @staticmethod
    def decimal_to_dms(decimal_degrees: float) -> tuple[int, int, float]:
        """Convert decimal degrees to degrees, minutes, seconds.

        Args:
            decimal_degrees: Decimal degrees value

        Returns:
            Tuple of (degrees, minutes, seconds)
        """
        degrees = int(abs(decimal_degrees))
        minutes_float = (abs(decimal_degrees) - degrees) * 60
        minutes = int(minutes_float)
        seconds = (minutes_float - minutes) * 60

        return degrees, minutes, seconds

    @staticmethod
    def dms_to_decimal(degrees: int, minutes: int, seconds: float) -> float:
        """Convert degrees, minutes, seconds to decimal degrees.

        Args:
            degrees: Degrees component
            minutes: Minutes component
            seconds: Seconds component

        Returns:
            Decimal degrees value
        """
        decimal = abs(degrees) + abs(minutes) / 60.0 + abs(seconds) / 3600.0

        # Handle negative coordinates
        if degrees < 0:
            decimal = -decimal

        return decimal

    @staticmethod
    def format_coordinate(coordinate: Coordinate, format_type: str = "decimal") -> str:
        """Format coordinate in various formats.

        Args:
            coordinate: Coordinate to format
            format_type: Format type ("decimal", "dms", "utm")

        Returns:
            Formatted coordinate string
        """
        if format_type == "decimal":
            return f"{coordinate.latitude:.6f}, {coordinate.longitude:.6f}"

        if format_type == "dms":
            lat_d, lat_m, lat_s = CoordinateConverter.decimal_to_dms(
                coordinate.latitude
            )
            lon_d, lon_m, lon_s = CoordinateConverter.decimal_to_dms(
                coordinate.longitude
            )

            lat_dir = "N" if coordinate.latitude >= 0 else "S"
            lon_dir = "E" if coordinate.longitude >= 0 else "W"

            return f"{lat_d}°{lat_m}'{lat_s:.2f}\"{lat_dir}, {lon_d}°{lon_m}'{lon_s:.2f}\"{lon_dir}"

        return f"{coordinate.latitude}, {coordinate.longitude}"


# Cache for expensive calculations
class MappingCache:
    """Simple in-memory cache for mapping calculations."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        """Initialize cache.

        Args:
            max_size: Maximum cache size
            ttl_seconds: Time to live in seconds
        """
        self.max_size = max_size
        self.ttl = timedelta(seconds=ttl_seconds)
        self._cache: dict[str, tuple[Any, datetime]] = {}

    def get(self, key: str) -> Any | None:
        """Get cached value.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if key in self._cache:
            value, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                return value
            del self._cache[key]

        return None

    def set(self, key: str, value: Any) -> None:
        """Set cached value.

        Args:
            key: Cache key
            value: Value to cache
        """
        # Remove oldest entries if at max size
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        self._cache[key] = (value, datetime.utcnow())

    def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()

    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)
