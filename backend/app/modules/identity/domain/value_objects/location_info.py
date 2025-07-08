"""
Location Info Value Object

Represents geographic location information.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class LocationInfo(ValueObject):
    """
    Value object representing geographic location information.
    
    Encapsulates location data, security indicators, and metadata
    for geolocation-based security decisions.
    """
    
    country_code: str
    country_name: str
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    accuracy_radius: int | None = None
    metadata: dict[str, Any] | None = None
    
    def __post_init__(self) -> None:
        """Validate location info data."""
        if len(self.country_code) != 2:
            raise ValueError("Country code must be 2 characters")
        
        if self.latitude is not None and not -90 <= self.latitude <= 90:
            raise ValueError("Latitude must be between -90 and 90")
        
        if self.longitude is not None and not -180 <= self.longitude <= 180:
            raise ValueError("Longitude must be between -180 and 180")
    
    def is_suspicious(self) -> bool:
        """Check if location has suspicious indicators."""
        return self.is_vpn or self.is_tor or self.is_proxy
    
    def has_coordinates(self) -> bool:
        """Check if location has coordinate data."""
        return self.latitude is not None and self.longitude is not None
    
    def get_display_name(self) -> str:
        """Get human-readable location name."""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region:
            parts.append(self.region)
        parts.append(self.country_name)
        return ", ".join(parts)
