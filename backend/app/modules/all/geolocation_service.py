"""
Geolocation Service Interface

Protocol for IP-based geolocation and location analysis operations.
"""

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from ....value_objects.ip_address import IpAddress

if TYPE_CHECKING:
    from ....value_objects.location_info import LocationInfo
    from ....value_objects.location_risk_assessment import LocationRiskAssessment


class IGeolocationService(Protocol):
    """Protocol for geolocation services."""
    
    async def get_location_info(self, ip_address: IpAddress) -> "LocationInfo":
        """
        Get location information for IP address.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            LocationInfo value object containing geographic and security data
        """
        ...
    
    async def is_suspicious_location(
        self, 
        user_id: UUID, 
        ip_address: IpAddress
    ) -> "LocationRiskAssessment":
        """
        Check if location is suspicious for user.
        
        Args:
            user_id: User identifier
            ip_address: IP address to check
            
        Returns:
            LocationRiskAssessment value object containing risk analysis
        """
    
    async def update_known_locations(
        self,
        user_id: UUID,
        location_info: dict[str, Any]
    ) -> None:
        """
        Update user's known locations.
        
        Args:
            user_id: User identifier
            location_info: Location details to add
        """
