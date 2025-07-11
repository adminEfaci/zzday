"""
Security Service Interface

Protocol for security monitoring, threat detection, and incident management.
"""

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from ....value_objects.ip_address import IpAddress

if TYPE_CHECKING:
    from ....value_objects.ip_reputation import IpReputation


class ISecurityService(Protocol):
    """Protocol for security monitoring and threat detection."""
    
    async def detect_anomalies(
        self, 
        user_id: UUID, 
        activity_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Detect anomalous behavior.
        
        Args:
            user_id: User identifier
            activity_data: Recent activity data
            
        Returns:
            List of detected anomalies with severity
        """
    
    async def check_ip_reputation(self, ip_address: IpAddress) -> "IpReputation":
        """
        Check IP address reputation.
        
        Args:
            ip_address: IP to check
            
        Returns:
            IpReputation value object containing reputation analysis
        """
        ...
    
    async def scan_for_threats(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Scan data for security threats.
        
        Args:
            data: Data to scan
            
        Returns:
            List of detected threats
        """
        ...
    
    async def report_security_incident(
        self,
        incident_type: str,
        details: dict[str, Any]
    ) -> str:
        """
        Report security incident.
        
        Args:
            incident_type: Type of incident
            details: Incident details
            
        Returns:
            Incident ID for tracking
        """
