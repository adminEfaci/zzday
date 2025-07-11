"""
Threat Intelligence Service Interface

Protocol for threat intelligence, breach detection, and security incident reporting.
"""

from typing import Any, Protocol

from ....value_objects.ip_address import IpAddress


class IThreatIntelligenceService(Protocol):
    """Protocol for threat intelligence operations."""
    
    async def check_compromised_credentials(
        self,
        email: str,
        password_hash: str
    ) -> bool:
        """
        Check if credentials are compromised.
        
        Args:
            email: User email
            password_hash: Hashed password
            
        Returns:
            True if credentials found in breach databases
        """
    
    async def get_threat_indicators(
        self,
        ip_address: IpAddress
    ) -> list[dict[str, Any]]:
        """
        Get threat indicators for IP address.
        
        Args:
            ip_address: IP to check
            
        Returns:
            List of threat indicators
        """
    
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
            Incident report ID
        """
