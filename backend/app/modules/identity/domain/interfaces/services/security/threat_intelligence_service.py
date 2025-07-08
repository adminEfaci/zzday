"""
Threat Intelligence Service Interface

Port for threat intelligence, breach detection, and security incident reporting.
"""

from abc import ABC, abstractmethod
from typing import Any

from ....value_objects.ip_address import IpAddress


class IThreatIntelligenceService(ABC):
    """Port for threat intelligence operations."""
    
    @abstractmethod
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
    
    @abstractmethod
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
    
    @abstractmethod
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
