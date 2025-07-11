"""
Security Validator Interface for Identity Domain

Domain port for security validation operations following hexagonal architecture.
This interface defines contracts for overall security validation that infrastructure adapters must implement.
"""

from typing import Any, Protocol
from uuid import UUID


class ISecurityValidator(Protocol):
    """Interface for security validation operations."""
    
    async def validate_request_security(
        self,
        user_id: UUID,
        request_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate overall security of a request.
        
        Args:
            user_id: User making the request
            request_context: Request context (IP, user agent, etc.)
            
        Returns:
            dict: Security validation result with risk level and recommendations
        """
        ...
    
    async def check_ip_reputation(self, ip_address: str) -> dict[str, Any]:
        """Check IP address reputation.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            dict: Reputation data with risk assessment
        """
        ...
    
    async def validate_device_fingerprint(
        self,
        user_id: UUID,
        device_fingerprint: str
    ) -> bool:
        """Validate device fingerprint against known devices.
        
        Args:
            user_id: User identifier
            device_fingerprint: Device fingerprint to validate
            
        Returns:
            bool: True if device is trusted
        """
        ...
    
    async def assess_login_risk(
        self,
        user_id: UUID,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Assess risk level for login attempt.
        
        Args:
            user_id: User attempting login
            context: Login context
            
        Returns:
            dict: Risk assessment with level and factors
        """
        ...
    
    async def validate_session_security(
        self,
        session_id: str,
        current_context: dict[str, Any]
    ) -> bool:
        """Validate ongoing session security.
        
        Args:
            session_id: Session to validate
            current_context: Current request context
            
        Returns:
            bool: True if session is secure
        """
        ...
