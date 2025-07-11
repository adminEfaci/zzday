"""
Configuration Port Interface

Protocol for accessing configuration and feature flags.
"""

from typing import Any, Protocol
from uuid import UUID


class IConfigurationPort(Protocol):
    """Protocol for configuration management."""
    
    async def get_password_policy(self) -> dict[str, Any]:
        """
        Get password policy configuration.
        
        Returns:
            Password policy settings
        """
        ...
    
    async def get_session_config(self) -> dict[str, Any]:
        """
        Get session configuration.
        
        Returns:
            Session settings
        """
        ...
    
    async def get_mfa_config(self) -> dict[str, Any]:
        """
        Get MFA configuration.
        
        Returns:
            MFA settings
        """
        ...
    
    async def get_rate_limit_config(self, endpoint: str) -> dict[str, Any]:
        """
        Get rate limit configuration for endpoint.
        
        Args:
            endpoint: API endpoint
            
        Returns:
            Rate limit settings
        """
        ...
    
    async def is_feature_enabled(
        self,
        feature: str,
        user_id: UUID | None = None
    ) -> bool:
        """
        Check if feature is enabled.
        
        Args:
            feature: Feature name
            user_id: Optional user for A/B testing
            
        Returns:
            True if feature is enabled
        """
    
    async def get_compliance_settings(self) -> dict[str, Any]:
        """
        Get compliance settings.
        
        Returns:
            Compliance configuration
        """
        ...
