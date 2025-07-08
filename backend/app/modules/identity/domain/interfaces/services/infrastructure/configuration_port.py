"""
Configuration Port Interface

Port for accessing configuration and feature flags.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IConfigurationPort(ABC):
    """Port for configuration management."""
    
    @abstractmethod
    async def get_password_policy(self) -> dict[str, Any]:
        """
        Get password policy configuration.
        
        Returns:
            Password policy settings
        """
    
    @abstractmethod
    async def get_session_config(self) -> dict[str, Any]:
        """
        Get session configuration.
        
        Returns:
            Session settings
        """
    
    @abstractmethod
    async def get_mfa_config(self) -> dict[str, Any]:
        """
        Get MFA configuration.
        
        Returns:
            MFA settings
        """
    
    @abstractmethod
    async def get_rate_limit_config(self, endpoint: str) -> dict[str, Any]:
        """
        Get rate limit configuration for endpoint.
        
        Args:
            endpoint: API endpoint
            
        Returns:
            Rate limit settings
        """
    
    @abstractmethod
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
    
    @abstractmethod
    async def get_compliance_settings(self) -> dict[str, Any]:
        """
        Get compliance settings.
        
        Returns:
            Compliance configuration
        """
