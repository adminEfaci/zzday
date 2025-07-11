"""
Access Token Service Interface

Protocol for access token management including refresh strategies,
security validation, and token family management.
"""

from typing import Any, Protocol
from uuid import UUID

from ....aggregates.access_token import AccessToken
from ....enums import RefreshStrategy


class IAccessTokenService(Protocol):
    """Protocol for access token domain service operations."""
    
    def determine_refresh_strategy(
        self,
        user_id: UUID,
        client_type: str,
        security_level: str = "standard"
    ) -> RefreshStrategy:
        """
        Determine appropriate refresh strategy based on context.
        
        Args:
            user_id: User identifier
            client_type: Type of client application
            security_level: Security level requirement
            
        Returns:
            Recommended refresh strategy
        """
        ...
    
    def validate_refresh_request(
        self,
        token: AccessToken,
        raw_refresh_token: str,
        client_security_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Validate refresh token request and detect security issues.
        
        Args:
            token: Access token to refresh
            raw_refresh_token: Raw refresh token value
            client_security_context: Optional security context
            
        Returns:
            Validation result with security assessment
        """
        ...
    
    def execute_refresh_with_security_checks(
        self,
        token: AccessToken,
        raw_refresh_token: str,
        new_ttl: int = 3600,
        refresh_ttl: int | None = None,
        security_context: dict[str, Any] | None = None
    ) -> tuple[AccessToken, str, str | None]:
        """
        Execute token refresh with comprehensive security checks.
        
        Args:
            token: Access token to refresh
            raw_refresh_token: Raw refresh token value
            new_ttl: New access token TTL in seconds
            refresh_ttl: New refresh token TTL in seconds
            security_context: Optional security context
            
        Returns:
            Tuple of (new_token, access_token_value, refresh_token_value)
        """
        ...
    
    def manage_token_family(
        self,
        family_id: UUID,
        operation: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        Manage token family operations.
        
        Args:
            family_id: Token family identifier
            operation: Operation to perform
            **kwargs: Additional operation parameters
            
        Returns:
            Operation result
        """
        ...
    
    def optimize_token_rotation_schedule(
        self,
        tokens: list[AccessToken],
        optimization_strategy: str = "balanced"
    ) -> dict[str, Any]:
        """
        Optimize token rotation schedules.
        
        Args:
            tokens: List of tokens to optimize
            optimization_strategy: Optimization strategy
            
        Returns:
            Optimization result and metrics
        """
        ...
    
    def generate_token_analytics(
        self,
        tokens: list[AccessToken],
        time_window_days: int = 30
    ) -> dict[str, Any]:
        """
        Generate comprehensive token usage analytics.
        
        Args:
            tokens: List of tokens to analyze
            time_window_days: Analysis time window
            
        Returns:
            Analytics data and metrics
        """
        ...
