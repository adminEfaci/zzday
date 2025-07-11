"""
API Gateway Service Interface

Port for API gateway operations including request routing,
rate limiting, authentication, and response transformation.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.integration.domain.enums import ApiAuthType, HttpMethod


class IApiGatewayService(ABC):
    """Port for API gateway operations."""
    
    @abstractmethod
    async def make_request(
        self,
        integration_id: UUID,
        endpoint: str,
        method: "HttpMethod",
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30
    ) -> dict[str, Any]:
        """
        Make an API request through the gateway.
        
        Args:
            integration_id: ID of integration to use
            endpoint: API endpoint path
            method: HTTP method
            data: Optional request data
            headers: Optional custom headers
            timeout: Request timeout in seconds
            
        Returns:
            Response data
            
        Raises:
            IntegrationNotFoundError: If integration doesn't exist
            RateLimitExceededError: If rate limit exceeded
            ApiRequestError: If request fails
            TimeoutError: If request times out
        """
        ...
    
    @abstractmethod
    async def authenticate_request(
        self,
        integration_id: UUID,
        auth_type: "ApiAuthType",
        credentials: dict[str, Any]
    ) -> dict[str, str]:
        """
        Generate authentication headers for request.
        
        Args:
            integration_id: ID of integration
            auth_type: Type of authentication
            credentials: Authentication credentials
            
        Returns:
            Dictionary of auth headers
            
        Raises:
            InvalidAuthTypeError: If auth type not supported
            InvalidCredentialsError: If credentials invalid
        """
        ...
    
    @abstractmethod
    async def apply_rate_limit(
        self,
        integration_id: UUID,
        endpoint: str,
        check_only: bool = False
    ) -> tuple[bool, dict[str, Any]]:
        """
        Apply or check rate limiting.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            check_only: Only check, don't consume quota
            
        Returns:
            Tuple of (allowed, rate_limit_info)
        """
        ...
    
    @abstractmethod
    async def cache_response(
        self,
        integration_id: UUID,
        endpoint: str,
        method: "HttpMethod",
        params: dict[str, Any],
        response: dict[str, Any],
        ttl: int = 300
    ) -> None:
        """
        Cache API response.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            method: HTTP method
            params: Request parameters
            response: Response to cache
            ttl: Time to live in seconds
        """
        ...
    
    @abstractmethod
    async def get_cached_response(
        self,
        integration_id: UUID,
        endpoint: str,
        method: "HttpMethod",
        params: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Get cached response if available.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            method: HTTP method
            params: Request parameters
            
        Returns:
            Cached response or None
        """
        ...
    
    @abstractmethod
    async def transform_request(
        self,
        integration_id: UUID,
        endpoint: str,
        data: dict[str, Any],
        transformation_rules: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Transform request data before sending.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            data: Original request data
            transformation_rules: Optional custom rules
            
        Returns:
            Transformed request data
        """
        ...
    
    @abstractmethod
    async def transform_response(
        self,
        integration_id: UUID,
        endpoint: str,
        response: dict[str, Any],
        transformation_rules: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Transform response data after receiving.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            response: Original response
            transformation_rules: Optional custom rules
            
        Returns:
            Transformed response data
        """
        ...
    
    @abstractmethod
    async def handle_pagination(
        self,
        integration_id: UUID,
        endpoint: str,
        method: "HttpMethod",
        params: dict[str, Any],
        max_pages: int | None = None
    ) -> list[dict[str, Any]]:
        """
        Handle paginated API responses.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            method: HTTP method
            params: Request parameters
            max_pages: Optional maximum pages to fetch
            
        Returns:
            List of all pages of results
        """
        ...
    
    @abstractmethod
    async def batch_requests(
        self,
        integration_id: UUID,
        requests: list[dict[str, Any]],
        parallel: bool = False,
        max_parallel: int = 5
    ) -> list[dict[str, Any]]:
        """
        Execute multiple API requests.
        
        Args:
            integration_id: ID of integration
            requests: List of request specifications
            parallel: Whether to execute in parallel
            max_parallel: Maximum parallel requests
            
        Returns:
            List of responses
        """
        ...
    
    @abstractmethod
    async def circuit_breaker_status(
        self,
        integration_id: UUID,
        endpoint: str | None = None
    ) -> dict[str, Any]:
        """
        Get circuit breaker status for integration.
        
        Args:
            integration_id: ID of integration
            endpoint: Optional specific endpoint
            
        Returns:
            Circuit breaker status and metrics
        """
        ...
    
    @abstractmethod
    async def record_api_metrics(
        self,
        integration_id: UUID,
        endpoint: str,
        method: "HttpMethod",
        response_time: float,
        status_code: int,
        success: bool
    ) -> None:
        """
        Record API call metrics.
        
        Args:
            integration_id: ID of integration
            endpoint: API endpoint
            method: HTTP method
            response_time: Response time in seconds
            status_code: HTTP status code
            success: Whether request succeeded
        """
        ...