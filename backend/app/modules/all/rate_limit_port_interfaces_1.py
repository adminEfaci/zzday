"""
Rate Limit Port Interface

Protocol for rate limiting and throttling operations.
"""

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ...value_objects.rate_limit_status import RateLimitStatus


class IRateLimitPort(Protocol):
    """Protocol for rate limiting operations."""
    
    async def check_rate_limit(
        self,
        identifier: str,
        rule: str
    ) -> "RateLimitStatus":
        """
        Check rate limit.
        
        Args:
            identifier: Client identifier (IP, user ID, etc.)
            rule: Rate limit rule name
            
        Returns:
            RateLimitStatus value object containing limit status
        """
    
    async def increment_usage(
        self,
        identifier: str,
        rule: str,
        amount: int = 1
    ) -> int:
        """
        Increment rate limit usage.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            amount: Increment amount
            
        Returns:
            New usage count
        """
    
    async def reset_rate_limit(
        self,
        identifier: str,
        rule: str
    ) -> bool:
        """
        Reset rate limit counter.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            
        Returns:
            True if reset successfully
        """
    
    async def get_rate_limit_status(
        self,
        identifier: str,
        rule: str
    ) -> dict[str, Any]:
        """
        Get current rate limit status.
        
        Args:
            identifier: Client identifier
            rule: Rate limit rule
            
        Returns:
            Current limit status
        """
