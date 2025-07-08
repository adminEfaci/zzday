"""
Cache Port Interface

Port for caching operations including session and user-specific data.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class ICachePort(ABC):
    """Port for caching operations."""
    
    @abstractmethod
    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Get session from cache.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data if found
        """
    
    @abstractmethod
    async def store_session(
        self,
        session_id: str,
        data: dict[str, Any],
        ttl: int
    ) -> bool:
        """
        Store session in cache.
        
        Args:
            session_id: Session identifier
            data: Session data
            ttl: Time to live in seconds
            
        Returns:
            True if stored successfully
        """
    
    @abstractmethod
    async def delete_session(self, session_id: str) -> bool:
        """
        Delete session from cache.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if deleted
        """
    
    @abstractmethod
    async def get_user_cache(
        self,
        user_id: UUID,
        key: str
    ) -> Any | None:
        """
        Get user-specific cache value.
        
        Args:
            user_id: User identifier
            key: Cache key
            
        Returns:
            Cached value if found
        """
    
    @abstractmethod
    async def set_user_cache(
        self,
        user_id: UUID,
        key: str,
        value: Any,
        ttl: int | None = None
    ) -> bool:
        """
        Set user-specific cache value.
        
        Args:
            user_id: User identifier
            key: Cache key
            value: Value to cache
            ttl: Optional TTL in seconds
            
        Returns:
            True if cached successfully
        """
    
    @abstractmethod
    async def invalidate_user_cache(self, user_id: UUID) -> None:
        """
        Invalidate all user cache entries.
        
        Args:
            user_id: User identifier
        """
    
    @abstractmethod
    async def increment_counter(
        self,
        key: str,
        amount: int = 1
    ) -> int:
        """
        Increment counter atomically.
        
        Args:
            key: Counter key
            amount: Increment amount
            
        Returns:
            New counter value
        """
