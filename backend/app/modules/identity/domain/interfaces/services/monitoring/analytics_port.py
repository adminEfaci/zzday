"""
Analytics Port Interface

Port for analytics and event tracking operations.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IAnalyticsPort(ABC):
    """Port for analytics tracking."""
    
    @abstractmethod
    async def track_user_event(
        self,
        event_name: str,
        user_id: UUID | None = None,
        properties: dict[str, Any] | None = None
    ) -> None:
        """
        Track user event.
        
        Args:
            event_name: Event name
            user_id: User identifier
            properties: Event properties
        """
    
    @abstractmethod
    async def track_authentication_attempt(
        self,
        user_id: UUID | None,
        success: bool,
        method: str,
        context: dict[str, Any]
    ) -> None:
        """
        Track authentication attempt.
        
        Args:
            user_id: User identifier
            success: Whether attempt succeeded
            method: Authentication method
            context: Additional context
        """
    
    @abstractmethod
    async def track_profile_completion(
        self,
        user_id: UUID,
        completion_percentage: float
    ) -> None:
        """
        Track profile completion progress.
        
        Args:
            user_id: User identifier
            completion_percentage: Completion percentage (0-100)
        """
    
    @abstractmethod
    async def track_security_event(
        self,
        event_type: str,
        user_id: UUID | None,
        severity: str,
        context: dict[str, Any]
    ) -> None:
        """
        Track security event.
        
        Args:
            event_type: Type of security event
            user_id: Affected user
            severity: Event severity (low/medium/high/critical)
            context: Event context
        """
