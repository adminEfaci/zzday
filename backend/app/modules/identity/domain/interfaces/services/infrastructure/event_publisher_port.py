"""
Event Publisher Port Interface

Port for publishing domain events to the event bus.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IEventPublisherPort(ABC):
    """Port for domain event publishing."""
    
    @abstractmethod
    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """
        Publish user registered event.
        
        Args:
            user_data: User registration data
        """
    
    @abstractmethod
    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """
        Publish user activated event.
        
        Args:
            user_data: User activation data
        """
    
    @abstractmethod
    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """
        Publish user deactivated event.
        
        Args:
            user_data: User deactivation data
        """
    
    @abstractmethod
    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """
        Publish profile completed event.
        
        Args:
            user_data: Profile completion data
        """
    
    @abstractmethod
    async def publish_security_alert(
        self,
        user_id: UUID,
        alert_data: dict[str, Any]
    ) -> None:
        """
        Publish security alert event.
        
        Args:
            user_id: User identifier
            alert_data: Alert details
        """
    
    @abstractmethod
    async def publish_password_changed(
        self,
        user_id: UUID,
        change_context: dict[str, Any]
    ) -> None:
        """
        Publish password changed event.
        
        Args:
            user_id: User identifier
            change_context: Change context (forced, expired, etc.)
        """
