"""
Event Publisher Port Interface

Protocol for publishing domain events to the event bus.
"""

from typing import Any, Protocol
from uuid import UUID


class IEventPublisherPort(Protocol):
    """Protocol for domain event publishing."""
    
    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """
        Publish user registered event.
        
        Args:
            user_data: User registration data
        """
        ...
    
    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """
        Publish user activated event.
        
        Args:
            user_data: User activation data
        """
        ...
    
    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """
        Publish user deactivated event.
        
        Args:
            user_data: User deactivation data
        """
        ...
    
    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """
        Publish profile completed event.
        
        Args:
            user_data: Profile completion data
        """
        ...
    
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
