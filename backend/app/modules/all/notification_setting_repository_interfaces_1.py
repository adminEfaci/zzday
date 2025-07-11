"""Notification Setting Repository Interface

Domain contract for notification setting data access that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import Protocol
from uuid import UUID


class INotificationSettingRepository(Protocol):
    """Repository interface for notification setting management."""
    
    @abstractmethod
    async def create(
        self, 
        user_id: UUID,
        notification_type: str,
        channel: str,
        enabled: bool = True,
        frequency: str | None = None,
        metadata: dict | None = None
    ) -> UUID:
        """Create notification setting.
        
        Args:
            user_id: User identifier
            notification_type: Type of notification (login, security, etc.)
            channel: Delivery channel (email, sms, push)
            enabled: Whether notification is enabled
            frequency: Notification frequency (immediate, daily, weekly)
            metadata: Additional setting metadata
            
        Returns:
            Created setting ID
        """
        ...
    
    @abstractmethod
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all notification settings for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's notification settings
        """
        ...
    
    @abstractmethod
    async def find_by_type(
        self, 
        user_id: UUID, 
        notification_type: str
    ) -> list[dict]:
        """Find notification settings by type for user.
        
        Args:
            user_id: User identifier
            notification_type: Notification type
            
        Returns:
            List of settings for the notification type
        """
        ...
    
    @abstractmethod
    async def find_by_channel(
        self, 
        user_id: UUID, 
        channel: str
    ) -> list[dict]:
        """Find notification settings by channel for user.
        
        Args:
            user_id: User identifier
            channel: Delivery channel
            
        Returns:
            List of settings for the channel
        """
        ...
    
    @abstractmethod
    async def is_enabled(
        self, 
        user_id: UUID,
        notification_type: str,
        channel: str
    ) -> bool:
        """Check if notification is enabled for user.
        
        Args:
            user_id: User identifier
            notification_type: Notification type
            channel: Delivery channel
            
        Returns:
            True if notification is enabled
        """
        ...
    
    @abstractmethod
    async def update_setting(
        self, 
        setting_id: UUID,
        enabled: bool | None = None,
        frequency: str | None = None,
        metadata: dict | None = None
    ) -> bool:
        """Update notification setting.
        
        Args:
            setting_id: Setting identifier
            enabled: New enabled status
            frequency: New frequency
            metadata: New metadata
            
        Returns:
            True if updated, False if not found
        """
        ...
    
    @abstractmethod
    async def bulk_update(
        self, 
        user_id: UUID,
        updates: list[dict]
    ) -> int:
        """Update multiple notification settings at once.
        
        Args:
            user_id: User identifier
            updates: List of setting updates
            
        Returns:
            Number of settings updated
        """
        ...
    
    @abstractmethod
    async def enable_all(self, user_id: UUID, channel: str | None = None) -> int:
        """Enable all notifications for user.
        
        Args:
            user_id: User identifier
            channel: Optional specific channel
            
        Returns:
            Number of settings enabled
        """
        ...
    
    @abstractmethod
    async def disable_all(self, user_id: UUID, channel: str | None = None) -> int:
        """Disable all notifications for user.
        
        Args:
            user_id: User identifier
            channel: Optional specific channel
            
        Returns:
            Number of settings disabled
        """
        ...