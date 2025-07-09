"""
Notification Preference Service Interface

Port for notification preference management including channel preferences,
frequency settings, and opt-out management.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.notification.domain.enums import NotificationChannel, NotificationType


class INotificationPreferenceService(ABC):
    """Port for notification preference operations."""
    
    @abstractmethod
    async def get_user_preferences(
        self,
        user_id: UUID
    ) -> dict[str, Any]:
        """
        Get all notification preferences for a user.
        
        Args:
            user_id: ID of user
            
        Returns:
            Dictionary of user preferences
        """
        ...
    
    @abstractmethod
    async def update_channel_preference(
        self,
        user_id: UUID,
        channel: "NotificationChannel",
        enabled: bool,
        settings: dict[str, Any] | None = None
    ) -> None:
        """
        Update preference for a specific channel.
        
        Args:
            user_id: ID of user
            channel: Notification channel
            enabled: Whether channel is enabled
            settings: Optional channel-specific settings
            
        Raises:
            UserNotFoundError: If user doesn't exist
            InvalidChannelError: If channel is invalid
        """
        ...
    
    @abstractmethod
    async def update_type_preference(
        self,
        user_id: UUID,
        notification_type: "NotificationType",
        enabled: bool,
        channels: list["NotificationChannel"] | None = None
    ) -> None:
        """
        Update preference for a notification type.
        
        Args:
            user_id: ID of user
            notification_type: Type of notification
            enabled: Whether type is enabled
            channels: Optional list of allowed channels
            
        Raises:
            UserNotFoundError: If user doesn't exist
            InvalidNotificationTypeError: If type is invalid
        """
        ...
    
    @abstractmethod
    async def set_frequency_limit(
        self,
        user_id: UUID,
        notification_type: "NotificationType | None",
        max_per_hour: int | None = None,
        max_per_day: int | None = None,
        max_per_week: int | None = None
    ) -> None:
        """
        Set frequency limits for notifications.
        
        Args:
            user_id: ID of user
            notification_type: Optional specific type (None for global)
            max_per_hour: Maximum notifications per hour
            max_per_day: Maximum notifications per day
            max_per_week: Maximum notifications per week
        """
        ...
    
    @abstractmethod
    async def check_frequency_limit(
        self,
        user_id: UUID,
        notification_type: "NotificationType"
    ) -> tuple[bool, str | None]:
        """
        Check if frequency limit is exceeded.
        
        Args:
            user_id: ID of user
            notification_type: Type of notification
            
        Returns:
            Tuple of (is_within_limit, limit_type_exceeded)
        """
        ...
    
    @abstractmethod
    async def set_quiet_hours(
        self,
        user_id: UUID,
        start_time: str,  # HH:MM format
        end_time: str,    # HH:MM format
        timezone: str = "UTC",
        days_of_week: list[int] | None = None  # 0=Monday, 6=Sunday
    ) -> None:
        """
        Set quiet hours for user.
        
        Args:
            user_id: ID of user
            start_time: Start time in HH:MM format
            end_time: End time in HH:MM format
            timezone: User's timezone
            days_of_week: Optional specific days (all days if None)
        """
        ...
    
    @abstractmethod
    async def opt_out_all(
        self,
        user_id: UUID,
        reason: str | None = None,
        except_types: list["NotificationType"] | None = None
    ) -> None:
        """
        Opt out user from all notifications.
        
        Args:
            user_id: ID of user
            reason: Optional opt-out reason
            except_types: Optional list of types to keep enabled
        """
        ...
    
    @abstractmethod
    async def opt_in_all(
        self,
        user_id: UUID
    ) -> None:
        """
        Opt in user to all notifications (reset to defaults).
        
        Args:
            user_id: ID of user
        """
        ...
    
    @abstractmethod
    async def get_preferred_channel(
        self,
        user_id: UUID,
        notification_type: "NotificationType"
    ) -> "NotificationChannel | None":
        """
        Get user's preferred channel for a notification type.
        
        Args:
            user_id: ID of user
            notification_type: Type of notification
            
        Returns:
            Preferred channel or None if no preference
        """
        ...
    
    @abstractmethod
    async def import_preferences(
        self,
        user_id: UUID,
        preferences: dict[str, Any],
        merge: bool = False
    ) -> None:
        """
        Import notification preferences from external source.
        
        Args:
            user_id: ID of user
            preferences: Preferences to import
            merge: Whether to merge with existing (False = replace)
        """
        ...
    
    @abstractmethod
    async def export_preferences(
        self,
        user_id: UUID
    ) -> dict[str, Any]:
        """
        Export user's notification preferences.
        
        Args:
            user_id: ID of user
            
        Returns:
            Exportable preferences dictionary
        """
        ...