"""
Notification Contract Interface

Contract for sending notifications to the notification module.
This defines how the Identity domain communicates with the Notification module.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class INotificationContract(ABC):
    """Contract for sending notifications to the notification module."""
    
    @abstractmethod
    async def send_email_notification(
        self,
        user_id: UUID,
        template_name: str,
        template_data: dict[str, Any],
        priority: str = "normal"
    ) -> None:
        """
        Send email notification via notification module.
        
        Args:
            user_id: User identifier
            template_name: Email template name
            template_data: Template variables
            priority: Email priority (low/normal/high)
        """
    
    @abstractmethod
    async def send_sms_notification(
        self,
        user_id: UUID,
        phone_number: str,
        message: str,
        priority: str = "normal"
    ) -> None:
        """
        Send SMS notification via notification module.
        
        Args:
            user_id: User identifier
            phone_number: Recipient phone number
            message: SMS message content
            priority: SMS priority
        """
    
    @abstractmethod
    async def send_push_notification(
        self,
        user_id: UUID,
        device_tokens: list[str],
        title: str,
        body: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """
        Send push notification via notification module.
        
        Args:
            user_id: User identifier
            device_tokens: List of device tokens
            title: Notification title
            body: Notification body
            data: Additional data payload
        """
    
    @abstractmethod
    async def send_in_app_notification(
        self,
        user_id: UUID,
        notification_type: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """
        Send in-app notification via notification module.
        
        Args:
            user_id: User identifier
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            data: Additional notification data
        """
    
    @abstractmethod
    async def schedule_notification(
        self,
        user_id: UUID,
        notification_type: str,
        scheduled_at: datetime,
        notification_data: dict[str, Any]
    ) -> str:
        """
        Schedule a future notification.
        
        Args:
            user_id: User identifier
            notification_type: Type of notification (email/sms/push)
            scheduled_at: When to send the notification
            notification_data: Notification details
            
        Returns:
            Scheduled notification ID
        """
