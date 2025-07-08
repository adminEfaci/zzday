"""
Notification Service Interface

Port for sending notifications via email, SMS, and push notifications.
"""

from abc import ABC, abstractmethod
from typing import Any


class INotificationService(ABC):
    """Port for notification operations."""
    
    @abstractmethod
    async def send_email(
        self,
        to: str,
        subject: str,
        template: str,
        data: dict[str, Any],
        priority: str = "normal"
    ) -> str:
        """
        Send email notification.
        
        Args:
            to: Recipient email
            subject: Email subject
            template: Template name
            data: Template data
            priority: Email priority (low/normal/high)
            
        Returns:
            Message ID for tracking
        """
    
    @abstractmethod
    async def send_sms(
        self,
        phone: str,
        message: str,
        template: str | None = None
    ) -> str:
        """
        Send SMS notification.
        
        Args:
            phone: Phone number
            message: Message text
            template: Optional template name
            
        Returns:
            Message ID
        """
    
    @abstractmethod
    async def send_push_notification(
        self,
        device_tokens: str | list[str],
        title: str,
        body: str,
        data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Send push notification.
        
        Args:
            device_tokens: Single token or list
            title: Notification title
            body: Notification body
            data: Additional data payload
            
        Returns:
            Dict with delivery results
        """
    
    @abstractmethod
    async def send_bulk_email(
        self,
        recipients: list[dict[str, Any]],
        template: str,
        common_data: dict[str, Any] | None = None
    ) -> str:
        """
        Send bulk email.
        
        Args:
            recipients: List of recipient data
            template: Template name
            common_data: Common template data
            
        Returns:
            Batch ID
        """
    
    @abstractmethod
    async def get_delivery_status(self, message_id: str) -> dict[str, Any]:
        """
        Get message delivery status.
        
        Args:
            message_id: Message identifier
            
        Returns:
            Delivery status information
        """
    
    @abstractmethod
    async def handle_delivery_webhook(
        self,
        provider: str,
        webhook_data: dict[str, Any]
    ) -> bool:
        """
        Handle delivery status webhook.
        
        Args:
            provider: Webhook provider name
            webhook_data: Webhook payload
            
        Returns:
            True if processed successfully
        """


class ISMSService(ABC):
    """Port for SMS-specific operations."""
    
    @abstractmethod
    async def send_sms(
        self,
        to: str,
        message: str
    ) -> dict[str, Any]:
        """
        Send SMS message.
        
        Args:
            to: Phone number
            message: Message text
            
        Returns:
            Send result with message ID
        """
    
    @abstractmethod
    async def is_available(self) -> bool:
        """Check if SMS service is available."""


class IEmailService(ABC):
    """Port for email-specific operations."""
    
    @abstractmethod
    async def send_email(
        self,
        to: str,
        subject: str,
        html_content: str,
        text_content: str | None = None
    ) -> dict[str, Any]:
        """
        Send email message.
        
        Args:
            to: Email address
            subject: Email subject
            html_content: HTML content
            text_content: Optional plain text content
            
        Returns:
            Send result with message ID
        """
    
    @abstractmethod
    async def is_available(self) -> bool:
        """Check if email service is available."""
