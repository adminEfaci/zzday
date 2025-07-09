"""
Notification Delivery Service Interface

Port for notification delivery operations including channel selection,
delivery orchestration, and status tracking.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.notification.domain.aggregates.notification_batch import NotificationBatch
    from app.modules.notification.domain.enums import NotificationChannel, NotificationStatus


class INotificationDeliveryService(ABC):
    """Port for notification delivery operations."""
    
    @abstractmethod
    async def deliver_notification(
        self,
        recipient_id: UUID,
        template_id: UUID,
        data: dict[str, Any],
        channel: "NotificationChannel | None" = None,
        priority: int = 5
    ) -> UUID:
        """
        Deliver a notification to a recipient.
        
        Args:
            recipient_id: ID of the recipient
            template_id: ID of the notification template
            data: Template data for rendering
            channel: Optional specific channel (auto-select if None)
            priority: Priority level (1-10, 10 being highest)
            
        Returns:
            ID of the created notification
            
        Raises:
            RecipientNotFoundError: If recipient doesn't exist
            TemplateNotFoundError: If template doesn't exist
            InvalidChannelError: If channel is not available for recipient
            DeliveryFailedError: If delivery fails
        """
        ...
    
    @abstractmethod
    async def deliver_batch(
        self,
        batch: "NotificationBatch"
    ) -> dict[UUID, "NotificationStatus"]:
        """
        Deliver a batch of notifications.
        
        Args:
            batch: NotificationBatch aggregate
            
        Returns:
            Dictionary mapping notification IDs to delivery status
        """
        ...
    
    @abstractmethod
    async def retry_failed_delivery(
        self,
        notification_id: UUID,
        force_channel: "NotificationChannel | None" = None
    ) -> bool:
        """
        Retry delivery of a failed notification.
        
        Args:
            notification_id: ID of notification to retry
            force_channel: Optional channel to force retry on
            
        Returns:
            True if retry succeeded
            
        Raises:
            NotificationNotFoundError: If notification doesn't exist
            MaxRetriesExceededError: If max retries reached
        """
        ...
    
    @abstractmethod
    async def select_delivery_channel(
        self,
        recipient_id: UUID,
        notification_type: str,
        available_channels: list["NotificationChannel"]
    ) -> "NotificationChannel":
        """
        Select the best delivery channel based on preferences and availability.
        
        Args:
            recipient_id: ID of the recipient
            notification_type: Type of notification
            available_channels: List of available channels
            
        Returns:
            Selected channel for delivery
            
        Raises:
            NoAvailableChannelError: If no suitable channel found
        """
        ...
    
    @abstractmethod
    async def validate_delivery_readiness(
        self,
        recipient_id: UUID,
        channel: "NotificationChannel"
    ) -> tuple[bool, str | None]:
        """
        Validate if recipient is ready to receive on channel.
        
        Args:
            recipient_id: ID of the recipient
            channel: Channel to validate
            
        Returns:
            Tuple of (is_ready, error_reason)
        """
        ...
    
    @abstractmethod
    async def track_delivery_status(
        self,
        notification_id: UUID,
        status: "NotificationStatus",
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Update delivery status of a notification.
        
        Args:
            notification_id: ID of notification
            status: New status
            metadata: Optional status metadata
        """
        ...
    
    @abstractmethod
    async def handle_delivery_feedback(
        self,
        notification_id: UUID,
        feedback_type: str,
        feedback_data: dict[str, Any]
    ) -> None:
        """
        Handle delivery feedback (bounces, complaints, etc).
        
        Args:
            notification_id: ID of notification
            feedback_type: Type of feedback (bounce, complaint, etc)
            feedback_data: Feedback details
        """
        ...
    
    @abstractmethod
    async def should_suppress_notification(
        self,
        recipient_id: UUID,
        notification_type: str,
        deduplication_key: str | None = None
    ) -> bool:
        """
        Check if notification should be suppressed.
        
        Args:
            recipient_id: ID of the recipient
            notification_type: Type of notification
            deduplication_key: Optional key for deduplication
            
        Returns:
            True if notification should be suppressed
        """
        ...