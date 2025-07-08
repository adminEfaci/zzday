"""
Notification Adapter

Implementation of INotificationService port for sending notifications.
Provides a unified interface for various notification channels.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.logging import logger
from app.modules.identity.application.contracts.ports import INotificationService


class NotificationAdapter(INotificationService):
    """Implementation of notification service port.
    
    This adapter provides a unified interface for sending notifications
    through various channels (email, SMS, push, in-app). In a real
    implementation, this would integrate with services like:
    - Email: SendGrid, AWS SES, Mailgun
    - SMS: Twilio, AWS SNS, Vonage
    - Push: Firebase, OneSignal, AWS SNS
    - In-app: WebSocket server, Redis pub/sub
    """
    
    def __init__(
        self,
        email_enabled: bool = True,
        sms_enabled: bool = True,
        push_enabled: bool = True,
        in_app_enabled: bool = True
    ):
        """Initialize notification adapter.
        
        Args:
            email_enabled: Whether email notifications are enabled
            sms_enabled: Whether SMS notifications are enabled
            push_enabled: Whether push notifications are enabled
            in_app_enabled: Whether in-app notifications are enabled
        """
        self._email_enabled = email_enabled
        self._sms_enabled = sms_enabled
        self._push_enabled = push_enabled
        self._in_app_enabled = in_app_enabled
        self._notification_log: list[dict[str, Any]] = []
    
    async def send_notification(
        self,
        user_id: UUID,
        notification_type: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """Send notification to user.
        
        Args:
            user_id: User identifier
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            data: Additional notification data
        """
        try:
            # Create notification record
            notification = {
                "id": str(UUID()),
                "user_id": str(user_id),
                "type": notification_type,
                "title": title,
                "message": message,
                "data": data or {},
                "timestamp": datetime.now(UTC).isoformat(),
                "channels": []
            }
            
            # Determine channels based on notification type and preferences
            channels = self._determine_channels(notification_type)
            
            # Send through each enabled channel
            tasks = []
            for channel in channels:
                if self._is_channel_enabled(channel):
                    tasks.append(self._send_to_channel(
                        channel,
                        user_id,
                        title,
                        message,
                        data
                    ))
                    notification["channels"].append(channel)
            
            # Execute all channel sends concurrently
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Log any failures
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(
                            f"Failed to send notification via {notification['channels'][i]}: {result}",
                            user_id=str(user_id),
                            channel=notification["channels"][i],
                            error=str(result)
                        )
            
            # Store notification record
            self._notification_log.append(notification)
            
            logger.info(
                f"Notification sent to user {user_id}",
                user_id=str(user_id),
                notification_type=notification_type,
                channels=notification["channels"]
            )
            
        except Exception as e:
            logger.error(
                f"Failed to send notification: {e}",
                user_id=str(user_id),
                notification_type=notification_type,
                error=str(e)
            )
            # Don't raise - notification failures should not break the application
    
    async def send_bulk_notification(
        self,
        user_ids: list[UUID],
        notification_type: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """Send notification to multiple users.
        
        Args:
            user_ids: List of user identifiers
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            data: Additional notification data
        """
        if not user_ids:
            return
        
        try:
            logger.info(
                f"Sending bulk notification to {len(user_ids)} users",
                user_count=len(user_ids),
                notification_type=notification_type
            )
            
            # Send to each user concurrently
            tasks = [
                self.send_notification(
                    user_id=user_id,
                    notification_type=notification_type,
                    title=title,
                    message=message,
                    data=data
                )
                for user_id in user_ids
            ]
            
            # Execute with controlled concurrency
            # Limit to 50 concurrent sends to avoid overwhelming services
            semaphore = asyncio.Semaphore(50)
            
            async def send_with_limit(task):
                async with semaphore:
                    return await task
            
            await asyncio.gather(
                *[send_with_limit(task) for task in tasks],
                return_exceptions=True
            )
            
            logger.info(
                "Bulk notification completed",
                user_count=len(user_ids),
                notification_type=notification_type
            )
            
        except Exception as e:
            logger.error(
                f"Failed to send bulk notification: {e}",
                user_count=len(user_ids),
                notification_type=notification_type,
                error=str(e)
            )
    
    def _determine_channels(self, notification_type: str) -> list[str]:
        """Determine which channels to use for notification type.
        
        Args:
            notification_type: Type of notification
            
        Returns:
            List of channel names
        """
        # Map notification types to channels
        # In a real implementation, this would be configurable
        channel_map = {
            "security_alert": ["email", "sms", "push", "in_app"],
            "password_reset": ["email"],
            "email_verification": ["email"],
            "login_notification": ["email", "push"],
            "account_update": ["email", "in_app"],
            "mfa_code": ["sms", "email"],
            "welcome": ["email", "in_app"],
            "general": ["in_app", "push"]
        }
        
        return channel_map.get(notification_type, ["in_app"])
    
    def _is_channel_enabled(self, channel: str) -> bool:
        """Check if channel is enabled.
        
        Args:
            channel: Channel name
            
        Returns:
            True if channel is enabled
        """
        channel_status = {
            "email": self._email_enabled,
            "sms": self._sms_enabled,
            "push": self._push_enabled,
            "in_app": self._in_app_enabled
        }
        
        return channel_status.get(channel, False)
    
    async def _send_to_channel(
        self,
        channel: str,
        user_id: UUID,
        title: str,
        message: str,
        data: dict[str, Any] | None
    ) -> None:
        """Send notification through specific channel.
        
        Args:
            channel: Channel name
            user_id: User identifier
            title: Notification title
            message: Notification message
            data: Additional data
        """
        # In a real implementation, each channel would call its respective service
        # For now, we'll simulate the send with a small delay
        
        if channel == "email":
            await self._send_email(user_id, title, message, data)
        elif channel == "sms":
            await self._send_sms(user_id, title, message, data)
        elif channel == "push":
            await self._send_push(user_id, title, message, data)
        elif channel == "in_app":
            await self._send_in_app(user_id, title, message, data)
    
    async def _send_email(self, user_id: UUID, title: str, message: str, data: dict[str, Any] | None) -> None:
        """Send email notification."""
        # Simulate email send
        await asyncio.sleep(0.1)
        logger.debug(f"Email sent to user {user_id}: {title}")
    
    async def _send_sms(self, user_id: UUID, title: str, message: str, data: dict[str, Any] | None) -> None:
        """Send SMS notification."""
        # Simulate SMS send
        await asyncio.sleep(0.05)
        logger.debug(f"SMS sent to user {user_id}: {message}")
    
    async def _send_push(self, user_id: UUID, title: str, message: str, data: dict[str, Any] | None) -> None:
        """Send push notification."""
        # Simulate push send
        await asyncio.sleep(0.02)
        logger.debug(f"Push notification sent to user {user_id}: {title}")
    
    async def _send_in_app(self, user_id: UUID, title: str, message: str, data: dict[str, Any] | None) -> None:
        """Send in-app notification."""
        # Simulate in-app send (e.g., WebSocket or Redis pub/sub)
        await asyncio.sleep(0.01)
        logger.debug(f"In-app notification sent to user {user_id}: {title}")
    
    def get_notification_log(self) -> list[dict[str, Any]]:
        """Get notification log (for testing/debugging).
        
        Returns:
            List of sent notifications
        """
        return self._notification_log.copy()
    
    async def health_check(self) -> dict[str, bool]:
        """Check health of notification channels.
        
        Returns:
            Dictionary of channel health status
        """
        return {
            "email": self._email_enabled,
            "sms": self._sms_enabled,
            "push": self._push_enabled,
            "in_app": self._in_app_enabled
        }
