"""In-app notification channel adapter."""

import contextlib
from datetime import datetime
from typing import Any
from uuid import UUID

import aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.infrastructure.adapters.base import (
import json
import asyncio
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)


class InAppChannelAdapter(BaseChannelAdapter):
    """In-app notification channel adapter."""

    SUPPORTED_PROVIDERS = ["internal", "pusher", "socket.io"]

    def __init__(
        self,
        config,
        session: AsyncSession | None = None,
        redis_client: aioredis.Redis | None = None,
    ):
        """Initialize in-app channel adapter.

        Args:
            config: Channel configuration
            session: Optional database session for internal provider
            redis_client: Optional Redis client for real-time updates
        """
        super().__init__(config)
        self.session = session
        self.redis_client = redis_client

        # Initialize provider client
        if self.provider == "pusher":
            self._init_pusher()
        elif self.provider == "socket.io":
            self._init_socketio()

    def _validate_config(self) -> None:
        """Validate in-app channel configuration."""
        if self.provider not in self.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported in-app provider: {self.provider}")

        # Validate provider-specific settings
        if self.provider == "pusher":
            self._validate_pusher_config()
        elif self.provider == "socket.io":
            self._validate_socketio_config()

    def _validate_pusher_config(self) -> None:
        """Validate Pusher configuration."""
        required_settings = ["app_id", "cluster"]
        for setting in required_settings:
            if setting not in self.config.settings:
                raise ValueError(f"Pusher {setting} required")

        required_creds = ["key", "secret"]
        for cred in required_creds:
            if cred not in self.config.credentials:
                raise ValueError(f"Pusher {cred} required")

    def _validate_socketio_config(self) -> None:
        """Validate Socket.IO configuration."""
        if "server_url" not in self.config.settings:
            raise ValueError("Socket.IO server URL required")

    def _init_pusher(self) -> None:
        """Initialize Pusher client."""
        try:
            import pusher

            self._pusher_client = pusher.Pusher(
                app_id=self.config.settings["app_id"],
                key=self.config.credentials["key"],
                secret=self.config.credentials["secret"],
                cluster=self.config.settings["cluster"],
                ssl=self.config.settings.get("use_ssl", True),
            )
        except ImportError:
            raise ValueError("Pusher library not installed")

    def _init_socketio(self) -> None:
        """Initialize Socket.IO client."""
        # Socket.IO client initialization would go here
        self._socketio_url = self.config.settings["server_url"]

    async def send(self, notification: Notification) -> DeliveryResult:
        """Send in-app notification."""
        try:
            if self.provider == "internal":
                return await self._send_internal(notification)
            if self.provider == "pusher":
                return await self._send_pusher(notification)
            if self.provider == "socket.io":
                return await self._send_socketio(notification)
            raise ChannelAdapterError(
                f"Unsupported provider: {self.provider}", is_retryable=False
            )
        except ChannelAdapterError:
            raise
        except Exception as e:
            raise ChannelAdapterError(
                f"Failed to send in-app notification: {e!s}", is_retryable=True
            )

    async def _send_internal(self, notification: Notification) -> DeliveryResult:
        """Send notification using internal storage."""
        # Store notification in database (already done by repository)
        # Just mark as delivered for in-app notifications

        # Publish to Redis for real-time updates if available
        if self.redis_client:
            await self._publish_to_redis(notification)

        return DeliveryResult(
            status=DeliveryStatus.DELIVERED,
            provider_message_id=str(notification.id),
            provider_status="delivered",
            delivered_at=datetime.utcnow(),
            response_data={"method": "internal"},
        )

    async def _send_pusher(self, notification: Notification) -> DeliveryResult:
        """Send notification via Pusher."""
        try:
            # Prepare event data
            event_data = {
                "id": str(notification.id),
                "title": notification.content.subject or "Notification",
                "body": notification.content.body,
                "priority": notification.priority.level.value,
                "timestamp": datetime.utcnow().isoformat(),
                "metadata": notification.metadata,
            }

            # Channel name based on user ID
            channel_name = f"private-user-{notification.recipient_id}"

            # Trigger Pusher event
            result = self._pusher_client.trigger(
                channel_name, "notification", event_data
            )

            return DeliveryResult(
                status=DeliveryStatus.DELIVERED,
                provider_message_id=str(notification.id),
                provider_status="triggered",
                delivered_at=datetime.utcnow(),
                response_data={"pusher_result": result},
            )

        except Exception as e:
            raise ChannelAdapterError(f"Pusher error: {e!s}", is_retryable=True)

    async def _send_socketio(self, notification: Notification) -> DeliveryResult:
        """Send notification via Socket.IO."""
        # Socket.IO implementation would go here
        # This would emit an event to connected clients
        raise NotImplementedError("Socket.IO adapter not yet implemented")

    async def _publish_to_redis(self, notification: Notification) -> None:
        """Publish notification to Redis for real-time updates.

        Args:
            notification: Notification to publish
        """
        if not self.redis_client:
            return

        # Prepare notification data
        notification_data = {
            "id": str(notification.id),
            "recipient_id": str(notification.recipient_id),
            "title": notification.content.subject or "Notification",
            "body": notification.content.body,
            "priority": notification.priority.level.value,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": notification.metadata,
        }

        # Publish to user channel
        channel = f"notifications:user:{notification.recipient_id}"
        await self.redis_client.publish(channel, json.dumps(notification_data))

        # Also add to user's notification list
        list_key = f"notifications:list:{notification.recipient_id}"
        await self.redis_client.lpush(list_key, json.dumps(notification_data))

        # Trim list to keep only recent notifications
        await self.redis_client.ltrim(list_key, 0, 99)  # Keep last 100

        # Set expiry
        await self.redis_client.expire(list_key, 86400 * 7)  # 7 days

    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check in-app notification delivery status."""
        # In-app notifications are considered delivered immediately
        # Status checking could be implemented to check if user has read it
        return None

    async def validate_address(self, address: str) -> bool:
        """Validate in-app recipient address."""
        # For in-app, address should be a valid user ID (UUID)
        try:
            UUID(address)
            return True
        except ValueError:
            return False

    async def mark_as_read(self, notification_id: UUID, user_id: UUID) -> bool:
        """Mark an in-app notification as read.

        Args:
            notification_id: Notification ID
            user_id: User ID (for verification)

        Returns:
            True if marked successfully
        """
        # This would typically update the notification status
        # Implementation depends on the notification repository

        # Remove from Redis unread list if using Redis
        if self.redis_client:
            pass
            # This is simplified - in practice, you'd need to find and remove the specific item

        return True

    async def get_unread_count(self, user_id: UUID) -> int:
        """Get count of unread notifications for a user.

        Args:
            user_id: User ID

        Returns:
            Count of unread notifications
        """
        if self.redis_client:
            list_key = f"notifications:list:{user_id}"
            return await self.redis_client.llen(list_key)

        # Otherwise would query database
        return 0

    async def get_recent_notifications(
        self, user_id: UUID, limit: int = 20, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Get recent notifications for a user.

        Args:
            user_id: User ID
            limit: Maximum number to return
            offset: Number to skip

        Returns:
            List of notification data
        """
        notifications = []

        if self.redis_client:
            list_key = f"notifications:list:{user_id}"
            items = await self.redis_client.lrange(list_key, offset, offset + limit - 1)

            for item in items:
                with contextlib.suppress(Exception):
                    notifications.append(json.loads(item))

        return notifications

    async def subscribe_to_updates(
        self, user_id: UUID, callback: Any | None = None
    ) -> Any | None:
        """Subscribe to real-time notification updates.

        Args:
            user_id: User ID
            callback: Optional callback function

        Returns:
            Subscription handle or None
        """
        if self.redis_client:
            # Create pubsub instance
            pubsub = self.redis_client.pubsub()
            channel = f"notifications:user:{user_id}"
            await pubsub.subscribe(channel)

            return pubsub

        return None
