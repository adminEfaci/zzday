"""
Event Publisher Adapter

Redis-based implementation of the event publisher port interface.
Publishes domain events to Redis pub/sub for real-time event distribution.
"""

import json
from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from redis.asyncio import Redis

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import IEventPublisherPort


class EventPublisherAdapter(IEventPublisherPort):
    """Redis pub/sub implementation of event publisher port."""
    
    def __init__(self, redis_client: Redis, channel_prefix: str = "identity:events:"):
        """Initialize event publisher adapter.
        
        Args:
            redis_client: Redis async client instance
            channel_prefix: Prefix for event channels
        """
        self._redis = redis_client
        self._channel_prefix = channel_prefix
    
    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """Publish user registered event.
        
        Args:
            user_data: User registration data
        """
        await self._publish_event(
            event_type="user.registered",
            data=user_data,
            channel="user"
        )
    
    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """Publish user activated event.
        
        Args:
            user_data: User activation data
        """
        await self._publish_event(
            event_type="user.activated",
            data=user_data,
            channel="user"
        )
    
    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """Publish user deactivated event.
        
        Args:
            user_data: User deactivation data
        """
        await self._publish_event(
            event_type="user.deactivated",
            data=user_data,
            channel="user"
        )
    
    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """Publish profile completed event.
        
        Args:
            user_data: Profile completion data
        """
        await self._publish_event(
            event_type="profile.completed",
            data=user_data,
            channel="profile"
        )
    
    async def publish_security_alert(
        self,
        user_id: UUID,
        alert_data: dict[str, Any]
    ) -> None:
        """Publish security alert event.
        
        Args:
            user_id: User identifier
            alert_data: Alert details
        """
        await self._publish_event(
            event_type="security.alert",
            data={
                "user_id": str(user_id),
                **alert_data
            },
            channel="security"
        )
    
    async def publish_password_changed(
        self,
        user_id: UUID,
        change_context: dict[str, Any]
    ) -> None:
        """Publish password changed event.
        
        Args:
            user_id: User identifier
            change_context: Change context (forced, expired, etc.)
        """
        await self._publish_event(
            event_type="password.changed",
            data={
                "user_id": str(user_id),
                **change_context
            },
            channel="security"
        )
    
    async def _publish_event(
        self,
        event_type: str,
        data: dict[str, Any],
        channel: str
    ) -> None:
        """Publish event to Redis channel.
        
        Args:
            event_type: Type of event
            data: Event data payload
            channel: Channel name (without prefix)
        """
        try:
            # Create event envelope
            event = {
                "event_type": event_type,
                "timestamp": datetime.now(UTC).isoformat(),
                "data": data,
                "source": "identity_module",
                "version": "1.0"
            }
            
            # Serialize event
            message = json.dumps(event, default=str)
            
            # Publish to channel
            full_channel = f"{self._channel_prefix}{channel}"
            await self._redis.publish(full_channel, message)
            
            logger.info(
                f"Published event {event_type} to channel {full_channel}",
                event_type=event_type,
                channel=full_channel,
                data_keys=list(data.keys()) if data else []
            )
            
        except Exception as e:
            logger.error(
                f"Failed to publish event {event_type}: {e}",
                event_type=event_type,
                channel=channel,
                error=str(e)
            )
            # Don't raise - event publishing should not break the application
    
    async def health_check(self) -> bool:
        """Check if event publisher is healthy.
        
        Returns:
            True if Redis pub/sub is accessible
        """
        try:
            # Test by publishing to a test channel
            test_channel = f"{self._channel_prefix}health_check"
            await self._redis.publish(test_channel, "ping")
            return True
        except Exception as e:
            logger.error(f"Event publisher health check failed: {e}")
            return False
    
    async def get_stats(self) -> dict[str, Any]:
        """Get event publishing statistics.
        
        Returns:
            Dictionary containing pub/sub statistics
        """
        try:
            # Get Redis pub/sub stats
            info = await self._redis.pubsub_channels()
            
            return {
                "connected": True,
                "active_channels": len(info),
                "channel_prefix": self._channel_prefix
            }
        except Exception as e:
            logger.error(f"Failed to get event publisher stats: {e}")
            return {
                "connected": False,
                "error": str(e)
            }