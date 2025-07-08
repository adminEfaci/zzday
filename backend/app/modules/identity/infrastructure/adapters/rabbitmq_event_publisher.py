"""
RabbitMQ Event Publisher Adapter

Production-ready implementation of IEventPublisherPort using RabbitMQ.
"""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import (
    IEventPublisherPort,
)


class RabbitMQEventPublisher(IEventPublisherPort):
    """RabbitMQ implementation of event publisher port."""

    def __init__(
        self,
        connection,  # aio_pika.Connection
        exchange_name: str = "identity_events",
        routing_key_prefix: str = "identity",
    ):
        """Initialize RabbitMQ event publisher.

        Args:
            connection: aio_pika Connection instance
            exchange_name: Exchange name for events
            routing_key_prefix: Prefix for routing keys
        """
        self._connection = connection
        self._exchange_name = exchange_name
        self._routing_key_prefix = routing_key_prefix
        self._channel = None
        self._exchange = None

    async def _ensure_channel(self):
        """Ensure channel and exchange are initialized."""
        if not self._channel:
            self._channel = await self._connection.channel()
            self._exchange = await self._channel.declare_exchange(
                self._exchange_name, durable=True
            )

    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """Publish user registered event."""
        await self._publish_event(
            event_type="user.registered",
            data=user_data,
            user_id=user_data.get("id"),
        )

    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """Publish user activated event."""
        await self._publish_event(
            event_type="user.activated",
            data=user_data,
            user_id=user_data.get("id"),
        )

    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """Publish user deactivated event."""
        await self._publish_event(
            event_type="user.deactivated",
            data=user_data,
            user_id=user_data.get("id"),
        )

    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """Publish profile completed event."""
        await self._publish_event(
            event_type="user.profile_completed",
            data=user_data,
            user_id=user_data.get("id"),
        )

    async def publish_security_alert(
        self, user_id: UUID, alert_data: dict[str, Any]
    ) -> None:
        """Publish security alert event."""
        await self._publish_event(
            event_type="security.alert",
            data=alert_data,
            user_id=user_id,
            priority=10,  # High priority
        )

    async def publish_password_changed(
        self, user_id: UUID, change_context: dict[str, Any]
    ) -> None:
        """Publish password changed event."""
        await self._publish_event(
            event_type="user.password_changed",
            data=change_context,
            user_id=user_id,
        )

    async def _publish_event(
        self,
        event_type: str,
        data: dict[str, Any],
        user_id: UUID | None = None,
        priority: int = 0,
    ) -> None:
        """Publish event to RabbitMQ."""
        try:
            await self._ensure_channel()

            event = {
                "id": str(uuid4()),
                "type": event_type,
                "timestamp": datetime.now(UTC).isoformat(),
                "version": "1.0",
                "source": "identity-service",
                "user_id": str(user_id) if user_id else None,
                "data": data,
                "metadata": {
                    "correlation_id": str(uuid4()),
                    "service": "identity",
                },
            }

            routing_key = f"{self._routing_key_prefix}.{event_type}"
            message_body = json.dumps(event, default=str).encode()

            await self._exchange.publish(
                message=message_body,
                routing_key=routing_key,
                properties={
                    "content_type": "application/json",
                    "message_id": event["id"],
                    "timestamp": int(datetime.now(UTC).timestamp()),
                    "priority": priority,
                },
            )

            logger.info(
                f"Event published: {event_type} (ID: {event['id']}, "
                f"User: {user_id or 'N/A'})"
            )

        except Exception as e:
            logger.error(f"Failed to publish event {event_type}: {e}")
            raise