"""
Event Publisher Adapter Implementation

Production-ready event publishing implementation using message broker.
"""

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import (
    IEventPublisherPort,
)

logger = logging.getLogger(__name__)


class EventPublisherAdapter(IEventPublisherPort):
    """Production event publisher implementation."""
    
    def __init__(
        self,
        message_broker,  # Could be RabbitMQ, Kafka, etc.
        topic_prefix: str = "identity",
        enable_dead_letter: bool = True
    ):
        """Initialize event publisher adapter.
        
        Args:
            message_broker: Message broker client (async)
            topic_prefix: Prefix for all event topics
            enable_dead_letter: Enable dead letter queue for failed events
        """
        self._broker = message_broker
        self._topic_prefix = topic_prefix
        self._enable_dead_letter = enable_dead_letter
    
    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """Publish user registered event to message broker."""
        event = self._create_event(
            event_type="user.registered",
            data=user_data,
            user_id=user_data.get("id")
        )
        await self._publish_event("user.registered", event)
    
    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """Publish user activated event to message broker."""
        event = self._create_event(
            event_type="user.activated",
            data=user_data,
            user_id=user_data.get("id")
        )
        await self._publish_event("user.activated", event)
    
    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """Publish user deactivated event to message broker."""
        event = self._create_event(
            event_type="user.deactivated",
            data=user_data,
            user_id=user_data.get("id")
        )
        await self._publish_event("user.deactivated", event)
    
    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """Publish profile completed event to message broker."""
        event = self._create_event(
            event_type="user.profile_completed",
            data=user_data,
            user_id=user_data.get("id")
        )
        await self._publish_event("user.profile_completed", event)
    
    async def publish_security_alert(
        self,
        user_id: UUID,
        alert_data: dict[str, Any]
    ) -> None:
        """Publish security alert event to message broker."""
        event = self._create_event(
            event_type="security.alert",
            data=alert_data,
            user_id=user_id
        )
        await self._publish_event("security.alert", event, priority="high")
    
    async def publish_password_changed(
        self,
        user_id: UUID,
        change_context: dict[str, Any]
    ) -> None:
        """Publish password changed event to message broker."""
        event = self._create_event(
            event_type="user.password_changed",
            data=change_context,
            user_id=user_id
        )
        await self._publish_event("user.password_changed", event)
    
    def _create_event(
        self,
        event_type: str,
        data: dict[str, Any],
        user_id: UUID | None = None
    ) -> dict[str, Any]:
        """Create standardized event structure."""
        return {
            "id": str(uuid4()),
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "1.0",
            "source": "identity-service",
            "user_id": str(user_id) if user_id else None,
            "data": data,
            "metadata": {
                "correlation_id": str(uuid4()),
                "created_at": datetime.now(UTC).isoformat(),
                "service": "identity"
            }
        }
    
    async def _publish_event(
        self,
        event_type: str,
        event: dict[str, Any],
        priority: str = "normal"
    ) -> None:
        """Publish event to message broker with error handling."""
        try:
            topic = f"{self._topic_prefix}.{event_type}"
            
            # Serialize event data
            event_payload = json.dumps(event, default=str)
            
            # Publish to message broker
            await self._broker.publish(
                topic=topic,
                message=event_payload,
                priority=priority,
                headers={
                    "event_type": event_type,
                    "event_id": event["id"],
                    "timestamp": event["timestamp"],
                    "user_id": event.get("user_id")
                }
            )
            
            logger.info(
                f"Event published successfully: {event_type} "
                f"(ID: {event['id']}, User: {event.get('user_id', 'N/A')})"
            )
            
        except Exception as e:
            logger.error(
                f"Failed to publish event {event_type} "
                f"(ID: {event['id']}): {e}"
            )
            
            # Send to dead letter queue if enabled
            if self._enable_dead_letter:
                await self._send_to_dead_letter(event, str(e))
            
            # Re-raise to allow calling code to handle
            raise
    
    async def _send_to_dead_letter(
        self,
        event: dict[str, Any],
        error_message: str
    ) -> None:
        """Send failed event to dead letter queue."""
        try:
            dead_letter_event = {
                **event,
                "failure_reason": error_message,
                "failed_at": datetime.now(UTC).isoformat(),
                "retry_count": event.get("retry_count", 0) + 1
            }
            
            await self._broker.publish(
                topic=f"{self._topic_prefix}.dead_letter",
                message=json.dumps(dead_letter_event, default=str),
                priority="low"
            )
            
            logger.info(f"Event sent to dead letter queue: {event['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send event to dead letter queue: {e}")


class InMemoryEventPublisher(IEventPublisherPort):
    """In-memory event publisher for testing and development."""
    
    def __init__(self):
        """Initialize in-memory event store."""
        self.published_events: list[dict[str, Any]] = []
        self._event_handlers: dict[str, list] = {}
    
    async def publish_user_registered(self, user_data: dict[str, Any]) -> None:
        """Store user registered event in memory."""
        event = self._create_event("user.registered", user_data)
        await self._store_event(event)
    
    async def publish_user_activated(self, user_data: dict[str, Any]) -> None:
        """Store user activated event in memory."""
        event = self._create_event("user.activated", user_data)
        await self._store_event(event)
    
    async def publish_user_deactivated(self, user_data: dict[str, Any]) -> None:
        """Store user deactivated event in memory."""
        event = self._create_event("user.deactivated", user_data)
        await self._store_event(event)
    
    async def publish_profile_completed(self, user_data: dict[str, Any]) -> None:
        """Store profile completed event in memory."""
        event = self._create_event("user.profile_completed", user_data)
        await self._store_event(event)
    
    async def publish_security_alert(
        self,
        user_id: UUID,
        alert_data: dict[str, Any]
    ) -> None:
        """Store security alert event in memory."""
        event = self._create_event("security.alert", alert_data, user_id)
        await self._store_event(event)
    
    async def publish_password_changed(
        self,
        user_id: UUID,
        change_context: dict[str, Any]
    ) -> None:
        """Store password changed event in memory."""
        event = self._create_event("user.password_changed", change_context, user_id)
        await self._store_event(event)
    
    def _create_event(
        self,
        event_type: str,
        data: dict[str, Any],
        user_id: UUID | None = None
    ) -> dict[str, Any]:
        """Create event for in-memory storage."""
        return {
            "id": str(uuid4()),
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "user_id": str(user_id) if user_id else None,
            "data": data
        }
    
    async def _store_event(self, event: dict[str, Any]) -> None:
        """Store event in memory and trigger handlers."""
        self.published_events.append(event)
        
        # Trigger any registered handlers
        event_type = event["type"]
        if event_type in self._event_handlers:
            for handler in self._event_handlers[event_type]:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Event handler failed for {event_type}: {e}")
    
    def register_handler(self, event_type: str, handler_func) -> None:
        """Register event handler for testing."""
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler_func)
    
    def clear_events(self) -> None:
        """Clear all stored events (for testing)."""
        self.published_events.clear()
    
    def get_events_by_type(self, event_type: str) -> list[dict[str, Any]]:
        """Get events by type (for testing)."""
        return [e for e in self.published_events if e["type"] == event_type]
    
    def get_events_by_user(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get events by user ID (for testing)."""
        user_id_str = str(user_id)
        return [e for e in self.published_events if e.get("user_id") == user_id_str]