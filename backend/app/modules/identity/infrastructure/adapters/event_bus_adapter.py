"""
Event Bus Adapter

Generic event bus implementation supporting multiple backends.
Provides unified interface for publishing domain events.
"""

import asyncio
import json
from datetime import datetime, UTC
from typing import Any
from uuid import uuid4

from redis.asyncio import Redis

from app.core.logging import logger
from app.modules.identity.application.contracts.ports import IEventBus


class RedisEventBusAdapter(IEventBus):
    """Redis-based implementation of generic event bus."""
    
    def __init__(
        self, 
        redis_client: Redis,
        channel: str = "domain:events",
        enable_persistence: bool = True
    ):
        """Initialize Redis event bus adapter.
        
        Args:
            redis_client: Redis async client instance
            channel: Default channel for events
            enable_persistence: Whether to persist events to a stream
        """
        self._redis = redis_client
        self._channel = channel
        self._enable_persistence = enable_persistence
        self._stream_key = "events:stream"
    
    async def publish(self, event: Any) -> None:
        """Publish single domain event.
        
        Args:
            event: Domain event to publish
        """
        try:
            # Create event envelope
            envelope = self._create_event_envelope(event)
            
            # Serialize event
            message = json.dumps(envelope, default=str)
            
            # Publish to pub/sub
            await self._redis.publish(self._channel, message)
            
            # Persist to stream if enabled
            if self._enable_persistence:
                await self._persist_event(envelope)
            
            logger.debug(
                f"Published event {type(event).__name__}",
                event_type=type(event).__name__,
                event_id=envelope["event_id"]
            )
            
        except Exception as e:
            logger.error(
                f"Failed to publish event {type(event).__name__}: {e}",
                event_type=type(event).__name__,
                error=str(e)
            )
            # Don't raise - event publishing should not break the application
    
    async def publish_batch(self, events: list[Any]) -> None:
        """Publish multiple events atomically.
        
        Args:
            events: List of domain events to publish
        """
        if not events:
            return
        
        try:
            # Create envelopes for all events
            envelopes = [self._create_event_envelope(event) for event in events]
            
            # Use pipeline for atomic operation
            async with self._redis.pipeline() as pipe:
                for envelope in envelopes:
                    message = json.dumps(envelope, default=str)
                    pipe.publish(self._channel, message)
                    
                    if self._enable_persistence:
                        pipe.xadd(
                            self._stream_key,
                            {
                                "event": message,
                                "type": envelope["event_type"],
                                "timestamp": envelope["timestamp"]
                            }
                        )
                
                await pipe.execute()
            
            logger.info(
                f"Published batch of {len(events)} events",
                event_count=len(events),
                event_types=[type(e).__name__ for e in events]
            )
            
        except Exception as e:
            logger.error(
                f"Failed to publish event batch: {e}",
                event_count=len(events),
                error=str(e)
            )
            # Don't raise - event publishing should not break the application
    
    def _create_event_envelope(self, event: Any) -> dict[str, Any]:
        """Create standardized event envelope.
        
        Args:
            event: Domain event
            
        Returns:
            Event envelope with metadata
        """
        # Extract event data
        event_data = {}
        if hasattr(event, "__dict__"):
            event_data = event.__dict__.copy()
        elif hasattr(event, "dict"):
            event_data = event.dict()
        
        # Remove internal fields
        event_data = {k: v for k, v in event_data.items() if not k.startswith("_")}
        
        return {
            "event_id": str(uuid4()),
            "event_type": type(event).__name__,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": event_data,
            "metadata": {
                "source": "identity_module",
                "version": "1.0",
                "correlation_id": getattr(event, "correlation_id", None),
                "causation_id": getattr(event, "causation_id", None),
                "user_id": getattr(event, "user_id", None)
            }
        }
    
    async def _persist_event(self, envelope: dict[str, Any]) -> None:
        """Persist event to Redis stream.
        
        Args:
            envelope: Event envelope to persist
        """
        try:
            await self._redis.xadd(
                self._stream_key,
                {
                    "event": json.dumps(envelope, default=str),
                    "type": envelope["event_type"],
                    "timestamp": envelope["timestamp"]
                },
                maxlen=10000  # Keep last 10k events
            )
        except Exception as e:
            logger.warning(f"Failed to persist event: {e}")
    
    async def health_check(self) -> bool:
        """Check if event bus is healthy.
        
        Returns:
            True if Redis is accessible
        """
        try:
            await self._redis.ping()
            return True
        except Exception as e:
            logger.error(f"Event bus health check failed: {e}")
            return False
    
    async def get_stats(self) -> dict[str, Any]:
        """Get event bus statistics.
        
        Returns:
            Dictionary containing event bus stats
        """
        try:
            # Get stream info if persistence is enabled
            stream_length = 0
            if self._enable_persistence:
                stream_info = await self._redis.xinfo_stream(self._stream_key)
                stream_length = stream_info.get("length", 0)
            
            # Get pub/sub stats
            pubsub_stats = await self._redis.pubsub_numsub(self._channel)
            subscribers = pubsub_stats[0][1] if pubsub_stats else 0
            
            return {
                "connected": True,
                "channel": self._channel,
                "subscribers": subscribers,
                "persistence_enabled": self._enable_persistence,
                "persisted_events": stream_length
            }
        except Exception as e:
            logger.error(f"Failed to get event bus stats: {e}")
            return {
                "connected": False,
                "error": str(e)
            }


class InMemoryEventBusAdapter(IEventBus):
    """In-memory implementation for testing and development."""
    
    def __init__(self):
        """Initialize in-memory event bus."""
        self._handlers: dict[type, list[Any]] = {}
        self._published_events: list[Any] = []
    
    async def publish(self, event: Any) -> None:
        """Publish single domain event.
        
        Args:
            event: Domain event to publish
        """
        self._published_events.append(event)
        
        # Call registered handlers
        event_type = type(event)
        if event_type in self._handlers:
            for handler in self._handlers[event_type]:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Handler failed for event {event_type.__name__}: {e}")
    
    async def publish_batch(self, events: list[Any]) -> None:
        """Publish multiple events.
        
        Args:
            events: List of domain events to publish
        """
        for event in events:
            await self.publish(event)
    
    def register_handler(self, event_type: type, handler: Any) -> None:
        """Register event handler for testing.
        
        Args:
            event_type: Type of event to handle
            handler: Async callable to handle event
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    def get_published_events(self) -> list[Any]:
        """Get all published events (for testing).
        
        Returns:
            List of published events
        """
        return self._published_events.copy()
    
    def clear(self) -> None:
        """Clear all published events and handlers."""
        self._published_events.clear()
        self._handlers.clear()