"""
Subscription Manager

Centralized management for all GraphQL subscriptions including:
- Connection pooling and load balancing
- Event publishing and distribution
- Health monitoring and metrics
- Connection cleanup and resource management
"""

import asyncio
import contextlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as redis

from app.core.cache import CacheManager
from app.core.logging import get_logger
from app.core.monitoring import metrics

from .base_subscription import SubscriptionContext, SubscriptionError

logger = get_logger(__name__)


@dataclass
class SubscriptionStats:
    """Statistics for subscription monitoring."""
    total_connections: int = 0
    active_connections: int = 0
    events_published: int = 0
    events_delivered: int = 0
    events_dropped: int = 0
    connection_errors: int = 0
    rate_limited_events: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ChannelStats:
    """Per-channel statistics."""
    channel_name: str
    subscriber_count: int = 0
    events_published: int = 0
    events_per_minute: float = 0.0
    last_event_time: datetime | None = None
    
    def update_event_rate(self, window_minutes: int = 5) -> None:
        """Update events per minute calculation."""
        if self.last_event_time:
            time_diff = (datetime.now(UTC) - self.last_event_time).total_seconds() / 60
            if time_diff > 0:
                self.events_per_minute = min(self.events_published / time_diff, 
                                           self.events_published / window_minutes)


class SubscriptionManager:
    """Centralized subscription management."""
    
    def __init__(
        self,
        cache_manager: CacheManager,
        redis_client: redis.Redis | None = None,
        connection_pool_size: int = 100,
        cleanup_interval: int = 300
    ):
        self._cache = cache_manager
        self._redis = redis_client or redis.from_url("redis://localhost:6379")
        self._logger = logger
        
        # Connection management
        self._connection_pool_size = connection_pool_size
        self._connections: dict[str, SubscriptionContext] = {}
        self._channel_connections: dict[str, set[str]] = defaultdict(set)
        
        # Statistics and monitoring
        self._stats = SubscriptionStats()
        self._channel_stats: dict[str, ChannelStats] = {}
        
        # Background tasks
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None
        self._is_running = False
        
        # Event batching
        self._event_batch_size = 50
        self._event_batch_timeout = 1.0  # seconds
        self._pending_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._batch_tasks: dict[str, asyncio.Task] = {}
    
    async def start(self) -> None:
        """Start the subscription manager."""
        if self._is_running:
            return
        
        self._is_running = True
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._stats_task = asyncio.create_task(self._stats_update_loop())
        
        self._logger.info("Subscription manager started")
    
    async def stop(self) -> None:
        """Stop the subscription manager."""
        if not self._is_running:
            return
        
        self._is_running = False
        
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
        
        if self._stats_task:
            self._stats_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stats_task
        
        # Cancel batch tasks
        for task in self._batch_tasks.values():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        
        # Close connections
        await self._close_all_connections()
        
        self._logger.info("Subscription manager stopped")
    
    async def register_connection(self, context: SubscriptionContext) -> None:
        """Register a new subscription connection."""
        if len(self._connections) >= self._connection_pool_size:
            raise SubscriptionError(
                f"Connection pool full (max: {self._connection_pool_size})",
                code="CONNECTION_POOL_FULL"
            )
        
        self._connections[context.connection_id] = context
        self._channel_connections[context.subscription_type].add(context.connection_id)
        
        # Update statistics
        self._stats.total_connections += 1
        self._stats.active_connections = len(self._connections)
        
        # Store in Redis for distributed environments
        await self._redis.hset(
            f"subscription:connection:{context.connection_id}",
            mapping={
                "user_id": str(context.user_id),
                "subscription_type": context.subscription_type,
                "created_at": context.created_at.isoformat(),
                "node_id": await self._get_node_id()
            }
        )
        
        # Set TTL
        await self._redis.expire(
            f"subscription:connection:{context.connection_id}",
            3600
        )
        
        # Track metrics
        metrics.subscription_connections_total.labels(
            subscription_type=context.subscription_type
        ).inc()
        
        self._logger.info(
            "Connection registered",
            connection_id=context.connection_id,
            user_id=str(context.user_id),
            subscription_type=context.subscription_type
        )
    
    async def unregister_connection(self, connection_id: str) -> None:
        """Unregister a subscription connection."""
        context = self._connections.get(connection_id)
        if not context:
            return
        
        # Remove from local storage
        del self._connections[connection_id]
        self._channel_connections[context.subscription_type].discard(connection_id)
        
        # Update statistics
        self._stats.active_connections = len(self._connections)
        
        # Remove from Redis
        await self._redis.delete(f"subscription:connection:{connection_id}")
        
        # Track metrics
        metrics.subscription_disconnections_total.labels(
            subscription_type=context.subscription_type
        ).inc()
        
        self._logger.info(
            "Connection unregistered",
            connection_id=connection_id,
            user_id=str(context.user_id),
            subscription_type=context.subscription_type
        )
    
    async def publish_event(
        self,
        channel: str,
        event: dict[str, Any],
        batch: bool = True
    ) -> None:
        """Publish event to subscription channel."""
        try:
            # Add metadata
            if "event_id" not in event:
                event["event_id"] = str(uuid4())
            
            if "timestamp" not in event:
                event["timestamp"] = datetime.now(UTC).isoformat()
            
            if "node_id" not in event:
                event["node_id"] = await self._get_node_id()
            
            if batch and len(self._pending_events[channel]) < self._event_batch_size:
                # Add to batch
                self._pending_events[channel].append(event)
                
                # Start batch timer if not already running
                if channel not in self._batch_tasks:
                    self._batch_tasks[channel] = asyncio.create_task(
                        self._flush_batch_after_timeout(channel)
                    )
            else:
                # Publish immediately
                await self._publish_event_immediate(channel, event)
            
            # Update statistics
            self._stats.events_published += 1
            
            # Update channel statistics
            if channel not in self._channel_stats:
                self._channel_stats[channel] = ChannelStats(channel_name=channel)
            
            channel_stat = self._channel_stats[channel]
            channel_stat.events_published += 1
            channel_stat.last_event_time = datetime.now(UTC)
            channel_stat.update_event_rate()
            
        except Exception as e:
            self._stats.connection_errors += 1
            self._logger.exception(
                "Failed to publish event",
                channel=channel,
                event=event,
                error=str(e)
            )
            raise
    
    async def _publish_event_immediate(
        self,
        channel: str,
        event: dict[str, Any]
    ) -> None:
        """Publish event immediately to Redis."""
        await self._redis.publish(
            f"subscription:{channel}",
            json.dumps(event, default=str)
        )
        
        # Track metrics
        metrics.subscription_events_published_total.labels(
            channel=channel,
            event_type=event.get("event_type", "unknown")
        ).inc()
    
    async def _flush_batch_after_timeout(self, channel: str) -> None:
        """Flush event batch after timeout."""
        await asyncio.sleep(self._event_batch_timeout)
        await self._flush_event_batch(channel)
    
    async def _flush_event_batch(self, channel: str) -> None:
        """Flush pending events for a channel."""
        if channel not in self._pending_events:
            return
        
        events = self._pending_events[channel]
        if not events:
            return
        
        # Clear pending events
        self._pending_events[channel] = []
        
        # Remove batch task
        if channel in self._batch_tasks:
            del self._batch_tasks[channel]
        
        try:
            # Create batch event
            batch_event = {
                "event_type": "batch",
                "events": events,
                "batch_size": len(events),
                "timestamp": datetime.now(UTC).isoformat(),
                "node_id": await self._get_node_id()
            }
            
            await self._publish_event_immediate(channel, batch_event)
            
            self._logger.debug(
                "Flushed event batch",
                channel=channel,
                batch_size=len(events)
            )
            
        except Exception as e:
            self._logger.exception(
                "Failed to flush event batch",
                channel=channel,
                batch_size=len(events),
                error=str(e)
            )
    
    async def get_connection_stats(self) -> SubscriptionStats:
        """Get current subscription statistics."""
        return self._stats
    
    async def get_channel_stats(self) -> dict[str, ChannelStats]:
        """Get per-channel statistics."""
        return self._channel_stats.copy()
    
    async def get_active_connections(
        self,
        subscription_type: str | None = None
    ) -> dict[str, SubscriptionContext]:
        """Get active connections, optionally filtered by type."""
        if subscription_type:
            return {
                conn_id: context
                for conn_id, context in self._connections.items()
                if context.subscription_type == subscription_type
            }
        return self._connections.copy()
    
    async def force_disconnect(
        self,
        connection_id: str | None = None,
        user_id: UUID | None = None,
        subscription_type: str | None = None
    ) -> int:
        """Force disconnect connections matching criteria."""
        connections_to_close = []
        
        for conn_id, context in self._connections.items():
            if connection_id and conn_id != connection_id:
                continue
            if user_id and context.user_id != user_id:
                continue
            if subscription_type and context.subscription_type != subscription_type:
                continue
            
            connections_to_close.append(conn_id)
        
        # Close connections
        for conn_id in connections_to_close:
            await self.unregister_connection(conn_id)
        
        self._logger.info(
            "Force disconnected connections",
            count=len(connections_to_close),
            connection_id=connection_id,
            user_id=str(user_id) if user_id else None,
            subscription_type=subscription_type
        )
        
        return len(connections_to_close)
    
    async def _cleanup_loop(self) -> None:
        """Background task for connection cleanup."""
        while self._is_running:
            try:
                await self._cleanup_stale_connections()
                await asyncio.sleep(self._cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.exception("Error in cleanup loop", error=str(e))
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _cleanup_stale_connections(self) -> None:
        """Clean up stale connections."""
        now = datetime.now(UTC)
        stale_connections = []
        
        for conn_id, context in self._connections.items():
            # Check if connection is stale (inactive for 30 minutes)
            if (now - context.last_activity).total_seconds() > 1800:
                stale_connections.append(conn_id)
        
        # Remove stale connections
        for conn_id in stale_connections:
            await self.unregister_connection(conn_id)
        
        if stale_connections:
            self._logger.info(
                "Cleaned up stale connections",
                count=len(stale_connections)
            )
    
    async def _stats_update_loop(self) -> None:
        """Background task for updating statistics."""
        while self._is_running:
            try:
                await self._update_stats()
                await asyncio.sleep(60)  # Update every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.exception("Error in stats update loop", error=str(e))
                await asyncio.sleep(60)
    
    async def _update_stats(self) -> None:
        """Update subscription statistics."""
        self._stats.active_connections = len(self._connections)
        self._stats.last_updated = datetime.now(UTC)
        
        # Update channel subscriber counts
        for channel, connections in self._channel_connections.items():
            if channel in self._channel_stats:
                self._channel_stats[channel].subscriber_count = len(connections)
        
        # Store stats in cache for monitoring
        await self._cache.set(
            "subscription:stats",
            {
                "total_connections": self._stats.total_connections,
                "active_connections": self._stats.active_connections,
                "events_published": self._stats.events_published,
                "events_delivered": self._stats.events_delivered,
                "events_dropped": self._stats.events_dropped,
                "connection_errors": self._stats.connection_errors,
                "rate_limited_events": self._stats.rate_limited_events,
                "last_updated": self._stats.last_updated.isoformat()
            },
            ttl=300
        )
    
    async def _close_all_connections(self) -> None:
        """Close all active connections."""
        connection_ids = list(self._connections.keys())
        for conn_id in connection_ids:
            await self.unregister_connection(conn_id)
    
    async def _get_node_id(self) -> str:
        """Get unique node identifier for distributed environments."""
        # This could be improved with actual node discovery
        return f"node-{id(self)}"
    
    async def health_check(self) -> dict[str, Any]:
        """Perform health check on subscription manager."""
        try:
            # Test Redis connection
            await self._redis.ping()
            redis_healthy = True
        except Exception:
            redis_healthy = False
        
        return {
            "status": "healthy" if redis_healthy else "unhealthy",
            "redis_connected": redis_healthy,
            "active_connections": len(self._connections),
            "total_channels": len(self._channel_stats),
            "uptime_seconds": (
                datetime.now(UTC) - self._stats.last_updated
            ).total_seconds(),
            "events_published": self._stats.events_published,
            "events_delivered": self._stats.events_delivered
        }