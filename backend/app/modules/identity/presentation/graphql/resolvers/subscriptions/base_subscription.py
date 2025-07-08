"""
Base subscription resolver with common infrastructure.

Provides WebSocket connection management, authorization, rate limiting,
and monitoring capabilities for all subscription resolvers.
"""

import json
from collections import defaultdict
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as redis
from strawberry.types import Info

from app.core.cache import CacheManager
from app.core.logging import get_logger
from app.core.monitoring import metrics
from app.modules.identity.domain.errors import (
    AuthenticationError,
    AuthorizationError,
)

from ..middleware import SecurityContext

logger = get_logger(__name__)


class SubscriptionError(Exception):
    """Base exception for subscription-related errors."""
    
    def __init__(self, message: str, code: str = "SUBSCRIPTION_ERROR", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ConnectionClosedError(SubscriptionError):
    """Raised when subscription connection is closed."""
    
    def __init__(self, connection_id: str):
        super().__init__(
            f"Connection {connection_id} is closed",
            code="CONNECTION_CLOSED"
        )
        self.details["connection_id"] = connection_id


class RateLimitExceededError(SubscriptionError):
    """Raised when subscription rate limit is exceeded."""
    
    def __init__(self, limit: int, window: int):
        super().__init__(
            f"Rate limit exceeded: {limit} events per {window}s",
            code="RATE_LIMIT_EXCEEDED"
        )
        self.details["limit"] = limit
        self.details["window"] = window


@dataclass
class SubscriptionFilter:
    """Filter criteria for subscription events."""
    user_ids: set[UUID] = field(default_factory=set)
    event_types: set[str] = field(default_factory=set)
    severity_levels: set[str] = field(default_factory=set)
    source_ips: set[str] = field(default_factory=set)
    custom_filters: dict[str, Any] = field(default_factory=dict)
    
    def matches(self, event: dict[str, Any]) -> bool:
        """Check if event matches filter criteria."""
        # User ID filter
        if self.user_ids and event.get("user_id") and UUID(event["user_id"]) not in self.user_ids:
            return False
        
        # Event type filter
        if self.event_types and event.get("event_type") and event["event_type"] not in self.event_types:
            return False
        
        # Severity filter
        if self.severity_levels and event.get("severity") and event["severity"] not in self.severity_levels:
            return False
        
        # Source IP filter
        if self.source_ips and event.get("source_ip") and event["source_ip"] not in self.source_ips:
            return False
        
        # Custom filters
        for key, expected_value in self.custom_filters.items():
            if event.get(key) != expected_value:
                return False
        
        return True


@dataclass
class RateLimitConfig:
    """Rate limiting configuration for subscriptions."""
    max_events: int = 100
    window_seconds: int = 60
    burst_limit: int = 20
    burst_window_seconds: int = 5
    
    def is_rate_limited(self, event_count: int, window_start: datetime) -> bool:
        """Check if rate limit is exceeded."""
        now = datetime.now(UTC)
        window_duration = now - window_start
        
        # Check main rate limit
        if window_duration.total_seconds() <= self.window_seconds and event_count >= self.max_events:
            return True
        
        # Check burst limit (more restrictive short-term limit)
        return window_duration.total_seconds() <= self.burst_window_seconds and event_count >= self.burst_limit


@dataclass
class SubscriptionContext:
    """Context for subscription connections."""
    connection_id: str
    user_id: UUID
    security_context: SecurityContext
    subscription_type: str
    filters: SubscriptionFilter
    rate_limit: RateLimitConfig
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_count: int = 0
    rate_limit_window_start: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseSubscriptionResolver:
    """Base class for all subscription resolvers."""
    
    def __init__(
        self,
        cache_manager: CacheManager,
        redis_client: redis.Redis | None = None
    ):
        self._cache = cache_manager
        self._redis = redis_client or redis.from_url("redis://localhost:6379")
        self._logger = logger
        self._connections: dict[str, SubscriptionContext] = {}
        self._subscription_channels: dict[str, set[str]] = defaultdict(set)
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = datetime.now(UTC)
        
        # Monitoring
        self._metrics_labels = {
            "resolver_type": self.__class__.__name__
        }
    
    async def _authenticate_connection(self, info: Info) -> SecurityContext:
        """Authenticate WebSocket connection."""
        security_context = getattr(info.context, 'security_context', None)
        
        if not security_context or not security_context.is_authenticated():
            raise AuthenticationError(
                "Authentication required for subscriptions",
                user_message="Please log in to access real-time updates"
            )
        
        return security_context
    
    def _authorize_subscription(
        self,
        security_context: SecurityContext,
        subscription_type: str,
        required_permissions: list[str] | None = None
    ) -> None:
        """Authorize subscription access."""
        # Check general subscription permission
        if not security_context.has_permission("subscription:access"):
            raise AuthorizationError(
                "Subscription access denied",
                user_message="You don't have permission to access real-time updates"
            )
        
        # Check specific permissions if provided
        if required_permissions and not security_context.has_any_permission(required_permissions):
            raise AuthorizationError(
                f"Insufficient permissions for {subscription_type}",
                user_message="You don't have permission to access this subscription"
            )
        
        # High-security subscriptions require MFA
        high_security_types = ["admin", "security", "audit"]
        if any(hs_type in subscription_type.lower() for hs_type in high_security_types) and not security_context.mfa_verified:
            raise AuthorizationError(
                "MFA required for security subscriptions",
                user_message="Multi-factor authentication required for this subscription"
            )
    
    def _create_connection_context(
        self,
        security_context: SecurityContext,
        subscription_type: str,
        filters: SubscriptionFilter = None,
        rate_limit: RateLimitConfig = None
    ) -> SubscriptionContext:
        """Create subscription connection context."""
        connection_id = str(uuid4())
        
        return SubscriptionContext(
            connection_id=connection_id,
            user_id=security_context.user_id,
            security_context=security_context,
            subscription_type=subscription_type,
            filters=filters or SubscriptionFilter(),
            rate_limit=rate_limit or RateLimitConfig(),
            metadata={
                "user_agent": security_context.user_agent,
                "ip_address": security_context.ip_address,
                "correlation_id": security_context.correlation_id
            }
        )
    
    async def _register_connection(self, context: SubscriptionContext) -> None:
        """Register new subscription connection."""
        self._connections[context.connection_id] = context
        
        # Register with Redis for distributed subscriptions
        channel_key = f"subscription:{context.subscription_type}"
        self._subscription_channels[channel_key].add(context.connection_id)
        
        await self._redis.sadd(
            f"connections:{channel_key}",
            context.connection_id
        )
        
        # Store connection metadata
        await self._redis.hset(
            f"connection:{context.connection_id}",
            mapping={
                "user_id": str(context.user_id),
                "subscription_type": context.subscription_type,
                "created_at": context.created_at.isoformat(),
                "filters": json.dumps(context.filters.__dict__, default=str),
                "rate_limit": json.dumps(context.rate_limit.__dict__)
            }
        )
        
        # Set TTL for connection metadata
        await self._redis.expire(f"connection:{context.connection_id}", 3600)
        
        # Track metrics
        metrics.subscription_connections.labels(
            subscription_type=context.subscription_type,
            **self._metrics_labels
        ).inc()
        
        self._logger.info(
            "Subscription connection registered",
            connection_id=context.connection_id,
            user_id=str(context.user_id),
            subscription_type=context.subscription_type
        )
    
    async def _unregister_connection(self, connection_id: str) -> None:
        """Unregister subscription connection."""
        context = self._connections.get(connection_id)
        if not context:
            return
        
        # Remove from local storage
        del self._connections[connection_id]
        
        # Remove from Redis
        channel_key = f"subscription:{context.subscription_type}"
        self._subscription_channels[channel_key].discard(connection_id)
        
        await self._redis.srem(f"connections:{channel_key}", connection_id)
        await self._redis.delete(f"connection:{connection_id}")
        
        # Update context
        context.is_active = False
        
        # Track metrics
        metrics.subscription_connections.labels(
            subscription_type=context.subscription_type,
            **self._metrics_labels
        ).dec()
        
        metrics.subscription_disconnections.labels(
            subscription_type=context.subscription_type,
            **self._metrics_labels
        ).inc()
        
        self._logger.info(
            "Subscription connection unregistered",
            connection_id=connection_id,
            user_id=str(context.user_id) if context else None,
            subscription_type=context.subscription_type if context else None
        )
    
    async def _check_rate_limit(self, context: SubscriptionContext) -> None:
        """Check rate limiting for subscription events."""
        now = datetime.now(UTC)
        
        # Reset window if needed
        if (now - context.rate_limit_window_start).total_seconds() > context.rate_limit.window_seconds:
            context.event_count = 0
            context.rate_limit_window_start = now
        
        # Check rate limit
        if context.rate_limit.is_rate_limited(
            context.event_count, context.rate_limit_window_start
        ):
            metrics.subscription_rate_limited.labels(
                subscription_type=context.subscription_type,
                **self._metrics_labels
            ).inc()
            
            raise RateLimitExceededError(
                context.rate_limit.max_events,
                context.rate_limit.window_seconds
            )
        
        context.event_count += 1
        context.last_activity = now
    
    async def _should_deliver_event(
        self,
        context: SubscriptionContext,
        event: dict[str, Any]
    ) -> bool:
        """Check if event should be delivered to connection."""
        if not context.is_active:
            return False
        
        # Check filters
        if not context.filters.matches(event):
            return False
        
        # Check authorization for specific event
        return await self._authorize_event_access(context.security_context, event)
    
    async def _authorize_event_access(
        self,
        security_context: SecurityContext,
        event: dict[str, Any]
    ) -> bool:
        """Check if user can access specific event."""
        # Users can always see their own events
        event_user_id = event.get("user_id")
        if event_user_id and UUID(event_user_id) == security_context.user_id:
            return True
        
        # Admin users can see all events
        if security_context.has_role("admin"):
            return True
        
        # Security team can see security events
        if event.get("event_type", "").startswith("security"):
            return security_context.has_permission("security:view")
        
        # Audit team can see audit events
        if event.get("event_type", "").startswith("audit"):
            return security_context.has_permission("audit:view")
        
        # Default deny for other users' events
        return False
    
    async def _publish_event(
        self,
        channel: str,
        event: dict[str, Any]
    ) -> None:
        """Publish event to subscription channel."""
        try:
            # Add timestamp if not present
            if "timestamp" not in event:
                event["timestamp"] = datetime.now(UTC).isoformat()
            
            # Publish to Redis
            await self._redis.publish(
                f"subscription:{channel}",
                json.dumps(event, default=str)
            )
            
            # Track metrics
            metrics.subscription_events_published.labels(
                channel=channel,
                event_type=event.get("event_type", "unknown"),
                **self._metrics_labels
            ).inc()
            
        except Exception:
            self._logger.exception(
                "Failed to publish subscription event",
                channel=channel,
                event=event
            )
            raise
    
    async def _cleanup_stale_connections(self) -> None:
        """Clean up stale connections."""
        now = datetime.now(UTC)
        
        # Only run cleanup periodically
        if (now - self._last_cleanup).total_seconds() < self._cleanup_interval:
            return
        
        stale_connections = []
        for connection_id, context in self._connections.items():
            # Mark as stale if inactive for more than 30 minutes
            if (now - context.last_activity).total_seconds() > 1800:
                stale_connections.append(connection_id)
        
        # Remove stale connections
        for connection_id in stale_connections:
            await self._unregister_connection(connection_id)
        
        self._last_cleanup = now
        
        if stale_connections:
            self._logger.info(
                "Cleaned up stale connections",
                count=len(stale_connections)
            )
    
    async def _heartbeat_check(self, context: SubscriptionContext) -> bool:
        """Check connection heartbeat."""
        now = datetime.now(UTC)
        
        # Consider connection dead if no activity for 5 minutes
        return (now - context.last_activity).total_seconds() <= 300
    
    async def _subscription_generator(
        self,
        context: SubscriptionContext,
        event_stream: AsyncGenerator[dict[str, Any], None]
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Base subscription event generator with error handling."""
        try:
            await self._register_connection(context)
            
            async for event in event_stream:
                try:
                    # Check connection health
                    if not await self._heartbeat_check(context):
                        self._logger.warning(
                            "Connection heartbeat failed",
                            connection_id=context.connection_id
                        )
                        break
                    
                    # Check if event should be delivered
                    if not await self._should_deliver_event(context, event):
                        continue
                    
                    # Check rate limiting
                    await self._check_rate_limit(context)
                    
                    # Track metrics
                    metrics.subscription_events_delivered.labels(
                        subscription_type=context.subscription_type,
                        event_type=event.get("event_type", "unknown"),
                        **self._metrics_labels
                    ).inc()
                    
                    yield event
                    
                except RateLimitExceededError:
                    # Send rate limit notification
                    yield {
                        "event_type": "rate_limit_exceeded",
                        "message": "Rate limit exceeded, some events may be dropped",
                        "timestamp": datetime.now(UTC).isoformat()
                    }
                    
                except Exception:
                    self._logger.exception(
                        "Error processing subscription event",
                        connection_id=context.connection_id,
                        event=event
                    )
                    
                    # Send error notification
                    yield {
                        "event_type": "subscription_error",
                        "message": "Error processing event",
                        "timestamp": datetime.now(UTC).isoformat()
                    }
                
                # Periodic cleanup
                await self._cleanup_stale_connections()
        
        except Exception as e:
            self._logger.exception(
                "Subscription generator error",
                connection_id=context.connection_id
            )
            
            # Send final error event
            yield {
                "event_type": "subscription_terminated",
                "message": "Subscription terminated due to error",
                "error": str(e),
                "timestamp": datetime.now(UTC).isoformat()
            }
        
        finally:
            await self._unregister_connection(context.connection_id)
    
    async def _listen_to_channel(
        self, channel: str
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Listen to Redis channel for events."""
        pubsub = self._redis.pubsub()
        
        try:
            await pubsub.subscribe(f"subscription:{channel}")
            
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        event = json.loads(message["data"])
                        yield event
                        
                    except json.JSONDecodeError:
                        self._logger.exception(
                            "Failed to decode subscription event",
                            channel=channel,
                            data=message["data"]
                        )
        
        except Exception:
            self._logger.exception(
                "Error listening to subscription channel",
                channel=channel
            )
            raise
        
        finally:
            await pubsub.unsubscribe(f"subscription:{channel}")
            await pubsub.close()