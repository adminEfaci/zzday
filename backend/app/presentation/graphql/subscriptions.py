"""
GraphQL Subscription Infrastructure

Provides WebSocket-based real-time subscriptions with authentication,
authorization, and connection management.
"""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from strawberry.subscriptions.protocols.graphql_transport_ws import (
    ConnectionAckMessage,
    ConnectionInitMessage,
    ErrorMessage,
    GraphQLTransportWSHandler,
    GraphQLTransportWSMessage,
    NextMessage,
    StartMessage,
    StopMessage,
)

logger = logging.getLogger(__name__)


class SubscriptionEventType(Enum):
    """Types of subscription events."""
    USER_STATUS_CHANGED = "user_status_changed"
    NOTIFICATION_RECEIVED = "notification_received"
    AUDIT_LOG_CREATED = "audit_log_created"
    SECURITY_EVENT = "security_event"
    SYSTEM_HEALTH = "system_health"
    INTEGRATION_STATUS = "integration_status"


class SubscriptionConnection:
    """Manages a single WebSocket subscription connection."""
    
    def __init__(self, connection_id: str, websocket: Any, context: dict[str, Any]):
        self.connection_id = connection_id
        self.websocket = websocket
        self.context = context
        self.user_id = context.get("user", {}).get("id") if context.get("user") else None
        self.is_authenticated = context.get("is_authenticated", False)
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.is_active = True
    
    async def send_message(self, message: GraphQLTransportWSMessage):
        """Send a message to the WebSocket connection."""
        try:
            await self.websocket.send_text(message.as_json())
            self.last_activity = datetime.utcnow()
        except Exception:
            logger.exception(f"Failed to send message to connection {self.connection_id}")
            self.is_active = False
    
    async def close(self, code: int = 1000, reason: str = "Normal closure"):
        """Close the WebSocket connection."""
        try:
            await self.websocket.close(code=code, reason=reason)
        except Exception:
            logger.exception(f"Error closing connection {self.connection_id}")
        finally:
            self.is_active = False
    
    def add_subscription(self, subscription_id: str, operation_name: str, query: str, variables: dict[str, Any]):
        """Add a subscription to this connection."""
        self.subscriptions[subscription_id] = {
            "operation_name": operation_name,
            "query": query,
            "variables": variables,
            "started_at": datetime.utcnow(),
        }
    
    def remove_subscription(self, subscription_id: str):
        """Remove a subscription from this connection."""
        self.subscriptions.pop(subscription_id, None)
    
    def has_subscription(self, subscription_id: str) -> bool:
        """Check if connection has a specific subscription."""
        return subscription_id in self.subscriptions


class SubscriptionManager:
    """Manages all WebSocket connections and subscriptions."""
    
    def __init__(self, max_connections: int = 1000, connection_timeout: int = 300):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.connections: dict[str, SubscriptionConnection] = {}
        self.user_connections: dict[str, set[str]] = defaultdict(set)
        self.subscription_handlers: dict[str, Callable] = {}
        self.event_listeners: dict[SubscriptionEventType, set[str]] = defaultdict(set)
        self._cleanup_task = None
        self._running = False
    
    async def start(self):
        """Start the subscription manager."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_connections())
        logger.info("Subscription manager started")
    
    async def stop(self):
        """Stop the subscription manager."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # Close all connections
        for connection in list(self.connections.values()):
            await connection.close(code=1001, reason="Server shutdown")
        
        self.connections.clear()
        self.user_connections.clear()
        logger.info("Subscription manager stopped")
    
    async def add_connection(self, connection: SubscriptionConnection) -> bool:
        """Add a new WebSocket connection."""
        if len(self.connections) >= self.max_connections:
            logger.warning(f"Maximum connections reached ({self.max_connections})")
            return False
        
        self.connections[connection.connection_id] = connection
        
        if connection.user_id:
            self.user_connections[connection.user_id].add(connection.connection_id)
        
        logger.info(f"New subscription connection: {connection.connection_id} (user: {connection.user_id})")
        return True
    
    async def remove_connection(self, connection_id: str):
        """Remove a WebSocket connection."""
        connection = self.connections.pop(connection_id, None)
        if not connection:
            return
        
        if connection.user_id:
            self.user_connections[connection.user_id].discard(connection_id)
            if not self.user_connections[connection.user_id]:
                del self.user_connections[connection.user_id]
        
        logger.info(f"Removed subscription connection: {connection_id}")
    
    async def add_subscription(self, connection_id: str, subscription_id: str, 
                             operation_name: str, query: str, variables: dict[str, Any]):
        """Add a subscription to a connection."""
        connection = self.connections.get(connection_id)
        if not connection:
            logger.error(f"Connection {connection_id} not found")
            return False
        
        connection.add_subscription(subscription_id, operation_name, query, variables)
        
        # Register event listener if it's a known event type
        for event_type in SubscriptionEventType:
            if event_type.value in operation_name.lower():
                self.event_listeners[event_type].add(connection_id)
                break
        
        logger.debug(f"Added subscription {subscription_id} to connection {connection_id}")
        return True
    
    async def remove_subscription(self, connection_id: str, subscription_id: str):
        """Remove a subscription from a connection."""
        connection = self.connections.get(connection_id)
        if not connection:
            return
        
        connection.remove_subscription(subscription_id)
        
        # Remove from event listeners
        for _event_type, listeners in self.event_listeners.items():
            listeners.discard(connection_id)
        
        logger.debug(f"Removed subscription {subscription_id} from connection {connection_id}")
    
    async def publish_event(self, event_type: SubscriptionEventType, data: Any, 
                          user_id: str | None = None, filter_fn: Callable | None = None):
        """Publish an event to relevant subscriptions."""
        connections_to_notify = set()
        
        # Get connections listening to this event type
        if event_type in self.event_listeners:
            connections_to_notify.update(self.event_listeners[event_type])
        
        # If user-specific, filter to user's connections
        if user_id and user_id in self.user_connections:
            user_connections = self.user_connections[user_id]
            connections_to_notify = connections_to_notify.intersection(user_connections)
        
        # Apply custom filter if provided
        if filter_fn:
            connections_to_notify = {
                conn_id for conn_id in connections_to_notify
                if conn_id in self.connections and filter_fn(self.connections[conn_id])
            }
        
        # Send to all matching connections
        for connection_id in connections_to_notify:
            connection = self.connections.get(connection_id)
            if connection and connection.is_active:
                await self._send_event_to_connection(connection, event_type, data)
    
    async def _send_event_to_connection(self, connection: SubscriptionConnection, 
                                      event_type: SubscriptionEventType, data: Any):
        """Send an event to a specific connection."""
        # Find matching subscriptions
        matching_subscriptions = []
        for sub_id, sub_data in connection.subscriptions.items():
            if event_type.value in sub_data["operation_name"].lower():
                matching_subscriptions.append(sub_id)
        
        # Send to each matching subscription
        for subscription_id in matching_subscriptions:
            message = NextMessage(
                id=subscription_id,
                payload={"data": data}
            )
            await connection.send_message(message)
    
    async def _cleanup_connections(self):
        """Periodically clean up inactive connections."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                cutoff_time = datetime.utcnow() - timedelta(seconds=self.connection_timeout)
                inactive_connections = []
                
                for conn_id, connection in self.connections.items():
                    if not connection.is_active or connection.last_activity < cutoff_time:
                        inactive_connections.append(conn_id)
                
                # Remove inactive connections
                for conn_id in inactive_connections:
                    connection = self.connections.get(conn_id)
                    if connection:
                        await connection.close(code=1001, reason="Timeout")
                        await self.remove_connection(conn_id)
                
                if inactive_connections:
                    logger.info(f"Cleaned up {len(inactive_connections)} inactive connections")
                
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in connection cleanup")
    
    def get_connection_stats(self) -> dict[str, Any]:
        """Get statistics about current connections."""
        total_connections = len(self.connections)
        authenticated_connections = sum(1 for conn in self.connections.values() if conn.is_authenticated)
        total_subscriptions = sum(len(conn.subscriptions) for conn in self.connections.values())
        
        return {
            "total_connections": total_connections,
            "authenticated_connections": authenticated_connections,
            "anonymous_connections": total_connections - authenticated_connections,
            "total_subscriptions": total_subscriptions,
            "unique_users": len(self.user_connections),
            "event_listeners": {
                event_type.value: len(listeners)
                for event_type, listeners in self.event_listeners.items()
            }
        }


class AuthenticatedSubscriptionHandler(GraphQLTransportWSHandler):
    """Custom WebSocket handler with authentication support."""
    
    def __init__(self, subscription_manager: SubscriptionManager, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscription_manager = subscription_manager
        self.connection: SubscriptionConnection | None = None
    
    async def handle_connection_init(self, message: ConnectionInitMessage):
        """Handle connection initialization with authentication."""
        try:
            # Extract authentication from connection params
            auth_token = None
            if message.payload:
                auth_token = message.payload.get("authToken")
            
            # Authenticate user
            user = await self._authenticate_user(auth_token)
            
            # Create connection context
            context = {
                "user": user,
                "is_authenticated": user is not None,
                "websocket": self.websocket,
                "auth_token": auth_token,
            }
            
            # Create connection
            connection_id = f"ws_{id(self.websocket)}"
            self.connection = SubscriptionConnection(
                connection_id=connection_id,
                websocket=self.websocket,
                context=context
            )
            
            # Add to manager
            if await self.subscription_manager.add_connection(self.connection):
                await self.websocket.send_text(ConnectionAckMessage().as_json())
                logger.info(f"WebSocket connection authenticated: {connection_id}")
            else:
                await self.websocket.send_text(
                    ErrorMessage(
                        id=None,
                        payload={"message": "Connection limit exceeded"}
                    ).as_json()
                )
                await self.websocket.close(code=1008, reason="Connection limit exceeded")
                
        except Exception:
            logger.exception("WebSocket authentication failed")
            await self.websocket.send_text(
                ErrorMessage(
                    id=None,
                    payload={"message": "Authentication failed"}
                ).as_json()
            )
            await self.websocket.close(code=1008, reason="Authentication failed")
    
    async def handle_start(self, message: StartMessage):
        """Handle subscription start with authorization."""
        if not self.connection:
            await self.websocket.send_text(
                ErrorMessage(
                    id=message.id,
                    payload={"message": "Connection not initialized"}
                ).as_json()
            )
            return
        
        try:
            # Check authorization for subscription
            if not await self._authorize_subscription(message.payload):
                await self.websocket.send_text(
                    ErrorMessage(
                        id=message.id,
                        payload={"message": "Unauthorized subscription"}
                    ).as_json()
                )
                return
            
            # Add subscription
            await self.subscription_manager.add_subscription(
                connection_id=self.connection.connection_id,
                subscription_id=message.id,
                operation_name=message.payload.get("operationName", ""),
                query=message.payload.get("query", ""),
                variables=message.payload.get("variables", {})
            )
            
            # Continue with normal handling
            await super().handle_start(message)
            
        except Exception:
            logger.exception("Error handling subscription start")
            await self.websocket.send_text(
                ErrorMessage(
                    id=message.id,
                    payload={"message": "Internal error"}
                ).as_json()
            )
    
    async def handle_stop(self, message: StopMessage):
        """Handle subscription stop."""
        if self.connection:
            await self.subscription_manager.remove_subscription(
                connection_id=self.connection.connection_id,
                subscription_id=message.id
            )
        
        await super().handle_stop(message)
    
    async def handle_connection_terminate(self):
        """Handle connection termination."""
        if self.connection:
            await self.subscription_manager.remove_connection(self.connection.connection_id)
        
        await super().handle_connection_terminate()
    
    async def _authenticate_user(self, auth_token: str | None) -> dict[str, Any] | None:
        """Authenticate user from token."""
        if not auth_token:
            return None
        
        try:
            # TODO: Implement actual token validation
            # This is a placeholder - integrate with your authentication system
            
            # Mock authentication for now
            return {"id": "user123", "email": "test@example.com"}
            
        except Exception:
            logger.exception("Token authentication failed")
            return None
    
    async def _authorize_subscription(self, payload: dict[str, Any]) -> bool:
        """Authorize subscription based on user and query."""
        if not self.connection.is_authenticated:
            # Allow some public subscriptions
            query = payload.get("query", "").lower()
            public_subscriptions = ["system_health", "public_announcements"]
            
            return any(sub in query for sub in public_subscriptions)
        
        # Authenticated users can subscribe to most things
        # TODO: Implement proper authorization logic
        return True


# Global subscription manager instance
subscription_manager = SubscriptionManager()


async def publish_user_status_changed(user_id: str, status: str, metadata: dict[str, Any] | None = None):
    """Publish user status change event."""
    await subscription_manager.publish_event(
        event_type=SubscriptionEventType.USER_STATUS_CHANGED,
        data={
            "user_id": user_id,
            "status": status,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat()
        },
        user_id=user_id
    )


async def publish_notification(user_id: str, notification: dict[str, Any]):
    """Publish notification event."""
    await subscription_manager.publish_event(
        event_type=SubscriptionEventType.NOTIFICATION_RECEIVED,
        data=notification,
        user_id=user_id
    )


async def publish_security_event(event_type: str, user_id: str | None = None, data: dict[str, Any] | None = None):
    """Publish security event."""
    await subscription_manager.publish_event(
        event_type=SubscriptionEventType.SECURITY_EVENT,
        data={
            "event_type": event_type,
            "user_id": user_id,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat()
        },
        user_id=user_id
    )


__all__ = [
    "AuthenticatedSubscriptionHandler",
    "SubscriptionConnection",
    "SubscriptionEventType",
    "SubscriptionManager",
    "publish_notification",
    "publish_security_event",
    "publish_user_status_changed",
    "subscription_manager",
]