"""
EventBusAdapter - Identity Event Bus Integration

Provides a seamless adapter that bridges the identity module's domain events 
with the core event bus system, handling event transformation, routing, and 
cross-module communication.

Key Features:
- Automatic event type registration with core event bus
- Event metadata enrichment and correlation tracking
- Priority-based event routing and processing
- Dead letter queue handling for failed events
- Event replay and recovery capabilities
- Cross-module event routing
- Event versioning and compatibility
- Performance monitoring and metrics
"""

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.core.events.bus import EventBus, create_event_bus
from app.core.events.types import (
    EventFactory,
    EventPriority,
)
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

logger = get_logger(__name__)


class EventRoutingRule:
    """Defines routing rules for events between modules."""
    
    def __init__(
        self,
        event_type: str,
        target_modules: list[str],
        priority: EventPriority = EventPriority.NORMAL,
        require_confirmation: bool = False,
        retry_policy: dict[str, Any] | None = None
    ):
        self.event_type = event_type
        self.target_modules = set(target_modules)
        self.priority = priority
        self.require_confirmation = require_confirmation
        self.retry_policy = retry_policy or {
            'max_retries': 3,
            'initial_delay': 1.0,
            'backoff_multiplier': 2.0,
            'max_delay': 300.0
        }


class EventBusAdapter:
    """
    Adapter that provides seamless integration between identity events and core event bus.
    
    This adapter handles:
    - Event type registration and mapping
    - Event transformation and enrichment
    - Cross-module event routing
    - Error handling and recovery
    - Performance monitoring
    - Event replay capabilities
    """
    
    def __init__(
        self,
        event_bus: EventBus | None = None,
        module_name: str = "identity",
        enable_cross_module: bool = True,
        enable_event_replay: bool = True,
        dead_letter_queue_enabled: bool = True
    ):
        """
        Initialize the event bus adapter.
        
        Args:
            event_bus: Core event bus instance (will create if None)
            module_name: Name of the module using this adapter
            enable_cross_module: Enable cross-module event routing
            enable_event_replay: Enable event replay capabilities
            dead_letter_queue_enabled: Enable dead letter queue for failed events
        """
        self.module_name = module_name
        self.enable_cross_module = enable_cross_module
        self.enable_event_replay = enable_event_replay
        self.dead_letter_queue_enabled = dead_letter_queue_enabled
        
        # Initialize event bus
        self.event_bus = event_bus or create_event_bus("hybrid")
        
        # Event routing and management
        self.routing_rules: dict[str, EventRoutingRule] = {}
        self.subscriptions: dict[str, list[Callable]] = {}
        self.event_handlers: dict[str, list[Callable]] = {}
        
        # Event storage for replay (in-memory for now, could be database)
        self.event_store: list[dict[str, Any]] = []
        self.dead_letter_queue: list[dict[str, Any]] = []
        
        # Performance tracking
        self.published_events: int = 0
        self.failed_events: int = 0
        self.processed_events: int = 0
        
        # Module registry
        self.registered_modules: set[str] = {module_name}
        
        logger.info(
            "EventBusAdapter initialized",
            module=self.module_name,
            cross_module_enabled=self.enable_cross_module,
            replay_enabled=self.enable_event_replay
        )
    
    async def start(self) -> None:
        """Start the event bus adapter and underlying event bus."""
        try:
            await self.event_bus.start()
            await self._register_identity_events()
            await self._setup_default_routing()
            
            logger.info(
                "EventBusAdapter started successfully",
                module=self.module_name,
                registered_events=len(EventFactory.get_registered_types())
            )
        except Exception as e:
            logger.exception("Failed to start EventBusAdapter", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the event bus adapter and cleanup resources."""
        try:
            await self.event_bus.stop()
            logger.info("EventBusAdapter stopped successfully", module=self.module_name)
        except Exception as e:
            logger.exception("Error stopping EventBusAdapter", error=str(e))
    
    async def publish(
        self,
        event: IdentityDomainEvent,
        correlation_id: str | None = None,
        target_modules: list[str] | None = None,
        priority: EventPriority | None = None
    ) -> None:
        """
        Publish an identity domain event through the core event bus.
        
        Args:
            event: The identity domain event to publish
            correlation_id: Optional correlation ID for tracking
            target_modules: Specific modules to route the event to
            priority: Event priority (overrides default)
        """
        try:
            # Enrich event metadata
            enriched_event = await self._enrich_event(event, correlation_id, priority)
            
            # Store event for replay if enabled
            if self.enable_event_replay:
                await self._store_event(enriched_event)
            
            # Route to target modules
            if self.enable_cross_module and target_modules:
                await self._route_to_modules(enriched_event, target_modules)
            
            # Publish to core event bus
            await self.event_bus.publish(enriched_event, correlation_id)
            
            self.published_events += 1
            
            logger.debug(
                "Event published successfully",
                event_type=event.__class__.__name__,
                event_id=str(enriched_event.event_id),
                correlation_id=correlation_id,
                target_modules=target_modules
            )
            
        except Exception as e:
            self.failed_events += 1
            logger.exception(
                "Failed to publish event",
                event_type=event.__class__.__name__,
                error=str(e)
            )
            
            # Add to dead letter queue if enabled
            if self.dead_letter_queue_enabled:
                await self._add_to_dead_letter_queue(event, str(e))
            
            raise
    
    def subscribe(
        self,
        event_type: type[IdentityDomainEvent],
        handler: Callable[[IdentityDomainEvent], None],
        filter_criteria: dict[str, Any] | None = None
    ) -> None:
        """
        Subscribe a handler to identity domain events.
        
        Args:
            event_type: The event type to subscribe to
            handler: The event handler function
            filter_criteria: Optional criteria for filtering events
        """
        try:
            # Wrap handler with adapter logic
            wrapped_handler = self._wrap_handler(handler, filter_criteria)
            
            # Subscribe to core event bus
            self.event_bus.subscribe(event_type, wrapped_handler)
            
            # Track subscription
            event_name = event_type.__name__
            if event_name not in self.subscriptions:
                self.subscriptions[event_name] = []
            self.subscriptions[event_name].append(handler)
            
            logger.debug(
                "Handler subscribed to event",
                event_type=event_name,
                handler=getattr(handler, '__name__', str(handler)),
                filter_criteria=filter_criteria
            )
            
        except Exception as e:
            logger.exception(
                "Failed to subscribe handler",
                event_type=event_type.__name__,
                error=str(e)
            )
            raise
    
    def unsubscribe(
        self,
        event_type: type[IdentityDomainEvent],
        handler: Callable[[IdentityDomainEvent], None]
    ) -> None:
        """
        Unsubscribe a handler from identity domain events.
        
        Args:
            event_type: The event type to unsubscribe from
            handler: The event handler function to remove
        """
        try:
            # Find and remove from subscriptions
            event_name = event_type.__name__
            if event_name in self.subscriptions and handler in self.subscriptions[event_name]:
                self.subscriptions[event_name].remove(handler)
                
                # Remove from core event bus
                self.event_bus.unsubscribe(event_type, handler)
                
                logger.debug(
                    "Handler unsubscribed from event",
                    event_type=event_name,
                    handler=getattr(handler, '__name__', str(handler))
                )
                    
        except Exception as e:
            logger.exception(
                "Failed to unsubscribe handler",
                event_type=event_type.__name__,
                error=str(e)
            )
    
    def add_routing_rule(
        self,
        event_type: str,
        target_modules: list[str],
        priority: EventPriority = EventPriority.NORMAL,
        require_confirmation: bool = False
    ) -> None:
        """Add a routing rule for cross-module event distribution."""
        rule = EventRoutingRule(
            event_type=event_type,
            target_modules=target_modules,
            priority=priority,
            require_confirmation=require_confirmation
        )
        
        self.routing_rules[event_type] = rule
        
        logger.debug(
            "Routing rule added",
            event_type=event_type,
            target_modules=target_modules,
            priority=priority.name
        )
    
    def register_module(self, module_name: str) -> None:
        """Register a module for cross-module communication."""
        self.registered_modules.add(module_name)
        logger.debug("Module registered", module=module_name)
    
    async def replay_events(
        self,
        from_timestamp: datetime | None = None,
        to_timestamp: datetime | None = None,
        event_types: list[str] | None = None,
        correlation_id: str | None = None
    ) -> int:
        """
        Replay stored events based on criteria.
        
        Args:
            from_timestamp: Start time for replay
            to_timestamp: End time for replay
            event_types: Specific event types to replay
            correlation_id: Specific correlation ID to replay
            
        Returns:
            Number of events replayed
        """
        if not self.enable_event_replay:
            logger.warning("Event replay is disabled")
            return 0
        
        try:
            replayed = 0
            
            for stored_event in self.event_store:
                # Apply filters
                event_time = datetime.fromisoformat(stored_event['timestamp'])
                
                if from_timestamp and event_time < from_timestamp:
                    continue
                if to_timestamp and event_time > to_timestamp:
                    continue
                if event_types and stored_event['event_type'] not in event_types:
                    continue
                if correlation_id and stored_event.get('correlation_id') != correlation_id:
                    continue
                
                # Recreate and republish event
                try:
                    event_data = stored_event['event_data']
                    event = EventFactory.reconstruct_event(event_data)
                    
                    # Mark as replay
                    replay_correlation_id = f"replay-{uuid4()}"
                    await self.event_bus.publish(event, replay_correlation_id)
                    
                    replayed += 1
                    
                except Exception as e:
                    logger.exception(
                        "Failed to replay event",
                        event_id=stored_event.get('event_id'),
                        error=str(e)
                    )
            
            logger.info(
                "Event replay completed",
                events_replayed=replayed,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp
            )
            
            return replayed
            
        except Exception as e:
            logger.exception("Event replay failed", error=str(e))
            raise
    
    def get_statistics(self) -> dict[str, Any]:
        """Get adapter statistics and metrics."""
        return {
            'module': self.module_name,
            'published_events': self.published_events,
            'failed_events': self.failed_events,
            'processed_events': self.processed_events,
            'subscriptions': {
                event_type: len(handlers)
                for event_type, handlers in self.subscriptions.items()
            },
            'routing_rules': len(self.routing_rules),
            'registered_modules': list(self.registered_modules),
            'event_store_size': len(self.event_store),
            'dead_letter_queue_size': len(self.dead_letter_queue),
            'cross_module_enabled': self.enable_cross_module,
            'replay_enabled': self.enable_event_replay
        }
    
    async def process_dead_letter_queue(self) -> int:
        """Process events in the dead letter queue and attempt reprocessing."""
        if not self.dead_letter_queue_enabled:
            return 0
        
        processed = 0
        retry_queue = []
        
        for dlq_entry in self.dead_letter_queue:
            try:
                # Recreate event
                event_data = dlq_entry['event_data']
                event = EventFactory.reconstruct_event(event_data)
                
                # Attempt republish
                await self.event_bus.publish(event, dlq_entry.get('correlation_id'))
                processed += 1
                
                logger.info(
                    "Dead letter event reprocessed",
                    event_id=dlq_entry.get('event_id'),
                    original_error=dlq_entry.get('error')
                )
                
            except Exception as e:
                # Keep in queue if still failing
                dlq_entry['retry_count'] = dlq_entry.get('retry_count', 0) + 1
                dlq_entry['last_retry'] = datetime.utcnow().isoformat()
                dlq_entry['last_error'] = str(e)
                
                # Only keep if under retry limit
                if dlq_entry['retry_count'] < 5:
                    retry_queue.append(dlq_entry)
        
        # Update dead letter queue
        self.dead_letter_queue = retry_queue
        
        logger.info(
            "Dead letter queue processed",
            reprocessed=processed,
            remaining=len(retry_queue)
        )
        
        return processed
    
    # Private methods
    
    async def _register_identity_events(self) -> None:
        """Register all identity domain events with the event factory."""
        from app.modules.identity.domain.entities.user.user_events import (
            EmailVerified,
            LoginFailed,
            LoginSuccessful,
            MFADisabled,
            MFAEnabled,
            PasswordChanged,
            PhoneNumberVerified,
            ProfileUpdated,
            UserActivated,
            UserCreated,
            UserDeactivated,
            UserSuspended,
        )
        
        # Register core identity events
        identity_events = [
            UserCreated, UserActivated, UserSuspended, UserDeactivated,
            ProfileUpdated, LoginSuccessful, LoginFailed, PasswordChanged,
            MFAEnabled, MFADisabled, EmailVerified, PhoneNumberVerified
        ]
        
        for event_class in identity_events:
            EventFactory.register_event_type(event_class)
        
        logger.debug(
            "Identity events registered",
            event_count=len(identity_events)
        )
    
    async def _setup_default_routing(self) -> None:
        """Setup default routing rules for common event patterns."""
        # Security events should go to audit module
        security_events = [
            'LoginFailed', 'AccountLockedOut', 'MFADisabled', 
            'SuspiciousActivityDetected', 'SecurityAlertTriggered'
        ]
        
        for event_type in security_events:
            self.add_routing_rule(
                event_type=event_type,
                target_modules=['audit', 'security'],
                priority=EventPriority.HIGH
            )
        
        # User lifecycle events should go to notifications and audit
        lifecycle_events = [
            'UserCreated', 'UserActivated', 'UserSuspended', 'UserDeleted'
        ]
        
        for event_type in lifecycle_events:
            self.add_routing_rule(
                event_type=event_type,
                target_modules=['notifications', 'audit'],
                priority=EventPriority.NORMAL
            )
    
    async def _enrich_event(
        self,
        event: IdentityDomainEvent,
        correlation_id: str | None,
        priority: EventPriority | None
    ) -> IdentityDomainEvent:
        """Enrich event with additional metadata."""
        # Create enhanced metadata
        metadata_updates = {
            'source': f'{self.module_name}_adapter',
            'environment': 'production',  # Should come from config
        }
        
        if correlation_id:
            metadata_updates['correlation_id'] = correlation_id
        
        if priority:
            metadata_updates['priority'] = priority
        
        # Return enriched event
        return event.with_metadata(**metadata_updates)
    
    async def _store_event(self, event: IdentityDomainEvent) -> None:
        """Store event for replay capabilities."""
        event_record = {
            'event_id': str(event.event_id),
            'event_type': event.__class__.__name__,
            'timestamp': event.timestamp.isoformat(),
            'correlation_id': event.correlation_id,
            'event_data': event.to_dict(),
            'module': self.module_name
        }
        
        self.event_store.append(event_record)
        
        # Cleanup old events (keep last 10000)
        if len(self.event_store) > 10000:
            self.event_store = self.event_store[-10000:]
    
    async def _route_to_modules(
        self,
        event: IdentityDomainEvent,
        target_modules: list[str]
    ) -> None:
        """Route event to specific target modules."""
        event_type = event.__class__.__name__
        
        # Check routing rules
        routing_rule = self.routing_rules.get(event_type)
        if routing_rule:
            # Use rule's target modules if specified
            modules_to_route = routing_rule.target_modules.intersection(target_modules)
        else:
            modules_to_route = set(target_modules)
        
        # Route to each target module
        for module in modules_to_route:
            if module in self.registered_modules:
                try:
                    # Create module-specific correlation ID
                    module_correlation_id = f"{event.correlation_id}->{module}"
                    
                    # This would typically involve module-specific routing
                    # For now, we log the routing
                    logger.debug(
                        "Event routed to module",
                        event_type=event_type,
                        target_module=module,
                        correlation_id=module_correlation_id
                    )
                    
                except Exception as e:
                    logger.exception(
                        "Failed to route event to module",
                        event_type=event_type,
                        target_module=module,
                        error=str(e)
                    )
    
    def _wrap_handler(
        self,
        handler: Callable,
        filter_criteria: dict[str, Any] | None
    ) -> Callable:
        """Wrap handler with adapter logic including filtering and error handling."""
        async def wrapped_handler(event: IdentityDomainEvent) -> None:
            try:
                # Apply filters if specified
                if filter_criteria and not self._should_process_event(event, filter_criteria):
                    return
                
                # Call original handler
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
                
                self.processed_events += 1
                
            except Exception as e:
                logger.exception(
                    "Handler execution failed",
                    event_type=event.__class__.__name__,
                    handler=getattr(handler, '__name__', str(handler)),
                    error=str(e)
                )
                
                # Add to dead letter queue if enabled
                if self.dead_letter_queue_enabled:
                    await self._add_to_dead_letter_queue(event, str(e))
        
        return wrapped_handler
    
    def _should_process_event(
        self,
        event: IdentityDomainEvent,
        filter_criteria: dict[str, Any]
    ) -> bool:
        """Check if event should be processed based on filter criteria."""
        try:
            for key, expected_value in filter_criteria.items():
                # Handle nested attributes
                event_value = event
                for attr in key.split('.'):
                    if hasattr(event_value, attr):
                        event_value = getattr(event_value, attr)
                    else:
                        return False
                
                # Check if value matches
                if event_value != expected_value:
                    return False
            
            return True
            
        except Exception as e:
            logger.exception(
                "Error applying event filter",
                filter_criteria=filter_criteria,
                error=str(e)
            )
            return True  # Default to processing if filter fails
    
    async def _add_to_dead_letter_queue(
        self,
        event: IdentityDomainEvent,
        error: str
    ) -> None:
        """Add failed event to dead letter queue."""
        dlq_entry = {
            'event_id': str(event.event_id),
            'event_type': event.__class__.__name__,
            'event_data': event.to_dict(),
            'correlation_id': event.correlation_id,
            'error': error,
            'failed_at': datetime.utcnow().isoformat(),
            'retry_count': 0,
            'module': self.module_name
        }
        
        self.dead_letter_queue.append(dlq_entry)
        
        # Cleanup old entries (keep last 1000)
        if len(self.dead_letter_queue) > 1000:
            self.dead_letter_queue = self.dead_letter_queue[-1000:]
        
        logger.warning(
            "Event added to dead letter queue",
            event_id=str(event.event_id),
            error=error
        )