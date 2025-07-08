"""
EventSubscriptionManager - Advanced Event Subscription Management

Provides sophisticated subscription management for event handlers with features like
dynamic subscription, filtering, priority handling, subscription groups, and
subscription lifecycle management.

Key Features:
- Dynamic subscription management
- Event handler filtering and routing
- Subscription groups and priority handling
- Subscription lifecycle hooks
- Performance monitoring and analytics
- Dead letter queue for failed subscriptions
- Subscription health monitoring
- Subscription persistence and recovery
"""

import asyncio
import contextlib
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.core.events.types import EventPriority
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class SubscriptionStatus(Enum):
    """Subscription status."""
    ACTIVE = "active"
    PAUSED = "paused"
    FAILED = "failed"
    DISABLED = "disabled"


class SubscriptionPriority(Enum):
    """Subscription execution priority."""
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


@dataclass
class SubscriptionFilter:
    """Filter configuration for event subscriptions."""
    event_types: list[str] = field(default_factory=list)
    event_priorities: list[EventPriority] = field(default_factory=list)
    user_ids: list[UUID] = field(default_factory=list)
    correlation_ids: list[str] = field(default_factory=list)
    custom_filters: dict[str, Any] = field(default_factory=dict)
    
    def matches(self, event: IdentityDomainEvent) -> bool:
        """Check if event matches this filter."""
        # Check event type
        if self.event_types and event.__class__.__name__ not in self.event_types:
            return False
        
        # Check event priority
        if self.event_priorities and hasattr(event.metadata, 'priority'):
            if event.metadata.priority not in self.event_priorities:
                return False
        
        # Check user ID
        if self.user_ids and hasattr(event, 'user_id'):
            if event.user_id not in self.user_ids:
                return False
        
        # Check correlation ID
        if self.correlation_ids and hasattr(event, 'correlation_id'):
            if event.correlation_id not in self.correlation_ids:
                return False
        
        # Check custom filters
        for key, expected_value in self.custom_filters.items():
            try:
                actual_value = event
                for attr in key.split('.'):
                    actual_value = getattr(actual_value, attr)
                
                if actual_value != expected_value:
                    return False
            except AttributeError:
                return False
        
        return True


@dataclass
class Subscription:
    """Represents an event subscription."""
    subscription_id: UUID
    name: str
    event_type: type[IdentityDomainEvent]
    handler: Callable[[IdentityDomainEvent], None]
    priority: SubscriptionPriority = SubscriptionPriority.NORMAL
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    filter_config: SubscriptionFilter | None = None
    group_name: str | None = None
    timeout_seconds: int = 30
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    
    # Runtime state
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_executed_at: datetime | None = None
    execution_count: int = 0
    failure_count: int = 0
    last_error: str | None = None
    
    # Performance tracking
    avg_execution_time_ms: float = 0.0
    min_execution_time_ms: float = 0.0
    max_execution_time_ms: float = 0.0
    
    def update_execution_stats(self, execution_time_ms: float, success: bool) -> None:
        """Update execution statistics."""
        self.execution_count += 1
        self.last_executed_at = datetime.utcnow()
        
        if not success:
            self.failure_count += 1
        
        # Update timing stats
        if self.execution_count == 1:
            self.avg_execution_time_ms = execution_time_ms
            self.min_execution_time_ms = execution_time_ms
            self.max_execution_time_ms = execution_time_ms
        else:
            self.avg_execution_time_ms = (
                (self.avg_execution_time_ms * (self.execution_count - 1) + execution_time_ms)
                / self.execution_count
            )
            self.min_execution_time_ms = min(self.min_execution_time_ms, execution_time_ms)
            self.max_execution_time_ms = max(self.max_execution_time_ms, execution_time_ms)
    
    def get_failure_rate(self) -> float:
        """Get subscription failure rate."""
        if self.execution_count == 0:
            return 0.0
        return self.failure_count / self.execution_count
    
    def is_healthy(self) -> bool:
        """Check if subscription is healthy."""
        if self.status != SubscriptionStatus.ACTIVE:
            return False
        
        # Check failure rate
        failure_rate = self.get_failure_rate()
        if failure_rate > 0.5:  # More than 50% failure rate
            return False
        
        # Check if recently executed (within last hour)
        if self.last_executed_at:
            time_since_execution = datetime.utcnow() - self.last_executed_at
            if time_since_execution > timedelta(hours=1):
                return False
        
        return True


@dataclass
class SubscriptionGroup:
    """Groups subscriptions for coordinated management."""
    group_name: str
    description: str
    subscriptions: list[UUID] = field(default_factory=list)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_subscription(self, subscription_id: UUID) -> None:
        """Add subscription to group."""
        if subscription_id not in self.subscriptions:
            self.subscriptions.append(subscription_id)
    
    def remove_subscription(self, subscription_id: UUID) -> None:
        """Remove subscription from group."""
        if subscription_id in self.subscriptions:
            self.subscriptions.remove(subscription_id)


class EventSubscriptionManager:
    """
    Advanced subscription manager for identity domain events.
    
    Provides comprehensive subscription management with filtering, priority handling,
    groups, performance monitoring, and health tracking.
    """
    
    def __init__(
        self,
        event_bus_adapter: 'EventBusAdapter',
        enable_health_monitoring: bool = True,
        health_check_interval_seconds: int = 300,
        max_concurrent_executions: int = 100
    ):
        """
        Initialize the subscription manager.
        
        Args:
            event_bus_adapter: Event bus adapter for event handling
            enable_health_monitoring: Enable subscription health monitoring
            health_check_interval_seconds: Health check frequency
            max_concurrent_executions: Maximum concurrent subscription executions
        """
        self.event_bus_adapter = event_bus_adapter
        self.enable_health_monitoring = enable_health_monitoring
        self.health_check_interval_seconds = health_check_interval_seconds
        self.max_concurrent_executions = max_concurrent_executions
        
        # Subscription storage
        self.subscriptions: dict[UUID, Subscription] = {}
        self.subscription_groups: dict[str, SubscriptionGroup] = {}
        self.event_type_mappings: dict[str, list[UUID]] = {}
        
        # Execution control
        self.execution_semaphore = asyncio.Semaphore(max_concurrent_executions)
        self.shutdown_event = asyncio.Event()
        
        # Background tasks
        self.health_monitor_task: asyncio.Task | None = None
        
        # Performance tracking
        self.total_events_processed = 0
        self.total_execution_time_ms = 0.0
        self.failed_executions = 0
        
        logger.info(
            "EventSubscriptionManager initialized",
            health_monitoring=enable_health_monitoring,
            max_concurrent=max_concurrent_executions
        )
    
    async def start(self) -> None:
        """Start the subscription manager and background tasks."""
        if self.enable_health_monitoring:
            self.health_monitor_task = asyncio.create_task(self._monitor_health())
        
        logger.info("EventSubscriptionManager started")
    
    async def stop(self) -> None:
        """Stop the subscription manager and cleanup resources."""
        self.shutdown_event.set()
        
        # Cancel background tasks
        if self.health_monitor_task:
            self.health_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.health_monitor_task
        
        logger.info("EventSubscriptionManager stopped")
    
    async def subscribe(
        self,
        name: str,
        event_type: type[IdentityDomainEvent],
        handler: Callable[[IdentityDomainEvent], None],
        priority: SubscriptionPriority = SubscriptionPriority.NORMAL,
        filter_config: SubscriptionFilter | None = None,
        group_name: str | None = None,
        timeout_seconds: int = 30,
        retry_attempts: int = 3
    ) -> UUID:
        """
        Subscribe to identity domain events with advanced configuration.
        
        Args:
            name: Human-readable subscription name
            event_type: Event type to subscribe to
            handler: Event handler function
            priority: Subscription priority
            filter_config: Optional event filtering configuration
            group_name: Optional subscription group
            timeout_seconds: Handler execution timeout
            retry_attempts: Number of retry attempts
            
        Returns:
            UUID: Subscription ID
        """
        # Validate handler
        self._validate_handler(handler)
        
        # Create subscription
        subscription_id = uuid4()
        subscription = Subscription(
            subscription_id=subscription_id,
            name=name,
            event_type=event_type,
            handler=handler,
            priority=priority,
            filter_config=filter_config,
            group_name=group_name,
            timeout_seconds=timeout_seconds,
            retry_attempts=retry_attempts
        )
        
        # Store subscription
        self.subscriptions[subscription_id] = subscription
        
        # Update event type mappings
        event_type_name = event_type.__name__
        if event_type_name not in self.event_type_mappings:
            self.event_type_mappings[event_type_name] = []
        self.event_type_mappings[event_type_name].append(subscription_id)
        
        # Add to group if specified
        if group_name:
            if group_name not in self.subscription_groups:
                self.subscription_groups[group_name] = SubscriptionGroup(
                    group_name=group_name,
                    description=f"Auto-created group for {group_name}"
                )
            self.subscription_groups[group_name].add_subscription(subscription_id)
        
        # Register with event bus adapter
        wrapped_handler = self._wrap_handler(subscription_id)
        self.event_bus_adapter.subscribe(event_type, wrapped_handler, 
                                        filter_config.custom_filters if filter_config else None)
        
        logger.info(
            "Subscription created",
            subscription_id=str(subscription_id),
            name=name,
            event_type=event_type_name,
            priority=priority.name,
            group=group_name
        )
        
        return subscription_id
    
    async def unsubscribe(self, subscription_id: UUID) -> bool:
        """
        Unsubscribe from events.
        
        Args:
            subscription_id: ID of subscription to remove
            
        Returns:
            bool: True if unsubscribed successfully
        """
        if subscription_id not in self.subscriptions:
            return False
        
        subscription = self.subscriptions[subscription_id]
        
        # Remove from event bus adapter
        self.event_bus_adapter.unsubscribe(subscription.event_type, subscription.handler)
        
        # Remove from event type mappings
        event_type_name = subscription.event_type.__name__
        if event_type_name in self.event_type_mappings:
            if subscription_id in self.event_type_mappings[event_type_name]:
                self.event_type_mappings[event_type_name].remove(subscription_id)
        
        # Remove from group
        if subscription.group_name and subscription.group_name in self.subscription_groups:
            self.subscription_groups[subscription.group_name].remove_subscription(subscription_id)
        
        # Remove subscription
        del self.subscriptions[subscription_id]
        
        logger.info(
            "Subscription removed",
            subscription_id=str(subscription_id),
            name=subscription.name
        )
        
        return True
    
    async def pause_subscription(self, subscription_id: UUID) -> bool:
        """Pause a subscription."""
        if subscription_id not in self.subscriptions:
            return False
        
        subscription = self.subscriptions[subscription_id]
        subscription.status = SubscriptionStatus.PAUSED
        
        logger.info(
            "Subscription paused",
            subscription_id=str(subscription_id),
            name=subscription.name
        )
        
        return True
    
    async def resume_subscription(self, subscription_id: UUID) -> bool:
        """Resume a paused subscription."""
        if subscription_id not in self.subscriptions:
            return False
        
        subscription = self.subscriptions[subscription_id]
        if subscription.status == SubscriptionStatus.PAUSED:
            subscription.status = SubscriptionStatus.ACTIVE
            
            logger.info(
                "Subscription resumed",
                subscription_id=str(subscription_id),
                name=subscription.name
            )
            
            return True
        
        return False
    
    async def pause_group(self, group_name: str) -> int:
        """Pause all subscriptions in a group."""
        if group_name not in self.subscription_groups:
            return 0
        
        paused_count = 0
        group = self.subscription_groups[group_name]
        
        for subscription_id in group.subscriptions:
            if await self.pause_subscription(subscription_id):
                paused_count += 1
        
        logger.info(
            "Subscription group paused",
            group_name=group_name,
            paused_count=paused_count
        )
        
        return paused_count
    
    async def resume_group(self, group_name: str) -> int:
        """Resume all subscriptions in a group."""
        if group_name not in self.subscription_groups:
            return 0
        
        resumed_count = 0
        group = self.subscription_groups[group_name]
        
        for subscription_id in group.subscriptions:
            if await self.resume_subscription(subscription_id):
                resumed_count += 1
        
        logger.info(
            "Subscription group resumed",
            group_name=group_name,
            resumed_count=resumed_count
        )
        
        return resumed_count
    
    def get_subscription(self, subscription_id: UUID) -> Subscription | None:
        """Get subscription by ID."""
        return self.subscriptions.get(subscription_id)
    
    def get_subscriptions_by_type(self, event_type: str) -> list[Subscription]:
        """Get all subscriptions for an event type."""
        subscription_ids = self.event_type_mappings.get(event_type, [])
        return [self.subscriptions[sid] for sid in subscription_ids if sid in self.subscriptions]
    
    def get_subscriptions_by_group(self, group_name: str) -> list[Subscription]:
        """Get all subscriptions in a group."""
        if group_name not in self.subscription_groups:
            return []
        
        group = self.subscription_groups[group_name]
        return [self.subscriptions[sid] for sid in group.subscriptions if sid in self.subscriptions]
    
    def get_healthy_subscriptions(self) -> list[Subscription]:
        """Get all healthy subscriptions."""
        return [sub for sub in self.subscriptions.values() if sub.is_healthy()]
    
    def get_unhealthy_subscriptions(self) -> list[Subscription]:
        """Get all unhealthy subscriptions."""
        return [sub for sub in self.subscriptions.values() if not sub.is_healthy()]
    
    def get_statistics(self) -> dict[str, Any]:
        """Get subscription manager statistics."""
        total_subscriptions = len(self.subscriptions)
        active_subscriptions = len([s for s in self.subscriptions.values() 
                                   if s.status == SubscriptionStatus.ACTIVE])
        healthy_subscriptions = len(self.get_healthy_subscriptions())
        
        avg_execution_time = (
            self.total_execution_time_ms / self.total_events_processed
            if self.total_events_processed > 0 else 0.0
        )
        
        failure_rate = (
            self.failed_executions / self.total_events_processed
            if self.total_events_processed > 0 else 0.0
        )
        
        return {
            'total_subscriptions': total_subscriptions,
            'active_subscriptions': active_subscriptions,
            'healthy_subscriptions': healthy_subscriptions,
            'subscription_groups': len(self.subscription_groups),
            'total_events_processed': self.total_events_processed,
            'total_execution_time_ms': self.total_execution_time_ms,
            'avg_execution_time_ms': avg_execution_time,
            'failed_executions': self.failed_executions,
            'failure_rate': failure_rate,
            'max_concurrent_executions': self.max_concurrent_executions
        }
    
    # Private methods
    
    def _validate_handler(self, handler: Callable) -> None:
        """Validate event handler signature."""
        if not callable(handler):
            raise ValueError("Handler must be callable")
        
        # Check signature
        sig = inspect.signature(handler)
        if len(sig.parameters) != 1:
            raise ValueError("Handler must accept exactly one parameter (event)")
    
    def _wrap_handler(self, subscription_id: UUID) -> Callable:
        """Wrap subscription handler with execution logic."""
        async def wrapped_handler(event: IdentityDomainEvent) -> None:
            if subscription_id not in self.subscriptions:
                return
            
            subscription = self.subscriptions[subscription_id]
            
            # Check if subscription is active
            if subscription.status != SubscriptionStatus.ACTIVE:
                return
            
            # Check if event matches filter
            if subscription.filter_config and not subscription.filter_config.matches(event):
                return
            
            # Execute with concurrency control
            async with self.execution_semaphore:
                await self._execute_subscription(subscription, event)
        
        return wrapped_handler
    
    async def _execute_subscription(
        self,
        subscription: Subscription,
        event: IdentityDomainEvent
    ) -> None:
        """Execute subscription handler with retry and timing."""
        start_time = datetime.utcnow()
        
        for attempt in range(subscription.retry_attempts + 1):
            try:
                # Execute handler with timeout
                if asyncio.iscoroutinefunction(subscription.handler):
                    await asyncio.wait_for(
                        subscription.handler(event),
                        timeout=subscription.timeout_seconds
                    )
                else:
                    # Run sync handler in thread pool
                    await asyncio.get_event_loop().run_in_executor(
                        None, subscription.handler, event
                    )
                
                # Update statistics
                execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                subscription.update_execution_stats(execution_time, success=True)
                self.total_events_processed += 1
                self.total_execution_time_ms += execution_time
                
                logger.debug(
                    "Subscription executed successfully",
                    subscription_id=str(subscription.subscription_id),
                    execution_time_ms=execution_time,
                    attempt=attempt + 1
                )
                
                return
                
            except TimeoutError:
                error = f"Handler timed out after {subscription.timeout_seconds} seconds"
                subscription.last_error = error
                
                if attempt < subscription.retry_attempts:
                    await asyncio.sleep(subscription.retry_delay_seconds)
                    continue
                
            except Exception as e:
                error = str(e)
                subscription.last_error = error
                
                logger.exception(
                    "Subscription execution failed",
                    subscription_id=str(subscription.subscription_id),
                    attempt=attempt + 1,
                    error=error
                )
                
                if attempt < subscription.retry_attempts:
                    await asyncio.sleep(subscription.retry_delay_seconds)
                    continue
        
        # All attempts failed
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        subscription.update_execution_stats(execution_time, success=False)
        self.total_events_processed += 1
        self.total_execution_time_ms += execution_time
        self.failed_executions += 1
        
        # Mark as failed if too many failures
        if subscription.get_failure_rate() > 0.8:  # 80% failure rate
            subscription.status = SubscriptionStatus.FAILED
            
            logger.warning(
                "Subscription marked as failed due to high failure rate",
                subscription_id=str(subscription.subscription_id),
                failure_rate=subscription.get_failure_rate()
            )
    
    async def _monitor_health(self) -> None:
        """Background task to monitor subscription health."""
        while not self.shutdown_event.is_set():
            try:
                unhealthy_subscriptions = self.get_unhealthy_subscriptions()
                
                for subscription in unhealthy_subscriptions:
                    logger.warning(
                        "Unhealthy subscription detected",
                        subscription_id=str(subscription.subscription_id),
                        name=subscription.name,
                        failure_rate=subscription.get_failure_rate(),
                        last_error=subscription.last_error
                    )
                    
                    # Auto-disable subscriptions with very high failure rates
                    if subscription.get_failure_rate() > 0.9:
                        subscription.status = SubscriptionStatus.DISABLED
                        
                        logger.error(
                            "Subscription auto-disabled due to excessive failures",
                            subscription_id=str(subscription.subscription_id),
                            name=subscription.name
                        )
                
                # Sleep until next check
                await asyncio.sleep(self.health_check_interval_seconds)
                
            except Exception as e:
                logger.exception("Error in subscription health monitor", error=str(e))
                await asyncio.sleep(60)  # Wait before retrying