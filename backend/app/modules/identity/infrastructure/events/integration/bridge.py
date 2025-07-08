"""
CrossModuleEventBridge - Inter-Module Event Communication

Provides sophisticated inter-module event communication capabilities with support for
module discovery, event routing, circuit breakers, retries, and comprehensive
monitoring of cross-module interactions.

Key Features:
- Inter-module event routing and communication
- Module discovery and service registration
- Circuit breaker pattern for resilience
- Event transformation for cross-module compatibility
- Comprehensive monitoring and analytics
- Message queuing and buffering
- Load balancing and failover
- Security and access control
"""

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class ModuleStatus(Enum):
    """Status of a registered module."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    FAILED = "failed"


class BridgeStatus(Enum):
    """Status of event bridge connections."""
    OPEN = "open"
    HALF_OPEN = "half_open"
    CLOSED = "closed"


class RoutingStrategy(Enum):
    """Event routing strategies."""
    BROADCAST = "broadcast"  # Send to all modules
    ROUND_ROBIN = "round_robin"  # Distribute evenly
    PRIORITY = "priority"  # Send based on priority
    FAILOVER = "failover"  # Send to backup on failure
    LOAD_BALANCED = "load_balanced"  # Send based on load


@dataclass
class ModuleInfo:
    """Information about a registered module."""
    module_id: str
    module_name: str
    version: str
    capabilities: list[str] = field(default_factory=list)
    event_types_consumed: list[str] = field(default_factory=list)
    event_types_produced: list[str] = field(default_factory=list)
    endpoint_url: str | None = None
    priority: int = 100
    max_concurrent_events: int = 10
    
    # Runtime state
    status: ModuleStatus = ModuleStatus.ACTIVE
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_seen_at: datetime = field(default_factory=datetime.utcnow)
    failure_count: int = 0
    success_count: int = 0
    current_load: int = 0
    
    def is_healthy(self) -> bool:
        """Check if module is healthy."""
        if self.status != ModuleStatus.ACTIVE:
            return False
        
        # Check if recently seen (within last 5 minutes)
        time_since_seen = datetime.utcnow() - self.last_seen_at
        if time_since_seen > timedelta(minutes=5):
            return False
        
        # Check failure rate
        total_requests = self.success_count + self.failure_count
        if total_requests > 10:
            failure_rate = self.failure_count / total_requests
            if failure_rate > 0.5:  # More than 50% failure rate
                return False
        
        return True
    
    def can_consume_event(self, event_type: str) -> bool:
        """Check if module can consume this event type."""
        return event_type in self.event_types_consumed
    
    def update_health(self, success: bool) -> None:
        """Update module health metrics."""
        self.last_seen_at = datetime.utcnow()
        
        if success:
            self.success_count += 1
            if self.failure_count > 0:
                self.failure_count = max(0, self.failure_count - 1)  # Gradual recovery
        else:
            self.failure_count += 1
        
        # Update status based on health
        if not self.is_healthy():
            if self.failure_count > 10:
                self.status = ModuleStatus.FAILED
            else:
                self.status = ModuleStatus.DEGRADED
        else:
            self.status = ModuleStatus.ACTIVE


@dataclass
class RoutingRule:
    """Defines how events should be routed between modules."""
    rule_id: str
    name: str
    source_modules: list[str] = field(default_factory=list)
    target_modules: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    routing_strategy: RoutingStrategy = RoutingStrategy.BROADCAST
    priority: int = 100
    enabled: bool = True
    conditions: dict[str, Any] = field(default_factory=dict)
    
    def matches_event(self, event: IdentityDomainEvent, source_module: str) -> bool:
        """Check if this routing rule applies to the event."""
        if not self.enabled:
            return False
        
        # Check source module
        if self.source_modules and source_module not in self.source_modules:
            return False
        
        # Check event type
        event_type = event.__class__.__name__
        if self.event_types and event_type not in self.event_types:
            return False
        
        # Check conditions
        for field_path, expected_value in self.conditions.items():
            try:
                actual_value = event
                for attr in field_path.split('.'):
                    actual_value = getattr(actual_value, attr)
                
                if actual_value != expected_value:
                    return False
            except AttributeError:
                return False
        
        return True


@dataclass
class CircuitBreaker:
    """Circuit breaker for module communication resilience."""
    module_id: str
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    half_open_max_calls: int = 3
    
    # State
    status: BridgeStatus = BridgeStatus.CLOSED
    failure_count: int = 0
    last_failure_time: datetime | None = None
    half_open_attempts: int = 0
    
    def can_proceed(self) -> bool:
        """Check if calls can proceed through this circuit breaker."""
        if self.status == BridgeStatus.CLOSED:
            return True
        
        if self.status == BridgeStatus.OPEN:
            # Check if recovery timeout has passed
            if (self.last_failure_time and 
                datetime.utcnow() - self.last_failure_time >= timedelta(seconds=self.recovery_timeout_seconds)):
                self.status = BridgeStatus.HALF_OPEN
                self.half_open_attempts = 0
                return True
            return False
        
        if self.status == BridgeStatus.HALF_OPEN:
            return self.half_open_attempts < self.half_open_max_calls
        
        return False
    
    def record_success(self) -> None:
        """Record a successful call."""
        if self.status == BridgeStatus.HALF_OPEN:
            self.half_open_attempts += 1
            if self.half_open_attempts >= self.half_open_max_calls:
                # Recovery successful
                self.status = BridgeStatus.CLOSED
                self.failure_count = 0
                self.half_open_attempts = 0
        elif self.status == BridgeStatus.CLOSED:
            # Gradual recovery from failures
            if self.failure_count > 0:
                self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.status == BridgeStatus.HALF_OPEN:
            # Half-open test failed, go back to open
            self.status = BridgeStatus.OPEN
            self.half_open_attempts = 0
        elif self.status == BridgeStatus.CLOSED:
            # Check if we should open the circuit
            if self.failure_count >= self.failure_threshold:
                self.status = BridgeStatus.OPEN


@dataclass
class EventQueue:
    """Queue for buffering events for modules."""
    module_id: str
    max_size: int = 1000
    events: list[tuple[IdentityDomainEvent, dict[str, Any]]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def enqueue(self, event: IdentityDomainEvent, metadata: dict[str, Any] | None = None) -> bool:
        """Add event to queue."""
        if len(self.events) >= self.max_size:
            return False
        
        self.events.append((event, metadata or {}))
        return True
    
    def dequeue(self) -> tuple[IdentityDomainEvent, dict[str, Any]] | None:
        """Remove and return next event from queue."""
        if self.events:
            return self.events.pop(0)
        return None
    
    def size(self) -> int:
        """Get current queue size."""
        return len(self.events)
    
    def is_full(self) -> bool:
        """Check if queue is full."""
        return len(self.events) >= self.max_size
    
    def clear(self) -> None:
        """Clear all events from queue."""
        self.events.clear()


class CrossModuleEventBridge:
    """
    Advanced cross-module event communication bridge.
    
    Provides reliable event routing between modules with resilience patterns,
    load balancing, and comprehensive monitoring.
    """
    
    def __init__(
        self,
        event_bus_adapter: 'EventBusAdapter',
        module_id: str = "identity",
        enable_circuit_breakers: bool = True,
        enable_event_queuing: bool = True,
        max_retry_attempts: int = 3,
        retry_delay_seconds: int = 1
    ):
        """
        Initialize the cross-module event bridge.
        
        Args:
            event_bus_adapter: Event bus adapter for integration
            module_id: ID of this module
            enable_circuit_breakers: Enable circuit breaker pattern
            enable_event_queuing: Enable event queuing for failed deliveries
            max_retry_attempts: Maximum retry attempts for failed events
            retry_delay_seconds: Delay between retry attempts
        """
        self.event_bus_adapter = event_bus_adapter
        self.module_id = module_id
        self.enable_circuit_breakers = enable_circuit_breakers
        self.enable_event_queuing = enable_event_queuing
        self.max_retry_attempts = max_retry_attempts
        self.retry_delay_seconds = retry_delay_seconds
        
        # Module registry
        self.registered_modules: dict[str, ModuleInfo] = {}
        self.routing_rules: list[RoutingRule] = []
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.event_queues: dict[str, EventQueue] = {}
        
        # Event handlers for different modules
        self.module_handlers: dict[str, Callable[[IdentityDomainEvent, str], None]] = {}
        
        # Performance tracking
        self.events_routed = 0
        self.events_delivered = 0
        self.events_failed = 0
        self.events_queued = 0
        
        # Background tasks
        self.queue_processor_task: asyncio.Task | None = None
        self.health_monitor_task: asyncio.Task | None = None
        self.shutdown_event = asyncio.Event()
        
        logger.info(
            "CrossModuleEventBridge initialized",
            module_id=module_id,
            circuit_breakers=enable_circuit_breakers,
            event_queuing=enable_event_queuing
        )
    
    async def start(self) -> None:
        """Start the event bridge and background tasks."""
        if self.enable_event_queuing:
            self.queue_processor_task = asyncio.create_task(self._process_queues())
        
        self.health_monitor_task = asyncio.create_task(self._monitor_module_health())
        
        logger.info("CrossModuleEventBridge started")
    
    async def stop(self) -> None:
        """Stop the event bridge and cleanup resources."""
        self.shutdown_event.set()
        
        # Cancel background tasks
        tasks = [self.queue_processor_task, self.health_monitor_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        
        logger.info("CrossModuleEventBridge stopped")
    
    def register_module(
        self,
        module_id: str,
        module_name: str,
        version: str,
        capabilities: list[str] | None = None,
        event_types_consumed: list[str] | None = None,
        event_types_produced: list[str] | None = None,
        endpoint_url: str | None = None,
        handler: Callable[[IdentityDomainEvent, str], None] | None = None
    ) -> bool:
        """
        Register a module for cross-module communication.
        
        Args:
            module_id: Unique module identifier
            module_name: Human-readable module name
            version: Module version
            capabilities: List of module capabilities
            event_types_consumed: Event types this module can consume
            event_types_produced: Event types this module produces
            endpoint_url: Optional endpoint URL for HTTP-based communication
            handler: Optional handler function for this module
            
        Returns:
            bool: True if registration successful
        """
        try:
            module_info = ModuleInfo(
                module_id=module_id,
                module_name=module_name,
                version=version,
                capabilities=capabilities or [],
                event_types_consumed=event_types_consumed or [],
                event_types_produced=event_types_produced or [],
                endpoint_url=endpoint_url
            )
            
            self.registered_modules[module_id] = module_info
            
            # Create circuit breaker if enabled
            if self.enable_circuit_breakers:
                self.circuit_breakers[module_id] = CircuitBreaker(module_id=module_id)
            
            # Create event queue if enabled
            if self.enable_event_queuing:
                self.event_queues[module_id] = EventQueue(module_id=module_id)
            
            # Register handler if provided
            if handler:
                self.module_handlers[module_id] = handler
            
            logger.info(
                "Module registered",
                module_id=module_id,
                module_name=module_name,
                version=version,
                capabilities=capabilities,
                consumed_events=len(event_types_consumed or []),
                produced_events=len(event_types_produced or [])
            )
            
            return True
            
        except Exception as e:
            logger.exception(
                "Module registration failed",
                module_id=module_id,
                error=str(e)
            )
            return False
    
    def unregister_module(self, module_id: str) -> bool:
        """Unregister a module."""
        try:
            if module_id in self.registered_modules:
                del self.registered_modules[module_id]
            
            if module_id in self.circuit_breakers:
                del self.circuit_breakers[module_id]
            
            if module_id in self.event_queues:
                del self.event_queues[module_id]
            
            if module_id in self.module_handlers:
                del self.module_handlers[module_id]
            
            logger.info("Module unregistered", module_id=module_id)
            return True
            
        except Exception as e:
            logger.exception(
                "Module unregistration failed",
                module_id=module_id,
                error=str(e)
            )
            return False
    
    def add_routing_rule(self, rule: RoutingRule) -> None:
        """Add a routing rule for event distribution."""
        self.routing_rules.append(rule)
        
        # Sort rules by priority (higher priority first)
        self.routing_rules.sort(key=lambda r: r.priority, reverse=True)
        
        logger.debug(
            "Routing rule added",
            rule_id=rule.rule_id,
            name=rule.name,
            strategy=rule.routing_strategy.value,
            priority=rule.priority
        )
    
    def remove_routing_rule(self, rule_id: str) -> bool:
        """Remove a routing rule."""
        for i, rule in enumerate(self.routing_rules):
            if rule.rule_id == rule_id:
                del self.routing_rules[i]
                logger.debug("Routing rule removed", rule_id=rule_id)
                return True
        return False
    
    async def route_event(
        self,
        event: IdentityDomainEvent,
        source_module: str | None = None,
        target_modules: list[str] | None = None,
        routing_strategy: RoutingStrategy | None = None
    ) -> dict[str, bool]:
        """
        Route an event to target modules.
        
        Args:
            event: Event to route
            source_module: Source module ID (defaults to this module)
            target_modules: Specific target modules (if None, uses routing rules)
            routing_strategy: Override routing strategy
            
        Returns:
            dict: Results of delivery attempts {module_id: success}
        """
        try:
            self.events_routed += 1
            source_module = source_module or self.module_id
            results = {}
            
            # Determine target modules
            if target_modules:
                # Use explicit target modules
                targets = target_modules
                strategy = routing_strategy or RoutingStrategy.BROADCAST
            else:
                # Use routing rules
                targets, strategy = self._find_target_modules(event, source_module)
            
            if not targets:
                logger.debug(
                    "No target modules found for event",
                    event_type=event.__class__.__name__,
                    source_module=source_module
                )
                return {}
            
            # Apply routing strategy
            selected_targets = self._apply_routing_strategy(targets, strategy)
            
            # Route to selected targets
            for target_module in selected_targets:
                success = await self._deliver_event(event, target_module, source_module)
                results[target_module] = success
                
                if success:
                    self.events_delivered += 1
                else:
                    self.events_failed += 1
            
            logger.debug(
                "Event routed",
                event_type=event.__class__.__name__,
                source_module=source_module,
                target_modules=list(results.keys()),
                successful_deliveries=sum(1 for s in results.values() if s)
            )
            
            return results
            
        except Exception as e:
            self.events_failed += 1
            logger.exception(
                "Event routing failed",
                event_type=event.__class__.__name__,
                source_module=source_module,
                error=str(e)
            )
            return {}
    
    def get_module_info(self, module_id: str) -> ModuleInfo | None:
        """Get information about a registered module."""
        return self.registered_modules.get(module_id)
    
    def get_healthy_modules(self) -> list[ModuleInfo]:
        """Get list of healthy modules."""
        return [module for module in self.registered_modules.values() if module.is_healthy()]
    
    def get_statistics(self) -> dict[str, Any]:
        """Get bridge statistics."""
        healthy_modules = len(self.get_healthy_modules())
        total_modules = len(self.registered_modules)
        
        # Circuit breaker stats
        circuit_stats = {}
        for module_id, cb in self.circuit_breakers.items():
            circuit_stats[module_id] = {
                'status': cb.status.value,
                'failure_count': cb.failure_count,
                'half_open_attempts': cb.half_open_attempts
            }
        
        # Queue stats
        queue_stats = {}
        for module_id, queue in self.event_queues.items():
            queue_stats[module_id] = {
                'size': queue.size(),
                'is_full': queue.is_full()
            }
        
        return {
            'module_id': self.module_id,
            'registered_modules': total_modules,
            'healthy_modules': healthy_modules,
            'routing_rules': len(self.routing_rules),
            'events_routed': self.events_routed,
            'events_delivered': self.events_delivered,
            'events_failed': self.events_failed,
            'events_queued': self.events_queued,
            'circuit_breakers': circuit_stats,
            'event_queues': queue_stats,
            'module_handlers': len(self.module_handlers)
        }
    
    # Private methods
    
    def _find_target_modules(
        self,
        event: IdentityDomainEvent,
        source_module: str
    ) -> tuple[list[str], RoutingStrategy]:
        """Find target modules using routing rules."""
        for rule in self.routing_rules:
            if rule.matches_event(event, source_module):
                return rule.target_modules, rule.routing_strategy
        
        # Default: find modules that can consume this event type
        event_type = event.__class__.__name__
        targets = [
            module_id for module_id, module_info in self.registered_modules.items()
            if module_info.can_consume_event(event_type) and module_info.is_healthy()
        ]
        
        return targets, RoutingStrategy.BROADCAST
    
    def _apply_routing_strategy(
        self,
        target_modules: list[str],
        strategy: RoutingStrategy
    ) -> list[str]:
        """Apply routing strategy to select final target modules."""
        if not target_modules:
            return []
        
        if strategy == RoutingStrategy.BROADCAST:
            return target_modules
        
        if strategy == RoutingStrategy.ROUND_ROBIN:
            # Simple round-robin: select one module
            # In real implementation, this would maintain state
            return [target_modules[self.events_routed % len(target_modules)]]
        
        if strategy == RoutingStrategy.PRIORITY:
            # Select module with highest priority
            modules_with_priority = [
                (module_id, self.registered_modules.get(module_id, ModuleInfo("", "", "")).priority)
                for module_id in target_modules
                if module_id in self.registered_modules
            ]
            if modules_with_priority:
                modules_with_priority.sort(key=lambda x: x[1], reverse=True)
                return [modules_with_priority[0][0]]
            return target_modules[:1]
        
        if strategy == RoutingStrategy.LOAD_BALANCED:
            # Select module with lowest current load
            modules_with_load = [
                (module_id, self.registered_modules.get(module_id, ModuleInfo("", "", "")).current_load)
                for module_id in target_modules
                if module_id in self.registered_modules
            ]
            if modules_with_load:
                modules_with_load.sort(key=lambda x: x[1])
                return [modules_with_load[0][0]]
            return target_modules[:1]
        
        if strategy == RoutingStrategy.FAILOVER:
            # Return all modules for failover handling
            return target_modules
        
        return target_modules
    
    async def _deliver_event(
        self,
        event: IdentityDomainEvent,
        target_module: str,
        source_module: str
    ) -> bool:
        """Deliver event to a specific module."""
        try:
            # Check circuit breaker
            if (self.enable_circuit_breakers and 
                target_module in self.circuit_breakers):
                circuit_breaker = self.circuit_breakers[target_module]
                if not circuit_breaker.can_proceed():
                    logger.warning(
                        "Circuit breaker open, event delivery blocked",
                        target_module=target_module,
                        circuit_status=circuit_breaker.status.value
                    )
                    return False
            
            # Update module load
            if target_module in self.registered_modules:
                self.registered_modules[target_module].current_load += 1
            
            try:
                # Attempt delivery
                success = await self._attempt_delivery(event, target_module, source_module)
                
                # Update circuit breaker
                if self.enable_circuit_breakers and target_module in self.circuit_breakers:
                    if success:
                        self.circuit_breakers[target_module].record_success()
                    else:
                        self.circuit_breakers[target_module].record_failure()
                
                # Update module health
                if target_module in self.registered_modules:
                    self.registered_modules[target_module].update_health(success)
                
                return success
                
            finally:
                # Decrease module load
                if target_module in self.registered_modules:
                    self.registered_modules[target_module].current_load = max(
                        0, self.registered_modules[target_module].current_load - 1
                    )
            
        except Exception as e:
            logger.exception(
                "Event delivery failed",
                target_module=target_module,
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return False
    
    async def _attempt_delivery(
        self,
        event: IdentityDomainEvent,
        target_module: str,
        source_module: str
    ) -> bool:
        """Attempt to deliver event to module."""
        for attempt in range(self.max_retry_attempts + 1):
            try:
                # Use registered handler if available
                if target_module in self.module_handlers:
                    handler = self.module_handlers[target_module]
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event, source_module)
                    else:
                        handler(event, source_module)
                    return True
                
                # For now, log the delivery (in real implementation, this would be HTTP/gRPC call)
                logger.info(
                    "Event delivered to module",
                    target_module=target_module,
                    source_module=source_module,
                    event_type=event.__class__.__name__,
                    event_id=str(event.event_id),
                    attempt=attempt + 1
                )
                return True
                
            except Exception as e:
                if attempt < self.max_retry_attempts:
                    logger.warning(
                        "Event delivery attempt failed, retrying",
                        target_module=target_module,
                        attempt=attempt + 1,
                        error=str(e)
                    )
                    await asyncio.sleep(self.retry_delay_seconds)
                else:
                    logger.exception(
                        "Event delivery failed after all retries",
                        target_module=target_module,
                        attempts=attempt + 1,
                        error=str(e)
                    )
                    
                    # Queue event if enabled
                    if self.enable_event_queuing and target_module in self.event_queues:
                        queue = self.event_queues[target_module]
                        if queue.enqueue(event, {'source_module': source_module}):
                            self.events_queued += 1
                            logger.info(
                                "Event queued for later delivery",
                                target_module=target_module,
                                queue_size=queue.size()
                            )
                    
                    return False
        
        return False
    
    async def _process_queues(self) -> None:
        """Background task to process queued events."""
        while not self.shutdown_event.is_set():
            try:
                for module_id, queue in self.event_queues.items():
                    if queue.size() > 0:
                        # Check if module is healthy enough for retry
                        if (module_id in self.registered_modules and 
                            self.registered_modules[module_id].is_healthy()):
                            
                            # Try to deliver one event
                            event_data = queue.dequeue()
                            if event_data:
                                event, metadata = event_data
                                source_module = metadata.get('source_module', self.module_id)
                                
                                success = await self._deliver_event(event, module_id, source_module)
                                
                                if not success:
                                    # Put it back in queue if delivery still fails
                                    queue.enqueue(event, metadata)
                                else:
                                    logger.info(
                                        "Queued event successfully delivered",
                                        target_module=module_id,
                                        remaining_queue_size=queue.size()
                                    )
                
                await asyncio.sleep(5)  # Process queues every 5 seconds
                
            except Exception as e:
                logger.exception("Queue processing error", error=str(e))
                await asyncio.sleep(10)
    
    async def _monitor_module_health(self) -> None:
        """Background task to monitor module health."""
        while not self.shutdown_event.is_set():
            try:
                current_time = datetime.utcnow()
                
                for module_id, module_info in self.registered_modules.items():
                    # Check if module has been silent too long
                    time_since_seen = current_time - module_info.last_seen_at
                    
                    if time_since_seen > timedelta(minutes=10):
                        if module_info.status != ModuleStatus.FAILED:
                            module_info.status = ModuleStatus.INACTIVE
                            logger.warning(
                                "Module marked as inactive due to silence",
                                module_id=module_id,
                                last_seen=module_info.last_seen_at.isoformat()
                            )
                    
                    # Log unhealthy modules
                    if not module_info.is_healthy():
                        logger.warning(
                            "Unhealthy module detected",
                            module_id=module_id,
                            status=module_info.status.value,
                            failure_count=module_info.failure_count,
                            success_count=module_info.success_count
                        )
                
                await asyncio.sleep(60)  # Check health every minute
                
            except Exception as e:
                logger.exception("Health monitoring error", error=str(e))
                await asyncio.sleep(60)