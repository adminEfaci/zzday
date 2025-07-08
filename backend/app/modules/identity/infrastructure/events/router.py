"""
Event Router Implementation

Routes events to appropriate handlers based on event type, priority, and
configured routing rules. Supports filtering, transformation, and conditional routing.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern
from typing import Any

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

logger = get_logger(__name__)


class RoutingStrategy(Enum):
    """Event routing strategies."""
    
    DIRECT = "direct"  # Route to specific handlers
    BROADCAST = "broadcast"  # Route to all matching handlers
    ROUND_ROBIN = "round_robin"  # Load balance across handlers
    PRIORITY = "priority"  # Route based on priority
    CONDITIONAL = "conditional"  # Route based on conditions


class RoutingDecision(Enum):
    """Routing decision outcomes."""
    
    ROUTE = "route"  # Route to handlers
    DROP = "drop"  # Drop the event
    TRANSFORM = "transform"  # Transform and re-route
    DELAY = "delay"  # Delay routing


@dataclass
class RoutingRule:
    """
    Routing rule for event processing.
    
    Defines how events should be routed based on various criteria
    including event type, priority, content, and metadata.
    """
    
    # Rule identification
    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 0  # Higher priority rules evaluated first
    
    # Event matching criteria
    event_types: set[str] = field(default_factory=set)  # Event type names
    event_type_patterns: list[Pattern] = field(default_factory=list)  # Regex patterns
    priority_levels: set[str] = field(default_factory=set)  # Event priorities
    
    # Content-based filtering
    content_filters: dict[str, Any] = field(default_factory=dict)  # Field value filters
    metadata_filters: dict[str, Any] = field(default_factory=dict)  # Metadata filters
    
    # Custom condition function
    condition_func: Callable[[IdentityDomainEvent], bool] | None = None
    
    # Routing configuration
    strategy: RoutingStrategy = RoutingStrategy.DIRECT
    target_handlers: list[str] = field(default_factory=list)
    target_queues: list[str] = field(default_factory=list)
    
    # Transformation
    transform_func: Callable[[IdentityDomainEvent], IdentityDomainEvent] | None = None
    
    # Action configuration
    decision: RoutingDecision = RoutingDecision.ROUTE
    delay_seconds: float = 0.0
    
    # Metadata
    tags: set[str] = field(default_factory=set)
    created_at: str | None = None
    updated_at: str | None = None
    
    def matches_event(self, event: IdentityDomainEvent) -> bool:
        """
        Check if event matches this routing rule.
        
        Args:
            event: Event to check
            
        Returns:
            bool: True if event matches rule criteria
        """
        if not self.enabled:
            return False
        
        # Check event type exact match
        if self.event_types and event.__class__.__name__ not in self.event_types:
            return False
        
        # Check event type pattern match
        if self.event_type_patterns:
            event_type = event.__class__.__name__
            if not any(pattern.match(event_type) for pattern in self.event_type_patterns):
                return False
        
        # Check priority levels
        if self.priority_levels:
            event_priority = getattr(event, 'get_risk_level', lambda: 'low')()
            if event_priority not in self.priority_levels:
                return False
        
        # Check content filters
        if self.content_filters and not self._matches_content_filters(event):
            return False
        
        # Check metadata filters
        if self.metadata_filters and not self._matches_metadata_filters(event):
            return False
        
        # Check custom condition
        if self.condition_func:
            try:
                if not self.condition_func(event):
                    return False
            except Exception as e:
                logger.warning(
                    "Custom condition function failed",
                    rule_id=self.rule_id,
                    event_type=event.__class__.__name__,
                    error=str(e),
                )
                return False
        
        return True
    
    def _matches_content_filters(self, event: IdentityDomainEvent) -> bool:
        """Check if event matches content filters."""
        for field_path, expected_value in self.content_filters.items():
            try:
                actual_value = self._get_nested_field(event, field_path)
                if not self._values_match(actual_value, expected_value):
                    return False
            except (AttributeError, KeyError, TypeError):
                return False
        return True
    
    def _matches_metadata_filters(self, event: IdentityDomainEvent) -> bool:
        """Check if event matches metadata filters."""
        event_metadata = event.get_event_metadata()
        for key, expected_value in self.metadata_filters.items():
            actual_value = event_metadata.get(key)
            if not self._values_match(actual_value, expected_value):
                return False
        return True
    
    def _get_nested_field(self, obj: Any, field_path: str) -> Any:
        """Get nested field value using dot notation."""
        fields = field_path.split('.')
        value = obj
        for field in fields:
            value = getattr(value, field)
        return value
    
    def _values_match(self, actual: Any, expected: Any) -> bool:
        """Check if actual value matches expected value with pattern support."""
        if isinstance(expected, str) and expected.startswith('regex:'):
            pattern = expected[6:]  # Remove 'regex:' prefix
            return bool(re.match(pattern, str(actual)))
        if isinstance(expected, list):
            return actual in expected
        if isinstance(expected, dict) and expected.get('operator'):
            return self._evaluate_operator(actual, expected)
        return actual == expected
    
    def _evaluate_operator(self, actual: Any, condition: dict) -> bool:
        """Evaluate operator-based condition."""
        operator = condition['operator']
        value = condition['value']
        
        if operator == 'eq':
            return actual == value
        if operator == 'ne':
            return actual != value
        if operator == 'gt':
            return actual > value
        if operator == 'gte':
            return actual >= value
        if operator == 'lt':
            return actual < value
        if operator == 'lte':
            return actual <= value
        if operator == 'in':
            return actual in value
        if operator == 'not_in':
            return actual not in value
        if operator == 'contains':
            return value in str(actual)
        if operator == 'starts_with':
            return str(actual).startswith(str(value))
        if operator == 'ends_with':
            return str(actual).endswith(str(value))
        logger.warning(f"Unknown operator: {operator}")
        return False


@dataclass
class RoutingInfo:
    """
    Routing information for an event.
    
    Contains the routing decision and target destinations for an event
    based on the applied routing rules.
    """
    
    event_type: str
    decision: RoutingDecision
    strategy: RoutingStrategy
    target_handlers: list[str] = field(default_factory=list)
    target_queues: list[str] = field(default_factory=list)
    applied_rules: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)
    delay_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def should_route(self) -> bool:
        """Check if event should be routed."""
        return self.decision == RoutingDecision.ROUTE
    
    @property
    def should_drop(self) -> bool:
        """Check if event should be dropped."""
        return self.decision == RoutingDecision.DROP
    
    @property
    def should_delay(self) -> bool:
        """Check if event should be delayed."""
        return self.decision == RoutingDecision.DELAY
    
    @property
    def has_targets(self) -> bool:
        """Check if routing has any targets."""
        return bool(self.target_handlers or self.target_queues)


class EventRouter:
    """
    Event router for identity domain events.
    
    Routes events to appropriate handlers based on configurable rules,
    event types, priorities, and content. Supports multiple routing
    strategies including direct routing, broadcasting, round-robin,
    and conditional routing.
    
    Features:
    - Rule-based routing with priority ordering
    - Content and metadata filtering
    - Multiple routing strategies
    - Event transformation support
    - Performance monitoring
    - Rule hot-reloading
    
    Usage:
        # Initialize router
        router = EventRouter()
        
        # Add routing rules
        rule = RoutingRule(
            rule_id="user_events",
            name="Route User Events",
            event_types={"UserCreated", "UserUpdated"},
            target_handlers=["user_handler", "audit_handler"],
            strategy=RoutingStrategy.BROADCAST
        )
        router.add_rule(rule)
        
        # Route event
        routing_info = router.route(user_created_event)
        
        if routing_info.should_route:
            for handler in routing_info.target_handlers:
                await handler.handle(event)
    """
    
    def __init__(self):
        """Initialize event router."""
        self._rules: list[RoutingRule] = []
        self._rules_by_id: dict[str, RoutingRule] = {}
        self._default_handlers: list[str] = []
        self._stats = {
            "events_routed": 0,
            "events_dropped": 0,
            "events_delayed": 0,
            "events_transformed": 0,
            "rules_matched": 0,
        }
        
        # Add default routing rules for identity events
        self._add_default_rules()
        
        logger.info("EventRouter initialized with default rules")
    
    def add_rule(self, rule: RoutingRule) -> None:
        """
        Add a routing rule.
        
        Args:
            rule: Routing rule to add
        """
        if rule.rule_id in self._rules_by_id:
            self.remove_rule(rule.rule_id)
        
        self._rules.append(rule)
        self._rules_by_id[rule.rule_id] = rule
        
        # Sort rules by priority (higher priority first)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        
        logger.debug(
            "Routing rule added",
            rule_id=rule.rule_id,
            name=rule.name,
            priority=rule.priority,
            event_types=list(rule.event_types),
        )
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a routing rule.
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            bool: True if rule was removed
        """
        if rule_id not in self._rules_by_id:
            return False
        
        rule = self._rules_by_id[rule_id]
        self._rules.remove(rule)
        del self._rules_by_id[rule_id]
        
        logger.debug("Routing rule removed", rule_id=rule_id)
        return True
    
    def get_rule(self, rule_id: str) -> RoutingRule | None:
        """Get routing rule by ID."""
        return self._rules_by_id.get(rule_id)
    
    def list_rules(self) -> list[RoutingRule]:
        """Get all routing rules."""
        return self._rules.copy()
    
    def route(self, event: IdentityDomainEvent) -> RoutingInfo:
        """
        Route an event using configured rules.
        
        Args:
            event: Event to route
            
        Returns:
            RoutingInfo: Routing information and targets
        """
        event_type = event.__class__.__name__
        routing_info = RoutingInfo(
            event_type=event_type,
            decision=RoutingDecision.ROUTE,
            strategy=RoutingStrategy.DIRECT,
        )
        
        # Apply routing rules in priority order
        for rule in self._rules:
            if rule.matches_event(event):
                self._apply_rule(event, rule, routing_info)
                routing_info.applied_rules.append(rule.rule_id)
                self._stats["rules_matched"] += 1
                
                # Stop at first matching rule unless it's a transform
                if rule.decision != RoutingDecision.TRANSFORM:
                    break
        
        # Apply default routing if no rules matched
        if not routing_info.applied_rules:
            self._apply_default_routing(event, routing_info)
        
        # Update statistics
        if routing_info.should_route:
            self._stats["events_routed"] += 1
        elif routing_info.should_drop:
            self._stats["events_dropped"] += 1
        elif routing_info.should_delay:
            self._stats["events_delayed"] += 1
        
        logger.debug(
            "Event routed",
            event_type=event_type,
            decision=routing_info.decision.value,
            applied_rules=routing_info.applied_rules,
            target_handlers=routing_info.target_handlers,
            target_queues=routing_info.target_queues,
        )
        
        return routing_info
    
    def _apply_rule(
        self,
        event: IdentityDomainEvent,
        rule: RoutingRule,
        routing_info: RoutingInfo,
    ) -> None:
        """Apply a routing rule to an event."""
        # Set decision and strategy
        routing_info.decision = rule.decision
        routing_info.strategy = rule.strategy
        
        # Add targets
        routing_info.target_handlers.extend(rule.target_handlers)
        routing_info.target_queues.extend(rule.target_queues)
        
        # Set delay
        if rule.delay_seconds > 0:
            routing_info.delay_seconds = max(routing_info.delay_seconds, rule.delay_seconds)
        
        # Apply transformation if specified
        if rule.transform_func:
            try:
                transformed_event = rule.transform_func(event)
                routing_info.transformations.append(rule.rule_id)
                self._stats["events_transformed"] += 1
                
                logger.debug(
                    "Event transformed",
                    rule_id=rule.rule_id,
                    original_type=event.__class__.__name__,
                    transformed_type=transformed_event.__class__.__name__,
                )
            except Exception as e:
                logger.exception(
                    "Event transformation failed",
                    rule_id=rule.rule_id,
                    event_type=event.__class__.__name__,
                    error=str(e),
                )
        
        # Add rule metadata
        routing_info.metadata[f"rule_{rule.rule_id}"] = {
            "name": rule.name,
            "priority": rule.priority,
            "tags": list(rule.tags),
        }
    
    def _apply_default_routing(
        self,
        event: IdentityDomainEvent,
        routing_info: RoutingInfo,
    ) -> None:
        """Apply default routing for events with no matching rules."""
        # Route to default handlers
        routing_info.target_handlers.extend(self._default_handlers)
        
        # Route based on event characteristics
        if event.is_security_event():
            routing_info.target_handlers.append("security_handler")
            routing_info.target_queues.append("security_events")
        
        if event.is_compliance_event():
            routing_info.target_handlers.append("compliance_handler")
            routing_info.target_queues.append("compliance_events")
        
        # Route based on risk level
        risk_level = event.get_risk_level()
        if risk_level == "high":
            routing_info.target_handlers.append("high_priority_handler")
            routing_info.target_queues.append("high_priority_events")
        elif risk_level == "critical":
            routing_info.target_handlers.append("critical_handler")
            routing_info.target_queues.append("critical_events")
            routing_info.strategy = RoutingStrategy.BROADCAST
        
        # Default to audit handler if no other targets
        if not routing_info.has_targets:
            routing_info.target_handlers.append("audit_handler")
            routing_info.target_queues.append("audit_events")
    
    def _add_default_rules(self) -> None:
        """Add default routing rules for identity events."""
        # High-priority security events
        security_rule = RoutingRule(
            rule_id="security_events",
            name="Security Events",
            description="Route security events to security handlers",
            priority=100,
            event_types={
                "SecurityAlertRaised",
                "SuspiciousActivityDetected",
                "AccountLockedOut",
                "LoginFailed",
                "ComplianceViolationDetected",
            },
            target_handlers=["security_handler", "alert_handler"],
            target_queues=["security_events", "alerts"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(security_rule)
        
        # User lifecycle events
        user_lifecycle_rule = RoutingRule(
            rule_id="user_lifecycle",
            name="User Lifecycle Events",
            description="Route user lifecycle events",
            priority=80,
            event_types={
                "UserCreated",
                "UserActivated",
                "UserSuspended",
                "UserDeactivated",
                "UserDeleted",
                "UserReactivated",
            },
            target_handlers=["user_handler", "audit_handler"],
            target_queues=["user_events", "audit_events"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(user_lifecycle_rule)
        
        # Authentication events
        auth_rule = RoutingRule(
            rule_id="authentication_events",
            name="Authentication Events",
            description="Route authentication-related events",
            priority=90,
            event_types={
                "LoginSuccessful",
                "LoginFailed",
                "PasswordChanged",
                "PasswordExpired",
                "MFAEnabled",
                "MFADisabled",
            },
            target_handlers=["auth_handler", "security_handler"],
            target_queues=["auth_events", "security_events"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(auth_rule)
        
        # Group events
        group_rule = RoutingRule(
            rule_id="group_events",
            name="Group Events",
            description="Route group-related events",
            priority=70,
            event_type_patterns=[re.compile(r".*Group.*"), re.compile(r".*Member.*")],
            target_handlers=["group_handler", "audit_handler"],
            target_queues=["group_events", "audit_events"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(group_rule)
        
        # Role and permission events
        rbac_rule = RoutingRule(
            rule_id="rbac_events",
            name="RBAC Events",
            description="Route role and permission events",
            priority=85,
            event_types={
                "RoleAssigned",
                "RoleUnassigned",
                "PermissionGranted",
                "PermissionRevoked",
                "PermissionAddedToRole",
                "PermissionRemovedFromRole",
            },
            target_handlers=["rbac_handler", "security_handler", "audit_handler"],
            target_queues=["rbac_events", "security_events", "audit_events"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(rbac_rule)
        
        # Compliance events
        compliance_rule = RoutingRule(
            rule_id="compliance_events",
            name="Compliance Events", 
            description="Route compliance-related events",
            priority=95,
            event_types={
                "UserExported",
                "ConsentGranted",
                "ConsentRevoked",
                "AuditLogCreated",
                "ComplianceViolationDetected",
            },
            target_handlers=["compliance_handler", "audit_handler"],
            target_queues=["compliance_events", "audit_events"],
            strategy=RoutingStrategy.BROADCAST,
        )
        self.add_rule(compliance_rule)
    
    def get_statistics(self) -> dict[str, Any]:
        """Get router statistics."""
        return {
            "total_rules": len(self._rules),
            "enabled_rules": len([r for r in self._rules if r.enabled]),
            "default_handlers": len(self._default_handlers),
            **self._stats,
        }
    
    def reset_statistics(self) -> None:
        """Reset router statistics."""
        self._stats = {
            "events_routed": 0,
            "events_dropped": 0,
            "events_delayed": 0,
            "events_transformed": 0,
            "rules_matched": 0,
        }