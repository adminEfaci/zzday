"""
EventFilter - Advanced Event Filtering and Routing

Provides sophisticated event filtering capabilities with support for complex criteria,
dynamic filtering rules, filter chaining, and performance-optimized filtering
operations.

Key Features:
- Advanced event filtering with complex criteria
- Dynamic filter rule management
- Filter chaining and composition
- Performance-optimized filtering operations
- Filter analytics and monitoring
- Content-based and metadata-based filtering
- Time-based and pattern-based filtering
- Security and compliance filtering
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from app.core.events.types import EventPriority
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class FilterOperator(Enum):
    """Filter comparison operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX_MATCH = "regex_match"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"


class FilterLogic(Enum):
    """Logical operators for combining filters."""
    AND = "and"
    OR = "or"
    NOT = "not"


class FilterResult(Enum):
    """Result of filter evaluation."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class FilterCriterion:
    """Individual filter criterion."""
    field_path: str
    operator: FilterOperator
    value: Any = None
    case_sensitive: bool = True
    
    def evaluate(self, event: IdentityDomainEvent) -> bool:
        """Evaluate this criterion against an event."""
        try:
            # Get field value from event
            field_value = self._get_field_value(event, self.field_path)
            
            # Apply operator
            return self._apply_operator(field_value, self.operator, self.value)
            
        except Exception as e:
            logger.debug(
                "Filter criterion evaluation error",
                field_path=self.field_path,
                operator=self.operator.value,
                error=str(e)
            )
            return False
    
    def _get_field_value(self, event: IdentityDomainEvent, field_path: str) -> Any:
        """Get value from event using dot notation."""
        try:
            value = event
            for attr in field_path.split('.'):
                value = getattr(value, attr)
            return value
        except AttributeError:
            return None
    
    def _apply_operator(self, field_value: Any, op: FilterOperator, expected_value: Any) -> bool:
        """Apply filter operator."""
        if op == FilterOperator.IS_NULL:
            return field_value is None
        if op == FilterOperator.IS_NOT_NULL:
            return field_value is not None
        
        if field_value is None:
            return False
        
        # String operations
        if isinstance(field_value, str) and not self.case_sensitive:
            field_value = field_value.lower()
            if isinstance(expected_value, str):
                expected_value = expected_value.lower()
        
        if op == FilterOperator.EQUALS:
            return field_value == expected_value
        if op == FilterOperator.NOT_EQUALS:
            return field_value != expected_value
        if op == FilterOperator.GREATER_THAN:
            return field_value > expected_value
        if op == FilterOperator.GREATER_THAN_OR_EQUAL:
            return field_value >= expected_value
        if op == FilterOperator.LESS_THAN:
            return field_value < expected_value
        if op == FilterOperator.LESS_THAN_OR_EQUAL:
            return field_value <= expected_value
        if op == FilterOperator.CONTAINS:
            return str(expected_value) in str(field_value)
        if op == FilterOperator.NOT_CONTAINS:
            return str(expected_value) not in str(field_value)
        if op == FilterOperator.STARTS_WITH:
            return str(field_value).startswith(str(expected_value))
        if op == FilterOperator.ENDS_WITH:
            return str(field_value).endswith(str(expected_value))
        if op == FilterOperator.REGEX_MATCH:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return bool(re.search(str(expected_value), str(field_value), flags))
        if op == FilterOperator.IN_LIST:
            return field_value in expected_value if isinstance(expected_value, list | tuple | set) else False
        if op == FilterOperator.NOT_IN_LIST:
            return field_value not in expected_value if isinstance(expected_value, list | tuple | set) else True
        
        return False


@dataclass
class FilterRule:
    """Represents a complete filter rule with multiple criteria."""
    rule_id: str
    name: str
    criteria: list[FilterCriterion] = field(default_factory=list)
    logic: FilterLogic = FilterLogic.AND
    enabled: bool = True
    priority: int = 100
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Performance tracking
    evaluation_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    
    def add_criterion(self, criterion: FilterCriterion) -> None:
        """Add a filter criterion to this rule."""
        self.criteria.append(criterion)
    
    def remove_criterion(self, index: int) -> bool:
        """Remove a filter criterion by index."""
        if 0 <= index < len(self.criteria):
            del self.criteria[index]
            return True
        return False
    
    def evaluate(self, event: IdentityDomainEvent) -> FilterResult:
        """Evaluate this filter rule against an event."""
        if not self.enabled:
            return FilterResult.PASS
        
        try:
            self.evaluation_count += 1
            
            if not self.criteria:
                self.pass_count += 1
                return FilterResult.PASS
            
            # Evaluate criteria based on logic
            if self.logic == FilterLogic.AND:
                result = all(criterion.evaluate(event) for criterion in self.criteria)
            elif self.logic == FilterLogic.OR:
                result = any(criterion.evaluate(event) for criterion in self.criteria)
            elif self.logic == FilterLogic.NOT:
                # For NOT logic, we negate the AND result of all criteria
                result = not all(criterion.evaluate(event) for criterion in self.criteria)
            else:
                result = True
            
            if result:
                self.pass_count += 1
                return FilterResult.PASS
            self.fail_count += 1
            return FilterResult.FAIL
                
        except Exception as e:
            self.error_count += 1
            logger.exception(
                "Filter rule evaluation error",
                rule_id=self.rule_id,
                error=str(e)
            )
            return FilterResult.ERROR
    
    def get_statistics(self) -> dict[str, Any]:
        """Get filter rule statistics."""
        pass_rate = (
            self.pass_count / self.evaluation_count
            if self.evaluation_count > 0 else 0.0
        )
        
        error_rate = (
            self.error_count / self.evaluation_count
            if self.evaluation_count > 0 else 0.0
        )
        
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'enabled': self.enabled,
            'criteria_count': len(self.criteria),
            'evaluation_count': self.evaluation_count,
            'pass_count': self.pass_count,
            'fail_count': self.fail_count,
            'error_count': self.error_count,
            'pass_rate': pass_rate,
            'error_rate': error_rate
        }


class BaseFilter(ABC):
    """Base class for specialized filters."""
    
    def __init__(self, filter_name: str):
        self.filter_name = filter_name
        self.filter_count = 0
        self.pass_count = 0
        self.fail_count = 0
    
    @abstractmethod
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter an event. Must be implemented by subclasses."""
    
    def get_statistics(self) -> dict[str, Any]:
        """Get filter statistics."""
        pass_rate = (
            self.pass_count / self.filter_count
            if self.filter_count > 0 else 0.0
        )
        
        return {
            'filter_name': self.filter_name,
            'filter_count': self.filter_count,
            'pass_count': self.pass_count,
            'fail_count': self.fail_count,
            'pass_rate': pass_rate
        }


class EventTypeFilter(BaseFilter):
    """Filters events based on event types."""
    
    def __init__(self, allowed_types: list[str] | None = None, blocked_types: list[str] | None = None):
        super().__init__("EventTypeFilter")
        self.allowed_types = set(allowed_types) if allowed_types else None
        self.blocked_types = set(blocked_types) if blocked_types else None
    
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter event based on type."""
        self.filter_count += 1
        event_type = event.__class__.__name__
        
        # Check blocked types first
        if self.blocked_types and event_type in self.blocked_types:
            self.fail_count += 1
            return FilterResult.FAIL
        
        # Check allowed types
        if self.allowed_types and event_type not in self.allowed_types:
            self.fail_count += 1
            return FilterResult.FAIL
        
        self.pass_count += 1
        return FilterResult.PASS


class SecurityFilter(BaseFilter):
    """Filters events based on security criteria."""
    
    def __init__(self):
        super().__init__("SecurityFilter")
        self.suspicious_patterns = [
            r'(?i)(sql\s+injection|script\s+injection)',
            r'(?i)(xss|cross.site.scripting)',
            r'(?i)(password|secret|token|key)\s*[=:]\s*["\']?\w+',
        ]
    
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter event based on security criteria."""
        self.filter_count += 1
        
        try:
            # Check if event is a security event
            if hasattr(event, 'is_security_event') and event.is_security_event():
                self.pass_count += 1
                return FilterResult.PASS
            
            # Check for suspicious patterns in event data
            event_data = str(event.to_dict())
            for pattern in self.suspicious_patterns:
                if re.search(pattern, event_data):
                    logger.warning(
                        "Suspicious pattern detected in event",
                        event_type=event.__class__.__name__,
                        pattern=pattern
                    )
                    self.fail_count += 1
                    return FilterResult.FAIL
            
            self.pass_count += 1
            return FilterResult.PASS
            
        except Exception as e:
            logger.exception("Security filter error", error=str(e))
            return FilterResult.ERROR


class TimeRangeFilter(BaseFilter):
    """Filters events based on time ranges."""
    
    def __init__(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        max_age_hours: int | None = None
    ):
        super().__init__("TimeRangeFilter")
        self.start_time = start_time
        self.end_time = end_time
        self.max_age_hours = max_age_hours
    
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter event based on time criteria."""
        self.filter_count += 1
        
        try:
            event_time = event.timestamp
            current_time = datetime.utcnow()
            
            # Check start time
            if self.start_time and event_time < self.start_time:
                self.fail_count += 1
                return FilterResult.FAIL
            
            # Check end time
            if self.end_time and event_time > self.end_time:
                self.fail_count += 1
                return FilterResult.FAIL
            
            # Check max age
            if self.max_age_hours:
                max_age = timedelta(hours=self.max_age_hours)
                if current_time - event_time > max_age:
                    self.fail_count += 1
                    return FilterResult.FAIL
            
            self.pass_count += 1
            return FilterResult.PASS
            
        except Exception as e:
            logger.exception("Time range filter error", error=str(e))
            return FilterResult.ERROR


class PriorityFilter(BaseFilter):
    """Filters events based on priority levels."""
    
    def __init__(self, min_priority: EventPriority = EventPriority.LOW):
        super().__init__("PriorityFilter")
        self.min_priority = min_priority
        self.priority_values = {
            EventPriority.LOW: 1,
            EventPriority.NORMAL: 2,
            EventPriority.HIGH: 3,
            EventPriority.CRITICAL: 4
        }
    
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter event based on priority."""
        self.filter_count += 1
        
        try:
            event_priority = getattr(event.metadata, 'priority', EventPriority.NORMAL)
            
            event_priority_value = self.priority_values.get(event_priority, 2)
            min_priority_value = self.priority_values.get(self.min_priority, 1)
            
            if event_priority_value >= min_priority_value:
                self.pass_count += 1
                return FilterResult.PASS
            self.fail_count += 1
            return FilterResult.FAIL
                
        except Exception as e:
            logger.exception("Priority filter error", error=str(e))
            return FilterResult.ERROR


class ContentFilter(BaseFilter):
    """Filters events based on content analysis."""
    
    def __init__(self):
        super().__init__("ContentFilter")
        self.blocked_content_patterns = [
            r'(?i)(spam|advertisement|promotion)',
            r'(?i)(test|debug|dummy).*event',
        ]
        self.required_fields = ['user_id', 'timestamp']
    
    def filter_event(self, event: IdentityDomainEvent) -> FilterResult:
        """Filter event based on content."""
        self.filter_count += 1
        
        try:
            event_dict = event.to_dict()
            
            # Check for required fields
            for field in self.required_fields:
                if field not in event_dict or event_dict[field] is None:
                    self.fail_count += 1
                    return FilterResult.FAIL
            
            # Check for blocked content patterns
            content = str(event_dict)
            for pattern in self.blocked_content_patterns:
                if re.search(pattern, content):
                    self.fail_count += 1
                    return FilterResult.FAIL
            
            self.pass_count += 1
            return FilterResult.PASS
            
        except Exception as e:
            logger.exception("Content filter error", error=str(e))
            return FilterResult.ERROR


@dataclass
class FilterChain:
    """Represents a chain of filters to be applied in sequence."""
    chain_id: str
    name: str
    filters: list[BaseFilter | FilterRule] = field(default_factory=list)
    fail_fast: bool = True  # Stop on first failure
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_filter(self, filter_obj: BaseFilter | FilterRule) -> None:
        """Add a filter to the chain."""
        self.filters.append(filter_obj)
    
    def remove_filter(self, index: int) -> bool:
        """Remove a filter from the chain."""
        if 0 <= index < len(self.filters):
            del self.filters[index]
            return True
        return False
    
    def evaluate(self, event: IdentityDomainEvent) -> FilterResult:
        """Evaluate the filter chain against an event."""
        if not self.enabled:
            return FilterResult.PASS
        
        results = []
        
        for filter_obj in self.filters:
            if isinstance(filter_obj, BaseFilter):
                result = filter_obj.filter_event(event)
            elif isinstance(filter_obj, FilterRule):
                result = filter_obj.evaluate(event)
            else:
                continue
            
            results.append(result)
            
            # Fail fast if enabled
            if self.fail_fast and result in [FilterResult.FAIL, FilterResult.ERROR]:
                return result
        
        # Determine overall result
        if FilterResult.ERROR in results:
            return FilterResult.ERROR
        if FilterResult.FAIL in results:
            return FilterResult.FAIL
        return FilterResult.PASS


class EventFilter:
    """
    Comprehensive event filtering system.
    
    Provides advanced event filtering capabilities with support for complex criteria,
    filter chaining, and performance monitoring.
    """
    
    def __init__(self, event_bus_adapter: 'EventBusAdapter'):
        """
        Initialize the event filter.
        
        Args:
            event_bus_adapter: Event bus adapter for integration
        """
        self.event_bus_adapter = event_bus_adapter
        
        # Built-in filters
        self.event_type_filter = EventTypeFilter()
        self.security_filter = SecurityFilter()
        self.time_range_filter = TimeRangeFilter()
        self.priority_filter = PriorityFilter()
        self.content_filter = ContentFilter()
        
        # Filter rules and chains
        self.filter_rules: dict[str, FilterRule] = {}
        self.filter_chains: dict[str, FilterChain] = {}
        
        # Performance tracking
        self.total_events_filtered = 0
        self.events_passed = 0
        self.events_failed = 0
        self.events_error = 0
        
        logger.info("EventFilter initialized")
    
    def add_filter_rule(self, rule: FilterRule) -> None:
        """Add a filter rule."""
        self.filter_rules[rule.rule_id] = rule
        
        logger.debug(
            "Filter rule added",
            rule_id=rule.rule_id,
            name=rule.name,
            criteria_count=len(rule.criteria)
        )
    
    def remove_filter_rule(self, rule_id: str) -> bool:
        """Remove a filter rule."""
        if rule_id in self.filter_rules:
            del self.filter_rules[rule_id]
            logger.debug("Filter rule removed", rule_id=rule_id)
            return True
        return False
    
    def get_filter_rule(self, rule_id: str) -> FilterRule | None:
        """Get a filter rule by ID."""
        return self.filter_rules.get(rule_id)
    
    def create_filter_chain(self, chain_id: str, name: str, fail_fast: bool = True) -> FilterChain:
        """Create a new filter chain."""
        chain = FilterChain(chain_id=chain_id, name=name, fail_fast=fail_fast)
        self.filter_chains[chain_id] = chain
        
        logger.debug("Filter chain created", chain_id=chain_id, name=name)
        return chain
    
    def get_filter_chain(self, chain_id: str) -> FilterChain | None:
        """Get a filter chain by ID."""
        return self.filter_chains.get(chain_id)
    
    def remove_filter_chain(self, chain_id: str) -> bool:
        """Remove a filter chain."""
        if chain_id in self.filter_chains:
            del self.filter_chains[chain_id]
            logger.debug("Filter chain removed", chain_id=chain_id)
            return True
        return False
    
    def filter_event(
        self,
        event: IdentityDomainEvent,
        rule_ids: list[str] | None = None,
        chain_ids: list[str] | None = None,
        use_built_in_filters: bool = True
    ) -> FilterResult:
        """
        Filter an event using specified rules and chains.
        
        Args:
            event: Event to filter
            rule_ids: Specific rule IDs to apply (if None, applies all)
            chain_ids: Specific chain IDs to apply (if None, applies all)
            use_built_in_filters: Whether to use built-in filters
            
        Returns:
            FilterResult: Overall filtering result
        """
        try:
            self.total_events_filtered += 1
            
            # Apply built-in filters
            if use_built_in_filters:
                built_in_results = [
                    self.security_filter.filter_event(event),
                    self.content_filter.filter_event(event)
                ]
                
                if FilterResult.FAIL in built_in_results or FilterResult.ERROR in built_in_results:
                    self.events_failed += 1
                    return FilterResult.FAIL
            
            # Apply filter rules
            rules_to_apply = (
                [self.filter_rules[rid] for rid in rule_ids if rid in self.filter_rules]
                if rule_ids
                else list(self.filter_rules.values())
            )
            
            for rule in rules_to_apply:
                result = rule.evaluate(event)
                if result in [FilterResult.FAIL, FilterResult.ERROR]:
                    self.events_failed += 1
                    return result
            
            # Apply filter chains
            chains_to_apply = (
                [self.filter_chains[cid] for cid in chain_ids if cid in self.filter_chains]
                if chain_ids
                else list(self.filter_chains.values())
            )
            
            for chain in chains_to_apply:
                result = chain.evaluate(event)
                if result in [FilterResult.FAIL, FilterResult.ERROR]:
                    self.events_failed += 1
                    return result
            
            # All filters passed
            self.events_passed += 1
            return FilterResult.PASS
            
        except Exception as e:
            self.events_error += 1
            logger.exception(
                "Event filtering failed",
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return FilterResult.ERROR
    
    def filter_by_type(
        self,
        event: IdentityDomainEvent,
        allowed_types: list[str] | None = None,
        blocked_types: list[str] | None = None
    ) -> FilterResult:
        """Filter event by type."""
        filter_obj = EventTypeFilter(allowed_types, blocked_types)
        return filter_obj.filter_event(event)
    
    def filter_by_priority(
        self,
        event: IdentityDomainEvent,
        min_priority: EventPriority = EventPriority.LOW
    ) -> FilterResult:
        """Filter event by priority."""
        filter_obj = PriorityFilter(min_priority)
        return filter_obj.filter_event(event)
    
    def filter_by_time_range(
        self,
        event: IdentityDomainEvent,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        max_age_hours: int | None = None
    ) -> FilterResult:
        """Filter event by time range."""
        filter_obj = TimeRangeFilter(start_time, end_time, max_age_hours)
        return filter_obj.filter_event(event)
    
    def create_simple_filter_rule(
        self,
        rule_id: str,
        name: str,
        field_path: str,
        operator: FilterOperator,
        value: Any,
        logic: FilterLogic = FilterLogic.AND
    ) -> FilterRule:
        """Create a simple filter rule with a single criterion."""
        rule = FilterRule(rule_id=rule_id, name=name, logic=logic)
        criterion = FilterCriterion(field_path=field_path, operator=operator, value=value)
        rule.add_criterion(criterion)
        
        self.add_filter_rule(rule)
        return rule
    
    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive filtering statistics."""
        pass_rate = (
            self.events_passed / self.total_events_filtered
            if self.total_events_filtered > 0 else 0.0
        )
        
        error_rate = (
            self.events_error / self.total_events_filtered
            if self.total_events_filtered > 0 else 0.0
        )
        
        # Get statistics from built-in filters
        built_in_stats = {
            'event_type_filter': self.event_type_filter.get_statistics(),
            'security_filter': self.security_filter.get_statistics(),
            'time_range_filter': self.time_range_filter.get_statistics(),
            'priority_filter': self.priority_filter.get_statistics(),
            'content_filter': self.content_filter.get_statistics()
        }
        
        # Get statistics from custom rules
        rule_stats = {
            rule_id: rule.get_statistics()
            for rule_id, rule in self.filter_rules.items()
        }
        
        return {
            'total_events_filtered': self.total_events_filtered,
            'events_passed': self.events_passed,
            'events_failed': self.events_failed,
            'events_error': self.events_error,
            'pass_rate': pass_rate,
            'error_rate': error_rate,
            'filter_rules_count': len(self.filter_rules),
            'filter_chains_count': len(self.filter_chains),
            'built_in_filters': built_in_stats,
            'custom_rules': rule_stats
        }