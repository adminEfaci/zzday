"""
Event Handler Registry

Provides handler registration, discovery, and management capabilities
for the identity domain event handling system.
"""

import inspect
import pkgutil
from collections import defaultdict
from typing import Any

from app.core.errors import ValidationError
from app.core.logging import get_logger

from .base import EventHandlerBase, HandlerPriority

logger = get_logger(__name__)


class EventHandlerRegistry:
    """
    Registry for event handlers with discovery and management capabilities.
    
    Provides centralized handler registration, discovery, filtering, and
    lifecycle management for all identity domain event handlers.
    
    Design Features:
    - Automatic handler discovery from packages
    - Type-safe handler registration
    - Flexible handler filtering and querying
    - Handler lifecycle management
    - Performance optimization with caching
    - Comprehensive validation and error handling
    
    Usage Example:
        registry = EventHandlerRegistry()
        
        # Register handlers manually
        registry.register_handler(UserCreatedHandler())
        
        # Auto-discover handlers from package
        registry.discover_handlers("app.modules.identity.infrastructure.events.handlers.user")
        
        # Get handlers for event
        handlers = registry.get_handlers_for_event("UserCreated")
        
        # Filter handlers
        high_priority_handlers = registry.get_handlers_by_priority(HandlerPriority.HIGH)
    """
    
    def __init__(self):
        """Initialize the handler registry."""
        self._handlers: dict[str, EventHandlerBase] = {}
        self._event_type_mapping: dict[str, set[str]] = defaultdict(set)
        self._priority_mapping: dict[HandlerPriority, set[str]] = defaultdict(set)
        self._category_mapping: dict[str, set[str]] = defaultdict(set)
        self._tag_mapping: dict[str, set[str]] = defaultdict(set)
        self._enabled_handlers: set[str] = set()
        
        # Discovery configuration
        self._auto_discovery_paths: list[str] = []
        self._discovered_packages: set[str] = set()
        
        logger.info("Event handler registry initialized")
    
    def register_handler(self, handler: EventHandlerBase) -> None:
        """
        Register an event handler.
        
        Args:
            handler: Event handler instance to register
            
        Raises:
            ValidationError: If handler is invalid or already registered
        """
        if not isinstance(handler, EventHandlerBase):
            raise ValidationError("Handler must be an instance of EventHandlerBase")
        
        handler_id = handler.metadata.handler_id
        
        # Check for duplicate registration
        if handler_id in self._handlers:
            existing_handler = self._handlers[handler_id]
            if existing_handler.__class__ == handler.__class__:
                logger.warning(f"Handler {handler_id} already registered, skipping")
                return
            raise ValidationError(f"Handler ID {handler_id} already registered with different class")
        
        # Validate handler
        self._validate_handler(handler)
        
        # Register handler
        self._handlers[handler_id] = handler
        
        # Update mappings
        self._update_mappings(handler)
        
        logger.info(
            f"Registered handler {handler.metadata.handler_name}",
            handler_id=handler_id,
            event_types=list(handler.metadata.event_types),
            priority=handler.metadata.priority.name,
            category=handler.metadata.category
        )
    
    def unregister_handler(self, handler_id: str) -> bool:
        """
        Unregister an event handler.
        
        Args:
            handler_id: ID of handler to unregister
            
        Returns:
            bool: True if handler was unregistered, False if not found
        """
        if handler_id not in self._handlers:
            logger.warning(f"Handler {handler_id} not found for unregistration")
            return False
        
        handler = self._handlers[handler_id]
        
        # Remove from mappings
        self._remove_from_mappings(handler)
        
        # Remove from registry
        del self._handlers[handler_id]
        
        logger.info(f"Unregistered handler {handler.metadata.handler_name}", handler_id=handler_id)
        return True
    
    def get_handler(self, handler_id: str) -> EventHandlerBase | None:
        """
        Get a specific handler by ID.
        
        Args:
            handler_id: Handler ID
            
        Returns:
            EventHandlerBase | None: Handler instance or None if not found
        """
        return self._handlers.get(handler_id)
    
    def get_all_handlers(self) -> list[EventHandlerBase]:
        """
        Get all registered handlers.
        
        Returns:
            List[EventHandlerBase]: List of all handlers
        """
        return list(self._handlers.values())
    
    def get_enabled_handlers(self) -> list[EventHandlerBase]:
        """
        Get all enabled handlers.
        
        Returns:
            List[EventHandlerBase]: List of enabled handlers
        """
        return [
            handler for handler in self._handlers.values()
            if handler.metadata.enabled
        ]
    
    def get_handlers_for_event(self, event_type: str) -> list[EventHandlerBase]:
        """
        Get handlers that can process a specific event type.
        
        Args:
            event_type: Event type name
            
        Returns:
            List[EventHandlerBase]: List of handlers sorted by priority
        """
        handler_ids = self._event_type_mapping.get(event_type, set())
        handlers = [
            self._handlers[handler_id] 
            for handler_id in handler_ids
            if handler_id in self._handlers and self._handlers[handler_id].metadata.enabled
        ]
        
        # Sort by priority (highest first)
        handlers.sort(key=lambda h: h.metadata.priority.value, reverse=True)
        
        return handlers
    
    def get_handlers_by_priority(self, priority: HandlerPriority) -> list[EventHandlerBase]:
        """
        Get handlers with specific priority.
        
        Args:
            priority: Handler priority
            
        Returns:
            List[EventHandlerBase]: List of handlers with specified priority
        """
        handler_ids = self._priority_mapping.get(priority, set())
        return [
            self._handlers[handler_id]
            for handler_id in handler_ids
            if handler_id in self._handlers
        ]
    
    def get_handlers_by_category(self, category: str) -> list[EventHandlerBase]:
        """
        Get handlers in specific category.
        
        Args:
            category: Handler category
            
        Returns:
            List[EventHandlerBase]: List of handlers in category
        """
        handler_ids = self._category_mapping.get(category, set())
        return [
            self._handlers[handler_id]
            for handler_id in handler_ids
            if handler_id in self._handlers
        ]
    
    def get_handlers_by_tag(self, tag: str) -> list[EventHandlerBase]:
        """
        Get handlers with specific tag.
        
        Args:
            tag: Handler tag
            
        Returns:
            List[EventHandlerBase]: List of handlers with tag
        """
        handler_ids = self._tag_mapping.get(tag, set())
        return [
            self._handlers[handler_id]
            for handler_id in handler_ids
            if handler_id in self._handlers
        ]
    
    def enable_handler(self, handler_id: str) -> bool:
        """
        Enable a specific handler.
        
        Args:
            handler_id: Handler ID
            
        Returns:
            bool: True if handler was enabled, False if not found
        """
        if handler_id not in self._handlers:
            return False
        
        handler = self._handlers[handler_id]
        handler.enable()
        self._enabled_handlers.add(handler_id)
        
        logger.info(f"Enabled handler {handler.metadata.handler_name}", handler_id=handler_id)
        return True
    
    def disable_handler(self, handler_id: str) -> bool:
        """
        Disable a specific handler.
        
        Args:
            handler_id: Handler ID
            
        Returns:
            bool: True if handler was disabled, False if not found
        """
        if handler_id not in self._handlers:
            return False
        
        handler = self._handlers[handler_id]
        handler.disable()
        self._enabled_handlers.discard(handler_id)
        
        logger.warning(f"Disabled handler {handler.metadata.handler_name}", handler_id=handler_id)
        return True
    
    def discover_handlers(self, package_path: str) -> int:
        """
        Auto-discover handlers from a package.
        
        Args:
            package_path: Python package path to discover handlers from
            
        Returns:
            int: Number of handlers discovered and registered
        """
        if package_path in self._discovered_packages:
            logger.debug(f"Package {package_path} already discovered, skipping")
            return 0
        
        discovered_count = 0
        
        try:
            # Import the package
            package = __import__(package_path, fromlist=[''])
            
            # Get package directory
            if hasattr(package, "__path__"):
                package_dir = package.__path__[0]
            else:
                logger.warning(f"Package {package_path} has no __path__, cannot discover")
                return 0
            
            # Walk through all modules in package
            for _importer, modname, _ispkg in pkgutil.walk_packages(
                [package_dir], 
                prefix=f"{package_path}."
            ):
                try:
                    # Import module
                    module = __import__(modname, fromlist=[''])
                    
                    # Find handler classes
                    for name in dir(module):
                        obj = getattr(module, name)
                        
                        # Check if it's a handler class (not the base class itself)
                        if (
                            inspect.isclass(obj) and
                            issubclass(obj, EventHandlerBase) and
                            obj is not EventHandlerBase and
                            not inspect.isabstract(obj)
                        ):
                            try:
                                # Create handler instance
                                handler = obj()
                                self.register_handler(handler)
                                discovered_count += 1
                                
                                logger.debug(
                                    f"Discovered handler {obj.__name__} from {modname}",
                                    handler_id=handler.metadata.handler_id
                                )
                            except Exception:
                                logger.exception(
                                    f"Failed to instantiate handler {obj.__name__} from {modname}"
                                )
                
                except Exception:
                    logger.exception(f"Failed to import module {modname}")
            
            # Mark package as discovered
            self._discovered_packages.add(package_path)
            
            logger.info(
                f"Discovered {discovered_count} handlers from package {package_path}",
                package=package_path,
                discovered_count=discovered_count
            )
            
        except Exception:
            logger.exception(
                f"Failed to discover handlers from package {package_path}",
                package=package_path
            )
        
        return discovered_count
    
    def get_registry_stats(self) -> dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Dict[str, Any]: Registry statistics
        """
        total_handlers = len(self._handlers)
        enabled_handlers = len(self._enabled_handlers)
        disabled_handlers = total_handlers - enabled_handlers
        
        # Count by priority
        priority_counts = {}
        for priority in HandlerPriority:
            priority_counts[priority.name] = len(self._priority_mapping[priority])
        
        # Count by category
        category_counts = {
            category: len(handler_ids)
            for category, handler_ids in self._category_mapping.items()
        }
        
        # Event type coverage
        event_type_counts = {
            event_type: len(handler_ids)
            for event_type, handler_ids in self._event_type_mapping.items()
        }
        
        return {
            "total_handlers": total_handlers,
            "enabled_handlers": enabled_handlers,
            "disabled_handlers": disabled_handlers,
            "discovered_packages": len(self._discovered_packages),
            "priority_distribution": priority_counts,
            "category_distribution": category_counts,
            "event_type_coverage": event_type_counts,
            "total_event_types": len(self._event_type_mapping),
        }
    
    def validate_registry(self) -> list[str]:
        """
        Validate all registered handlers.
        
        Returns:
            List[str]: List of validation errors
        """
        errors = []
        
        for handler_id, handler in self._handlers.items():
            try:
                self._validate_handler(handler)
            except ValidationError as e:
                errors.append(f"Handler {handler_id}: {e}")
        
        return errors
    
    def clear(self) -> None:
        """Clear all registered handlers."""
        self._handlers.clear()
        self._event_type_mapping.clear()
        self._priority_mapping.clear()
        self._category_mapping.clear()
        self._tag_mapping.clear()
        self._enabled_handlers.clear()
        self._discovered_packages.clear()
        
        logger.info("Handler registry cleared")
    
    def _validate_handler(self, handler: EventHandlerBase) -> None:
        """
        Validate a handler instance.
        
        Args:
            handler: Handler to validate
            
        Raises:
            ValidationError: If handler is invalid
        """
        # Validate metadata
        handler.metadata.validate()
        
        # Check that handler can handle at least one event type
        if not handler.metadata.event_types:
            raise ValidationError("Handler must support at least one event type")
        
        # Validate handle method
        if not hasattr(handler, "handle"):
            raise ValidationError("Handler must implement handle method")
        
        # Check if handle method has correct signature
        sig = inspect.signature(handler.handle)
        params = list(sig.parameters.keys())
        
        if len(params) < 2:
            raise ValidationError("Handler.handle must accept at least 2 parameters")
    
    def _update_mappings(self, handler: EventHandlerBase) -> None:
        """Update internal mappings when adding a handler."""
        handler_id = handler.metadata.handler_id
        
        # Update event type mapping
        for event_type in handler.metadata.event_types:
            self._event_type_mapping[event_type].add(handler_id)
        
        # Update priority mapping
        self._priority_mapping[handler.metadata.priority].add(handler_id)
        
        # Update category mapping
        self._category_mapping[handler.metadata.category].add(handler_id)
        
        # Update tag mapping
        for tag in handler.metadata.tags:
            self._tag_mapping[tag].add(handler_id)
        
        # Update enabled handlers
        if handler.metadata.enabled:
            self._enabled_handlers.add(handler_id)
    
    def _remove_from_mappings(self, handler: EventHandlerBase) -> None:
        """Remove handler from internal mappings."""
        handler_id = handler.metadata.handler_id
        
        # Remove from event type mapping
        for event_type in handler.metadata.event_types:
            self._event_type_mapping[event_type].discard(handler_id)
            # Clean up empty sets
            if not self._event_type_mapping[event_type]:
                del self._event_type_mapping[event_type]
        
        # Remove from priority mapping
        self._priority_mapping[handler.metadata.priority].discard(handler_id)
        if not self._priority_mapping[handler.metadata.priority]:
            del self._priority_mapping[handler.metadata.priority]
        
        # Remove from category mapping
        self._category_mapping[handler.metadata.category].discard(handler_id)
        if not self._category_mapping[handler.metadata.category]:
            del self._category_mapping[handler.metadata.category]
        
        # Remove from tag mapping
        for tag in handler.metadata.tags:
            self._tag_mapping[tag].discard(handler_id)
            if not self._tag_mapping[tag]:
                del self._tag_mapping[tag]
        
        # Remove from enabled handlers
        self._enabled_handlers.discard(handler_id)


# Global registry instance
_global_registry: EventHandlerRegistry | None = None


def get_global_registry() -> EventHandlerRegistry:
    """
    Get the global handler registry instance.
    
    Returns:
        EventHandlerRegistry: Global registry instance
    """
    global _global_registry  # noqa: PLW0603
    if _global_registry is None:
        _global_registry = EventHandlerRegistry()
    return _global_registry


def register_handler(handler: EventHandlerBase) -> None:
    """
    Register a handler with the global registry.
    
    Args:
        handler: Handler to register
    """
    get_global_registry().register_handler(handler)


def get_handlers_for_event(event_type: str) -> list[EventHandlerBase]:
    """
    Get handlers for an event type from the global registry.
    
    Args:
        event_type: Event type name
        
    Returns:
        List[EventHandlerBase]: List of handlers
    """
    return get_global_registry().get_handlers_for_event(event_type)


# Export all classes and functions
__all__ = [
    "EventHandlerRegistry",
    "get_global_registry",
    "get_handlers_for_event",
    "register_handler",
]