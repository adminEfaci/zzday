"""Integration event handlers.

This module provides event handlers for cross-module integration,
subscribing to events from other modules as defined in shared contracts.
"""

from typing import TYPE_CHECKING

from .user_deactivated_handler import UserDeactivatedEventHandler
from .user_registered_handler import UserRegisteredEventHandler
from .user_role_changed_handler import UserRoleChangedEventHandler

if TYPE_CHECKING:
    from app.core.events.bus import EventBus


def register_integration_event_handlers(event_bus: "EventBus") -> None:
    """Register all integration module event handlers with the event bus."""
    # Initialize and register event handlers
    UserRegisteredEventHandler()
    UserRoleChangedEventHandler()
    UserDeactivatedEventHandler()

    # Register handlers with event bus
    # This would typically involve registering specific event types
    # with their corresponding handler methods
    # Implementation depends on event bus interface


__all__ = [
    "UserDeactivatedEventHandler",
    "UserRegisteredEventHandler",
    "UserRoleChangedEventHandler",
    "register_integration_event_handlers",
]
