"""
Identity Module Event Integration Layer

This module provides seamless integration between the identity module's event system
and the core event bus, implementing event workflows and cross-module communication.

Key Components:
- EventBusAdapter: Adapts identity events to core event bus
- EventWorkflowEngine: Manages complex event workflows
- EventSaga: Implements long-running business processes
- EventSubscriptionManager: Manages event subscriptions
- EventTransformer: Transforms events between different formats
- EventFilter: Filters events based on criteria
- CrossModuleEventBridge: Handles inter-module event communication

Workflows:
- UserRegistrationWorkflow: Complete user registration process
- PasswordResetWorkflow: Password reset process
- UserSuspensionWorkflow: User suspension and reinstatement
- SecurityIncidentWorkflow: Security incident response
- DataExportWorkflow: GDPR data export requests
"""

from .adapter import EventBusAdapter
from .bridge import CrossModuleEventBridge
from .engine import EventWorkflowEngine
from .filter import EventFilter
from .saga import EventSaga
from .subscription_manager import EventSubscriptionManager
from .transformer import EventTransformer

__all__ = [
    'CrossModuleEventBridge',
    'EventBusAdapter',
    'EventFilter',
    'EventSaga',
    'EventSubscriptionManager',
    'EventTransformer',
    'EventWorkflowEngine',
]