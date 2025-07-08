"""
GraphQL Subscription Resolvers for Identity Module

This module provides real-time subscription capabilities for identity-related events.
Includes comprehensive WebSocket connection management, authorization, and monitoring.
"""

from .administrative_subscriptions import AdministrativeSubscriptions
from .audit_compliance_subscriptions import AuditComplianceSubscriptions
from .base_subscription import (
    BaseSubscriptionResolver,
    SubscriptionContext,
    SubscriptionError,
)
from .security_event_subscriptions import SecurityEventSubscriptions
from .session_management_subscriptions import SessionManagementSubscriptions
from .subscription_manager import SubscriptionManager
from .user_status_subscriptions import UserStatusSubscriptions

__all__ = [
    "AdministrativeSubscriptions",
    "AuditComplianceSubscriptions",
    "BaseSubscriptionResolver",
    "SecurityEventSubscriptions",
    "SessionManagementSubscriptions",
    "SubscriptionContext",
    "SubscriptionError",
    "SubscriptionManager",
    "UserStatusSubscriptions",
]