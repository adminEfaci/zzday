"""
Internal adapters for Identity module.

These adapters provide the Identity module with access to other modules
following the established contract patterns and maintaining proper
module boundaries.
"""

from .audit_adapter import AuditAdapter
from .integration_adapter import IntegrationAdapter
from .notification_adapter import NotificationAdapter

__all__ = [
    "AuditAdapter",
    "IntegrationAdapter",
    "NotificationAdapter",
]