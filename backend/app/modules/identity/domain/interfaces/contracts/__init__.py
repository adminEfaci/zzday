"""
Domain Contracts

Contracts for cross-module communication.
These interfaces define how the Identity domain communicates with other modules.
"""

from .audit_contract import IAuditContract
from .notification_contract import INotificationContract

__all__ = [
    'IAuditContract',
    'INotificationContract'
]