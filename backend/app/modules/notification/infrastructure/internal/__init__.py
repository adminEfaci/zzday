"""
Internal adapters for Notification module.

These adapters provide the Notification module with access to other modules,
especially the Integration module for external communications.
"""

from .integration_adapter import IntegrationAdapter

__all__ = [
    "IntegrationAdapter",
]