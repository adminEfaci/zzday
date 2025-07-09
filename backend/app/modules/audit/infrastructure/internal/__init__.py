"""
Internal adapters for Audit module.

These adapters provide the Audit module with access to other modules
following the established contract patterns.
"""

from .identity_adapter import IdentityAdapter

__all__ = [
    "IdentityAdapter",
]