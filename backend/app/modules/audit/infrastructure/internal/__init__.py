"""
Internal Adapters for Audit Module

These adapters handle communication with other modules through
their contracts, ensuring proper module boundaries.
"""

from .identity_adapter import IdentityAdapter

__all__ = [
    "IdentityAdapter",
]