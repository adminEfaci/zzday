"""
MFA Service Interfaces

Multi-factor authentication service protocols and interfaces.
"""

from .mfa_service import IMFAService

__all__ = [
    "IMFAService",
]

# Metadata
__version__ = "1.0.0"
__domain__ = "identity"