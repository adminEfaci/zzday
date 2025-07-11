"""
Identity Domain Entities

This module contains all entity definitions for the identity domain.
Entities represent objects with identity that can change over time while maintaining
their conceptual identity.
"""

# Import all entities from subdirectories
from .group import *
from .session import *
from .shared import *
from .user import *

__all__ = [
    # All exports are re-exported from subdirectories
]

# Metadata
__version__ = "1.0.0"
__domain__ = "identity"