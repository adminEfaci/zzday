"""
Identity Domain Aggregates

Main aggregate roots for the identity domain following DDD patterns.
Each aggregate is responsible for maintaining consistency within its boundaries
and coordinating with other aggregates through domain events.
"""

# Aggregate Roots
from .group import (
    Group,
    GroupInvitation,
    GroupMembershipRequest,
)
from .user import User

# Quick access collections
IDENTITY_AGGREGATES = [Group, User]
GROUP_AGGREGATES = [Group, GroupInvitation, GroupMembershipRequest]

__all__ = [
    # === MAIN AGGREGATES ===
    "Group",
    "User",
    
    # === GROUP SUB-AGGREGATES ===
    "GroupInvitation",
    "GroupMembershipRequest",
    
    # === COLLECTIONS ===
    "IDENTITY_AGGREGATES",
    "GROUP_AGGREGATES",
]

# Metadata
__version__ = "1.0.0"
__domain__ = "identity"