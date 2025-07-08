"""
Value objects for group configuration.

Contains configuration objects to reduce function argument counts
in group-related operations.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class GroupMemberConfig:
    """Configuration for group member operations."""
    
    user_id: UUID
    role: str  # GroupMemberRole enum value
    membership_type: str  # GroupMembershipType enum value
    invited_by: UUID | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class GroupCreationConfig:
    """Configuration for group creation."""
    
    name: str
    description: str | None = None
    visibility: str = "private"  # GroupVisibility enum value
    group_type: str = "standard"  # GroupType enum value
    max_members: int | None = None
    auto_join: bool = False
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class GroupSettingsConfig:
    """Configuration for group settings update."""
    
    name: str | None = None
    description: str | None = None
    visibility: str | None = None
    auto_join: bool | None = None
    max_members: int | None = None
    metadata: dict[str, Any] | None = None