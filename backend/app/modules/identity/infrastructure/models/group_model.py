"""
Group Model

SQLModel definition for group persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, Relationship, SQLModel


class GroupModel(SQLModel, table=True):
    """Group persistence model."""
    
    __tablename__ = "groups"
    
    # Core identity
    id: UUID = Field(primary_key=True)
    name: str = Field(index=True)
    description: str = Field(default="")
    
    # Group properties
    group_type: str = Field(index=True)
    status: str = Field(index=True)
    visibility: str = Field(default="private")
    join_method: str = Field(default="request")
    
    # Hierarchy
    parent_group_id: UUID | None = Field(default=None, foreign_key="groups.id", index=True)
    nesting_level: int = Field(default=0)
    
    # Settings
    max_members: int = Field(default=1000)
    allow_nested_groups: bool = Field(default=True)
    allow_guest_members: bool = Field(default=False)
    require_approval: bool = Field(default=False)
    auto_approve_members: bool = Field(default=False)
    
    # Metadata
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    settings: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Statistics
    member_count: int = Field(default=0)
    owner_count: int = Field(default=0)
    subgroup_count: int = Field(default=0)
    
    # Ownership tracking
    owner_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_by: UUID = Field(index=True)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    archived_at: datetime | None = Field(default=None)
    deleted_at: datetime | None = Field(default=None, index=True)
    
    # Relationships
    members: list["GroupMemberModel"] = Relationship(back_populates="group")


class GroupMemberModel(SQLModel, table=True):
    """Group member persistence model."""
    
    __tablename__ = "group_members"
    
    # Identity
    id: UUID = Field(primary_key=True)
    group_id: UUID = Field(foreign_key="groups.id", index=True)
    user_id: UUID = Field(index=True)
    
    # Membership details
    role: str = Field(index=True)
    membership_type: str = Field(default="direct")
    
    # Tracking
    joined_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    invited_by: UUID | None = Field(default=None)
    expires_at: datetime | None = Field(default=None, index=True)
    
    # Status
    is_active: bool = Field(default=True, index=True)
    
    # Metadata
    permissions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    # Relationships
    group: GroupModel = Relationship(back_populates="members")
    
    # Composite unique constraint
    class Config:
        # Ensure one membership per user per group
        constraints = [
            {"name": "unique_group_user", "unique": True, "fields": ["group_id", "user_id"]}
        ]