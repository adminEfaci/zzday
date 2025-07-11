"""
Permission Model

SQLModel definition for permission persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel


class PermissionModel(SQLModel, table=True):
    """Permission persistence model."""
    
    __tablename__ = "permissions"
    
    # Identity
    id: UUID = Field(primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str
    resource: str = Field(index=True)
    action: str = Field(index=True)
    
    # Scope and conditions
    scope: str | None = Field(default=None)
    conditions: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    
    # Status
    is_system: bool = Field(default=False, index=True)
    is_active: bool = Field(default=True, index=True)
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "resource": self.resource,
            "action": self.action,
            "scope": self.scope,
            "conditions": self.conditions,
            "is_system": self.is_system,
            "is_active": self.is_active,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }