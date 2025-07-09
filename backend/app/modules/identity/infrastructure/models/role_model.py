"""
Role Model

SQLModel definition for role persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.modules.identity.domain.entities.role.role import Role
from app.modules.identity.domain.entities.role.role_enums import InheritanceMode


class RoleModel(SQLModel, table=True):
    """Role persistence model."""
    
    __tablename__ = "roles"
    
    # Identity
    id: UUID = Field(primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str
    level: int = Field(default=0, index=True)
    
    # Hierarchy
    parent_role_id: UUID | None = Field(default=None, index=True, foreign_key="roles.id")
    parent_roles: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Permissions
    permissions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    denied_permissions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Inheritance
    inheritance_mode: str = Field(default=InheritanceMode.FULL.value)
    permission_rules: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Conditional permissions
    conditional_permissions: dict[str, dict[str, Any]] = Field(default_factory=dict, sa_column=Column(JSON))
    permission_scopes: dict[str, dict[str, Any]] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Role composition
    includes_roles: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    excludes_roles: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    
    # Template properties
    is_template: bool = Field(default=False)
    template_variables: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    expires_at: datetime | None = Field(default=None)
    
    # Status
    is_system: bool = Field(default=False, index=True)
    is_active: bool = Field(default=True, index=True)
    
    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    @classmethod
    def from_domain(cls, role: Role) -> "RoleModel":
        """Create model from domain entity."""
        return cls(
            id=role.id,
            name=role.name,
            description=role.description,
            level=role.level,
            parent_role_id=role.parent_role_id,
            parent_roles=[str(pid) for pid in role.parent_roles],
            permissions=role.permissions,
            denied_permissions=role.denied_permissions,
            inheritance_mode=role.inheritance_mode.value,
            permission_rules=role.permission_rules,
            conditional_permissions=role.conditional_permissions,
            permission_scopes={
                perm: scope.to_dict() for perm, scope in role.permission_scopes.items()
            },
            includes_roles=[str(rid) for rid in role.includes_roles],
            excludes_roles=[str(rid) for rid in role.excludes_roles],
            is_template=role.is_template,
            template_variables=role.template_variables,
            expires_at=role.expires_at,
            is_system=role.is_system,
            is_active=role.is_active,
            metadata=role.metadata,
            created_at=role.created_at,
            updated_at=role.updated_at
        )
    
    def to_domain(self) -> Role:
        """Convert to domain entity."""
        from app.modules.identity.domain.value_objects.permission_scope import (
            PermissionScope,
        )
        
        role = Role(
            id=self.id,
            name=self.name,
            description=self.description,
            level=self.level,
            parent_role_id=self.parent_role_id,
            permissions=self.permissions,
            is_system=self.is_system,
            is_active=self.is_active,
            created_at=self.created_at,
            updated_at=self.updated_at,
            metadata=self.metadata,
            parent_roles=[UUID(pid) for pid in self.parent_roles],
            inheritance_mode=InheritanceMode(self.inheritance_mode),
            permission_rules=self.permission_rules,
            denied_permissions=self.denied_permissions,
            conditional_permissions=self.conditional_permissions,
            permission_scopes={
                perm: PermissionScope.from_dict(scope_dict)
                for perm, scope_dict in self.permission_scopes.items()
            },
            includes_roles=[UUID(rid) for rid in self.includes_roles],
            excludes_roles=[UUID(rid) for rid in self.excludes_roles],
            is_template=self.is_template,
            template_variables=self.template_variables,
            expires_at=self.expires_at
        )
        
        return role
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "level": self.level,
            "parent_role_id": str(self.parent_role_id) if self.parent_role_id else None,
            "parent_roles": self.parent_roles,
            "permissions": self.permissions,
            "denied_permissions": self.denied_permissions,
            "inheritance_mode": self.inheritance_mode,
            "permission_rules": self.permission_rules,
            "conditional_permissions": self.conditional_permissions,
            "permission_scopes": self.permission_scopes,
            "includes_roles": self.includes_roles,
            "excludes_roles": self.excludes_roles,
            "is_template": self.is_template,
            "template_variables": self.template_variables,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_system": self.is_system,
            "is_active": self.is_active,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }


class RoleUserAssociation(SQLModel, table=True):
    """Many-to-many association between roles and users."""
    
    __tablename__ = "role_user_associations"
    
    role_id: UUID = Field(primary_key=True, foreign_key="roles.id")
    user_id: UUID = Field(primary_key=True, foreign_key="users.id")
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assigned_by: UUID | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    
    # Add indexes for queries
    __table_args__ = (
        {"extend_existing": True}
    )


class RolePermissionAssociation(SQLModel, table=True):
    """Many-to-many association between roles and permissions."""
    
    __tablename__ = "role_permission_associations"
    
    role_id: UUID = Field(primary_key=True, foreign_key="roles.id")
    permission_id: UUID = Field(primary_key=True, foreign_key="permissions.id")
    granted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    granted_by: UUID | None = Field(default=None)
    conditions: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    
    # Add indexes for queries
    __table_args__ = (
        {"extend_existing": True}
    )