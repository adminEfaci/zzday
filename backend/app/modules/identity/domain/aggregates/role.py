"""
Role Aggregate Root

Manages role definitions, permissions, and hierarchies in the identity domain.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import AggregateRoot

from ..enums import RoleStatus, RoleType
from ..value_objects import RoleName
from .role_events import (
    RoleCreated, RoleUpdated, RoleDeleted, RoleActivated, RoleDeactivated,
    RolePermissionGranted, RolePermissionRevoked, RoleHierarchyChanged
)


@dataclass
class Role(AggregateRoot):
    """
    Role aggregate root - manages role definitions and permissions.
    
    Aggregate Boundaries:
    - Role identity and metadata
    - Permission assignments to roles
    - Role hierarchies and inheritance
    - Role status and lifecycle
    
    External Concerns:
    - User-role assignments -> User aggregate
    - Permission validation -> Domain services
    """
    
    # Core identity
    id: UUID
    name: RoleName
    created_at: datetime
    
    # Mutable properties
    display_name: str
    description: str
    status: RoleStatus
    role_type: RoleType
    updated_at: datetime
    
    # Permissions and hierarchy
    _permission_ids: set[UUID] = field(default_factory=set, init=False)
    _parent_role_ids: set[UUID] = field(default_factory=set, init=False)
    _child_role_ids: set[UUID] = field(default_factory=set, init=False)
    
    # Role properties
    is_system_role: bool = False
    is_inheritable: bool = True
    max_assignees: int | None = None
    
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    
    # Lifecycle tracking
    created_by: UUID
    updated_by: UUID | None = None
    deleted_at: datetime | None = None
    deleted_by: UUID | None = None
    
    def __post_init__(self):
        """Initialize role aggregate with validation."""
        super().__post_init__()
        self._validate_invariants()
    
    def _validate_invariants(self) -> None:
        """Validate domain invariants."""
        if not isinstance(self.name, RoleName):
            raise ValueError("Name must be a RoleName value object")
        
        if not isinstance(self.status, RoleStatus):
            raise ValueError("Status must be a RoleStatus enum")
        
        if not isinstance(self.role_type, RoleType):
            raise ValueError("Role type must be a RoleType enum")
        
        if not self.display_name.strip():
            raise ValueError("Display name cannot be empty")
        
        if self.max_assignees is not None and self.max_assignees < 0:
            raise ValueError("Max assignees cannot be negative")
        
        if self.updated_at < self.created_at:
            raise ValueError("Updated timestamp cannot be before created timestamp")
        
        # System role validation
        if self.is_system_role and self.status == RoleStatus.DELETED:
            raise ValueError("System roles cannot be deleted")
    
    @classmethod
    def create_new(
        cls,
        name: str,
        display_name: str,
        description: str,
        role_type: RoleType,
        created_by: UUID,
        is_system_role: bool = False,
        max_assignees: int | None = None,
        metadata: dict[str, Any] | None = None
    ) -> 'Role':
        """Create new role with proper validation."""
        role_name = RoleName(name)
        now = datetime.now(UTC)
        
        role = cls(
            id=uuid4(),
            name=role_name,
            display_name=display_name.strip(),
            description=description.strip(),
            status=RoleStatus.ACTIVE,
            role_type=role_type,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            is_system_role=is_system_role,
            max_assignees=max_assignees,
            metadata=metadata or {}
        )
        
        # Emit creation event
        role.add_domain_event(RoleCreated(
            role_id=role.id,
            name=name,
            display_name=display_name,
            role_type=role_type.value,
            created_by=created_by,
            is_system_role=is_system_role
        ))
        
        return role
    
    def update_details(
        self,
        display_name: str | None = None,
        description: str | None = None,
        updated_by: UUID | None = None
    ) -> None:
        """Update role details."""
        if self.status == RoleStatus.DELETED:
            raise ValueError("Cannot update deleted role")
        
        changed = False
        old_display_name = self.display_name
        old_description = self.description
        
        if display_name and display_name.strip() != self.display_name:
            self.display_name = display_name.strip()
            changed = True
        
        if description and description.strip() != self.description:
            self.description = description.strip()
            changed = True
        
        if changed:
            self.updated_by = updated_by
            self._touch()
            
            self.add_domain_event(RoleUpdated(
                role_id=self.id,
                updated_by=updated_by,
                old_display_name=old_display_name,
                new_display_name=self.display_name,
                old_description=old_description,
                new_description=self.description
            ))
    
    def grant_permission(self, permission_id: UUID, granted_by: UUID) -> None:
        """Grant permission to role."""
        if self.status != RoleStatus.ACTIVE:
            raise ValueError("Cannot grant permissions to inactive role")
        
        if permission_id in self._permission_ids:
            return
        
        self._permission_ids.add(permission_id)
        self.updated_by = granted_by
        self._touch()
        
        self.add_domain_event(RolePermissionGranted(
            role_id=self.id,
            permission_id=permission_id,
            permission_name="",  # Would be resolved by service
            granted_by=granted_by
        ))
    
    def revoke_permission(self, permission_id: UUID, revoked_by: UUID) -> None:
        """Revoke permission from role."""
        if permission_id not in self._permission_ids:
            return
        
        self._permission_ids.remove(permission_id)
        self.updated_by = revoked_by
        self._touch()
        
        self.add_domain_event(RolePermissionRevoked(
            role_id=self.id,
            permission_id=permission_id,
            permission_name="",  # Would be resolved by service
            revoked_by=revoked_by
        ))
    
    def add_parent_role(self, parent_role_id: UUID, updated_by: UUID) -> None:
        """Add parent role for inheritance."""
        if self.id == parent_role_id:
            raise ValueError("Role cannot be its own parent")
        
        if parent_role_id in self._parent_role_ids:
            return
        
        self._parent_role_ids.add(parent_role_id)
        self.updated_by = updated_by
        self._touch()
        
        self.add_domain_event(RoleHierarchyChanged(
            role_id=self.id,
            parent_role_id=parent_role_id,
            action="parent_added",
            updated_by=updated_by
        ))
    
    def remove_parent_role(self, parent_role_id: UUID, updated_by: UUID) -> None:
        """Remove parent role."""
        if parent_role_id not in self._parent_role_ids:
            return
        
        self._parent_role_ids.remove(parent_role_id)
        self.updated_by = updated_by
        self._touch()
        
        self.add_domain_event(RoleHierarchyChanged(
            role_id=self.id,
            parent_role_id=parent_role_id,
            action="parent_removed",
            updated_by=updated_by
        ))
    
    def add_child_role(self, child_role_id: UUID) -> None:
        """Add child role reference."""
        if child_role_id != self.id and child_role_id not in self._child_role_ids:
            self._child_role_ids.add(child_role_id)
    
    def remove_child_role(self, child_role_id: UUID) -> None:
        """Remove child role reference."""
        self._child_role_ids.discard(child_role_id)
    
    def activate(self, activated_by: UUID) -> None:
        """Activate role."""
        if self.status == RoleStatus.ACTIVE:
            return
        
        if self.status == RoleStatus.DELETED:
            raise ValueError("Cannot activate deleted role")
        
        self.status = RoleStatus.ACTIVE
        self.updated_by = activated_by
        self._touch()
        
        self.add_domain_event(RoleActivated(
            role_id=self.id,
            activated_by=activated_by
        ))
    
    def deactivate(self, deactivated_by: UUID, reason: str = "") -> None:
        """Deactivate role."""
        if self.status != RoleStatus.ACTIVE:
            return
        
        if self.is_system_role:
            raise ValueError("Cannot deactivate system role")
        
        self.status = RoleStatus.INACTIVE
        self.updated_by = deactivated_by
        self._touch()
        
        if reason:
            self.metadata["deactivation_reason"] = reason
        
        self.add_domain_event(RoleDeactivated(
            role_id=self.id,
            deactivated_by=deactivated_by,
            reason=reason
        ))
    
    def soft_delete(self, deleted_by: UUID) -> None:
        """Soft delete role."""
        if self.is_system_role:
            raise ValueError("Cannot delete system role")
        
        if self.status == RoleStatus.DELETED:
            return
        
        self.status = RoleStatus.DELETED
        self.deleted_at = datetime.now(UTC)
        self.deleted_by = deleted_by
        self.updated_by = deleted_by
        self._touch()
        
        self.add_domain_event(RoleDeleted(
            role_id=self.id,
            deleted_by=deleted_by,
            role_name=self.name.value,
            had_permissions=len(self._permission_ids) > 0
        ))
    
    def add_tag(self, tag: str) -> None:
        """Add tag to role."""
        self.tags.add(tag.lower().strip())
        self._touch()
    
    def remove_tag(self, tag: str) -> None:
        """Remove tag from role."""
        self.tags.discard(tag.lower().strip())
        self._touch()
    
    def update_metadata(self, key: str, value: Any, updated_by: UUID) -> None:
        """Update metadata."""
        self.metadata[key] = value
        self.updated_by = updated_by
        self._touch()
    
    # =============================================================================
    # COMPUTED PROPERTIES
    # =============================================================================
    
    def is_active(self) -> bool:
        """Check if role is active."""
        return self.status == RoleStatus.ACTIVE and not self.deleted_at
    
    def is_deleted(self) -> bool:
        """Check if role is deleted."""
        return self.status == RoleStatus.DELETED or self.deleted_at is not None
    
    def get_permission_ids(self) -> set[UUID]:
        """Get direct permission IDs."""
        return self._permission_ids.copy()
    
    def get_parent_role_ids(self) -> set[UUID]:
        """Get parent role IDs."""
        return self._parent_role_ids.copy()
    
    def get_child_role_ids(self) -> set[UUID]:
        """Get child role IDs."""
        return self._child_role_ids.copy()
    
    def has_permission(self, permission_id: UUID) -> bool:
        """Check if role has direct permission."""
        return permission_id in self._permission_ids
    
    def can_inherit_from(self, parent_role_id: UUID) -> bool:
        """Check if role can inherit from parent."""
        return (
            self.is_inheritable and
            self.id != parent_role_id and
            parent_role_id not in self._child_role_ids  # Prevent cycles
        )
    
    def get_hierarchy_level(self) -> int:
        """Get hierarchy level (0 = root role)."""
        return len(self._parent_role_ids)
    
    # =============================================================================
    # HELPER METHODS
    # =============================================================================
    
    def _touch(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = datetime.now(UTC)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "name": self.name.value,
            "display_name": self.display_name,
            "description": self.description,
            "status": self.status.value,
            "role_type": self.role_type.value,
            "is_system_role": self.is_system_role,
            "is_inheritable": self.is_inheritable,
            "max_assignees": self.max_assignees,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": str(self.created_by),
            "updated_by": str(self.updated_by) if self.updated_by else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "deleted_by": str(self.deleted_by) if self.deleted_by else None,
            "permission_ids": [str(pid) for pid in self._permission_ids],
            "parent_role_ids": [str(pid) for pid in self._parent_role_ids],
            "child_role_ids": [str(pid) for pid in self._child_role_ids],
            "metadata": self.metadata,
            "tags": list(self.tags)
        }


# Export the aggregate
__all__ = ['Role']