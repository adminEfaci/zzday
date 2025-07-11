"""
Permission Aggregate Root

Manages permission definitions, hierarchies, and business rules.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Optional
from uuid import UUID, uuid4

from app.core.domain.base import AggregateRoot

from ...value_objects.permission_scope import PermissionScope
from .permission_events import (
    PermissionActivated,
    PermissionCloned,
    PermissionConstraintAdded,
    PermissionConstraintRemoved,
    PermissionCreated,
    PermissionDeactivated,
    PermissionDeleted,
    PermissionHierarchyChanged,
    PermissionMerged,
    PermissionUpdated,
)
from .role_enums import PermissionType, ResourceType


@dataclass
class Permission(AggregateRoot):
    """
    Permission aggregate root - manages permission definitions and hierarchies.
    
    Aggregate Boundaries:
    - Permission identity and metadata
    - Permission hierarchy and inheritance
    - Constraints and scope management
    - Permission business rules and validation
    
    External Concerns:
    - Role-permission assignments -> Role aggregate
    - User permission evaluation -> Domain services
    """
    
    # Core identity
    id: UUID
    name: str
    code: str  # Unique permission code (e.g., "users.read", "posts.write")
    description: str
    permission_type: PermissionType
    resource_type: ResourceType
    created_at: datetime
    
    # Hierarchy
    parent_id: UUID | None = None
    path: str = ""  # Materialized path for efficient queries
    depth: int = 0
    
    # Scope and constraints
    scope: PermissionScope | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    
    # Properties
    is_active: bool = True
    is_system: bool = False  # System permissions cannot be modified
    is_dangerous: bool = False  # Requires additional confirmation
    requires_mfa: bool = False
    
    # Metadata
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    # Audit
    created_by: UUID | None = None
    modified_at: datetime | None = None
    modified_by: UUID | None = None
    deleted_at: datetime | None = None
    deleted_by: UUID | None = None
    
    # Cached hierarchy data
    _child_permission_ids: set[UUID] = field(default_factory=set, init=False)
    _descendant_permission_ids: set[UUID] = field(default_factory=set, init=False)
    
    def __post_init__(self):
        """Initialize permission aggregate."""
        super().__post_init__()
        self._validate_invariants()
        
        # Initialize path if not set
        if not self.path and not self.parent_id:
            self.path = str(self.id)
        
        # Mark dangerous permissions
        self._check_dangerous_permission()
    
    def _validate_invariants(self) -> None:
        """Validate domain invariants."""
        if not self.name.strip():
            raise ValueError("Permission name cannot be empty")
        
        if not self.code.strip():
            raise ValueError("Permission code cannot be empty")
        
        if not self._is_valid_code(self.code):
            raise ValueError(f"Invalid permission code format: {self.code}")
        
        if not isinstance(self.permission_type, PermissionType):
            raise ValueError("Permission type must be a PermissionType enum")
        
        if not isinstance(self.resource_type, ResourceType):
            raise ValueError("Resource type must be a ResourceType enum")
        
        if self.depth < 0:
            raise ValueError("Permission depth cannot be negative")
        
        if self.parent_id and self.parent_id == self.id:
            raise ValueError("Permission cannot be its own parent")
        
        if self.modified_at and self.modified_at < self.created_at:
            raise ValueError("Modified timestamp cannot be before created timestamp")
    
    @classmethod
    def create_new(
        cls,
        name: str,
        code: str,
        description: str,
        permission_type: PermissionType,
        resource_type: ResourceType,
        parent: Optional['Permission'] = None,
        scope: PermissionScope | None = None,
        is_system: bool = False,
        created_by: UUID | None = None
    ) -> 'Permission':
        """Create a new permission."""
        permission_id = uuid4()
        now = datetime.now(UTC)
        
        # Build hierarchy data
        parent_id = parent.id if parent else None
        path = f"{parent.path}/{permission_id}" if parent else str(permission_id)
        depth = parent.depth + 1 if parent else 0
        
        # Validate hierarchy depth
        if depth > 10:  # Reasonable depth limit
            raise ValueError("Permission hierarchy too deep (max 10 levels)")
        
        permission = cls(
            id=permission_id,
            name=name.strip(),
            code=code.strip(),
            description=description.strip(),
            permission_type=permission_type,
            resource_type=resource_type,
            parent_id=parent_id,
            path=path,
            depth=depth,
            scope=scope,
            is_system=is_system,
            created_by=created_by,
            created_at=now
        )
        
        # Emit creation event
        permission.add_domain_event(PermissionCreated(
            permission_id=permission.id,
            name=name,
            code=code,
            permission_type=permission_type.value,
            resource_type=resource_type.value,
            parent_id=parent_id,
            created_by=created_by,
            is_system=is_system
        ))
        
        return permission
    
    @staticmethod
    def _is_valid_code(code: str) -> bool:
        """Validate permission code format.
        
        Expected format: resource.action or resource.subresource.action
        """
        pattern = r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$'
        return bool(re.match(pattern, code)) and len(code) <= 100
    
    def _check_dangerous_permission(self) -> None:
        """Check if permission should be marked as dangerous."""
        dangerous_patterns = [
            r'.*\.delete_all$',
            r'.*\.destroy$',
            r'^admin\.',
            r'^system\.',
            r'.*\.bypass',
            r'.*\.sudo',
            r'.*\.impersonate',
            r'.*\.export_all',
        ]
        
        for pattern in dangerous_patterns:
            if re.match(pattern, self.code):
                self.is_dangerous = True
                self.requires_mfa = True
                break
    
    # =============================================================================
    # COMMAND METHODS
    # =============================================================================
    
    def update_details(
        self,
        name: str | None = None,
        description: str | None = None,
        updated_by: UUID | None = None
    ) -> None:
        """Update permission details."""
        if self.is_deleted():
            raise ValueError("Cannot update deleted permission")
        
        if self.is_system:
            raise ValueError("Cannot update system permission")
        
        changed = False
        old_name = self.name
        old_description = self.description
        
        if name and name.strip() != self.name:
            self.name = name.strip()
            changed = True
        
        if description and description.strip() != self.description:
            self.description = description.strip()
            changed = True
        
        if changed:
            self.modified_by = updated_by
            self._touch()
            
            self.add_domain_event(PermissionUpdated(
                permission_id=self.id,
                updated_by=updated_by,
                old_name=old_name,
                new_name=self.name,
                old_description=old_description,
                new_description=self.description
            ))
    
    def activate(self, activated_by: UUID) -> None:
        """Activate permission."""
        if self.is_active:
            return
        
        if self.is_deleted():
            raise ValueError("Cannot activate deleted permission")
        
        self.is_active = True
        self.modified_by = activated_by
        self._touch()
        
        self.add_domain_event(PermissionActivated(
            permission_id=self.id,
            activated_by=activated_by
        ))
    
    def deactivate(self, deactivated_by: UUID, reason: str = "") -> None:
        """Deactivate permission."""
        if not self.is_active:
            return
        
        if self.is_system:
            raise ValueError("Cannot deactivate system permission")
        
        self.is_active = False
        self.modified_by = deactivated_by
        self._touch()
        
        if reason:
            self.metadata["deactivation_reason"] = reason
        
        self.add_domain_event(PermissionDeactivated(
            permission_id=self.id,
            deactivated_by=deactivated_by,
            reason=reason
        ))
    
    def soft_delete(self, deleted_by: UUID) -> None:
        """Soft delete permission."""
        if self.is_system:
            raise ValueError("Cannot delete system permission")
        
        if self.is_deleted():
            return
        
        self.deleted_at = datetime.now(UTC)
        self.deleted_by = deleted_by
        self.modified_by = deleted_by
        self.is_active = False
        self._touch()
        
        self.add_domain_event(PermissionDeleted(
            permission_id=self.id,
            deleted_by=deleted_by,
            permission_code=self.code,
            had_children=len(self._child_permission_ids) > 0
        ))
    
    def move_to_parent(self, new_parent: Optional['Permission'], updated_by: UUID) -> None:
        """Move permission to new parent in hierarchy."""
        if self.is_system:
            raise ValueError("Cannot move system permission")
        
        if new_parent and new_parent.id == self.id:
            raise ValueError("Permission cannot be its own parent")
        
        # Check for circular reference
        if new_parent and self._would_create_cycle(new_parent):
            raise ValueError("Moving permission would create circular reference")
        
        old_parent_id = self.parent_id
        old_path = self.path
        old_depth = self.depth
        
        # Update hierarchy data
        self.parent_id = new_parent.id if new_parent else None
        self.path = f"{new_parent.path}/{self.id}" if new_parent else str(self.id)
        self.depth = new_parent.depth + 1 if new_parent else 0
        self.modified_by = updated_by
        self._touch()
        
        self.add_domain_event(PermissionHierarchyChanged(
            permission_id=self.id,
            old_parent_id=old_parent_id,
            new_parent_id=self.parent_id,
            old_path=old_path,
            new_path=self.path,
            updated_by=updated_by
        ))
    
    def add_child_reference(self, child_permission_id: UUID) -> None:
        """Add child permission reference for hierarchy management."""
        if child_permission_id != self.id:
            self._child_permission_ids.add(child_permission_id)
    
    def remove_child_reference(self, child_permission_id: UUID) -> None:
        """Remove child permission reference."""
        self._child_permission_ids.discard(child_permission_id)
    
    def add_constraint(self, key: str, value: Any, updated_by: UUID) -> None:
        """Add a constraint to the permission."""
        if self.is_system:
            raise ValueError("Cannot modify constraints of system permission")
        
        old_value = self.constraints.get(key)
        self.constraints[key] = value
        self.modified_by = updated_by
        self._touch()
        
        self.add_domain_event(PermissionConstraintAdded(
            permission_id=self.id,
            constraint_key=key,
            constraint_value=value,
            old_value=old_value,
            updated_by=updated_by
        ))
    
    def remove_constraint(self, key: str, updated_by: UUID) -> None:
        """Remove a constraint from the permission."""
        if self.is_system:
            raise ValueError("Cannot modify constraints of system permission")
        
        if key not in self.constraints:
            return
        
        old_value = self.constraints.pop(key)
        self.modified_by = updated_by
        self._touch()
        
        self.add_domain_event(PermissionConstraintRemoved(
            permission_id=self.id,
            constraint_key=key,
            old_value=old_value,
            updated_by=updated_by
        ))
    
    def add_tag(self, tag: str) -> None:
        """Add tag to permission."""
        clean_tag = tag.lower().strip()
        if clean_tag and clean_tag not in self.tags:
            self.tags.add(clean_tag)
            self._touch()
    
    def remove_tag(self, tag: str) -> None:
        """Remove tag from permission."""
        self.tags.discard(tag.lower().strip())
        self._touch()
    
    def update_metadata(self, key: str, value: Any, updated_by: UUID) -> None:
        """Update metadata."""
        self.metadata[key] = value
        self.modified_by = updated_by
        self._touch()
    
    # =============================================================================
    # BUSINESS LOGIC METHODS
    # =============================================================================
    
    def matches(self, requested_permission: str) -> bool:
        """Check if this permission matches a requested permission (simple cases only)."""
        # Exact match
        if self.code == requested_permission:
            return True
        
        # Simple wildcard matching
        if self.is_wildcard:
            pattern = self.code.replace('.', r'\.').replace('*', '.*')
            return bool(re.match(f"^{pattern}$", requested_permission))
        
        return False
    
    def implies(self, other: 'Permission') -> bool:
        """Check if this permission implies another (basic comparison only)."""
        # Same permission
        if self.id == other.id:
            return True
        
        # Direct ancestor relationship
        if self.is_ancestor_of(other):
            return True
        
        # Simple wildcard match
        if self.is_wildcard and self.matches(other.code):
            return True
        
        return False
    
    def evaluate_constraints(self, context: dict[str, Any]) -> bool:
        """Evaluate if constraints are satisfied in given context."""
        for key, expected_value in self.constraints.items():
            if key not in context:
                return False
            
            actual_value = context[key]
            
            # Handle different constraint types
            if isinstance(expected_value, list):
                # Value must be in list
                if actual_value not in expected_value:
                    return False
            elif isinstance(expected_value, dict):
                # Complex constraint (e.g., range)
                if "min" in expected_value and actual_value < expected_value["min"]:
                    return False
                if "max" in expected_value and actual_value > expected_value["max"]:
                    return False
                if "pattern" in expected_value:
                    if not re.match(expected_value["pattern"], str(actual_value)):
                        return False
            # Direct equality
            elif actual_value != expected_value:
                return False
        
        return True
    
    def clone(self, new_code: str | None = None, cloned_by: UUID | None = None) -> 'Permission':
        """Create a clone of this permission."""
        cloned = Permission.create_new(
            name=f"{self.name} (Clone)",
            code=new_code or f"{self.code}_clone",
            description=self.description,
            permission_type=self.permission_type,
            resource_type=self.resource_type,
            parent=None,  # Clones start at root level
            scope=self.scope,
            is_system=False,  # Clones are never system permissions
            created_by=cloned_by
        )
        
        # Copy non-system properties
        cloned.constraints = self.constraints.copy()
        cloned.is_dangerous = self.is_dangerous
        cloned.requires_mfa = self.requires_mfa
        cloned.tags = self.tags.copy()
        cloned.metadata = self.metadata.copy()
        
        cloned.add_domain_event(PermissionCloned(
            original_permission_id=self.id,
            cloned_permission_id=cloned.id,
            cloned_by=cloned_by
        ))
        
        return cloned
    
    def merge_with(self, other: 'Permission', merged_by: UUID | None = None) -> 'Permission':
        """Merge this permission with another, creating a combined permission."""
        # Create new permission that encompasses both
        merged_code = f"{self.resource}.{self.action}_{other.action}"
        
        # Merge scopes
        merged_scope = None
        if self.scope and other.scope:
            merged_scope = self.scope.union(other.scope)
        elif self.scope:
            merged_scope = self.scope
        elif other.scope:
            merged_scope = other.scope
        
        merged = Permission.create_new(
            name=f"{self.name} + {other.name}",
            code=merged_code,
            description=f"Merged: {self.description} AND {other.description}",
            permission_type=PermissionType.CUSTOM if hasattr(PermissionType, 'CUSTOM') else self.permission_type,
            resource_type=self.resource_type,
            scope=merged_scope,
            created_by=merged_by
        )
        
        # Merge constraints (this would need business rules for conflict resolution)
        merged.constraints = {**self.constraints, **other.constraints}
        merged.tags = self.tags | other.tags
        merged.is_dangerous = self.is_dangerous or other.is_dangerous
        merged.requires_mfa = self.requires_mfa or other.requires_mfa
        
        merged.add_domain_event(PermissionMerged(
            permission1_id=self.id,
            permission2_id=other.id,
            merged_permission_id=merged.id,
            merged_by=merged_by
        ))
        
        return merged
    
    # =============================================================================
    # QUERY METHODS
    # =============================================================================
    
    @property
    def resource(self) -> str:
        """Extract resource from permission code."""
        parts = self.code.split('.')
        return parts[0] if parts else ""
    
    @property
    def action(self) -> str:
        """Extract action from permission code."""
        parts = self.code.split('.')
        return parts[-1] if len(parts) > 1 else ""
    
    @property
    def is_wildcard(self) -> bool:
        """Check if permission includes wildcards."""
        return '*' in self.code
    
    @property
    def is_read_only(self) -> bool:
        """Check if permission is read-only."""
        read_actions = ['read', 'view', 'list', 'get', 'search', 'export']
        return self.action in read_actions
    
    @property
    def is_write(self) -> bool:
        """Check if permission allows write operations."""
        write_actions = ['write', 'create', 'update', 'edit', 'modify', 'import']
        return self.action in write_actions
    
    @property
    def is_delete(self) -> bool:
        """Check if permission allows delete operations."""
        delete_actions = ['delete', 'remove', 'destroy', 'purge']
        return self.action in delete_actions
    
    def is_ancestor_of(self, other: 'Permission') -> bool:
        """Check if this permission is an ancestor of another."""
        return other.path.startswith(f"{self.path}/")
    
    def is_descendant_of(self, other: 'Permission') -> bool:
        """Check if this permission is a descendant of another."""
        return self.path.startswith(f"{other.path}/")
    
    def is_sibling_of(self, other: 'Permission') -> bool:
        """Check if this permission is a sibling of another."""
        return (self.parent_id == other.parent_id and 
                self.id != other.id and 
                self.parent_id is not None)
    
    def is_deleted(self) -> bool:
        """Check if permission is deleted."""
        return self.deleted_at is not None
    
    def has_constraint(self, key: str) -> bool:
        """Check if permission has a specific constraint."""
        return key in self.constraints
    
    def get_child_permission_ids(self) -> set[UUID]:
        """Get direct child permission IDs."""
        return self._child_permission_ids.copy()
    
    def get_ancestors(self) -> list[UUID]:
        """Get list of ancestor permission IDs from path."""
        if not self.path or '/' not in self.path:
            return []
        
        parts = self.path.split('/')[:-1]  # Exclude self
        return [UUID(part) for part in parts if part]
    
    def _would_create_cycle(self, potential_parent: 'Permission') -> bool:
        """Check if making potential_parent a parent would create a cycle."""
        # If potential parent is a descendant of this permission, it would create a cycle
        return potential_parent.is_descendant_of(self)
    
    # =============================================================================
    # HELPER METHODS
    # =============================================================================
    
    def _touch(self) -> None:
        """Update the last modified timestamp."""
        self.modified_at = datetime.now(UTC)
    
    def to_policy_statement(self) -> dict[str, Any]:
        """Convert to policy statement format."""
        statement = {
            "effect": "allow" if self.is_active else "deny",
            "action": self.code,
            "resource": self.resource_type.value,
            "conditions": {}
        }
        
        # Add scope conditions
        if self.scope:
            statement["conditions"]["scope"] = self.scope.to_dict()
        
        # Add constraints as conditions
        if self.constraints:
            statement["conditions"]["constraints"] = self.constraints
        
        # Add MFA requirement
        if self.requires_mfa:
            statement["conditions"]["mfa_required"] = True
        
        return statement
    
    def get_display_info(self) -> dict[str, Any]:
        """Get permission information for display."""
        return {
            "id": str(self.id),
            "name": self.name,
            "code": self.code,
            "description": self.description,
            "type": self.permission_type.value,
            "resource": self.resource_type.value,
            "action": self.action,
            "is_active": self.is_active,
            "is_system": self.is_system,
            "is_dangerous": self.is_dangerous,
            "requires_mfa": self.requires_mfa,
            "is_read_only": self.is_read_only,
            "depth": self.depth,
            "has_children": len(self._child_permission_ids) > 0,
            "tags": list(self.tags),
            "is_deleted": self.is_deleted()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for persistence."""
        return {
            "id": str(self.id),
            "name": self.name,
            "code": self.code,
            "description": self.description,
            "permission_type": self.permission_type.value,
            "resource_type": self.resource_type.value,
            "parent_id": str(self.parent_id) if self.parent_id else None,
            "path": self.path,
            "depth": self.depth,
            "scope": self.scope.to_dict() if self.scope else None,
            "constraints": self.constraints,
            "is_active": self.is_active,
            "is_system": self.is_system,
            "is_dangerous": self.is_dangerous,
            "requires_mfa": self.requires_mfa,
            "tags": list(self.tags),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "created_by": str(self.created_by) if self.created_by else None,
            "modified_at": self.modified_at.isoformat() if self.modified_at else None,
            "modified_by": str(self.modified_by) if self.modified_by else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            "deleted_by": str(self.deleted_by) if self.deleted_by else None,
            "child_permission_ids": [str(pid) for pid in self._child_permission_ids]
        }


# Export the aggregate
__all__ = ['Permission']