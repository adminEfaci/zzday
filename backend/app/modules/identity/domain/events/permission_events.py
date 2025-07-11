"""Permission-related domain events."""

from typing import Any
from uuid import UUID

from .base import IdentityDomainEvent


class PermissionCreated(IdentityDomainEvent):
    """Event raised when a new permission is created."""
    permission_id: UUID
    name: str
    code: str
    permission_type: str
    resource_type: str
    parent_id: UUID | None = None
    created_by: UUID | None = None
    is_system: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionUpdated(IdentityDomainEvent):
    """Event raised when permission details are updated."""
    permission_id: UUID
    updated_by: UUID | None = None
    old_name: str
    new_name: str
    old_description: str
    new_description: str

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionDeleted(IdentityDomainEvent):
    """Event raised when a permission is deleted."""
    permission_id: UUID
    deleted_by: UUID
    permission_code: str
    had_children: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionActivated(IdentityDomainEvent):
    """Event raised when a permission is activated."""
    permission_id: UUID
    activated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionDeactivated(IdentityDomainEvent):
    """Event raised when a permission is deactivated."""
    permission_id: UUID
    deactivated_by: UUID
    reason: str = ""

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionHierarchyChanged(IdentityDomainEvent):
    """Event raised when permission hierarchy changes."""
    permission_id: UUID
    old_parent_id: UUID | None = None
    new_parent_id: UUID | None = None
    old_path: str
    new_path: str
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionConstraintAdded(IdentityDomainEvent):
    """Event raised when a constraint is added to permission."""
    permission_id: UUID
    constraint_key: str
    constraint_value: Any
    old_value: Any = None
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionConstraintRemoved(IdentityDomainEvent):
    """Event raised when a constraint is removed from permission."""
    permission_id: UUID
    constraint_key: str
    removed_value: Any
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionCloned(IdentityDomainEvent):
    """Event raised when a permission is cloned."""
    original_permission_id: UUID
    cloned_permission_id: UUID
    cloned_by: UUID
    name_changes: dict[str, str]

    def get_aggregate_id(self) -> str:
        return str(self.cloned_permission_id)


class PermissionMerged(IdentityDomainEvent):
    """Event raised when permissions are merged."""
    target_permission_id: UUID
    source_permission_ids: list[UUID]
    merged_by: UUID
    merge_strategy: str

    def get_aggregate_id(self) -> str:
        return str(self.target_permission_id)


class PermissionGranted(IdentityDomainEvent):
    """Event raised when a permission is granted to a user."""
    user_id: UUID
    permission_id: UUID
    granted_by: UUID
    granted_at: str
    context: dict[str, Any] | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PermissionRevoked(IdentityDomainEvent):
    """Event raised when a permission is revoked from a user."""
    user_id: UUID
    permission_id: UUID
    revoked_by: UUID
    revoked_at: str
    reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)