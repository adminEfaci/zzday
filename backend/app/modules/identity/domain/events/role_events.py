"""Role-related domain events."""

from datetime import datetime
from typing import Any
from uuid import UUID

from .base import IdentityDomainEvent


class RoleCreated(IdentityDomainEvent):
    """Event raised when a new role is created."""
    role_id: UUID
    name: str
    code: str
    role_type: str
    is_system: bool = False
    created_by: UUID | None = None
    parent_id: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleUpdated(IdentityDomainEvent):
    """Event raised when role details are updated."""
    role_id: UUID
    updated_by: UUID | None = None
    old_name: str
    new_name: str
    old_description: str
    new_description: str

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleDeleted(IdentityDomainEvent):
    """Event raised when a role is deleted."""
    role_id: UUID
    deleted_by: UUID
    role_code: str
    had_children: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleActivated(IdentityDomainEvent):
    """Event raised when a role is activated."""
    role_id: UUID
    activated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleDeactivated(IdentityDomainEvent):
    """Event raised when a role is deactivated."""
    role_id: UUID
    deactivated_by: UUID
    reason: str = ""

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RolePermissionGranted(IdentityDomainEvent):
    """Event raised when permission is granted to role."""
    role_id: UUID
    permission_id: UUID
    granted_by: UUID
    granted_at: datetime
    context: dict[str, Any] | None = None

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RolePermissionRevoked(IdentityDomainEvent):
    """Event raised when permission is revoked from role."""
    role_id: UUID
    permission_id: UUID
    revoked_by: UUID
    revoked_at: datetime
    reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleHierarchyChanged(IdentityDomainEvent):
    """Event raised when role hierarchy changes."""
    role_id: UUID
    old_parent_id: UUID | None = None
    new_parent_id: UUID | None = None
    old_path: str
    new_path: str
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleAssigned(IdentityDomainEvent):
    """Event raised when a role is assigned to a user."""
    user_id: UUID
    role_id: UUID
    assigned_by: UUID
    assigned_at: datetime
    expires_at: datetime | None = None
    context: dict[str, Any] | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleUnassigned(IdentityDomainEvent):
    """Event raised when a role is removed from a user."""
    user_id: UUID
    role_id: UUID
    unassigned_by: UUID
    unassigned_at: datetime
    reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleAssignmentExpired(IdentityDomainEvent):
    """Event raised when role assignment expires."""
    user_id: UUID
    role_id: UUID
    expired_at: datetime
    assignment_duration: int  # in days

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleAssignmentSuspended(IdentityDomainEvent):
    """Event raised when role assignment is suspended."""
    user_id: UUID
    role_id: UUID
    suspended_by: UUID
    suspended_at: datetime
    reason: str
    suspension_expires_at: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PermissionAddedToRole(IdentityDomainEvent):
    """Event raised when a permission is added to a role."""
    role_id: UUID
    permission_id: UUID
    added_by: UUID
    added_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class PermissionRemovedFromRole(IdentityDomainEvent):
    """Event raised when a permission is removed from a role."""
    role_id: UUID
    permission_id: UUID
    removed_by: UUID
    removed_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.role_id)