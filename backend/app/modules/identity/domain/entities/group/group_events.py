"""
Group Entity Events

Domain events related to group lifecycle and membership.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from ...events import IdentityDomainEvent


# Group Lifecycle Events
class GroupCreated(IdentityDomainEvent):
    """Event raised when a new group is created."""
    group_id: UUID
    group_name: str
    group_type: str
    visibility: str
    created_by: UUID
    parent_group_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupUpdated(IdentityDomainEvent):
    """Event raised when group details are updated."""
    group_id: UUID
    updated_by: UUID
    changes: dict[str, Any]
    previous_values: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupDeleted(IdentityDomainEvent):
    """Event raised when a group is deleted."""
    group_id: UUID
    group_name: str
    deleted_by: UUID
    deletion_reason: str | None = None
    member_count: int = 0

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupArchived(IdentityDomainEvent):
    """Event raised when a group is archived."""
    group_id: UUID
    group_name: str
    archived_by: UUID
    archive_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupRestored(IdentityDomainEvent):
    """Event raised when an archived group is restored."""
    group_id: UUID
    group_name: str
    restored_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupSuspended(IdentityDomainEvent):
    """Event raised when a group is suspended."""
    group_id: UUID
    group_name: str
    suspended_by: UUID
    suspension_reason: str
    suspended_until: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupReactivated(IdentityDomainEvent):
    """Event raised when a suspended group is reactivated."""
    group_id: UUID
    group_name: str
    reactivated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Membership Events
class MemberAdded(IdentityDomainEvent):
    """Event raised when a member is added to a group."""
    group_id: UUID
    user_id: UUID
    member_role: str
    added_by: UUID
    join_method: str
    expires_at: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class MemberRemoved(IdentityDomainEvent):
    """Event raised when a member is removed from a group."""
    group_id: UUID
    user_id: UUID
    removed_by: UUID
    removal_reason: str = Field(default="manual_removal")

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class MemberRoleChanged(IdentityDomainEvent):
    """Event raised when a member's role is changed."""
    group_id: UUID
    user_id: UUID
    previous_role: str
    new_role: str
    changed_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class MembershipExpired(IdentityDomainEvent):
    """Event raised when a temporary membership expires."""
    group_id: UUID
    user_id: UUID
    member_role: str
    expired_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Owner Management Events
class OwnershipTransferred(IdentityDomainEvent):
    """Event raised when group ownership is transferred."""
    group_id: UUID
    previous_owner_id: UUID
    new_owner_id: UUID
    transferred_by: UUID
    transfer_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class OwnerAdded(IdentityDomainEvent):
    """Event raised when an additional owner is added."""
    group_id: UUID
    user_id: UUID
    added_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Invitation Events
class InvitationSent(IdentityDomainEvent):
    """Event raised when a group invitation is sent."""
    group_id: UUID
    invitation_id: UUID
    invitee_email: str
    invitee_user_id: UUID | None = None
    invited_by: UUID
    expires_at: datetime
    message: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class InvitationAccepted(IdentityDomainEvent):
    """Event raised when a group invitation is accepted."""
    group_id: UUID
    invitation_id: UUID
    user_id: UUID
    accepted_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class InvitationDeclined(IdentityDomainEvent):
    """Event raised when a group invitation is declined."""
    group_id: UUID
    invitation_id: UUID
    user_id: UUID
    declined_at: datetime
    decline_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class InvitationRevoked(IdentityDomainEvent):
    """Event raised when a group invitation is revoked."""
    group_id: UUID
    invitation_id: UUID
    revoked_by: UUID
    revoke_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Membership Request Events
class MembershipRequested(IdentityDomainEvent):
    """Event raised when user requests to join a group."""
    group_id: UUID
    request_id: UUID
    user_id: UUID
    requested_at: datetime
    message: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class MembershipRequestApproved(IdentityDomainEvent):
    """Event raised when membership request is approved."""
    group_id: UUID
    request_id: UUID
    user_id: UUID
    approved_by: UUID
    approved_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class MembershipRequestRejected(IdentityDomainEvent):
    """Event raised when membership request is rejected."""
    group_id: UUID
    request_id: UUID
    user_id: UUID
    rejected_by: UUID
    rejected_at: datetime
    rejection_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Group Settings Events
class GroupSettingsUpdated(IdentityDomainEvent):
    """Event raised when group settings are updated."""
    group_id: UUID
    updated_by: UUID
    setting_changes: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupVisibilityChanged(IdentityDomainEvent):
    """Event raised when group visibility is changed."""
    group_id: UUID
    previous_visibility: str
    new_visibility: str
    changed_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class GroupJoinMethodChanged(IdentityDomainEvent):
    """Event raised when group join method is changed."""
    group_id: UUID
    previous_method: str
    new_method: str
    changed_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Hierarchy Events
class SubgroupAdded(IdentityDomainEvent):
    """Event raised when a subgroup is added."""
    parent_group_id: UUID
    subgroup_id: UUID
    added_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.parent_group_id)


class SubgroupRemoved(IdentityDomainEvent):
    """Event raised when a subgroup is removed."""
    parent_group_id: UUID
    subgroup_id: UUID
    removed_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.parent_group_id)


# Bulk Operation Events
class BulkMembersAdded(IdentityDomainEvent):
    """Event raised when multiple members are added at once."""
    group_id: UUID
    user_ids: list[UUID]
    member_role: str
    added_by: UUID
    total_added: int

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


class BulkMembersRemoved(IdentityDomainEvent):
    """Event raised when multiple members are removed at once."""
    group_id: UUID
    user_ids: list[UUID]
    removed_by: UUID
    removal_reason: str
    total_removed: int

    def get_aggregate_id(self) -> str:
        return str(self.group_id)


# Export all events
__all__ = [
    # Bulk Operations
    'BulkMembersAdded',
    'BulkMembersRemoved',
    'GroupArchived',
    # Lifecycle
    'GroupCreated',
    'GroupDeleted',
    'GroupJoinMethodChanged',
    'GroupReactivated',
    'GroupRestored',
    # Settings
    'GroupSettingsUpdated',
    'GroupSuspended',
    'GroupUpdated',
    'GroupVisibilityChanged',
    'InvitationAccepted',
    'InvitationDeclined',
    'InvitationRevoked',
    # Invitations
    'InvitationSent',
    # Membership
    'MemberAdded',
    'MemberRemoved',
    'MemberRoleChanged',
    'MembershipExpired',
    'MembershipRequestApproved',
    'MembershipRequestRejected',
    # Membership Requests
    'MembershipRequested',
    'OwnerAdded',
    # Ownership
    'OwnershipTransferred',
    # Hierarchy
    'SubgroupAdded',
    'SubgroupRemoved'
]