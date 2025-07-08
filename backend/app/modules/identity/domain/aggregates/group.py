"""
Group Domain Aggregates

Contains all group-related aggregates: Group, GroupInvitation, GroupMembershipRequest
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import AggregateRoot
from app.modules.identity.domain.entities.group.group_constants import (
    GroupDefaults,
    GroupLimits,
    GroupTypeSettings,
)
from app.modules.identity.domain.entities.group.group_enums import (
    GroupInvitationStatus,
    GroupJoinMethod,
    GroupMemberRole,
    GroupMembershipRequestStatus,
    GroupMembershipType,
    GroupPermission,
    GroupStatus,
    GroupType,
    GroupVisibility,
)
from app.modules.identity.domain.entities.group.group_errors import (
    GroupInactiveError,
    GroupQuotaExceededError,
    InsufficientGroupPermissionsError,
    InvitationExpiredError,
    UserAlreadyMemberError,
    UserNotMemberError,
)
from app.modules.identity.domain.entities.group.group_events import (
    GroupCreated,
    GroupDeleted,
    GroupArchived,
    GroupRestored,
    GroupSettingsUpdated,
    MemberAdded,
    MemberRemoved,
    MemberRoleChanged,
    OwnershipTransferred,
    InvitationSent,
    InvitationAccepted,
    InvitationDeclined,
    InvitationRevoked,
    MembershipRequested,
    MembershipRequestApproved,
    MembershipRequestRejected,
)
from app.modules.identity.domain.entities.group.group_member import GroupMember
from app.modules.identity.domain.value_objects.group_config import (
    GroupCreationConfig,
    GroupSettingsConfig,
)
from app.modules.identity.domain.value_objects.group_name import GroupName


# =============================================================================
# GROUP AGGREGATE (Main)
# =============================================================================

@dataclass
class Group(AggregateRoot):
    """
    Group aggregate root - manages group identity and core membership.
    
    Responsibilities:
    - Group identity and basic information
    - Direct membership management (add/remove members)
    - Group hierarchy (parent/child relationships)
    - Basic group settings and permissions
    
    NOT responsible for:
    - Invitation workflows (handled by GroupInvitation aggregate)
    - Membership request workflows (handled by GroupMembershipRequest aggregate)
    """
    
    # Core identity (immutable after creation)
    id: UUID
    name: GroupName
    created_at: datetime
    created_by: UUID
    
    # Mutable core properties
    description: str
    group_type: GroupType
    status: GroupStatus
    visibility: GroupVisibility
    join_method: GroupJoinMethod
    updated_at: datetime
    
    # Hierarchy
    parent_group_id: UUID | None = None
    nesting_level: int = 0
    subgroup_ids: list[UUID] = field(default_factory=list)
    
    # SINGLE source of truth for members
    _members: dict[UUID, GroupMember] = field(default_factory=dict, init=False)
    
    # Group settings
    max_members: int = field(default=GroupDefaults.DEFAULT_MAX_MEMBERS)
    allow_nested_groups: bool = field(default=GroupDefaults.DEFAULT_ALLOW_NESTED_GROUPS)
    allow_guest_members: bool = field(default=GroupDefaults.DEFAULT_ALLOW_GUEST_MEMBERS)
    require_approval: bool = field(default=GroupDefaults.DEFAULT_REQUIRE_APPROVAL)
    
    # Lifecycle
    archived_at: datetime | None = None
    deleted_at: datetime | None = None
    archived_by: UUID | None = None
    deleted_by: UUID | None = None
    
    # Metadata
    tags: list[str] = field(default_factory=list)
    custom_attributes: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize group aggregate and enforce domain invariants."""
        super().__post_init__()
        self._validate_invariants()
        
        # Add creator as owner if not already present
        if not self.get_member(self.created_by):
            creator_member = GroupMember.create(
                group_id=self.id,
                user_id=self.created_by,
                role=GroupMemberRole.OWNER,
                membership_type=GroupMembershipType.DIRECT,
                invited_by=None
            )
            self._members[self.created_by] = creator_member

    def _validate_invariants(self) -> None:
        """Validate domain invariants."""
        if not isinstance(self.name, GroupName):
            raise ValueError("Group name must be a GroupName value object")
        
        if self.nesting_level < 0:
            raise ValueError("Nesting level cannot be negative")
        
        if self.nesting_level > GroupLimits.MAX_NESTING_DEPTH:
            raise ValueError(f"Nesting level exceeds maximum depth of {GroupLimits.MAX_NESTING_DEPTH}")
        
        if self.max_members <= 0:
            raise ValueError("Max members must be positive")
    
    @classmethod
    def create(
        cls,
        creation_config: GroupCreationConfig,
        created_by: UUID,
        parent_group_id: UUID | None = None
    ) -> 'Group':
        """Create a new group with proper domain validation."""
        if not isinstance(creation_config.name, GroupName):
            group_name = GroupName(creation_config.name)
        else:
            group_name = creation_config.name
        
        group_type = GroupType(creation_config.group_type)
        type_settings = GroupTypeSettings.get_settings_for_type(group_type.value)
        
        if creation_config.visibility:
            visibility = GroupVisibility(creation_config.visibility)
        else:
            visibility = GroupVisibility(type_settings.get("default_visibility", "private"))
        
        now = datetime.now(UTC)
        
        group = cls(
            id=uuid4(),
            name=group_name,
            description=creation_config.description or "",
            group_type=group_type,
            status=GroupStatus.ACTIVE,
            visibility=visibility,
            join_method=GroupJoinMethod.REQUEST,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            parent_group_id=parent_group_id,
            max_members=type_settings.get("max_members", GroupDefaults.DEFAULT_MAX_MEMBERS),
            allow_guest_members=type_settings.get("allow_guests", GroupDefaults.DEFAULT_ALLOW_GUEST_MEMBERS)
        )
        
        # Domain event
        group.add_domain_event(GroupCreated(
            group_id=group.id,
            group_name=group.name.value,
            group_type=group.group_type.value,
            visibility=group.visibility.value,
            created_by=created_by,
            parent_group_id=parent_group_id,
            metadata={"type_settings": type_settings}
        ))
        
        return group
    
    # =============================================================================
    # MEMBERSHIP MANAGEMENT
    # =============================================================================
    
    def add_member(
        self,
        user_id: UUID,
        role: GroupMemberRole,
        added_by: UUID,
        skip_permission_check: bool = False
    ) -> GroupMember:
        """Add a member to the group with proper validation."""
        if not self.is_active:
            raise GroupInactiveError(self.id)
        
        if self.is_member(user_id):
            raise UserAlreadyMemberError(user_id, self.id)
        
        if not skip_permission_check and not self._can_add_members(added_by):
            raise InsufficientGroupPermissionsError(GroupPermission.ADD_MEMBERS.value)
        
        if self.member_count >= self.max_members:
            raise GroupQuotaExceededError("members", self.max_members)
        
        if role == GroupMemberRole.OWNER and self.owner_count >= GroupLimits.MAX_OWNERS_PER_GROUP:
            raise GroupQuotaExceededError("owners", GroupLimits.MAX_OWNERS_PER_GROUP)
        
        member = GroupMember.create(
            group_id=self.id,
            user_id=user_id,
            role=role,
            membership_type=GroupMembershipType.DIRECT,
            invited_by=added_by
        )
        
        self._members[user_id] = member
        self._touch()
        
        self.add_domain_event(MemberAdded(
            group_id=self.id,
            user_id=user_id,
            member_role=role.value,
            added_by=added_by,
            join_method=self.join_method.value
        ))
        
        return member

    def remove_member(
        self,
        user_id: UUID,
        removed_by: UUID,
        reason: str = "manual_removal"
    ) -> None:
        """Remove a member from the group."""
        member = self.get_member(user_id)
        if not member:
            raise UserNotMemberError(user_id, self.id)
        
        # Ensure at least one owner remains
        if member.is_owner and self.owner_count == 1:
            raise ValueError("Cannot remove the last owner from the group")
        
        del self._members[user_id]
        self._touch()
        
        self.add_domain_event(MemberRemoved(
            group_id=self.id,
            user_id=user_id,
            removed_by=removed_by,
            removal_reason=reason
        ))
    
    def change_member_role(
        self,
        user_id: UUID,
        new_role: GroupMemberRole,
        changed_by: UUID
    ) -> None:
        """Change a member's role in the group."""
        member = self.get_member(user_id)
        if not member:
            raise UserNotMemberError(user_id, self.id)
        
        previous_role = member.role
        
        # ✅ NO EVENT EMISSION IN VALIDATION
        member.change_role(new_role, changed_by)
        self._touch()
        
        # ✅ EVENT EMISSION IN BUSINESS METHOD
        self.add_domain_event(MemberRoleChanged(
            group_id=self.id,
            user_id=user_id,
            previous_role=previous_role.value,
            new_role=new_role.value,
            changed_by=changed_by
        ))
    
    def transfer_ownership(
        self,
        new_owner_id: UUID,
        transferred_by: UUID,
        reason: str | None = None
    ) -> None:
        """Transfer primary ownership of the group."""
        new_owner = self.get_member(new_owner_id)
        if not new_owner:
            raise UserNotMemberError(new_owner_id, self.id)
        
        transferring_member = self.get_member(transferred_by)
        if not transferring_member or not transferring_member.is_owner:
            raise InsufficientGroupPermissionsError("transfer_ownership")
        
        if not new_owner.is_owner:
            new_owner.change_role(GroupMemberRole.OWNER, transferred_by)
        
        self._touch()
        
        self.add_domain_event(OwnershipTransferred(
            group_id=self.id,
            previous_owner_id=transferred_by,
            new_owner_id=new_owner_id,
            transferred_by=transferred_by,
            transfer_reason=reason
        ))
    
    def archive(self, archived_by: UUID, reason: str | None = None) -> None:
        """Archive the group."""
        if self.status == GroupStatus.ARCHIVED:
            return
        
        self.status = GroupStatus.ARCHIVED
        self.archived_at = datetime.now(UTC)
        self.archived_by = archived_by
        self._touch()
        
        self.add_domain_event(GroupArchived(
            group_id=self.id,
            group_name=self.name.value,
            archived_by=archived_by,
            archive_reason=reason
        ))
    
    def delete(self, deleted_by: UUID, reason: str | None = None) -> None:
        """Soft delete the group."""
        self.status = GroupStatus.DELETED
        self.deleted_at = datetime.now(UTC)
        self.deleted_by = deleted_by
        self._touch()
        
        self.add_domain_event(GroupDeleted(
            group_id=self.id,
            group_name=self.name.value,
            deleted_by=deleted_by,
            deletion_reason=reason,
            member_count=self.member_count
        ))
    
    # =============================================================================
    # COMPUTED PROPERTIES (No caching!)
    # =============================================================================
    
    @property
    def member_count(self) -> int:
        """Get current active member count."""
        return len([m for m in self._members.values() if m.is_active and not m.is_expired])
    
    @property
    def owner_count(self) -> int:
        """Get current owner count."""
        return len([m for m in self._members.values() if m.is_owner and m.is_active and not m.is_expired])
    
    @property
    def is_active(self) -> bool:
        """Check if group is active."""
        return self.status == GroupStatus.ACTIVE and not self.deleted_at
    
    @property
    def is_full(self) -> bool:
        """Check if group has reached member limit."""
        return self.member_count >= self.max_members
    
    # =============================================================================
    # HELPER METHODS
    # =============================================================================
    
    def is_member(self, user_id: UUID) -> bool:
        """Check if user is an active member of the group."""
        member = self._members.get(user_id)
        return member is not None and member.is_active and not member.is_expired
    
    def get_member(self, user_id: UUID) -> GroupMember | None:
        """Get a member by user ID if they are active."""
        member = self._members.get(user_id)
        if member and member.is_active and not member.is_expired:
            return member
        return None
    
    def get_active_members(self) -> list[GroupMember]:
        """Get all active, non-expired members."""
        return [
            member for member in self._members.values()
            if member.is_active and not member.is_expired
        ]
    
    def _can_add_members(self, user_id: UUID) -> bool:
        """Check if user can add members to this group."""
        member = self.get_member(user_id)
        return member is not None and member.has_permission(GroupPermission.ADD_MEMBERS.value)
    
    def _touch(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = datetime.now(UTC)


# =============================================================================
# GROUP INVITATION AGGREGATE
# =============================================================================

@dataclass
class GroupInvitation(AggregateRoot):
    """
    Group Invitation aggregate - manages invitation lifecycle.
    
    Responsibilities:
    - Invitation creation and validation
    - Invitation acceptance/decline workflow
    - Invitation expiration management
    """
    
    id: UUID
    group_id: UUID  # Reference to Group aggregate
    invitee_email: str
    invitee_user_id: UUID | None = None
    invited_by: UUID
    role: GroupMemberRole = GroupMemberRole.MEMBER
    status: GroupInvitationStatus = GroupInvitationStatus.PENDING
    message: str | None = None
    token: str = field(default_factory=lambda: uuid4().hex)
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(days=7))
    accepted_at: datetime | None = None
    declined_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    @classmethod
    def create(
        cls,
        group_id: UUID,
        invitee_email: str,
        invited_by: UUID,
        role: GroupMemberRole = GroupMemberRole.MEMBER,
        message: str | None = None,
        expires_in_days: int = 7,
        invitee_user_id: UUID | None = None
    ) -> "GroupInvitation":
        """Create a new group invitation."""
        invitation = cls(
            id=uuid4(),
            group_id=group_id,
            invitee_email=invitee_email,
            invitee_user_id=invitee_user_id,
            invited_by=invited_by,
            role=role,
            message=message,
            expires_at=datetime.now(UTC) + timedelta(days=expires_in_days)
        )
        
        invitation.add_domain_event(InvitationSent(
            group_id=group_id,
            invitation_id=invitation.id,
            invitee_email=invitee_email,
            invitee_user_id=invitee_user_id,
            invited_by=invited_by,
            expires_at=invitation.expires_at,
            message=message
        ))
        
        return invitation
    
    def accept(self, user_id: UUID) -> None:
        """Accept the invitation."""
        if self.status != GroupInvitationStatus.PENDING:
            raise ValueError(f"Cannot accept invitation in {self.status.value} status")
        
        if self.is_expired():
            raise InvitationExpiredError(self.id)
        
        self.status = GroupInvitationStatus.ACCEPTED
        self.accepted_at = datetime.now(UTC)
        self.invitee_user_id = user_id
        self.updated_at = datetime.now(UTC)
        
        self.add_domain_event(InvitationAccepted(
            group_id=self.group_id,
            invitation_id=self.id,
            user_id=user_id,
            accepted_at=self.accepted_at
        ))
    
    def decline(self, decline_reason: str | None = None) -> None:
        """Decline the invitation."""
        if self.status != GroupInvitationStatus.PENDING:
            raise ValueError(f"Cannot decline invitation in {self.status.value} status")
        
        self.status = GroupInvitationStatus.DECLINED
        self.declined_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)
        
        self.add_domain_event(InvitationDeclined(
            group_id=self.group_id,
            invitation_id=self.id,
            user_id=self.invitee_user_id,
            declined_at=self.declined_at,
            decline_reason=decline_reason
        ))
    
    def revoke(self, revoked_by: UUID, revoke_reason: str | None = None) -> None:
        """Revoke the invitation."""
        if self.status != GroupInvitationStatus.PENDING:
            raise ValueError(f"Cannot revoke invitation in {self.status.value} status")
        
        self.status = GroupInvitationStatus.REVOKED
        self.updated_at = datetime.now(UTC)
        
        self.add_domain_event(InvitationRevoked(
            group_id=self.group_id,
            invitation_id=self.id,
            revoked_by=revoked_by,
            revoke_reason=revoke_reason
        ))
    
    def is_expired(self) -> bool:
        """Check if invitation has expired."""
        return (
            self.status == GroupInvitationStatus.EXPIRED or
            (self.status == GroupInvitationStatus.PENDING and 
             datetime.now(UTC) >= self.expires_at)
        )
    
    def can_be_accepted(self) -> bool:
        """Check if invitation can be accepted."""
        return (
            self.status == GroupInvitationStatus.PENDING and
            not self.is_expired()
        )


# =============================================================================
# GROUP MEMBERSHIP REQUEST AGGREGATE
# =============================================================================

@dataclass
class GroupMembershipRequest(AggregateRoot):
    """
    Group Membership Request aggregate - manages membership request lifecycle.
    
    Responsibilities:
    - Membership request creation
    - Request approval/rejection workflow
    - Request status management
    """
    
    id: UUID
    group_id: UUID  # Reference to Group aggregate
    user_id: UUID
    requested_role: GroupMemberRole = GroupMemberRole.MEMBER
    status: GroupMembershipRequestStatus = GroupMembershipRequestStatus.PENDING
    message: str | None = None
    reviewed_by: UUID | None = None
    review_message: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    @classmethod
    def create(
        cls,
        group_id: UUID,
        user_id: UUID,
        requested_role: GroupMemberRole = GroupMemberRole.MEMBER,
        message: str | None = None
    ) -> "GroupMembershipRequest":
        """Create a new membership request."""
        request = cls(
            id=uuid4(),
            group_id=group_id,
            user_id=user_id,
            requested_role=requested_role,
            message=message
        )
        
        request.add_domain_event(MembershipRequested(
            group_id=group_id,
            request_id=request.id,
            user_id=user_id,
            requested_at=request.created_at,
            message=message
        ))
        
        return request
    
    def approve(
        self,
        reviewed_by: UUID,
        approved_role: GroupMemberRole | None = None,
        review_message: str | None = None
    ) -> None:
        """Approve the membership request."""
        if self.status != GroupMembershipRequestStatus.PENDING:
            raise ValueError(f"Cannot approve request in {self.status.value} status")
        
        self.status = GroupMembershipRequestStatus.APPROVED
        self.reviewed_by = reviewed_by
        self.reviewed_at = datetime.now(UTC)
        self.review_message = review_message
        
        if approved_role and approved_role != self.requested_role:
            self.requested_role = approved_role
        
        self.updated_at = datetime.now(UTC)
        
        self.add_domain_event(MembershipRequestApproved(
            group_id=self.group_id,
            request_id=self.id,
            user_id=self.user_id,
            approved_by=reviewed_by,
            approved_at=self.reviewed_at
        ))
    
    def reject(
        self,
        reviewed_by: UUID,
        review_message: str | None = None
    ) -> None:
        """Reject the membership request."""
        if self.status != GroupMembershipRequestStatus.PENDING:
            raise ValueError(f"Cannot reject request in {self.status.value} status")
        
        self.status = GroupMembershipRequestStatus.REJECTED
        self.reviewed_by = reviewed_by
        self.reviewed_at = datetime.now(UTC)
        self.review_message = review_message
        self.updated_at = datetime.now(UTC)
        
        self.add_domain_event(MembershipRequestRejected(
            group_id=self.group_id,
            request_id=self.id,
            user_id=self.user_id,
            rejected_by=reviewed_by,
            rejected_at=self.reviewed_at,
            rejection_reason=review_message
        ))
    
    def withdraw(self) -> None:
        """Withdraw the membership request by the requester."""
        if self.status != GroupMembershipRequestStatus.PENDING:
            raise ValueError(f"Cannot withdraw request in {self.status.value} status")
        
        self.status = GroupMembershipRequestStatus.WITHDRAWN
        self.review_message = "Withdrawn by requester"
        self.reviewed_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)


# Export all aggregates
__all__ = ['Group', 'GroupInvitation', 'GroupMembershipRequest']