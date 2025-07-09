"""
Group Entity Module

Exports all group-related aggregates, entities, enums, errors, events, constants, and services.
"""

# Aggregates (main domain objects)
from .group import (
    Group,
    GroupInvitation,
    GroupMembershipRequest,
)

# Constants
from .group_constants import (
    GroupActivityTypes,
    GroupDefaults,
    GroupLimits,
    GroupNamePatterns,
    GroupPermissionMatrix,
    GroupTypeSettings,
)

# Enums
from .group_enums import (
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

# Errors
from .group_errors import (
    CircularGroupHierarchyError,
    DuplicateMembershipRequestError,
    GroupAlreadyExistsError,
    GroupArchivedError,
    GroupError,
    GroupHierarchyError,
    GroupInactiveError,
    GroupInvitationError,
    GroupMembershipError,
    GroupNameTooLongError,
    GroupNotFoundError,
    GroupOperationError,
    GroupQuotaExceededError,
    InsufficientGroupPermissionsError,
    InvalidGroupSettingsError,
    InvalidGroupTypeError,
    InvitationAlreadyUsedError,
    InvitationExpiredError,
    InvitationNotFoundError,
    MaxNestingDepthExceededError,
    MembershipRequestError,
    MembershipRequestNotFoundError,
    UserAlreadyMemberError,
    UserNotMemberError,
)

# Events
from .group_events import (
    BulkMembersAdded,
    BulkMembersRemoved,
    GroupArchived,
    GroupCreated,
    GroupDeleted,
    GroupJoinMethodChanged,
    GroupReactivated,
    GroupRestored,
    GroupSettingsUpdated,
    GroupSuspended,
    GroupUpdated,
    GroupVisibilityChanged,
    InvitationAccepted,
    InvitationDeclined,
    InvitationRevoked,
    InvitationSent,
    MemberAdded,
    MemberRemoved,
    MemberRoleChanged,
    MembershipExpired,
    MembershipRequestApproved,
    MembershipRequested,
    MembershipRequestRejected,
    OwnerAdded,
    OwnershipTransferred,
    SubgroupAdded,
    SubgroupRemoved,
)

# Entities
from .group_member import GroupMember

# Domain Services
from .group_permission_service import GroupPermissionService

__all__ = [
    # === AGGREGATES ===
    "Group",
    "GroupInvitation", 
    "GroupMembershipRequest",
    
    # === ENTITIES ===
    "GroupMember",
    
    # === DOMAIN SERVICES ===
    "GroupPermissionService",
    
    # === CONSTANTS ===
    "GroupActivityTypes",
    "GroupDefaults",
    "GroupLimits",
    "GroupNamePatterns",
    "GroupPermissionMatrix",
    "GroupTypeSettings",
    
    # === ENUMS ===
    "GroupInvitationStatus",
    "GroupJoinMethod",
    "GroupMemberRole",
    "GroupMembershipRequestStatus",
    "GroupMembershipType",
    "GroupPermission",
    "GroupStatus",
    "GroupType",
    "GroupVisibility",
    
    # === ERRORS ===
    "CircularGroupHierarchyError",
    "DuplicateMembershipRequestError", 
    "GroupAlreadyExistsError",
    "GroupArchivedError",
    "GroupError",
    "GroupHierarchyError",
    "GroupInactiveError",
    "GroupInvitationError",
    "GroupMembershipError",
    "GroupNameTooLongError",
    "GroupNotFoundError",
    "GroupOperationError",
    "GroupQuotaExceededError",
    "InsufficientGroupPermissionsError",
    "InvalidGroupSettingsError",
    "InvalidGroupTypeError",
    "InvitationAlreadyUsedError",
    "InvitationExpiredError",
    "InvitationNotFoundError",
    "MaxNestingDepthExceededError",
    "MembershipRequestError",
    "MembershipRequestNotFoundError",
    "UserAlreadyMemberError",
    "UserNotMemberError",
    
    # === EVENTS ===
    "BulkMembersAdded",
    "BulkMembersRemoved",
    "GroupArchived",
    "GroupCreated",
    "GroupDeleted",
    "GroupJoinMethodChanged",
    "GroupReactivated",
    "GroupRestored",
    "GroupSettingsUpdated",
    "GroupSuspended",
    "GroupUpdated",
    "GroupVisibilityChanged",
    "InvitationAccepted",
    "InvitationDeclined",
    "InvitationRevoked",
    "InvitationSent",
    "MemberAdded",
    "MemberRemoved",
    "MemberRoleChanged",
    "MembershipExpired",
    "MembershipRequestApproved",
    "MembershipRequested",
    "MembershipRequestRejected",
    "OwnerAdded",
    "OwnershipTransferred",
    "SubgroupAdded",
    "SubgroupRemoved",
]

# Convenience imports for common use cases
from .group import Group as GroupAggregate
from .group_member import GroupMember as GroupMemberEntity

# Version info
__version__ = "1.0.0"
__author__ = "Identity Domain Team"

# Quick access to commonly used items
CORE_AGGREGATES = [Group, GroupInvitation, GroupMembershipRequest]
CORE_ENTITIES = [GroupMember]
CORE_SERVICES = [GroupPermissionService]