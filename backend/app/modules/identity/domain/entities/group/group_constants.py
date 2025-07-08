"""
Group Entity Constants

Group-specific constants that extend domain-wide constants without duplication.
"""

from dataclasses import dataclass
from datetime import timedelta

# Import domain-wide constants to extend, not duplicate
from ...constants import SecurityLimits, ValidationRules


@dataclass(frozen=True)
class GroupLimits:
    """Group-specific limits extending domain SecurityLimits."""
    # Member limits
    MAX_MEMBERS_PER_GROUP: int = 10000
    MAX_OWNERS_PER_GROUP: int = 10
    MIN_OWNERS_REQUIRED: int = 1
    
    # Hierarchy limits
    MAX_NESTING_DEPTH: int = 5
    MAX_SUBGROUPS: int = 100
    
    # Content limits
    MAX_NAME_LENGTH: int = ValidationRules.NAME_MAX_LENGTH  # Reuse domain constant
    MIN_NAME_LENGTH: int = ValidationRules.NAME_MIN_LENGTH  # Reuse domain constant
    MAX_DESCRIPTION_LENGTH: int = 500
    MAX_TAGS_PER_GROUP: int = 20
    MAX_TAG_LENGTH: int = 50
    MAX_CUSTOM_ATTRIBUTES: int = 50
    
    # Time limits
    INVITATION_EXPIRY_DAYS: int = 7
    MEMBERSHIP_REQUEST_EXPIRY_DAYS: int = 30


@dataclass(frozen=True)
class GroupDefaults:
    """Default values for group settings."""
    DEFAULT_VISIBILITY: str = "internal"
    DEFAULT_JOIN_METHOD: str = "invite_only"
    DEFAULT_MEMBER_ROLE: str = "member"
    DEFAULT_MAX_MEMBERS: int = 1000
    DEFAULT_ALLOW_NESTED_GROUPS: bool = True
    DEFAULT_ALLOW_GUEST_MEMBERS: bool = False
    DEFAULT_REQUIRE_APPROVAL: bool = True
    DEFAULT_AUTO_APPROVE_MEMBERS: bool = False


class GroupPermissionMatrix:
    """Permission matrix for group roles."""
    
    OWNER_PERMISSIONS: set[str] = {
        "view_members", "add_members", "remove_members", "edit_group",
        "delete_group", "manage_roles", "create_subgroup", "manage_settings",
        "transfer_ownership", "manage_invitations", "approve_requests"
    }
    
    ADMIN_PERMISSIONS: set[str] = {
        "view_members", "add_members", "remove_members", "edit_group",
        "manage_roles", "create_subgroup", "manage_settings",
        "manage_invitations", "approve_requests"
    }
    
    MODERATOR_PERMISSIONS: set[str] = {
        "view_members", "add_members", "remove_members",
        "manage_invitations", "approve_requests"
    }
    
    MEMBER_PERMISSIONS: set[str] = {
        "view_members", "invite_members"
    }
    
    GUEST_PERMISSIONS: set[str] = {
        "view_members"
    }
    
    @classmethod
    def get_permissions_for_role(cls, role: str) -> set[str]:
        """Get permissions for a specific role."""
        role_permissions = {
            "owner": cls.OWNER_PERMISSIONS,
            "admin": cls.ADMIN_PERMISSIONS,
            "moderator": cls.MODERATOR_PERMISSIONS,
            "member": cls.MEMBER_PERMISSIONS,
            "guest": cls.GUEST_PERMISSIONS
        }
        return role_permissions.get(role, set())


class GroupNamePatterns:
    """Group name validation patterns extending domain ValidationRules."""
    
    # Reserved prefixes
    RESERVED_PREFIXES: set[str] = {
        "system:", "admin:", "internal:", "test:", "temp:", "_"
    }
    
    # Forbidden characters (stricter than domain USERNAME_PATTERN)
    FORBIDDEN_CHARS: set[str] = {
        "/", "\\", "<", ">", ":", '"', "|", "?", "*", "\0"
    }
    
    # Reserved names
    RESERVED_NAMES: set[str] = {
        "admin", "administrator", "root", "system", "superuser",
        "all", "everyone", "nobody", "anonymous", "guest",
        "public", "private", "default"
    }


class GroupTypeSettings:
    """Settings specific to different group types."""
    
    TYPE_SETTINGS: dict[str, dict[str, any]] = {
        "team": {
            "max_members": 50,
            "allow_subgroups": True,
            "allow_guests": False,
            "default_visibility": "internal"
        },
        "department": {
            "max_members": 500,
            "allow_subgroups": True,
            "allow_guests": False,
            "default_visibility": "internal"
        },
        "project": {
            "max_members": 100,
            "allow_subgroups": True,
            "allow_guests": True,
            "default_visibility": "private"
        },
        "organization": {
            "max_members": 10000,
            "allow_subgroups": True,
            "allow_guests": False,
            "default_visibility": "public"
        },
        "custom": {
            "max_members": 1000,
            "allow_subgroups": True,
            "allow_guests": True,
            "default_visibility": "private"
        }
    }
    
    @classmethod
    def get_settings_for_type(cls, group_type: str) -> dict[str, any]:
        """Get settings for a specific group type."""
        return cls.TYPE_SETTINGS.get(group_type, cls.TYPE_SETTINGS["custom"])


class GroupActivityTypes:
    """Types of activities tracked for groups."""
    
    # Member activities
    MEMBER_JOINED = "member_joined"
    MEMBER_LEFT = "member_left"
    MEMBER_REMOVED = "member_removed"
    MEMBER_ROLE_CHANGED = "member_role_changed"
    
    # Group management
    GROUP_CREATED = "group_created"
    GROUP_UPDATED = "group_updated"
    GROUP_DELETED = "group_deleted"
    GROUP_ARCHIVED = "group_archived"
    
    # Invitation activities
    INVITATION_SENT = "invitation_sent"
    INVITATION_ACCEPTED = "invitation_accepted"
    INVITATION_DECLINED = "invitation_declined"
    
    # Request activities
    MEMBERSHIP_REQUESTED = "membership_requested"
    REQUEST_APPROVED = "request_approved"
    REQUEST_REJECTED = "request_rejected"


# Export all constants
__all__ = [
    'GroupActivityTypes',
    'GroupDefaults',
    'GroupLimits',
    'GroupNamePatterns',
    'GroupPermissionMatrix',
    'GroupTypeSettings'
]