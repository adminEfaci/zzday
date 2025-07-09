"""
Group Entity Enumerations

Enums with rich utility methods for group management and membership.
"""

from enum import Enum


class GroupType(str, Enum):
    """Types of groups in the system."""
    TEAM = "team"
    DEPARTMENT = "department"
    PROJECT = "project"
    COMMITTEE = "committee"
    ORGANIZATION = "organization"
    CUSTOM = "custom"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        names = {
            self.TEAM: "Team",
            self.DEPARTMENT: "Department", 
            self.PROJECT: "Project",
            self.COMMITTEE: "Committee",
            self.ORGANIZATION: "Organization",
            self.CUSTOM: "Custom Group"
        }
        return names[self]
    
    @property
    def description(self) -> str:
        """Get type description."""
        descriptions = {
            self.TEAM: "Small collaborative groups for specific work",
            self.DEPARTMENT: "Organizational departments and divisions",
            self.PROJECT: "Temporary groups for specific projects",
            self.COMMITTEE: "Formal committees and working groups",
            self.ORGANIZATION: "Large organizational units",
            self.CUSTOM: "Custom group type with flexible settings"
        }
        return descriptions[self]
    
    @property
    def supports_nesting(self) -> bool:
        """Check if this type supports nested groups."""
        return self in [self.DEPARTMENT, self.ORGANIZATION, self.CUSTOM]
    
    @classmethod
    def get_hierarchical_types(cls) -> list['GroupType']:
        """Get types that support hierarchy."""
        return [cls.DEPARTMENT, cls.ORGANIZATION, cls.CUSTOM]


class GroupVisibility(str, Enum):
    """Group visibility levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    SECRET = "secret"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.title()
    
    @property
    def description(self) -> str:
        """Get visibility description."""
        descriptions = {
            self.PUBLIC: "Visible to everyone, including external users",
            self.INTERNAL: "Visible to all internal users",
            self.PRIVATE: "Visible only to members",
            self.SECRET: "Hidden from all searches and listings"
        }
        return descriptions[self]
    
    @property
    def privacy_level(self) -> int:
        """Get numeric privacy level (higher = more private)."""
        levels = {
            self.PUBLIC: 1,
            self.INTERNAL: 2,
            self.PRIVATE: 3,
            self.SECRET: 4
        }
        return levels[self]
    
    def is_more_private_than(self, other: 'GroupVisibility') -> bool:
        """Check if this visibility is more private than another."""
        return self.privacy_level > other.privacy_level
    
    @classmethod
    def get_public_levels(cls) -> list['GroupVisibility']:
        """Get visibility levels that are publicly discoverable."""
        return [cls.PUBLIC, cls.INTERNAL]


class GroupMemberRole(str, Enum):
    """Roles within a group."""
    OWNER = "owner"
    ADMIN = "admin"
    MODERATOR = "moderator"
    MEMBER = "member"
    GUEST = "guest"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.title()
    
    @property
    def description(self) -> str:
        """Get role description."""
        descriptions = {
            self.OWNER: "Full control over group settings and membership",
            self.ADMIN: "Manage group settings and most member operations", 
            self.MODERATOR: "Manage member activities and approve requests",
            self.MEMBER: "Regular group member with basic permissions",
            self.GUEST: "Limited access member with view-only permissions"
        }
        return descriptions[self]
    
    def get_hierarchy_level(self) -> int:
        """Get numeric level for role comparison."""
        levels = {
            self.GUEST: 1,
            self.MEMBER: 2,
            self.MODERATOR: 3,
            self.ADMIN: 4,
            self.OWNER: 5
        }
        return levels[self]
    
    def can_manage_role(self, target_role: 'GroupMemberRole') -> bool:
        """Check if this role can manage target role."""
        return self.get_hierarchy_level() > target_role.get_hierarchy_level()
    
    def is_elevated(self) -> bool:
        """Check if this is an elevated role (moderator+)."""
        return self in [self.OWNER, self.ADMIN, self.MODERATOR]
    
    def is_administrative(self) -> bool:
        """Check if this is an administrative role (admin+)."""
        return self in [self.OWNER, self.ADMIN]
    
    @classmethod
    def get_management_roles(cls) -> list['GroupMemberRole']:
        """Get roles that can manage others."""
        return [cls.OWNER, cls.ADMIN, cls.MODERATOR]
    
    @classmethod
    def get_roles_below(cls, role: 'GroupMemberRole') -> list['GroupMemberRole']:
        """Get all roles below the specified role."""
        all_roles = [cls.GUEST, cls.MEMBER, cls.MODERATOR, cls.ADMIN, cls.OWNER]
        role_index = all_roles.index(role)
        return all_roles[:role_index]


class GroupJoinMethod(str, Enum):
    """How users can join a group."""
    OPEN = "open"
    REQUEST = "request"
    INVITE_ONLY = "invite_only"
    ADMIN_ADD = "admin_add"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        names = {
            self.OPEN: "Open",
            self.REQUEST: "Request to Join",
            self.INVITE_ONLY: "Invite Only",
            self.ADMIN_ADD: "Admin Add Only"
        }
        return names[self]
    
    @property
    def description(self) -> str:
        """Get join method description."""
        descriptions = {
            self.OPEN: "Anyone can join immediately",
            self.REQUEST: "Users can request to join (approval required)",
            self.INVITE_ONLY: "Users can only join via invitation",
            self.ADMIN_ADD: "Only admins can add new members"
        }
        return descriptions[self]
    
    @property
    def requires_approval(self) -> bool:
        """Check if this method requires approval."""
        return self in [self.REQUEST, self.INVITE_ONLY, self.ADMIN_ADD]
    
    @property
    def allows_self_join(self) -> bool:
        """Check if users can join themselves."""
        return self in [self.OPEN, self.REQUEST]
    
    @classmethod
    def get_restrictive_methods(cls) -> list['GroupJoinMethod']:
        """Get methods that restrict joining."""
        return [cls.INVITE_ONLY, cls.ADMIN_ADD]


class GroupStatus(str, Enum):
    """Group lifecycle status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"
    DELETED = "deleted"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.title()
    
    @property
    def description(self) -> str:
        """Get status description."""
        descriptions = {
            self.ACTIVE: "Group is active and fully functional",
            self.INACTIVE: "Group is temporarily inactive",
            self.SUSPENDED: "Group is suspended due to policy violations",
            self.ARCHIVED: "Group is archived but data is preserved",
            self.DELETED: "Group is marked for deletion"
        }
        return descriptions[self]
    
    @property
    def is_operational(self) -> bool:
        """Check if group is operational."""
        return self == self.ACTIVE
    
    @property
    def allows_modifications(self) -> bool:
        """Check if group can be modified."""
        return self in [self.ACTIVE, self.INACTIVE]
    
    @property
    def is_recoverable(self) -> bool:
        """Check if group can be restored."""
        return self in [self.INACTIVE, self.SUSPENDED, self.ARCHIVED]
    
    @classmethod
    def get_terminal_states(cls) -> list['GroupStatus']:
        """Get states that are terminal (hard to reverse)."""
        return [cls.ARCHIVED, cls.DELETED]


class GroupInvitationStatus(str, Enum):
    """Status of group invitations."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    EXPIRED = "expired"
    REVOKED = "revoked"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.title()
    
    @property
    def is_final(self) -> bool:
        """Check if this is a final status."""
        return self in [self.ACCEPTED, self.DECLINED, self.EXPIRED, self.REVOKED]
    
    @property
    def is_actionable(self) -> bool:
        """Check if invitation can still be acted upon."""
        return self == self.PENDING
    
    @classmethod
    def get_final_states(cls) -> list['GroupInvitationStatus']:
        """Get all final states."""
        return [cls.ACCEPTED, cls.DECLINED, cls.EXPIRED, cls.REVOKED]


class GroupMembershipRequestStatus(str, Enum):
    """Status of membership requests."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        return self.value.title()
    
    @property
    def is_final(self) -> bool:
        """Check if this is a final status."""
        return self in [self.APPROVED, self.REJECTED, self.WITHDRAWN, self.EXPIRED]
    
    @property
    def is_actionable(self) -> bool:
        """Check if request can still be acted upon."""
        return self == self.PENDING
    
    @property
    def was_successful(self) -> bool:
        """Check if request was successful."""
        return self == self.APPROVED
    
    @classmethod
    def get_final_states(cls) -> list['GroupMembershipRequestStatus']:
        """Get all final states."""
        return [cls.APPROVED, cls.REJECTED, cls.WITHDRAWN, cls.EXPIRED]


class GroupMembershipType(str, Enum):
    """Types of group membership."""
    DIRECT = "direct"
    INHERITED = "inherited"
    NESTED = "nested"
    TEMPORARY = "temporary"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        names = {
            self.DIRECT: "Direct Member",
            self.INHERITED: "Inherited Member", 
            self.NESTED: "Nested Member",
            self.TEMPORARY: "Temporary Member"
        }
        return names[self]
    
    @property
    def description(self) -> str:
        """Get membership type description."""
        descriptions = {
            self.DIRECT: "Directly added to this group",
            self.INHERITED: "Member through parent group inheritance",
            self.NESTED: "Member through nested group structure",
            self.TEMPORARY: "Temporary membership with expiration"
        }
        return descriptions[self]
    
    @property
    def is_permanent(self) -> bool:
        """Check if this is a permanent membership type."""
        return self in [self.DIRECT, self.INHERITED, self.NESTED]
    
    @property
    def can_be_directly_managed(self) -> bool:
        """Check if this membership can be directly managed."""
        return self in [self.DIRECT, self.TEMPORARY]


class GroupPermission(str, Enum):
    """Permissions within a group."""
    VIEW_MEMBERS = "view_members"
    ADD_MEMBERS = "add_members"
    REMOVE_MEMBERS = "remove_members"
    EDIT_GROUP = "edit_group"
    DELETE_GROUP = "delete_group"
    MANAGE_ROLES = "manage_roles"
    CREATE_SUBGROUP = "create_subgroup"
    MANAGE_SETTINGS = "manage_settings"
    
    @property
    def display_name(self) -> str:
        """Get user-friendly display name."""
        names = {
            self.VIEW_MEMBERS: "View Members",
            self.ADD_MEMBERS: "Add Members",
            self.REMOVE_MEMBERS: "Remove Members",
            self.EDIT_GROUP: "Edit Group",
            self.DELETE_GROUP: "Delete Group",
            self.MANAGE_ROLES: "Manage Roles",
            self.CREATE_SUBGROUP: "Create Subgroups",
            self.MANAGE_SETTINGS: "Manage Settings"
        }
        return names[self]
    
    @property
    def description(self) -> str:
        """Get permission description."""
        descriptions = {
            self.VIEW_MEMBERS: "View the list of group members",
            self.ADD_MEMBERS: "Add new members to the group",
            self.REMOVE_MEMBERS: "Remove members from the group",
            self.EDIT_GROUP: "Edit group information and description",
            self.DELETE_GROUP: "Delete the entire group",
            self.MANAGE_ROLES: "Change member roles and permissions",
            self.CREATE_SUBGROUP: "Create nested subgroups",
            self.MANAGE_SETTINGS: "Modify group settings and configuration"
        }
        return descriptions[self]
    
    @property
    def is_destructive(self) -> bool:
        """Check if this is a destructive permission."""
        return self in [self.REMOVE_MEMBERS, self.DELETE_GROUP]
    
    @property
    def requires_elevated_role(self) -> bool:
        """Check if this permission requires elevated role."""
        return self in [
            self.REMOVE_MEMBERS, self.DELETE_GROUP, 
            self.MANAGE_ROLES, self.MANAGE_SETTINGS
        ]
    
    @classmethod
    def get_basic_permissions(cls) -> set['GroupPermission']:
        """Get basic permissions for regular members."""
        return {cls.VIEW_MEMBERS}
    
    @classmethod
    def get_management_permissions(cls) -> set['GroupPermission']:
        """Get permissions for management roles."""
        return {
            cls.VIEW_MEMBERS, cls.ADD_MEMBERS, cls.REMOVE_MEMBERS,
            cls.EDIT_GROUP, cls.MANAGE_ROLES, cls.MANAGE_SETTINGS
        }


# Export all enums
__all__ = [
    'GroupInvitationStatus',
    'GroupJoinMethod',
    'GroupMemberRole',
    'GroupMembershipRequestStatus',
    'GroupMembershipType',
    'GroupPermission',
    'GroupStatus',
    'GroupType',
    'GroupVisibility'
]