"""
Authorization GraphQL Type Definitions for Identity Module

This module contains all GraphQL types related to authorization, including
roles, permissions, role assignments, and related input types.
"""


import graphene

from .common_types import (
    AuditMetadataType,
    ConnectionType,
    EdgeType,
    FilterInput,
    PageInfoType,
)
from .enums import (
    InheritanceModeEnum,
    PermissionEffectEnum,
    PermissionScopeEnum,
    PermissionTypeEnum,
    ResourceTypeEnum,
    UserRoleEnum,
)


class PermissionType(graphene.ObjectType):
    """Permission definition."""
    
    class Meta:
        description = "A specific permission that can be granted to users or roles"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the permission"
    )
    
    name = graphene.String(
        required=True,
        description="Unique name for the permission"
    )
    
    display_name = graphene.String(
        required=True,
        description="Human-readable display name"
    )
    
    description = graphene.String(
        description="Description of what this permission allows"
    )
    
    permission_type = graphene.Field(
        PermissionTypeEnum,
        required=True,
        description="Type of permission (create, read, update, delete, etc.)"
    )
    
    resource_type = graphene.Field(
        ResourceTypeEnum,
        required=True,
        description="Type of resource this permission applies to"
    )
    
    scope = graphene.Field(
        PermissionScopeEnum,
        required=True,
        description="Scope level of the permission"
    )
    
    effect = graphene.Field(
        PermissionEffectEnum,
        default_value=PermissionEffectEnum.ALLOW,
        description="Whether this permission allows or denies access"
    )
    
    conditions = graphene.JSONString(
        description="JSON conditions that must be met for this permission"
    )
    
    is_system = graphene.Boolean(
        default_value=False,
        description="Whether this is a system-defined permission"
    )
    
    is_active = graphene.Boolean(
        default_value=True,
        description="Whether this permission is currently active"
    )
    
    parent_permission_id = graphene.ID(
        description="ID of parent permission for hierarchical permissions"
    )
    
    child_permissions = graphene.List(
        "PermissionType",
        description="Child permissions that inherit from this permission"
    )
    
    roles = graphene.List(
        "RoleType",
        description="Roles that have this permission"
    )
    
    users = graphene.List(
        "UserSummaryType",
        description="Users who have this permission directly assigned"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


class RoleType(graphene.ObjectType):
    """Role definition with permissions."""
    
    class Meta:
        description = "A role that groups permissions and can be assigned to users"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the role"
    )
    
    name = graphene.String(
        required=True,
        description="Unique name for the role"
    )
    
    display_name = graphene.String(
        required=True,
        description="Human-readable display name"
    )
    
    description = graphene.String(
        description="Description of the role and its purpose"
    )
    
    role_type = graphene.Field(
        UserRoleEnum,
        description="Type/level of the role"
    )
    
    scope = graphene.Field(
        PermissionScopeEnum,
        default_value=PermissionScopeEnum.ORGANIZATION,
        description="Default scope for this role"
    )
    
    inheritance_mode = graphene.Field(
        InheritanceModeEnum,
        default_value=InheritanceModeEnum.ADDITIVE,
        description="How this role inherits permissions from parent roles"
    )
    
    is_system = graphene.Boolean(
        default_value=False,
        description="Whether this is a system-defined role"
    )
    
    is_active = graphene.Boolean(
        default_value=True,
        description="Whether this role is currently active"
    )
    
    is_default = graphene.Boolean(
        default_value=False,
        description="Whether this is a default role for new users"
    )
    
    max_users = graphene.Int(
        description="Maximum number of users that can have this role"
    )
    
    hierarchy_level = graphene.Int(
        description="Hierarchy level of the role (higher = more privileges)"
    )
    
    parent_role_id = graphene.ID(
        description="ID of parent role for role inheritance"
    )
    
    parent_role = graphene.Field(
        "RoleType",
        description="Parent role that this role inherits from"
    )
    
    child_roles = graphene.List(
        "RoleType",
        description="Child roles that inherit from this role"
    )
    
    permissions = graphene.List(
        PermissionType,
        description="Permissions directly assigned to this role"
    )
    
    effective_permissions = graphene.List(
        PermissionType,
        description="All permissions available to this role (including inherited)"
    )
    
    users = graphene.List(
        "UserSummaryType",
        description="Users who have this role assigned"
    )
    
    user_count = graphene.Int(
        description="Number of users currently assigned to this role"
    )
    
    conditions = graphene.JSONString(
        description="JSON conditions for role assignment and usage"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


class RolePermissionType(graphene.ObjectType):
    """Association between a role and a permission."""
    
    class Meta:
        description = "Link between a role and a specific permission"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the role-permission association"
    )
    
    role_id = graphene.ID(
        required=True,
        description="ID of the role"
    )
    
    permission_id = graphene.ID(
        required=True,
        description="ID of the permission"
    )
    
    role = graphene.Field(
        RoleType,
        description="The role in this association"
    )
    
    permission = graphene.Field(
        PermissionType,
        description="The permission in this association"
    )
    
    granted_by = graphene.ID(
        description="ID of user who granted this permission to the role"
    )
    
    granted_at = graphene.DateTime(
        required=True,
        description="When this permission was granted to the role"
    )
    
    expires_at = graphene.DateTime(
        description="When this permission assignment expires"
    )
    
    conditions = graphene.JSONString(
        description="Additional conditions for this specific assignment"
    )
    
    is_inherited = graphene.Boolean(
        default_value=False,
        description="Whether this permission is inherited from a parent role"
    )
    
    inherited_from_role_id = graphene.ID(
        description="ID of the role this permission was inherited from"
    )


class UserRoleType(graphene.ObjectType):
    """Association between a user and a role."""
    
    class Meta:
        description = "Assignment of a role to a specific user"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the user-role assignment"
    )
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user"
    )
    
    role_id = graphene.ID(
        required=True,
        description="ID of the role"
    )
    
    user = graphene.Field(
        "UserSummaryType",
        description="The user in this assignment"
    )
    
    role = graphene.Field(
        RoleType,
        description="The role in this assignment"
    )
    
    assigned_by = graphene.ID(
        description="ID of user who assigned this role"
    )
    
    assigned_at = graphene.DateTime(
        required=True,
        description="When this role was assigned"
    )
    
    expires_at = graphene.DateTime(
        description="When this role assignment expires"
    )
    
    scope_context = graphene.JSONString(
        description="Context for scoped role assignments (e.g., specific project)"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the user's primary role"
    )
    
    is_temporary = graphene.Boolean(
        default_value=False,
        description="Whether this is a temporary role assignment"
    )
    
    conditions = graphene.JSONString(
        description="Additional conditions for this role assignment"
    )


class PermissionCheckResult(graphene.ObjectType):
    """Result of a permission check."""
    
    class Meta:
        description = "Result of checking if a user has a specific permission"
    
    has_permission = graphene.Boolean(
        required=True,
        description="Whether the user has the requested permission"
    )
    
    permission = graphene.Field(
        PermissionType,
        description="The permission that was checked"
    )
    
    granted_through_roles = graphene.List(
        RoleType,
        description="Roles through which this permission was granted"
    )
    
    granted_directly = graphene.Boolean(
        description="Whether the permission was granted directly to the user"
    )
    
    conditions_met = graphene.Boolean(
        description="Whether all conditions for the permission were met"
    )
    
    effective_scope = graphene.Field(
        PermissionScopeEnum,
        description="Effective scope of the permission"
    )
    
    denial_reason = graphene.String(
        description="Reason why permission was denied (if applicable)"
    )


# Input Types for Role and Permission Operations

class PermissionCreateInput(graphene.InputObjectType):
    """Input type for creating a permission."""
    
    class Meta:
        description = "Input for creating a new permission"
    
    name = graphene.String(
        required=True,
        description="Unique name for the permission"
    )
    
    display_name = graphene.String(
        required=True,
        description="Human-readable display name"
    )
    
    description = graphene.String(
        description="Description of what this permission allows"
    )
    
    permission_type = graphene.Field(
        PermissionTypeEnum,
        required=True,
        description="Type of permission"
    )
    
    resource_type = graphene.Field(
        ResourceTypeEnum,
        required=True,
        description="Type of resource this permission applies to"
    )
    
    scope = graphene.Field(
        PermissionScopeEnum,
        required=True,
        description="Scope level of the permission"
    )
    
    effect = graphene.Field(
        PermissionEffectEnum,
        default_value=PermissionEffectEnum.ALLOW,
        description="Whether this permission allows or denies access"
    )
    
    conditions = graphene.JSONString(
        description="JSON conditions that must be met for this permission"
    )
    
    parent_permission_id = graphene.ID(
        description="ID of parent permission for hierarchical permissions"
    )


class PermissionUpdateInput(graphene.InputObjectType):
    """Input type for updating a permission."""
    
    class Meta:
        description = "Input for updating an existing permission"
    
    display_name = graphene.String(
        description="Updated display name"
    )
    
    description = graphene.String(
        description="Updated description"
    )
    
    conditions = graphene.JSONString(
        description="Updated conditions"
    )
    
    is_active = graphene.Boolean(
        description="Whether the permission should be active"
    )


class RoleCreateInput(graphene.InputObjectType):
    """Input type for creating a role."""
    
    class Meta:
        description = "Input for creating a new role"
    
    name = graphene.String(
        required=True,
        description="Unique name for the role"
    )
    
    display_name = graphene.String(
        required=True,
        description="Human-readable display name"
    )
    
    description = graphene.String(
        description="Description of the role and its purpose"
    )
    
    role_type = graphene.Field(
        UserRoleEnum,
        description="Type/level of the role"
    )
    
    scope = graphene.Field(
        PermissionScopeEnum,
        default_value=PermissionScopeEnum.ORGANIZATION,
        description="Default scope for this role"
    )
    
    inheritance_mode = graphene.Field(
        InheritanceModeEnum,
        default_value=InheritanceModeEnum.ADDITIVE,
        description="How this role inherits permissions"
    )
    
    max_users = graphene.Int(
        description="Maximum number of users that can have this role"
    )
    
    parent_role_id = graphene.ID(
        description="ID of parent role for inheritance"
    )
    
    permission_ids = graphene.List(
        graphene.ID,
        description="List of permission IDs to assign to this role"
    )
    
    conditions = graphene.JSONString(
        description="JSON conditions for role assignment and usage"
    )


class RoleUpdateInput(graphene.InputObjectType):
    """Input type for updating a role."""
    
    class Meta:
        description = "Input for updating an existing role"
    
    display_name = graphene.String(
        description="Updated display name"
    )
    
    description = graphene.String(
        description="Updated description"
    )
    
    max_users = graphene.Int(
        description="Updated maximum number of users"
    )
    
    conditions = graphene.JSONString(
        description="Updated conditions"
    )
    
    is_active = graphene.Boolean(
        description="Whether the role should be active"
    )


class RoleAssignmentInput(graphene.InputObjectType):
    """Input type for assigning a role to a user."""
    
    class Meta:
        description = "Input for assigning a role to a user"
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user to assign the role to"
    )
    
    role_id = graphene.ID(
        required=True,
        description="ID of the role to assign"
    )
    
    expires_at = graphene.DateTime(
        description="When this role assignment should expire"
    )
    
    scope_context = graphene.JSONString(
        description="Context for scoped role assignments"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this should be the user's primary role"
    )
    
    is_temporary = graphene.Boolean(
        default_value=False,
        description="Whether this is a temporary assignment"
    )
    
    conditions = graphene.JSONString(
        description="Additional conditions for this assignment"
    )


class PermissionCheckInput(graphene.InputObjectType):
    """Input type for permission checks."""
    
    class Meta:
        description = "Input for checking user permissions"
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user to check permissions for"
    )
    
    permission_name = graphene.String(
        description="Name of the permission to check"
    )
    
    resource_type = graphene.Field(
        ResourceTypeEnum,
        description="Type of resource to check permission for"
    )
    
    permission_type = graphene.Field(
        PermissionTypeEnum,
        description="Type of permission to check"
    )
    
    resource_id = graphene.ID(
        description="Specific resource ID to check permission for"
    )
    
    context = graphene.JSONString(
        description="Additional context for the permission check"
    )


# Filter Input Types

class PermissionFilterInput(FilterInput):
    """Input type for filtering permissions."""
    
    class Meta:
        description = "Filters for querying permissions"
    
    name = graphene.String(
        description="Filter by permission name"
    )
    
    permission_type = graphene.List(
        PermissionTypeEnum,
        description="Filter by permission type"
    )
    
    resource_type = graphene.List(
        ResourceTypeEnum,
        description="Filter by resource type"
    )
    
    scope = graphene.List(
        PermissionScopeEnum,
        description="Filter by permission scope"
    )
    
    effect = graphene.List(
        PermissionEffectEnum,
        description="Filter by permission effect"
    )
    
    is_system = graphene.Boolean(
        description="Filter by system permission status"
    )
    
    is_active = graphene.Boolean(
        description="Filter by active status"
    )


class RoleFilterInput(FilterInput):
    """Input type for filtering roles."""
    
    class Meta:
        description = "Filters for querying roles"
    
    name = graphene.String(
        description="Filter by role name"
    )
    
    role_type = graphene.List(
        UserRoleEnum,
        description="Filter by role type"
    )
    
    scope = graphene.List(
        PermissionScopeEnum,
        description="Filter by role scope"
    )
    
    is_system = graphene.Boolean(
        description="Filter by system role status"
    )
    
    is_active = graphene.Boolean(
        description="Filter by active status"
    )
    
    is_default = graphene.Boolean(
        description="Filter by default role status"
    )
    
    has_users = graphene.Boolean(
        description="Filter by whether role has users assigned"
    )


# Connection Types for Relay Pagination

class RoleEdge(graphene.ObjectType):
    """Role edge for Relay connections."""
    
    class Meta:
        interfaces = (EdgeType,)
        description = "Role edge containing cursor and node"
    
    node = graphene.Field(
        RoleType,
        description="The role node"
    )
    
    cursor = graphene.String(
        required=True,
        description="Cursor for this edge"
    )


class RoleConnection(graphene.ObjectType):
    """Role connection for Relay pagination."""
    
    class Meta:
        interfaces = (ConnectionType,)
        description = "Role connection with edges and page info"
    
    edges = graphene.List(
        RoleEdge,
        description="List of role edges"
    )
    
    page_info = graphene.Field(
        PageInfoType,
        required=True,
        description="Pagination information"
    )
    
    total_count = graphene.Int(
        description="Total number of roles matching the query"
    )


class PermissionEdge(graphene.ObjectType):
    """Permission edge for Relay connections."""
    
    class Meta:
        interfaces = (EdgeType,)
        description = "Permission edge containing cursor and node"
    
    node = graphene.Field(
        PermissionType,
        description="The permission node"
    )
    
    cursor = graphene.String(
        required=True,
        description="Cursor for this edge"
    )


class PermissionConnection(graphene.ObjectType):
    """Permission connection for Relay pagination."""
    
    class Meta:
        interfaces = (ConnectionType,)
        description = "Permission connection with edges and page info"
    
    edges = graphene.List(
        PermissionEdge,
        description="List of permission edges"
    )
    
    page_info = graphene.Field(
        PageInfoType,
        required=True,
        description="Pagination information"
    )
    
    total_count = graphene.Int(
        description="Total number of permissions matching the query"
    )


# Export all types
__all__ = [
    "PermissionCheckInput",
    "PermissionCheckResult",
    "PermissionConnection",
    "PermissionCreateInput",
    "PermissionEdge",
    "PermissionFilterInput",
    "PermissionType",
    "PermissionUpdateInput",
    "RoleAssignmentInput",
    "RoleConnection",
    "RoleCreateInput",
    "RoleEdge",
    "RoleFilterInput",
    "RolePermissionType",
    "RoleType",
    "RoleUpdateInput",
    "UserRoleType",
]