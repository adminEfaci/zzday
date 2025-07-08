"""
Authorization query handlers.

Handles retrieval of role-based access control, permissions, policies, and 
access decisions.
"""

from .check_permission_query import CheckPermissionQuery, CheckPermissionQueryHandler
from .get_access_policies_query import (
    GetAccessPoliciesQuery,
    GetAccessPoliciesQueryHandler,
)
from .get_resource_access_query import (
    GetResourceAccessQuery,
    GetResourceAccessQueryHandler,
)
from .get_role_permissions_query import (
    GetRolePermissionsQuery,
    GetRolePermissionsQueryHandler,
)
from .get_user_access_query import GetUserAccessQuery, GetUserAccessQueryHandler

__all__ = [
    # Permission checking
    "CheckPermissionQuery",
    "CheckPermissionQueryHandler",
    # Access policies
    "GetAccessPoliciesQuery",
    "GetAccessPoliciesQueryHandler",
    # Resource access
    "GetResourceAccessQuery",
    "GetResourceAccessQueryHandler",
    # Role permissions
    "GetRolePermissionsQuery",
    "GetRolePermissionsQueryHandler",
    # User access
    "GetUserAccessQuery",
    "GetUserAccessQueryHandler"
]