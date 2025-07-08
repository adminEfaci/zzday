"""
User query handlers.

Handles retrieval of user information, profiles, preferences, and 
user-related analytics.
"""

from .get_user_devices_query import GetUserDevicesQuery, GetUserDevicesQueryHandler
from .get_user_permissions_query import (
    GetUserPermissionsQuery,
    GetUserPermissionsQueryHandler,
)
from .get_user_preferences_query import (
    GetUserPreferencesQuery,
    GetUserPreferencesQueryHandler,
)
from .get_user_profile_query import GetUserProfileQuery, GetUserProfileQueryHandler
from .get_user_sessions_query import GetUserSessionsQuery, GetUserSessionsQueryHandler
from .search_users_query import SearchUsersQuery, SearchUsersQueryHandler

__all__ = [
    # User devices
    "GetUserDevicesQuery",
    "GetUserDevicesQueryHandler",
    # User permissions
    "GetUserPermissionsQuery",
    "GetUserPermissionsQueryHandler",
    # User preferences
    "GetUserPreferencesQuery",
    "GetUserPreferencesQueryHandler",
    # User profile
    "GetUserProfileQuery",
    "GetUserProfileQueryHandler",
    # User sessions
    "GetUserSessionsQuery",
    "GetUserSessionsQueryHandler",
    # User search
    "SearchUsersQuery",
    "SearchUsersQueryHandler"
]