"""
User Status Subscription Resolvers

Real-time subscriptions for user status changes, login/logout events,
profile updates, role assignments, and session events.
"""

from collections.abc import AsyncGenerator
from uuid import UUID

import strawberry
from strawberry.types import Info

from ..middleware import require_authentication, require_permission
from .base_subscription import (
    BaseSubscriptionResolver,
    RateLimitConfig,
    SubscriptionFilter,
)


@strawberry.type
class UserStatusChange:
    """User status change event."""
    user_id: strawberry.ID
    old_status: str
    new_status: str
    changed_by: strawberry.ID | None = None
    reason: str | None = None
    timestamp: str
    ip_address: str | None = None
    user_agent: str | None = None


@strawberry.type
class UserLoginEvent:
    """User login event."""
    user_id: strawberry.ID
    session_id: strawberry.ID
    session_type: str
    ip_address: str
    user_agent: str
    device_info: str
    mfa_verified: bool
    location: str | None = None
    timestamp: str


@strawberry.type  
class UserLogoutEvent:
    """User logout event."""
    user_id: strawberry.ID
    session_id: strawberry.ID
    logout_type: str  # manual, timeout, forced
    ip_address: str
    user_agent: str
    timestamp: str


@strawberry.type
class UserProfileUpdate:
    """User profile update event."""
    user_id: strawberry.ID
    updated_fields: list[str]
    updated_by: strawberry.ID | None = None
    ip_address: str
    user_agent: str
    timestamp: str


@strawberry.type
class UserPreferencesChange:
    """User preferences change event."""
    user_id: strawberry.ID
    preference_category: str
    changed_settings: list[str] 
    timestamp: str


@strawberry.type
class UserRoleAssignment:
    """User role assignment event."""
    user_id: strawberry.ID
    role_name: str
    assigned_by: strawberry.ID
    assignment_type: str  # granted, revoked
    effective_date: str | None = None
    expiry_date: str | None = None
    timestamp: str


@strawberry.type
class UserPermissionChange:
    """User permission change event."""
    user_id: strawberry.ID
    permission_name: str
    change_type: str  # granted, revoked
    changed_by: strawberry.ID
    resource_id: strawberry.ID | None = None
    timestamp: str


@strawberry.type
class UserSessionEvent:
    """User session event (created/expired)."""
    user_id: strawberry.ID
    session_id: strawberry.ID
    event_type: str  # created, expired
    session_type: str
    ip_address: str
    user_agent: str
    expires_at: str | None = None
    reason: str | None = None
    timestamp: str


class UserStatusSubscriptions(BaseSubscriptionResolver):
    """Subscription resolvers for user status and activity events."""
    
    @strawberry.subscription
    @require_authentication
    async def user_status_changed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserStatusChange, None]:
        """Subscribe to user status changes."""
        security_context = await self._authenticate_connection(info)
        
        # Create filters
        filters = SubscriptionFilter()
        if user_id:
            # Check authorization for specific user
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:view")):
                self._authorize_subscription(
                    security_context, 
                    "user_status",
                    ["user:admin", "user:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            # For all users, require admin permission
            self._authorize_subscription(
                security_context,
                "user_status", 
                ["user:admin"]
            )
        
        filters.event_types.add("user_status_changed")
        
        # Create connection context
        context = self._create_connection_context(
            security_context,
            "user_status", 
            filters,
            RateLimitConfig(max_events=50, window_seconds=60)
        )
        
        # Listen to events
        event_stream = self._listen_to_channel("user_status")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_status_changed":
                yield UserStatusChange(
                    user_id=event["user_id"],
                    old_status=event["old_status"],
                    new_status=event["new_status"],
                    changed_by=event.get("changed_by"),
                    reason=event.get("reason"),
                    timestamp=event["timestamp"],
                    ip_address=event.get("ip_address"),
                    user_agent=event.get("user_agent")
                )
    
    @strawberry.subscription
    @require_authentication
    async def user_logged_in(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserLoginEvent, None]:
        """Subscribe to user login events."""
        security_context = await self._authenticate_connection(info)
        
        # Create filters
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:view")):
                self._authorize_subscription(
                    security_context,
                    "user_login",
                    ["user:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_login",
                ["user:admin", "security:view"]
            )
        
        filters.event_types.add("user_login")
        
        context = self._create_connection_context(
            security_context,
            "user_login",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_activity")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_login":
                yield UserLoginEvent(
                    user_id=event["user_id"],
                    session_id=event["session_id"],
                    session_type=event["session_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    device_info=event.get("device_info", ""),
                    mfa_verified=event.get("mfa_verified", False),
                    location=event.get("location"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def user_logged_out(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserLogoutEvent, None]:
        """Subscribe to user logout events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:view")):
                self._authorize_subscription(
                    security_context,
                    "user_logout", 
                    ["user:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_logout",
                ["user:admin", "security:view"]
            )
        
        filters.event_types.add("user_logout")
        
        context = self._create_connection_context(
            security_context,
            "user_logout",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_activity")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_logout":
                yield UserLogoutEvent(
                    user_id=event["user_id"],
                    session_id=event["session_id"],
                    logout_type=event["logout_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def user_profile_updated(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserProfileUpdate, None]:
        """Subscribe to user profile updates."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:view")):
                self._authorize_subscription(
                    security_context,
                    "user_profile",
                    ["user:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_profile",
                ["user:admin"]
            )
        
        filters.event_types.add("user_profile_updated")
        
        context = self._create_connection_context(
            security_context,
            "user_profile",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_profile")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_profile_updated":
                yield UserProfileUpdate(
                    user_id=event["user_id"],
                    updated_fields=event["updated_fields"],
                    updated_by=event.get("updated_by"),
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication  
    async def user_preferences_changed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserPreferencesChange, None]:
        """Subscribe to user preference changes."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can subscribe to their own preferences
            if target_user_id != security_context.user_id:
                self._authorize_subscription(
                    security_context,
                    "user_preferences",
                    ["user:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_preferences",
                ["user:admin"]
            )
        
        filters.event_types.add("user_preferences_changed")
        
        context = self._create_connection_context(
            security_context,
            "user_preferences",
            filters,
            RateLimitConfig(max_events=15, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_preferences")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_preferences_changed":
                yield UserPreferencesChange(
                    user_id=event["user_id"],
                    preference_category=event["preference_category"],
                    changed_settings=event["changed_settings"],
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    async def user_role_assigned(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserRoleAssignment, None]:
        """Subscribe to user role assignments."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            filters.user_ids.add(UUID(user_id))
        
        filters.event_types.add("user_role_assigned")
        filters.event_types.add("user_role_revoked")
        
        context = self._create_connection_context(
            security_context,
            "user_roles",
            filters,
            RateLimitConfig(max_events=25, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_roles")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") in ["user_role_assigned", "user_role_revoked"]:
                yield UserRoleAssignment(
                    user_id=event["user_id"],
                    role_name=event["role_name"],
                    assigned_by=event["assigned_by"],
                    assignment_type=event["assignment_type"],
                    effective_date=event.get("effective_date"),
                    expiry_date=event.get("expiry_date"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    async def user_permission_changed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserPermissionChange, None]:
        """Subscribe to user permission changes."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            filters.user_ids.add(UUID(user_id))
        
        filters.event_types.add("user_permission_granted")
        filters.event_types.add("user_permission_revoked")
        
        context = self._create_connection_context(
            security_context,
            "user_permissions",
            filters,
            RateLimitConfig(max_events=25, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("user_permissions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") in [
                "user_permission_granted", "user_permission_revoked"
            ]:
                yield UserPermissionChange(
                    user_id=event["user_id"],
                    permission_name=event["permission_name"],
                    change_type=event["change_type"],
                    changed_by=event["changed_by"],
                    resource_id=event.get("resource_id"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def user_session_created(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserSessionEvent, None]:
        """Subscribe to user session creation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:view")):
                self._authorize_subscription(
                    security_context,
                    "user_sessions",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_sessions",
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("session_created")
        
        context = self._create_connection_context(
            security_context,
            "user_sessions",
            filters,
            RateLimitConfig(max_events=40, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_created":
                yield UserSessionEvent(
                    user_id=event["user_id"],
                    session_id=event["session_id"],
                    event_type="created",
                    session_type=event["session_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    expires_at=event.get("expires_at"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def user_session_expired(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[UserSessionEvent, None]:
        """Subscribe to user session expiration events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:view")):
                self._authorize_subscription(
                    security_context,
                    "user_sessions",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "user_sessions", 
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("session_expired")
        
        context = self._create_connection_context(
            security_context,
            "user_sessions",
            filters,
            RateLimitConfig(max_events=40, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_expired":
                yield UserSessionEvent(
                    user_id=event["user_id"],
                    session_id=event["session_id"],
                    event_type="expired",
                    session_type=event.get("session_type", "unknown"),
                    ip_address=event.get("ip_address", ""),
                    user_agent=event.get("user_agent", ""),
                    reason=event.get("reason"),
                    timestamp=event["timestamp"]
                )