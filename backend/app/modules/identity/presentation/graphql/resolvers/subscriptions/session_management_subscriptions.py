"""
Session Management Subscription Resolvers

Real-time subscriptions for session lifecycle events, session activity,
concurrent session detection, and session security alerts.
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
class SessionCreated:
    """Session creation event."""
    session_id: strawberry.ID
    user_id: strawberry.ID
    session_type: str
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    location: str | None = None
    expires_at: str
    created_via: str  # login, refresh, impersonation
    mfa_verified: bool
    device_trusted: bool
    timestamp: str


@strawberry.type
class SessionExpired:
    """Session expiration event."""
    session_id: strawberry.ID
    user_id: strawberry.ID
    session_type: str
    expiry_reason: str  # timeout, manual, security, policy
    ip_address: str | None = None
    last_activity: str
    auto_cleanup: bool
    grace_period: int | None = None  # seconds
    timestamp: str


@strawberry.type
class SessionRevoked:
    """Session revocation event."""
    session_id: strawberry.ID
    user_id: strawberry.ID
    session_type: str
    revoked_by: strawberry.ID | None = None
    revocation_reason: str
    revoke_all_sessions: bool
    force_logout: bool
    ip_address: str
    user_agent: str
    timestamp: str


@strawberry.type
class SessionActivity:
    """Session activity event."""
    session_id: strawberry.ID
    user_id: strawberry.ID
    activity_type: str  # request, heartbeat, refresh, update
    ip_address: str
    user_agent: str
    location: str | None = None
    endpoint: str | None = None
    request_count: int
    last_seen: str
    risk_score: float
    anomaly_detected: bool
    timestamp: str


@strawberry.type
class ConcurrentSessionsDetected:
    """Concurrent sessions detection event."""
    user_id: strawberry.ID
    active_session_count: int
    max_allowed_sessions: int
    session_ids: list[strawberry.ID]
    detection_trigger: str  # new_login, policy_check, periodic_scan
    locations: list[str]
    devices: list[str]
    action_taken: str  # none, oldest_terminated, all_terminated, user_notified
    timestamp: str


@strawberry.type
class SessionSecurityAlert:
    """Session security alert event."""
    alert_id: strawberry.ID
    session_id: strawberry.ID
    user_id: strawberry.ID
    alert_type: str  # location_change, device_change, suspicious_activity
    severity: str
    details: str
    risk_indicators: list[str]
    auto_mitigated: bool
    mitigation_actions: list[str]
    requires_user_action: bool
    timestamp: str


class SessionManagementSubscriptions(BaseSubscriptionResolver):
    """Subscription resolvers for session management events."""
    
    @strawberry.subscription
    @require_authentication
    async def session_created(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SessionCreated, None]:
        """Subscribe to session creation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own sessions
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:view")):
                self._authorize_subscription(
                    security_context,
                    "session_created_user",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "session_created",
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("session_created")
        
        context = self._create_connection_context(
            security_context,
            "session_created",
            filters,
            RateLimitConfig(max_events=50, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_created":
                yield SessionCreated(
                    session_id=event["session_id"],
                    user_id=event["user_id"],
                    session_type=event["session_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    device_fingerprint=event.get("device_fingerprint"),
                    location=event.get("location"),
                    expires_at=event["expires_at"],
                    created_via=event.get("created_via", "login"),
                    mfa_verified=event.get("mfa_verified", False),
                    device_trusted=event.get("device_trusted", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def session_expired(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SessionExpired, None]:
        """Subscribe to session expiration events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own sessions
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:view")):
                self._authorize_subscription(
                    security_context,
                    "session_expired_user",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "session_expired",
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("session_expired")
        
        context = self._create_connection_context(
            security_context,
            "session_expired",
            filters,
            RateLimitConfig(max_events=40, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_expired":
                yield SessionExpired(
                    session_id=event["session_id"],
                    user_id=event["user_id"],
                    session_type=event.get("session_type", "unknown"),
                    expiry_reason=event["expiry_reason"],
                    ip_address=event.get("ip_address"),
                    last_activity=event["last_activity"],
                    auto_cleanup=event.get("auto_cleanup", True),
                    grace_period=event.get("grace_period"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def session_revoked(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SessionRevoked, None]:
        """Subscribe to session revocation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own sessions
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:view")):
                self._authorize_subscription(
                    security_context,
                    "session_revoked_user",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "session_revoked",
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("session_revoked")
        
        context = self._create_connection_context(
            security_context,
            "session_revoked",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_revoked":
                yield SessionRevoked(
                    session_id=event["session_id"],
                    user_id=event["user_id"],
                    session_type=event.get("session_type", "unknown"),
                    revoked_by=event.get("revoked_by"),
                    revocation_reason=event["revocation_reason"],
                    revoke_all_sessions=event.get("revoke_all_sessions", False),
                    force_logout=event.get("force_logout", True),
                    ip_address=event.get("ip_address", ""),
                    user_agent=event.get("user_agent", ""),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("session:monitor")
    async def session_activity(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SessionActivity, None]:
        """Subscribe to session activity events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # More restrictive for monitoring other users' activity
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:admin")):
                self._authorize_subscription(
                    security_context,
                    "session_activity_user",
                    ["session:admin", "security:investigate"]
                )
            filters.user_ids.add(target_user_id)
        
        filters.event_types.add("session_activity")
        
        context = self._create_connection_context(
            security_context,
            "session_activity",
            filters,
            RateLimitConfig(max_events=200, window_seconds=60, burst_limit=50)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_activity":
                yield SessionActivity(
                    session_id=event["session_id"],
                    user_id=event["user_id"],
                    activity_type=event["activity_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    location=event.get("location"),
                    endpoint=event.get("endpoint"),
                    request_count=event.get("request_count", 1),
                    last_seen=event["last_seen"],
                    risk_score=event.get("risk_score", 0.0),
                    anomaly_detected=event.get("anomaly_detected", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("session:view")
    async def concurrent_sessions_detected(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[ConcurrentSessionsDetected, None]:
        """Subscribe to concurrent session detection events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own concurrent sessions
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("session:admin")):
                self._authorize_subscription(
                    security_context,
                    "concurrent_sessions_user",
                    ["session:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "concurrent_sessions",
                ["session:admin", "security:view"]
            )
        
        filters.event_types.add("concurrent_sessions_detected")
        
        context = self._create_connection_context(
            security_context,
            "concurrent_sessions",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "concurrent_sessions_detected":
                yield ConcurrentSessionsDetected(
                    user_id=event["user_id"],
                    active_session_count=event["active_session_count"],
                    max_allowed_sessions=event["max_allowed_sessions"],
                    session_ids=event["session_ids"],
                    detection_trigger=event["detection_trigger"],
                    locations=event.get("locations", []),
                    devices=event.get("devices", []),
                    action_taken=event.get("action_taken", "none"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def session_security_alert(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SessionSecurityAlert, None]:
        """Subscribe to session security alerts."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own session security alerts
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("security:view")):
                self._authorize_subscription(
                    security_context,
                    "session_security_user",
                    ["security:admin", "session:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "session_security",
                ["security:view", "session:admin"]
            )
        
        filters.event_types.add("session_security_alert")
        
        context = self._create_connection_context(
            security_context,
            "session_security",
            filters,
            RateLimitConfig(max_events=40, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("sessions")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "session_security_alert":
                yield SessionSecurityAlert(
                    alert_id=event["alert_id"],
                    session_id=event["session_id"],
                    user_id=event["user_id"],
                    alert_type=event["alert_type"],
                    severity=event["severity"],
                    details=event["details"],
                    risk_indicators=event.get("risk_indicators", []),
                    auto_mitigated=event.get("auto_mitigated", False),
                    mitigation_actions=event.get("mitigation_actions", []),
                    requires_user_action=event.get("requires_user_action", False),
                    timestamp=event["timestamp"]
                )