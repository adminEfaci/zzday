"""
Security Event Subscription Resolvers

Real-time subscriptions for security events, suspicious activity,
login attempts, account locks, password changes, and MFA events.
"""

from collections.abc import AsyncGenerator
from uuid import UUID

import strawberry
from strawberry.types import Info

from app.core.enums import SecurityEventType

from ..middleware import require_authentication, require_mfa, require_permission
from .base_subscription import (
    BaseSubscriptionResolver,
    RateLimitConfig,
    SubscriptionFilter,
)


@strawberry.type
class SecurityEvent:
    """Security event notification."""
    event_id: strawberry.ID
    event_type: str
    severity: str
    user_id: strawberry.ID | None = None
    ip_address: str
    user_agent: str | None = None
    location: str | None = None
    details: str
    risk_score: float
    auto_mitigated: bool
    timestamp: str
    correlation_id: str | None = None


@strawberry.type
class SuspiciousActivity:
    """Suspicious activity alert."""
    alert_id: strawberry.ID
    user_id: strawberry.ID | None = None
    activity_type: str
    threat_level: str
    indicators: list[str]
    ip_address: str
    user_agent: str | None = None
    location: str | None = None
    context: str
    auto_blocked: bool
    timestamp: str


@strawberry.type
class LoginAttemptFailed:
    """Failed login attempt notification."""
    attempt_id: strawberry.ID
    user_id: strawberry.ID | None = None
    username: str | None = None
    failure_reason: str
    ip_address: str
    user_agent: str
    location: str | None = None
    attempt_count: int
    lockout_triggered: bool
    timestamp: str


@strawberry.type
class AccountLocked:
    """Account locked notification."""
    user_id: strawberry.ID
    lock_reason: str
    locked_by: strawberry.ID | None = None
    lock_duration: int | None = None  # seconds
    unlock_time: str | None = None
    auto_lock: bool
    trigger_event: str | None = None
    timestamp: str


@strawberry.type
class PasswordChanged:
    """Password change notification."""
    user_id: strawberry.ID
    changed_by: strawberry.ID | None = None
    change_type: str  # self_service, admin_reset, forced_reset
    ip_address: str
    user_agent: str
    password_strength: str
    requires_reauth: bool
    timestamp: str


@strawberry.type
class MFADeviceEvent:
    """MFA device addition/removal event."""
    user_id: strawberry.ID
    device_id: strawberry.ID
    device_type: str
    device_name: str
    event_type: str  # added, removed, verified
    changed_by: strawberry.ID | None = None
    ip_address: str
    user_agent: str
    backup_codes_generated: bool
    timestamp: str


@strawberry.type
class SecurityEventResolved:
    """Security event resolution notification."""
    event_id: strawberry.ID
    original_event_type: str
    resolved_by: strawberry.ID
    resolution_type: str  # manual, automatic, false_positive
    resolution_notes: str | None = None
    time_to_resolution: int  # seconds
    timestamp: str


class SecurityEventSubscriptions(BaseSubscriptionResolver):
    """Subscription resolvers for security and threat events."""
    
    @strawberry.subscription
    @require_authentication
    @require_permission("security:view")
    async def security_event_created(
        self,
        info: Info,
        event_type: str | None = None,
        severity: str | None = None
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Subscribe to new security events."""
        security_context = await self._authenticate_connection(info)
        
        # High-severity events require MFA
        if severity in ["high", "critical"] and not security_context.mfa_verified:
            self._authorize_subscription(
                security_context,
                "security_events_critical",
                ["security:admin"]
            )
        
        filters = SubscriptionFilter()
        if event_type:
            filters.event_types.add(f"security_{event_type}")
        else:
            # Subscribe to all security events
            for sec_event in SecurityEventType:
                filters.event_types.add(f"security_{sec_event.value}")
        
        if severity:
            filters.severity_levels.add(severity)
        
        context = self._create_connection_context(
            security_context,
            "security_events",
            filters,
            RateLimitConfig(max_events=100, window_seconds=60, burst_limit=30)
        )
        
        event_stream = self._listen_to_channel("security")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type", "").startswith("security_"):
                yield SecurityEvent(
                    event_id=event["event_id"],
                    event_type=event["event_type"].replace("security_", ""),
                    severity=event["severity"],
                    user_id=event.get("user_id"),
                    ip_address=event["ip_address"],
                    user_agent=event.get("user_agent"),
                    location=event.get("location"),
                    details=event["details"],
                    risk_score=event.get("risk_score", 0.0),
                    auto_mitigated=event.get("auto_mitigated", False),
                    timestamp=event["timestamp"],
                    correlation_id=event.get("correlation_id")
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("security:view")
    @require_mfa
    async def suspicious_activity_detected(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SuspiciousActivity, None]:
        """Subscribe to suspicious activity alerts."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            # Additional authorization check for specific user monitoring
            if not security_context.has_permission("security:investigate"):
                self._authorize_subscription(
                    security_context,
                    "suspicious_activity_user",
                    ["security:admin"]
                )
            filters.user_ids.add(UUID(user_id))
        
        filters.event_types.add("suspicious_activity")
        
        context = self._create_connection_context(
            security_context,
            "suspicious_activity",
            filters,
            RateLimitConfig(max_events=50, window_seconds=60, burst_limit=20)
        )
        
        event_stream = self._listen_to_channel("security")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "suspicious_activity":
                yield SuspiciousActivity(
                    alert_id=event["alert_id"],
                    user_id=event.get("user_id"),
                    activity_type=event["activity_type"],
                    threat_level=event["threat_level"],
                    indicators=event["indicators"],
                    ip_address=event["ip_address"],
                    user_agent=event.get("user_agent"),
                    location=event.get("location"),
                    context=event["context"],
                    auto_blocked=event.get("auto_blocked", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("security:view")
    async def login_attempt_failed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[LoginAttemptFailed, None]:
        """Subscribe to failed login attempts."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            # Users can monitor their own failed attempts
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("security:investigate")):
                self._authorize_subscription(
                    security_context,
                    "login_attempts_user",
                    ["security:admin"]
                )
            filters.user_ids.add(target_user_id)
        
        filters.event_types.add("login_attempt_failed")
        
        context = self._create_connection_context(
            security_context,
            "login_attempts",
            filters,
            RateLimitConfig(max_events=75, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("authentication")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "login_attempt_failed":
                yield LoginAttemptFailed(
                    attempt_id=event["attempt_id"],
                    user_id=event.get("user_id"),
                    username=event.get("username"),
                    failure_reason=event["failure_reason"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    location=event.get("location"),
                    attempt_count=event.get("attempt_count", 1),
                    lockout_triggered=event.get("lockout_triggered", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("security:view")
    async def account_locked(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[AccountLocked, None]:
        """Subscribe to account lock events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:admin")):
                self._authorize_subscription(
                    security_context,
                    "account_locks_user",
                    ["security:admin"]
                )
            filters.user_ids.add(target_user_id)
        
        filters.event_types.add("account_locked")
        
        context = self._create_connection_context(
            security_context,
            "account_locks",
            filters,
            RateLimitConfig(max_events=25, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("security")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "account_locked":
                yield AccountLocked(
                    user_id=event["user_id"],
                    lock_reason=event["lock_reason"],
                    locked_by=event.get("locked_by"),
                    lock_duration=event.get("lock_duration"),
                    unlock_time=event.get("unlock_time"),
                    auto_lock=event.get("auto_lock", True),
                    trigger_event=event.get("trigger_event"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def password_changed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[PasswordChanged, None]:
        """Subscribe to password change events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own password changes
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:admin")):
                self._authorize_subscription(
                    security_context,
                    "password_changes_user",
                    ["user:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "password_changes",
                ["user:admin", "security:view"]
            )
        
        filters.event_types.add("password_changed")
        
        context = self._create_connection_context(
            security_context,
            "password_changes",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("authentication")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "password_changed":
                yield PasswordChanged(
                    user_id=event["user_id"],
                    changed_by=event.get("changed_by"),
                    change_type=event["change_type"],
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    password_strength=event.get("password_strength", "unknown"),
                    requires_reauth=event.get("requires_reauth", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def mfa_device_added(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[MFADeviceEvent, None]:
        """Subscribe to MFA device addition events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can monitor their own MFA changes
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:admin")):
                self._authorize_subscription(
                    security_context,
                    "mfa_changes_user",
                    ["user:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "mfa_changes",
                ["user:admin", "security:view"]
            )
        
        filters.event_types.add("mfa_device_added")
        
        context = self._create_connection_context(
            security_context,
            "mfa_devices",
            filters,
            RateLimitConfig(max_events=15, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("mfa")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "mfa_device_added":
                yield MFADeviceEvent(
                    user_id=event["user_id"],
                    device_id=event["device_id"],
                    device_type=event["device_type"],
                    device_name=event["device_name"],
                    event_type="added",
                    changed_by=event.get("changed_by"),
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    backup_codes_generated=event.get("backup_codes_generated", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def mfa_device_removed(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[MFADeviceEvent, None]:
        """Subscribe to MFA device removal events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("user:admin")):
                self._authorize_subscription(
                    security_context,
                    "mfa_changes_user",
                    ["user:admin", "security:view"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "mfa_changes",
                ["user:admin", "security:view"]
            )
        
        filters.event_types.add("mfa_device_removed")
        
        context = self._create_connection_context(
            security_context,
            "mfa_devices",
            filters,
            RateLimitConfig(max_events=15, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("mfa")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "mfa_device_removed":
                yield MFADeviceEvent(
                    user_id=event["user_id"],
                    device_id=event["device_id"],
                    device_type=event["device_type"],
                    device_name=event["device_name"],
                    event_type="removed",
                    changed_by=event.get("changed_by"),
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    backup_codes_generated=False,
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("security:admin")
    async def security_event_resolved(
        self,
        info: Info,
        event_id: strawberry.ID | None = None
    ) -> AsyncGenerator[SecurityEventResolved, None]:
        """Subscribe to security event resolutions."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("security_event_resolved")
        
        if event_id:
            filters.custom_filters["resolved_event_id"] = event_id
        
        context = self._create_connection_context(
            security_context,
            "security_resolutions",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("security")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "security_event_resolved":
                yield SecurityEventResolved(
                    event_id=event["event_id"],
                    original_event_type=event["original_event_type"],
                    resolved_by=event["resolved_by"],
                    resolution_type=event["resolution_type"],
                    resolution_notes=event.get("resolution_notes"),
                    time_to_resolution=event["time_to_resolution"],
                    timestamp=event["timestamp"]
                )