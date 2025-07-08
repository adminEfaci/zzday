"""Audit application event handlers.

This module contains event handlers that subscribe to cross-module events
and create appropriate audit trails and compliance records.
"""

from typing import TYPE_CHECKING

# Import Identity domain events
from app.modules.identity.domain.events import (
    MFAChallengeCompleted,
    MFAChallengeFailed,
)
from app.modules.identity.domain.entities.user.user_events import (
    UserCreated,
    UserDeleted,
    UserSuspended,
    UserActivated,
    UserDeactivated,
    LoginSuccessful,
    LoginFailed,
    AccountLockedOut,
    MFAEnabled,
    MFADisabled,
)

# Import existing event handlers
from .data_sync_completed_event_handler import DataSyncCompletedEventHandler
from .notification_sent_event_handler import NotificationSentEventHandler
from .user_authenticated_event_handler import UserAuthenticatedEventHandler
from .user_registered_event_handler import UserRegisteredEventHandler
from .user_role_changed_event_handler import UserRoleChangedEventHandler
from .webhook_received_event_handler import WebhookReceivedEventHandler

# Import new Identity event handlers
from .mfa_enabled_event_handler import MFAEnabledEventHandler
from .mfa_challenge_event_handlers import (
    MFAChallengeCompletedEventHandler,
    MFAChallengeFailedEventHandler,
)
from .login_event_handlers import (
    LoginSuccessfulEventHandler,
    LoginFailedEventHandler,
    AccountLockedOutEventHandler,
)
from .user_lifecycle_event_handlers import (
    UserCreatedEventHandler,
    UserDeletedEventHandler,
    UserSuspendedEventHandler,
)

if TYPE_CHECKING:
    from app.core.events.bus import EventBus
    from app.modules.audit.application.services.audit_service import AuditService


async def register_audit_event_handlers(
    event_bus: "EventBus",
    audit_service: "AuditService"
) -> None:
    """Register all audit module event handlers with the event bus.
    
    Args:
        event_bus: The application event bus
        audit_service: The audit service for creating audit trails
    """
    # Register Identity event handlers
    
    # MFA event handlers
    mfa_enabled_handler = MFAEnabledEventHandler(audit_service)
    await event_bus.subscribe(MFAEnabled, mfa_enabled_handler.handle)
    
    mfa_challenge_completed_handler = MFAChallengeCompletedEventHandler(audit_service)
    await event_bus.subscribe(MFAChallengeCompleted, mfa_challenge_completed_handler.handle)
    
    mfa_challenge_failed_handler = MFAChallengeFailedEventHandler(audit_service)
    await event_bus.subscribe(MFAChallengeFailed, mfa_challenge_failed_handler.handle)
    
    # Login event handlers
    login_successful_handler = LoginSuccessfulEventHandler(audit_service)
    await event_bus.subscribe(LoginSuccessful, login_successful_handler.handle)
    
    login_failed_handler = LoginFailedEventHandler(audit_service)
    await event_bus.subscribe(LoginFailed, login_failed_handler.handle)
    
    account_locked_handler = AccountLockedOutEventHandler(audit_service)
    await event_bus.subscribe(AccountLockedOut, account_locked_handler.handle)
    
    # User lifecycle event handlers
    user_created_handler = UserCreatedEventHandler(audit_service)
    await event_bus.subscribe(UserCreated, user_created_handler.handle)
    
    user_deleted_handler = UserDeletedEventHandler(audit_service)
    await event_bus.subscribe(UserDeleted, user_deleted_handler.handle)
    
    user_suspended_handler = UserSuspendedEventHandler(audit_service)
    await event_bus.subscribe(UserSuspended, user_suspended_handler.handle)
    
    # Register existing event handlers (if they have been updated with proper events)
    # These would need to be updated to use actual domain events instead of shared contracts
    # user_registered_handler = UserRegisteredEventHandler(audit_service)
    # user_authenticated_handler = UserAuthenticatedEventHandler(audit_service)
    # user_role_changed_handler = UserRoleChangedEventHandler(audit_service)
    # notification_sent_handler = NotificationSentEventHandler(audit_service)
    # webhook_received_handler = WebhookReceivedEventHandler(audit_service)
    # data_sync_completed_handler = DataSyncCompletedEventHandler(audit_service)


__all__ = [
    # Identity Events
    "MFAEnabled",
    "MFADisabled",
    "MFAChallengeCompleted",
    "MFAChallengeFailed",
    "UserCreated",
    "UserDeleted",
    "UserSuspended",
    "UserActivated",
    "UserDeactivated",
    "LoginSuccessful",
    "LoginFailed",
    "AccountLockedOut",
    
    # Event Handlers
    "MFAEnabledEventHandler",
    "MFAChallengeCompletedEventHandler",
    "MFAChallengeFailedEventHandler",
    "LoginSuccessfulEventHandler",
    "LoginFailedEventHandler",
    "AccountLockedOutEventHandler",
    "UserCreatedEventHandler",
    "UserDeletedEventHandler",
    "UserSuspendedEventHandler",
    
    # Existing handlers
    "DataSyncCompletedEventHandler",
    "NotificationSentEventHandler",
    "UserAuthenticatedEventHandler",
    "UserRegisteredEventHandler",
    "UserRoleChangedEventHandler",
    "WebhookReceivedEventHandler",
    
    # Registration function
    "register_audit_event_handlers",
]
