"""Identity domain entities package.

This package contains all domain entities that are not aggregate roots.
Entities have identity and lifecycle but are not aggregate roots.
"""

# User entities
from .user.emergency_contact import EmergencyContact
from .user.login_attempt import LoginAttempt
from .user.notification_setting import NotificationSetting
from .user.password_history import PasswordHistory
from .user.preference import Preference
from .user.profile import Profile

# Session entities
from .session.partial_session import PartialSession
from .session.security_event import SecurityEvent

# Group entities
from .group.group_member import GroupMember

# Shared entities
from .shared.base_entity import BaseEntity

__all__ = [
    # User entities
    "EmergencyContact",
    "LoginAttempt",
    "NotificationSetting",
    "PasswordHistory",
    "Preference",
    "Profile",
    
    # Session entities
    "PartialSession",
    "SecurityEvent",
    
    # Group entities
    "GroupMember",
    
    # Shared
    "BaseEntity",
]