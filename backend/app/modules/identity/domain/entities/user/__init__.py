"""User domain entities package.

This package contains all user-related entities that are not aggregate roots.
"""

from .emergency_contact import EmergencyContact
from .login_attempt import LoginAttempt
from .notification_setting import NotificationSetting
from .password_history import PasswordHistory
from .preference import Preference
from .profile import Profile

__all__ = [
    "EmergencyContact",
    "LoginAttempt",
    "NotificationSetting",
    "PasswordHistory",
    "Preference",
    "Profile",
]