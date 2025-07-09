"""
Identity Domain Repository Interfaces

Domain contracts for data access that must be implemented by the infrastructure layer.
These interfaces define the persistence boundaries for the identity domain.
"""

# Core Identity Repositories
from .access_token_repository import IAccessTokenRepository
from .device_registration_repository import IDeviceRegistrationRepository

# User Data Repositories
from .emergency_contact_repository import IEmergencyContactRepository
from .group_repository import IGroupRepository

# Security Repositories
from .login_attempt_repository import ILoginAttemptRepository
from .mfa_repository import IMFARepository
from .notification_setting_repository import INotificationSettingRepository
from .password_history_repository import IPasswordHistoryRepository
from .permission_repository import IPermissionRepository

# Access Control Repositories
from .role_repository import IRoleRepository
from .security_event_repository import ISecurityEventRepository
from .session_repository import ISessionRepository
from .user_preference_repository import IUserPreferenceRepository
from .user_profile_repository import IUserProfileRepository
from .user_repository import IUserRepository

__all__ = [
    # Core Identity
    'IUserRepository',
    'IUserProfileRepository',
    'ISessionRepository',
    'IGroupRepository',
    
    # Access Control
    'IRoleRepository',
    'IPermissionRepository',
    'IAccessTokenRepository',
    
    # Security
    'ILoginAttemptRepository',
    'IPasswordHistoryRepository',
    'IMFARepository',
    'IDeviceRegistrationRepository',
    'ISecurityEventRepository',
    
    # User Data
    'IEmergencyContactRepository',
    'INotificationSettingRepository',
    'IUserPreferenceRepository',

]