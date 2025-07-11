"""
Identity Domain Repository Interfaces

Domain contracts for data access that must be implemented by the infrastructure layer.
These interfaces define the persistence boundaries for the identity domain.
"""

# Core Identity Repositories
from .user_repository import IUserRepository
from .user_profile_repository import IUserProfileRepository
from .session_repository import ISessionRepository
from .group_repository import IGroupRepository

# Access Control Repositories
from .role_repository import IRoleRepository
from .permission_repository import IPermissionRepository
from .access_token_repository import IAccessTokenRepository

# Security Repositories
from .login_attempt_repository import ILoginAttemptRepository
from .password_history_repository import IPasswordHistoryRepository
from .mfa_repository import IMFARepository
from .device_registration_repository import IDeviceRegistrationRepository
from .security_event_repository import ISecurityEventRepository

# Monitoring & Analytics Repositories
from .activity_repository import IActivityRepository
from .audit_repository import IAuditRepository
from .analytics_repository import IAnalyticsRepository

# Compliance Repositories
from .compliance_repository import IComplianceRepository

# User Data Repositories
from .emergency_contact_repository import IEmergencyContactRepository
from .notification_setting_repository import INotificationSettingRepository
from .user_preference_repository import IUserPreferenceRepository

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
    
    # Monitoring & Analytics
    'IActivityRepository',
    'IAuditRepository',
    'IAnalyticsRepository',
    
    # Compliance
    'IComplianceRepository',
    
    # User Data
    'IEmergencyContactRepository',
    'INotificationSettingRepository',
    'IUserPreferenceRepository',

]