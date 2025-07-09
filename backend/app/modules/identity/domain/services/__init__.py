"""
Identity Domain Services Package
"""

# Admin services
from .admin.administrative_service import AdministrativeService
from .admin.authorization_service import AuthorizationService
from .admin.device_service import DeviceService
from .admin.mfa_service import MFAService as AdminMFAService
from .admin.password_service import PasswordService as AdminPasswordService
from .admin.risk_assessment_service import RiskAssessmentService
from .admin.security_service import SecurityService

# User services
from .user.authentication_service import AuthenticationService
from .user.factory_service import UserFactory
from .user.mfa_service import MFAService
from .user.notification_service import NotificationService
from .user.password_service import PasswordService
from .user.preference_service import PreferenceService
from .user.profile_service import ProfileService
from .user.registration_service import RegistrationService
from .user.user_domain_service import UserDomainService

# Role services
from .role.role_factory import RoleFactory
from .role.role_service import RoleService

# Session services
from .session.session_service import SessionService
from .session_validation_service import SessionValidationService

# Additional domain services (previously prefixed with NEW_/New_)
from .access_token_service import AccessTokenService
from .emergency_contact_service import EmergencyContactService
from .permission_service import PermissionService
from .user_authentication_service import UserAuthenticationService
from .user_preference_service import UserPreferenceService
from .user_security_service import UserSecurityService

__all__ = [
    # Admin services
    'AdministrativeService',
    'AuthorizationService',
    'DeviceService',
    'AdminMFAService',
    'AdminPasswordService',
    'RiskAssessmentService',
    'SecurityService',
    
    # User services
    'AuthenticationService',
    'UserFactory',
    'MFAService',
    'NotificationService',
    'PasswordService',
    'PreferenceService',
    'ProfileService',
    'RegistrationService',
    'UserDomainService',
    
    # Role services
    'RoleFactory',
    'RoleService',
    
    # Session services
    'SessionService',
    'SessionValidationService',
    
    # Additional domain services (previously prefixed with NEW_/New_)
    'AccessTokenService',
    'EmergencyContactService',
    'PermissionService',
    'UserAuthenticationService',
    'UserPreferenceService',
    'UserSecurityService',
]