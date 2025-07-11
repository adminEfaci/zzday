"""
Identity Domain Layer

This package contains the core business logic for the identity domain,
implementing Domain-Driven Design patterns with event sourcing support.
"""

# Constants
from .constants import (
    AuditConstants,
    ComplianceConstants,
    DefaultValues,
    ErrorMessages,
    PolicyConstants,
    RegexPatterns,
    SecurityLimits,
    TokenExpiry,
    ValidationRules,
)

# Enums
from .enums import (
    AccountType,
    AuditAction,
    AuthenticationMethod,
    ComplianceStatus,
    DevicePlatform,
    DeviceType,
    LoginFailureReason,
    MfaMethod,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    SessionStatus,
    SessionType,
    UserStatus,
    VerificationStatus,
)

# Errors
from .errors import (
    AuthenticationError,
    AuthorizationError,
    BusinessRuleError,
    ComplianceError,
    IdentityDomainError,
    IdentityRateLimitError,
    InvalidOperationError,
    SecurityPolicyError,
    VerificationAttemptsExceededError,
    VerificationError,
)

# Events
from .events import IdentityDomainEvent

# Interfaces - Import commonly used interfaces at the domain level
from .interfaces import (
    # Repository Interfaces
    IUserRepository,
    ISessionRepository,
    IAccessTokenRepository,
    IMFARepository,
    IDeviceRegistrationRepository,
    
    # Core Service Interfaces
    IAuthenticationService,
    IPasswordService,
    IMFAService,
    IAccessTokenService,
    IAuthorizationService,
    ISecurityService,
    IRiskAssessmentService,
    IDeviceService,
    
    # Infrastructure Interfaces
    ICachePort,
    IEventPublisherPort,
    INotificationService,
    
    # Monitoring Interfaces
    IAuditService,
    IActivityService,
    IRateLimitPort,
)

__all__ = [
    # Enums
    "AccountType",
    "AuditAction",
    # Constants
    "AuditConstants",
    # Errors
    "AuthenticationError",
    "AuthenticationMethod",
    "AuthorizationError",
    "BusinessRuleError",
    "ComplianceConstants",
    "ComplianceError",
    "ComplianceStatus",
    "DefaultValues",
    "DevicePlatform",
    "DeviceType",
    "ErrorMessages",
    "IdentityDomainError",
    # Events
    "IdentityDomainEvent",
    "IdentityRateLimitError",
    "InvalidOperationError",
    "LoginFailureReason",
    "MfaMethod",
    "NotificationType",
    "PolicyConstants",
    "RegexPatterns",
    "RiskLevel",
    "SecurityEventType",
    "SecurityLimits",
    "SecurityPolicyError",
    "SessionStatus",
    "SessionType",
    "TokenExpiry",
    "UserStatus",
    "ValidationRules",
    "VerificationAttemptsExceededError",
    "VerificationError",
    "VerificationStatus",
    
    # Repository Interfaces
    "IUserRepository",
    "ISessionRepository", 
    "IAccessTokenRepository",
    "IMFARepository",
    "IDeviceRegistrationRepository",
    
    # Core Service Interfaces
    "IAuthenticationService",
    "IPasswordService",
    "IMFAService",
    "IAccessTokenService",
    "IAuthorizationService",
    "ISecurityService",
    "IRiskAssessmentService",
    "IDeviceService",
    
    # Infrastructure Interfaces
    "ICachePort",
    "IEventPublisherPort",
    "INotificationService",
    
    # Monitoring Interfaces
    "IAuditService",
    "IActivityService",
    "IRateLimitPort",
]

__version__ = "1.0.0"
__author__ = "Identity Domain Team"