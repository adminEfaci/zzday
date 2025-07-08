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
    MFAMethod,
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
    "MFAMethod",
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
]

__version__ = "1.0.0"
__author__ = "Identity Domain Team"