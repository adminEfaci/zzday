"""
Identity Domain Services

This module contains all domain services for the identity module,
organized by functional areas.
"""

# Access Token Services
from .access_token import AccessTokenService

# Admin Services
from .admin import (
    AdministrativeService,
    AuthorizationService,
    RiskAssessmentService,
    SecurityService,
)

# Compliance Services
from .compliance import ComplianceService

# Device Services
from .device import DeviceService

# Monitoring Services
from .monitoring import (
    AnalyticsService,
    AuditService,
)

# Group Services
from .group import GroupPermissionService

# MFA Services
from .mfa import MFAService

# Permission Services
from .permissions import PermissionService

# Role Services
from .role import RoleService, RoleFactoryService

# Session Services
from .session import SessionService, SecurityService as SessionSecurityService

# User Services
from .user import (
    ActivityService,
    AuthenticationService,
    EmergencyContactService,
    NotificationService,
    PasswordService,
    PreferenceService,
    ProfileService,
    RegistrationService,
    UserContactService,
    UserDomainService,
    UserFactoryService,
    UserPermissionService,
    UserSecurityService,
)

__all__ = [
    # Core Services
    "MFAService",
    
    # User Services
    "UserDomainService",
    "AuthenticationService", 
    "RegistrationService",
    "ProfileService",
    "PreferenceService",
    "PasswordService",
    "UserSecurityService",
    "UserPermissionService",
    "UserContactService",
    "EmergencyContactService",
    "ActivityService",
    "NotificationService",
    "UserFactoryService",
    
    # Role Services
    "RoleService",
    "RoleFactoryService",
    
    # Permission Services
    "PermissionService",
    
    # Group Services
    "GroupPermissionService",
    
    # Device Services
    "DeviceService",
    
    # Access Token Services
    "AccessTokenService",
    
    # Session Services
    "SessionService",
    "SessionSecurityService",
    
    # Admin Services
    "AdministrativeService",
    "AuthorizationService",
    "RiskAssessmentService",
    "SecurityService",
    
    # Compliance Services
    "ComplianceService",
    
    # Monitoring Services
    "AnalyticsService",
    "AuditService",
]
