"""
Identity Domain Interfaces

All domain interfaces for the identity module including repositories, services, and contracts.
"""

# Repository Interfaces
from .repositories import (
    IAccessTokenRepository,
    IDeviceRegistrationRepository,
    IEmergencyContactRepository,
    ILoginAttemptRepository,
    IMFARepository,
    INotificationSettingRepository,
    IPasswordHistoryRepository,
    IPermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    ISessionRepository,
    IUserPreferenceRepository,
    IUserProfileRepository,
    IUserRepository,
)

# Service Interfaces - Authentication
from .services.authentication import (
    IBiometricService,
    IPasswordHasher,
    IPasswordService,
    ITokenGenerator,
)

# Service Interfaces - MFA
from .services.mfa import IMFAService

# Service Interfaces - Token
from .services.token import IAccessTokenService

# Service Interfaces - Security
from .services.security import (
    IDeviceService,
    IGeolocationService,
    IRiskAssessmentService,
    ISecurityService,
    IThreatIntelligenceService,
)

# Service Interfaces - Monitoring
from .services.monitoring import (
    IAnalyticsPort,
    IAuditService,
    IRateLimitPort,
)

# Service Interfaces - Infrastructure
from .services.infrastructure import (
    ICachePort,
    IConfigurationPort,
    IEventPublisherPort,
    IFileStoragePort,
    ITaskQueuePort,
)

# Service Interfaces - Communication
from .services.communication import (
    INotificationService,
)

# Service Interfaces - Compliance
from .services.compliance import (
    IComplianceService,
)

# Additional service interfaces that are missing from the analysis
from abc import ABC, abstractmethod
from typing import Protocol, Optional, Dict, Any, List
from uuid import UUID


class IAuthenticationService(Protocol):
    """Authentication service interface."""
    
    @abstractmethod
    async def generate_tokens(self, user_id: UUID, session_id: UUID) -> Dict[str, str]:
        """Generate access and refresh tokens for user session."""
        ...
    
    @abstractmethod
    async def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token and return token data."""
        ...
    
    @abstractmethod
    async def verify_email_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify email verification token."""
        ...
    
    @abstractmethod
    async def send_verification_email(self, user) -> None:
        """Send email verification to user."""
        ...
    
    @abstractmethod
    async def send_password_reset_email(self, user) -> None:
        """Send password reset email to user."""
        ...


class IAuthorizationService(Protocol):
    """Authorization service interface."""
    
    @abstractmethod
    async def check_permission(self, user_id: UUID, permission: str) -> bool:
        """Check if user has specific permission."""
        ...
    
    @abstractmethod
    async def get_user_permissions(self, user_id: UUID) -> List[str]:
        """Get all permissions for a user."""
        ...
    
    @abstractmethod
    async def has_role(self, user_id: UUID, role: str) -> bool:
        """Check if user has specific role."""
        ...


class IAdministrativeService(Protocol):
    """Administrative service interface."""
    
    @abstractmethod
    async def suspend_user(self, user_id: UUID, reason: str) -> None:
        """Suspend a user account."""
        ...
    
    @abstractmethod
    async def reactivate_user(self, user_id: UUID) -> None:
        """Reactivate a suspended user account."""
        ...


class IActivityService(Protocol):
    """Activity tracking service interface."""
    
    @abstractmethod
    async def log_activity(self, user_id: UUID, activity: str, metadata: Dict[str, Any]) -> None:
        """Log user activity."""
        ...
    
    @abstractmethod
    async def get_user_activity(self, user_id: UUID, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user activity history."""
        ...


__all__ = [
    # Repository Interfaces
    'IAccessTokenRepository',
    'IDeviceRegistrationRepository',
    'IEmergencyContactRepository',
    'ILoginAttemptRepository',
    'IMFARepository',
    'INotificationSettingRepository',
    'IPasswordHistoryRepository',
    'IPermissionRepository',
    'IRoleRepository',
    'ISecurityEventRepository',
    'ISessionRepository',
    'IUserPreferenceRepository',
    'IUserProfileRepository',
    'IUserRepository',
    
    # Service Interfaces - Authentication
    'IAuthenticationService',
    'IBiometricService',
    'IPasswordHasher',
    'IPasswordService',
    'ITokenGenerator',
    
    # Service Interfaces - MFA & Token
    'IMFAService',
    'IAccessTokenService',
    
    # Service Interfaces - Security
    'IAuthorizationService',
    'IDeviceService',
    'IGeolocationService',
    'IRiskAssessmentService',
    'ISecurityService',
    'IThreatIntelligenceService',
    
    # Service Interfaces - Administrative
    'IAdministrativeService',
    
    # Service Interfaces - Monitoring
    'IActivityService',
    'IAnalyticsPort',
    'IAuditService',
    'IRateLimitPort',
    
    # Service Interfaces - Infrastructure
    'ICachePort',
    'IConfigurationPort',
    'IEventPublisherPort',
    'IFileStoragePort',
    'ITaskQueuePort',
    
    # Service Interfaces - Communication
    'INotificationService',
    
    # Service Interfaces - Compliance
    'IComplianceService',
]
