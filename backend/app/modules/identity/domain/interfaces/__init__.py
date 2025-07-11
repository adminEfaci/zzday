"""
Identity Domain Interfaces

All domain interfaces for the identity module including repositories, services, and contracts.
"""

# Repository Interfaces
# Create IAuthenticationService interface that wasn't found
from abc import abstractmethod
from typing import Protocol
from uuid import UUID

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
from .services.authentication.mfa_service import IMFAService
from .services.authentication.password_service import IPasswordService
from .services.authentication.token_generator import ITokenGenerator

# Service Interfaces - Infrastructure
from .services.infrastructure.cache_port import ICachePort
from .services.infrastructure.event_publisher_port import IEventPublisherPort
from .services.infrastructure.file_storage_port import IFileStoragePort
from .services.infrastructure.task_queue_port import ITaskQueuePort

# Service Interfaces - Monitoring
from .services.monitoring.audit_service import IAuditService
from .services.monitoring.rate_limit_port import IRateLimitPort

# Service Interfaces - Security
from .services.security.authorization_service import IAuthorizationService
from .services.security.geolocation_service import IGeolocationService
from .services.security.risk_assessment_service import IRiskAssessmentService
from .services.security.security_service import ISecurityService


class IAuthenticationService(Protocol):
    """Authentication service interface."""
    
    @abstractmethod
    async def generate_tokens(self, user_id: UUID, session_id: UUID) -> dict[str, str]:
        """Generate access and refresh tokens for user session."""
        ...
    
    @abstractmethod
    async def verify_refresh_token(self, token: str) -> dict | None:
        """Verify refresh token and return token data."""
        ...
    
    @abstractmethod
    async def verify_email_token(self, token: str) -> dict | None:
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
    'IMFAService',
    'IPasswordService',
    'ITokenGenerator',
    
    # Service Interfaces - Security
    'IAuthorizationService',
    'IGeolocationService',
    'IRiskAssessmentService',
    'ISecurityService',
    
    # Service Interfaces - Monitoring
    'IAuditService',
    'IRateLimitPort',
    
    # Service Interfaces - Infrastructure
    'ICachePort',
    'IEventPublisherPort',
    'IFileStoragePort',
    'ITaskQueuePort',
]