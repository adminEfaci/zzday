"""
Identity Domain Service Interfaces

All service interfaces (ports) for the identity domain following hexagonal architecture.
These interfaces define contracts that must be implemented by infrastructure adapters.
"""

# Authentication interfaces
from .authentication import (
    IBiometricService,
    IMFAService,
    IPasswordHasher,
    ITokenGenerator,
)

# Communication interfaces
from .communication import INotificationService

# Compliance interfaces
from .compliance import IComplianceService

# Infrastructure interfaces
from .infrastructure import (
    ICachePort,
    IConfigurationPort,
    IEventPublisherPort,
    IFileStoragePort,
    ITaskQueuePort,
)

# Monitoring interfaces
from .monitoring import IAnalyticsPort, IAuditService, IRateLimitPort

# Security interfaces
from .security import (
    IDeviceService,
    IGeolocationService,
    IRiskAssessmentService,
    ISecurityService,
    IThreatIntelligenceService,
)

# User domain service interfaces
from .user_authentication_service import IUserAuthenticationService
from .session_validation_service import ISessionValidationService

__all__ = [
    'IAnalyticsPort',
    # Monitoring
    'IAuditService',
    'IBiometricService',
    'ICachePort',
    # Compliance
    'IComplianceService',
    'IConfigurationPort',
    'IDeviceService',
    'IEventPublisherPort',
    # Infrastructure
    'IFileStoragePort',
    'IGeolocationService',
    'IMFAService',
    # Communication
    'INotificationService',
    # Authentication
    'IPasswordHasher',
    'IRateLimitPort',
    # Security
    'IRiskAssessmentService',
    'ISecurityService',
    'ITaskQueuePort',
    'IThreatIntelligenceService',
    'ITokenGenerator',
    # User domain services
    'IUserAuthenticationService',
    'ISessionValidationService'
]