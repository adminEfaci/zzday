"""
Identity domain application contracts.

Defines ports and adapters for clean architecture.
"""

from .ports import (
    IAccessRepository,
    IAuditRepository,
    IAuthorizationRepository,
    ICacheService,
    ICertificateRepository,
    IComplianceRepository,
    IDeviceRepository,
    # External Service Interfaces
    IEmailService,
    IEmergencyContactRepository,
    IEncryptionRepository,
    IEventBus,
    IEvidenceRepository,
    IForensicsRepository,
    IIncidentRepository,
    IKeyRepository,
    IMFARepository,
    IMonitoringRepository,
    INotificationService,
    IPasswordBreachService,
    IPasswordHistoryRepository,
    IPermissionRepository,
    IPolicyRepository,
    IPreferencesRepository,
    IRoleRepository,
    IRuleRepository,
    ISecurityRepository,
    ISessionRepository,
    ISMSService,
    IStorageService,
    IThreatIntelligenceService,
    ITokenService,
    # Repository Interfaces
    IUserRepository,
)

__all__ = [
    "IAccessRepository",
    "IAuditRepository",
    "IAuthorizationRepository",
    "ICacheService",
    "ICertificateRepository",
    "IComplianceRepository",
    "IDeviceRepository",
    # External Service Interfaces
    "IEmailService",
    "IEmergencyContactRepository",
    "IEncryptionRepository",
    "IEventBus",
    "IEvidenceRepository",
    "IForensicsRepository",
    "IIncidentRepository",
    "IKeyRepository",
    "IMFARepository",
    "IMonitoringRepository",
    "INotificationService",
    "IPasswordBreachService",
    "IPasswordHistoryRepository",
    "IPermissionRepository",
    "IPolicyRepository",
    "IPreferencesRepository",
    "IRoleRepository",
    "IRuleRepository",
    "ISMSService",
    "ISecurityRepository",
    "ISessionRepository",
    "IStorageService",
    "IThreatIntelligenceService",
    "ITokenService",
    # Repository Interfaces
    "IUserRepository",
]