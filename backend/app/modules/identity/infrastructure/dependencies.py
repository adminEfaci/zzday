"""Identity module dependency configuration."""

from app.core.dependencies import Container, RegistrationRequest
from app.core.enums import ServiceLifetime


async def configure_identity_dependencies(container: Container) -> None:
    """Configure identity module dependencies in the main container.

    Args:
        container: Dependency injection container
    """
    
    # Register repository implementations
    
    # User repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
        from app.modules.identity.infrastructure.repositories.user_repository import SQLUserRepository
        
        await container.register(RegistrationRequest(
            interface=IUserRepository,
            implementation=SQLUserRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="user_repository",
            description="User data repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IUserRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="user_repository_placeholder"
        ))
    
    # Session repository
    try:
        from app.modules.identity.domain.interfaces.repositories.session.session_repository import ISessionRepository
        from app.modules.identity.infrastructure.repositories.session_repository import SQLSessionRepository
        
        await container.register(RegistrationRequest(
            interface=ISessionRepository,
            implementation=SQLSessionRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="session_repository",
            description="Session data repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('ISessionRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="session_repository_placeholder"
        ))
    
    # Group repository
    try:
        from app.modules.identity.domain.interfaces.repositories.group_repository import IGroupRepository
        from app.modules.identity.infrastructure.repositories.group_repository import SQLGroupRepository
        
        await container.register(RegistrationRequest(
            interface=IGroupRepository,
            implementation=SQLGroupRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="group_repository",
            description="Group data repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IGroupRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="group_repository_placeholder"
        ))
    
    # Role repository
    try:
        from app.modules.identity.domain.interfaces.repositories.role_repository import IRoleRepository
        from app.modules.identity.infrastructure.repositories.role_repository import SQLRoleRepository
        
        await container.register(RegistrationRequest(
            interface=IRoleRepository,
            implementation=SQLRoleRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="role_repository",
            description="Role data repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IRoleRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="role_repository_placeholder"
        ))
    
    # Permission repository
    try:
        from app.modules.identity.domain.interfaces.repositories.permission_repository import IPermissionRepository
        from app.modules.identity.infrastructure.repositories.permission_repository import SQLPermissionRepository
        
        await container.register(RegistrationRequest(
            interface=IPermissionRepository,
            implementation=SQLPermissionRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="permission_repository",
            description="Permission data repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IPermissionRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="permission_repository_placeholder"
        ))
    
    # Device registration repository
    try:
        from app.modules.identity.domain.interfaces.repositories.session.device_registration_repository import IDeviceRegistrationRepository
        from app.modules.identity.infrastructure.repositories.device_registration_repository import SQLDeviceRegistrationRepository
        
        await container.register(RegistrationRequest(
            interface=IDeviceRegistrationRepository,
            implementation=SQLDeviceRegistrationRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="device_registration_repository",
            description="Device registration repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IDeviceRegistrationRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="device_registration_repository_placeholder"
        ))
    
    # MFA repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user.mfa_repository import IMFARepository
        from app.modules.identity.infrastructure.repositories.mfa_repository import SQLMFARepository
        
        await container.register(RegistrationRequest(
            interface=IMFARepository,
            implementation=SQLMFARepository,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_repository",
            description="MFA device repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IMFARepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_repository_placeholder"
        ))
    
    # MFA device repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user.mfa_device_repository import IMFADeviceRepository
        from app.modules.identity.infrastructure.repositories.mfa_device_repository import SQLMFADeviceRepository
        
        await container.register(RegistrationRequest(
            interface=IMFADeviceRepository,
            implementation=SQLMFADeviceRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_device_repository",
            description="MFA device repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IMFADeviceRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_device_repository_placeholder"
        ))
    
    # MFA challenge repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user.mfa_challenge_repository import IMFAChallengeRepository
        from app.modules.identity.infrastructure.repositories.mfa_challenge_repository import CacheMFAChallengeRepository
        
        await container.register(RegistrationRequest(
            interface=IMFAChallengeRepository,
            implementation=CacheMFAChallengeRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_challenge_repository",
            description="MFA challenge repository implementation for temporary storage"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IMFAChallengeRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="mfa_challenge_repository_placeholder"
        ))
    
    # Access token repository
    try:
        from app.modules.identity.domain.interfaces.repositories.session.access_token_repository import IAccessTokenRepository
        from app.modules.identity.infrastructure.repositories.access_token_repository import SQLAccessTokenRepository
        
        await container.register(RegistrationRequest(
            interface=IAccessTokenRepository,
            implementation=SQLAccessTokenRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="access_token_repository",
            description="Access token repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IAccessTokenRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="access_token_repository_placeholder"
        ))
    
    # User preference repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user.user_preference_repository import IUserPreferenceRepository
        from app.modules.identity.infrastructure.repositories.user_preference_repository import SQLUserPreferenceRepository
        
        await container.register(RegistrationRequest(
            interface=IUserPreferenceRepository,
            implementation=SQLUserPreferenceRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="user_preference_repository",
            description="User preference repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IUserPreferenceRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="user_preference_repository_placeholder"
        ))
    
    # Emergency contact repository
    try:
        from app.modules.identity.domain.interfaces.repositories.user.emergency_contact_repository import IEmergencyContactRepository
        from app.modules.identity.infrastructure.repositories.emergency_contact_repository import SQLEmergencyContactRepository
        
        await container.register(RegistrationRequest(
            interface=IEmergencyContactRepository,
            implementation=SQLEmergencyContactRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="emergency_contact_repository",
            description="Emergency contact repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IEmergencyContactRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="emergency_contact_repository_placeholder"
        ))
    
    # Login attempt repository
    try:
        from app.modules.identity.domain.interfaces.repositories.session.login_attempt_repository import ILoginAttemptRepository
        from app.modules.identity.infrastructure.repositories.login_attempt_repository import SQLLoginAttemptRepository
        
        await container.register(RegistrationRequest(
            interface=ILoginAttemptRepository,
            implementation=SQLLoginAttemptRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="login_attempt_repository",
            description="Login attempt repository implementation"
        ))
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('ILoginAttemptRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="login_attempt_repository_placeholder"
        ))
    
    # Security event repository
    try:
        from app.modules.identity.domain.interfaces.repositories.session.security_event_repository import ISecurityEventRepository
        from app.modules.identity.infrastructure.repositories.security_event_repository import SQLSecurityEventRepository
        
        await container.register(RegistrationRequest(
            interface=ISecurityEventRepository,
            implementation=SQLSecurityEventRepository,
            lifetime=ServiceLifetime.SCOPED,
            name="security_event_repository",
            description="Security event repository implementation"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('ISecurityEventRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SCOPED,
            name="security_event_repository_placeholder"
        ))

    # NOTE: Application services should be registered in the application layer
    # This infrastructure module should only register infrastructure concerns
    # Application services are registered through the application dependency module

    # NOTE: Application services should be registered in the application layer
    # This infrastructure module should only register infrastructure concerns

    try:
        # Token services
        from app.modules.identity.domain.interfaces.services import ITokenService
        from app.modules.identity.infrastructure.services.token_service import TokenService
        
        await container.register(RegistrationRequest(
            interface=ITokenService,
            implementation=TokenService,
            lifetime=ServiceLifetime.SINGLETON,
            name="token_service",
            description="JWT token generation and validation service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('ITokenService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="token_service_placeholder"
        ))
        
    logger.info("Identity module dependencies registered successfully")