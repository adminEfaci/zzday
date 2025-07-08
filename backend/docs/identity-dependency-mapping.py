# Dependencies for Identity Module

## Required Core Dependencies

### Event System
from app.core.events.bus import EventBus, InMemoryEventBus, DistributedEventBus
from app.core.events.types import DomainEvent, EventMetadata
from app.core.events.handlers import EventHandler, BatchEventHandler, CompensatingEventHandler
from app.core.events.registry import register_event, get_event_class
from app.core.events.tracking import (
    set_correlation_id, 
    get_correlation_id,
    set_causation_id,
    get_causation_id,
    track_event_flow
)

### CQRS System
from app.core.cqrs.base import (
    Command,
    Query,
    CommandHandler,
    QueryHandler,
    CommandBus,
    QueryBus
)

### Repository System
from app.core.infrastructure.repository import (
    BaseRepository,
    CachedRepository,
    EventSourcedRepository
)
from app.core.infrastructure.specification import SpecificationEvaluator
from app.core.infrastructure.unit_of_work import BaseUnitOfWork
from app.core.infrastructure.transaction import (
    TransactionManager,
    DistributedTransactionManager,
    ITransactionParticipant
)

### Domain Primitives
from app.core.domain.base import (
    Entity,
    AggregateRoot,
    ValueObject,
    DomainService
)
from app.core.domain.contracts import (
    IRepository,
    IUnitOfWork,
    IEventPublisher
)
from app.core.domain.specification import (
    Specification,
    AndSpecification,
    OrSpecification,
    NotSpecification
)

### Security System
from app.core.security import (
    # Password Handling
    hash_password,
    verify_password,
    
    # Token Management
    create_access_token,
    create_refresh_token,
    decode_token,
    is_token_expired,
    generate_token,
    generate_verification_code,
    
    # Data Privacy
    mask_email,
    mask_phone
)

### Authentication Middleware
from app.core.middleware.auth import (
    AuthMiddleware,
    get_current_user_id,
    get_auth_context,
    require_auth,
    require_permission
)

### Error Handling
from app.core.errors import (
    # Base Errors
    EzzDayError,
    DomainError,
    ApplicationError,
    InfrastructureError,
    
    # Specific Errors
    ValidationError,
    NotFoundError,
    ConflictError,
    UnauthorizedError,
    ForbiddenError,
    RateLimitError,
    ConfigurationError,
    ExternalServiceError,
    
    # Repository Errors
    EntityNotFoundError,
    RepositoryError,
    OptimisticLockError,
    RepositoryIntegrityError
)

### Dependency Injection
from app.core.dependencies import Container, create_container

### Configuration
from app.core.config import settings, get_settings

### Logging and Monitoring
from app.core.logging import get_logger, log_context
from app.core.monitoring import metrics

### Database
from app.core.database import (
    get_db_session,
    AsyncSession,
    # Any other database utilities
)

### Cache Manager
from app.core.cache import (
    # Cache interface to be imported
    # Assuming something like:
    CacheManager,
    get_cache_manager
)

### Shared Value Objects
from app.shared.value_objects.interface import (
    IAuditable,
    ISoftDeletable,
    IVersionable,
    ITaggable,
    ISearchable
)
from app.shared.value_objects.email import Email
from app.shared.value_objects.phone import PhoneNumber
from app.shared.value_objects.address import Address
from app.shared.value_objects.money import Money
from app.shared.value_objects.location import Location
from app.shared.value_objects.enums import (
    # Any shared enums
)

## Identity-Specific Dependencies

### External Service Interfaces (to be implemented)

class IEmailService(Protocol):
    """Email service interface."""
    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        html_body: str | None = None
    ) -> None: ...
    
    async def send_template_email(
        self,
        to: str,
        template_id: str,
        context: dict[str, Any]
    ) -> None: ...

class ISMSService(Protocol):
    """SMS service interface."""
    async def send_sms(
        self,
        to: str,
        message: str
    ) -> None: ...
    
    async def send_verification_code(
        self,
        to: str,
        code: str
    ) -> None: ...

class IAuditService(Protocol):
    """Audit logging service interface."""
    async def log_event(
        self,
        user_id: UUID,
        action: str,
        resource: str,
        details: dict[str, Any],
        ip_address: str | None = None,
        user_agent: str | None = None
    ) -> None: ...

class IRiskAssessmentService(Protocol):
    """Risk assessment service interface."""
    async def assess_login_risk(
        self,
        user_id: UUID,
        ip_address: str,
        user_agent: str,
        location: Location | None = None
    ) -> RiskScore: ...
    
    async def assess_transaction_risk(
        self,
        user_id: UUID,
        action: str,
        context: dict[str, Any]
    ) -> RiskScore: ...

class IGeolocationService(Protocol):
    """Geolocation service interface."""
    async def get_location_from_ip(
        self,
        ip_address: str
    ) -> Location | None: ...

### Identity-Specific Services (to be implemented)

class IPasswordService(Protocol):
    """Password policy and validation service."""
    def validate_password_strength(self, password: str) -> PasswordStrength: ...
    def check_password_history(self, user_id: UUID, password_hash: str) -> bool: ...
    async def add_to_password_history(self, user_id: UUID, password_hash: str) -> None: ...

class ITokenService(Protocol):
    """Token management service."""
    async def create_access_token(self, user: User) -> str: ...
    async def create_refresh_token(self, user: User) -> str: ...
    async def validate_refresh_token(self, token: str) -> UUID | None: ...
    async def revoke_refresh_token(self, token: str) -> None: ...
    async def revoke_all_user_tokens(self, user_id: UUID) -> None: ...

class IMFAService(Protocol):
    """Multi-factor authentication service."""
    async def generate_totp_secret(self) -> str: ...
    async def verify_totp_code(self, secret: str, code: str) -> bool: ...
    async def send_sms_code(self, phone: str) -> str: ...
    async def verify_sms_code(self, phone: str, code: str) -> bool: ...
    async def generate_backup_codes(self, count: int = 10) -> list[str]: ...

class ISessionService(Protocol):
    """Session management service."""
    async def create_session(
        self,
        user_id: UUID,
        ip_address: str,
        user_agent: str,
        device_id: str | None = None
    ) -> Session: ...
    async def validate_session(self, session_id: UUID) -> Session | None: ...
    async def terminate_session(self, session_id: UUID) -> None: ...
    async def terminate_all_user_sessions(self, user_id: UUID) -> None: ...
    async def get_active_sessions(self, user_id: UUID) -> list[Session]: ...

## Dependency Registration Example

```python
def register_identity_dependencies(container: Container) -> None:
    """Register all identity module dependencies."""
    
    # Core services
    container.register(EventBus, InMemoryEventBus, singleton=True)
    container.register(CommandBus, CommandBus, singleton=True)
    container.register(QueryBus, QueryBus, singleton=True)
    
    # Repositories
    container.register(IUserRepository, UserRepository, singleton=True)
    container.register(IRoleRepository, RoleRepository, singleton=True)
    container.register(IPermissionRepository, PermissionRepository, singleton=True)
    container.register(ISessionRepository, SessionRepository, singleton=True)
    container.register(IAuditLogRepository, AuditLogRepository, singleton=True)
    
    # Domain services
    container.register(IPasswordService, PasswordService, singleton=True)
    container.register(ITokenService, TokenService, singleton=True)
    container.register(IMFAService, MFAService, singleton=True)
    container.register(ISessionService, SessionService, singleton=True)
    
    # Application services
    container.register(IUserService, UserService)
    container.register(IAuthenticationService, AuthenticationService)
    container.register(IAuthorizationService, AuthorizationService)
    
    # External services (implementation depends on providers)
    if settings.EMAIL_PROVIDER == "sendgrid":
        container.register(IEmailService, SendGridEmailService, singleton=True)
    elif settings.EMAIL_PROVIDER == "smtp":
        container.register(IEmailService, SMTPEmailService, singleton=True)
    else:
        container.register(IEmailService, MockEmailService, singleton=True)
    
    if settings.SMS_PROVIDER == "twilio":
        container.register(ISMSService, TwilioSMSService, singleton=True)
    else:
        container.register(ISMSService, MockSMSService, singleton=True)
    
    # Audit service
    container.register(IAuditService, DatabaseAuditService, singleton=True)
    
    # Risk assessment (optional)
    if settings.FEATURE_RISK_ASSESSMENT:
        container.register(IRiskAssessmentService, RiskAssessmentService, singleton=True)
    
    # Geolocation (optional)
    if settings.FEATURE_GEOLOCATION:
        container.register(IGeolocationService, GeolocationService, singleton=True)
```

## Configuration Dependencies

```python
# Identity-specific configuration needed in settings
class IdentitySettings:
    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_COUNT: int = 5
    
    # Account Security
    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30
    SESSION_TIMEOUT_MINUTES: int = 60
    CONCURRENT_SESSIONS_LIMIT: int = 5
    
    # MFA Settings
    MFA_CODE_LENGTH: int = 6
    MFA_CODE_VALIDITY_SECONDS: int = 300
    TOTP_WINDOW: int = 1
    BACKUP_CODES_COUNT: int = 10
    
    # Token Settings (inherits from core)
    # ACCESS_TOKEN_EXPIRE_MINUTES
    # REFRESH_TOKEN_EXPIRE_DAYS
    
    # Email Templates
    EMAIL_VERIFICATION_TEMPLATE_ID: str = "user-verification"
    PASSWORD_RESET_TEMPLATE_ID: str = "password-reset"
    MFA_CODE_TEMPLATE_ID: str = "mfa-code"
    
    # Feature Flags
    FEATURE_EMAIL_VERIFICATION: bool = True
    FEATURE_PHONE_VERIFICATION: bool = True
    FEATURE_SOCIAL_LOGIN: bool = False
    FEATURE_RISK_ASSESSMENT: bool = True
    FEATURE_GEOLOCATION: bool = True
    FEATURE_AUDIT_LOGGING: bool = True
```