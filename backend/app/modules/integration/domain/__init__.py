"""Integration domain layer following pure Python DDD principles.

This domain layer provides comprehensive integration capabilities:
- Integration aggregates for external system connections
- Webhook endpoint management
- API credential secure storage
- Data synchronization orchestration
- Event-driven integration workflows
"""

# Import with error handling
import warnings

try:
    from .aggregates.integration import Integration
except ImportError as e:
    warnings.warn(f"Integration aggregate not available: {e}", ImportWarning, stacklevel=2)
    Integration = None

try:
    from .aggregates.webhook_endpoint import WebhookEndpoint
except ImportError as e:
    warnings.warn(f"WebhookEndpoint aggregate not available: {e}", ImportWarning, stacklevel=2)
    WebhookEndpoint = None

try:
    from .entities.api_credential import ApiCredential
except ImportError as e:
    warnings.warn(f"ApiCredential entity not available: {e}", ImportWarning, stacklevel=2)
    ApiCredential = None

try:
    from .entities.integration_mapping import IntegrationMapping
except ImportError as e:
    warnings.warn(f"IntegrationMapping entity not available: {e}", ImportWarning, stacklevel=2)
    IntegrationMapping = None

try:
    from .entities.sync_job import SyncJob
except ImportError as e:
    warnings.warn(f"SyncJob entity not available: {e}", ImportWarning, stacklevel=2)
    SyncJob = None

try:
    from .entities.webhook_event import WebhookEvent
except ImportError as e:
    warnings.warn(f"WebhookEvent entity not available: {e}", ImportWarning, stacklevel=2)
    WebhookEvent = None

try:
    from .value_objects.api_endpoint import ApiEndpoint
except ImportError as e:
    warnings.warn(f"ApiEndpoint value object not available: {e}", ImportWarning, stacklevel=2)
    ApiEndpoint = None

try:
    from .value_objects.auth_method import AuthMethod
except ImportError as e:
    warnings.warn(f"AuthMethod value object not available: {e}", ImportWarning, stacklevel=2)
    AuthMethod = None

try:
    from .value_objects.rate_limit_config import RateLimitConfig
except ImportError as e:
    warnings.warn(f"RateLimitConfig value object not available: {e}", ImportWarning, stacklevel=2)
    RateLimitConfig = None

try:
    from .value_objects.sync_status import SyncStatus
except ImportError as e:
    warnings.warn(f"SyncStatus value object not available: {e}", ImportWarning, stacklevel=2)
    SyncStatus = None

try:
    from .value_objects.webhook_signature import WebhookSignature
except ImportError as e:
    warnings.warn(f"WebhookSignature value object not available: {e}", ImportWarning, stacklevel=2)
    WebhookSignature = None

# Import enums, errors, events with fallbacks
try:
    from .enums import (
        AuthType,
        ConnectionStatus,
        CredentialStatus,
        EntityType,
        FieldType,
        HttpMethod,
        IntegrationType,
        MappingTransformation,
        MappingType,
        RateLimitStrategy,
        SyncDirection,
        SyncStatus,
        WebhookMethod,
        WebhookStatus,
    )
except ImportError as e:
    warnings.warn(f"Integration enums not available: {e}", ImportWarning, stacklevel=2)

try:
    from .errors import (
        AuthenticationError,
        ConnectionFailedError,
        CredentialExpiredError,
        IntegrationConfigurationError,
        IntegrationError,
        IntegrationNotFoundError,
        MappingError,
        RateLimitExceededError,
        SyncConflictError,
        WebhookEndpointError,
        WebhookValidationError,
    )
except ImportError as e:
    warnings.warn(f"Integration errors not available: {e}", ImportWarning, stacklevel=2)
    
    # Provide fallback error classes
    class IntegrationError(Exception):
        """Base integration error."""

try:
    from .events import (
        IntegrationConnected,
        IntegrationDisconnected,
        IntegrationErrorEvent,
        SyncCompleted,
        SyncFailed,
        SyncStarted,
        WebhookProcessed,
        WebhookReceived,
    )
except ImportError as e:
    warnings.warn(f"Integration events not available: {e}", ImportWarning, stacklevel=2)

# Build __all__ dynamically based on what was successfully imported
__all__ = []

for item in [
    "Integration", "WebhookEndpoint", "ApiCredential", "IntegrationMapping",
    "SyncJob", "WebhookEvent", "ApiEndpoint", "AuthMethod", "RateLimitConfig",
    "SyncStatus", "WebhookSignature"
]:
    if globals().get(item) is not None:
        __all__.append(item)
