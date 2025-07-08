"""Integration domain enums for type safety and domain modeling.

This module provides comprehensive enumerations for the Integration domain,
ensuring type safety and clear domain boundaries.
"""

from enum import Enum


class IntegrationType(Enum):
    """Types of integrations supported by the system."""

    REST_API = "rest_api"
    GRAPHQL = "graphql"
    WEBHOOK = "webhook"
    DATABASE = "database"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.replace("_", " ").title()

    @property
    def supports_webhooks(self) -> bool:
        """Check if this integration type supports webhooks."""
        return self in {
            IntegrationType.REST_API,
            IntegrationType.GRAPHQL,
            IntegrationType.WEBHOOK,
        }

    @property
    def supports_sync(self) -> bool:
        """Check if this integration type supports data synchronization."""
        return self in {
            IntegrationType.REST_API,
            IntegrationType.GRAPHQL,
            IntegrationType.DATABASE,
        }


class AuthType(Enum):
    """Authentication types for external integrations."""

    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    JWT = "jwt"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        if self == AuthType.API_KEY:
            return "API Key"
        if self == AuthType.OAUTH2:
            return "OAuth 2.0"
        if self == AuthType.JWT:
            return "JWT"
        return str(self.value.title())

    @property
    def requires_refresh(self) -> bool:
        """Check if this auth type requires token refresh."""
        return self in {AuthType.OAUTH2, AuthType.JWT}

    @property
    def is_token_based(self) -> bool:
        """Check if this auth type uses tokens."""
        return self in {AuthType.API_KEY, AuthType.OAUTH2, AuthType.JWT}


class SyncDirection(Enum):
    """Data synchronization directions."""

    IMPORT = "import"
    EXPORT = "export"
    BIDIRECTIONAL = "bidirectional"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()

    @property
    def allows_import(self) -> bool:
        """Check if this direction allows importing data."""
        return self in {SyncDirection.IMPORT, SyncDirection.BIDIRECTIONAL}

    @property
    def allows_export(self) -> bool:
        """Check if this direction allows exporting data."""
        return self in {SyncDirection.EXPORT, SyncDirection.BIDIRECTIONAL}


class WebhookStatus(Enum):
    """Status of webhook events."""

    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal status."""
        return self in {WebhookStatus.PROCESSED, WebhookStatus.FAILED}

    @property
    def is_active(self) -> bool:
        """Check if this status indicates active processing."""
        return self == WebhookStatus.PROCESSING


class ConnectionStatus(Enum):
    """Status of integration connections."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()

    @property
    def is_healthy(self) -> bool:
        """Check if this status indicates a healthy connection."""
        return self == ConnectionStatus.CONNECTED

    @property
    def requires_attention(self) -> bool:
        """Check if this status requires user attention."""
        return self == ConnectionStatus.ERROR


class SyncStatus(Enum):
    """Status of synchronization jobs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal status."""
        return self in {SyncStatus.COMPLETED, SyncStatus.FAILED, SyncStatus.CANCELLED}

    @property
    def is_active(self) -> bool:
        """Check if this status indicates active synchronization."""
        return self == SyncStatus.RUNNING

    @property
    def is_successful(self) -> bool:
        """Check if this status indicates successful completion."""
        return self == SyncStatus.COMPLETED


class RateLimitStrategy(Enum):
    """Rate limiting strategies for API calls."""

    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.replace("_", " ").title()


class WebhookMethod(Enum):
    """HTTP methods for webhooks."""

    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"

    def __str__(self) -> str:
        """Return the HTTP method."""
        return self.value


class FieldType(Enum):
    """Types of fields for integration mappings."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    DATE = "date"
    JSON = "json"
    ARRAY = "array"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()

    @property
    def is_numeric(self) -> bool:
        """Check if this is a numeric field type."""
        return self in {FieldType.INTEGER, FieldType.FLOAT}

    @property
    def is_temporal(self) -> bool:
        """Check if this is a temporal field type."""
        return self in {FieldType.DATETIME, FieldType.DATE}

    @property
    def is_complex(self) -> bool:
        """Check if this is a complex field type."""
        return self in {FieldType.JSON, FieldType.ARRAY}


class MappingTransformation(Enum):
    """Transformation types for field mappings."""

    NONE = "none"
    UPPERCASE = "uppercase"
    LOWERCASE = "lowercase"
    TRIM = "trim"
    DATE_FORMAT = "date_format"
    NUMBER_FORMAT = "number_format"
    CUSTOM = "custom"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.replace("_", " ").title()


class EntityType(Enum):
    """Types of entities that can be mapped in integrations."""

    USER = "user"
    CONTACT = "contact"
    ACCOUNT = "account"
    LEAD = "lead"
    OPPORTUNITY = "opportunity"
    PRODUCT = "product"
    ORDER = "order"
    INVOICE = "invoice"
    CUSTOM = "custom"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()


class MappingType(Enum):
    """Types of field mappings."""

    DIRECT = "direct"
    TRANSFORMED = "transformed"
    COMPUTED = "computed"
    CONSTANT = "constant"
    CONDITIONAL = "conditional"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.title()


class CredentialStatus(Enum):
    """Status of API credentials."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_RENEWAL = "pending_renewal"
    INVALID = "invalid"

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.value.replace("_", " ").title()

    @property
    def is_usable(self) -> bool:
        """Check if credentials can be used."""
        return self == CredentialStatus.ACTIVE

    @property
    def requires_action(self) -> bool:
        """Check if credentials require user action."""
        return self in {CredentialStatus.EXPIRED, CredentialStatus.PENDING_RENEWAL}


class HttpMethod(Enum):
    """HTTP methods for API calls."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

    def __str__(self) -> str:
        """Return the HTTP method."""
        return self.value

    @property
    def is_safe(self) -> bool:
        """Check if this is a safe HTTP method."""
        return self in {HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS}

    @property
    def is_idempotent(self) -> bool:
        """Check if this is an idempotent HTTP method."""
        return self in {
            HttpMethod.GET,
            HttpMethod.PUT,
            HttpMethod.DELETE,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS,
        }


# Export all enums
__all__: list[str] = [
    "AuthType",
    "ConnectionStatus",
    "CredentialStatus",
    "EntityType",
    "FieldType",
    "HttpMethod",
    "IntegrationType",
    "MappingTransformation",
    "MappingType",
    "RateLimitStrategy",
    "SyncDirection",
    "SyncStatus",
    "WebhookMethod",
    "WebhookStatus",
]
