"""GraphQL enums for Integration module.

This module provides GraphQL enum definitions that map to domain enums
for type safety in the GraphQL API.
"""


import strawberry

from app.modules.integration.domain.enums import AuthType as DomainAuthType
from app.modules.integration.domain.enums import (
    ConnectionStatus as DomainConnectionStatus,
)
from app.modules.integration.domain.enums import FieldType as DomainFieldType
from app.modules.integration.domain.enums import (
    IntegrationType as DomainIntegrationType,
)
from app.modules.integration.domain.enums import (
    MappingTransformation as DomainMappingTransformation,
)
from app.modules.integration.domain.enums import (
    RateLimitStrategy as DomainRateLimitStrategy,
)
from app.modules.integration.domain.enums import SyncDirection as DomainSyncDirection
from app.modules.integration.domain.enums import SyncStatus as DomainSyncStatus
from app.modules.integration.domain.enums import WebhookMethod as DomainWebhookMethod
from app.modules.integration.domain.enums import WebhookStatus as DomainWebhookStatus


@strawberry.enum
class IntegrationTypeEnum:
    """GraphQL enum for integration types."""

    REST_API = DomainIntegrationType.REST_API
    GRAPHQL = DomainIntegrationType.GRAPHQL
    WEBHOOK = DomainIntegrationType.WEBHOOK
    DATABASE = DomainIntegrationType.DATABASE


@strawberry.enum
class AuthTypeEnum:
    """GraphQL enum for authentication types."""

    API_KEY = DomainAuthType.API_KEY
    OAUTH2 = DomainAuthType.OAUTH2
    BASIC = DomainAuthType.BASIC
    JWT = DomainAuthType.JWT


@strawberry.enum
class SyncDirectionEnum:
    """GraphQL enum for synchronization directions."""

    IMPORT = DomainSyncDirection.IMPORT
    EXPORT = DomainSyncDirection.EXPORT
    BIDIRECTIONAL = DomainSyncDirection.BIDIRECTIONAL


@strawberry.enum
class WebhookStatusEnum:
    """GraphQL enum for webhook statuses."""

    PENDING = DomainWebhookStatus.PENDING
    PROCESSING = DomainWebhookStatus.PROCESSING
    PROCESSED = DomainWebhookStatus.PROCESSED
    FAILED = DomainWebhookStatus.FAILED


@strawberry.enum
class ConnectionStatusEnum:
    """GraphQL enum for connection statuses."""

    CONNECTED = DomainConnectionStatus.CONNECTED
    DISCONNECTED = DomainConnectionStatus.DISCONNECTED
    ERROR = DomainConnectionStatus.ERROR


@strawberry.enum
class SyncStatusEnum:
    """GraphQL enum for sync statuses."""

    PENDING = DomainSyncStatus.PENDING
    RUNNING = DomainSyncStatus.RUNNING
    COMPLETED = DomainSyncStatus.COMPLETED
    FAILED = DomainSyncStatus.FAILED
    CANCELLED = DomainSyncStatus.CANCELLED


@strawberry.enum
class RateLimitStrategyEnum:
    """GraphQL enum for rate limiting strategies."""

    FIXED_WINDOW = DomainRateLimitStrategy.FIXED_WINDOW
    SLIDING_WINDOW = DomainRateLimitStrategy.SLIDING_WINDOW
    TOKEN_BUCKET = DomainRateLimitStrategy.TOKEN_BUCKET
    LEAKY_BUCKET = DomainRateLimitStrategy.LEAKY_BUCKET


@strawberry.enum
class WebhookMethodEnum:
    """GraphQL enum for webhook HTTP methods."""

    POST = DomainWebhookMethod.POST
    PUT = DomainWebhookMethod.PUT
    PATCH = DomainWebhookMethod.PATCH


@strawberry.enum
class FieldTypeEnum:
    """GraphQL enum for field types."""

    STRING = DomainFieldType.STRING
    INTEGER = DomainFieldType.INTEGER
    FLOAT = DomainFieldType.FLOAT
    BOOLEAN = DomainFieldType.BOOLEAN
    DATETIME = DomainFieldType.DATETIME
    DATE = DomainFieldType.DATE
    JSON = DomainFieldType.JSON
    ARRAY = DomainFieldType.ARRAY


@strawberry.enum
class MappingTransformationEnum:
    """GraphQL enum for mapping transformations."""

    NONE = DomainMappingTransformation.NONE
    UPPERCASE = DomainMappingTransformation.UPPERCASE
    LOWERCASE = DomainMappingTransformation.LOWERCASE
    TRIM = DomainMappingTransformation.TRIM
    DATE_FORMAT = DomainMappingTransformation.DATE_FORMAT
    NUMBER_FORMAT = DomainMappingTransformation.NUMBER_FORMAT
    CUSTOM = DomainMappingTransformation.CUSTOM


@strawberry.enum
class HealthStatusEnum:
    """GraphQL enum for health statuses."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


@strawberry.enum
class HealthCheckTypeEnum:
    """GraphQL enum for health check types."""

    CONNECTIVITY = "CONNECTIVITY"
    AUTHENTICATION = "AUTHENTICATION"
    RATE_LIMIT = "RATE_LIMIT"
    RESPONSE_TIME = "RESPONSE_TIME"
    ERROR_RATE = "ERROR_RATE"


@strawberry.enum
class IntegrationCapabilityEnum:
    """GraphQL enum for integration capabilities."""

    SYNC = "SYNC"
    WEBHOOK = "WEBHOOK"
    REAL_TIME = "REAL_TIME"
    BATCH = "BATCH"
    STREAMING = "STREAMING"
    FILE_TRANSFER = "FILE_TRANSFER"
    AUTHENTICATION = "AUTHENTICATION"
    RATE_LIMITING = "RATE_LIMITING"


@strawberry.enum
class FleetProviderEnum:
    """GraphQL enum for fleet management providers."""

    SAMSARA = "SAMSARA"
    GEOTAB = "GEOTAB"
    FLEET_COMPLETE = "FLEET_COMPLETE"
    VERIZON_CONNECT = "VERIZON_CONNECT"


@strawberry.enum
class EmailProviderEnum:
    """GraphQL enum for email service providers."""

    RESEND = "RESEND"
    SENDGRID = "SENDGRID"
    MAILGUN = "MAILGUN"
    SES = "SES"


@strawberry.enum
class MapsProviderEnum:
    """GraphQL enum for maps service providers."""

    OPENSTREETMAP = "OPENSTREETMAP"
    GOOGLE_MAPS = "GOOGLE_MAPS"
    MAPBOX = "MAPBOX"
    HERE = "HERE"


@strawberry.enum
class SyncFrequencyEnum:
    """GraphQL enum for sync frequencies."""

    REAL_TIME = "REAL_TIME"
    EVERY_MINUTE = "EVERY_MINUTE"
    EVERY_5_MINUTES = "EVERY_5_MINUTES"
    EVERY_15_MINUTES = "EVERY_15_MINUTES"
    EVERY_30_MINUTES = "EVERY_30_MINUTES"
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"
    MANUAL = "MANUAL"


@strawberry.enum
class ErrorSeverityEnum:
    """GraphQL enum for error severities."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@strawberry.enum
class WebhookEventTypeEnum:
    """GraphQL enum for webhook event types."""

    DATA_SYNC = "DATA_SYNC"
    STATUS_CHANGE = "STATUS_CHANGE"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    HEALTH_CHECK = "HEALTH_CHECK"
    RATE_LIMIT = "RATE_LIMIT"
    AUTHENTICATION = "AUTHENTICATION"
    CUSTOM = "CUSTOM"


# Export all enums
__all__: list[str] = [
    "AuthTypeEnum",
    "ConnectionStatusEnum",
    "EmailProviderEnum",
    "ErrorSeverityEnum",
    "FieldTypeEnum",
    "FleetProviderEnum",
    "HealthCheckTypeEnum",
    "HealthStatusEnum",
    "IntegrationCapabilityEnum",
    "IntegrationTypeEnum",
    "MappingTransformationEnum",
    "MapsProviderEnum",
    "RateLimitStrategyEnum",
    "SyncDirectionEnum",
    "SyncFrequencyEnum",
    "SyncStatusEnum",
    "WebhookEventTypeEnum",
    "WebhookMethodEnum",
    "WebhookStatusEnum",
]
