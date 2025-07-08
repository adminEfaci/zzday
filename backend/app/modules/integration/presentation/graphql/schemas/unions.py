"""GraphQL unions for Integration module.

This module provides GraphQL union types for handling polymorphic
responses in the Integration module API.
"""

from typing import Annotated

import strawberry

from .types.health_type import HealthCheckResult, HealthError
from .types.integration_type import IntegrationError, IntegrationType
from .types.mapping_type import MappingError, MappingValidationResult
from .types.sync_type import SyncError, SyncJobResult
from .types.webhook_type import WebhookError, WebhookEventResult


@strawberry.type
class Success:
    """Generic success response."""

    success: bool = True
    message: str = "Operation completed successfully"


@strawberry.type
class ValidationError:
    """Validation error response."""

    success: bool = False
    message: str
    field_errors: dict[str, list[str]] = strawberry.field(default_factory=dict)


@strawberry.type
class AuthenticationError:
    """Authentication error response."""

    success: bool = False
    message: str = "Authentication required"


@strawberry.type
class AuthorizationError:
    """Authorization error response."""

    success: bool = False
    message: str = "Insufficient permissions"


@strawberry.type
class RateLimitError:
    """Rate limit error response."""

    success: bool = False
    message: str = "Rate limit exceeded"
    retry_after: int  # Seconds until retry is allowed


@strawberry.type
class ServiceUnavailableError:
    """Service unavailable error response."""

    success: bool = False
    message: str = "Service temporarily unavailable"
    estimated_recovery_time: int | None = None  # Seconds


@strawberry.type
class IntegrationNotFoundError:
    """Integration not found error response."""

    success: bool = False
    message: str = "Integration not found"
    integration_id: str


# Union types for different operation results
IntegrationResult = Annotated[
    IntegrationType
    | IntegrationError
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError,
    strawberry.union("IntegrationResult"),
]

HealthResult = Annotated[
    HealthCheckResult
    | HealthError
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError
    | ServiceUnavailableError,
    strawberry.union("HealthResult"),
]

SyncResult = Annotated[
    SyncJobResult
    | SyncError
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError
    | RateLimitError,
    strawberry.union("SyncResult"),
]

WebhookResult = Annotated[
    WebhookEventResult
    | WebhookError
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError,
    strawberry.union("WebhookResult"),
]

MappingResult = Annotated[
    MappingValidationResult
    | MappingError
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError,
    strawberry.union("MappingResult"),
]

# Generic operation results
OperationResult = Annotated[
    Success
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | RateLimitError
    | ServiceUnavailableError,
    strawberry.union("OperationResult"),
]

# Batch operation results
BatchOperationResult = Annotated[
    Success
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | RateLimitError,
    strawberry.union("BatchOperationResult"),
]

# Configuration results
ConfigurationResult = Annotated[
    Success
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError,
    strawberry.union("ConfigurationResult"),
]

# Test results for integration testing
TestResult = Annotated[
    Success | ValidationError | ServiceUnavailableError | IntegrationNotFoundError,
    strawberry.union("TestResult"),
]

# Analytics results
AnalyticsResult = Annotated[
    dict
    | ValidationError
    | AuthenticationError
    | AuthorizationError
    | IntegrationNotFoundError,
    strawberry.union("AnalyticsResult"),
]


__all__ = [
    "AnalyticsResult",
    "AuthenticationError",
    "AuthorizationError",
    "BatchOperationResult",
    "ConfigurationResult",
    "HealthResult",
    "IntegrationNotFoundError",
    # Union types
    "IntegrationResult",
    "MappingResult",
    "OperationResult",
    "RateLimitError",
    "ServiceUnavailableError",
    # Error types
    "Success",
    "SyncResult",
    "TestResult",
    "ValidationError",
    "WebhookResult",
]
