"""GraphQL schemas for Integration module.

This module provides all GraphQL type definitions, inputs, enums, and unions
for the Integration module API.
"""

from .enums import (
    AuthTypeEnum,
    ConnectionStatusEnum,
    FieldTypeEnum,
    IntegrationTypeEnum,
    MappingTransformationEnum,
    SyncDirectionEnum,
    SyncStatusEnum,
    WebhookStatusEnum,
)
from .inputs import (
    FleetQueryInput,
    HealthCheckInput,
    IntegrationConfigInput,
    MappingInput,
    SyncInput,
    WebhookInput,
)
from .types import (
    EmailServiceType,
    FleetType,
    HealthType,
    IntegrationType,
    MappingType,
    MapsType,
    SyncType,
    WebhookType,
)
from .unions import HealthResult, IntegrationResult, SyncResult

__all__ = [
    "AuthTypeEnum",
    "ConnectionStatusEnum",
    "EmailServiceType",
    "FieldTypeEnum",
    "FleetQueryInput",
    "FleetType",
    "HealthCheckInput",
    "HealthResult",
    "HealthType",
    # Inputs
    "IntegrationConfigInput",
    # Unions
    "IntegrationResult",
    # Types
    "IntegrationType",
    # Enums
    "IntegrationTypeEnum",
    "MappingInput",
    "MappingTransformationEnum",
    "MappingType",
    "MapsType",
    "SyncDirectionEnum",
    "SyncInput",
    "SyncResult",
    "SyncStatusEnum",
    "SyncType",
    "WebhookInput",
    "WebhookStatusEnum",
    "WebhookType",
]
