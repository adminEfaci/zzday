"""GraphQL types for Integration module.

This module provides all GraphQL type definitions for the Integration module,
including integrations, health monitoring, webhooks, mappings, and more.
"""

from .email_service_type import EmailMetrics, EmailServiceType, EmailTemplate
from .fleet_type import FleetDriver, FleetType, FleetVehicle
from .health_type import HealthCheckResult, HealthMetrics, HealthType
from .integration_type import (
    IntegrationConfiguration,
    IntegrationCredentials,
    IntegrationType,
)
from .mapping_type import FieldMapping, MappingType, MappingValidation
from .maps_type import Location, MapsType, Route
from .sync_type import SyncJob, SyncProgress, SyncType
from .webhook_type import WebhookEvent, WebhookPayload, WebhookType

__all__ = [
    "EmailMetrics",
    # Email service types
    "EmailServiceType",
    "EmailTemplate",
    "FieldMapping",
    "FleetDriver",
    # Fleet types
    "FleetType",
    "FleetVehicle",
    "HealthCheckResult",
    "HealthMetrics",
    # Health types
    "HealthType",
    "IntegrationConfiguration",
    "IntegrationCredentials",
    # Integration types
    "IntegrationType",
    "Location",
    # Mapping types
    "MappingType",
    "MappingValidation",
    # Maps types
    "MapsType",
    "Route",
    "SyncJob",
    "SyncProgress",
    # Sync types
    "SyncType",
    "WebhookEvent",
    "WebhookPayload",
    # Webhook types
    "WebhookType",
]
