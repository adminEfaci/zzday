"""GraphQL inputs for integration operations.

This module provides comprehensive input types for all integration-related
GraphQL operations including configuration, health monitoring, webhooks,
fleet management, email services, and mapping services.
"""

# Configuration inputs
from .configuration_inputs import (
    ApiEndpointConfigInput,
    IntegrationConfigInput,
    RateLimitConfigInput,
    UpdateConfigInput,
    ValidateConfigInput,
)

# Email inputs  
from .email_inputs import (
    EmailProviderConfigInput,
    EmailTestInput,
    ResendConfigInput,
)

# Fleet inputs
from .fleet_inputs import (
    FleetProviderConfigInput,
    FleetSyncInput,
    GeotabConfigInput,
    SamsaraConfigInput,
)

# Health inputs
from .health_inputs import (
    AlertingConfigInput,
    HealthCheckInput,
    HealthFilterInput,
    MetricsFilterInput,
)

# Integration inputs
from .integration_inputs import (
    ConnectIntegrationInput,
    CreateIntegrationInput,
    DisconnectIntegrationInput,
    IntegrationFilterInput,
    IntegrationSortInput,
    UpdateIntegrationInput,
)

# Mapping inputs
from .mapping_inputs import (
    DataMappingInput,
    GoogleMapsConfigInput,
    MapboxConfigInput,
    MappingProviderConfigInput,
    OSMConfigInput,
    RoutingInput,
)

# Sync inputs
from .sync_inputs import (
    SyncFilterInput,
    SyncJobInput,
    SyncScheduleInput,
)

# Testing inputs
from .testing_inputs import (
    IntegrationTestInput,
    LoadTestInput,
    PerformanceTestInput,
    TestScenarioInput,
)

# Webhook inputs
from .webhook_inputs import (
    WebhookEndpointInput,
    WebhookEventInput,
    WebhookRetryInput,
    WebhookTestInput,
)

__all__ = [
    "AlertingConfigInput",
    # Configuration inputs
    "ApiEndpointConfigInput",
    "ConnectIntegrationInput",
    # Integration inputs
    "CreateIntegrationInput",
    "DataMappingInput",
    "DisconnectIntegrationInput",
    # Email inputs
    "EmailProviderConfigInput",
    "EmailTestInput",
    # Fleet inputs
    "FleetProviderConfigInput",
    "FleetSyncInput",
    "GeotabConfigInput",
    "GoogleMapsConfigInput",
    # Health inputs
    "HealthCheckInput",
    "HealthFilterInput",
    "IntegrationConfigInput",
    "IntegrationFilterInput",
    "IntegrationSortInput",
    # Testing inputs
    "IntegrationTestInput",
    "LoadTestInput",
    "MapboxConfigInput",
    # Mapping inputs
    "MappingProviderConfigInput",
    "MetricsFilterInput",
    "OSMConfigInput",
    "PerformanceTestInput",
    "RateLimitConfigInput",
    "ResendConfigInput",
    "RoutingInput",
    "SamsaraConfigInput",
    "SyncFilterInput",
    # Sync inputs
    "SyncJobInput",
    "SyncScheduleInput",
    "TestScenarioInput",
    "UpdateConfigInput",
    "UpdateIntegrationInput",
    "ValidateConfigInput",
    # Webhook inputs
    "WebhookEndpointInput",
    "WebhookEventInput",
    "WebhookRetryInput",
    "WebhookTestInput",
]
