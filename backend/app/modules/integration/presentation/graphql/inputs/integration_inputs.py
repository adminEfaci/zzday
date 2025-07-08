"""Core integration GraphQL input types."""

from datetime import datetime
from typing import Any
from uuid import UUID

import strawberry

from ..schemas.enums import (
    AuthTypeEnum,
    ConnectionStatusEnum,
    IntegrationCapabilityEnum,
    IntegrationTypeEnum,
    SortOrderEnum,
)


@strawberry.input
class CreateIntegrationInput:
    """Input for creating a new integration."""

    name: str
    description: str | None = None
    integration_type: IntegrationTypeEnum
    system_name: str

    # Configuration dictionary for flexible configuration
    configuration: dict[str, Any] | None = None


@strawberry.input
class UpdateIntegrationInput:
    """Input for updating an existing integration."""

    name: str | None = None
    description: str | None = None
    configuration: dict[str, Any] | None = None
    is_active: bool | None = None


@strawberry.input
class ConnectIntegrationInput:
    """Input for connecting/reconnecting an integration."""

    integration_id: UUID

    # Force reconnection
    force_reconnect: bool = False

    # Validation options
    validate_credentials: bool = True
    test_connection: bool = True

    # Retry configuration for connection
    max_connection_attempts: int = 3
    connection_timeout: int = 30


@strawberry.input
class DisconnectIntegrationInput:
    """Input for disconnecting an integration."""

    integration_id: UUID

    # Graceful shutdown options
    wait_for_pending_operations: bool = True
    timeout_seconds: int = 60

    # Cleanup options
    clear_cache: bool = False
    revoke_tokens: bool = False


@strawberry.input
class CredentialUpdateInput:
    """Input for updating integration credentials."""

    integration_id: UUID
    auth_type: AuthTypeEnum

    # Credential data
    api_key: str | None = None
    api_secret: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_access_token: str | None = None
    oauth_refresh_token: str | None = None
    username: str | None = None
    password: str | None = None

    # Token expiration
    expires_at: datetime | None = None

    # Validation
    validate_immediately: bool = True


@strawberry.input
class IntegrationFilterInput:
    """Input for filtering integrations."""

    # Basic filters
    integration_ids: list[UUID] | None = None
    name_contains: str | None = None
    integration_types: list[IntegrationTypeEnum] | None = None
    system_names: list[str] | None = None

    # Status filters
    is_active: bool | None = None
    connection_statuses: list[ConnectionStatusEnum] | None = None
    is_healthy: bool | None = None
    needs_attention: bool | None = None

    # Capability filters
    has_capabilities: list[IntegrationCapabilityEnum] | None = None
    supports_webhooks: bool | None = None
    supports_sync: bool | None = None
    supports_real_time: bool | None = None

    # Owner filters
    owner_ids: list[UUID] | None = None

    # Date filters
    created_after: datetime | None = None
    created_before: datetime | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None
    last_activity_after: datetime | None = None
    last_activity_before: datetime | None = None

    # Health filters
    uptime_percentage_min: float | None = None
    error_rate_max: float | None = None
    consecutive_failures_max: int | None = None


@strawberry.input
class IntegrationSortInput:
    """Input for sorting integrations."""

    field: str  # name, created_at, updated_at, last_activity, uptime_percentage, error_rate
    order: SortOrderEnum = SortOrderEnum.ASC


@strawberry.input
class BulkOperationInput:
    """Input for bulk operations on integrations."""

    integration_ids: list[UUID]
    operation: str  # activate, deactivate, reconnect, disconnect, test

    # Operation-specific options
    options: dict[str, Any] | None = None

    # Execution options
    parallel_execution: bool = True
    max_concurrent: int = 5
    stop_on_error: bool = False


@strawberry.input
class IntegrationExportInput:
    """Input for exporting integration data."""

    integration_ids: list[UUID] | None = None
    filters: IntegrationFilterInput | None = None

    # Export options
    include_credentials: bool = False  # Never include actual credentials
    include_metrics: bool = True
    include_configuration: bool = True
    include_health_status: bool = True

    # Format options
    format: str = "json"  # json, csv, xlsx
    compress: bool = False


@strawberry.input
class IntegrationImportInput:
    """Input for importing integration configurations."""

    # Import data (JSON string)
    data: str

    # Import options
    validate_before_import: bool = True
    skip_existing: bool = True
    update_existing: bool = False

    # Credential handling
    require_credential_input: bool = True
    default_credentials: dict[str, str] | None = None


# Additional input types for mutations


@strawberry.input
class TestIntegrationInput:
    """Input for testing integration connectivity."""

    test_type: str = "full"  # basic, connectivity, authentication, full
    timeout_seconds: int = 30
    include_diagnostics: bool = True


@strawberry.input
class RefreshCredentialsInput:
    """Input for refreshing integration credentials."""

    force_refresh: bool = False
    validate_after_refresh: bool = True


@strawberry.input
class ActivateIntegrationInput:
    """Input for activating an integration."""

    validate_configuration: bool = True
    test_connectivity: bool = True


@strawberry.input
class DeactivateIntegrationInput:
    """Input for deactivating an integration."""

    reason: str | None = None
    graceful_shutdown: bool = True
    timeout_seconds: int = 60


@strawberry.input
class IntegrationConfigurationInput:
    """Input for updating integration configuration."""

    api_endpoint: dict[str, Any] | None = None
    rate_limit: dict[str, Any] | None = None
    capabilities: list[str] | None = None
    custom_fields: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for service layer."""
        return {
            "api_endpoint": self.api_endpoint,
            "rate_limit": self.rate_limit,
            "capabilities": self.capabilities,
            "custom_fields": self.custom_fields,
        }


@strawberry.input
class PaginationInput:
    """Input for pagination parameters."""

    page: int = 1
    page_size: int = 20


@strawberry.input
class AnalyticsTimeRangeInput:
    """Input for analytics time range."""

    start_date: datetime
    end_date: datetime


__all__ = [
    "ActivateIntegrationInput",
    "AnalyticsTimeRangeInput",
    "BulkOperationInput",
    "ConnectIntegrationInput",
    "CreateIntegrationInput",
    "CredentialUpdateInput",
    "DeactivateIntegrationInput",
    "DisconnectIntegrationInput",
    "IntegrationConfigurationInput",
    "IntegrationExportInput",
    "IntegrationFilterInput",
    "IntegrationImportInput",
    "IntegrationSortInput",
    "PaginationInput",
    "RefreshCredentialsInput",
    "TestIntegrationInput",
    "UpdateIntegrationInput",
]
