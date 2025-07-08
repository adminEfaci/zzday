"""Integration aggregate root for external system connections.

This module provides the main Integration aggregate that manages
external system connections, credentials, and data synchronization.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType
from app.modules.integration.domain.events import (
    IntegrationConfigurationUpdated,
    IntegrationConnected,
    IntegrationDisconnected,
    IntegrationErrorEvent,
    IntegrationHealthChecked,
)
from app.modules.integration.domain.value_objects import ApiEndpoint, RateLimitConfig


class Integration(AggregateRoot):
    """Aggregate root for managing external system integrations.

    This class serves as the main entry point for all integration-related
    operations, managing connections, credentials, mappings, and sync jobs.
    """

    def __init__(
        self,
        name: str,
        integration_type: IntegrationType,
        system_name: str,
        api_endpoint: ApiEndpoint,
        owner_id: UUID,
        description: str | None = None,
        rate_limit: RateLimitConfig | None = None,
        capabilities: list[str] | None = None,
        configuration: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize Integration aggregate.

        Args:
            name: Integration name
            integration_type: Type of integration
            system_name: External system name
            api_endpoint: API endpoint configuration
            owner_id: Owner user ID
            description: Optional description
            rate_limit: Optional rate limit configuration
            capabilities: List of enabled capabilities
            configuration: Additional configuration
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.name = self._validate_name(name)
        self.integration_type = integration_type
        self.system_name = self._validate_system_name(system_name)
        self.api_endpoint = api_endpoint
        self.owner_id = owner_id
        self.description = description

        # Configuration
        self.rate_limit = rate_limit
        self.capabilities = capabilities or self._default_capabilities()
        self.configuration = configuration or {}

        # State
        self.status = ConnectionStatus.DISCONNECTED
        self.is_active = True
        self.last_health_check: datetime | None = None
        self.health_check_failures = 0

        # Child entities (managed separately but referenced here)
        self._credential_ids: list[UUID] = []
        self._sync_job_ids: list[UUID] = []
        self._mapping_ids: list[UUID] = []
        self._webhook_endpoint_ids: list[UUID] = []

        # Validate state
        self._validate_aggregate()

    def _validate_name(self, name: str) -> str:
        """Validate integration name."""
        if not name or not name.strip():
            raise ValidationError("Integration name cannot be empty")

        name = name.strip()
        if len(name) > 100:
            raise ValidationError("Integration name cannot exceed 100 characters")

        return name

    def _validate_system_name(self, system_name: str) -> str:
        """Validate system name."""
        if not system_name or not system_name.strip():
            raise ValidationError("System name cannot be empty")

        system_name = system_name.strip()
        if len(system_name) > 50:
            raise ValidationError("System name cannot exceed 50 characters")

        return system_name

    def _default_capabilities(self) -> list[str]:
        """Get default capabilities based on integration type."""
        capabilities = []

        if self.integration_type.supports_sync:
            capabilities.extend(["read", "write", "sync"])

        if self.integration_type.supports_webhooks:
            capabilities.append("webhooks")

        if self.integration_type == IntegrationType.DATABASE:
            capabilities.extend(["query", "bulk_operations"])

        return capabilities

    def _validate_aggregate(self) -> None:
        """Validate aggregate state."""
        if not isinstance(self.integration_type, IntegrationType):
            raise ValidationError("integration_type must be an IntegrationType enum")

        if not isinstance(self.api_endpoint, ApiEndpoint):
            raise ValidationError("api_endpoint must be an ApiEndpoint instance")

        if self.rate_limit and not isinstance(self.rate_limit, RateLimitConfig):
            raise ValidationError("rate_limit must be a RateLimitConfig instance")

        if not isinstance(self.status, ConnectionStatus):
            raise ValidationError("status must be a ConnectionStatus enum")

    @property
    def is_connected(self) -> bool:
        """Check if integration is connected."""
        return self.status == ConnectionStatus.CONNECTED

    @property
    def is_healthy(self) -> bool:
        """Check if integration is healthy."""
        return self.status.is_healthy and self.health_check_failures < 3

    @property
    def needs_attention(self) -> bool:
        """Check if integration needs attention."""
        return self.status.requires_attention or self.health_check_failures >= 3

    @property
    def can_sync(self) -> bool:
        """Check if integration can perform sync operations."""
        return (
            self.is_connected
            and self.is_active
            and "sync" in self.capabilities
            and self.integration_type.supports_sync
        )

    @property
    def can_receive_webhooks(self) -> bool:
        """Check if integration can receive webhooks."""
        return (
            self.is_active
            and "webhooks" in self.capabilities
            and self.integration_type.supports_webhooks
        )

    def connect(self, credential_id: UUID, test_connection: bool = True) -> None:
        """Connect to external system.

        Args:
            credential_id: ID of credential to use
            test_connection: Whether to test connection

        Raises:
            ConnectionFailedError: If connection fails
            DomainError: If already connected
        """
        if self.is_connected:
            raise DomainError("Integration is already connected")

        if not self.is_active:
            raise DomainError("Cannot connect inactive integration")

        if credential_id not in self._credential_ids:
            raise DomainError("Credential not associated with this integration")

        # In real implementation, would test connection here
        # For now, assume success

        self.status = ConnectionStatus.CONNECTED
        self.health_check_failures = 0
        self.mark_modified()

        # Emit event
        self.add_event(
            IntegrationConnected(
                integration_id=self.id,
                integration_name=self.name,
                integration_type=self.integration_type,
                system_name=self.system_name,
                connected_by=self.owner_id,
                capabilities=self.capabilities,
                configuration=self._sanitize_configuration(),
            )
        )

    def disconnect(
        self, user_id: UUID | None = None, reason: str | None = None
    ) -> None:
        """Disconnect from external system.

        Args:
            user_id: User who initiated disconnection
            reason: Reason for disconnection
        """
        if not self.is_connected:
            return

        self.status = ConnectionStatus.DISCONNECTED
        self.mark_modified()

        # Emit event
        self.add_event(
            IntegrationDisconnected(
                integration_id=self.id,
                integration_name=self.name,
                system_name=self.system_name,
                disconnected_by=user_id,
                reason=reason,
                is_automatic=user_id is None,
            )
        )

    def record_error(
        self, error_type: str, error_message: str, is_retryable: bool = False
    ) -> None:
        """Record an integration error.

        Args:
            error_type: Type of error
            error_message: Error message
            is_retryable: Whether error is retryable
        """
        if self.status == ConnectionStatus.CONNECTED:
            self.status = ConnectionStatus.ERROR

        self.mark_modified()

        # Emit event
        self.add_event(
            IntegrationErrorEvent(
                integration_id=self.id,
                integration_name=self.name,
                error_type=error_type,
                error_message=error_message,
                is_retryable=is_retryable,
            )
        )

    def health_check(
        self,
        is_healthy: bool,
        response_time_ms: float | None = None,
        error_message: str | None = None,
    ) -> None:
        """Record health check result.

        Args:
            is_healthy: Whether check passed
            response_time_ms: Response time
            error_message: Error if unhealthy
        """
        self.last_health_check = datetime.now(UTC)

        if is_healthy:
            if self.status == ConnectionStatus.ERROR:
                self.status = ConnectionStatus.CONNECTED
            self.health_check_failures = 0
        else:
            self.health_check_failures += 1
            if self.health_check_failures >= 3:
                self.status = ConnectionStatus.ERROR

        self.mark_modified()

        # Emit event
        status = ConnectionStatus.CONNECTED if is_healthy else ConnectionStatus.ERROR
        self.add_event(
            IntegrationHealthChecked(
                integration_id=self.id,
                integration_name=self.name,
                status=status,
                response_time_ms=response_time_ms,
                error_message=error_message,
            )
        )

    def update_configuration(self, updates: dict[str, Any], updated_by: UUID) -> None:
        """Update integration configuration.

        Args:
            updates: Configuration updates
            updated_by: User making updates

        Raises:
            IntegrationConfigurationError: If configuration is invalid
        """
        if not updates:
            return

        # Capture previous values
        previous = {}
        for key in updates:
            if key in self.configuration:
                previous[key] = self.configuration[key]

        # Apply updates
        self.configuration.update(updates)
        self.mark_modified()

        # Emit event
        self.add_event(
            IntegrationConfigurationUpdated(
                integration_id=self.id,
                integration_name=self.name,
                updated_by=updated_by,
                changes=updates,
                previous_values=previous,
            )
        )

    def add_credential(self, credential_id: UUID) -> None:
        """Add a credential to the integration.

        Args:
            credential_id: Credential ID to add

        Raises:
            DomainError: If credential already added
        """
        if credential_id in self._credential_ids:
            raise DomainError("Credential already added to integration")

        self._credential_ids.append(credential_id)
        self.mark_modified()

    def remove_credential(self, credential_id: UUID) -> None:
        """Remove a credential from the integration.

        Args:
            credential_id: Credential ID to remove

        Raises:
            DomainError: If credential not found
        """
        if credential_id not in self._credential_ids:
            raise DomainError("Credential not found in integration")

        self._credential_ids.remove(credential_id)
        self.mark_modified()

    def add_sync_job(self, sync_job_id: UUID) -> None:
        """Add a sync job to the integration.

        Args:
            sync_job_id: Sync job ID to add
        """
        if sync_job_id not in self._sync_job_ids:
            self._sync_job_ids.append(sync_job_id)
            self.mark_modified()

    def remove_sync_job(self, sync_job_id: UUID) -> None:
        """Remove a sync job from the integration.

        Args:
            sync_job_id: Sync job ID to remove
        """
        if sync_job_id in self._sync_job_ids:
            self._sync_job_ids.remove(sync_job_id)
            self.mark_modified()

    def add_mapping(self, mapping_id: UUID) -> None:
        """Add a mapping to the integration.

        Args:
            mapping_id: Mapping ID to add
        """
        if mapping_id not in self._mapping_ids:
            self._mapping_ids.append(mapping_id)
            self.mark_modified()

    def remove_mapping(self, mapping_id: UUID) -> None:
        """Remove a mapping from the integration.

        Args:
            mapping_id: Mapping ID to remove
        """
        if mapping_id in self._mapping_ids:
            self._mapping_ids.remove(mapping_id)
            self.mark_modified()

    def add_webhook_endpoint(self, endpoint_id: UUID) -> None:
        """Add a webhook endpoint to the integration.

        Args:
            endpoint_id: Endpoint ID to add

        Raises:
            DomainError: If webhooks not supported
        """
        if not self.can_receive_webhooks:
            raise DomainError("Integration does not support webhooks")

        if endpoint_id not in self._webhook_endpoint_ids:
            self._webhook_endpoint_ids.append(endpoint_id)
            self.mark_modified()

    def remove_webhook_endpoint(self, endpoint_id: UUID) -> None:
        """Remove a webhook endpoint from the integration.

        Args:
            endpoint_id: Endpoint ID to remove
        """
        if endpoint_id in self._webhook_endpoint_ids:
            self._webhook_endpoint_ids.remove(endpoint_id)
            self.mark_modified()

    def activate(self) -> None:
        """Activate the integration."""
        if not self.is_active:
            self.is_active = True
            self.mark_modified()

    def deactivate(self) -> None:
        """Deactivate the integration."""
        if self.is_active:
            self.is_active = False
            if self.is_connected:
                self.disconnect(reason="Integration deactivated")
            self.mark_modified()

    def update_rate_limit(self, rate_limit: RateLimitConfig) -> None:
        """Update rate limit configuration.

        Args:
            rate_limit: New rate limit configuration
        """
        self.rate_limit = rate_limit
        self.mark_modified()

    def add_capability(self, capability: str) -> None:
        """Add a capability to the integration.

        Args:
            capability: Capability to add
        """
        if capability not in self.capabilities:
            self.capabilities.append(capability)
            self.mark_modified()

    def remove_capability(self, capability: str) -> None:
        """Remove a capability from the integration.

        Args:
            capability: Capability to remove
        """
        if capability in self.capabilities:
            self.capabilities.remove(capability)
            self.mark_modified()

    def _sanitize_configuration(self) -> dict[str, Any]:
        """Sanitize configuration for events."""
        # Remove sensitive information
        sanitized = {}
        sensitive_keys = {"password", "secret", "key", "token", "credential"}

        for key, value in self.configuration.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add integration specific fields
        data.update(
            {
                "name": self.name,
                "integration_type": self.integration_type.value,
                "system_name": self.system_name,
                "api_endpoint": self.api_endpoint.to_dict(),
                "owner_id": str(self.owner_id),
                "description": self.description,
                "rate_limit": self.rate_limit.to_dict() if self.rate_limit else None,
                "capabilities": self.capabilities,
                "configuration": self._sanitize_configuration(),
                "status": self.status.value,
                "is_active": self.is_active,
                "is_connected": self.is_connected,
                "is_healthy": self.is_healthy,
                "needs_attention": self.needs_attention,
                "can_sync": self.can_sync,
                "can_receive_webhooks": self.can_receive_webhooks,
                "last_health_check": self.last_health_check.isoformat()
                if self.last_health_check
                else None,
                "health_check_failures": self.health_check_failures,
                "credential_count": len(self._credential_ids),
                "sync_job_count": len(self._sync_job_ids),
                "mapping_count": len(self._mapping_ids),
                "webhook_endpoint_count": len(self._webhook_endpoint_ids),
            }
        )

        return data

    def __str__(self) -> str:
        """String representation."""
        return f"Integration({self.name}, {self.system_name}, {self.status.value})"
