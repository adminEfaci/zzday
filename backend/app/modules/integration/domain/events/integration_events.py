"""Integration connection and lifecycle events.

This module provides domain events for integration lifecycle management,
including connection, disconnection, and error tracking.
"""

from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent, EventMetadata
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType


class IntegrationConnected(DomainEvent):
    """Event raised when an integration is successfully connected."""

    def __init__(
        self,
        integration_id: UUID,
        integration_name: str,
        integration_type: IntegrationType,
        system_name: str,
        connected_by: UUID,
        capabilities: list[str],
        configuration: dict[str, Any],
        metadata: EventMetadata | None = None,
    ):
        """Initialize integration connected event.

        Args:
            integration_id: ID of the integration
            integration_name: Name of the integration
            integration_type: Type of integration
            system_name: Name of the external system
            connected_by: User ID who connected the integration
            capabilities: List of capabilities enabled
            configuration: Integration configuration (sanitized)
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.integration_id = integration_id
        self.integration_name = integration_name
        self.integration_type = integration_type
        self.system_name = system_name
        self.connected_by = connected_by
        self.capabilities = capabilities
        self.configuration = configuration

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = integration_id
            self.metadata.aggregate_type = "Integration"
            self.metadata.user_id = connected_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not isinstance(self.integration_type, IntegrationType):
            raise ValidationError("integration_type must be an IntegrationType enum")

        if not self.system_name:
            raise ValidationError("system_name is required")

        if not self.connected_by:
            raise ValidationError("connected_by is required")

        if not isinstance(self.capabilities, list):
            raise ValidationError("capabilities must be a list")

        if not isinstance(self.configuration, dict):
            raise ValidationError("configuration must be a dictionary")


class IntegrationDisconnected(DomainEvent):
    """Event raised when an integration is disconnected."""

    def __init__(
        self,
        integration_id: UUID,
        integration_name: str,
        system_name: str,
        disconnected_by: UUID | None = None,
        reason: str | None = None,
        is_automatic: bool = False,
        metadata: EventMetadata | None = None,
    ):
        """Initialize integration disconnected event.

        Args:
            integration_id: ID of the integration
            integration_name: Name of the integration
            system_name: Name of the external system
            disconnected_by: User ID who disconnected (if manual)
            reason: Reason for disconnection
            is_automatic: Whether disconnection was automatic
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.integration_id = integration_id
        self.integration_name = integration_name
        self.system_name = system_name
        self.disconnected_by = disconnected_by
        self.reason = reason
        self.is_automatic = is_automatic

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = integration_id
            self.metadata.aggregate_type = "Integration"
            if disconnected_by:
                self.metadata.user_id = disconnected_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.system_name:
            raise ValidationError("system_name is required")

        if not self.is_automatic and not self.disconnected_by:
            raise ValidationError(
                "disconnected_by is required for manual disconnection"
            )


class IntegrationErrorEvent(DomainEvent):
    """Event raised when an integration encounters an error.

    Note: Named IntegrationErrorEvent to avoid conflict with IntegrationError exception.
    """

    def __init__(
        self,
        integration_id: UUID,
        integration_name: str,
        error_type: str,
        error_message: str,
        error_code: str | None = None,
        is_retryable: bool = False,
        retry_count: int = 0,
        error_details: dict[str, Any] | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize integration error event.

        Args:
            integration_id: ID of the integration
            integration_name: Name of the integration
            error_type: Type of error
            error_message: Error message
            error_code: Optional error code
            is_retryable: Whether the error is retryable
            retry_count: Number of retry attempts
            error_details: Additional error details
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.integration_id = integration_id
        self.integration_name = integration_name
        self.error_type = error_type
        self.error_message = error_message
        self.error_code = error_code
        self.is_retryable = is_retryable
        self.retry_count = retry_count
        self.error_details = error_details or {}

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = integration_id
            self.metadata.aggregate_type = "Integration"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.error_type:
            raise ValidationError("error_type is required")

        if not self.error_message:
            raise ValidationError("error_message is required")

        if self.retry_count < 0:
            raise ValidationError("retry_count cannot be negative")

        if not isinstance(self.error_details, dict):
            raise ValidationError("error_details must be a dictionary")


class IntegrationHealthChecked(DomainEvent):
    """Event raised when integration health is checked."""

    def __init__(
        self,
        integration_id: UUID,
        integration_name: str,
        status: ConnectionStatus,
        response_time_ms: float | None = None,
        error_message: str | None = None,
        checked_endpoints: list[str] | None = None,
        metadata: EventMetadata | None = None,
    ):
        """Initialize integration health check event.

        Args:
            integration_id: ID of the integration
            integration_name: Name of the integration
            status: Connection status result
            response_time_ms: Response time in milliseconds
            error_message: Error message if unhealthy
            checked_endpoints: List of endpoints checked
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.integration_id = integration_id
        self.integration_name = integration_name
        self.status = status
        self.response_time_ms = response_time_ms
        self.error_message = error_message
        self.checked_endpoints = checked_endpoints or []

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = integration_id
            self.metadata.aggregate_type = "Integration"

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not isinstance(self.status, ConnectionStatus):
            raise ValidationError("status must be a ConnectionStatus enum")

        if self.response_time_ms is not None and self.response_time_ms < 0:
            raise ValidationError("response_time_ms cannot be negative")

        if not isinstance(self.checked_endpoints, list):
            raise ValidationError("checked_endpoints must be a list")


class IntegrationConfigurationUpdated(DomainEvent):
    """Event raised when integration configuration is updated."""

    def __init__(
        self,
        integration_id: UUID,
        integration_name: str,
        updated_by: UUID,
        changes: dict[str, Any],
        previous_values: dict[str, Any],
        metadata: EventMetadata | None = None,
    ):
        """Initialize integration configuration updated event.

        Args:
            integration_id: ID of the integration
            integration_name: Name of the integration
            updated_by: User ID who updated configuration
            changes: Dictionary of changed values (sanitized)
            previous_values: Previous values (sanitized)
            metadata: Optional event metadata
        """
        super().__init__(metadata)

        self.integration_id = integration_id
        self.integration_name = integration_name
        self.updated_by = updated_by
        self.changes = changes
        self.previous_values = previous_values

        # Set aggregate information
        if self.metadata:
            self.metadata.aggregate_id = integration_id
            self.metadata.aggregate_type = "Integration"
            self.metadata.user_id = updated_by

    def validate_payload(self) -> None:
        """Validate event payload."""
        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not self.integration_name:
            raise ValidationError("integration_name is required")

        if not self.updated_by:
            raise ValidationError("updated_by is required")

        if not isinstance(self.changes, dict):
            raise ValidationError("changes must be a dictionary")

        if not isinstance(self.previous_values, dict):
            raise ValidationError("previous_values must be a dictionary")

        if not self.changes:
            raise ValidationError("changes cannot be empty")
