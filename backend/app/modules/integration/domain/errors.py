"""Integration domain errors following pure Python principles.

This module provides comprehensive error types for the Integration domain,
with clear error messages, recovery hints, and proper error categorization.
"""

from typing import Any
from uuid import UUID

from app.core.errors import DomainError


class IntegrationError(DomainError):
    """Base error for integration domain."""

    default_code = "INTEGRATION_ERROR"


class IntegrationNotFoundError(IntegrationError):
    """Raised when an integration cannot be found."""

    default_code = "INTEGRATION_NOT_FOUND"

    def __init__(self, integration_id: UUID, message: str | None = None, **kwargs):
        """Initialize integration not found error.

        Args:
            integration_id: ID of the integration that was not found
            message: Optional custom error message
            **kwargs: Additional error context
        """
        if not message:
            message = f"Integration with ID {integration_id} not found"

        super().__init__(
            message=message,
            user_message="The requested integration was not found",
            recovery_hint="Please check the integration ID and try again",
            **kwargs,
        )
        self.integration_id = integration_id
        self.details["integration_id"] = str(integration_id)


class ConnectionFailedError(IntegrationError):
    """Raised when connection to external system fails."""

    default_code = "CONNECTION_FAILED"
    retryable = True

    def __init__(
        self,
        system_name: str,
        reason: str,
        endpoint: str | None = None,
        status_code: int | None = None,
        **kwargs,
    ):
        """Initialize connection failed error.

        Args:
            system_name: Name of the external system
            reason: Reason for connection failure
            endpoint: Optional endpoint that failed
            status_code: Optional HTTP status code
            **kwargs: Additional error context
        """
        message = f"Failed to connect to {system_name}: {reason}"

        super().__init__(
            message=message,
            user_message=f"Unable to connect to {system_name}",
            recovery_hint="Please check your connection settings and try again",
            **kwargs,
        )

        self.system_name = system_name
        self.reason = reason
        self.endpoint = endpoint
        self.status_code = status_code

        self.details.update(
            {
                "system_name": system_name,
                "reason": reason,
                "endpoint": endpoint,
                "status_code": status_code,
            }
        )


class AuthenticationError(IntegrationError):
    """Raised when authentication with external system fails."""

    default_code = "AUTHENTICATION_ERROR"

    def __init__(
        self, system_name: str, auth_type: str, reason: str | None = None, **kwargs
    ):
        """Initialize authentication error.

        Args:
            system_name: Name of the external system
            auth_type: Type of authentication that failed
            reason: Optional specific reason for failure
            **kwargs: Additional error context
        """
        message = f"Authentication failed for {system_name} using {auth_type}"
        if reason:
            message += f": {reason}"

        super().__init__(
            message=message,
            user_message=f"Unable to authenticate with {system_name}",
            recovery_hint="Please check your credentials and authentication settings",
            **kwargs,
        )

        self.system_name = system_name
        self.auth_type = auth_type
        self.reason = reason

        self.details.update(
            {"system_name": system_name, "auth_type": auth_type, "reason": reason}
        )


class WebhookValidationError(IntegrationError):
    """Raised when webhook validation fails."""

    default_code = "WEBHOOK_VALIDATION_ERROR"

    def __init__(
        self,
        webhook_id: UUID | None = None,
        reason: str = "Invalid webhook signature",
        expected_signature: str | None = None,
        received_signature: str | None = None,
        **kwargs,
    ):
        """Initialize webhook validation error.

        Args:
            webhook_id: Optional webhook event ID
            reason: Reason for validation failure
            expected_signature: Expected signature (sanitized)
            received_signature: Received signature (sanitized)
            **kwargs: Additional error context
        """
        message = f"Webhook validation failed: {reason}"

        super().__init__(
            message=message,
            user_message="Invalid webhook request",
            recovery_hint="Please verify the webhook configuration and signature",
            **kwargs,
        )

        self.webhook_id = webhook_id
        self.reason = reason

        self.details.update(
            {
                "webhook_id": str(webhook_id) if webhook_id else None,
                "reason": reason,
                # Only include sanitized signature info for debugging
                "signature_mismatch": expected_signature is not None
                and received_signature is not None,
            }
        )


class SyncConflictError(IntegrationError):
    """Raised when data synchronization encounters conflicts."""

    default_code = "SYNC_CONFLICT"

    def __init__(
        self,
        sync_job_id: UUID,
        resource_type: str,
        resource_id: str,
        conflict_type: str,
        local_value: Any | None = None,
        remote_value: Any | None = None,
        **kwargs,
    ):
        """Initialize sync conflict error.

        Args:
            sync_job_id: ID of the sync job
            resource_type: Type of resource with conflict
            resource_id: ID of the conflicting resource
            conflict_type: Type of conflict (e.g., "version_mismatch", "duplicate_key")
            local_value: Local value (sanitized)
            remote_value: Remote value (sanitized)
            **kwargs: Additional error context
        """
        message = f"Sync conflict for {resource_type} {resource_id}: {conflict_type}"

        super().__init__(
            message=message,
            user_message="Data conflict detected during synchronization",
            recovery_hint="Please resolve the conflict and retry synchronization",
            **kwargs,
        )

        self.sync_job_id = sync_job_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.conflict_type = conflict_type

        self.details.update(
            {
                "sync_job_id": str(sync_job_id),
                "resource_type": resource_type,
                "resource_id": resource_id,
                "conflict_type": conflict_type,
                "has_conflict_data": local_value is not None
                or remote_value is not None,
            }
        )


class RateLimitExceededError(IntegrationError):
    """Raised when rate limit is exceeded."""

    default_code = "RATE_LIMIT_EXCEEDED"
    retryable = True

    def __init__(
        self,
        integration_name: str,
        limit: int,
        window_seconds: int,
        retry_after_seconds: int | None = None,
        **kwargs,
    ):
        """Initialize rate limit exceeded error.

        Args:
            integration_name: Name of the integration
            limit: Rate limit that was exceeded
            window_seconds: Time window in seconds
            retry_after_seconds: Optional seconds to wait before retry
            **kwargs: Additional error context
        """
        message = f"Rate limit exceeded for {integration_name}: {limit} requests per {window_seconds}s"

        retry_hint = "Please wait before making more requests"
        if retry_after_seconds:
            retry_hint = f"Please wait {retry_after_seconds} seconds before retrying"

        super().__init__(
            message=message,
            user_message=f"Too many requests to {integration_name}",
            recovery_hint=retry_hint,
            **kwargs,
        )

        self.integration_name = integration_name
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after_seconds = retry_after_seconds

        self.details.update(
            {
                "integration_name": integration_name,
                "limit": limit,
                "window_seconds": window_seconds,
                "retry_after_seconds": retry_after_seconds,
            }
        )


class IntegrationConfigurationError(IntegrationError):
    """Raised when integration configuration is invalid."""

    default_code = "INTEGRATION_CONFIGURATION_ERROR"

    def __init__(self, integration_name: str, config_field: str, reason: str, **kwargs):
        """Initialize integration configuration error.

        Args:
            integration_name: Name of the integration
            config_field: Configuration field with error
            reason: Reason for configuration error
            **kwargs: Additional error context
        """
        message = (
            f"Invalid configuration for {integration_name}.{config_field}: {reason}"
        )

        super().__init__(
            message=message,
            user_message="Integration configuration error",
            recovery_hint=f"Please check the {config_field} configuration",
            **kwargs,
        )

        self.integration_name = integration_name
        self.config_field = config_field
        self.reason = reason

        self.details.update(
            {
                "integration_name": integration_name,
                "config_field": config_field,
                "reason": reason,
            }
        )


class WebhookEndpointError(IntegrationError):
    """Raised when webhook endpoint operations fail."""

    default_code = "WEBHOOK_ENDPOINT_ERROR"

    def __init__(self, endpoint_id: UUID, operation: str, reason: str, **kwargs):
        """Initialize webhook endpoint error.

        Args:
            endpoint_id: ID of the webhook endpoint
            operation: Operation that failed
            reason: Reason for failure
            **kwargs: Additional error context
        """
        message = f"Webhook endpoint {operation} failed: {reason}"

        super().__init__(
            message=message,
            user_message="Webhook operation failed",
            recovery_hint="Please check the webhook endpoint configuration",
            **kwargs,
        )

        self.endpoint_id = endpoint_id
        self.operation = operation
        self.reason = reason

        self.details.update(
            {"endpoint_id": str(endpoint_id), "operation": operation, "reason": reason}
        )


class MappingError(IntegrationError):
    """Raised when field mapping operations fail."""

    default_code = "MAPPING_ERROR"

    def __init__(
        self,
        mapping_id: UUID,
        source_field: str,
        target_field: str,
        reason: str,
        **kwargs,
    ):
        """Initialize mapping error.

        Args:
            mapping_id: ID of the mapping
            source_field: Source field name
            target_field: Target field name
            reason: Reason for mapping failure
            **kwargs: Additional error context
        """
        message = f"Mapping from {source_field} to {target_field} failed: {reason}"

        super().__init__(
            message=message,
            user_message="Data mapping error",
            recovery_hint="Please check the field mapping configuration",
            **kwargs,
        )

        self.mapping_id = mapping_id
        self.source_field = source_field
        self.target_field = target_field
        self.reason = reason

        self.details.update(
            {
                "mapping_id": str(mapping_id),
                "source_field": source_field,
                "target_field": target_field,
                "reason": reason,
            }
        )


class CredentialExpiredError(IntegrationError):
    """Raised when credentials have expired."""

    default_code = "CREDENTIAL_EXPIRED"

    def __init__(
        self,
        credential_id: UUID,
        credential_type: str,
        expired_at: str | None = None,
        **kwargs,
    ):
        """Initialize credential expired error.

        Args:
            credential_id: ID of the expired credential
            credential_type: Type of credential
            expired_at: Optional expiration timestamp
            **kwargs: Additional error context
        """
        message = f"{credential_type} credential has expired"
        if expired_at:
            message += f" at {expired_at}"

        super().__init__(
            message=message,
            user_message="Authentication credentials have expired",
            recovery_hint="Please refresh or update your credentials",
            **kwargs,
        )

        self.credential_id = credential_id
        self.credential_type = credential_type
        self.expired_at = expired_at

        self.details.update(
            {
                "credential_id": str(credential_id),
                "credential_type": credential_type,
                "expired_at": expired_at,
            }
        )


# Export all errors
__all__ = [
    "AuthenticationError",
    "ConnectionFailedError",
    "CredentialExpiredError",
    "IntegrationConfigurationError",
    "IntegrationError",
    "IntegrationNotFoundError",
    "MappingError",
    "RateLimitExceededError",
    "SyncConflictError",
    "WebhookEndpointError",
    "WebhookValidationError",
]
