"""Webhook endpoint repository interface."""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.modules.integration.domain.aggregates import WebhookEndpoint
from app.modules.integration.domain.enums import WebhookStatus


class IWebhookEndpointRepository(ABC):
    """Repository interface for WebhookEndpoint aggregate operations."""

    @abstractmethod
    async def get_by_id(self, endpoint_id: UUID) -> WebhookEndpoint | None:
        """Get a webhook endpoint by its ID.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint

        Returns:
            WebhookEndpoint | None: The webhook endpoint if found, None otherwise
        """

    @abstractmethod
    async def get_by_integration_id(
        self, integration_id: UUID, include_inactive: bool = False
    ) -> list[WebhookEndpoint]:
        """Get all webhook endpoints for an integration.

        Args:
            integration_id: The integration identifier
            include_inactive: Whether to include inactive endpoints

        Returns:
            list[WebhookEndpoint]: List of webhook endpoints
        """

    @abstractmethod
    async def get_by_url(self, tenant_id: UUID, url: str) -> WebhookEndpoint | None:
        """Get a webhook endpoint by its URL.

        Args:
            tenant_id: The tenant identifier
            url: The webhook URL

        Returns:
            WebhookEndpoint | None: The webhook endpoint if found, None otherwise
        """

    @abstractmethod
    async def get_active_endpoints(self, tenant_id: UUID) -> list[WebhookEndpoint]:
        """Get all active webhook endpoints for a tenant.

        Args:
            tenant_id: The tenant identifier

        Returns:
            list[WebhookEndpoint]: List of active webhook endpoints
        """

    @abstractmethod
    async def save(self, endpoint: WebhookEndpoint) -> WebhookEndpoint:
        """Save a webhook endpoint (create or update).

        Args:
            endpoint: The webhook endpoint to save

        Returns:
            WebhookEndpoint: The saved webhook endpoint
        """

    @abstractmethod
    async def delete(self, endpoint_id: UUID) -> bool:
        """Delete a webhook endpoint.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint

        Returns:
            bool: True if deleted successfully, False otherwise
        """

    @abstractmethod
    async def exists(self, endpoint_id: UUID) -> bool:
        """Check if a webhook endpoint exists.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint

        Returns:
            bool: True if exists, False otherwise
        """

    @abstractmethod
    async def update_status(
        self, endpoint_id: UUID, status: WebhookStatus, error_message: str | None = None
    ) -> bool:
        """Update the status of a webhook endpoint.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint
            status: The new status
            error_message: Optional error message if status is error

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def record_event(
        self,
        endpoint_id: UUID,
        event_data: dict[str, Any],
        success: bool,
        response_status: int | None = None,
        error_message: str | None = None,
    ) -> bool:
        """Record a webhook event for an endpoint.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint
            event_data: The event data that was sent
            success: Whether the webhook was delivered successfully
            response_status: The HTTP response status code
            error_message: Optional error message if delivery failed

        Returns:
            bool: True if recorded successfully, False otherwise
        """

    @abstractmethod
    async def get_event_history(
        self, endpoint_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Get event history for a webhook endpoint.

        Args:
            endpoint_id: The unique identifier of the webhook endpoint
            limit: Maximum number of events to return
            offset: Number of events to skip

        Returns:
            list[dict[str, Any]]: List of webhook events
        """

    @abstractmethod
    async def cleanup_old_events(self, days_to_keep: int = 30) -> int:
        """Clean up old webhook events.

        Args:
            days_to_keep: Number of days to keep events

        Returns:
            int: Number of events deleted
        """
