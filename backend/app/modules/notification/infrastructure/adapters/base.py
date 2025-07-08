"""Base channel adapter interface and utilities."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus
from app.modules.notification.domain.value_objects import ChannelConfig


class ChannelAdapterError(Exception):
    """Base exception for channel adapter errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        is_retryable: bool = True,
        provider_response: dict[str, Any] | None = None,
    ):
        """Initialize channel adapter error.

        Args:
            message: Error message
            error_code: Provider-specific error code
            is_retryable: Whether the error is retryable
            provider_response: Raw provider response
        """
        super().__init__(message)
        self.error_code = error_code
        self.is_retryable = is_retryable
        self.provider_response = provider_response


@dataclass
class DeliveryResult:
    """Result of a notification delivery attempt."""

    status: DeliveryStatus
    provider_message_id: str | None = None
    provider_status: str | None = None
    delivered_at: datetime | None = None
    cost_amount: int | None = None  # In cents
    cost_currency: str | None = None
    response_data: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    is_retryable: bool = True


class BaseChannelAdapter(ABC):
    """Base class for notification channel adapters."""

    def __init__(self, config: ChannelConfig):
        """Initialize channel adapter.

        Args:
            config: Channel configuration
        """
        self.config = config
        self.channel = config.channel
        self.provider = config.provider
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate channel configuration.

        Raises:
            ValueError: If configuration is invalid
        """

    @abstractmethod
    async def send(self, notification: Notification) -> DeliveryResult:
        """Send a notification through this channel.

        Args:
            notification: Notification to send

        Returns:
            Delivery result

        Raises:
            ChannelAdapterError: If delivery fails
        """

    @abstractmethod
    async def check_status(self, provider_message_id: str) -> DeliveryResult | None:
        """Check delivery status of a sent notification.

        Args:
            provider_message_id: Provider's message ID

        Returns:
            Updated delivery result if available
        """

    @abstractmethod
    async def validate_address(self, address: str) -> bool:
        """Validate a recipient address for this channel.

        Args:
            address: Address to validate

        Returns:
            True if address is valid
        """

    async def handle_webhook(
        self, webhook_data: dict[str, Any]
    ) -> DeliveryResult | None:
        """Handle webhook callback from provider.

        Args:
            webhook_data: Webhook payload

        Returns:
            Updated delivery result if applicable
        """
        # Default implementation - can be overridden
        return None

    async def get_quota_info(self) -> dict[str, Any]:
        """Get current quota/limit information.

        Returns:
            Dictionary with quota information
        """
        # Default implementation
        return {
            "provider": self.provider,
            "channel": self.channel.value,
            "quota_available": True,
            "rate_limits": self.config.rate_limits,
        }

    def _sanitize_error_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Sanitize provider response to remove sensitive data.

        Args:
            response: Raw provider response

        Returns:
            Sanitized response
        """
        # Remove common sensitive fields
        sensitive_fields = [
            "api_key",
            "secret",
            "token",
            "password",
            "authorization",
            "x-api-key",
            "bearer",
        ]

        sanitized = response.copy()
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = "[REDACTED]"
            # Also check nested fields
            for key in list(sanitized.keys()):
                if isinstance(sanitized[key], dict):
                    sanitized[key] = self._sanitize_error_response(sanitized[key])

        return sanitized

    def _log_delivery_attempt(
        self, notification: Notification, result: DeliveryResult
    ) -> None:
        """Log delivery attempt for monitoring.

        Args:
            notification: Notification being sent
            result: Delivery result
        """
        # This would typically integrate with logging/monitoring
        {
            "notification_id": str(notification.id),
            "channel": self.channel.value,
            "provider": self.provider,
            "status": result.status.value,
            "provider_message_id": result.provider_message_id,
            "error_code": result.error_code,
            "timestamp": datetime.utcnow().isoformat(),
        }
        # TODO: Implement actual logging
