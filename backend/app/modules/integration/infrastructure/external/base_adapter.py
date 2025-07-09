"""
Base channel adapter interface for Integration module.

This module provides base classes for external channel adapters without
dependencies on other modules' domain objects.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, List
from enum import Enum
from uuid import UUID


class DeliveryStatus(str, Enum):
    """Delivery status for notifications."""
    
    PENDING = "PENDING"
    SENDING = "SENDING"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    BOUNCED = "BOUNCED"
    RETRYING = "RETRYING"


class ChannelType(str, Enum):
    """Supported channel types."""
    
    EMAIL = "EMAIL"
    SMS = "SMS"
    PUSH = "PUSH"
    IN_APP = "IN_APP"
    WEBHOOK = "WEBHOOK"


@dataclass
class NotificationData:
    """Simple notification data structure for adapters."""
    
    id: UUID
    channel: ChannelType
    recipient: str  # Email, phone, device token, etc.
    subject: Optional[str] = None  # For email
    content: str = ""
    html_content: Optional[str] = None  # For email
    data: Dict[str, Any] = None  # Additional data
    attachments: List[Dict[str, Any]] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.attachments is None:
            self.attachments = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ChannelConfig:
    """Channel configuration."""
    
    channel: ChannelType
    provider: str
    credentials: Dict[str, Any]
    settings: Dict[str, Any]
    rate_limits: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.rate_limits is None:
            self.rate_limits = {}


class ChannelAdapterError(Exception):
    """Base exception for channel adapter errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        is_retryable: bool = True,
        provider_response: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize channel adapter error.

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
    provider_message_id: Optional[str] = None
    provider_status: Optional[str] = None
    delivered_at: Optional[datetime] = None
    cost_amount: Optional[int] = None  # In cents
    cost_currency: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    is_retryable: bool = True


class BaseChannelAdapter(ABC):
    """Base class for notification channel adapters."""

    def __init__(self, config: ChannelConfig):
        """
        Initialize channel adapter.

        Args:
            config: Channel configuration
        """
        self.config = config
        self.channel = config.channel
        self.provider = config.provider
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """
        Validate channel configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        pass

    @abstractmethod
    async def send(self, notification: NotificationData) -> DeliveryResult:
        """
        Send a notification through this channel.

        Args:
            notification: Notification data to send

        Returns:
            Delivery result

        Raises:
            ChannelAdapterError: If delivery fails
        """
        pass

    @abstractmethod
    async def check_status(self, provider_message_id: str) -> Optional[DeliveryResult]:
        """
        Check delivery status of a sent notification.

        Args:
            provider_message_id: Provider's message ID

        Returns:
            Updated delivery result if available
        """
        pass

    @abstractmethod
    async def validate_recipient(self, recipient: str) -> bool:
        """
        Validate recipient format for this channel.

        Args:
            recipient: Recipient identifier (email, phone, etc.)

        Returns:
            True if valid, False otherwise
        """
        pass

    async def get_cost_estimate(self, notification: NotificationData) -> Optional[Dict[str, Any]]:
        """
        Get cost estimate for sending notification.

        Args:
            notification: Notification data

        Returns:
            Cost estimate with amount and currency
        """
        # Default implementation - override if provider supports cost estimation
        return None

    async def health_check(self) -> bool:
        """
        Check if the adapter is healthy and can send notifications.

        Returns:
            True if healthy, False otherwise
        """
        # Default implementation - override for specific providers
        return True