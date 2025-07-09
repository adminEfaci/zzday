"""
Webhook Service Interface

Port for webhook management including registration, validation,
delivery, and retry handling.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.integration.domain.aggregates.webhook_endpoint import WebhookEndpoint
    from app.modules.integration.domain.enums import WebhookStatus, HttpMethod


class IWebhookService(ABC):
    """Port for webhook management operations."""
    
    @abstractmethod
    async def register_webhook(
        self,
        url: str,
        events: list[str],
        secret: str | None = None,
        active: bool = True,
        metadata: dict[str, Any] | None = None
    ) -> "WebhookEndpoint":
        """
        Register a new webhook endpoint.
        
        Args:
            url: Webhook URL
            events: List of events to subscribe to
            secret: Optional secret for signing
            active: Whether webhook is active
            metadata: Optional metadata
            
        Returns:
            Created WebhookEndpoint aggregate
            
        Raises:
            InvalidUrlError: If URL is invalid
            InvalidEventError: If any event is invalid
            DuplicateWebhookError: If URL+events already registered
        """
        ...
    
    @abstractmethod
    async def deliver_webhook(
        self,
        webhook_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None
    ) -> tuple[bool, dict[str, Any]]:
        """
        Deliver a webhook payload.
        
        Args:
            webhook_id: ID of webhook endpoint
            event_type: Type of event
            payload: Event payload
            idempotency_key: Optional key for deduplication
            
        Returns:
            Tuple of (success, response_details)
            
        Raises:
            WebhookNotFoundError: If webhook doesn't exist
            WebhookInactiveError: If webhook is inactive
            EventNotSubscribedError: If event not subscribed
        """
        ...
    
    @abstractmethod
    async def validate_webhook_signature(
        self,
        webhook_id: UUID,
        payload: bytes,
        signature: str,
        timestamp: str | None = None
    ) -> bool:
        """
        Validate webhook signature.
        
        Args:
            webhook_id: ID of webhook
            payload: Request payload
            signature: Signature to validate
            timestamp: Optional timestamp for replay protection
            
        Returns:
            True if signature is valid
        """
        ...
    
    @abstractmethod
    async def generate_webhook_signature(
        self,
        webhook_id: UUID,
        payload: dict[str, Any],
        timestamp: datetime | None = None
    ) -> dict[str, str]:
        """
        Generate webhook signature headers.
        
        Args:
            webhook_id: ID of webhook
            payload: Payload to sign
            timestamp: Optional timestamp
            
        Returns:
            Dictionary of signature headers
        """
        ...
    
    @abstractmethod
    async def retry_failed_webhook(
        self,
        delivery_id: UUID,
        force: bool = False
    ) -> bool:
        """
        Retry a failed webhook delivery.
        
        Args:
            delivery_id: ID of failed delivery
            force: Force retry even if max retries exceeded
            
        Returns:
            True if retry succeeded
            
        Raises:
            DeliveryNotFoundError: If delivery doesn't exist
            MaxRetriesExceededError: If max retries reached
        """
        ...
    
    @abstractmethod
    async def update_webhook_url(
        self,
        webhook_id: UUID,
        new_url: str,
        test_connectivity: bool = True
    ) -> None:
        """
        Update webhook URL.
        
        Args:
            webhook_id: ID of webhook
            new_url: New URL
            test_connectivity: Whether to test new URL
            
        Raises:
            WebhookNotFoundError: If webhook doesn't exist
            InvalidUrlError: If URL is invalid
            ConnectivityTestFailedError: If test fails
        """
        ...
    
    @abstractmethod
    async def pause_webhook(
        self,
        webhook_id: UUID,
        reason: str | None = None,
        until: datetime | None = None
    ) -> None:
        """
        Pause webhook deliveries.
        
        Args:
            webhook_id: ID of webhook
            reason: Optional pause reason
            until: Optional resume time
            
        Raises:
            WebhookNotFoundError: If webhook doesn't exist
            WebhookAlreadyPausedError: If already paused
        """
        ...
    
    @abstractmethod
    async def resume_webhook(
        self,
        webhook_id: UUID
    ) -> None:
        """
        Resume paused webhook.
        
        Args:
            webhook_id: ID of webhook
            
        Raises:
            WebhookNotFoundError: If webhook doesn't exist
            WebhookNotPausedError: If not paused
        """
        ...
    
    @abstractmethod
    async def get_webhook_metrics(
        self,
        webhook_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get delivery metrics for webhook.
        
        Args:
            webhook_id: ID of webhook
            start_date: Optional start date
            end_date: Optional end date
            
        Returns:
            Dictionary of metrics
        """
        ...
    
    @abstractmethod
    async def verify_endpoint_ownership(
        self,
        url: str,
        verification_token: str
    ) -> bool:
        """
        Verify ownership of webhook endpoint.
        
        Args:
            url: Webhook URL to verify
            verification_token: Token to send
            
        Returns:
            True if ownership verified
        """
        ...
    
    @abstractmethod
    async def apply_retry_policy(
        self,
        webhook_id: UUID,
        max_retries: int,
        backoff_strategy: str,
        backoff_params: dict[str, Any] | None = None
    ) -> None:
        """
        Apply retry policy to webhook.
        
        Args:
            webhook_id: ID of webhook
            max_retries: Maximum retry attempts
            backoff_strategy: Strategy (exponential, linear, etc)
            backoff_params: Optional strategy parameters
        """
        ...