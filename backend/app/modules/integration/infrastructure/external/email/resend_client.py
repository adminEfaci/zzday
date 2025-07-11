"""Resend API client with advanced features."""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .resend_types import (
    ResendAnalyticsRequest,
    ResendAnalyticsResponse,
    ResendBatchRequest,
    ResendBatchResponse,
    ResendDomainVerification,
    ResendEmailRequest,
    ResendEmailResponse,
    ResendEmailStatus,
    ResendScheduleRequest,
    ResendScheduleResponse,
    ResendSuppressionEntry,
    ResendTemplateRequest,
    ResendWebhookConfig,
)

logger = logging.getLogger(__name__)


class ResendRateLimitError(Exception):
    """Rate limit exceeded error."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ResendAPIError(Exception):
    """Resend API error."""

    def __init__(
        self,
        message: str,
        status_code: int,
        error_code: str | None = None,
        response_data: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.response_data = response_data


class ResendApiClient:
    """Advanced Resend API client with comprehensive features."""

    BASE_URL = "https://api.resend.com"
    DEFAULT_TIMEOUT = 30.0
    MAX_RETRIES = 3

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        rate_limit_buffer: float = 0.1,  # 10% buffer for rate limits
    ):
        """Initialize Resend API client.

        Args:
            api_key: Resend API key
            base_url: Custom base URL (for testing)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            rate_limit_buffer: Buffer for rate limit calculations (0.0-1.0)
        """
        self.api_key = api_key
        self.base_url = base_url or self.BASE_URL
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_buffer = rate_limit_buffer

        # Rate limiting state
        self._rate_limit_remaining = None
        self._rate_limit_reset = None
        self._last_request_time = None

        # HTTP client
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized."""
        if self._client is None:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "EzzDay-Resend-Client/1.0",
                "Accept": "application/json",
            }

            timeout = httpx.Timeout(
                connect=10.0, read=self.timeout, write=10.0, pool=10.0
            )

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=timeout,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            )

        return self._client

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _wait_for_rate_limit(self):
        """Wait if rate limit requires it."""
        if self._rate_limit_reset and self._rate_limit_remaining is not None:
            if self._rate_limit_remaining <= 1:
                wait_time = self._rate_limit_reset - time.time()
                if wait_time > 0:
                    logger.warning(
                        f"Rate limit reached, waiting {wait_time:.2f} seconds"
                    )
                    await asyncio.sleep(wait_time + 1)  # Add 1 second buffer

    def _update_rate_limit_info(self, response: httpx.Response):
        """Update rate limit information from response headers."""
        remaining = response.headers.get("x-ratelimit-remaining")
        reset = response.headers.get("x-ratelimit-reset")

        if remaining:
            self._rate_limit_remaining = int(remaining)

        if reset:
            self._rate_limit_reset = int(reset)

        self._last_request_time = time.time()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(
            (ResendRateLimitError, httpx.TimeoutException, httpx.ConnectError)
        ),
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make HTTP request with retry logic."""
        await self._wait_for_rate_limit()

        client = await self._ensure_client()

        try:
            if method.upper() == "GET":
                response = await client.get(endpoint, params=params)
            elif method.upper() == "POST":
                response = await client.post(endpoint, json=data, params=params)
            elif method.upper() == "PUT":
                response = await client.put(endpoint, json=data, params=params)
            elif method.upper() == "DELETE":
                response = await client.delete(endpoint, params=params)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._update_rate_limit_info(response)

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("retry-after", 60))
                raise ResendRateLimitError(
                    "Rate limit exceeded", retry_after=retry_after
                )

            return response

        except httpx.TimeoutException as e:
            logger.warning(f"Request timeout for {method} {endpoint}: {e}")
            raise
        except httpx.ConnectError as e:
            logger.warning(f"Connection error for {method} {endpoint}: {e}")
            raise

    async def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle API response and errors."""
        try:
            response_data = response.json()
        except json.JSONDecodeError:
            response_data = {"message": response.text or "Unknown error"}

        if response.is_success:
            return response_data

        # Handle API errors
        error_message = response_data.get("message", "Unknown API error")
        error_code = response_data.get("type", "unknown")

        logger.error(
            f"Resend API error {response.status_code}: {error_message}",
            extra={
                "status_code": response.status_code,
                "error_code": error_code,
                "response": response_data,
            },
        )

        raise ResendAPIError(
            message=error_message,
            status_code=response.status_code,
            error_code=error_code,
            response_data=response_data,
        )

    # Email Operations

    async def send_email(
        self, email_request: ResendEmailRequest
    ) -> ResendEmailResponse:
        """Send a single email."""
        response = await self._make_request("POST", "/emails", email_request.to_dict())
        data = await self._handle_response(response)
        return ResendEmailResponse.from_dict(data)

    async def get_email(self, email_id: str) -> ResendEmailStatus:
        """Get email status by ID."""
        response = await self._make_request("GET", f"/emails/{email_id}")
        data = await self._handle_response(response)
        return ResendEmailStatus.from_dict(data)

    async def send_batch(
        self, batch_request: ResendBatchRequest
    ) -> ResendBatchResponse:
        """Send multiple emails in a batch."""
        response = await self._make_request(
            "POST", "/emails/batch", batch_request.to_dict()
        )
        data = await self._handle_response(response)
        return ResendBatchResponse.from_dict(data)

    # Template Operations

    async def send_template_email(
        self,
        template_id: str,
        to: list[str],
        variables: dict[str, Any],
        from_email: str,
        subject: str | None = None,
    ) -> ResendEmailResponse:
        """Send email using a template."""
        template_request = ResendTemplateRequest(
            template_id=template_id,
            to=to,
            variables=variables,
            from_email=from_email,
            subject=subject,
        )

        response = await self._make_request(
            "POST", "/emails/template", template_request.to_dict()
        )
        data = await self._handle_response(response)
        return ResendEmailResponse.from_dict(data)

    # Scheduling Operations

    async def schedule_email(
        self, email_request: ResendEmailRequest, send_at: datetime
    ) -> ResendScheduleResponse:
        """Schedule an email for future delivery."""
        schedule_request = ResendScheduleRequest(email=email_request, send_at=send_at)

        response = await self._make_request(
            "POST", "/emails/schedule", schedule_request.to_dict()
        )
        data = await self._handle_response(response)
        return ResendScheduleResponse.from_dict(data)

    async def cancel_scheduled_email(self, schedule_id: str) -> bool:
        """Cancel a scheduled email."""
        response = await self._make_request("DELETE", f"/emails/schedule/{schedule_id}")
        await self._handle_response(response)
        return True

    async def get_scheduled_emails(self) -> list[ResendScheduleResponse]:
        """Get all scheduled emails."""
        response = await self._make_request("GET", "/emails/schedule")
        data = await self._handle_response(response)

        return [ResendScheduleResponse.from_dict(item) for item in data.get("data", [])]

    # Suppression Management

    async def add_suppression(
        self, email: str, reason: str = "user_request"
    ) -> ResendSuppressionEntry:
        """Add email to suppression list."""
        suppression_data = {
            "email": email,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
        }

        response = await self._make_request("POST", "/suppressions", suppression_data)
        data = await self._handle_response(response)
        return ResendSuppressionEntry.from_dict(data)

    async def remove_suppression(self, email: str) -> bool:
        """Remove email from suppression list."""
        response = await self._make_request("DELETE", f"/suppressions/{email}")
        await self._handle_response(response)
        return True

    async def get_suppressions(self) -> list[ResendSuppressionEntry]:
        """Get suppression list."""
        response = await self._make_request("GET", "/suppressions")
        data = await self._handle_response(response)

        return [ResendSuppressionEntry.from_dict(item) for item in data.get("data", [])]

    # Analytics Operations

    async def get_analytics(
        self, start_date: datetime, end_date: datetime, events: list[str] | None = None
    ) -> ResendAnalyticsResponse:
        """Get email analytics for a date range."""
        analytics_request = ResendAnalyticsRequest(
            start_date=start_date,
            end_date=end_date,
            events=events
            or ["sent", "delivered", "opened", "clicked", "bounced", "complained"],
        )

        params = analytics_request.to_params()
        response = await self._make_request("GET", "/analytics", params=params)
        data = await self._handle_response(response)
        return ResendAnalyticsResponse.from_dict(data)

    # Domain Management

    async def verify_domain(self, domain: str) -> ResendDomainVerification:
        """Verify domain for sending."""
        domain_data = {"domain": domain}
        response = await self._make_request("POST", "/domains/verify", domain_data)
        data = await self._handle_response(response)
        return ResendDomainVerification.from_dict(data)

    async def get_domain_status(self, domain: str) -> ResendDomainVerification:
        """Get domain verification status."""
        response = await self._make_request("GET", f"/domains/{domain}")
        data = await self._handle_response(response)
        return ResendDomainVerification.from_dict(data)

    # Webhook Management

    async def create_webhook(
        self, endpoint: str, events: list[str], secret: str | None = None
    ) -> ResendWebhookConfig:
        """Create a webhook endpoint."""
        webhook_data = {"endpoint": endpoint, "events": events, "secret": secret}

        response = await self._make_request("POST", "/webhooks", webhook_data)
        data = await self._handle_response(response)
        return ResendWebhookConfig.from_dict(data)

    async def get_webhooks(self) -> list[ResendWebhookConfig]:
        """Get all webhook configurations."""
        response = await self._make_request("GET", "/webhooks")
        data = await self._handle_response(response)

        return [ResendWebhookConfig.from_dict(item) for item in data.get("data", [])]

    async def update_webhook(
        self,
        webhook_id: str,
        endpoint: str | None = None,
        events: list[str] | None = None,
        secret: str | None = None,
    ) -> ResendWebhookConfig:
        """Update webhook configuration."""
        webhook_data = {}
        if endpoint:
            webhook_data["endpoint"] = endpoint
        if events:
            webhook_data["events"] = events
        if secret:
            webhook_data["secret"] = secret

        response = await self._make_request(
            "PUT", f"/webhooks/{webhook_id}", webhook_data
        )
        data = await self._handle_response(response)
        return ResendWebhookConfig.from_dict(data)

    async def delete_webhook(self, webhook_id: str) -> bool:
        """Delete webhook configuration."""
        response = await self._make_request("DELETE", f"/webhooks/{webhook_id}")
        await self._handle_response(response)
        return True

    # Health Check

    async def health_check(self) -> dict[str, Any]:
        """Check API health status."""
        try:
            response = await self._make_request("GET", "/health")
            return await self._handle_response(response)
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
