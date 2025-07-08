"""REST API client with retry and circuit breaker support.

This module provides a robust REST API client with connection pooling,
automatic retries, circuit breaker pattern, and comprehensive error handling.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import aiohttp
import backoff
from aiohttp import ClientError, ClientSession, ClientTimeout
from circuit_breaker import CircuitBreaker

from app.core.errors import IntegrationError
from app.modules.integration.domain.value_objects import AuthMethod, RateLimitConfig
from app.modules.integration.infrastructure.services import RateLimiterService

logger = logging.getLogger(__name__)


class RestApiClientError(IntegrationError):
    """REST API client specific errors."""


class RestApiClient:
    """REST API client with advanced features for external integrations."""

    def __init__(
        self,
        base_url: str,
        auth_method: AuthMethod | None = None,
        rate_limit: RateLimitConfig | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 60,
        pool_size: int = 10,
        pool_limit: int = 100,
    ):
        """Initialize REST API client.

        Args:
            base_url: Base URL for API
            auth_method: Authentication method
            rate_limit: Rate limiting configuration
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            circuit_breaker_threshold: Failures before circuit opens
            circuit_breaker_timeout: Circuit breaker timeout in seconds
            pool_size: Connection pool size
            pool_limit: Maximum connections in pool
        """
        self.base_url = base_url.rstrip("/")
        self.auth_method = auth_method
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries

        # Initialize rate limiter
        self.rate_limiter = None
        if rate_limit:
            self.rate_limiter = RateLimiterService(
                strategy=rate_limit.strategy,
                requests_per_window=rate_limit.requests_per_window,
                window_seconds=rate_limit.window_seconds,
            )

        # Initialize circuit breaker
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold,
            recovery_timeout=circuit_breaker_timeout,
            expected_exception=ClientError,
        )

        # Connection pool configuration
        self.connector = aiohttp.TCPConnector(
            limit=pool_limit, limit_per_host=pool_size, ttl_dns_cache=300
        )

        # Session will be created on first use
        self._session: ClientSession | None = None

        # Metrics
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retried_requests": 0,
            "circuit_breaker_opens": 0,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _ensure_session(self) -> None:
        """Ensure HTTP session is created."""
        if not self._session or self._session.closed:
            headers = {}
            if self.auth_method:
                headers.update(self.auth_method.get_auth_header())

            self._session = ClientSession(
                connector=self.connector, timeout=self.timeout, headers=headers
            )

    async def close(self) -> None:
        """Close HTTP session and cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()
        await self.connector.close()

    def _get_full_url(self, endpoint: str) -> str:
        """Get full URL for endpoint."""
        if endpoint.startswith("http"):
            return endpoint
        return urljoin(self.base_url + "/", endpoint.lstrip("/"))

    async def _check_rate_limit(self) -> None:
        """Check and enforce rate limits."""
        if self.rate_limiter:
            await self.rate_limiter.check_rate_limit(self.base_url)

    @backoff.on_exception(
        backoff.expo, (ClientError, asyncio.TimeoutError), max_tries=3, max_time=60
    )
    async def _make_request(
        self, method: str, url: str, **kwargs
    ) -> aiohttp.ClientResponse:
        """Make HTTP request with retry logic."""
        await self._ensure_session()

        # Apply rate limiting
        await self._check_rate_limit()

        # Update metrics
        self.metrics["total_requests"] += 1

        try:
            # Make request through circuit breaker
            async with self.circuit_breaker:
                async with self._session.request(method, url, **kwargs) as response:
                    # Check for rate limit headers
                    self._handle_rate_limit_headers(response.headers)

                    # Raise for non-success status codes
                    response.raise_for_status()

                    self.metrics["successful_requests"] += 1
                    return response

        except Exception:
            self.metrics["failed_requests"] += 1
            if self.circuit_breaker.current_state == "open":
                self.metrics["circuit_breaker_opens"] += 1
            raise

    def _handle_rate_limit_headers(self, headers: dict[str, str]) -> None:
        """Handle rate limit headers from response."""
        if not self.rate_limiter:
            return

        # Common rate limit headers
        rate_limit_remaining = headers.get("X-RateLimit-Remaining")
        rate_limit_reset = headers.get("X-RateLimit-Reset")

        if rate_limit_remaining and int(rate_limit_remaining) == 0:
            if rate_limit_reset:
                reset_time = datetime.fromtimestamp(int(rate_limit_reset), tz=UTC)
                wait_seconds = (reset_time - datetime.now(UTC)).total_seconds()
                if wait_seconds > 0:
                    logger.warning(
                        f"Rate limit reached, need to wait {wait_seconds} seconds"
                    )

    async def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Additional headers

        Returns:
            Response data as dictionary
        """
        url = self._get_full_url(endpoint)

        try:
            response = await self._make_request(
                "GET", url, params=params, headers=headers
            )

            async with response:
                return await response.json()

        except aiohttp.ClientResponseError as e:
            raise RestApiClientError(
                f"GET request failed: {e.status} {e.message}",
                details={"url": url, "status": e.status},
            )
        except Exception as e:
            raise RestApiClientError(f"GET request error: {e!s}", details={"url": url})

    async def post(
        self,
        endpoint: str,
        data: dict[str, Any] | str | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make POST request.

        Args:
            endpoint: API endpoint
            data: Form data or raw string
            json_data: JSON data
            headers: Additional headers

        Returns:
            Response data as dictionary
        """
        url = self._get_full_url(endpoint)

        kwargs = {}
        if json_data is not None:
            kwargs["json"] = json_data
        elif isinstance(data, dict):
            kwargs["data"] = data
        elif data is not None:
            kwargs["data"] = data
            if headers is None:
                headers = {}
            headers["Content-Type"] = "application/json"

        try:
            response = await self._make_request("POST", url, headers=headers, **kwargs)

            async with response:
                return await response.json()

        except aiohttp.ClientResponseError as e:
            raise RestApiClientError(
                f"POST request failed: {e.status} {e.message}",
                details={"url": url, "status": e.status},
            )
        except Exception as e:
            raise RestApiClientError(f"POST request error: {e!s}", details={"url": url})

    async def put(
        self,
        endpoint: str,
        data: dict[str, Any] | str | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make PUT request."""
        url = self._get_full_url(endpoint)

        kwargs = {}
        if json_data is not None:
            kwargs["json"] = json_data
        elif isinstance(data, dict):
            kwargs["data"] = data
        elif data is not None:
            kwargs["data"] = data
            if headers is None:
                headers = {}
            headers["Content-Type"] = "application/json"

        try:
            response = await self._make_request("PUT", url, headers=headers, **kwargs)

            async with response:
                return await response.json()

        except aiohttp.ClientResponseError as e:
            raise RestApiClientError(
                f"PUT request failed: {e.status} {e.message}",
                details={"url": url, "status": e.status},
            )
        except Exception as e:
            raise RestApiClientError(f"PUT request error: {e!s}", details={"url": url})

    async def patch(
        self,
        endpoint: str,
        data: dict[str, Any] | str | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make PATCH request."""
        url = self._get_full_url(endpoint)

        kwargs = {}
        if json_data is not None:
            kwargs["json"] = json_data
        elif isinstance(data, dict):
            kwargs["data"] = data
        elif data is not None:
            kwargs["data"] = data
            if headers is None:
                headers = {}
            headers["Content-Type"] = "application/json"

        try:
            response = await self._make_request("PATCH", url, headers=headers, **kwargs)

            async with response:
                return await response.json()

        except aiohttp.ClientResponseError as e:
            raise RestApiClientError(
                f"PATCH request failed: {e.status} {e.message}",
                details={"url": url, "status": e.status},
            )
        except Exception as e:
            raise RestApiClientError(
                f"PATCH request error: {e!s}", details={"url": url}
            )

    async def delete(
        self, endpoint: str, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Make DELETE request."""
        url = self._get_full_url(endpoint)

        try:
            response = await self._make_request("DELETE", url, headers=headers)

            async with response:
                if response.content_length:
                    return await response.json()
                return {"success": True}

        except aiohttp.ClientResponseError as e:
            raise RestApiClientError(
                f"DELETE request failed: {e.status} {e.message}",
                details={"url": url, "status": e.status},
            )
        except Exception as e:
            raise RestApiClientError(
                f"DELETE request error: {e!s}", details={"url": url}
            )

    async def paginate(
        self,
        endpoint: str,
        page_param: str = "page",
        per_page_param: str = "per_page",
        per_page: int = 100,
        max_pages: int | None = None,
        data_key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Paginate through API results.

        Args:
            endpoint: API endpoint
            page_param: Page parameter name
            per_page_param: Per page parameter name
            per_page: Results per page
            max_pages: Maximum pages to fetch
            data_key: Key containing data in response
            headers: Additional headers

        Returns:
            Combined list of all results
        """
        all_results = []
        page = 1

        while True:
            params = {page_param: page, per_page_param: per_page}

            response = await self.get(endpoint, params=params, headers=headers)

            # Extract data
            if data_key:
                data = response.get(data_key, [])
            else:
                data = response if isinstance(response, list) else [response]

            if not data:
                break

            all_results.extend(data)

            # Check if we've reached max pages
            if max_pages and page >= max_pages:
                break

            # Check if there are more pages
            if len(data) < per_page:
                break

            page += 1

        return all_results

    async def batch_request(
        self, requests: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Execute multiple requests in parallel.

        Args:
            requests: List of request configurations with:
                - method: HTTP method
                - endpoint: API endpoint
                - data: Request data (optional)
                - headers: Additional headers (optional)

        Returns:
            List of responses in same order as requests
        """
        tasks = []

        for req in requests:
            method = req.get("method", "GET").upper()
            endpoint = req["endpoint"]
            data = req.get("data")
            headers = req.get("headers")

            if method == "GET":
                task = self.get(endpoint, params=data, headers=headers)
            elif method == "POST":
                task = self.post(endpoint, json_data=data, headers=headers)
            elif method == "PUT":
                task = self.put(endpoint, json_data=data, headers=headers)
            elif method == "PATCH":
                task = self.patch(endpoint, json_data=data, headers=headers)
            elif method == "DELETE":
                task = self.delete(endpoint, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")

            tasks.append(task)

        return await asyncio.gather(*tasks, return_exceptions=True)

    def get_metrics(self) -> dict[str, Any]:
        """Get client metrics."""
        return {
            **self.metrics,
            "circuit_breaker_state": self.circuit_breaker.current_state,
            "success_rate": (
                self.metrics["successful_requests"] / self.metrics["total_requests"]
                if self.metrics["total_requests"] > 0
                else 0
            ),
        }
