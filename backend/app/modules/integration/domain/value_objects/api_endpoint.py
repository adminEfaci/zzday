"""API endpoint value object for external system connections.

This module provides a comprehensive API endpoint representation with
validation, URL construction, and endpoint management capabilities.
"""

import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class ApiEndpoint(ValueObject):
    """Value object representing an external API endpoint.

    This class encapsulates all information needed to connect to an external
    API endpoint, including base URL, path, headers, and timeout settings.
    """

    def __init__(
        self,
        base_url: str,
        path: str = "",
        headers: dict[str, str] | None = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ):
        """Initialize API endpoint.

        Args:
            base_url: Base URL of the API (e.g., https://api.example.com)
            path: Optional path to append to base URL
            headers: Optional default headers
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates

        Raises:
            ValidationError: If endpoint configuration is invalid
        """
        # Validate and normalize base URL
        self.base_url = self._validate_base_url(base_url)

        # Validate and normalize path
        self.path = self._validate_path(path)

        # Validate headers
        self.headers = self._validate_headers(headers or {})

        # Validate timeout
        if timeout_seconds <= 0 or timeout_seconds > 300:
            raise ValidationError("Timeout must be between 1 and 300 seconds")
        self.timeout_seconds = timeout_seconds

        # Validate retries
        if max_retries < 0 or max_retries > 10:
            raise ValidationError("Max retries must be between 0 and 10")
        self.max_retries = max_retries

        self.verify_ssl = verify_ssl

        # Freeze the object
        self._freeze()

    def _validate_base_url(self, url: str) -> str:
        """Validate and normalize base URL.

        Args:
            url: URL to validate

        Returns:
            str: Normalized URL

        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError("Base URL cannot be empty")

        # Parse URL
        parsed = urlparse(url)

        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            raise ValidationError("URL must use http or https scheme")

        # Validate netloc
        if not parsed.netloc:
            raise ValidationError("URL must include a domain")

        # Validate domain format
        domain_pattern = re.compile(
            r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
        )

        # Extract hostname without port
        hostname = parsed.hostname
        if hostname and not (
            domain_pattern.match(hostname) or self._is_valid_ip(hostname)
        ):
            raise ValidationError(f"Invalid domain: {hostname}")

        # Ensure URL doesn't end with slash
        if url.endswith("/"):
            url = url[:-1]

        return url

    def _is_valid_ip(self, hostname: str) -> bool:
        """Check if hostname is a valid IP address.

        Args:
            hostname: Hostname to check

        Returns:
            bool: True if valid IP address
        """
        # Simple IPv4 validation
        parts = hostname.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        return False

    def _validate_path(self, path: str) -> str:
        """Validate and normalize path.

        Args:
            path: Path to validate

        Returns:
            str: Normalized path
        """
        if not path:
            return ""

        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Remove trailing slash
        if path.endswith("/") and len(path) > 1:
            path = path[:-1]

        # Basic path validation
        if "//" in path:
            raise ValidationError("Path cannot contain double slashes")

        return path

    def _validate_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Validate headers.

        Args:
            headers: Headers to validate

        Returns:
            dict[str, str]: Validated headers

        Raises:
            ValidationError: If headers are invalid
        """
        if not isinstance(headers, dict):
            raise ValidationError("Headers must be a dictionary")

        # Validate header names and values
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValidationError("Header keys and values must be strings")

            # Basic header name validation
            if not re.match(r"^[a-zA-Z0-9\-_]+$", key):
                raise ValidationError(f"Invalid header name: {key}")

        return headers.copy()

    @property
    def full_url(self) -> str:
        """Get the full URL including base and path."""
        if self.path:
            return urljoin(self.base_url + "/", self.path.lstrip("/"))
        return self.base_url

    @property
    def host(self) -> str:
        """Get the hostname from the base URL."""
        parsed = urlparse(self.base_url)
        return parsed.hostname or ""

    @property
    def port(self) -> int | None:
        """Get the port from the base URL."""
        parsed = urlparse(self.base_url)
        return parsed.port

    @property
    def scheme(self) -> str:
        """Get the URL scheme (http/https)."""
        parsed = urlparse(self.base_url)
        return parsed.scheme

    @property
    def is_secure(self) -> bool:
        """Check if the endpoint uses HTTPS."""
        return self.scheme == "https"

    def with_path(self, path: str) -> "ApiEndpoint":
        """Create a new endpoint with a different path.

        Args:
            path: New path

        Returns:
            ApiEndpoint: New endpoint instance
        """
        return ApiEndpoint(
            base_url=self.base_url,
            path=path,
            headers=self.headers.copy(),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            verify_ssl=self.verify_ssl,
        )

    def with_headers(self, headers: dict[str, str]) -> "ApiEndpoint":
        """Create a new endpoint with additional headers.

        Args:
            headers: Headers to add/update

        Returns:
            ApiEndpoint: New endpoint instance
        """
        new_headers = self.headers.copy()
        new_headers.update(headers)

        return ApiEndpoint(
            base_url=self.base_url,
            path=self.path,
            headers=new_headers,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            verify_ssl=self.verify_ssl,
        )

    def build_url(self, **params: Any) -> str:
        """Build a URL with query parameters.

        Args:
            **params: Query parameters

        Returns:
            str: Full URL with query parameters
        """
        url = self.full_url

        if params:
            # Build query string
            query_parts = []
            for key, value in params.items():
                if value is not None:
                    if isinstance(value, list | tuple):
                        for v in value:
                            query_parts.append(f"{key}={v}")
                    else:
                        query_parts.append(f"{key}={value}")

            if query_parts:
                query_string = "&".join(query_parts)
                url = f"{url}?{query_string}"

        return url

    def __str__(self) -> str:
        """Return string representation of endpoint."""
        return self.full_url

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "base_url": self.base_url,
            "path": self.path,
            "headers": self.headers,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "verify_ssl": self.verify_ssl,
            "full_url": self.full_url,
            "is_secure": self.is_secure,
        }

    @classmethod
    def from_url(cls, url: str, **kwargs) -> "ApiEndpoint":
        """Create endpoint from a full URL.

        Args:
            url: Full URL to parse
            **kwargs: Additional endpoint parameters

        Returns:
            ApiEndpoint: Created endpoint
        """
        parsed = urlparse(url)

        # Reconstruct base URL
        base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # Get path
        path = parsed.path

        return cls(base_url=base_url, path=path, **kwargs)
