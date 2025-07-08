"""Webhook signature value object for secure webhook validation.

This module provides comprehensive webhook signature validation with
support for various signing algorithms and security best practices.
"""

import base64
import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class WebhookSignature(ValueObject):
    """Value object representing webhook signature configuration and validation.

    This class encapsulates webhook signature verification logic,
    supporting multiple signing algorithms and security measures.
    """

    SUPPORTED_ALGORITHMS = {
        "hmac-sha256": hashlib.sha256,
        "hmac-sha1": hashlib.sha1,
        "hmac-sha512": hashlib.sha512,
        "hmac-md5": hashlib.md5,  # Deprecated but still used by some services
    }

    def __init__(
        self,
        algorithm: str,
        secret: str,
        header_name: str = "X-Webhook-Signature",
        timestamp_header: str | None = None,
        timestamp_tolerance_seconds: int = 300,
        include_timestamp: bool = False,
        encoding: str = "hex",
        prefix: str | None = None,
    ):
        """Initialize webhook signature configuration.

        Args:
            algorithm: Signing algorithm (e.g., 'hmac-sha256')
            secret: Secret key for signing
            header_name: Header name containing signature
            timestamp_header: Optional header name for timestamp
            timestamp_tolerance_seconds: Max age for timestamp validation
            include_timestamp: Whether timestamp is included in signature
            encoding: Signature encoding ('hex', 'base64')
            prefix: Optional prefix for signature value (e.g., 'sha256=')

        Raises:
            ValidationError: If configuration is invalid
        """
        # Validate algorithm
        algorithm_lower = algorithm.lower()
        if algorithm_lower not in self.SUPPORTED_ALGORITHMS:
            supported = ", ".join(self.SUPPORTED_ALGORITHMS.keys())
            raise ValidationError(
                f"Unsupported algorithm: {algorithm}. Supported: {supported}"
            )
        self.algorithm = algorithm_lower

        # Validate secret
        if not secret:
            raise ValidationError("Secret cannot be empty")
        if len(secret) < 16:
            raise ValidationError(
                "Secret should be at least 16 characters for security"
            )
        self.secret = secret

        # Validate header name
        if not header_name:
            raise ValidationError("Header name cannot be empty")
        self.header_name = header_name

        # Validate timestamp configuration
        self.timestamp_header = timestamp_header
        if timestamp_tolerance_seconds <= 0:
            raise ValidationError("Timestamp tolerance must be positive")
        if timestamp_tolerance_seconds > 3600:  # 1 hour
            raise ValidationError("Timestamp tolerance should not exceed 1 hour")
        self.timestamp_tolerance_seconds = timestamp_tolerance_seconds
        self.include_timestamp = include_timestamp

        # Validate encoding
        if encoding not in ("hex", "base64"):
            raise ValidationError("Encoding must be 'hex' or 'base64'")
        self.encoding = encoding

        # Store prefix
        self.prefix = prefix

        # Freeze the object
        self._freeze()

    def compute_signature(
        self,
        payload: bytes,
        timestamp: datetime | None = None,
        additional_headers: dict[str, str] | None = None,
    ) -> str:
        """Compute signature for payload.

        Args:
            payload: Request payload bytes
            timestamp: Optional timestamp to include
            additional_headers: Optional headers to include in signature

        Returns:
            str: Computed signature
        """
        # Get hash function
        hash_func = self.SUPPORTED_ALGORITHMS[self.algorithm]

        # Build data to sign
        data_parts = []

        # Add timestamp if required
        if self.include_timestamp and timestamp:
            timestamp_str = str(int(timestamp.timestamp()))
            data_parts.append(timestamp_str.encode("utf-8"))

        # Add payload
        data_parts.append(payload)

        # Add additional headers if specified
        if additional_headers:
            # Sort headers for consistent ordering
            for key in sorted(additional_headers.keys()):
                value = additional_headers[key]
                data_parts.append(f"{key}:{value}".encode())

        # Combine all parts
        data_to_sign = b".".join(data_parts)

        # Compute HMAC
        h = hmac.new(self.secret.encode("utf-8"), data_to_sign, hash_func)

        # Encode signature
        if self.encoding == "hex":
            signature = h.hexdigest()
        else:  # base64
            signature = base64.b64encode(h.digest()).decode("utf-8")

        # Add prefix if specified
        if self.prefix:
            signature = f"{self.prefix}{signature}"

        return signature

    def validate_signature(
        self,
        payload: bytes,
        received_signature: str,
        headers: dict[str, str],
        current_time: datetime | None = None,
    ) -> bool:
        """Validate webhook signature.

        Args:
            payload: Request payload bytes
            received_signature: Signature from request header
            headers: Request headers
            current_time: Optional current time for testing

        Returns:
            bool: True if signature is valid

        Raises:
            ValidationError: If validation configuration is invalid
        """
        if not received_signature:
            return False

        # Remove prefix if present
        if self.prefix and received_signature.startswith(self.prefix):
            received_signature = received_signature[len(self.prefix) :]

        # Validate timestamp if required
        timestamp = None
        if self.timestamp_header:
            timestamp_str = headers.get(self.timestamp_header)
            if not timestamp_str:
                return False

            try:
                timestamp = datetime.fromtimestamp(int(timestamp_str), tz=UTC)
            except (ValueError, TypeError):
                return False

            # Check timestamp age
            current = current_time or datetime.now(UTC)
            age = abs((current - timestamp).total_seconds())
            if age > self.timestamp_tolerance_seconds:
                return False

        # Extract additional headers for signature if needed
        additional_headers = None
        if self.include_timestamp and timestamp:
            # Timestamp will be included in signature computation
            pass

        # Compute expected signature
        expected_signature = self.compute_signature(
            payload,
            timestamp=timestamp if self.include_timestamp else None,
            additional_headers=additional_headers,
        )

        # Remove prefix from expected signature for comparison
        if self.prefix and expected_signature.startswith(self.prefix):
            expected_signature = expected_signature[len(self.prefix) :]

        # Constant-time comparison
        return hmac.compare_digest(expected_signature, received_signature)

    def extract_signature_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Extract signature-related headers.

        Args:
            headers: Request headers

        Returns:
            dict[str, str]: Signature-related headers
        """
        sig_headers = {}

        # Get signature header
        if self.header_name in headers:
            sig_headers[self.header_name] = headers[self.header_name]

        # Get timestamp header if configured
        if self.timestamp_header and self.timestamp_header in headers:
            sig_headers[self.timestamp_header] = headers[self.timestamp_header]

        return sig_headers

    def generate_test_signature(self, payload: str) -> dict[str, str]:
        """Generate test signature and headers for testing.

        Args:
            payload: Test payload string

        Returns:
            dict[str, str]: Headers with signature
        """
        payload_bytes = payload.encode("utf-8")
        timestamp = datetime.now(UTC)

        headers = {}

        # Add timestamp header if configured
        if self.timestamp_header:
            headers[self.timestamp_header] = str(int(timestamp.timestamp()))

        # Compute signature
        signature = self.compute_signature(
            payload_bytes, timestamp=timestamp if self.include_timestamp else None
        )

        headers[self.header_name] = signature

        return headers

    @property
    def is_timestamp_required(self) -> bool:
        """Check if timestamp validation is required."""
        return bool(self.timestamp_header) or self.include_timestamp

    @property
    def algorithm_name(self) -> str:
        """Get human-readable algorithm name."""
        return self.algorithm.upper().replace("-", " ")

    def __str__(self) -> str:
        """Return string representation of webhook signature."""
        return f"{self.algorithm_name} webhook signature"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "algorithm": self.algorithm,
            "header_name": self.header_name,
            "timestamp_header": self.timestamp_header,
            "timestamp_tolerance_seconds": self.timestamp_tolerance_seconds,
            "include_timestamp": self.include_timestamp,
            "encoding": self.encoding,
            "prefix": self.prefix,
            "is_timestamp_required": self.is_timestamp_required,
            "secret_length": len(self.secret),  # Don't expose actual secret
        }

    @classmethod
    def for_github(cls, secret: str) -> "WebhookSignature":
        """Create signature config for GitHub webhooks.

        Args:
            secret: Webhook secret

        Returns:
            WebhookSignature: GitHub-compatible configuration
        """
        return cls(
            algorithm="hmac-sha256",
            secret=secret,
            header_name="X-Hub-Signature-256",
            encoding="hex",
            prefix="sha256=",
        )

    @classmethod
    def for_stripe(cls, secret: str) -> "WebhookSignature":
        """Create signature config for Stripe webhooks.

        Args:
            secret: Webhook secret

        Returns:
            WebhookSignature: Stripe-compatible configuration
        """
        return cls(
            algorithm="hmac-sha256",
            secret=secret,
            header_name="Stripe-Signature",
            timestamp_header="Stripe-Signature",  # Timestamp is in same header
            include_timestamp=True,
            encoding="hex",
            prefix="t=",  # Stripe uses t=timestamp,v1=signature format
        )

    @classmethod
    def for_slack(cls, secret: str) -> "WebhookSignature":
        """Create signature config for Slack webhooks.

        Args:
            secret: Webhook secret

        Returns:
            WebhookSignature: Slack-compatible configuration
        """
        return cls(
            algorithm="hmac-sha256",
            secret=secret,
            header_name="X-Slack-Signature",
            timestamp_header="X-Slack-Request-Timestamp",
            include_timestamp=True,
            encoding="hex",
            prefix="v0=",
        )
