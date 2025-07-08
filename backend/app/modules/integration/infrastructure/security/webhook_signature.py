"""Webhook signature validation service.

This module provides signature validation for incoming webhooks
supporting various signature algorithms and encoding methods.
"""

import base64
import hashlib
import hmac
import logging
import time
from typing import Any

from app.core.errors import SecurityError

logger = logging.getLogger(__name__)


class WebhookSignatureValidator:
    """Service for validating webhook signatures."""

    # Supported algorithms
    SUPPORTED_ALGORITHMS = {
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5,  # Not recommended but supported for compatibility
    }

    # Supported encodings
    SUPPORTED_ENCODINGS = ["hex", "base64"]

    def __init__(self, tolerance_seconds: int = 300, strict_mode: bool = True):
        """Initialize signature validator.

        Args:
            tolerance_seconds: Timestamp tolerance in seconds
            strict_mode: Enforce strict validation rules
        """
        self.tolerance_seconds = tolerance_seconds
        self.strict_mode = strict_mode

    def validate(
        self,
        secret: str,
        signature: str,
        payload: str | bytes,
        algorithm: str = "sha256",
        encoding: str = "hex",
        timestamp: int | None = None,
        include_timestamp: bool = False,
    ) -> bool:
        """Validate webhook signature.

        Args:
            secret: Webhook secret key
            signature: Signature to validate
            payload: Request payload
            algorithm: Hash algorithm
            encoding: Signature encoding
            timestamp: Optional timestamp for replay protection
            include_timestamp: Include timestamp in signature

        Returns:
            True if signature is valid

        Raises:
            SecurityError: If validation configuration is invalid
        """
        try:
            # Validate algorithm
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                if self.strict_mode:
                    raise SecurityError(f"Unsupported algorithm: {algorithm}")
                logger.warning(f"Unsupported algorithm: {algorithm}")
                return False

            # Validate encoding
            if encoding not in self.SUPPORTED_ENCODINGS:
                if self.strict_mode:
                    raise SecurityError(f"Unsupported encoding: {encoding}")
                logger.warning(f"Unsupported encoding: {encoding}")
                return False

            # Check timestamp if provided
            if timestamp and include_timestamp:
                current_time = int(time.time())
                if abs(current_time - timestamp) > self.tolerance_seconds:
                    logger.warning("Timestamp outside tolerance window")
                    return False

            # Prepare payload
            if isinstance(payload, str):
                payload = payload.encode("utf-8")

            # Include timestamp in payload if required
            if include_timestamp and timestamp:
                payload = f"{timestamp}.".encode() + payload

            # Calculate expected signature
            expected = self.generate_signature(secret, payload, algorithm, encoding)

            # Compare signatures
            return self._secure_compare(signature, expected)

        except Exception as e:
            logger.exception(f"Signature validation error: {e}")
            if self.strict_mode:
                raise
            return False

    def generate_signature(
        self,
        secret: str,
        payload: str | bytes,
        algorithm: str = "sha256",
        encoding: str = "hex",
    ) -> str:
        """Generate webhook signature.

        Args:
            secret: Webhook secret key
            payload: Request payload
            algorithm: Hash algorithm
            encoding: Signature encoding

        Returns:
            Generated signature
        """
        # Get hash function
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm]

        # Prepare payload
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        # Prepare secret
        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        # Calculate HMAC
        mac = hmac.new(secret, payload, hash_func)

        # Encode result
        if encoding == "hex":
            return mac.hexdigest()
        if encoding == "base64":
            return base64.b64encode(mac.digest()).decode()
        raise ValueError(f"Unsupported encoding: {encoding}")

    def validate_github_signature(
        self, secret: str, signature: str, payload: str | bytes
    ) -> bool:
        """Validate GitHub webhook signature.

        GitHub uses HMAC-SHA256 with hex encoding and 'sha256=' prefix.

        Args:
            secret: Webhook secret
            signature: GitHub signature header value
            payload: Request body

        Returns:
            True if valid
        """
        if not signature.startswith("sha256="):
            return False

        expected_signature = signature.split("=", 1)[1]
        return self.validate(
            secret, expected_signature, payload, algorithm="sha256", encoding="hex"
        )

    def validate_stripe_signature(
        self, secret: str, signature: str, payload: str | bytes, timestamp: int
    ) -> bool:
        """Validate Stripe webhook signature.

        Stripe uses HMAC-SHA256 with timestamp validation.

        Args:
            secret: Webhook secret
            signature: Stripe signature
            payload: Request body
            timestamp: Request timestamp

        Returns:
            True if valid
        """
        # Stripe includes timestamp in signed payload
        signed_payload = f"{timestamp}.{payload}"

        # Extract signature from header (format: t=timestamp,v1=signature)
        for item in signature.split(","):
            if item.startswith("v1="):
                expected_signature = item.split("=", 1)[1]
                break
        else:
            return False

        return self.validate(
            secret,
            expected_signature,
            signed_payload,
            algorithm="sha256",
            encoding="hex",
        )

    def validate_slack_signature(
        self, secret: str, signature: str, payload: str | bytes, timestamp: str
    ) -> bool:
        """Validate Slack webhook signature.

        Slack uses HMAC-SHA256 with version prefix.

        Args:
            secret: Signing secret
            signature: Slack signature header
            payload: Request body
            timestamp: Request timestamp header

        Returns:
            True if valid
        """
        # Check timestamp
        current_time = int(time.time())
        if abs(current_time - int(timestamp)) > self.tolerance_seconds:
            return False

        # Slack signature format: v0=signature
        if not signature.startswith("v0="):
            return False

        expected_signature = signature.split("=", 1)[1]

        # Slack includes version, timestamp, and body
        base_string = f"v0:{timestamp}:{payload}"

        return self.validate(
            secret, expected_signature, base_string, algorithm="sha256", encoding="hex"
        )

    def validate_with_multiple_secrets(
        self, secrets: list[str], signature: str, payload: str | bytes, **kwargs
    ) -> bool:
        """Validate signature against multiple possible secrets.

        Useful for key rotation scenarios.

        Args:
            secrets: List of possible secrets
            signature: Signature to validate
            payload: Request payload
            **kwargs: Additional validation parameters

        Returns:
            True if any secret validates
        """
        for secret in secrets:
            if self.validate(secret, signature, payload, **kwargs):
                return True
        return False

    def extract_timestamp_from_header(
        self, header_value: str, format: str = "stripe"
    ) -> int | None:
        """Extract timestamp from signature header.

        Args:
            header_value: Signature header value
            format: Header format (stripe, custom)

        Returns:
            Timestamp if found
        """
        if format == "stripe":
            # Format: t=timestamp,v1=signature
            for item in header_value.split(","):
                if item.startswith("t="):
                    try:
                        return int(item.split("=", 1)[1])
                    except ValueError:
                        return None
        elif format == "custom":
            # Format: timestamp.signature
            try:
                timestamp_str = header_value.split(".", 1)[0]
                return int(timestamp_str)
            except (ValueError, IndexError):
                return None

        return None

    def _secure_compare(self, a: str, b: str) -> bool:
        """Secure string comparison to prevent timing attacks.

        Args:
            a: First string
            b: Second string

        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False

        result = 0
        for char_a, char_b in zip(a, b, strict=False):
            result |= ord(char_a) ^ ord(char_b)

        return result == 0

    @staticmethod
    def parse_signature_header(header: str, provider: str) -> dict[str, Any]:
        """Parse provider-specific signature header.

        Args:
            header: Signature header value
            provider: Webhook provider name

        Returns:
            Parsed signature components
        """
        parsed = {}

        if provider == "github":
            # sha256=signature
            if "=" in header:
                algo, sig = header.split("=", 1)
                parsed["algorithm"] = algo
                parsed["signature"] = sig

        elif provider == "stripe":
            # t=timestamp,v1=signature
            for item in header.split(","):
                if "=" in item:
                    key, value = item.split("=", 1)
                    if key == "t":
                        parsed["timestamp"] = int(value)
                    elif key == "v1":
                        parsed["signature"] = value

        elif provider == "slack":
            # v0=signature
            if "=" in header:
                version, sig = header.split("=", 1)
                parsed["version"] = version
                parsed["signature"] = sig

        # Generic format: algorithm=signature
        elif "=" in header:
            algo, sig = header.split("=", 1)
            parsed["algorithm"] = algo
            parsed["signature"] = sig
        else:
            parsed["signature"] = header

        return parsed
