"""API key management service.

This module provides API key generation, validation, and management
for secure API access control.
"""

import base64
import hashlib
import json
import logging
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.errors import SecurityError

logger = logging.getLogger(__name__)


class APIKeyManager:
    """Service for managing API keys."""

    # API key format: prefix_randompart_checksum
    KEY_PREFIX = "ik"  # Integration Key
    KEY_LENGTH = 32  # Random part length
    CHECKSUM_LENGTH = 6

    def __init__(
        self,
        prefix: str | None = None,
        key_length: int | None = None,
        include_checksum: bool = True,
        hash_algorithm: str = "sha256",
    ):
        """Initialize API key manager.

        Args:
            prefix: Custom key prefix
            key_length: Length of random part
            include_checksum: Include checksum in key
            hash_algorithm: Algorithm for hashing keys
        """
        self.prefix = prefix or self.KEY_PREFIX
        self.key_length = key_length or self.KEY_LENGTH
        self.include_checksum = include_checksum
        self.hash_algorithm = hash_algorithm

        # Compile regex for key validation
        if self.include_checksum:
            pattern = f"^{self.prefix}_[A-Za-z0-9]{{{self.key_length}}}[A-Za-z0-9]{{{self.CHECKSUM_LENGTH}}}$"
        else:
            pattern = f"^{self.prefix}_[A-Za-z0-9]{{{self.key_length}}}$"

        self.key_pattern = re.compile(pattern)

    def generate_api_key(
        self, metadata: dict[str, Any] | None = None
    ) -> tuple[str, str]:
        """Generate a new API key.

        Args:
            metadata: Optional metadata to associate with key

        Returns:
            Tuple of (api_key, key_hash)
        """
        # Generate random part
        random_part = secrets.token_urlsafe(self.key_length)[: self.key_length]

        # Build key
        if self.include_checksum:
            # Calculate checksum
            checksum = self._calculate_checksum(f"{self.prefix}_{random_part}")
            api_key = f"{self.prefix}_{random_part}{checksum}"
        else:
            api_key = f"{self.prefix}_{random_part}"

        # Generate hash for storage
        key_hash = self.hash_api_key(api_key)

        logger.info(f"Generated new API key with prefix: {self.prefix}")

        return api_key, key_hash

    def hash_api_key(self, api_key: str) -> str:
        """Hash an API key for secure storage.

        Args:
            api_key: Plain API key

        Returns:
            Hashed key
        """
        if self.hash_algorithm == "sha256":
            return hashlib.sha256(api_key.encode()).hexdigest()
        if self.hash_algorithm == "sha512":
            return hashlib.sha512(api_key.encode()).hexdigest()
        raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")

    def validate_format(self, api_key: str) -> bool:
        """Validate API key format.

        Args:
            api_key: API key to validate

        Returns:
            True if format is valid
        """
        if not self.key_pattern.match(api_key):
            return False

        if self.include_checksum:
            # Verify checksum
            prefix_and_random = api_key[: -self.CHECKSUM_LENGTH]
            checksum = api_key[-self.CHECKSUM_LENGTH :]
            expected_checksum = self._calculate_checksum(prefix_and_random)

            return checksum == expected_checksum

        return True

    def extract_prefix(self, api_key: str) -> str | None:
        """Extract prefix from API key.

        Args:
            api_key: API key

        Returns:
            Prefix if valid key
        """
        if not self.validate_format(api_key):
            return None

        parts = api_key.split("_", 1)
        return parts[0] if len(parts) > 0 else None

    def generate_scoped_key(
        self, parent_key: str, scope: str, expiry: datetime | None = None
    ) -> str:
        """Generate a scoped API key from parent key.

        Args:
            parent_key: Parent API key
            scope: Scope identifier
            expiry: Optional expiry time

        Returns:
            Scoped API key
        """
        # Validate parent key
        if not self.validate_format(parent_key):
            raise SecurityError("Invalid parent API key")

        # Create scope data
        scope_data = {
            "parent": self.hash_api_key(parent_key)[:16],  # Partial hash
            "scope": scope,
            "created": datetime.now(UTC).isoformat(),
        }

        if expiry:
            scope_data["expiry"] = expiry.isoformat()

        # Encode scope data
        scope_json = json.dumps(scope_data, separators=(",", ":"))
        scope_encoded = (
            base64.urlsafe_b64encode(scope_json.encode()).decode().rstrip("=")
        )

        # Generate scoped key with special prefix
        scoped_prefix = f"{self.prefix}s"  # 's' for scoped

        return f"{scoped_prefix}_{scope_encoded}"

    def validate_scoped_key(
        self, scoped_key: str, parent_key_hash: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate a scoped API key.

        Args:
            scoped_key: Scoped API key
            parent_key_hash: Hash of parent key for verification

        Returns:
            Tuple of (is_valid, scope_data)
        """
        try:
            # Check format
            if not scoped_key.startswith(f"{self.prefix}s_"):
                return False, None

            # Extract encoded part
            encoded_part = scoped_key.split("_", 1)[1]

            # Decode scope data
            # Add padding if needed
            padding = 4 - (len(encoded_part) % 4)
            if padding != 4:
                encoded_part += "=" * padding

            scope_json = base64.urlsafe_b64decode(encoded_part).decode()
            scope_data = json.loads(scope_json)

            # Verify parent key
            if not parent_key_hash.startswith(scope_data["parent"]):
                return False, None

            # Check expiry
            if "expiry" in scope_data:
                expiry = datetime.fromisoformat(scope_data["expiry"])
                if datetime.now(UTC) > expiry:
                    return False, None

            return True, scope_data

        except Exception as e:
            logger.exception(f"Scoped key validation error: {e}")
            return False, None

    def rotate_key(
        self, old_key_hash: str, metadata: dict[str, Any] | None = None
    ) -> tuple[str, str]:
        """Rotate an API key by generating a new one.

        Args:
            old_key_hash: Hash of old key being rotated
            metadata: Optional metadata for new key

        Returns:
            Tuple of (new_api_key, new_key_hash)
        """
        # Add rotation metadata
        if metadata is None:
            metadata = {}

        metadata["rotated_from"] = old_key_hash[:16]  # Partial hash
        metadata["rotated_at"] = datetime.now(UTC).isoformat()

        return self.generate_api_key(metadata)

    def _calculate_checksum(self, data: str) -> str:
        """Calculate checksum for data.

        Args:
            data: Data to checksum

        Returns:
            Checksum string
        """
        # Use first N characters of hash as checksum
        hash_value = hashlib.sha256(data.encode()).hexdigest()
        return hash_value[: self.CHECKSUM_LENGTH]

    @staticmethod
    def generate_temporary_key(
        duration_seconds: int = 3600, prefix: str = "tmp"
    ) -> tuple[str, datetime]:
        """Generate a temporary API key.

        Args:
            duration_seconds: Validity duration
            prefix: Key prefix

        Returns:
            Tuple of (temp_key, expiry_time)
        """
        # Generate simple temporary key
        random_part = secrets.token_urlsafe(16)
        temp_key = f"{prefix}_{random_part}"

        expiry = datetime.now(UTC) + timedelta(seconds=duration_seconds)

        return temp_key, expiry

    def parse_api_key_header(self, header_value: str) -> str | None:
        """Parse API key from authorization header.

        Args:
            header_value: Authorization header value

        Returns:
            API key if found
        """
        # Support various formats
        if header_value.startswith(("Bearer ", "ApiKey ")):
            return header_value[7:]
        if header_value.startswith("Token "):
            return header_value[6:]
        if self.validate_format(header_value):
            # Direct API key
            return header_value

        return None

    def mask_api_key(self, api_key: str) -> str:
        """Mask API key for safe display.

        Args:
            api_key: API key to mask

        Returns:
            Masked key showing only prefix and last 4 chars
        """
        if not api_key or len(api_key) < 10:
            return "***"

        prefix = api_key.split("_")[0] if "_" in api_key else api_key[:3]
        suffix = api_key[-4:]

        return f"{prefix}_****{suffix}"
