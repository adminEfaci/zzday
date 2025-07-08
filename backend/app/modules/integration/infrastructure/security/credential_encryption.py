"""Credential encryption service for secure storage.

This module provides encryption and decryption services for API credentials
using industry-standard encryption algorithms.
"""

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.errors import SecurityError

logger = logging.getLogger(__name__)


class CredentialEncryptionService:
    """Service for encrypting and decrypting credentials."""

    def __init__(
        self,
        master_key: str | None = None,
        use_key_derivation: bool = True,
        rotation_enabled: bool = True,
    ):
        """Initialize encryption service.

        Args:
            master_key: Master encryption key (base64 encoded)
            use_key_derivation: Use key derivation for additional security
            rotation_enabled: Enable key rotation support
        """
        if master_key:
            self.master_key = base64.urlsafe_b64decode(master_key)
        else:
            # In production, load from secure key management service
            self.master_key = os.environ.get(
                "INTEGRATION_MASTER_KEY", Fernet.generate_key()
            )
            if isinstance(self.master_key, str):
                self.master_key = self.master_key.encode()

        self.use_key_derivation = use_key_derivation
        self.rotation_enabled = rotation_enabled

        # Key cache for derived keys
        self._key_cache: dict[str, bytes] = {}

        # Initialize primary cipher
        self._primary_cipher = Fernet(self.master_key)

    def _derive_key(self, key_id: str, salt: bytes | None = None) -> bytes:
        """Derive encryption key from master key and key ID.

        Args:
            key_id: Unique key identifier
            salt: Optional salt for key derivation

        Returns:
            Derived encryption key
        """
        if key_id in self._key_cache:
            return self._key_cache[key_id]

        if salt is None:
            # Use deterministic salt based on key_id for consistency
            salt = hashlib.sha256(key_id.encode()).digest()[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(self.master_key + key_id.encode()))

        self._key_cache[key_id] = key
        return key

    def encrypt_data(self, data: dict[str, Any] | str | bytes, key_id: str) -> bytes:
        """Encrypt data using specified key ID.

        Args:
            data: Data to encrypt (dict, string, or bytes)
            key_id: Encryption key identifier

        Returns:
            Encrypted data as bytes

        Raises:
            SecurityError: If encryption fails
        """
        try:
            # Convert data to bytes
            if isinstance(data, dict):
                plaintext = json.dumps(data).encode("utf-8")
            elif isinstance(data, str):
                plaintext = data.encode("utf-8")
            else:
                plaintext = data

            if self.use_key_derivation:
                # Use derived key
                key = self._derive_key(key_id)
                cipher = Fernet(key)
            else:
                # Use primary cipher
                cipher = self._primary_cipher

            # Encrypt data
            encrypted = cipher.encrypt(plaintext)

            # Add metadata for rotation support
            if self.rotation_enabled:
                metadata = {
                    "v": 1,  # Version
                    "k": key_id,  # Key ID
                    "d": base64.b64encode(encrypted).decode(),  # Data
                }
                return base64.b64encode(json.dumps(metadata).encode()).decode().encode()

            return encrypted

        except Exception as e:
            logger.exception(f"Encryption failed: {e}")
            raise SecurityError(f"Failed to encrypt data: {e!s}")

    def decrypt_data(self, encrypted_data: bytes, key_id: str) -> dict[str, Any] | str:
        """Decrypt data using specified key ID.

        Args:
            encrypted_data: Encrypted data
            key_id: Encryption key identifier

        Returns:
            Decrypted data (dict or string)

        Raises:
            SecurityError: If decryption fails
        """
        try:
            # Check for rotation metadata
            if self.rotation_enabled:
                try:
                    # Try to decode as metadata
                    metadata_json = base64.b64decode(encrypted_data).decode()
                    metadata = json.loads(metadata_json)

                    if isinstance(metadata, dict) and "v" in metadata:
                        # Extract encrypted data from metadata
                        encrypted_data = base64.b64decode(metadata["d"])
                        # Use key ID from metadata if available
                        key_id = metadata.get("k", key_id)
                except Exception:
                    # Not metadata format, proceed normally
                    pass

            if self.use_key_derivation:
                # Use derived key
                key = self._derive_key(key_id)
                cipher = Fernet(key)
            else:
                # Use primary cipher
                cipher = self._primary_cipher

            # Decrypt data
            decrypted = cipher.decrypt(encrypted_data)

            # Try to decode as JSON
            try:
                return json.loads(decrypted.decode("utf-8"))
            except json.JSONDecodeError:
                # Return as string if not JSON
                return decrypted.decode("utf-8")

        except Exception as e:
            logger.exception(f"Decryption failed: {e}")
            raise SecurityError(f"Failed to decrypt data: {e!s}")

    def encrypt_field(self, field_value: Any, field_name: str, entity_id: str) -> str:
        """Encrypt a specific field value.

        Args:
            field_value: Value to encrypt
            field_name: Name of the field
            entity_id: ID of the entity containing the field

        Returns:
            Base64 encoded encrypted value
        """
        # Create unique key ID for this field
        key_id = f"{entity_id}:{field_name}"

        # Convert value to string if needed
        if not isinstance(field_value, str | bytes):
            field_value = json.dumps(field_value)

        encrypted = self.encrypt_data(field_value, key_id)
        return base64.b64encode(encrypted).decode()

    def decrypt_field(
        self, encrypted_value: str, field_name: str, entity_id: str
    ) -> Any:
        """Decrypt a specific field value.

        Args:
            encrypted_value: Base64 encoded encrypted value
            field_name: Name of the field
            entity_id: ID of the entity containing the field

        Returns:
            Decrypted value
        """
        # Create unique key ID for this field
        key_id = f"{entity_id}:{field_name}"

        encrypted_bytes = base64.b64decode(encrypted_value)
        return self.decrypt_data(encrypted_bytes, key_id)

    def generate_key_id(self) -> str:
        """Generate a new unique key ID.

        Returns:
            Unique key identifier
        """
        return secrets.token_urlsafe(16)

    def rotate_key(
        self, old_encrypted_data: bytes, old_key_id: str, new_key_id: str
    ) -> bytes:
        """Rotate encryption key for data.

        Args:
            old_encrypted_data: Data encrypted with old key
            old_key_id: Old key identifier
            new_key_id: New key identifier

        Returns:
            Data encrypted with new key
        """
        # Decrypt with old key
        decrypted = self.decrypt_data(old_encrypted_data, old_key_id)

        # Encrypt with new key
        return self.encrypt_data(decrypted, new_key_id)

    def bulk_encrypt(
        self, data_items: list[dict[str, Any]], key_id: str
    ) -> list[bytes]:
        """Encrypt multiple data items efficiently.

        Args:
            data_items: List of data items to encrypt
            key_id: Encryption key identifier

        Returns:
            List of encrypted data
        """
        if self.use_key_derivation:
            key = self._derive_key(key_id)
            cipher = Fernet(key)
        else:
            cipher = self._primary_cipher

        encrypted_items = []
        for item in data_items:
            plaintext = json.dumps(item).encode("utf-8")
            encrypted_items.append(cipher.encrypt(plaintext))

        return encrypted_items

    def create_encrypted_backup(
        self, data: dict[str, Any], backup_key: str | None = None
    ) -> dict[str, Any]:
        """Create an encrypted backup of data.

        Args:
            data: Data to backup
            backup_key: Optional backup encryption key

        Returns:
            Encrypted backup with metadata
        """
        backup_key_id = backup_key or self.generate_key_id()

        encrypted = self.encrypt_data(data, backup_key_id)

        return {
            "version": 1,
            "key_id": backup_key_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": base64.b64encode(encrypted).decode(),
            "checksum": hashlib.sha256(encrypted).hexdigest(),
        }

    def verify_encrypted_data(self, encrypted_data: bytes, key_id: str) -> bool:
        """Verify that encrypted data can be decrypted.

        Args:
            encrypted_data: Encrypted data to verify
            key_id: Encryption key identifier

        Returns:
            True if data can be decrypted successfully
        """
        try:
            self.decrypt_data(encrypted_data, key_id)
            return True
        except Exception:
            return False

    def clear_key_cache(self) -> None:
        """Clear derived key cache for security."""
        self._key_cache.clear()
