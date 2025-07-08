"""Cryptography utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic cryptography utilities that follow Domain-Driven Design
principles. All cryptographic operations are pure Python classes that can be used across different
layers of the application without tight coupling to any specific framework.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static utility methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.core.errors import ValidationError

# =====================================================================================
# CRYPTOGRAPHIC CLASSES
# =====================================================================================


class RandomStringGenerator:
    """Cryptographically secure random string generation with rich functionality."""

    def __init__(self, length: int = 32, alphabet: str | None = None):
        """
        Initialize and generate random string.

        Args:
            length: Length of string to generate
            alphabet: Custom alphabet to use (None for URL-safe)

        Raises:
            ValidationError: If parameters are invalid
        """
        if length < 1:
            raise ValidationError("Length must be positive")

        if alphabet is not None and len(alphabet) < 2:
            raise ValidationError("Alphabet must have at least 2 characters")

        self.length = length
        self.alphabet = alphabet
        self.value = self._generate_string()

    def _generate_string(self) -> str:
        """Generate cryptographically secure random string."""
        if self.alphabet:
            return "".join(secrets.choice(self.alphabet) for _ in range(self.length))

        # Default to URL-safe characters
        return secrets.token_urlsafe(self.length)[: self.length]

    @staticmethod
    def generate_random_string(length: int = 32, alphabet: str | None = None) -> str:
        """
        Static method to generate random string.

        Args:
            length: Length of string to generate
            alphabet: Custom alphabet to use

        Returns:
            str: Generated random string
        """
        try:
            generator = RandomStringGenerator(length, alphabet)
            return generator.value
        except ValidationError:
            return secrets.token_urlsafe(32)[:length]

    @property
    def entropy_bits(self) -> float:
        """Calculate entropy in bits."""
        if self.alphabet:
            alphabet_size = len(self.alphabet)
        else:
            alphabet_size = 64  # URL-safe base64 alphabet

        import math

        return self.length * math.log2(alphabet_size)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, RandomStringGenerator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"RandomStringGenerator(length={self.length}, entropy={self.entropy_bits:.1f} bits)"


class APIKeyGenerator:
    """API key generation with prefixes and rich functionality."""

    def __init__(self, prefix: str = "ezd", key_length: int = 32):
        """
        Initialize and generate API key.

        Args:
            prefix: Prefix for the API key
            key_length: Length of the random part

        Raises:
            ValidationError: If parameters are invalid
        """
        if not prefix or not isinstance(prefix, str):
            raise ValidationError("Prefix cannot be empty")

        if key_length < 16:
            raise ValidationError("Key length must be at least 16 characters")

        self.prefix = prefix
        self.key_length = key_length
        self.random_part = RandomStringGenerator.generate_random_string(key_length)
        self.value = f"{prefix}_{self.random_part}"

    @staticmethod
    def generate_api_key(prefix: str = "ezd", key_length: int = 32) -> str:
        """
        Static method to generate API key.

        Args:
            prefix: Prefix for the API key
            key_length: Length of the random part

        Returns:
            str: Generated API key
        """
        try:
            generator = APIKeyGenerator(prefix, key_length)
            return generator.value
        except ValidationError:
            return f"ezd_{RandomStringGenerator.generate_random_string(32)}"

    @property
    def masked_value(self) -> str:
        """Get masked version for display."""
        if len(self.value) <= 8:
            return "*" * len(self.value)
        return f"{self.value[:4]}{'*' * (len(self.value) - 8)}{self.value[-4:]}"

    def __str__(self) -> str:
        """String representation (masked for security)."""
        return self.masked_value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, APIKeyGenerator):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"APIKeyGenerator(prefix='{self.prefix}', length={self.key_length})"


class DataHasher:
    """Data hashing with multiple algorithms and rich functionality."""

    SUPPORTED_ALGORITHMS = {"sha256", "sha512", "md5", "sha1", "sha224", "sha384"}

    def __init__(self, data: str, algorithm: str = "sha256"):
        """
        Initialize and hash data.

        Args:
            data: Data to hash
            algorithm: Hashing algorithm to use

        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(data, str):
            raise ValidationError("Data must be a string")

        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValidationError(
                f"Unsupported algorithm: {algorithm}. Supported: {self.SUPPORTED_ALGORITHMS}"
            )

        self.data = data
        self.algorithm = algorithm
        self.value = self._hash_data()

    def _hash_data(self) -> str:
        """Hash data using specified algorithm."""
        hash_obj = hashlib.new(self.algorithm)
        hash_obj.update(self.data.encode("utf-8"))
        return hash_obj.hexdigest()

    @staticmethod
    def hash_data(data: str, algorithm: str = "sha256") -> str:
        """
        Static method to hash data.

        Args:
            data: Data to hash
            algorithm: Hashing algorithm

        Returns:
            str: Hex digest of hash
        """
        try:
            hasher = DataHasher(data, algorithm)
            return hasher.value
        except ValidationError:
            # Fallback to SHA256
            return hashlib.sha256(data.encode()).hexdigest()

    @property
    def hash_length(self) -> int:
        """Get length of hash in characters."""
        return len(self.value)

    @property
    def hash_bytes(self) -> bytes:
        """Get hash as bytes."""
        return bytes.fromhex(self.value)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, DataHasher):
            return False
        return self.value == other.value and self.algorithm == other.algorithm

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.value, self.algorithm))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"DataHasher(algorithm='{self.algorithm}', hash='{self.value[:16]}...')"


class HMACSignature:
    """HMAC signature creation and verification with rich functionality."""

    SUPPORTED_ALGORITHMS = {"sha256", "sha512", "sha1", "sha224", "sha384"}

    def __init__(self, data: str, secret: str, algorithm: str = "sha256"):
        """
        Initialize and create HMAC signature.

        Args:
            data: Data to sign
            secret: Secret key for signing
            algorithm: HMAC algorithm to use

        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(data, str):
            raise ValidationError("Data must be a string")

        if not isinstance(secret, str) or len(secret) < 16:
            raise ValidationError("Secret must be a string with at least 16 characters")

        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValidationError(f"Unsupported algorithm: {algorithm}")

        self.data = data
        self.secret = secret
        self.algorithm = algorithm
        self.value = self._create_signature()

    def _create_signature(self) -> str:
        """Create HMAC signature."""
        hash_func = getattr(hashlib, self.algorithm)
        h = hmac.new(self.secret.encode(), self.data.encode(), hash_func)
        return h.hexdigest()

    @staticmethod
    def create_signature(data: str, secret: str, algorithm: str = "sha256") -> str:
        """
        Static method to create HMAC signature.

        Args:
            data: Data to sign
            secret: Secret key
            algorithm: HMAC algorithm

        Returns:
            str: HMAC signature
        """
        try:
            hmac_sig = HMACSignature(data, secret, algorithm)
            return hmac_sig.value
        except ValidationError:
            # Fallback
            return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(
        data: str, signature: str, secret: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Verify HMAC signature.

        Args:
            data: Original data
            signature: Signature to verify
            secret: Secret key
            algorithm: HMAC algorithm

        Returns:
            bool: True if signature is valid
        """
        try:
            expected = HMACSignature.create_signature(data, secret, algorithm)
            return hmac.compare_digest(expected, signature)
        except (ValidationError, TypeError):
            return False

    def verify(self, signature: str) -> bool:
        """
        Verify signature against this instance.

        Args:
            signature: Signature to verify

        Returns:
            bool: True if signature matches
        """
        return hmac.compare_digest(self.value, signature)

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, HMACSignature):
            return False
        return (
            self.value == other.value
            and self.algorithm == other.algorithm
            and self.data == other.data
        )

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.value, self.algorithm, self.data))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"HMACSignature(algorithm='{self.algorithm}', signature='{self.value[:16]}...')"


class DataEncryptor:
    """Data encryption/decryption using Fernet with rich functionality."""

    def __init__(self, key: str | None = None):
        """
        Initialize encryptor with key.

        Args:
            key: Encryption key (generates from settings if None)

        Raises:
            ValidationError: If key is invalid
        """
        if key:
            try:
                self.fernet = Fernet(key.encode())
                self.key = key
            except Exception as e:
                raise ValidationError(f"Invalid encryption key: {e!s}")
        else:
            # Generate key from secret
            key_material = settings.SECRET_KEY.encode()
            self.key = base64.urlsafe_b64encode(
                key_material[:32].ljust(32, b"0")
            ).decode()
            self.fernet = Fernet(self.key.encode())

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet key.

        Returns:
            str: Base64-encoded Fernet key
        """
        return Fernet.generate_key().decode()

    def encrypt(self, data: str) -> str:
        """
        Encrypt string data.

        Args:
            data: Data to encrypt

        Returns:
            str: Encrypted data as string

        Raises:
            ValidationError: If encryption fails
        """
        try:
            return self.fernet.encrypt(data.encode()).decode()
        except Exception as e:
            raise ValidationError(f"Encryption failed: {e!s}")

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt string data.

        Args:
            encrypted: Encrypted data

        Returns:
            str: Decrypted data

        Raises:
            ValidationError: If decryption fails
        """
        try:
            return self.fernet.decrypt(encrypted.encode()).decode()
        except InvalidToken:
            raise ValidationError("Invalid token or key")
        except Exception as e:
            raise ValidationError(f"Decryption failed: {e!s}")

    def encrypt_dict(self, data: dict) -> str:
        """
        Encrypt dictionary as JSON.

        Args:
            data: Dictionary to encrypt

        Returns:
            str: Encrypted JSON string
        """
        import json

        json_str = json.dumps(data)
        return self.encrypt(json_str)

    def decrypt_dict(self, encrypted: str) -> dict:
        """
        Decrypt to dictionary.

        Args:
            encrypted: Encrypted JSON string

        Returns:
            dict: Decrypted dictionary

        Raises:
            ValidationError: If decryption or JSON parsing fails
        """
        import json

        try:
            json_str = self.decrypt(encrypted)
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON in encrypted data: {e!s}")

    def can_decrypt(self, encrypted: str) -> bool:
        """
        Check if data can be decrypted with current key.

        Args:
            encrypted: Encrypted data to test

        Returns:
            bool: True if can be decrypted
        """
        try:
            self.decrypt(encrypted)
            return True
        except ValidationError:
            return False

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"DataEncryptor(key_type={'custom' if hasattr(self, 'key') else 'derived'})"
        )


class SensitiveDataMasker:
    """Mask sensitive data for display with rich functionality."""

    def __init__(self, data: str, visible_chars: int = 4, mask_char: str = "*"):
        """
        Initialize and mask sensitive data.

        Args:
            data: Sensitive data to mask
            visible_chars: Number of characters to keep visible
            mask_char: Character to use for masking

        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(data, str):
            raise ValidationError("Data must be a string")

        if visible_chars < 0:
            raise ValidationError("Visible characters cannot be negative")

        if not mask_char or len(mask_char) != 1:
            raise ValidationError("Mask character must be a single character")

        self.original_data = data
        self.visible_chars = visible_chars
        self.mask_char = mask_char
        self.value = self._mask_data()

    def _mask_data(self) -> str:
        """Mask sensitive data for display."""
        if not self.original_data or len(self.original_data) <= self.visible_chars:
            return (
                self.mask_char * len(self.original_data) if self.original_data else ""
            )

        if self.visible_chars == 0:
            return self.mask_char * len(self.original_data)

        # Show first and last n characters
        show_start = self.visible_chars // 2
        show_end = self.visible_chars - show_start

        masked_middle = self.mask_char * (len(self.original_data) - self.visible_chars)

        if show_end > 0:
            return (
                self.original_data[:show_start]
                + masked_middle
                + self.original_data[-show_end:]
            )
        return self.original_data[:show_start] + masked_middle

    @staticmethod
    def mask_sensitive_data(
        data: str, visible_chars: int = 4, mask_char: str = "*"
    ) -> str:
        """
        Static method to mask sensitive data.

        Args:
            data: Data to mask
            visible_chars: Number of visible characters
            mask_char: Masking character

        Returns:
            str: Masked data
        """
        try:
            masker = SensitiveDataMasker(data, visible_chars, mask_char)
            return masker.value
        except ValidationError:
            return "*" * len(data) if data else ""

    @property
    def masking_percentage(self) -> float:
        """Get percentage of data that is masked."""
        if not self.original_data:
            return 0.0

        masked_chars = len(self.original_data) - self.visible_chars
        return (max(0, masked_chars) / len(self.original_data)) * 100

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __eq__(self, other) -> bool:
        """Check equality based on masked value."""
        if not isinstance(other, SensitiveDataMasker):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"SensitiveDataMasker('{self.value}', {self.masking_percentage:.1f}% masked)"


# =====================================================================================
# BACKWARD COMPATIBILITY FUNCTIONS (Legacy API)
# =====================================================================================


def generate_random_string(length: int = 32, alphabet: str | None = None) -> str:
    """Generate cryptographically secure random string."""
    return RandomStringGenerator.generate_random_string(length, alphabet)


def generate_api_key(prefix: str = "ezd") -> str:
    """Generate API key with prefix."""
    return APIKeyGenerator.generate_api_key(prefix)


def hash_data(data: str, algorithm: str = "sha256") -> str:
    """Hash data using specified algorithm."""
    return DataHasher.hash_data(data, algorithm)


def create_signature(data: str, secret: str, algorithm: str = "sha256") -> str:
    """Create HMAC signature."""
    return HMACSignature.create_signature(data, secret, algorithm)


def verify_signature(
    data: str, signature: str, secret: str, algorithm: str = "sha256"
) -> bool:
    """Verify HMAC signature."""
    return HMACSignature.verify_signature(data, signature, secret, algorithm)


def mask_sensitive_data(data: str, visible_chars: int = 4, mask_char: str = "*") -> str:
    """Mask sensitive data for display."""
    return SensitiveDataMasker.mask_sensitive_data(data, visible_chars, mask_char)
