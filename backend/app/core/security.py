"""Security services following pure Python principles.

This module provides comprehensive security services for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are
completely independent of any framework.

The security layer handles authentication, authorization, cryptographic operations,
token management, and data protection following industry best practices.

Design Principles:
- Pure Python implementation with explicit configuration
- Framework-agnostic design for maximum portability
- Rich functionality with comprehensive error handling
- Secure defaults with configurable parameters
- Performance optimizations for cryptographic operations
- Comprehensive logging and auditing

Architecture:
- SecurityService: Main security coordination service
- PasswordService: Password hashing and verification
- TokenService: JWT and secure token management
- CryptographyService: Encryption and cryptographic utilities
- MaskingService: Data masking and privacy protection
- Uses SecurityConfig from app.core.config for configuration
"""

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import SecurityConfig
from app.core.enums import PasswordStrength, SecurityEventType, SessionType, ThreatLevel
from app.core.errors import SecurityError, UnauthorizedError, ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


# =====================================================================================
# PASSWORD SERVICE
# =====================================================================================


class PasswordService:
    """
    Password hashing and verification service.

    Provides secure password hashing using Argon2id with configurable parameters
    and comprehensive validation and verification capabilities.

    Design Features:
    - Secure password hashing with Argon2id
    - Configurable security parameters
    - Password strength validation
    - Timing attack protection
    - Comprehensive error handling

    Usage Example:
        config = SecurityConfig()
        password_service = PasswordService(config)

        # Hash password
        hashed = password_service.hash_password("secure_password123")

        # Verify password
        is_valid = password_service.verify_password("secure_password123", hashed)

        # Check password strength
        strength = password_service.calculate_strength("password123")
    """

    def __init__(self, config: SecurityConfig):
        """
        Initialize password service with configuration.

        Args:
            config: Security configuration
        """
        self.config = config
        self._hasher = self._create_hasher()
        self._operation_count = 0
        self._hash_time_total = 0.0
        self._verify_time_total = 0.0

    def _create_hasher(self) -> PasswordHasher:
        """Create Argon2 password hasher with configured parameters."""
        return PasswordHasher(
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len,
            salt_len=self.config.argon2_salt_len,
        )

    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: Plain text password to hash

        Returns:
            str: Hashed password

        Raises:
            ValidationError: If password is invalid
            SecurityError: If hashing fails
        """
        import time

        start_time = time.time()

        try:
            # Validate password
            self._validate_password(password)

            # Hash password
            hashed = self._hasher.hash(password)

            # Update metrics
            hash_time = time.time() - start_time
            self._operation_count += 1
            self._hash_time_total += hash_time

            logger.debug(
                "Password hashed successfully",
                hash_time=hash_time,
                operation_count=self._operation_count,
            )

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Password hashing failed", error=str(e), error_type=type(e).__name__
            )
            raise SecurityError("Password hashing failed") from e
        else:
            return hashed

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            hashed: Hashed password to verify against

        Returns:
            bool: True if password matches hash, False otherwise
        """
        import time

        start_time = time.time()

        try:
            # Basic validation
            if not password or not hashed:
                return False

            # Verify password
            result = self._hasher.verify(hashed, password)

            # Update metrics
            verify_time = time.time() - start_time
            self._verify_time_total += verify_time

            logger.debug(
                "Password verification completed",
                verify_time=verify_time,
                result=result,
            )

        except (InvalidHash, VerificationError, VerifyMismatchError):
            logger.debug("Password verification failed - invalid hash or mismatch")
            return False
        except Exception as e:
            logger.exception(
                "Password verification error", error=str(e), error_type=type(e).__name__
            )
            return False
        else:
            return result

    def _validate_password(self, password: str) -> None:
        """
        Validate password against security requirements.

        Args:
            password: Password to validate

        Raises:
            ValidationError: If password doesn't meet requirements
        """
        if not isinstance(password, str):
            raise ValidationError("Password must be a string")

        if len(password) < self.config.min_password_length:
            raise ValidationError(
                f"Password must be at least {self.config.min_password_length} characters"
            )

        if len(password) > self.config.max_password_length:
            raise ValidationError(
                f"Password must be no more than {self.config.max_password_length} characters"
            )

        if self.config.require_strong_passwords:
            self._validate_password_strength(password)

    def _validate_password_strength(self, password: str) -> None:
        """
        Validate password meets strength requirements.

        Args:
            password: Password to validate

        Raises:
            ValidationError: If password is not strong enough
        """
        issues = []

        if self.config.password_require_lowercase and not re.search(r"[a-z]", password):
            issues.append("at least one lowercase letter")

        if self.config.password_require_uppercase and not re.search(r"[A-Z]", password):
            issues.append("at least one uppercase letter")

        if self.config.password_require_numbers and not re.search(r"\d", password):
            issues.append("at least one number")

        if self.config.password_require_special_chars and not re.search(
            r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password
        ):
            issues.append("at least one special character")

        if issues:
            raise ValidationError(f"Password must contain: {', '.join(issues)}")

    def calculate_strength(self, password: str) -> dict[str, Any]:
        """
        Calculate password strength score and feedback using shared PasswordStrength enum.

        Args:
            password: Password to analyze

        Returns:
            dict[str, Any]: Strength analysis with score and feedback
        """
        if not password:
            return {
                "score": 0,
                "level": PasswordStrength.VERY_WEAK.level,
                "enum": PasswordStrength.VERY_WEAK,
                "feedback": ["Password cannot be empty"],
            }

        score, feedback = self._calculate_password_score_and_feedback(password)
        strength_enum = PasswordStrength.from_score(min(score, 100))

        # Character type analysis
        char_patterns = {
            "has_lowercase": r"[a-z]",
            "has_uppercase": r"[A-Z]",
            "has_numbers": r"\d",
            "has_special": r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]",
        }
        
        char_analysis = {
            key: bool(re.search(pattern, password))
            for key, pattern in char_patterns.items()
        }

        return {
            "score": min(score, 100),
            "level": strength_enum.level,
            "enum": strength_enum,
            "feedback": feedback,
            "length": len(password),
            **char_analysis,
            "is_acceptable": strength_enum.is_acceptable,
            "meets_security_policy": strength_enum.meets_security_policy,
        }

    def _calculate_password_score_and_feedback(self, password: str) -> tuple[int, list[str]]:
        """Calculate password score and feedback, extracted to reduce method complexity."""
        score = 0
        feedback = []

        # Length scoring with consolidated logic
        length_scores = [(8, 20), (12, 10), (16, 10)]
        for min_length, points in length_scores:
            if len(password) >= min_length:
                score += points
            elif min_length == 8:  # Only add feedback for minimum requirement
                feedback.append("Use at least 8 characters")

        # Character variety scoring
        char_checks = [
            (r"[a-z]", 10, "Add lowercase letters"),
            (r"[A-Z]", 10, "Add uppercase letters"),
            (r"\d", 10, "Add numbers"),
            (r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", 15, "Add special characters"),
        ]

        char_types = 0
        for pattern, points, message in char_checks:
            if re.search(pattern, password):
                score += points
                char_types += 1
            else:
                feedback.append(message)

        # Complexity bonus
        if char_types >= 3:
            score += 15

        return score, feedback

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for the password service."""
        avg_hash_time = self._hash_time_total / max(self._operation_count, 1)
        avg_verify_time = self._verify_time_total / max(self._operation_count, 1)

        return {
            "operation_count": self._operation_count,
            "total_hash_time": self._hash_time_total,
            "total_verify_time": self._verify_time_total,
            "average_hash_time": avg_hash_time,
            "average_verify_time": avg_verify_time,
            "algorithm": self.config.password_algorithm.value,
            "time_cost": self.config.argon2_time_cost,
            "memory_cost": self.config.argon2_memory_cost,
        }


# =====================================================================================
# TOKEN SERVICE
# =====================================================================================


class TokenService:
    """
    JWT and secure token management service.

    Provides comprehensive token management including JWT creation/validation,
    secure random token generation, and token lifecycle management.

    Design Features:
    - JWT access and refresh token management
    - Secure random token generation
    - Token validation and verification
    - Clock skew handling
    - Token blacklisting support

    Usage Example:
        config = SecurityConfig()
        token_service = TokenService(config)

        # Create access token
        access_token = token_service.create_access_token("user123")

        # Validate token
        payload = token_service.decode_access_token(access_token)

        # Generate secure token
        secure_token = token_service.generate_secure_token()
    """

    def __init__(self, config: SecurityConfig):
        """
        Initialize token service with security configuration.

        Args:
            config: Security configuration containing JWT secrets and settings
        """
        self.config = config
        self._validate_secrets()

        # Token statistics
        self._tokens_created = 0
        self._tokens_validated = 0
        self._validation_errors = 0

    def _validate_secrets(self) -> None:
        """Validate token secrets are sufficiently strong."""
        if len(self.config.access_token_secret) < 32:
            raise ValidationError("Access token secret must be at least 32 characters")

        if len(self.config.refresh_token_secret) < 32:
            raise ValidationError("Refresh token secret must be at least 32 characters")

        if self.config.access_token_secret == self.config.refresh_token_secret:
            raise ValidationError("Access and refresh token secrets must be different")

    def create_access_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Create JWT access token.

        Args:
            subject: Token subject (usually user ID)
            expires_delta: Optional custom expiration time
            additional_claims: Optional additional claims

        Returns:
            str: Encoded JWT access token
        """
        now = self._now_utc()
        expire = now + (
            expires_delta or timedelta(minutes=self.config.access_token_expire_minutes)
        )

        claims = {
            "sub": subject,
            "iat": self._timestamp(now),
            "exp": self._timestamp(expire),
            "type": "access",
            "aud": self.config.jwt_audience,
            "iss": self.config.jwt_issuer,
            "jti": self.generate_secure_token(16),
        }

        if additional_claims:
            claims.update(additional_claims)

        try:
            token = jwt.encode(
                claims,
                self.config.access_token_secret,
                algorithm=self.config.jwt_algorithm.value,
            )

            self._tokens_created += 1

            logger.debug(
                "Access token created",
                subject=subject,
                expires=expire.isoformat(),
                jti=claims["jti"],
            )

        except Exception as e:
            logger.exception(
                "Failed to create access token", subject=subject, error=str(e)
            )
            raise SecurityError("Failed to create access token") from e
        else:
            return token

    def create_refresh_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Create JWT refresh token.

        Args:
            subject: Token subject (usually user ID)
            expires_delta: Optional custom expiration time
            additional_claims: Optional additional claims

        Returns:
            str: Encoded JWT refresh token
        """
        now = self._now_utc()
        expire = now + (
            expires_delta or timedelta(days=self.config.refresh_token_expire_days)
        )

        claims = {
            "sub": subject,
            "iat": self._timestamp(now),
            "exp": self._timestamp(expire),
            "type": "refresh",
            "aud": self.config.jwt_audience,
            "iss": self.config.jwt_issuer,
            "jti": self.generate_secure_token(16),
        }

        if additional_claims:
            claims.update(additional_claims)

        try:
            token = jwt.encode(
                claims,
                self.config.refresh_token_secret,
                algorithm=self.config.jwt_algorithm.value,
            )

            self._tokens_created += 1

            logger.debug(
                "Refresh token created",
                subject=subject,
                expires=expire.isoformat(),
                jti=claims["jti"],
            )

        except Exception as e:
            logger.exception(
                "Failed to create refresh token", subject=subject, error=str(e)
            )
            raise SecurityError("Failed to create refresh token") from e
        else:
            return token

    def decode_access_token(self, token: str) -> dict[str, Any]:
        """
        Decode and validate access token.

        Args:
            token: JWT access token to decode

        Returns:
            dict[str, Any]: Token payload

        Raises:
            UnauthorizedError: If token is invalid
        """
        return self._decode_token(
            token, secret=self.config.access_token_secret, expected_type="access"
        )

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        """
        Decode and validate refresh token.

        Args:
            token: JWT refresh token to decode

        Returns:
            dict[str, Any]: Token payload

        Raises:
            UnauthorizedError: If token is invalid
        """
        return self._decode_token(
            token, secret=self.config.refresh_token_secret, expected_type="refresh"
        )

    def _decode_token(
        self, token: str, secret: str, expected_type: str | None = None
    ) -> dict[str, Any]:
        """
        Decode and validate JWT token.

        Args:
            token: JWT token to decode
            secret: Secret key for validation
            expected_type: Expected token type

        Returns:
            dict[str, Any]: Token payload

        Raises:
            UnauthorizedError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[self.config.jwt_algorithm.value],
                audience=self.config.jwt_audience,
                issuer=self.config.jwt_issuer,
                options={
                    "require_exp": True,
                    "require_iat": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=self.config.jwt_clock_skew_seconds,
            )

            # Validate token type if specified
            if expected_type and payload.get("type") != expected_type:
                self._raise_token_type_mismatch()

            self._tokens_validated += 1

        except JWTError as e:
            self._validation_errors += 1
            logger.warning(
                "JWT token validation failed", error=str(e), error_type=type(e).__name__
            )
            raise UnauthorizedError("Invalid token") from e
        except Exception as e:
            self._validation_errors += 1
            logger.exception(
                "Token validation error", error=str(e), error_type=type(e).__name__
            )
            raise UnauthorizedError("Token validation failed") from e
        else:
            return payload

    def is_token_expired(self, payload: dict[str, Any]) -> bool:
        """
        Check if decoded token payload is expired.

        Args:
            payload: Decoded token payload

        Returns:
            bool: True if token is expired
        """
        exp = payload.get("exp")
        if not exp or not isinstance(exp, int | float):
            return True

        now = self._timestamp(self._now_utc())
        return now >= int(exp)

    def generate_secure_token(self, nbytes: int | None = None) -> str:
        """
        Generate cryptographically secure random token.

        Args:
            nbytes: Number of bytes for token (default from config)

        Returns:
            str: URL-safe base64 encoded token
        """
        if nbytes is None:
            nbytes = self.config.default_token_bytes

        if nbytes < 16:
            raise ValidationError("Token must be at least 16 bytes")

        return secrets.token_urlsafe(nbytes)

    def generate_verification_code(self, length: int | None = None) -> str:
        """
        Generate numeric verification code.

        Args:
            length: Code length (default from config)

        Returns:
            str: Numeric verification code
        """
        if length is None:
            length = self.config.verification_code_length

        if length < 4 or length > 10:
            raise ValidationError("Verification code length must be between 4 and 10")

        digits = "0123456789"
        return "".join(secrets.choice(digits) for _ in range(length))

    def generate_api_key(self, prefix: str | None = None) -> str:
        """
        Generate API key with optional prefix.

        Args:
            prefix: Optional prefix for API key (default from config)

        Returns:
            str: Generated API key
        """
        if prefix is None:
            prefix = self.config.api_key_prefix

        token = self.generate_secure_token(self.config.api_key_length)
        return f"{prefix}{token}"

    def _now_utc(self) -> datetime:
        """Get current UTC datetime."""
        return datetime.now(UTC)

    def _timestamp(self, dt: datetime) -> int:
        """Convert datetime to Unix timestamp."""
        return int(dt.timestamp())

    def _raise_token_type_mismatch(self) -> None:
        """Raise UnauthorizedError for token type mismatch."""
        raise UnauthorizedError("Token type mismatch")

    def get_statistics(self) -> dict[str, Any]:
        """Get token service statistics."""
        return {
            "tokens_created": self._tokens_created,
            "tokens_validated": self._tokens_validated,
            "validation_errors": self._validation_errors,
            "error_rate": self._validation_errors / max(self._tokens_validated, 1),
            "access_token_expire_minutes": self.config.access_token_expire_minutes,
            "refresh_token_expire_days": self.config.refresh_token_expire_days,
            "jwt_algorithm": self.config.jwt_algorithm.value,
        }


# =====================================================================================
# CRYPTOGRAPHY SERVICE
# =====================================================================================


class CryptographyService:
    """
    Cryptographic operations service.

    Provides encryption, decryption, and other cryptographic utilities
    using configurable algorithms and secure key management.
    """

    def __init__(self, config: SecurityConfig):
        """
        Initialize cryptography service.

        Args:
            config: Security configuration
        """
        self.config = config
        self._operation_count = 0

    def generate_salt(self, length: int = 32) -> bytes:
        """
        Generate cryptographically secure salt.

        Args:
            length: Salt length in bytes

        Returns:
            bytes: Generated salt
        """
        if length < 16:
            raise ValidationError("Salt must be at least 16 bytes")

        return secrets.token_bytes(length)

    def derive_key(self, password: str, salt: bytes, length: int = 32) -> bytes:
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password: Source password
            salt: Cryptographic salt
            length: Key length in bytes

        Returns:
            bytes: Derived key
        """

        if length < 16:
            raise ValidationError("Key length must be at least 16 bytes")

        # Use PBKDF2 with SHA-256
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000, length  # iterations
        )

        self._operation_count += 1

        return key

    def constant_time_compare(self, a: str, b: str) -> bool:
        """
        Compare two strings in constant time to prevent timing attacks.

        Args:
            a: First string
            b: Second string

        Returns:
            bool: True if strings are equal
        """
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    def get_statistics(self) -> dict[str, Any]:
        """Get cryptography service statistics."""
        return {
            "operation_count": self._operation_count,
            "encryption_algorithm": self.config.encryption_algorithm.value,
            "key_rotation_days": self.config.encryption_key_rotation_days,
        }


# =====================================================================================
# MASKING SERVICE
# =====================================================================================


class MaskingService:
    """
    Data masking and privacy protection service.

    Provides utilities for masking sensitive data in logs, displays,
    and other contexts where data privacy is important.

    Design Features:
    - Email masking with domain preservation
    - Phone number masking with partial visibility
    - Credit card number masking
    - Custom masking patterns
    - Configurable masking levels

    Usage Example:
        masking_service = MaskingService()

        masked_email = masking_service.mask_email("user@example.com")  # "us***@example.com"
        masked_phone = masking_service.mask_phone("+1234567890")       # "+12***90"
        masked_card = masking_service.mask_credit_card("4111111111111111")  # "4111 **** **** 1111"
    """

    def __init__(self, mask_char: str = "*"):
        """
        Initialize masking service.

        Args:
            mask_char: Character to use for masking
        """
        self.mask_char = mask_char

    def mask_email(
        self, email: str, visible_start: int = 2, visible_end: int = 1
    ) -> str:
        """
        Mask email address preserving domain.

        Args:
            email: Email address to mask
            visible_start: Number of characters to show at start of local part
            visible_end: Number of characters to show at end of local part

        Returns:
            str: Masked email address
        """
        if not isinstance(email, str) or "@" not in email:
            return self.mask_char * 8

        try:
            local, domain = email.split("@", 1)

            if len(local) <= visible_start + visible_end:
                masked_local = self.mask_char * len(local)
            else:
                start = local[:visible_start]
                end = local[-visible_end:] if visible_end > 0 else ""
                middle_length = len(local) - visible_start - visible_end
                middle = self.mask_char * middle_length
                masked_local = start + middle + end

        except Exception:
            return self.mask_char * 8
        else:
            return f"{masked_local}@{domain}"

    def mask_phone(
        self, phone: str, visible_start: int = 3, visible_end: int = 2
    ) -> str:
        """
        Mask phone number keeping country code and last digits.

        Args:
            phone: Phone number to mask
            visible_start: Number of digits to show at start
            visible_end: Number of digits to show at end

        Returns:
            str: Masked phone number
        """
        if not isinstance(phone, str):
            return self.mask_char * 10

        # Extract digits only
        digits = re.sub(r"\D", "", phone)

        if len(digits) <= visible_start + visible_end:
            return self.mask_char * len(digits)

        start = digits[:visible_start]
        end = digits[-visible_end:] if visible_end > 0 else ""
        middle_length = len(digits) - visible_start - visible_end
        middle = self.mask_char * middle_length

        return start + middle + end

    def mask_credit_card(self, card_number: str) -> str:
        """
        Mask credit card number showing first 4 and last 4 digits.

        Args:
            card_number: Credit card number to mask

        Returns:
            str: Masked credit card number
        """
        if not isinstance(card_number, str):
            return self.mask_char * 16

        # Extract digits only
        digits = re.sub(r"\D", "", card_number)

        if len(digits) < 8:
            return self.mask_char * len(digits)

        if len(digits) <= 8:
            # Show first 4 and last 4
            return digits[:4] + self.mask_char * (len(digits) - 8) + digits[-4:]
        # Standard format: 4 visible, middle masked, 4 visible
        return (
            digits[:4]
            + " "
            + self.mask_char * 4
            + " "
            + self.mask_char * 4
            + " "
            + digits[-4:]
        )

    def mask_text(
        self,
        text: str,
        visible_start: int = 0,
        visible_end: int = 0,
        min_mask_length: int = 3,
    ) -> str:
        """
        Mask arbitrary text with configurable visibility.

        Args:
            text: Text to mask
            visible_start: Number of characters to show at start
            visible_end: Number of characters to show at end
            min_mask_length: Minimum number of mask characters

        Returns:
            str: Masked text
        """
        if not isinstance(text, str):
            return self.mask_char * min_mask_length

        if len(text) <= visible_start + visible_end:
            return self.mask_char * max(len(text), min_mask_length)

        start = text[:visible_start] if visible_start > 0 else ""
        end = text[-visible_end:] if visible_end > 0 else ""
        middle_length = max(len(text) - visible_start - visible_end, min_mask_length)
        middle = self.mask_char * middle_length

        return start + middle + end

    def mask_ssn(self, ssn: str) -> str:
        """
        Mask Social Security Number showing only last 4 digits.

        Args:
            ssn: SSN to mask

        Returns:
            str: Masked SSN
        """
        digits = re.sub(r"\D", "", ssn)

        if len(digits) != 9:
            return self.mask_char * 9

        return f"XXX-XX-{digits[-4:]}"

    def mask_json_fields(
        self, data: dict[str, Any], sensitive_fields: list[str]
    ) -> dict[str, Any]:
        """
        Mask sensitive fields in JSON/dict data.

        Args:
            data: Dictionary data to mask
            sensitive_fields: List of field names to mask

        Returns:
            dict[str, Any]: Data with masked sensitive fields
        """
        if not isinstance(data, dict):
            return data

        masked_data = data.copy()

        for field in sensitive_fields:
            if field in masked_data:
                value = masked_data[field]

                if isinstance(value, str):
                    if "@" in value:
                        masked_data[field] = self.mask_email(value)
                    elif value.isdigit() and len(value) >= 9:
                        masked_data[field] = self.mask_phone(value)
                    else:
                        masked_data[field] = self.mask_text(
                            value, visible_start=2, visible_end=1
                        )
                else:
                    masked_data[field] = f"[{type(value).__name__}]"

        return masked_data


# =====================================================================================
# SECURITY AUDIT SERVICE
# =====================================================================================


class SecurityAuditService:
    """
    Security audit and event logging service.

    Provides comprehensive security event logging and audit functionality
    using the shared security enums for consistent event classification.
    """

    def __init__(self, config: SecurityConfig):
        """
        Initialize security audit service.

        Args:
            config: Security configuration
        """
        self.config = config
        self._events_logged = 0

    def log_security_event(
        self,
        event_type: SecurityEventType,
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
        threat_level: ThreatLevel = ThreatLevel.LOW,
        session_type: SessionType | None = None,
    ) -> None:
        """
        Log a security event.

        Args:
            event_type: Type of security event
            user_id: Optional user ID associated with event
            details: Optional additional event details
            threat_level: Assessed threat level
            session_type: Optional session type
        """
        event_data = {
            "event_type": event_type.value,
            "user_id": user_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "threat_level": threat_level.value,
            "threat_score": threat_level.score,
            "session_type": session_type.value if session_type else None,
            "details": details or {},
            "requires_attention": threat_level.requires_immediate_action,
            "triggers_alert": threat_level.triggers_alerting,
        }

        # Log the event
        if threat_level.requires_immediate_action:
            logger.critical("Security event requires immediate attention", **event_data)
        elif threat_level.triggers_alerting:
            logger.warning("Security event triggered alert", **event_data)
        else:
            logger.info("Security event logged", **event_data)

        self._events_logged += 1

    def assess_threat_level(
        self, event_type: SecurityEventType, context: dict[str, Any] | None = None
    ) -> ThreatLevel:
        """
        Assess threat level for a security event.

        Args:
            event_type: Type of security event
            context: Optional context information

        Returns:
            ThreatLevel: Assessed threat level
        """
        # Default threat levels by event type
        threat_mapping = {
            SecurityEventType.LOGIN_SUCCESS: ThreatLevel.MINIMAL,
            SecurityEventType.LOGIN_FAILURE: ThreatLevel.LOW,
            SecurityEventType.LOGOUT: ThreatLevel.MINIMAL,
            SecurityEventType.PASSWORD_CHANGE: ThreatLevel.LOW,
            SecurityEventType.PASSWORD_RESET: ThreatLevel.MEDIUM,
            SecurityEventType.ACCOUNT_LOCKED: ThreatLevel.HIGH,
            SecurityEventType.ACCOUNT_UNLOCKED: ThreatLevel.MEDIUM,
            SecurityEventType.MFA_ENABLED: ThreatLevel.LOW,
            SecurityEventType.MFA_DISABLED: ThreatLevel.MEDIUM,
            SecurityEventType.PERMISSION_GRANTED: ThreatLevel.MEDIUM,
            SecurityEventType.PERMISSION_REVOKED: ThreatLevel.MEDIUM,
            SecurityEventType.DATA_ACCESS: ThreatLevel.LOW,
            SecurityEventType.DATA_MODIFICATION: ThreatLevel.MEDIUM,
            SecurityEventType.SUSPICIOUS_ACTIVITY: ThreatLevel.HIGH,
            SecurityEventType.SECURITY_VIOLATION: ThreatLevel.CRITICAL,
        }

        base_threat = threat_mapping.get(event_type, ThreatLevel.MEDIUM)

        # Adjust threat level based on context
        if context:
            # Multiple failed attempts increase threat level
            if event_type == SecurityEventType.LOGIN_FAILURE:
                attempt_count = context.get("attempt_count", 1)
                if attempt_count >= 5:
                    return ThreatLevel.HIGH
                if attempt_count >= 3:
                    return ThreatLevel.MEDIUM

            # Admin actions have higher threat levels
            if context.get("is_admin_action") and base_threat.score < ThreatLevel.MEDIUM.score:
                return ThreatLevel.MEDIUM

        return base_threat

    def get_statistics(self) -> dict[str, Any]:
        """Get security audit statistics."""
        return {
            "events_logged": self._events_logged,
            "audit_login_events": self.config.audit_login_events,
            "audit_permission_changes": self.config.audit_permission_changes,
            "audit_data_access": self.config.audit_data_access,
            "retention_days": self.config.security_event_retention_days,
        }


# =====================================================================================
# MAIN SECURITY SERVICE
# =====================================================================================


class SecurityService:
    """
    Main security service coordinating all security operations.

    Provides a unified interface to all security services with
    consistent configuration and comprehensive functionality.

    Design Features:
    - Unified security service interface
    - Consistent configuration management
    - Performance monitoring across all services
    - Comprehensive error handling
    - Audit logging and compliance

    Usage Example:
        from app.core.config import settings
        security_service = SecurityService(settings.security)

        # Password operations
        hashed = security_service.hash_password("password123")
        is_valid = security_service.verify_password("password123", hashed)

        # Token operations
        token = security_service.create_access_token("user123")
        payload = security_service.decode_access_token(token)

        # Masking operations
        masked = security_service.mask_email("user@example.com")
    """

    def __init__(self, config: SecurityConfig):
        """
        Initialize security service with configuration.

        Args:
            config: Security configuration from main config
        """
        self.config = config

        # Initialize sub-services
        self.password_service = PasswordService(config)
        self.token_service = TokenService(config)
        self.cryptography_service = CryptographyService(config)
        self.masking_service = MaskingService()
        self.audit_service = SecurityAuditService(config)

        logger.info(
            "Security service initialized",
            password_algorithm=config.password_algorithm.value,
            jwt_algorithm=config.jwt_algorithm.value,
            access_token_expire_minutes=config.access_token_expire_minutes,
            mfa_enabled_by_default=config.mfa_enabled_by_default,
            audit_enabled=config.audit_login_events,
        )

    # Password service delegation
    def hash_password(self, password: str) -> str:
        """Hash password using configured algorithm."""
        return self.password_service.hash_password(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return self.password_service.verify_password(password, hashed)

    def calculate_password_strength(self, password: str) -> dict[str, Any]:
        """Calculate password strength with shared enums."""
        return self.password_service.calculate_strength(password)

    # Token service delegation
    def create_access_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create JWT access token."""
        return self.token_service.create_access_token(
            subject, expires_delta, additional_claims
        )

    def create_refresh_token(
        self,
        subject: str,
        expires_delta: timedelta | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create JWT refresh token."""
        return self.token_service.create_refresh_token(
            subject, expires_delta, additional_claims
        )

    def decode_access_token(self, token: str) -> dict[str, Any]:
        """Decode and validate access token."""
        return self.token_service.decode_access_token(token)

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        """Decode and validate refresh token."""
        return self.token_service.decode_refresh_token(token)

    def generate_secure_token(self, nbytes: int | None = None) -> str:
        """Generate secure random token."""
        return self.token_service.generate_secure_token(nbytes)

    def generate_verification_code(self, length: int | None = None) -> str:
        """Generate verification code."""
        return self.token_service.generate_verification_code(length)

    def generate_api_key(self, prefix: str | None = None) -> str:
        """Generate API key."""
        return self.token_service.generate_api_key(prefix)

    # Cryptography service delegation
    def generate_salt(self, length: int = 32) -> bytes:
        """Generate cryptographic salt."""
        return self.cryptography_service.generate_salt(length)

    def derive_key(self, password: str, salt: bytes, length: int = 32) -> bytes:
        """Derive encryption key from password."""
        return self.cryptography_service.derive_key(password, salt, length)

    def constant_time_compare(self, a: str, b: str) -> bool:
        """Compare strings in constant time."""
        return self.cryptography_service.constant_time_compare(a, b)

    # Masking service delegation
    def mask_email(self, email: str) -> str:
        """Mask email address."""
        return self.masking_service.mask_email(email)

    def mask_phone(self, phone: str) -> str:
        """Mask phone number."""
        return self.masking_service.mask_phone(phone)

    def mask_credit_card(self, card_number: str) -> str:
        """Mask credit card number."""
        return self.masking_service.mask_credit_card(card_number)

    def mask_json_fields(
        self, data: dict[str, Any], sensitive_fields: list[str]
    ) -> dict[str, Any]:
        """Mask sensitive fields in JSON data."""
        return self.masking_service.mask_json_fields(data, sensitive_fields)

    # Audit service delegation
    def log_security_event(
        self,
        event_type: SecurityEventType,
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
        threat_level: ThreatLevel = ThreatLevel.LOW,
        session_type: SessionType | None = None,
    ) -> None:
        """Log security event."""
        self.audit_service.log_security_event(
            event_type, user_id, details, threat_level, session_type
        )

    def assess_threat_level(
        self, event_type: SecurityEventType, context: dict[str, Any] | None = None
    ) -> ThreatLevel:
        """Assess threat level for security event."""
        return self.audit_service.assess_threat_level(event_type, context)

    # Configuration access
    def get_password_policy(self) -> dict[str, Any]:
        """Get password policy configuration."""
        return self.config.get_password_policy()

    def get_session_config(self) -> dict[str, Any]:
        """Get session configuration."""
        return self.config.get_session_config()

    def get_mfa_config(self) -> dict[str, Any]:
        """Get MFA configuration."""
        return self.config.get_mfa_config()

    def get_comprehensive_stats(self) -> dict[str, Any]:
        """Get comprehensive statistics from all security services."""
        return {
            "config": {
                "password_algorithm": self.config.password_algorithm.value,
                "jwt_algorithm": self.config.jwt_algorithm.value,
                "encryption_algorithm": self.config.encryption_algorithm.value,
                "access_token_expire_minutes": self.config.access_token_expire_minutes,
                "refresh_token_expire_days": self.config.refresh_token_expire_days,
                "mfa_enabled_by_default": self.config.mfa_enabled_by_default,
                "require_strong_passwords": self.config.require_strong_passwords,
            },
            "password_service": self.password_service.get_performance_stats(),
            "token_service": self.token_service.get_statistics(),
            "cryptography_service": self.cryptography_service.get_statistics(),
            "audit_service": self.audit_service.get_statistics(),
        }


# =====================================================================================
# CONVENIENCE FACTORY FUNCTION
# =====================================================================================


def create_security_service(config: SecurityConfig) -> SecurityService:
    """
    Factory function to create SecurityService instance.

    Args:
        config: Security configuration

    Returns:
        SecurityService: Initialized security service
    """
    return SecurityService(config)


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "CryptographyService",
    "MaskingService",
    # Individual services
    "PasswordService",
    "SecurityAuditService",
    # Main service
    "SecurityService",
    "TokenService",
    # Factory function
    "create_security_service",
]
