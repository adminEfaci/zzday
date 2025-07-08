"""
Test cases for Token value object.

Tests JWT tokens, refresh tokens, session tokens, and security features.
"""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.modules.identity.domain.value_objects.token import (
    Token,
    TokenStatus,
    TokenType,
)


class TestTokenCreation:
    """Test Token creation and validation."""

    def test_create_valid_token(self):
        """Test creating a valid token."""
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_payload.signature",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=expires_at,
            subject="user_123",
            audience="ezzday_api",
        )

        assert token.value.startswith("eyJ")
        assert token.token_type == TokenType.ACCESS_TOKEN
        assert token.expires_at == expires_at
        assert token.subject == "user_123"
        assert token.audience == "ezzday_api"

    def test_empty_value_raises_error(self):
        """Test that empty token value raises ValueError."""
        with pytest.raises(ValueError, match="Token value is required"):
            Token(
                value="",
                token_type=TokenType.ACCESS_TOKEN,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )

    def test_invalid_jwt_format_raises_error(self):
        """Test that invalid JWT format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid JWT token format"):
            Token(
                value="invalid.token.format.too.many.parts",
                token_type=TokenType.ACCESS_TOKEN,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )


class TestTokenGeneration:
    """Test token generation methods."""

    def test_generate_access_token(self):
        """Test generating access token."""
        token = Token.generate_access_token(
            subject="user_123", audience="ezzday_api", expires_in_minutes=30
        )

        assert token.token_type == TokenType.ACCESS_TOKEN
        assert token.subject == "user_123"
        assert token.audience == "ezzday_api"
        assert token.expires_at > datetime.now(UTC)

    def test_generate_refresh_token(self):
        """Test generating refresh token."""
        token = Token.generate_refresh_token(subject="user_123", expires_in_days=7)

        assert token.token_type == TokenType.REFRESH_TOKEN
        assert token.subject == "user_123"


class TestTokenProperties:
    """Test token properties and validation."""

    def test_is_expired_false(self):
        """Test token that is not expired."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert token.is_expired is False

    def test_is_expired_true(self):
        """Test expired token."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        assert token.is_expired is True

    def test_time_until_expiry(self):
        """Test time until expiry calculation."""
        expires_at = datetime.now(UTC) + timedelta(hours=2)
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=expires_at,
        )

        time_left = token.time_until_expiry
        assert time_left.total_seconds() > 7000  # About 2 hours


class TestTokenVerification:
    """Test token verification and validation."""

    def test_verify_signature_valid(self):
        """Test verifying valid token signature."""
        secret = "test_secret_key"
        payload = {
            "sub": "user_123",
            "exp": (datetime.now(UTC) + timedelta(hours=1)).timestamp(),
        }
        jwt_token = jwt.encode(payload, secret, algorithm="HS256")

        token = Token(
            value=jwt_token,
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert token.verify_signature(secret) is True

    def test_verify_signature_invalid(self):
        """Test verifying invalid token signature."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert token.verify_signature("wrong_secret") is False

    def test_decode_payload(self):
        """Test decoding token payload."""
        secret = "test_secret_key"
        payload = {
            "sub": "user_123",
            "aud": "ezzday_api",
            "exp": (datetime.now(UTC) + timedelta(hours=1)).timestamp(),
            "roles": ["user", "admin"],
        }
        jwt_token = jwt.encode(payload, secret, algorithm="HS256")

        token = Token(
            value=jwt_token,
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        decoded = token.decode_payload(secret)
        assert decoded["sub"] == "user_123"
        assert decoded["aud"] == "ezzday_api"
        assert decoded["roles"] == ["user", "admin"]

    def test_get_claims(self):
        """Test extracting token claims."""
        secret = "test_secret_key"
        payload = {
            "sub": "user_123",
            "aud": "ezzday_api",
            "iss": "ezzday_auth",
            "jti": "token_id_123",
            "scope": "read write",
        }
        jwt_token = jwt.encode(payload, secret, algorithm="HS256")

        token = Token(
            value=jwt_token,
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        claims = token.get_claims(secret)
        assert claims.subject == "user_123"
        assert claims.audience == "ezzday_api"
        assert claims.issuer == "ezzday_auth"
        assert claims.jti == "token_id_123"
        assert claims.scope == "read write"


class TestTokenSecurity:
    """Test token security features."""

    def test_token_immutability(self):
        """Test that tokens are immutable."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        with pytest.raises(FrozenInstanceError):
            token.value = "modified"

        with pytest.raises(FrozenInstanceError):
            token.token_type = TokenType.REFRESH_TOKEN

    def test_secure_comparison(self):
        """Test secure token value comparison."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        # Secure comparison should work
        assert (
            token.secure_compare("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig")
            is True
        )
        assert token.secure_compare("different_token") is False

    def test_get_masked_value(self):
        """Test getting masked token value for logging."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.very_long_payload_content.signature",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        masked = token.get_masked_value()

        # Should not contain full token
        assert "very_long_payload_content" not in masked
        assert "****" in masked or "..." in masked
        assert len(masked) < len(token.value)


class TestTokenStatus:
    """Test token status management."""

    def test_revoke_token(self):
        """Test token revocation."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=TokenStatus.ACTIVE,
        )

        revoked_token = token.revoke(reason="User logout")

        assert revoked_token.status == TokenStatus.REVOKED
        assert revoked_token.revoked_at is not None
        assert revoked_token.revocation_reason == "User logout"

    def test_mark_used(self):
        """Test marking token as used."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.REFRESH_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            status=TokenStatus.ACTIVE,
        )

        used_token = token.mark_used()

        assert used_token.status == TokenStatus.USED
        assert used_token.used_at is not None
        assert used_token.use_count == 1

    def test_is_valid_active_token(self):
        """Test validation of active token."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=TokenStatus.ACTIVE,
        )

        assert token.is_valid is True

    def test_is_valid_revoked_token(self):
        """Test validation of revoked token."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=TokenStatus.REVOKED,
        )

        assert token.is_valid is False

    def test_is_valid_expired_token(self):
        """Test validation of expired token."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            status=TokenStatus.ACTIVE,
        )

        assert token.is_valid is False


class TestTokenMetadata:
    """Test token metadata and claims."""

    def test_get_metadata(self):
        """Test getting token metadata."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            subject="user_123",
            audience="ezzday_api",
            issuer="ezzday_auth",
            scope="read write delete",
            jti="token_id_123",
        )

        metadata = token.get_metadata()

        assert metadata["token_type"] == "access_token"
        assert metadata["subject"] == "user_123"
        assert metadata["audience"] == "ezzday_api"
        assert metadata["issuer"] == "ezzday_auth"
        assert metadata["scope"] == "read write delete"
        assert metadata["jti"] == "token_id_123"
        assert "expires_at" in metadata
        assert "issued_at" in metadata

    def test_has_scope(self):
        """Test scope checking."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="read write admin:users",
        )

        assert token.has_scope("read") is True
        assert token.has_scope("write") is True
        assert token.has_scope("admin:users") is True
        assert token.has_scope("delete") is False

    def test_has_all_scopes(self):
        """Test checking multiple scopes."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="read write admin:users",
        )

        assert token.has_all_scopes(["read", "write"]) is True
        assert token.has_all_scopes(["read", "delete"]) is False


class TestTokenTypes:
    """Test different token type behaviors."""

    def test_access_token_properties(self):
        """Test access token specific properties."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert token.is_access_token is True
        assert token.is_refresh_token is False
        assert token.is_short_lived is True

    def test_refresh_token_properties(self):
        """Test refresh token specific properties."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.REFRESH_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )

        assert token.is_refresh_token is True
        assert token.is_access_token is False
        assert token.is_long_lived is True

    def test_session_token_properties(self):
        """Test session token specific properties."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.SESSION_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=8),
        )

        assert token.is_session_token is True
        assert token.is_medium_lived is True


class TestTokenUtilities:
    """Test token utility methods."""

    def test_get_fingerprint(self):
        """Test getting token fingerprint for tracking."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        fingerprint = token.get_fingerprint()

        assert len(fingerprint) == 16  # Short hash for tracking
        assert fingerprint.isalnum()

        # Same token should have same fingerprint
        assert fingerprint == token.get_fingerprint()

    def test_to_audit_log(self):
        """Test creating audit log entry."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            subject="user_123",
            audience="ezzday_api",
        )

        audit_entry = token.to_audit_log()

        assert audit_entry["token_id"] == token.get_fingerprint()
        assert audit_entry["token_type"] == "access_token"
        assert audit_entry["subject"] == "user_123"
        assert audit_entry["audience"] == "ezzday_api"
        assert "value" not in audit_entry  # Never log token value
        assert "expires_at" in audit_entry

    def test_extract_header_algorithm(self):
        """Test extracting algorithm from JWT header."""
        # Create a token with specific algorithm
        secret = "test_secret"
        payload = {"sub": "user_123"}
        jwt_token = jwt.encode(payload, secret, algorithm="HS512")

        token = Token(
            value=jwt_token,
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        algorithm = token.extract_header_algorithm()
        assert algorithm == "HS512"


class TestTokenRefresh:
    """Test token refresh functionality."""

    def test_create_refresh_payload(self):
        """Test creating refresh token payload."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            subject="user_123",
            audience="ezzday_api",
        )

        refresh_payload = token.create_refresh_payload()

        assert refresh_payload["sub"] == "user_123"
        assert refresh_payload["aud"] == "ezzday_api"
        assert refresh_payload["token_type"] == "refresh"
        assert "exp" in refresh_payload
        assert "iat" in refresh_payload

    def test_refresh_from_token(self):
        """Test creating new access token from refresh token."""
        refresh_token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh.sig",
            token_type=TokenType.REFRESH_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(days=7),
            subject="user_123",
            audience="ezzday_api",
        )

        new_access_token = Token.from_refresh_token(
            refresh_token=refresh_token, expires_in_minutes=30
        )

        assert new_access_token.token_type == TokenType.ACCESS_TOKEN
        assert new_access_token.subject == "user_123"
        assert new_access_token.audience == "ezzday_api"
        assert new_access_token.value != refresh_token.value


class TestTokenEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_token_with_no_expiry(self):
        """Test token without expiration."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.API_KEY,
            expires_at=None,  # No expiration
        )

        assert token.is_expired is False
        assert token.time_until_expiry is None
        assert token.is_permanent is True

    def test_token_just_expired(self):
        """Test token that just expired."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.ACCESS_TOKEN,
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )

        assert token.is_expired is True
        assert token.is_valid is False

    def test_very_long_lived_token(self):
        """Test very long-lived token."""
        token = Token(
            value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig",
            token_type=TokenType.API_KEY,
            expires_at=datetime.now(UTC) + timedelta(days=3650),  # 10 years
        )

        assert token.is_long_lived is True
        assert token.time_until_expiry.days > 3649
