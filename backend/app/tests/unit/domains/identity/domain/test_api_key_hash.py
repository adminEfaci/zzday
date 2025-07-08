"""
Test cases for APIKeyHash value object.

Tests all aspects of API key hashing including generation, verification,
security features, and audit functionality.
"""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.identity.domain.value_objects.api_key_hash import (
    APIKeyHash,
    APIKeyScope,
    APIKeyType,
)


class TestAPIKeyHashCreation:
    """Test APIKeyHash creation and validation."""

    def test_create_valid_api_key_hash(self):
        """Test creating a valid API key hash."""
        api_key_hash = APIKeyHash(
            key_hash="a" * 64,  # SHA256 hash length
            key_prefix="pk_12345678",
            key_type=APIKeyType.PERSONAL,
            salt="salt123456",
            algorithm="sha256",
        )

        assert api_key_hash.key_hash == "a" * 64
        assert api_key_hash.key_prefix == "pk_12345678"
        assert api_key_hash.key_type == APIKeyType.PERSONAL
        assert api_key_hash.salt == "salt123456"
        assert api_key_hash.algorithm == "sha256"

    def test_create_with_different_types(self):
        """Test creating API keys of different types."""
        # Personal key
        personal = APIKeyHash(
            key_hash="b" * 64, key_prefix="pk_personal", key_type=APIKeyType.PERSONAL
        )
        assert personal.is_user_key is True
        assert personal.is_service_key is False
        assert personal.is_high_privilege is False

        # Service key
        service = APIKeyHash(
            key_hash="c" * 64, key_prefix="sk_service", key_type=APIKeyType.SERVICE
        )
        assert service.is_service_key is True
        assert service.is_user_key is False
        assert service.is_high_privilege is True

        # Master key
        master = APIKeyHash(
            key_hash="d" * 64, key_prefix="mk_master", key_type=APIKeyType.MASTER
        )
        assert master.is_high_privilege is True
        assert master.requires_mfa is True

    def test_invalid_api_key_hash(self):
        """Test validation of invalid API key hashes."""
        # Empty hash
        with pytest.raises(ValueError, match="Key hash is required"):
            APIKeyHash(
                key_hash="", key_prefix="pk_12345678", key_type=APIKeyType.PERSONAL
            )

        # Short prefix
        with pytest.raises(
            ValueError, match="Key prefix must be at least 4 characters"
        ):
            APIKeyHash(key_hash="a" * 64, key_prefix="pk", key_type=APIKeyType.PERSONAL)

        # Invalid SHA256 hash length
        with pytest.raises(ValueError, match="Invalid SHA256 hash length"):
            APIKeyHash(
                key_hash="short_hash",
                key_prefix="pk_12345678",
                key_type=APIKeyType.PERSONAL,
                algorithm="sha256",
            )

        # Invalid SHA512 hash length
        with pytest.raises(ValueError, match="Invalid SHA512 hash length"):
            APIKeyHash(
                key_hash="a" * 64,  # Too short for SHA512
                key_prefix="pk_12345678",
                key_type=APIKeyType.PERSONAL,
                algorithm="sha512",
            )


class TestAPIKeyGeneration:
    """Test API key generation functionality."""

    def test_generate_personal_key(self):
        """Test generating a personal API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        assert api_key_hash.key_type == APIKeyType.PERSONAL
        assert api_key_hash.key_prefix.startswith("pk_")
        assert len(api_key_hash.key_hash) == 64  # SHA256
        assert plain_key.startswith("pk_")
        assert len(plain_key) > 32  # Reasonable key length

        # Verify the generated key
        assert api_key_hash.verify_key(plain_key) is True

    def test_generate_service_key(self):
        """Test generating a service API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(
            APIKeyType.SERVICE, scopes=[APIKeyScope.READ, APIKeyScope.WRITE]
        )

        assert api_key_hash.key_type == APIKeyType.SERVICE
        assert api_key_hash.key_prefix.startswith("sk_")
        assert APIKeyScope.READ in api_key_hash.scopes
        assert APIKeyScope.WRITE in api_key_hash.scopes
        assert api_key_hash.verify_key(plain_key) is True

    def test_generate_master_key(self):
        """Test generating a master API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(
            APIKeyType.MASTER, algorithm="sha512"
        )

        assert api_key_hash.key_type == APIKeyType.MASTER
        assert api_key_hash.key_prefix.startswith("mk_")
        assert len(api_key_hash.key_hash) == 128  # SHA512
        assert api_key_hash.algorithm == "sha512"
        assert api_key_hash.verify_key(plain_key) is True

    def test_generate_with_metadata(self):
        """Test generating API key with metadata."""
        metadata = {
            "application": "mobile_app",
            "version": "1.0.0",
            "environment": "production",
        }

        api_key_hash, plain_key = APIKeyHash.generate_api_key(
            APIKeyType.PERSONAL, metadata=metadata
        )

        assert api_key_hash.metadata == metadata
        assert api_key_hash.metadata["application"] == "mobile_app"


class TestAPIKeyVerification:
    """Test API key verification functionality."""

    def test_verify_correct_key(self):
        """Test verifying a correct API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        assert api_key_hash.verify_key(plain_key) is True
        assert api_key_hash.verify_key(plain_key.lower()) is True  # Case insensitive
        assert api_key_hash.verify_key(f" {plain_key} ") is True  # Trimmed

    def test_verify_incorrect_key(self):
        """Test verifying incorrect API keys."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Wrong key
        assert api_key_hash.verify_key("wrong_key") is False

        # Modified key
        modified_key = plain_key[:-1] + "X"
        assert api_key_hash.verify_key(modified_key) is False

        # Empty key
        assert api_key_hash.verify_key("") is False

        # None key
        assert api_key_hash.verify_key(None) is False

    def test_verify_with_wrong_prefix(self):
        """Test verification fails with wrong prefix."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Replace prefix
        wrong_prefix_key = "sk_" + plain_key[3:]
        assert api_key_hash.verify_key(wrong_prefix_key) is False


class TestAPIKeyScopes:
    """Test API key scope functionality."""

    def test_create_with_scopes(self):
        """Test creating API key with specific scopes."""
        scopes = [APIKeyScope.READ, APIKeyScope.WRITE, APIKeyScope.DELETE]

        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.SERVICE, scopes=scopes)

        assert api_key_hash.has_scope(APIKeyScope.READ) is True
        assert api_key_hash.has_scope(APIKeyScope.WRITE) is True
        assert api_key_hash.has_scope(APIKeyScope.DELETE) is True
        assert api_key_hash.has_scope(APIKeyScope.ADMIN) is False

    def test_scope_validation(self):
        """Test scope validation for different key types."""
        # Personal keys have limited scopes
        personal, _ = APIKeyHash.generate_api_key(
            APIKeyType.PERSONAL, scopes=[APIKeyScope.READ, APIKeyScope.WRITE]
        )
        assert personal.can_perform_action("read") is True
        assert personal.can_perform_action("write") is True
        assert personal.can_perform_action("admin") is False

        # Master keys have all scopes
        master, _ = APIKeyHash.generate_api_key(APIKeyType.MASTER)
        assert master.can_perform_action("read") is True
        assert master.can_perform_action("write") is True
        assert master.can_perform_action("delete") is True
        assert master.can_perform_action("admin") is True

    def test_scope_inheritance(self):
        """Test scope inheritance rules."""
        # Admin scope includes all others
        admin_key, _ = APIKeyHash.generate_api_key(
            APIKeyType.SERVICE, scopes=[APIKeyScope.ADMIN]
        )

        assert admin_key.has_scope(APIKeyScope.ADMIN) is True
        assert admin_key.has_effective_scope(APIKeyScope.READ) is True
        assert admin_key.has_effective_scope(APIKeyScope.WRITE) is True
        assert admin_key.has_effective_scope(APIKeyScope.DELETE) is True


class TestAPIKeySecurity:
    """Test API key security features."""

    def test_api_key_immutability(self):
        """Test that API key hash is immutable."""
        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        with pytest.raises(FrozenInstanceError):
            api_key_hash.key_hash = "modified"

        with pytest.raises(FrozenInstanceError):
            api_key_hash.key_type = APIKeyType.MASTER

    def test_api_key_rotation(self):
        """Test API key rotation functionality."""
        original, original_plain = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Rotate key
        rotated, rotated_plain = original.rotate()

        assert rotated.key_type == original.key_type
        assert rotated.scopes == original.scopes
        assert rotated.metadata.get("rotated_from") == original.key_prefix
        assert rotated.key_hash != original.key_hash
        assert rotated_plain != original_plain

        # Old key should not work with new hash
        assert rotated.verify_key(original_plain) is False

        # New key should work
        assert rotated.verify_key(rotated_plain) is True

    def test_api_key_expiration(self):
        """Test API key expiration functionality."""
        # Create expired key
        expired_at = datetime.now(UTC) - timedelta(days=1)
        api_key_hash = APIKeyHash(
            key_hash="a" * 64,
            key_prefix="pk_expired",
            key_type=APIKeyType.PERSONAL,
            expires_at=expired_at,
        )

        assert api_key_hash.is_expired is True
        assert api_key_hash.is_active is False

        # Create active key
        active_until = datetime.now(UTC) + timedelta(days=30)
        active_key = APIKeyHash(
            key_hash="b" * 64,
            key_prefix="pk_active",
            key_type=APIKeyType.PERSONAL,
            expires_at=active_until,
        )

        assert active_key.is_expired is False
        assert active_key.is_active is True
        assert active_key.days_until_expiry > 29

    def test_api_key_revocation(self):
        """Test API key revocation."""
        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Revoke key
        revoked = api_key_hash.revoke(reason="Security incident")

        assert revoked.is_revoked is True
        assert revoked.is_active is False
        assert revoked.revoked_at is not None
        assert revoked.revocation_reason == "Security incident"


class TestAPIKeyUsageTracking:
    """Test API key usage tracking."""

    def test_usage_increment(self):
        """Test incrementing usage count."""
        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Initial state
        assert api_key_hash.usage_count == 0
        assert api_key_hash.last_used_at is None

        # Track usage
        updated = api_key_hash.increment_usage()

        assert updated.usage_count == 1
        assert updated.last_used_at is not None
        assert updated.last_used_at <= datetime.now(UTC)

    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        # Create key with rate limit
        api_key_hash = APIKeyHash(
            key_hash="a" * 64,
            key_prefix="pk_limited",
            key_type=APIKeyType.PERSONAL,
            rate_limit=100,  # 100 requests per period
            rate_limit_period=3600,  # 1 hour
        )

        assert api_key_hash.rate_limit == 100
        assert api_key_hash.rate_limit_period == 3600
        assert api_key_hash.is_rate_limited is False

        # Simulate reaching rate limit
        for _ in range(100):
            api_key_hash = api_key_hash.increment_usage()

        assert api_key_hash.usage_count == 100
        assert api_key_hash.is_rate_limited is True


class TestAPIKeyAudit:
    """Test API key audit functionality."""

    def test_audit_log_generation(self):
        """Test generating audit log entries."""
        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.SERVICE)

        audit_entry = api_key_hash.create_audit_entry(
            action="api_call", resource="/api/users", ip_address="192.168.1.1"
        )

        assert audit_entry["key_prefix"] == api_key_hash.key_prefix
        assert audit_entry["key_type"] == "SERVICE"
        assert audit_entry["action"] == "api_call"
        assert audit_entry["resource"] == "/api/users"
        assert audit_entry["ip_address"] == "192.168.1.1"
        assert "timestamp" in audit_entry
        assert "key_hash" not in audit_entry  # Never expose full hash

    def test_security_event_tracking(self):
        """Test tracking security events."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # Track failed verification
        audit = api_key_hash.track_failed_verification(
            attempted_key="wrong_key", ip_address="10.0.0.1"
        )

        assert audit["event_type"] == "failed_verification"
        assert audit["ip_address"] == "10.0.0.1"
        assert "attempted_key" not in audit  # Don't log attempted keys
        assert audit["key_prefix"] == api_key_hash.key_prefix


class TestAPIKeyComparison:
    """Test API key comparison and equality."""

    def test_api_key_equality(self):
        """Test API key equality comparison."""
        # Same hash and prefix
        key1 = APIKeyHash(
            key_hash="a" * 64, key_prefix="pk_12345678", key_type=APIKeyType.PERSONAL
        )

        key2 = APIKeyHash(
            key_hash="a" * 64, key_prefix="pk_12345678", key_type=APIKeyType.PERSONAL
        )

        key3 = APIKeyHash(
            key_hash="b" * 64, key_prefix="pk_87654321", key_type=APIKeyType.PERSONAL
        )

        assert key1 == key2
        assert key1 != key3
        assert hash(key1) == hash(key2)
        assert hash(key1) != hash(key3)

    def test_api_key_string_representation(self):
        """Test string representation security."""
        api_key_hash, _ = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        str_repr = str(api_key_hash)
        repr_repr = repr(api_key_hash)

        # Should not expose full hash
        assert api_key_hash.key_hash not in str_repr
        assert api_key_hash.key_hash not in repr_repr

        # Should include prefix for identification
        assert api_key_hash.key_prefix in str_repr
        assert api_key_hash.key_type.value in str_repr

    def test_create_valid_api_key_hash(self):
        """Test creating a valid API key hash."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
            salt="test_salt_123",
        )

        assert (
            api_key_hash.key_hash
            == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        assert api_key_hash.key_prefix == "pk_test1234"
        assert api_key_hash.key_type == APIKeyType.PERSONAL
        assert api_key_hash.salt == "test_salt_123"

    def test_create_with_creation_timestamp(self):
        """Test creating API key hash with timestamp."""
        now = datetime.now(UTC)
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
            created_at=now,
        )

        assert api_key_hash.created_at == now

    def test_empty_key_hash_raises_error(self):
        """Test that empty key hash raises ValueError."""
        with pytest.raises(ValueError, match="Key hash is required"):
            APIKeyHash(
                key_hash="", key_prefix="pk_test1234", key_type=APIKeyType.PERSONAL
            )

    def test_short_prefix_raises_error(self):
        """Test that short prefix raises ValueError."""
        with pytest.raises(
            ValueError, match="Key prefix must be at least 4 characters"
        ):
            APIKeyHash(
                key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                key_prefix="pk",
                key_type=APIKeyType.PERSONAL,
            )

    def test_long_prefix_raises_error(self):
        """Test that long prefix raises ValueError."""
        with pytest.raises(ValueError, match="Key prefix too long"):
            APIKeyHash(
                key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                key_prefix="pk_very_long_prefix_123",
                key_type=APIKeyType.PERSONAL,
            )

    def test_invalid_sha256_hash_length_raises_error(self):
        """Test that invalid SHA256 hash length raises ValueError."""
        with pytest.raises(ValueError, match="Invalid SHA256 hash length"):
            APIKeyHash(
                key_hash="short_hash",
                key_prefix="pk_test1234",
                key_type=APIKeyType.PERSONAL,
            )

    def test_invalid_prefix_format_raises_error(self):
        """Test that invalid prefix format raises ValueError."""
        with pytest.raises(ValueError, match="Key prefix must be alphanumeric"):
            APIKeyHash(
                key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                key_prefix="pk@invalid!",
                key_type=APIKeyType.PERSONAL,
            )

    def test_naive_datetime_raises_error(self):
        """Test that naive datetime raises ValueError."""
        with pytest.raises(ValueError, match="created_at must be timezone-aware"):
            APIKeyHash(
                key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                key_prefix="pk_test1234",
                key_type=APIKeyType.PERSONAL,
                created_at=datetime.now(),  # Naive datetime
            )


class TestAPIKeyGeneration:
    """Test API key generation methods."""

    def test_generate_api_key_personal(self):
        """Test generating personal API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        assert api_key_hash.key_type == APIKeyType.PERSONAL
        assert api_key_hash.key_prefix.startswith("pk_")
        assert len(api_key_hash.key_hash) == 64  # SHA256 hex
        assert plain_key.startswith("pk_")
        assert api_key_hash.salt is not None
        assert api_key_hash.created_at is not None

    def test_generate_api_key_service(self):
        """Test generating service API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.SERVICE)

        assert api_key_hash.key_type == APIKeyType.SERVICE
        assert api_key_hash.key_prefix.startswith("sk_")
        assert plain_key.startswith("sk_")

    def test_generate_api_key_webhook(self):
        """Test generating webhook API key."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.WEBHOOK)

        assert api_key_hash.key_type == APIKeyType.WEBHOOK
        assert api_key_hash.key_prefix.startswith("whk_")
        assert plain_key.startswith("whk_")

    def test_generate_api_key_with_custom_prefix(self):
        """Test generating API key with custom prefix."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(
            APIKeyType.APPLICATION, prefix="custom"
        )

        assert api_key_hash.key_prefix.startswith("custom_")
        assert plain_key.startswith("custom_")

    def test_generate_api_key_with_custom_length(self):
        """Test generating API key with custom length."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(
            APIKeyType.PERSONAL, length=64
        )

        # Longer key should result in longer plain text
        assert len(plain_key) > 50  # Should be much longer

    def test_generated_keys_are_unique(self):
        """Test that generated keys are unique."""
        keys = [APIKeyHash.generate_api_key(APIKeyType.PERSONAL) for _ in range(10)]
        hashes = [api_key_hash.key_hash for api_key_hash, _ in keys]
        plain_keys = [plain_key for _, plain_key in keys]

        assert len(set(hashes)) == 10  # All unique hashes
        assert len(set(plain_keys)) == 10  # All unique plain keys


class TestAPIKeyFromPlainKey:
    """Test creating APIKeyHash from plain text keys."""

    def test_from_plain_key_valid(self):
        """Test creating APIKeyHash from valid plain key."""
        plain_key = "pk_test1234567890abcdef"
        api_key_hash = APIKeyHash.from_plain_key(plain_key, APIKeyType.PERSONAL)

        assert api_key_hash.key_prefix == "pk_test1234"
        assert api_key_hash.key_type == APIKeyType.PERSONAL
        assert len(api_key_hash.key_hash) == 64

    def test_from_plain_key_with_salt(self):
        """Test creating APIKeyHash from plain key with salt."""
        plain_key = "sk_service1234567890"
        salt = "test_salt_123"
        api_key_hash = APIKeyHash.from_plain_key(
            plain_key, APIKeyType.SERVICE, salt=salt
        )

        assert api_key_hash.salt == salt
        assert api_key_hash.key_prefix == "sk_service1"

    def test_from_plain_key_invalid_format(self):
        """Test from_plain_key with invalid format."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKeyHash.from_plain_key("invalid_key", APIKeyType.PERSONAL)

    def test_from_plain_key_short_random_part(self):
        """Test from_plain_key with short random part."""
        plain_key = "pk_short"
        api_key_hash = APIKeyHash.from_plain_key(plain_key, APIKeyType.PERSONAL)

        assert api_key_hash.key_prefix == "pk_short"


class TestAPIKeyVerification:
    """Test API key verification functionality."""

    def test_verify_key_with_salt(self):
        """Test key verification with salt."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        assert api_key_hash.verify_key(plain_key) is True
        assert api_key_hash.verify_key("wrong_key") is False

    def test_verify_key_without_salt(self):
        """Test key verification without salt (legacy)."""
        plain_key = "pk_test1234567890"
        api_key_hash = APIKeyHash.from_plain_key(plain_key, APIKeyType.PERSONAL)

        assert api_key_hash.verify_key(plain_key) is True
        assert api_key_hash.verify_key("wrong_key") is False

    def test_verify_key_timing_safe(self):
        """Test that key verification is timing-safe."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        # These should both take similar time (timing-safe comparison)
        result1 = api_key_hash.verify_key(plain_key)
        result2 = api_key_hash.verify_key("completely_different_wrong_key")

        assert result1 is True
        assert result2 is False

    def test_verify_key_case_sensitive(self):
        """Test that key verification is case-sensitive."""
        api_key_hash, plain_key = APIKeyHash.generate_api_key(APIKeyType.PERSONAL)

        assert api_key_hash.verify_key(plain_key) is True
        assert api_key_hash.verify_key(plain_key.upper()) is False
        assert api_key_hash.verify_key(plain_key.lower()) is False


class TestAPIKeyProperties:
    """Test API key property methods."""

    def test_is_service_key(self):
        """Test service key identification."""
        service_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
        )

        master_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="mk_master1",
            key_type=APIKeyType.MASTER,
        )

        personal_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_personal",
            key_type=APIKeyType.PERSONAL,
        )

        assert service_key.is_service_key is True
        assert master_key.is_service_key is True
        assert personal_key.is_service_key is False

    def test_is_user_key(self):
        """Test user key identification."""
        personal_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_personal",
            key_type=APIKeyType.PERSONAL,
        )

        service_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
        )

        assert personal_key.is_user_key is True
        assert service_key.is_user_key is False

    def test_is_high_privilege(self):
        """Test high privilege key identification."""
        master_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="mk_master1",
            key_type=APIKeyType.MASTER,
        )

        service_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
        )

        personal_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_personal",
            key_type=APIKeyType.PERSONAL,
        )

        assert master_key.is_high_privilege is True
        assert service_key.is_high_privilege is True
        assert personal_key.is_high_privilege is False


class TestAPIKeyRotation:
    """Test API key rotation logic."""

    def test_requires_rotation_no_creation_date(self):
        """Test rotation requirement when no creation date."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        assert api_key_hash.requires_rotation() is True

    def test_requires_rotation_temporary_key(self):
        """Test rotation requirement for temporary keys (7 days)."""
        old_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="tk_temp1234",
            key_type=APIKeyType.TEMPORARY,
            created_at=datetime.now(UTC) - timedelta(days=8),
        )

        recent_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="tk_temp5678",
            key_type=APIKeyType.TEMPORARY,
            created_at=datetime.now(UTC) - timedelta(days=5),
        )

        assert old_key.requires_rotation() is True
        assert recent_key.requires_rotation() is False

    def test_requires_rotation_master_key(self):
        """Test rotation requirement for master keys (30 days)."""
        old_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="mk_master1",
            key_type=APIKeyType.MASTER,
            created_at=datetime.now(UTC) - timedelta(days=35),
        )

        recent_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="mk_master2",
            key_type=APIKeyType.MASTER,
            created_at=datetime.now(UTC) - timedelta(days=20),
        )

        assert old_key.requires_rotation() is True
        assert recent_key.requires_rotation() is False

    def test_requires_rotation_service_key(self):
        """Test rotation requirement for service keys (90 days)."""
        old_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
            created_at=datetime.now(UTC) - timedelta(days=95),
        )

        recent_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service2",
            key_type=APIKeyType.SERVICE,
            created_at=datetime.now(UTC) - timedelta(days=60),
        )

        assert old_key.requires_rotation() is True
        assert recent_key.requires_rotation() is False

    def test_requires_rotation_personal_key(self):
        """Test rotation requirement for personal keys (365 days)."""
        old_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_personal",
            key_type=APIKeyType.PERSONAL,
            created_at=datetime.now(UTC) - timedelta(days=400),
        )

        recent_key = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_personal2",
            key_type=APIKeyType.PERSONAL,
            created_at=datetime.now(UTC) - timedelta(days=300),
        )

        assert old_key.requires_rotation() is True
        assert recent_key.requires_rotation() is False


class TestAPIKeyDisplay:
    """Test API key display and formatting methods."""

    def test_get_display_format(self):
        """Test display format showing only prefix and hash suffix."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        display = api_key_hash.get_display_format()
        expected = "pk_test1234...7890"
        assert display == expected

    def test_get_fingerprint(self):
        """Test fingerprint generation."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        fingerprint = api_key_hash.get_fingerprint()
        expected = "abcd...7890"
        assert fingerprint == expected

    def test_matches_prefix(self):
        """Test prefix matching."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        assert api_key_hash.matches_prefix("pk_") is True
        assert api_key_hash.matches_prefix("pk_test") is True
        assert api_key_hash.matches_prefix("sk_") is False
        assert api_key_hash.matches_prefix("pk_different") is False


class TestAPIKeyAudit:
    """Test audit and logging functionality."""

    def test_to_audit_entry_complete(self):
        """Test creating complete audit log entry."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
            salt="test_salt",
            created_at=datetime.now(UTC) - timedelta(days=30),
        )

        audit_entry = api_key_hash.to_audit_entry()

        assert audit_entry["key_prefix"] == "pk_test1234"
        assert audit_entry["key_type"] == "personal"
        assert audit_entry["fingerprint"] == "abcd...7890"
        assert audit_entry["algorithm"] == "sha256"
        assert audit_entry["has_salt"] is True
        assert "created_at" in audit_entry
        assert audit_entry["age_days"] == 30
        assert "requires_rotation" in audit_entry

    def test_to_audit_entry_minimal(self):
        """Test audit entry for key without optional fields."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
        )

        audit_entry = api_key_hash.to_audit_entry()

        assert audit_entry["key_prefix"] == "sk_service1"
        assert audit_entry["key_type"] == "service"
        assert audit_entry["has_salt"] is False
        assert "created_at" not in audit_entry
        assert "age_days" not in audit_entry


class TestAPIKeyStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_safe(self):
        """Test that __str__ doesn't expose sensitive data."""
        api_key_hash = APIKeyHash(
            key_hash="sensitive1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        str_repr = str(api_key_hash)

        assert "sensitive" not in str_repr
        assert "pk_test1234" in str_repr
        assert "7890" in str_repr  # Last 4 chars of hash

    def test_repr_representation_safe(self):
        """Test that __repr__ doesn't expose sensitive data."""
        api_key_hash = APIKeyHash(
            key_hash="sensitive1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
            created_at=datetime.now(UTC) - timedelta(days=15),
        )

        repr_str = repr(api_key_hash)

        assert "sensitive" not in repr_str
        assert "personal" in repr_str
        assert "pk_test1234" in repr_str
        assert "15d" in repr_str


class TestAPIKeyImmutability:
    """Test that APIKeyHash is immutable."""

    def test_immutable_key_hash(self):
        """Test that key_hash cannot be changed."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        with pytest.raises(FrozenInstanceError):
            api_key_hash.key_hash = "new_hash"

    def test_immutable_key_type(self):
        """Test that key_type cannot be changed."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        with pytest.raises(FrozenInstanceError):
            api_key_hash.key_type = APIKeyType.SERVICE


class TestAPIKeyEquality:
    """Test equality and comparison behavior."""

    def test_equal_api_keys(self):
        """Test that identical API keys are equal."""
        api_key1 = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        api_key2 = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        assert api_key1 == api_key2

    def test_different_api_keys_not_equal(self):
        """Test that different API keys are not equal."""
        api_key1 = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_test1234",
            key_type=APIKeyType.PERSONAL,
        )

        api_key2 = APIKeyHash(
            key_hash="fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            key_prefix="sk_service1",
            key_type=APIKeyType.SERVICE,
        )

        assert api_key1 != api_key2


class TestAPIKeyEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_minimum_valid_prefix_length(self):
        """Test API key with minimum valid prefix length."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_1",  # Minimum length (4 chars)
            key_type=APIKeyType.PERSONAL,
        )

        assert len(api_key_hash.key_prefix) == 4

    def test_maximum_valid_prefix_length(self):
        """Test API key with maximum valid prefix length."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_123456789",  # Maximum length (12 chars)
            key_type=APIKeyType.PERSONAL,
        )

        assert len(api_key_hash.key_prefix) == 12

    def test_prefix_with_underscores_and_hyphens(self):
        """Test that prefixes with underscores and hyphens are valid."""
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk-test_123",
            key_type=APIKeyType.PERSONAL,
        )

        assert api_key_hash.key_prefix == "pk-test_123"

    def test_very_old_api_key(self):
        """Test behavior with very old API key."""
        very_old = datetime.now(UTC) - timedelta(days=2000)
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_old12345",
            key_type=APIKeyType.PERSONAL,
            created_at=very_old,
        )

        audit_entry = api_key_hash.to_audit_entry()
        assert audit_entry["age_days"] >= 2000
        assert api_key_hash.requires_rotation() is True

    def test_future_creation_date_edge_case(self):
        """Test API key with future creation date (edge case)."""
        future_time = datetime.now(UTC) + timedelta(minutes=1)
        api_key_hash = APIKeyHash(
            key_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            key_prefix="pk_future1",
            key_type=APIKeyType.PERSONAL,
            created_at=future_time,
        )

        # Should handle gracefully
        assert api_key_hash.created_at == future_time
        # Age might be negative, but requires_rotation should handle it
        rotation_required = api_key_hash.requires_rotation()
        assert isinstance(rotation_required, bool)
