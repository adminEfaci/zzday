"""
Test cases for PasswordHash value object.

Tests all aspects of password hashing including security, validation,
and algorithm-specific behavior.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.password_hash import (
    HashAlgorithm,
    PasswordHash,
)


class TestPasswordHashCreation:
    """Test PasswordHash creation and validation."""

    def test_create_valid_argon2_hash(self):
        """Test creating a valid Argon2 password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt1234567890abcdef",
            hash_value="$argon2id$v=19$m=65536,t=3,p=4$hash1234567890",
            memory_cost=65536,
            time_cost=3,
            parallelism=4,
        )

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.salt == "salt1234567890abcdef"
        assert password_hash.memory_cost == 65536
        assert password_hash.time_cost == 3
        assert password_hash.parallelism == 4
        assert password_hash.is_argon2 is True
        assert password_hash.is_legacy is False

    def test_create_valid_pbkdf2_hash(self):
        """Test creating a valid PBKDF2 password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="salt9876543210fedcba",
            hash_value="pbkdf2_sha256$260000$hash9876543210",
            iterations=260000,
        )

        assert password_hash.algorithm == HashAlgorithm.PBKDF2_SHA256
        assert password_hash.iterations == 260000
        assert password_hash.is_argon2 is False
        assert password_hash.is_legacy is True

    def test_create_valid_bcrypt_hash(self):
        """Test creating a valid bcrypt password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT,
            salt="$2b$12$salt123456789012345678",
            hash_value="$2b$12$hash123456789012345678901234567890",
            rounds=12,
        )

        assert password_hash.algorithm == HashAlgorithm.BCRYPT
        assert password_hash.rounds == 12
        assert password_hash.is_legacy is True

    def test_invalid_password_hash_creation(self):
        """Test validation of invalid password hashes."""
        # Missing salt
        with pytest.raises(ValueError, match="Salt is required"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="",
                hash_value="hash123",
                memory_cost=65536,
                parallelism=4,
            )

        # Missing hash value
        with pytest.raises(ValueError, match="Hash value is required"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="salt123",
                hash_value="",
                memory_cost=65536,
                parallelism=4,
            )

        # Missing iterations for PBKDF2
        with pytest.raises(ValueError, match="Iterations required for PBKDF2"):
            PasswordHash(
                algorithm=HashAlgorithm.PBKDF2_SHA256,
                salt="salt123",
                hash_value="hash123",
            )

        # Missing memory cost for Argon2
        with pytest.raises(ValueError, match="Memory cost.*required for Argon2"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID, salt="salt123", hash_value="hash123"
            )

        # Invalid iterations
        with pytest.raises(ValueError, match="Iterations must be positive"):
            PasswordHash(
                algorithm=HashAlgorithm.PBKDF2_SHA256,
                salt="salt123",
                hash_value="hash123",
                iterations=0,
            )


class TestPasswordHashStrength:
    """Test password hash strength evaluation."""

    def test_argon2_strength_scoring(self):
        """Test strength scoring for Argon2 hashes."""
        # Strong Argon2 hash
        strong_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="strongsalt123456",
            hash_value="$argon2id$strong",
            memory_cost=131072,  # 128MB
            time_cost=4,
            parallelism=8,
        )

        assert strong_hash.strength_score >= 95
        assert strong_hash.is_strong is True

        # Medium strength Argon2
        medium_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="mediumsalt123456",
            hash_value="$argon2id$medium",
            memory_cost=65536,  # 64MB
            time_cost=3,
            parallelism=4,
        )

        assert 70 <= medium_hash.strength_score < 95
        assert medium_hash.is_medium_strength is True

        # Weak Argon2 (low memory)
        weak_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="weaksalt12345678",
            hash_value="$argon2id$weak",
            memory_cost=32768,  # 32MB
            time_cost=2,
            parallelism=2,
        )

        assert weak_hash.strength_score < 70
        assert weak_hash.needs_rehash is True

    def test_pbkdf2_strength_scoring(self):
        """Test strength scoring for PBKDF2 hashes."""
        # High iteration PBKDF2
        high_iter = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="salt123",
            hash_value="hash123",
            iterations=500000,
        )

        assert high_iter.strength_score > 50

        # Low iteration PBKDF2
        low_iter = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="salt123",
            hash_value="hash123",
            iterations=50000,
        )

        assert low_iter.strength_score < 50
        assert low_iter.needs_rehash is True

    def test_bcrypt_strength_scoring(self):
        """Test strength scoring for bcrypt hashes."""
        # High rounds bcrypt
        high_rounds = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT,
            salt="$2b$14$salt",
            hash_value="$2b$14$hash",
            rounds=14,
        )

        assert high_rounds.strength_score > 60

        # Low rounds bcrypt
        low_rounds = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT,
            salt="$2b$10$salt",
            hash_value="$2b$10$hash",
            rounds=10,
        )

        assert low_rounds.strength_score < 60
        assert low_rounds.needs_rehash is True


class TestPasswordHashRehashing:
    """Test password hash rehashing detection."""

    def test_needs_rehash_detection(self):
        """Test detection of hashes that need rehashing."""
        # Legacy algorithm
        legacy_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="salt123",
            hash_value="hash123",
            iterations=100000,
        )

        assert legacy_hash.needs_rehash is True
        assert legacy_hash.rehash_reason == "legacy_algorithm"

        # Low memory Argon2
        low_memory = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt123",
            hash_value="hash123",
            memory_cost=16384,  # 16MB - too low
            time_cost=3,
            parallelism=4,
        )

        assert low_memory.needs_rehash is True
        assert "memory" in low_memory.rehash_reason

        # Good hash
        good_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt123",
            hash_value="hash123",
            memory_cost=65536,
            time_cost=3,
            parallelism=4,
        )

        assert good_hash.needs_rehash is False

    def test_get_rehash_parameters(self):
        """Test getting recommended rehash parameters."""
        old_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="salt123",
            hash_value="hash123",
            iterations=50000,
        )

        rehash_params = old_hash.get_rehash_parameters()

        assert rehash_params["algorithm"] == HashAlgorithm.ARGON2ID
        assert rehash_params["memory_cost"] >= 65536
        assert rehash_params["time_cost"] >= 3
        assert rehash_params["parallelism"] >= 4


class TestPasswordHashSerialization:
    """Test password hash serialization."""

    def test_to_string_argon2(self):
        """Test string serialization of Argon2 hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="saltsaltsalt",
            hash_value="hashhashhashhash",
            memory_cost=65536,
            time_cost=3,
            parallelism=4,
            version=19,
        )

        hash_string = password_hash.to_string()

        assert "argon2id" in hash_string
        assert "m=65536" in hash_string
        assert "t=3" in hash_string
        assert "p=4" in hash_string
        assert "v=19" in hash_string

    def test_from_string_argon2(self):
        """Test deserialization from Argon2 string."""
        hash_string = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo"

        password_hash = PasswordHash.from_string(hash_string)

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.memory_cost == 65536
        assert password_hash.time_cost == 3
        assert password_hash.parallelism == 4
        assert password_hash.version == 19

    def test_to_string_pbkdf2(self):
        """Test string serialization of PBKDF2 hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="saltsalt",
            hash_value="hashhash",
            iterations=260000,
        )

        hash_string = password_hash.to_string()

        assert "pbkdf2_sha256" in hash_string
        assert "260000" in hash_string

    def test_round_trip_serialization(self):
        """Test round-trip serialization."""
        original = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="testsalt123",
            hash_value="testhash123",
            memory_cost=131072,
            time_cost=4,
            parallelism=8,
        )

        hash_string = original.to_string()
        reconstructed = PasswordHash.from_string(hash_string)

        assert reconstructed.algorithm == original.algorithm
        assert reconstructed.memory_cost == original.memory_cost
        assert reconstructed.time_cost == original.time_cost
        assert reconstructed.parallelism == original.parallelism


class TestPasswordHashSecurity:
    """Test password hash security features."""

    def test_hash_immutability(self):
        """Test that password hashes are immutable."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt123",
            hash_value="hash123",
            memory_cost=65536,
            parallelism=4,
        )

        with pytest.raises(FrozenInstanceError):
            password_hash.salt = "modified"

        with pytest.raises(FrozenInstanceError):
            password_hash.hash_value = "modified"

    def test_secure_comparison(self):
        """Test secure hash comparison."""
        hash1 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt123",
            hash_value="hash123",
            memory_cost=65536,
            parallelism=4,
        )

        hash2 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt123",
            hash_value="hash123",
            memory_cost=65536,
            parallelism=4,
        )

        hash3 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="salt456",
            hash_value="hash456",
            memory_cost=65536,
            parallelism=4,
        )

        assert hash1 == hash2
        assert hash1 != hash3
        assert hash(hash1) == hash(hash2)
        assert hash(hash1) != hash(hash3)

    def test_no_plain_text_exposure(self):
        """Test that plain text is never exposed."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="secretsalt",
            hash_value="secrethash",
            memory_cost=65536,
            parallelism=4,
        )

        str_repr = str(password_hash)
        repr_repr = repr(password_hash)

        # Should not expose full hash
        assert "secrethash" not in str_repr
        assert "secrethash" not in repr_repr

        # Should show algorithm and strength
        assert "ARGON2ID" in str_repr
        assert "strength" in str_repr.lower()


class TestPasswordHashMigration:
    """Test password hash migration scenarios."""

    def test_migrate_from_pbkdf2_to_argon2(self):
        """Test migration from PBKDF2 to Argon2."""
        old_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="oldsalt",
            hash_value="oldhash",
            iterations=100000,
        )

        migration_params = old_hash.get_migration_parameters()

        assert migration_params["from_algorithm"] == HashAlgorithm.PBKDF2_SHA256
        assert migration_params["to_algorithm"] == HashAlgorithm.ARGON2ID
        assert migration_params["requires_rehash"] is True
        assert "recommended_params" in migration_params

    def test_upgrade_weak_argon2(self):
        """Test upgrading weak Argon2 parameters."""
        weak_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="weaksalt",
            hash_value="weakhash",
            memory_cost=16384,  # Too low
            time_cost=1,  # Too low
            parallelism=1,  # Too low
        )

        upgrade_params = weak_hash.get_upgrade_parameters()

        assert upgrade_params["memory_cost"] >= 65536
        assert upgrade_params["time_cost"] >= 3
        assert upgrade_params["parallelism"] >= 4
        assert upgrade_params["reason"] == "weak_parameters"


class TestPasswordHashCompatibility:
    """Test compatibility with various hashing libraries."""

    def test_django_compatibility(self):
        """Test compatibility with Django password hashes."""
        # Django PBKDF2 format
        django_hash = "pbkdf2_sha256$260000$salt$hash"

        password_hash = PasswordHash.from_django_format(django_hash)

        assert password_hash.algorithm == HashAlgorithm.PBKDF2_SHA256
        assert password_hash.iterations == 260000
        assert password_hash.salt == "salt"
        assert password_hash.hash_value == "hash"

    def test_passlib_compatibility(self):
        """Test compatibility with passlib hashes."""
        # Passlib Argon2 format
        passlib_hash = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"

        password_hash = PasswordHash.from_passlib_format(passlib_hash)

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.memory_cost == 65536
        assert password_hash.time_cost == 3
        assert password_hash.parallelism == 4

    def test_export_formats(self):
        """Test exporting to various formats."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="exportsalt",
            hash_value="exporthash",
            memory_cost=65536,
            time_cost=3,
            parallelism=4,
        )

        # Export to different formats
        django_format = password_hash.to_django_format()
        passlib_format = password_hash.to_passlib_format()

        assert django_format.startswith("argon2")
        assert passlib_format.startswith("$argon2id$")
        """Test creating a valid Argon2 password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="valid_base64_salt_here123==",
            hash_value="valid_hash_value_here456==",
            memory_cost=65536,
            parallelism=4,
        )

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.salt == "valid_base64_salt_here123=="
        assert password_hash.hash_value == "valid_hash_value_here456=="
        assert password_hash.memory_cost == 65536
        assert password_hash.parallelism == 4

    def test_create_valid_pbkdf2_hash(self):
        """Test creating a valid PBKDF2 password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="pbkdf2_salt_123",
            hash_value="pbkdf2_hash_456",
            iterations=100000,
        )

        assert password_hash.algorithm == HashAlgorithm.PBKDF2_SHA256
        assert password_hash.iterations == 100000

    def test_create_valid_bcrypt_hash(self):
        """Test creating a valid bcrypt password hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT,
            salt="bcrypt_salt_789",
            hash_value="bcrypt_hash_012",
        )

        assert password_hash.algorithm == HashAlgorithm.BCRYPT

    def test_empty_salt_raises_error(self):
        """Test that empty salt raises ValueError."""
        with pytest.raises(ValueError, match="Salt is required"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="",
                hash_value="valid_hash",
                memory_cost=65536,
                parallelism=4,
            )

    def test_empty_hash_raises_error(self):
        """Test that empty hash value raises ValueError."""
        with pytest.raises(ValueError, match="Hash value is required"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="valid_salt",
                hash_value="",
                memory_cost=65536,
                parallelism=4,
            )

    def test_invalid_salt_format_raises_error(self):
        """Test that invalid salt format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid salt format"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="invalid@salt#format",
                hash_value="valid_hash",
                memory_cost=65536,
                parallelism=4,
            )

    def test_invalid_hash_format_raises_error(self):
        """Test that invalid hash format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid hash format"):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="valid_salt",
                hash_value="invalid@hash#format",
                memory_cost=65536,
                parallelism=4,
            )

    def test_argon2_missing_memory_cost_raises_error(self):
        """Test that Argon2 without memory cost raises ValueError."""
        with pytest.raises(
            ValueError, match="Memory cost and parallelism required for Argon2"
        ):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="valid_salt",
                hash_value="valid_hash",
                parallelism=4,
            )

    def test_argon2_missing_parallelism_raises_error(self):
        """Test that Argon2 without parallelism raises ValueError."""
        with pytest.raises(
            ValueError, match="Memory cost and parallelism required for Argon2"
        ):
            PasswordHash(
                algorithm=HashAlgorithm.ARGON2ID,
                salt="valid_salt",
                hash_value="valid_hash",
                memory_cost=65536,
            )

    def test_pbkdf2_missing_iterations_raises_error(self):
        """Test that PBKDF2 without iterations raises ValueError."""
        with pytest.raises(ValueError, match="Iterations required for PBKDF2"):
            PasswordHash(
                algorithm=HashAlgorithm.PBKDF2_SHA256,
                salt="valid_salt",
                hash_value="valid_hash",
            )


class TestPasswordHashStringConversion:
    """Test string conversion methods."""

    def test_argon2_to_string(self):
        """Test Argon2 hash to string conversion."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        result = password_hash.to_string()
        expected = "argon2id$test_salt$test_hash$m=65536,p=4"
        assert result == expected

    def test_pbkdf2_to_string(self):
        """Test PBKDF2 hash to string conversion."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="test_salt",
            hash_value="test_hash",
            iterations=100000,
        )

        result = password_hash.to_string()
        expected = "pbkdf2_sha256$test_salt$test_hash$i=100000"
        assert result == expected

    def test_bcrypt_to_string(self):
        """Test bcrypt hash to string conversion."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT, salt="test_salt", hash_value="test_hash"
        )

        result = password_hash.to_string()
        expected = "bcrypt$test_salt$test_hash"
        assert result == expected

    def test_from_string_argon2(self):
        """Test creating PasswordHash from Argon2 string."""
        hash_string = "argon2id$test_salt$test_hash$m=65536,p=4"
        password_hash = PasswordHash.from_string(hash_string)

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.salt == "test_salt"
        assert password_hash.hash_value == "test_hash"
        assert password_hash.memory_cost == 65536
        assert password_hash.parallelism == 4

    def test_from_string_pbkdf2(self):
        """Test creating PasswordHash from PBKDF2 string."""
        hash_string = "pbkdf2_sha256$test_salt$test_hash$i=100000"
        password_hash = PasswordHash.from_string(hash_string)

        assert password_hash.algorithm == HashAlgorithm.PBKDF2_SHA256
        assert password_hash.salt == "test_salt"
        assert password_hash.hash_value == "test_hash"
        assert password_hash.iterations == 100000

    def test_from_string_bcrypt(self):
        """Test creating PasswordHash from bcrypt string."""
        hash_string = "bcrypt$test_salt$test_hash"
        password_hash = PasswordHash.from_string(hash_string)

        assert password_hash.algorithm == HashAlgorithm.BCRYPT
        assert password_hash.salt == "test_salt"
        assert password_hash.hash_value == "test_hash"

    def test_from_string_invalid_format(self):
        """Test from_string with invalid format."""
        with pytest.raises(ValueError, match="Invalid hash string format"):
            PasswordHash.from_string("invalid_format")

    def test_from_string_unsupported_algorithm(self):
        """Test from_string with unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            PasswordHash.from_string("unknown$salt$hash")

    def test_round_trip_conversion(self):
        """Test that to_string and from_string are inverses."""
        original = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        string_repr = original.to_string()
        recreated = PasswordHash.from_string(string_repr)

        assert original == recreated


class TestPasswordHashFactory:
    """Test factory method for creating hashes from passwords."""

    def test_create_from_password_argon2(self):
        """Test creating hash from password with Argon2."""
        password_hash = PasswordHash.create_from_password(
            password="test_password", algorithm=HashAlgorithm.ARGON2ID
        )

        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.salt is not None
        assert len(password_hash.salt) > 0
        assert password_hash.memory_cost == 65536
        assert password_hash.parallelism == 4

    def test_create_from_password_pbkdf2(self):
        """Test creating hash from password with PBKDF2."""
        password_hash = PasswordHash.create_from_password(
            password="test_password", algorithm=HashAlgorithm.PBKDF2_SHA256
        )

        assert password_hash.algorithm == HashAlgorithm.PBKDF2_SHA256
        assert password_hash.iterations == 100000

    def test_create_from_password_with_custom_salt(self):
        """Test creating hash with custom salt."""
        custom_salt = "custom_salt_123"
        password_hash = PasswordHash.create_from_password(
            password="test_password", salt=custom_salt
        )

        assert password_hash.salt == custom_salt

    def test_create_from_empty_password_raises_error(self):
        """Test that empty password raises ValueError."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            PasswordHash.create_from_password(password="")


class TestPasswordHashSecurity:
    """Test security-related properties and methods."""

    def test_is_legacy_algorithm_pbkdf2(self):
        """Test that PBKDF2 is considered legacy."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="test_salt",
            hash_value="test_hash",
            iterations=100000,
        )

        assert password_hash.is_legacy_algorithm is True

    def test_is_legacy_algorithm_bcrypt(self):
        """Test that bcrypt is considered legacy."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT, salt="test_salt", hash_value="test_hash"
        )

        assert password_hash.is_legacy_algorithm is True

    def test_is_legacy_algorithm_argon2(self):
        """Test that Argon2 is not considered legacy."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        assert password_hash.is_legacy_algorithm is False

    def test_needs_rehash_legacy_algorithm(self):
        """Test that legacy algorithms need rehashing."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="test_salt",
            hash_value="test_hash",
            iterations=100000,
        )

        assert password_hash.needs_rehash is True

    def test_needs_rehash_low_memory_cost(self):
        """Test that low memory cost needs rehashing."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=32000,  # Below recommended 46MB
            parallelism=4,
        )

        assert password_hash.needs_rehash is True

    def test_needs_rehash_low_iterations(self):
        """Test that low iterations need rehashing."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="test_salt",
            hash_value="test_hash",
            iterations=50000,  # Below recommended 100k
        )

        assert password_hash.needs_rehash is True

    def test_strength_score_argon2(self):
        """Test strength score for Argon2."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        score = password_hash.strength_score
        assert score == 100  # 90 base + 5 for memory + 5 for parallelism

    def test_strength_score_pbkdf2_high_iterations(self):
        """Test strength score for PBKDF2 with high iterations."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.PBKDF2_SHA256,
            salt="test_salt",
            hash_value="test_hash",
            iterations=100000,
        )

        score = password_hash.strength_score
        assert score == 60  # 50 base + 10 for high iterations

    def test_strength_score_bcrypt(self):
        """Test strength score for bcrypt."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.BCRYPT, salt="test_salt", hash_value="test_hash"
        )

        score = password_hash.strength_score
        assert score == 60


class TestPasswordHashMetadata:
    """Test metadata and auditing functionality."""

    def test_get_metadata(self):
        """Test getting hash metadata."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt_123",
            hash_value="test_hash_456",
            memory_cost=65536,
            parallelism=4,
        )

        metadata = password_hash.get_metadata()

        assert metadata["algorithm"] == "argon2id"
        assert metadata["strength_score"] == 100
        assert metadata["is_legacy"] is False
        assert metadata["needs_rehash"] is False
        assert metadata["salt_length"] == len("test_salt_123")
        assert metadata["hash_length"] == len("test_hash_456")


class TestPasswordHashImmutability:
    """Test that PasswordHash is immutable."""

    def test_immutable_algorithm(self):
        """Test that algorithm cannot be changed."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        with pytest.raises(FrozenInstanceError):
            password_hash.algorithm = HashAlgorithm.BCRYPT

    def test_immutable_salt(self):
        """Test that salt cannot be changed."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        with pytest.raises(FrozenInstanceError):
            password_hash.salt = "new_salt"


class TestPasswordHashStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_safe(self):
        """Test that __str__ doesn't expose sensitive data."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="sensitive_salt",
            hash_value="sensitive_hash",
            memory_cost=65536,
            parallelism=4,
        )

        str_repr = str(password_hash)

        assert "sensitive_salt" not in str_repr
        assert "sensitive_hash" not in str_repr
        assert "argon2id" in str_repr
        assert "strength=100" in str_repr

    def test_repr_representation_safe(self):
        """Test that __repr__ doesn't expose sensitive data."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="sensitive_salt",
            hash_value="sensitive_hash",
            memory_cost=65536,
            parallelism=4,
        )

        repr_str = repr(password_hash)

        assert "sensitive_salt" not in repr_str
        assert "sensitive_hash" not in repr_str
        assert "argon2id" in repr_str
        assert "salt_length=" in repr_str


class TestPasswordHashEquality:
    """Test equality and comparison behavior."""

    def test_equal_hashes(self):
        """Test that identical hashes are equal."""
        hash1 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        hash2 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        assert hash1 == hash2

    def test_different_hashes_not_equal(self):
        """Test that different hashes are not equal."""
        hash1 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        hash2 = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="different_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=4,
        )

        assert hash1 != hash2


class TestPasswordHashEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_hex_format_salt_and_hash(self):
        """Test with hexadecimal format salt and hash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="abcdef1234567890",
            hash_value="fedcba0987654321",
            memory_cost=65536,
            parallelism=4,
        )

        assert password_hash.salt == "abcdef1234567890"
        assert password_hash.hash_value == "fedcba0987654321"

    def test_maximum_strength_score(self):
        """Test that strength score doesn't exceed 100."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=1000000,  # Very high
            parallelism=100,  # Very high
        )

        assert password_hash.strength_score <= 100

    def test_zero_parallelism_not_allowed(self):
        """Test that zero parallelism is caught in needs_rehash."""
        password_hash = PasswordHash(
            algorithm=HashAlgorithm.ARGON2ID,
            salt="test_salt",
            hash_value="test_hash",
            memory_cost=65536,
            parallelism=0,
        )

        assert password_hash.needs_rehash is True
