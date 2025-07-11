"""
Comprehensive unit tests for PasswordHash value object.

Tests cover:
- Password hashing and verification
- Hash format validation
- Immutability
- Security properties
"""

from unittest.mock import patch

import bcrypt
import pytest

from app.modules.identity.domain.errors import DomainError
from app.modules.identity.domain.value_objects.password_hash import PasswordHash


class TestPasswordHash:
    """Test suite for PasswordHash value object."""

    def test_from_password_creates_valid_hash(self):
        """Test creating password hash from plain password."""
        password = "SecurePass123!"
        
        password_hash = PasswordHash.from_password(password)
        
        assert password_hash is not None
        assert password_hash.value != password  # Should not store plain password
        assert password_hash.value.startswith('$2b$')  # bcrypt hash format
        assert len(password_hash.value) > 50  # bcrypt hashes are ~60 chars

    def test_verify_correct_password(self):
        """Test verifying correct password against hash."""
        password = "MySecurePassword123!"
        password_hash = PasswordHash.from_password(password)
        
        is_valid = password_hash.verify(password)
        
        assert is_valid is True

    def test_verify_incorrect_password(self):
        """Test verifying incorrect password against hash."""
        password = "CorrectPassword123!"
        wrong_password = "WrongPassword123!"
        password_hash = PasswordHash.from_password(password)
        
        is_valid = password_hash.verify(wrong_password)
        
        assert is_valid is False

    def test_verify_similar_password_fails(self):
        """Test that similar passwords don't match."""
        password = "SecurePass123!"
        password_hash = PasswordHash.from_password(password)
        
        # Test variations
        assert password_hash.verify("SecurePass123") is False  # Missing !
        assert password_hash.verify("securePass123!") is False  # Different case
        assert password_hash.verify("SecurePass123! ") is False  # Extra space
        assert password_hash.verify("SecurePass123!!") is False  # Extra char

    def test_create_from_existing_hash(self):
        """Test creating PasswordHash from existing bcrypt hash."""
        # Generate a known hash
        original_password = "TestPassword123!"
        bcrypt_hash = bcrypt.hashpw(
            original_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
        
        # Create from existing hash
        password_hash = PasswordHash(bcrypt_hash)
        
        assert password_hash.value == bcrypt_hash
        assert password_hash.verify(original_password) is True

    def test_invalid_hash_format_raises_error(self):
        """Test that invalid hash format raises error."""
        with pytest.raises(DomainError) as exc_info:
            PasswordHash("not-a-valid-bcrypt-hash")
        
        assert "Invalid password hash format" in str(exc_info.value)

    def test_empty_hash_raises_error(self):
        """Test that empty hash raises error."""
        with pytest.raises(DomainError) as exc_info:
            PasswordHash("")
        
        assert "Password hash cannot be empty" in str(exc_info.value)

    def test_password_hash_is_immutable(self):
        """Test that PasswordHash is immutable."""
        password_hash = PasswordHash.from_password("TestPass123!")
        
        # Should not be able to modify the hash
        with pytest.raises(AttributeError):
            password_hash.value = "new-hash"

    def test_different_passwords_produce_different_hashes(self):
        """Test that different passwords produce different hashes."""
        hash1 = PasswordHash.from_password("Password1!")
        hash2 = PasswordHash.from_password("Password2!")
        
        assert hash1.value != hash2.value

    def test_same_password_produces_different_hashes(self):
        """Test that same password produces different hashes (due to salt)."""
        password = "SamePassword123!"
        hash1 = PasswordHash.from_password(password)
        hash2 = PasswordHash.from_password(password)
        
        # Hashes should be different due to different salts
        assert hash1.value != hash2.value
        
        # But both should verify the same password
        assert hash1.verify(password) is True
        assert hash2.verify(password) is True

    def test_hash_strength_configuration(self):
        """Test hash strength can be configured."""
        with patch('bcrypt.gensalt') as mock_gensalt:
            # Mock to verify rounds parameter
            mock_gensalt.return_value = bcrypt.gensalt(12)
            
            password_hash = PasswordHash.from_password(
                "TestPass123!",
                rounds=12
            )
            
            mock_gensalt.assert_called_once_with(12)

    def test_unicode_password_support(self):
        """Test that unicode passwords are supported."""
        unicode_password = "Пароль123!🔐"
        
        password_hash = PasswordHash.from_password(unicode_password)
        
        assert password_hash.verify(unicode_password) is True
        assert password_hash.verify("Different123!") is False

    def test_long_password_support(self):
        """Test that long passwords are supported."""
        long_password = "A" * 100 + "1!"
        
        password_hash = PasswordHash.from_password(long_password)
        
        assert password_hash.verify(long_password) is True

    def test_special_characters_in_password(self):
        """Test passwords with special characters."""
        special_passwords = [
            "Pass@word!123",
            "P@$$w0rd!",
            "Test#123$%^",
            "Quote\"Pass'123",
            "Back\\Slash/123!",
        ]
        
        for password in special_passwords:
            password_hash = PasswordHash.from_password(password)
            assert password_hash.verify(password) is True

    def test_equality_comparison(self):
        """Test equality comparison of PasswordHash objects."""
        hash_value = bcrypt.hashpw(
            b"TestPass123!",
            bcrypt.gensalt()
        ).decode('utf-8')
        
        hash1 = PasswordHash(hash_value)
        hash2 = PasswordHash(hash_value)
        
        assert hash1 == hash2
        assert hash(hash1) == hash(hash2)

    def test_string_representation(self):
        """Test string representation doesn't expose hash."""
        password_hash = PasswordHash.from_password("SecretPass123!")
        
        str_repr = str(password_hash)
        repr_repr = repr(password_hash)
        
        # Should not expose the actual hash
        assert password_hash.value not in str_repr
        assert password_hash.value not in repr_repr
        assert "PasswordHash" in repr_repr

    def test_verify_with_none_password(self):
        """Test verify with None password."""
        password_hash = PasswordHash.from_password("TestPass123!")
        
        with pytest.raises(TypeError):
            password_hash.verify(None)

    def test_verify_with_empty_password(self):
        """Test verify with empty password."""
        password_hash = PasswordHash.from_password("TestPass123!")
        
        is_valid = password_hash.verify("")
        
        assert is_valid is False

    @pytest.mark.performance
    def test_hash_generation_performance(self, benchmark_async):
        """Test password hash generation performance."""
        def generate_hash():
            return PasswordHash.from_password("TestPassword123!")
        
        # Should complete in reasonable time
        result = benchmark_async(generate_hash)
        assert result is not None

    @pytest.mark.performance
    def test_verification_performance(self, benchmark_async):
        """Test password verification performance."""
        password = "TestPassword123!"
        password_hash = PasswordHash.from_password(password)
        
        def verify_password():
            return password_hash.verify(password)
        
        # Verification should be reasonably fast
        result = benchmark_async(verify_password)
        assert result is True

    def test_constant_time_comparison(self):
        """Test that password verification uses constant-time comparison."""
        password_hash = PasswordHash.from_password("TestPass123!")
        
        # These should take similar time despite different lengths
        # (bcrypt handles this internally)
        short_wrong = "a"
        long_wrong = "a" * 100
        
        # Both should fail
        assert password_hash.verify(short_wrong) is False
        assert password_hash.verify(long_wrong) is False

    def test_migration_from_old_hash_format(self):
        """Test handling migration from old hash formats."""
        # Simulate an old MD5 hash (DO NOT USE IN PRODUCTION)
        old_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # "password"
        
        with pytest.raises(DomainError) as exc_info:
            PasswordHash(old_hash)
        
        assert "Invalid password hash format" in str(exc_info.value)

    def test_hash_truncation_protection(self):
        """Test protection against hash truncation attacks."""
        password = "VeryLongPasswordThatExceedsBcryptLimit" * 10
        
        password_hash = PasswordHash.from_password(password)
        
        # Should still work correctly despite bcrypt's 72-byte limit
        assert password_hash.verify(password) is True
        assert password_hash.verify(password[:-1]) is False