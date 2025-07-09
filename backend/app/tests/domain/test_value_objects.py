"""
Value Objects Domain Tests

Pure domain tests for value objects isolated from infrastructure.
Tests business rules and domain logic for value objects.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.modules.identity.domain.exceptions import (
    InvalidEmailError,
    InvalidPasswordError,
    InvalidSecurityStampError,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import (
    HashAlgorithm,
    PasswordHash,
)
from app.modules.identity.domain.value_objects.security_stamp import SecurityStamp


@pytest.mark.unit
class TestEmailValueObject:
    """Test Email value object."""
    
    def test_create_valid_email(self):
        """Test creating valid email."""
        email = Email("test@example.com")
        
        assert email.value == "test@example.com"
        assert email.local_part == "test"
        assert email.domain == "example.com"
    
    def test_create_email_with_subdomain(self):
        """Test creating email with subdomain."""
        email = Email("user@mail.example.com")
        
        assert email.value == "user@mail.example.com"
        assert email.local_part == "user"
        assert email.domain == "mail.example.com"
    
    def test_create_email_with_plus_addressing(self):
        """Test creating email with plus addressing."""
        email = Email("user+tag@example.com")
        
        assert email.value == "user+tag@example.com"
        assert email.local_part == "user+tag"
        assert email.domain == "example.com"
    
    def test_create_email_with_dots_in_local_part(self):
        """Test creating email with dots in local part."""
        email = Email("first.last@example.com")
        
        assert email.value == "first.last@example.com"
        assert email.local_part == "first.last"
        assert email.domain == "example.com"
    
    def test_email_is_normalized_to_lowercase(self):
        """Test email is normalized to lowercase."""
        email = Email("TEST@EXAMPLE.COM")
        
        assert email.value == "test@example.com"
        assert email.local_part == "test"
        assert email.domain == "example.com"
    
    def test_email_trims_whitespace(self):
        """Test email trims whitespace."""
        email = Email("  test@example.com  ")
        
        assert email.value == "test@example.com"
    
    def test_invalid_email_format_raises_error(self):
        """Test invalid email format raises error."""
        invalid_emails = [
            "invalid",
            "@example.com",
            "test@",
            "test..test@example.com",
            "test@example",
            "test@.com",
            "test@example.",
            "",
            None,
        ]
        
        for invalid_email in invalid_emails:
            with pytest.raises(InvalidEmailError):
                Email(invalid_email)
    
    def test_email_equality(self):
        """Test email equality."""
        email1 = Email("test@example.com")
        email2 = Email("TEST@EXAMPLE.COM")
        email3 = Email("different@example.com")
        
        assert email1 == email2
        assert email1 != email3
        assert hash(email1) == hash(email2)
        assert hash(email1) != hash(email3)
    
    def test_email_string_representation(self):
        """Test email string representation."""
        email = Email("test@example.com")
        
        assert str(email) == "test@example.com"
        assert repr(email) == "Email(test@example.com)"
    
    def test_email_is_immutable(self):
        """Test email is immutable."""
        email = Email("test@example.com")
        
        with pytest.raises(AttributeError):
            email.value = "changed@example.com"
    
    def test_email_domain_validation(self):
        """Test email domain validation."""
        # Valid domains
        valid_emails = [
            "test@example.com",
            "test@sub.example.com",
            "test@example.co.uk",
            "test@localhost",
            "test@127.0.0.1",
        ]
        
        for valid_email in valid_emails:
            email = Email(valid_email)
            assert email.value == valid_email.lower()
        
        # Invalid domains
        invalid_emails = [
            "test@",
            "test@.",
            "test@.com",
            "test@example.",
            "test@-example.com",
            "test@example-.com",
        ]
        
        for invalid_email in invalid_emails:
            with pytest.raises(InvalidEmailError):
                Email(invalid_email)


@pytest.mark.unit
class TestPasswordHashValueObject:
    """Test PasswordHash value object."""
    
    def test_create_password_hash_from_password(self):
        """Test creating password hash from password."""
        password = "secure_password123"
        password_hash = PasswordHash.create_from_password(password)
        
        assert password_hash.hash_value is not None
        assert password_hash.algorithm == HashAlgorithm.ARGON2ID
        assert password_hash.salt is not None
        assert len(password_hash.salt) > 0
    
    def test_create_password_hash_with_different_algorithms(self):
        """Test creating password hash with different algorithms."""
        password = "secure_password123"
        
        # Test Argon2ID
        hash_argon2id = PasswordHash.create_from_password(password, HashAlgorithm.ARGON2ID)
        assert hash_argon2id.algorithm == HashAlgorithm.ARGON2ID
        
        # Test PBKDF2
        hash_pbkdf2 = PasswordHash.create_from_password(password, HashAlgorithm.PBKDF2)
        assert hash_pbkdf2.algorithm == HashAlgorithm.PBKDF2
    
    def test_verify_correct_password(self):
        """Test verifying correct password."""
        password = "secure_password123"
        password_hash = PasswordHash.create_from_password(password)
        
        assert password_hash.verify_password(password) is True
    
    def test_verify_incorrect_password(self):
        """Test verifying incorrect password."""
        password = "secure_password123"
        wrong_password = "wrong_password123"
        password_hash = PasswordHash.create_from_password(password)
        
        assert password_hash.verify_password(wrong_password) is False
    
    def test_password_hash_is_different_for_same_password(self):
        """Test password hash is different for same password due to salt."""
        password = "secure_password123"
        hash1 = PasswordHash.create_from_password(password)
        hash2 = PasswordHash.create_from_password(password)
        
        assert hash1.hash_value != hash2.hash_value
        assert hash1.salt != hash2.salt
    
    def test_password_hash_string_representation(self):
        """Test password hash string representation."""
        password = "secure_password123"
        password_hash = PasswordHash.create_from_password(password)
        
        hash_str = password_hash.to_string()
        assert hash_str is not None
        assert len(hash_str) > 0
        assert password not in hash_str  # Should not contain original password
    
    def test_password_hash_from_string(self):
        """Test creating password hash from string."""
        password = "secure_password123"
        original_hash = PasswordHash.create_from_password(password)
        hash_str = original_hash.to_string()
        
        restored_hash = PasswordHash.from_string(hash_str)
        
        assert restored_hash.algorithm == original_hash.algorithm
        assert restored_hash.verify_password(password) is True
    
    def test_weak_password_validation(self):
        """Test weak password validation."""
        weak_passwords = [
            "123",
            "password",
            "abc",
            "12345678",
            "qwerty",
            "",
            None,
        ]
        
        for weak_password in weak_passwords:
            with pytest.raises(InvalidPasswordError):
                PasswordHash.create_from_password(weak_password)
    
    def test_password_strength_requirements(self):
        """Test password strength requirements."""
        # Valid strong passwords
        strong_passwords = [
            "SecurePass123!",
            "MyStr0ngP@ssw0rd",
            "C0mpl3xP@ssw0rd!",
            "AnotherStr0ng!Pass",
        ]
        
        for strong_password in strong_passwords:
            password_hash = PasswordHash.create_from_password(strong_password)
            assert password_hash.verify_password(strong_password) is True
    
    def test_password_hash_equality(self):
        """Test password hash equality."""
        password = "secure_password123"
        hash1 = PasswordHash.create_from_password(password)
        hash2 = PasswordHash.create_from_password(password)
        
        # Different hashes for same password (due to salt)
        assert hash1 != hash2
        
        # Same hash from string
        hash_str = hash1.to_string()
        hash3 = PasswordHash.from_string(hash_str)
        assert hash1 == hash3
    
    def test_password_hash_is_immutable(self):
        """Test password hash is immutable."""
        password = "secure_password123"
        password_hash = PasswordHash.create_from_password(password)
        
        with pytest.raises(AttributeError):
            password_hash.hash_value = "changed"
        
        with pytest.raises(AttributeError):
            password_hash.salt = "changed"
        
        with pytest.raises(AttributeError):
            password_hash.algorithm = HashAlgorithm.PBKDF2


@pytest.mark.unit
class TestSecurityStampValueObject:
    """Test SecurityStamp value object."""
    
    def test_generate_initial_security_stamp(self):
        """Test generating initial security stamp."""
        stamp = SecurityStamp.generate_initial()
        
        assert stamp.value is not None
        assert len(stamp.value) == 32  # 32 character hex string
        assert stamp.created_at is not None
        assert stamp.created_at <= datetime.now(UTC)
    
    def test_generate_new_security_stamp(self):
        """Test generating new security stamp."""
        stamp = SecurityStamp.generate_new()
        
        assert stamp.value is not None
        assert len(stamp.value) == 32  # 32 character hex string
        assert stamp.created_at is not None
        assert stamp.created_at <= datetime.now(UTC)
    
    def test_security_stamps_are_unique(self):
        """Test security stamps are unique."""
        stamp1 = SecurityStamp.generate_initial()
        stamp2 = SecurityStamp.generate_initial()
        
        assert stamp1.value != stamp2.value
    
    def test_security_stamp_from_value(self):
        """Test creating security stamp from value."""
        stamp_value = "abcdef1234567890abcdef1234567890"
        created_at = datetime.now(UTC)
        
        stamp = SecurityStamp.from_value(stamp_value, created_at)
        
        assert stamp.value == stamp_value
        assert stamp.created_at == created_at
    
    def test_security_stamp_validation(self):
        """Test security stamp validation."""
        # Valid values
        valid_values = [
            "abcdef1234567890abcdef1234567890",
            "0123456789abcdef0123456789abcdef",
            "ffffffffffffffffffffffffffffffff",
        ]
        
        for valid_value in valid_values:
            stamp = SecurityStamp.from_value(valid_value, datetime.now(UTC))
            assert stamp.value == valid_value
        
        # Invalid values
        invalid_values = [
            "short",
            "toolongabcdef1234567890abcdef1234567890",
            "invalid_chars!@#$%^&*(){}[]",
            "",
            None,
        ]
        
        for invalid_value in invalid_values:
            with pytest.raises(InvalidSecurityStampError):
                SecurityStamp.from_value(invalid_value, datetime.now(UTC))
    
    def test_security_stamp_expiry(self):
        """Test security stamp expiry."""
        # Fresh stamp
        fresh_stamp = SecurityStamp.generate_initial()
        assert not fresh_stamp.is_expired()
        
        # Old stamp
        old_created_at = datetime.now(UTC) - timedelta(days=100)
        old_stamp = SecurityStamp.from_value("abcdef1234567890abcdef1234567890", old_created_at)
        assert old_stamp.is_expired()
    
    def test_security_stamp_age(self):
        """Test security stamp age calculation."""
        created_at = datetime.now(UTC) - timedelta(hours=2)
        stamp = SecurityStamp.from_value("abcdef1234567890abcdef1234567890", created_at)
        
        age = stamp.age()
        assert age.total_seconds() >= 7200  # 2 hours in seconds
    
    def test_security_stamp_equality(self):
        """Test security stamp equality."""
        stamp_value = "abcdef1234567890abcdef1234567890"
        created_at = datetime.now(UTC)
        
        stamp1 = SecurityStamp.from_value(stamp_value, created_at)
        stamp2 = SecurityStamp.from_value(stamp_value, created_at)
        stamp3 = SecurityStamp.from_value("different1234567890abcdef1234567890", created_at)
        
        assert stamp1 == stamp2
        assert stamp1 != stamp3
        assert hash(stamp1) == hash(stamp2)
        assert hash(stamp1) != hash(stamp3)
    
    def test_security_stamp_string_representation(self):
        """Test security stamp string representation."""
        stamp = SecurityStamp.generate_initial()
        
        stamp_str = str(stamp)
        assert stamp.value in stamp_str
        assert "SecurityStamp" in repr(stamp)
    
    def test_security_stamp_is_immutable(self):
        """Test security stamp is immutable."""
        stamp = SecurityStamp.generate_initial()
        
        with pytest.raises(AttributeError):
            stamp.value = "changed"
        
        with pytest.raises(AttributeError):
            stamp.created_at = datetime.now(UTC)
    
    def test_security_stamp_refresh(self):
        """Test security stamp refresh."""
        old_stamp = SecurityStamp.generate_initial()
        new_stamp = old_stamp.refresh()
        
        assert new_stamp.value != old_stamp.value
        assert new_stamp.created_at > old_stamp.created_at
    
    def test_security_stamp_invalidation(self):
        """Test security stamp invalidation."""
        stamp = SecurityStamp.generate_initial()
        
        # Stamp should be valid initially
        assert stamp.is_valid()
        
        # Simulate invalidation by creating an old stamp
        old_created_at = datetime.now(UTC) - timedelta(days=100)
        old_stamp = SecurityStamp.from_value(stamp.value, old_created_at)
        
        assert not old_stamp.is_valid()


@pytest.mark.unit
class TestValueObjectBehavior:
    """Test common value object behavior."""
    
    def test_value_objects_are_immutable(self):
        """Test that all value objects are immutable."""
        email = Email("test@example.com")
        password_hash = PasswordHash.create_from_password("password123")
        security_stamp = SecurityStamp.generate_initial()
        
        # All value objects should be immutable
        with pytest.raises(AttributeError):
            email.value = "changed"
        
        with pytest.raises(AttributeError):
            password_hash.hash_value = "changed"
        
        with pytest.raises(AttributeError):
            security_stamp.value = "changed"
    
    def test_value_objects_equality_by_value(self):
        """Test that value objects are equal by value."""
        email1 = Email("test@example.com")
        email2 = Email("test@example.com")
        
        assert email1 == email2
        assert hash(email1) == hash(email2)
    
    def test_value_objects_have_string_representation(self):
        """Test that value objects have string representation."""
        email = Email("test@example.com")
        password_hash = PasswordHash.create_from_password("password123")
        security_stamp = SecurityStamp.generate_initial()
        
        # All should have meaningful string representations
        assert str(email) == "test@example.com"
        assert str(password_hash) is not None
        assert str(security_stamp) is not None
        
        # All should have repr
        assert "Email" in repr(email)
        assert "PasswordHash" in repr(password_hash)
        assert "SecurityStamp" in repr(security_stamp)