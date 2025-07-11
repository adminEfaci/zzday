"""
Comprehensive unit tests for Email value object.

Tests cover:
- Valid email creation
- Invalid email validation
- Email normalization
- Equality and hashing
- Domain rules enforcement
"""

import pytest

from app.modules.identity.domain.errors import DomainError
from app.modules.identity.domain.value_objects.email import Email


class TestEmail:
    """Test suite for Email value object."""

    def test_create_valid_email(self):
        """Test creating email with valid format."""
        email = Email("user@example.com")
        assert email.value == "user@example.com"
        assert str(email) == "user@example.com"

    def test_email_normalization(self):
        """Test email normalization (lowercase)."""
        email = Email("User@EXAMPLE.COM")
        assert email.value == "user@example.com"
        assert email.local_part == "user"
        assert email.domain == "example.com"

    def test_email_with_plus_addressing(self):
        """Test email with plus addressing."""
        email = Email("user+tag@example.com")
        assert email.value == "user+tag@example.com"
        assert email.local_part == "user+tag"
        assert email.normalized == "user@example.com"

    def test_email_whitespace_handling(self):
        """Test email with surrounding whitespace."""
        email = Email("  user@example.com  ")
        assert email.value == "user@example.com"

    @pytest.mark.parametrize("invalid_email", [
        "",  # Empty
        "   ",  # Whitespace only
        "invalid",  # No @ symbol
        "@example.com",  # No local part
        "user@",  # No domain
        "user@@example.com",  # Double @
        "user@.com",  # Domain starts with dot
        "user@example.",  # Domain ends with dot
        "user@exam ple.com",  # Space in domain
        "user @example.com",  # Space in local part
        "user@example..com",  # Consecutive dots
        "user@-example.com",  # Domain starts with hyphen
        "user@example-.com",  # Domain ends with hyphen
        "user@exam_ple.com",  # Underscore in domain
        "a" * 255 + "@example.com",  # Too long
    ])
    def test_invalid_email_raises_error(self, invalid_email):
        """Test invalid email formats raise DomainError."""
        with pytest.raises(DomainError) as exc_info:
            Email(invalid_email)
        assert "Invalid email" in str(exc_info.value)

    def test_email_equality(self):
        """Test email equality comparison."""
        email1 = Email("user@example.com")
        email2 = Email("USER@EXAMPLE.COM")
        email3 = Email("different@example.com")

        assert email1 == email2
        assert email1 != email3
        assert email1 != "user@example.com"  # Not equal to string

    def test_email_hashing(self):
        """Test email can be used in sets and as dict keys."""
        email1 = Email("user@example.com")
        email2 = Email("USER@EXAMPLE.COM")
        email3 = Email("different@example.com")

        email_set = {email1, email2, email3}
        assert len(email_set) == 2  # email1 and email2 are equal

        email_dict = {email1: "value1", email3: "value2"}
        assert email_dict[email2] == "value1"  # email2 equals email1

    def test_email_immutability(self):
        """Test email value object is immutable."""
        email = Email("user@example.com")
        
        # Value objects should be frozen/immutable
        with pytest.raises(AttributeError):
            email.value = "new@example.com"

    def test_email_special_valid_cases(self):
        """Test special but valid email cases."""
        valid_cases = [
            "test.email.with+symbol@example.com",
            "user123@example.co.uk",
            "user_name@example.com",
            "user-name@example-domain.com",
            "1234567890@example.com",
            "user@subdomain.example.com",
            "user@123.123.123.123",  # IP address domain
            "user@[123.123.123.123]",  # Bracketed IP
        ]
        
        for valid_email in valid_cases:
            email = Email(valid_email)
            assert email.value == valid_email.lower()

    def test_email_domain_extraction(self):
        """Test domain extraction from email."""
        email = Email("user@subdomain.example.com")
        assert email.domain == "subdomain.example.com"
        assert email.top_level_domain == "com"

    def test_email_is_corporate(self):
        """Test corporate email detection."""
        corporate_email = Email("user@company.com")
        free_email = Email("user@gmail.com")
        
        assert corporate_email.is_corporate_email()
        assert not free_email.is_corporate_email()

    def test_email_repr(self):
        """Test email representation."""
        email = Email("user@example.com")
        assert repr(email) == "Email('user@example.com')"

    def test_email_json_serialization(self):
        """Test email can be serialized to JSON."""
        email = Email("user@example.com")
        assert email.to_json() == "user@example.com"

    def test_email_from_json(self):
        """Test email can be created from JSON."""
        email = Email.from_json("user@example.com")
        assert email.value == "user@example.com"

    def test_email_comparison_operators(self):
        """Test email comparison operators for sorting."""
        email1 = Email("alice@example.com")
        email2 = Email("bob@example.com")
        email3 = Email("alice@example.com")
        
        assert email1 < email2
        assert email2 > email1
        assert email1 <= email3
        assert email1 >= email3

    def test_email_length_validation(self):
        """Test email length constraints."""
        # Maximum valid length (254 characters)
        max_local = "a" * 64
        max_domain = "b" * 189
        max_email = f"{max_local}@{max_domain}.com"
        
        email = Email(max_email)
        assert len(email.value) <= 254
        
        # Too long email
        with pytest.raises(DomainError):
            Email("a" * 250 + "@example.com")

    def test_email_unicode_handling(self):
        """Test email with unicode characters."""
        # Most email systems don't support unicode in email addresses
        with pytest.raises(DomainError):
            Email("用户@example.com")
        
        with pytest.raises(DomainError):
            Email("user@例え.com")

    def test_email_subdomain_handling(self):
        """Test email with multiple subdomains."""
        email = Email("user@mail.subdomain.example.co.uk")
        assert email.domain == "mail.subdomain.example.co.uk"
        assert email.top_level_domain == "uk"