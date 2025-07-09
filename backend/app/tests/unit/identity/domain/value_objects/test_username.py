"""
Comprehensive unit tests for Username value object.

Tests cover:
- Valid username creation
- Invalid username validation
- Username normalization
- Reserved username checking
- Profanity filtering
"""

import pytest

from app.modules.identity.domain.errors import DomainError
from app.modules.identity.domain.value_objects.username import Username


class TestUsername:
    """Test suite for Username value object."""

    def test_create_valid_username(self):
        """Test creating username with valid format."""
        username = Username("john_doe123")
        assert username.value == "john_doe123"
        assert str(username) == "john_doe123"

    def test_username_normalization(self):
        """Test username normalization preserves case."""
        username = Username("JohnDoe")
        assert username.value == "JohnDoe"  # Preserves case
        assert username.normalized == "johndoe"  # Lowercase for comparison

    def test_username_length_constraints(self):
        """Test username length validation."""
        # Minimum length (3 characters)
        Username("abc")
        
        # Maximum length (30 characters)
        Username("a" * 30)
        
        # Too short
        with pytest.raises(DomainError) as exc_info:
            Username("ab")
        assert "must be between 3 and 30 characters" in str(exc_info.value)
        
        # Too long
        with pytest.raises(DomainError) as exc_info:
            Username("a" * 31)
        assert "must be between 3 and 30 characters" in str(exc_info.value)

    @pytest.mark.parametrize("invalid_username", [
        "",  # Empty
        "   ",  # Whitespace only
        "user name",  # Contains space
        "user@name",  # Contains @
        "user#name",  # Contains #
        "user$name",  # Contains $
        "user%name",  # Contains %
        "user&name",  # Contains &
        "user*name",  # Contains *
        "user+name",  # Contains +
        "user=name",  # Contains =
        "user!name",  # Contains !
        "user?name",  # Contains ?
        "user/name",  # Contains /
        "user\\name",  # Contains backslash
        ".username",  # Starts with dot
        "username.",  # Ends with dot
        "-username",  # Starts with hyphen
        "username-",  # Ends with hyphen
        "_username",  # Starts with underscore
        "username_",  # Ends with underscore
        "user..name",  # Consecutive dots
        "user__name",  # Consecutive underscores
        "user--name",  # Consecutive hyphens
    ])
    def test_invalid_username_format(self, invalid_username):
        """Test invalid username formats raise DomainError."""
        with pytest.raises(DomainError) as exc_info:
            Username(invalid_username)
        assert "Invalid username" in str(exc_info.value)

    def test_valid_username_patterns(self):
        """Test various valid username patterns."""
        valid_usernames = [
            "user123",
            "john_doe",
            "jane.doe",
            "user-name",
            "User.Name_123",
            "a1b2c3",
            "FirstLast",
            "user.name-123_test",
        ]
        
        for valid_username in valid_usernames:
            username = Username(valid_username)
            assert username.value == valid_username

    def test_reserved_usernames(self):
        """Test reserved usernames are rejected."""
        reserved_names = [
            "admin",
            "administrator",
            "root",
            "system",
            "moderator",
            "support",
            "help",
            "api",
            "www",
            "mail",
            "ftp",
            "test",
            "guest",
            "bot",
            "webhook",
            "postmaster",
            "abuse",
            "security",
            "noreply",
            "no-reply",
        ]
        
        for reserved in reserved_names:
            with pytest.raises(DomainError) as exc_info:
                Username(reserved)
            assert "reserved" in str(exc_info.value).lower()
            
            # Also test case variations
            with pytest.raises(DomainError):
                Username(reserved.upper())
            with pytest.raises(DomainError):
                Username(reserved.title())

    def test_profanity_filter(self):
        """Test usernames with profanity are rejected."""
        # Note: In real implementation, this would use a proper profanity filter
        offensive_names = [
            "damn123",
            "hell_user",
            "shit.happens",
            "f_u_c_k",
        ]
        
        for offensive in offensive_names:
            with pytest.raises(DomainError) as exc_info:
                Username(offensive)
            assert "inappropriate" in str(exc_info.value).lower()

    def test_username_equality(self):
        """Test username equality comparison (case-insensitive)."""
        username1 = Username("JohnDoe")
        username2 = Username("johndoe")
        username3 = Username("JOHNDOE")
        username4 = Username("JaneDoe")

        assert username1 == username2
        assert username1 == username3
        assert username2 == username3
        assert username1 != username4
        assert username1 != "JohnDoe"  # Not equal to string

    def test_username_hashing(self):
        """Test username can be used in sets and as dict keys."""
        username1 = Username("JohnDoe")
        username2 = Username("johndoe")
        username3 = Username("JaneDoe")

        username_set = {username1, username2, username3}
        assert len(username_set) == 2  # username1 and username2 are equal

        username_dict = {username1: "value1", username3: "value2"}
        assert username_dict[username2] == "value1"  # username2 equals username1

    def test_username_immutability(self):
        """Test username value object is immutable."""
        username = Username("john_doe")
        
        with pytest.raises(AttributeError):
            username.value = "new_name"

    def test_username_unicode_rejection(self):
        """Test unicode usernames are rejected."""
        unicode_names = [
            "用户名",
            "пользователь",
            "مستخدم",
            "user😀",
            "user♠",
        ]
        
        for unicode_name in unicode_names:
            with pytest.raises(DomainError):
                Username(unicode_name)

    def test_username_repr(self):
        """Test username representation."""
        username = Username("john_doe")
        assert repr(username) == "Username('john_doe')"

    def test_username_json_serialization(self):
        """Test username can be serialized to JSON."""
        username = Username("john_doe")
        assert username.to_json() == "john_doe"

    def test_username_from_json(self):
        """Test username can be created from JSON."""
        username = Username.from_json("john_doe")
        assert username.value == "john_doe"

    def test_username_suggestions(self):
        """Test username suggestion generation."""
        username = Username("john_doe")
        suggestions = username.generate_suggestions()
        
        assert len(suggestions) >= 3
        assert all(isinstance(s, str) for s in suggestions)
        assert all(len(s) >= 3 and len(s) <= 30 for s in suggestions)

    def test_username_comparison_operators(self):
        """Test username comparison operators for sorting."""
        username1 = Username("alice")
        username2 = Username("bob")
        username3 = Username("Alice")  # Same as username1
        
        assert username1 < username2
        assert username2 > username1
        assert username1 <= username3
        assert username1 >= username3

    def test_username_numeric_only(self):
        """Test numeric-only usernames."""
        # Should be valid
        username = Username("12345")
        assert username.value == "12345"
        
        # But not recommended
        assert username.is_numeric_only()

    def test_username_similar_to_email(self):
        """Test usernames that look like emails are rejected."""
        with pytest.raises(DomainError):
            Username("user@domain")

    def test_username_url_safe(self):
        """Test username is URL-safe."""
        username = Username("john.doe_123")
        assert username.is_url_safe()
        
        # Check URL encoding not needed
        import urllib.parse
        assert urllib.parse.quote(username.value) == username.value

    def test_username_display_name(self):
        """Test username display name generation."""
        username = Username("john_doe")
        assert username.display_name == "John Doe"
        
        username2 = Username("john.doe.smith")
        assert username2.display_name == "John Doe Smith"
        
        username3 = Username("johndoe")
        assert username3.display_name == "Johndoe"

    def test_username_mentions_format(self):
        """Test username mention format (like @username)."""
        username = Username("john_doe")
        assert username.mention_format == "@john_doe"

    def test_username_slug_format(self):
        """Test username slug format for URLs."""
        username = Username("John.Doe_123")
        assert username.slug == "john-doe-123"