"""
Test cases for DeviceName value object.

Tests all aspects of device names including validation, normalization,
pattern detection, and security features.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.device_name import (
    DeviceName,
    DeviceNamePattern,
)


class TestDeviceNameCreation:
    """Test DeviceName creation and validation."""

    def test_create_valid_device_name(self):
        """Test creating a valid device name."""
        device_name = DeviceName(
            value="John's iPhone", pattern=DeviceNamePattern.PERSONAL
        )

        assert device_name.value == "John's iPhone"
        assert device_name.pattern == DeviceNamePattern.PERSONAL
        assert device_name.is_personal is True
        assert device_name.is_generic is False
        assert device_name.is_generated is False

    def test_create_with_different_patterns(self):
        """Test creating device names with different patterns."""
        # Personal pattern
        personal = DeviceName(
            value="Sarah's MacBook", pattern=DeviceNamePattern.PERSONAL
        )
        assert personal.pattern == DeviceNamePattern.PERSONAL
        assert personal.is_personal is True

        # Model-based pattern
        model = DeviceName(value="iPhone 15 Pro", pattern=DeviceNamePattern.MODEL_BASED)
        assert model.pattern == DeviceNamePattern.MODEL_BASED
        assert model.is_generic is True

        # Location-based pattern
        location = DeviceName(
            value="Office Desktop", pattern=DeviceNamePattern.LOCATION_BASED
        )
        assert location.pattern == DeviceNamePattern.LOCATION_BASED

        # Generated pattern
        generated = DeviceName(
            value="Device-ABC123", pattern=DeviceNamePattern.GENERATED
        )
        assert generated.pattern == DeviceNamePattern.GENERATED
        assert generated.is_generated is True

    def test_invalid_device_name(self):
        """Test validation of invalid device names."""
        # Empty name
        with pytest.raises(ValueError, match="Device name cannot be empty"):
            DeviceName(value="")

        # Whitespace only
        with pytest.raises(ValueError, match="Device name cannot be empty"):
            DeviceName(value="   ")

        # Too long
        with pytest.raises(ValueError, match="Device name too long"):
            DeviceName(value="a" * 101)

        # SQL injection attempt
        with pytest.raises(ValueError, match="Device name contains invalid characters"):
            DeviceName(value="Robert'; DROP TABLE devices;--")

        # XSS attempt
        with pytest.raises(ValueError, match="Device name contains invalid characters"):
            DeviceName(value="<script>alert('xss')</script>")

        # Control characters
        with pytest.raises(ValueError, match="Device name contains invalid characters"):
            DeviceName(value="Device\x00Name")


class TestDeviceNameNormalization:
    """Test device name normalization."""

    def test_whitespace_normalization(self):
        """Test whitespace normalization."""
        # Multiple spaces
        name1 = DeviceName(value="John's    iPhone")
        assert name1.value == "John's iPhone"

        # Leading/trailing whitespace
        name2 = DeviceName(value="  Office Computer  ")
        assert name2.value == "Office Computer"

        # Mixed whitespace
        name3 = DeviceName(value="My\t\nDevice")
        assert name3.value == "My Device"

    def test_special_character_handling(self):
        """Test special character handling."""
        # Allowed special characters
        allowed = DeviceName(value="John's iPhone (Work)")
        assert "'" in allowed.value
        assert "(" in allowed.value
        assert ")" in allowed.value

        # Remove disallowed special characters
        cleaned = DeviceName(value="Device@Name#123!")
        assert "@" not in cleaned.value
        assert "#" not in cleaned.value
        assert "!" not in cleaned.value

    def test_unicode_normalization(self):
        """Test Unicode normalization."""
        # Accented characters
        name1 = DeviceName(value="José's iPhone")
        assert "José" in name1.value

        # Emoji handling
        name2 = DeviceName(value="My Phone 📱")
        assert name2.value  # Should handle gracefully

        # Different Unicode forms
        name3 = DeviceName(value="Café Computer")  # NFC
        name4 = DeviceName(value="Café Computer")  # NFD
        assert name3.value == name4.value  # Should normalize to same form


class TestDeviceNamePatternDetection:
    """Test automatic pattern detection."""

    def test_personal_pattern_detection(self):
        """Test detection of personal device names."""
        personal_names = [
            "John's iPhone",
            "Sarah's MacBook",
            "Mike's PC",
            "Emma's Laptop",
            "David's Phone",
        ]

        for name_str in personal_names:
            name = DeviceName(value=name_str)
            assert name.pattern == DeviceNamePattern.PERSONAL
            assert name.is_personal is True

    def test_model_pattern_detection(self):
        """Test detection of model-based device names."""
        model_names = [
            "iPhone 15 Pro",
            "Galaxy S23 Ultra",
            "MacBook Pro M3",
            "Dell XPS 15",
            "Surface Pro 9",
        ]

        for name_str in model_names:
            name = DeviceName(value=name_str)
            assert name.pattern == DeviceNamePattern.MODEL_BASED

    def test_location_pattern_detection(self):
        """Test detection of location-based device names."""
        location_names = [
            "Office Desktop",
            "Home Computer",
            "Kitchen iPad",
            "Living Room TV",
            "Bedroom Laptop",
        ]

        for name_str in location_names:
            name = DeviceName(value=name_str)
            assert name.pattern == DeviceNamePattern.LOCATION_BASED

    def test_custom_pattern_detection(self):
        """Test detection of custom device names."""
        custom_names = [
            "My Awesome Device",
            "WorkHorse 2000",
            "Gaming Rig",
            "Development Machine",
            "Test Device",
        ]

        for name_str in custom_names:
            name = DeviceName(value=name_str)
            assert name.pattern == DeviceNamePattern.CUSTOM


class TestDeviceNameGeneration:
    """Test device name generation."""

    def test_generate_default_name(self):
        """Test default name generation."""
        # With user name
        personal = DeviceName.generate_default("iPhone", "Alice")
        assert personal.value == "Alice's iPhone"
        assert personal.pattern == DeviceNamePattern.PERSONAL

        # Without user name
        generic = DeviceName.generate_default("Laptop")
        assert "Laptop" in generic.value
        assert generic.pattern == DeviceNamePattern.GENERATED

    def test_generate_unique_name(self):
        """Test unique name generation."""
        existing_names = ["Office Computer", "Office Computer 2", "Office Computer 3"]

        unique = DeviceName.generate_unique("Office Computer", existing_names)
        assert unique.value == "Office Computer 4"
        assert unique.value not in existing_names

    def test_generate_anonymous_name(self):
        """Test anonymous name generation."""
        anonymous = DeviceName.generate_anonymous("iPhone")
        assert "Anonymous" in anonymous.value
        assert "iPhone" in anonymous.value
        assert anonymous.pattern == DeviceNamePattern.GENERATED
        assert anonymous.contains_pii is False


class TestDeviceNamePII:
    """Test PII detection and handling."""

    def test_pii_detection(self):
        """Test detection of PII in device names."""
        # Names with PII
        pii_names = [
            "John Smith's iPhone",
            "sarah.jones@company.com Device",
            "Bob's Phone (555-1234)",
            "Alice Johnson MacBook",
        ]

        for name_str in pii_names:
            name = DeviceName(value=name_str)
            assert name.contains_pii is True

        # Names without PII
        safe_names = ["Office Desktop", "iPhone 15", "Gaming PC", "Test Device"]

        for name_str in safe_names:
            name = DeviceName(value=name_str)
            assert name.contains_pii is False

    def test_email_detection(self):
        """Test email detection in device names."""
        email_name = DeviceName(value="john.doe@example.com's Device")
        assert email_name.contains_pii is True
        assert email_name.has_email is True

    def test_phone_detection(self):
        """Test phone number detection in device names."""
        phone_names = [
            "Device (555) 123-4567",
            "Phone 555-1234",
            "+1-555-123-4567 Work",
        ]

        for name_str in phone_names:
            name = DeviceName(value=name_str)
            assert name.contains_pii is True
            assert name.has_phone is True


class TestDeviceNameAnonymization:
    """Test device name anonymization."""

    def test_anonymize_personal_name(self):
        """Test anonymization of personal device names."""
        personal = DeviceName(value="John's iPhone")
        anonymized = personal.anonymize()

        assert anonymized.value == "Anonymous iPhone"
        assert anonymized.pattern == DeviceNamePattern.GENERATED
        assert anonymized.contains_pii is False
        assert "John" not in anonymized.value

    def test_anonymize_safe_name(self):
        """Test that safe names are not unnecessarily anonymized."""
        safe = DeviceName(value="Office Computer")
        anonymized = safe.anonymize()

        assert anonymized.value == safe.value  # No change needed
        assert anonymized.pattern == safe.pattern

    def test_anonymize_with_preservation(self):
        """Test anonymization while preserving device type."""
        names_and_expected = [
            ("Sarah's MacBook Pro", "Anonymous MacBook Pro"),
            ("john.doe@email.com iPad", "Anonymous iPad"),
            ("Mike's Gaming PC", "Anonymous Gaming PC"),
        ]

        for original_str, expected in names_and_expected:
            original = DeviceName(value=original_str)
            anonymized = original.anonymize()
            assert anonymized.value == expected


class TestDeviceNameFormatting:
    """Test device name formatting."""

    def test_display_formatting(self):
        """Test display formatting with length limits."""
        long_name = DeviceName(
            value="This is a very long device name that exceeds normal display limits and should be truncated"
        )

        # Short display
        short = long_name.format_display(max_length=20)
        assert len(short) <= 20
        assert short.endswith("...")

        # Medium display
        medium = long_name.format_display(max_length=50)
        assert len(medium) <= 50

        # Full display
        full = long_name.format_display()
        assert full == long_name.value

    def test_safe_formatting(self):
        """Test safe formatting for different contexts."""
        # HTML context
        html_name = DeviceName(value="Device <script>alert('xss')</script>")
        safe_html = html_name.format_safe_html()
        assert "<script>" not in safe_html
        assert "&lt;script&gt;" in safe_html

        # SQL context
        sql_name = DeviceName(value="Device'; DROP TABLE--")
        safe_sql = sql_name.format_safe_sql()
        assert "'" not in safe_sql or "''" in safe_sql

        # JSON context
        json_name = DeviceName(value='Device "quoted"')
        safe_json = json_name.format_safe_json()
        assert '\\"' in safe_json or safe_json.count('"') % 2 == 0


class TestDeviceNameSimilarity:
    """Test device name similarity calculations."""

    def test_exact_match_similarity(self):
        """Test similarity of exact matches."""
        name1 = DeviceName(value="John's iPhone")
        name2 = DeviceName(value="John's iPhone")

        assert name1.similarity_score(name2) == 1.0
        assert name1.is_similar_to(name2, threshold=0.9)

    def test_case_insensitive_similarity(self):
        """Test case-insensitive similarity."""
        name1 = DeviceName(value="Office Computer")
        name2 = DeviceName(value="office computer")

        similarity = name1.similarity_score(name2)
        assert similarity > 0.9  # Very similar despite case difference

    def test_partial_similarity(self):
        """Test partial name similarity."""
        name1 = DeviceName(value="John's iPhone 15 Pro")
        name2 = DeviceName(value="John's iPhone")

        similarity = name1.similarity_score(name2)
        assert 0.6 < similarity < 0.9  # Partially similar

    def test_different_names_similarity(self):
        """Test similarity of completely different names."""
        name1 = DeviceName(value="Office Desktop")
        name2 = DeviceName(value="Sarah's MacBook")

        similarity = name1.similarity_score(name2)
        assert similarity < 0.3  # Very different


class TestDeviceNameSecurity:
    """Test device name security features."""

    def test_name_immutability(self):
        """Test that device names are immutable."""
        name = DeviceName(value="Test Device")

        with pytest.raises(FrozenInstanceError):
            name.value = "Modified"

        with pytest.raises(FrozenInstanceError):
            name.pattern = DeviceNamePattern.GENERATED

    def test_name_comparison(self):
        """Test device name comparison."""
        name1 = DeviceName(value="Test Device")
        name2 = DeviceName(value="Test Device")
        name3 = DeviceName(value="Different Device")

        assert name1 == name2
        assert name1 != name3
        assert hash(name1) == hash(name2)
        assert hash(name1) != hash(name3)

    def test_secure_string_representation(self):
        """Test secure string representations."""
        # Name with PII
        pii_name = DeviceName(value="john.doe@email.com Device")

        str_repr = str(pii_name)
        repr(pii_name)

        # Should mask PII in string representation
        assert "john.doe@email.com" not in str_repr
        assert "****" in str_repr or "[PII]" in str_repr


class TestDeviceNameValidation:
    """Test device name validation rules."""

    def test_length_validation(self):
        """Test length validation rules."""
        # Minimum length
        with pytest.raises(ValueError):
            DeviceName(value="")  # Too short

        # Maximum length
        with pytest.raises(ValueError):
            DeviceName(value="a" * 101)  # Too long

        # Valid lengths
        short_valid = DeviceName(value="PC")
        assert len(short_valid.value) >= 2

        long_valid = DeviceName(value="a" * 100)
        assert len(long_valid.value) == 100

    def test_character_validation(self):
        """Test character validation rules."""
        # Valid characters
        valid_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '-()."
        )
        for char in valid_chars:
            name = DeviceName(value=f"Device{char}Name")
            assert char in name.value or name.value  # Should not raise

        # Invalid characters
        invalid_chars = "<>{}[]|\\^~`"
        for char in invalid_chars:
            with pytest.raises(ValueError):
                DeviceName(value=f"Device{char}Name")

    def test_reserved_name_validation(self):
        """Test validation of reserved names."""
        reserved_names = ["null", "undefined", "none", "nil", "true", "false"]

        for reserved in reserved_names:
            # Should either reject or modify reserved names
            name = DeviceName(value=reserved)
            assert name.value != reserved or name.pattern == DeviceNamePattern.GENERATED
        """Test creating a valid device name."""
        device_name = DeviceName(
            value="John's iPhone", pattern=DeviceNamePattern.PERSONAL
        )

        assert device_name.value == "John's iPhone"
        assert device_name.pattern == DeviceNamePattern.PERSONAL

    def test_create_with_auto_pattern_detection(self):
        """Test creating device name with automatic pattern detection."""
        device_name = DeviceName(value="iPhone 15 Pro")

        assert device_name.value == "iPhone 15 Pro"
        assert device_name.pattern == DeviceNamePattern.MODEL_BASED

    def test_normalization_whitespace(self):
        """Test whitespace normalization."""
        device_name = DeviceName(value="  John's   iPhone  ")

        assert device_name.value == "John's iPhone"

    def test_normalization_multiple_spaces(self):
        """Test multiple space normalization."""
        device_name = DeviceName(value="John's     iPhone")

        assert device_name.value == "John's iPhone"

    def test_normalization_unicode(self):
        """Test Unicode normalization."""
        # Using Unicode with combining characters
        device_name = DeviceName(value="Café's iPad")  # é as combining characters

        assert "Café" in device_name.value
        assert device_name.value == "Café's iPad"

    def test_normalization_special_characters(self):
        """Test special character filtering."""
        device_name = DeviceName(value="John's iPhone@#$%")

        # Should remove invalid special characters
        assert device_name.value == "John's iPhone"

    def test_empty_name_raises_error(self):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="Device name cannot be empty"):
            DeviceName(value="")

    def test_whitespace_only_name_raises_error(self):
        """Test that whitespace-only name raises ValueError."""
        with pytest.raises(ValueError, match="Device name cannot be empty"):
            DeviceName(value="   ")

    def test_name_too_short_after_normalization_raises_error(self):
        """Test that name too short after normalization raises error."""
        with pytest.raises(
            ValueError, match="Device name too short after normalization"
        ):
            DeviceName(value="@#$%")  # Only special chars, will be removed

    def test_name_too_long_raises_error(self):
        """Test that name too long raises ValueError."""
        long_name = "x" * 101

        with pytest.raises(ValueError, match="Device name too long"):
            DeviceName(value=long_name)

    def test_sql_injection_patterns_raise_error(self):
        """Test that SQL injection patterns raise error."""
        malicious_names = [
            "Device'; DROP TABLE users; --",
            "Device UNION SELECT * FROM passwords",
            "Device/* malicious comment */",
            'Device"test"something',
        ]

        for malicious_name in malicious_names:
            with pytest.raises(
                ValueError, match="Device name contains invalid characters or patterns"
            ):
                DeviceName(value=malicious_name)

    def test_xss_patterns_raise_error(self):
        """Test that XSS patterns raise error."""
        malicious_names = [
            "Device<script>alert('xss')</script>",
            "Device javascript:alert('xss')",
            "Device onclick=alert('xss')",
            "Device onload=malicious()",
        ]

        for malicious_name in malicious_names:
            with pytest.raises(
                ValueError, match="Device name contains invalid characters or patterns"
            ):
                DeviceName(value=malicious_name)

    def test_no_alphanumeric_raises_error(self):
        """Test that names without alphanumeric characters raise error."""
        with pytest.raises(
            ValueError, match="Device name contains invalid characters or patterns"
        ):
            DeviceName(value="!@#$%^&*()")


class TestDeviceNamePatternDetection:
    """Test device name pattern detection."""

    def test_detect_personal_pattern(self):
        """Test detection of personal naming pattern."""
        personal_names = ["John's iPhone", "Mary's Android", "Bob's Tablet"]

        for name in personal_names:
            device_name = DeviceName(value=name)
            assert device_name.pattern == DeviceNamePattern.PERSONAL

    def test_detect_model_based_pattern(self):
        """Test detection of model-based naming pattern."""
        model_names = [
            "iPhone 15 Pro",
            "Samsung Galaxy S24",
            "MacBook Pro 2023",
            "Surface Laptop",
            "ThinkPad X1",
            "Dell Inspiron",
        ]

        for name in model_names:
            device_name = DeviceName(value=name)
            assert device_name.pattern == DeviceNamePattern.MODEL_BASED

    def test_detect_location_based_pattern(self):
        """Test detection of location-based naming pattern."""
        location_names = [
            "Office Desktop",
            "Home Laptop",
            "Work Mobile",
            "Kitchen Tablet",
            "Living Room TV",
        ]

        for name in location_names:
            device_name = DeviceName(value=name)
            assert device_name.pattern == DeviceNamePattern.LOCATION_BASED

    def test_detect_generated_pattern(self):
        """Test detection of generated UUID pattern."""
        uuid_names = [
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400e29b41d4a716446655440000",  # Without hyphens
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ]

        for name in uuid_names:
            device_name = DeviceName(value=name)
            assert device_name.pattern == DeviceNamePattern.GENERATED

    def test_detect_custom_pattern(self):
        """Test detection of custom naming pattern."""
        custom_names = [
            "My Device",
            "Gaming Rig",
            "Primary Computer",
            "Test Device 123",
        ]

        for name in custom_names:
            device_name = DeviceName(value=name)
            assert device_name.pattern == DeviceNamePattern.CUSTOM

    def test_explicit_pattern_overrides_detection(self):
        """Test that explicitly set pattern overrides detection."""
        device_name = DeviceName(
            value="iPhone 15 Pro",  # Would normally be MODEL_BASED
            pattern=DeviceNamePattern.CUSTOM,
        )

        assert device_name.pattern == DeviceNamePattern.CUSTOM


class TestDeviceNameGeneration:
    """Test device name generation methods."""

    def test_generate_default_with_user_name(self):
        """Test generating default name with user name."""
        device_name = DeviceName.generate_default("iPhone", user_name="John")

        assert device_name.value == "John's iPhone"
        assert device_name.pattern == DeviceNamePattern.PERSONAL

    def test_generate_default_without_user_name(self):
        """Test generating default name without user name."""
        device_name = DeviceName.generate_default("Laptop")

        assert "Laptop" in device_name.value
        assert device_name.pattern == DeviceNamePattern.GENERATED
        # Should include timestamp
        import re

        assert re.search(r"\d{8}", device_name.value)  # YYYYMMDD format

    def test_generate_default_various_device_types(self):
        """Test generating default names for various device types."""
        device_types = ["Phone", "Tablet", "Desktop", "Smartwatch"]

        for device_type in device_types:
            device_name = DeviceName.generate_default(device_type, user_name="Alice")
            assert device_name.value == f"Alice's {device_type}"
            assert device_name.pattern == DeviceNamePattern.PERSONAL


class TestDeviceNameProperties:
    """Test device name properties."""

    def test_is_personal_true(self):
        """Test is_personal property when true."""
        device_name = DeviceName(
            value="John's iPhone", pattern=DeviceNamePattern.PERSONAL
        )

        assert device_name.is_personal is True

    def test_is_personal_false(self):
        """Test is_personal property when false."""
        device_name = DeviceName(
            value="iPhone 15 Pro", pattern=DeviceNamePattern.MODEL_BASED
        )

        assert device_name.is_personal is False

    def test_is_generic_true_generated(self):
        """Test is_generic property with generated pattern."""
        device_name = DeviceName(
            value="Device 20240101", pattern=DeviceNamePattern.GENERATED
        )

        assert device_name.is_generic is True

    def test_is_generic_true_model_based(self):
        """Test is_generic property with model-based pattern."""
        device_name = DeviceName(
            value="iPhone 15 Pro", pattern=DeviceNamePattern.MODEL_BASED
        )

        assert device_name.is_generic is True

    def test_is_generic_false(self):
        """Test is_generic property when false."""
        device_name = DeviceName(
            value="John's iPhone", pattern=DeviceNamePattern.PERSONAL
        )

        assert device_name.is_generic is False

    def test_contains_pii_personal_pattern(self):
        """Test contains_pii with personal pattern."""
        device_name = DeviceName(
            value="John's iPhone", pattern=DeviceNamePattern.PERSONAL
        )

        assert device_name.contains_pii is True

    def test_contains_pii_multiple_capitalized_words(self):
        """Test contains_pii with multiple capitalized words."""
        device_name = DeviceName(
            value="John Smith Device", pattern=DeviceNamePattern.CUSTOM
        )

        assert device_name.contains_pii is True

    def test_contains_pii_email_pattern(self):
        """Test contains_pii with email-like pattern."""
        device_name = DeviceName(
            value="john.smith@company.com Device", pattern=DeviceNamePattern.CUSTOM
        )

        assert device_name.contains_pii is True

    def test_contains_pii_false(self):
        """Test contains_pii when false."""
        device_name = DeviceName(
            value="Office Desktop", pattern=DeviceNamePattern.LOCATION_BASED
        )

        assert device_name.contains_pii is False

    def test_contains_pii_single_capitalized_word(self):
        """Test contains_pii with single capitalized word."""
        device_name = DeviceName(
            value="Office Device", pattern=DeviceNamePattern.CUSTOM
        )

        # Single capitalized word should not be considered PII
        assert device_name.contains_pii is False


class TestDeviceNameAnonymization:
    """Test device name anonymization."""

    def test_anonymize_already_anonymous(self):
        """Test anonymizing already anonymous name."""
        device_name = DeviceName(value="Office Desktop")
        anonymized = device_name.anonymize()

        assert anonymized == device_name  # Should be the same

    def test_anonymize_with_recognized_device_type(self):
        """Test anonymizing name with recognized device type."""
        device_name = DeviceName(value="John's iPhone")
        anonymized = device_name.anonymize()

        assert anonymized.value == "Anonymous iPhone"
        assert anonymized.pattern == DeviceNamePattern.GENERATED

    def test_anonymize_without_recognized_device_type(self):
        """Test anonymizing name without recognized device type."""
        device_name = DeviceName(value="John Smith Personal")
        anonymized = device_name.anonymize()

        assert anonymized.value == "Anonymous Device"
        assert anonymized.pattern == DeviceNamePattern.GENERATED

    def test_anonymize_case_insensitive_device_detection(self):
        """Test that device type detection is case insensitive."""
        device_name = DeviceName(value="john's android phone")
        anonymized = device_name.anonymize()

        assert "Android" in anonymized.value or "Phone" in anonymized.value

    def test_anonymize_various_device_types(self):
        """Test anonymizing various device types."""
        test_cases = [
            ("Mary's tablet", "Tablet"),
            ("Bob's desktop computer", "Desktop"),
            ("Alice's laptop", "Laptop"),
            ("Unknown device", "Device"),
        ]

        for original, expected_type in test_cases:
            device_name = DeviceName(value=original)
            anonymized = device_name.anonymize()
            assert expected_type in anonymized.value


class TestDeviceNameFormatting:
    """Test device name formatting methods."""

    def test_format_display_short_name(self):
        """Test format_display with short name."""
        device_name = DeviceName(value="iPhone")

        assert device_name.format_display() == "iPhone"
        assert device_name.format_display(max_length=10) == "iPhone"

    def test_format_display_long_name(self):
        """Test format_display with long name."""
        long_name = "Very Long Device Name That Exceeds Limit"
        device_name = DeviceName(value=long_name)

        formatted = device_name.format_display(max_length=20)
        assert len(formatted) == 20
        assert formatted.endswith("...")
        assert formatted == long_name[:17] + "..."

    def test_format_display_default_length(self):
        """Test format_display with default max length."""
        long_name = "This is a very long device name that exceeds thirty characters"
        device_name = DeviceName(value=long_name)

        formatted = device_name.format_display()  # Default 30 chars
        assert len(formatted) == 30
        assert formatted.endswith("...")

    def test_format_safe_html_escaping(self):
        """Test HTML escaping in format_safe."""
        device_name = DeviceName(value="Device & 'Test' \"Quote\" <tag>")

        safe_formatted = device_name.format_safe()

        assert "&amp;" in safe_formatted
        assert "&#39;" in safe_formatted
        assert "&quot;" in safe_formatted
        assert "&lt;" in safe_formatted
        assert "&gt;" in safe_formatted

        # Should not contain any raw HTML characters
        assert "&" not in safe_formatted or "&amp;" in safe_formatted
        assert "<" not in safe_formatted
        assert ">" not in safe_formatted

    def test_format_safe_no_html_chars(self):
        """Test format_safe with no HTML characters."""
        device_name = DeviceName(value="Normal Device Name")

        safe_formatted = device_name.format_safe()
        assert safe_formatted == "Normal Device Name"


class TestDeviceNameSimilarity:
    """Test device name similarity scoring."""

    def test_similarity_identical_names(self):
        """Test similarity of identical names."""
        device_name1 = DeviceName(value="iPhone")
        device_name2 = DeviceName(value="iPhone")

        assert device_name1.similarity_score(device_name2) == 1.0

    def test_similarity_completely_different_names(self):
        """Test similarity of completely different names."""
        device_name1 = DeviceName(value="iPhone")
        device_name2 = DeviceName(value="Android")

        score = device_name1.similarity_score(device_name2)
        assert 0.0 <= score < 1.0

    def test_similarity_case_insensitive(self):
        """Test that similarity is case insensitive."""
        device_name1 = DeviceName(value="iPhone")
        device_name2 = DeviceName(value="iphone")

        # Should have high similarity despite case difference
        score = device_name1.similarity_score(device_name2)
        assert score > 0.8

    def test_similarity_partial_match(self):
        """Test similarity with partial matches."""
        device_name1 = DeviceName(value="iPhone 15")
        device_name2 = DeviceName(value="iPhone 14")

        score = device_name1.similarity_score(device_name2)
        assert 0.5 < score < 1.0

    def test_similarity_empty_strings(self):
        """Test similarity edge case with empty content."""
        # This test may not be applicable due to validation,
        # but tests the underlying algorithm
        device_name = DeviceName(value="test")

        # Test levenshtein distance implementation
        distance = device_name._levenshtein_distance("", "")
        assert distance == 0

    def test_levenshtein_distance_implementation(self):
        """Test the Levenshtein distance implementation."""
        device_name = DeviceName(value="test")

        # Test known cases
        assert device_name._levenshtein_distance("kitten", "sitting") == 3
        assert device_name._levenshtein_distance("", "abc") == 3
        assert device_name._levenshtein_distance("abc", "") == 3
        assert device_name._levenshtein_distance("abc", "abc") == 0

    def test_similarity_various_lengths(self):
        """Test similarity with various string lengths."""
        short_name = DeviceName(value="PC")
        long_name = DeviceName(value="Personal Computer")

        score = short_name.similarity_score(long_name)
        assert 0.0 <= score <= 1.0


class TestDeviceNameStringRepresentation:
    """Test string representation methods."""

    def test_str_representation(self):
        """Test __str__ method."""
        device_name = DeviceName(value="iPhone 15 Pro")

        assert str(device_name) == "iPhone 15 Pro"

    def test_repr_representation(self):
        """Test __repr__ method."""
        device_name = DeviceName(value="iPhone 15 Pro")

        repr_str = repr(device_name)
        assert "DeviceName" in repr_str
        assert "iPhone 15 Pro" in repr_str
        assert device_name.pattern.value in repr_str

    def test_repr_with_long_name(self):
        """Test __repr__ with long name uses display formatting."""
        long_name = "Very Long Device Name That Should Be Truncated"
        device_name = DeviceName(value=long_name)

        repr_str = repr(device_name)
        # Should use format_display() which truncates
        if len(long_name) > 30:
            assert "..." in repr_str


class TestDeviceNameImmutability:
    """Test that DeviceName is immutable."""

    def test_immutable_value(self):
        """Test that value cannot be changed."""
        device_name = DeviceName(value="iPhone")

        with pytest.raises(FrozenInstanceError):
            device_name.value = "Android"

    def test_immutable_pattern(self):
        """Test that pattern cannot be changed."""
        device_name = DeviceName(value="iPhone")

        with pytest.raises(FrozenInstanceError):
            device_name.pattern = DeviceNamePattern.CUSTOM


class TestDeviceNameEquality:
    """Test equality and comparison behavior."""

    def test_equal_device_names(self):
        """Test that identical device names are equal."""
        device_name1 = DeviceName(value="iPhone", pattern=DeviceNamePattern.MODEL_BASED)

        device_name2 = DeviceName(value="iPhone", pattern=DeviceNamePattern.MODEL_BASED)

        assert device_name1 == device_name2

    def test_different_values_not_equal(self):
        """Test that different values are not equal."""
        device_name1 = DeviceName(value="iPhone")
        device_name2 = DeviceName(value="Android")

        assert device_name1 != device_name2

    def test_different_patterns_not_equal(self):
        """Test that different patterns are not equal."""
        device_name1 = DeviceName(value="iPhone", pattern=DeviceNamePattern.MODEL_BASED)

        device_name2 = DeviceName(value="iPhone", pattern=DeviceNamePattern.CUSTOM)

        assert device_name1 != device_name2


class TestDeviceNameEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_all_device_name_patterns_supported(self):
        """Test that all device name patterns are supported."""
        test_names = {
            DeviceNamePattern.PERSONAL: "John's iPhone",
            DeviceNamePattern.MODEL_BASED: "iPhone 15 Pro",
            DeviceNamePattern.LOCATION_BASED: "Office Desktop",
            DeviceNamePattern.CUSTOM: "My Device",
            DeviceNamePattern.GENERATED: "Device 20240101",
        }

        for pattern, name in test_names.items():
            device_name = DeviceName(value=name, pattern=pattern)
            assert device_name.pattern == pattern

    def test_maximum_valid_length(self):
        """Test device name with maximum valid length."""
        max_length_name = "x" * 100
        device_name = DeviceName(value=max_length_name)

        assert len(device_name.value) == 100

    def test_unicode_characters(self):
        """Test with various Unicode characters."""
        unicode_names = [
            "Café's iPhone",
            "João's Android",
            "Müller's Device",
            "Device_测试",
        ]

        for name in unicode_names:
            device_name = DeviceName(value=name)
            assert device_name.value is not None
            assert len(device_name.value) > 0

    def test_allowed_special_characters(self):
        """Test that allowed special characters are preserved."""
        allowed_chars_name = "John's iPhone-2024 (Work).Device_v1.0, & Co"
        device_name = DeviceName(value=allowed_chars_name)

        # Should preserve allowed characters
        assert "'" in device_name.value
        assert "-" in device_name.value
        assert "(" in device_name.value
        assert ")" in device_name.value
        assert "." in device_name.value
        assert "_" in device_name.value
        assert "," in device_name.value
        assert "&" in device_name.value

    def test_control_character_removal(self):
        """Test that control characters are removed."""
        # Include some control characters
        name_with_controls = "Device\x00\x01\x02Name"
        device_name = DeviceName(value=name_with_controls)

        assert device_name.value == "DeviceName"

    def test_similarity_edge_cases(self):
        """Test similarity calculation edge cases."""
        device_name = DeviceName(value="test")

        # Test when one string is much longer
        short = "a"
        long_str = "a" * 100

        distance = device_name._levenshtein_distance(short, long_str)
        assert distance == 99

    def test_pattern_detection_edge_cases(self):
        """Test pattern detection with edge cases."""
        # Case where multiple patterns could match
        device_name = DeviceName(value="John's Office iPhone")

        # Should detect personal pattern first (has possessive)
        assert device_name.pattern == DeviceNamePattern.PERSONAL

    def test_anonymization_with_multiple_device_types(self):
        """Test anonymization when multiple device types are present."""
        device_name = DeviceName(value="John's iPhone Mobile Device")
        anonymized = device_name.anonymize()

        # Should pick the first matching device type
        assert "iPhone" in anonymized.value or "Mobile" in anonymized.value

    def test_format_display_exact_boundary(self):
        """Test format_display at exact boundary."""
        # Name exactly at limit
        name_exact = "x" * 30
        device_name = DeviceName(value=name_exact)

        formatted = device_name.format_display(max_length=30)
        assert formatted == name_exact
        assert not formatted.endswith("...")

    def test_normalization_preserves_valid_content(self):
        """Test that normalization preserves valid content."""
        original = "John's iPhone-2024 (Work)"
        device_name = DeviceName(value=original)

        # Should preserve the structure and valid characters
        assert "John's" in device_name.value
        assert "iPhone" in device_name.value
        assert "2024" in device_name.value
        assert "Work" in device_name.value
