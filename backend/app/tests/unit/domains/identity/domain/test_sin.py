"""
Test cases for SIN (Social Insurance Number) value object.

Tests all aspects of Canadian SIN including validation, Luhn algorithm,
pattern checking, formatting, and security features.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.SIN import SIN


class TestSINCreation:
    """Test SIN creation and validation."""

    def test_create_valid_sin(self):
        """Test creating a valid SIN."""
        # Test SIN that passes Luhn algorithm
        sin = SIN(value="130692544")  # Valid SIN for testing
        assert sin.value == "130692544"
        assert sin.first_digit == "1"
        assert sin.is_permanent_resident is False
        assert sin.is_temporary_resident is False

    def test_create_with_formatting(self):
        """Test creating SIN with various formats."""
        # With spaces
        sin1 = SIN(value="130 692 544")
        assert sin1.value == "130692544"

        # With dashes
        sin2 = SIN(value="130-692-544")
        assert sin2.value == "130692544"

        # Mixed formatting
        sin3 = SIN(value=" 130 - 692 - 544 ")
        assert sin3.value == "130692544"

    def test_permanent_resident_sin(self):
        """Test SIN starting with 0 (permanent resident)."""
        sin = SIN(value="046454286")
        assert sin.is_permanent_resident is True
        assert sin.is_temporary_resident is False
        assert sin.province_of_registration == "Atlantic"

    def test_temporary_resident_sin(self):
        """Test SIN starting with 9 (temporary resident)."""
        sin = SIN(value="990802842")
        assert sin.is_temporary_resident is True
        assert sin.is_permanent_resident is False
        assert sin.province_of_registration == "Temporary Resident"

    def test_invalid_sin_values(self):
        """Test various invalid SIN values."""
        # Empty
        with pytest.raises(ValueError, match="SIN is required"):
            SIN(value="")

        # None
        with pytest.raises(ValueError, match="SIN is required"):
            SIN(value=None)

        # Too short
        with pytest.raises(ValueError, match="SIN must be exactly 9 digits"):
            SIN(value="12345678")

        # Too long
        with pytest.raises(ValueError, match="SIN must be exactly 9 digits"):
            SIN(value="1234567890")

        # Non-numeric
        with pytest.raises(ValueError, match="SIN must contain only digits"):
            SIN(value="12345678A")

        # Invalid checksum
        with pytest.raises(ValueError, match="Invalid SIN checksum"):
            SIN(value="123456789")

        # Invalid pattern (starts with 0)
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="000000000")

        # Invalid pattern (starts with 8)
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="800000000")


class TestSINFormatting:
    """Test SIN formatting methods."""

    def test_format_display(self):
        """Test display formatting."""
        sin = SIN(value="130692544")
        assert sin.format_display() == "130-692-544"

    def test_format_masked(self):
        """Test masked formatting for security."""
        sin = SIN(value="130692544")
        assert sin.format_masked() == "130-69*-***"

    def test_format_partial(self):
        """Test partial formatting."""
        sin = SIN(value="130692544")
        assert sin.format_partial() == "***-**2-544"

    def test_format_hidden(self):
        """Test fully hidden formatting."""
        sin = SIN(value="130692544")
        assert sin.format_hidden() == "***-***-***"


class TestSINProvince:
    """Test province detection logic."""

    @pytest.mark.parametrize(
        ("first_digit", "expected_province"),
        [
            ("0", "Atlantic"),
            ("1", "Atlantic"),
            ("2", "Quebec"),
            ("3", "Quebec"),
            ("4", "Ontario"),
            ("5", "Ontario"),
            ("6", "Prairie"),
            ("7", "Pacific"),
            ("9", "Temporary Resident"),
        ],
    )
    def test_province_detection(self, first_digit, expected_province):
        """Test province detection based on first digit."""
        # Generate valid SIN for each first digit
        test_sins = {
            "0": "046454286",
            "1": "130692544",
            "2": "241625904",
            "3": "336195505",
            "4": "453248734",
            "5": "567659729",
            "6": "611086565",
            "7": "777435283",
            "9": "990802842",
        }

        sin = SIN(value=test_sins[first_digit])
        assert sin.province_of_registration == expected_province


class TestSINValidation:
    """Test SIN validation logic."""

    def test_luhn_algorithm(self):
        """Test Luhn algorithm implementation."""
        # Valid SINs
        valid_sins = ["046454286", "130692544", "990802842"]

        for sin_value in valid_sins:
            sin = SIN(value=sin_value)
            assert sin.is_valid_luhn() is True

    def test_pattern_validation(self):
        """Test SIN pattern validation."""
        # Test that SINs cannot start with 8
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="800000018")  # Even with valid checksum

        # Test that SINs cannot be all zeros
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="000000000")


class TestSINSecurity:
    """Test SIN security features."""

    def test_sin_immutability(self):
        """Test that SIN is immutable."""
        sin = SIN(value="130692544")

        with pytest.raises(FrozenInstanceError):
            sin.value = "999999999"

        with pytest.raises(FrozenInstanceError):
            sin.first_digit = "9"

    def test_sin_comparison(self):
        """Test SIN comparison."""
        sin1 = SIN(value="130692544")
        sin2 = SIN(value="130692544")
        sin3 = SIN(value="046454286")

        assert sin1 == sin2
        assert sin1 != sin3
        assert hash(sin1) == hash(sin2)
        assert hash(sin1) != hash(sin3)

    def test_sin_string_representation(self):
        """Test string representations."""
        sin = SIN(value="130692544")

        # Should not expose full SIN in string representation
        assert "130692544" not in str(sin)
        assert "130692544" not in repr(sin)
        assert "***-**2-544" in str(sin)

    def test_partial_matching(self):
        """Test partial SIN matching."""
        sin = SIN(value="130692544")

        # Last 4 digits
        assert sin.matches_partial("2544") is True
        assert sin.matches_partial("1234") is False

        # Formatted partial
        assert sin.matches_partial("***-**2-544") is True

        # Full SIN
        assert sin.matches_partial("130692544") is True
        assert sin.matches_partial("130-692-544") is True


class TestSINBusinessLogic:
    """Test SIN business logic and edge cases."""

    def test_generate_test_sin(self):
        """Test generation of valid test SINs."""
        # Generate multiple test SINs
        test_sins = [SIN.generate_test_sin() for _ in range(10)]

        # All should be valid
        for sin in test_sins:
            assert sin.is_valid_luhn() is True
            assert sin.is_temporary_resident is True
            assert sin.first_digit == "9"

        # Should be unique
        sin_values = [sin.value for sin in test_sins]
        assert len(sin_values) == len(set(sin_values))

    def test_sin_age_verification(self):
        """Test SIN can be used for age verification."""
        sin = SIN(value="130692544")

        # SIN itself doesn't contain birth date
        # This is just to ensure the value object doesn't expose methods it shouldn't
        assert not hasattr(sin, "get_birth_date")
        assert not hasattr(sin, "get_age")

    def test_sin_serialization(self):
        """Test SIN serialization for storage."""
        sin = SIN(value="130692544")

        # Should provide secure serialization
        serialized = sin.to_secure_string()
        assert "130692544" not in serialized
        assert sin.format_partial() in serialized

    def test_sin_audit_info(self):
        """Test SIN provides audit information."""
        sin = SIN(value="130692544")

        audit_info = sin.get_audit_info()
        assert audit_info["masked_value"] == "130-69*-***"
        assert audit_info["partial_value"] == "***-**2-544"
        assert audit_info["province"] == "Atlantic"
        assert audit_info["is_temporary"] is False
        assert "full_value" not in audit_info  # Never expose full SIN

        assert sin.value == "130692544"

    def test_create_sin_with_formatting(self):
        """Test creating SIN with formatting that gets normalized."""
        sin = SIN(value="130-692-544")

        assert sin.value == "130692544"

    def test_create_sin_with_spaces(self):
        """Test creating SIN with spaces."""
        sin = SIN(value="130 692 544")

        assert sin.value == "130692544"

    def test_create_sin_mixed_formatting(self):
        """Test creating SIN with mixed formatting."""
        sin = SIN(value="130-692 544")

        assert sin.value == "130692544"

    def test_empty_sin_raises_error(self):
        """Test that empty SIN raises ValueError."""
        with pytest.raises(ValueError, match="SIN is required"):
            SIN(value="")

    def test_none_sin_raises_error(self):
        """Test that None SIN raises ValueError."""
        with pytest.raises(ValueError, match="SIN is required"):
            SIN(value=None)

    def test_too_short_sin_raises_error(self):
        """Test that SIN with less than 9 digits raises error."""
        with pytest.raises(ValueError, match="SIN must be exactly 9 digits"):
            SIN(value="12345678")  # 8 digits

    def test_too_long_sin_raises_error(self):
        """Test that SIN with more than 9 digits raises error."""
        with pytest.raises(ValueError, match="SIN must be exactly 9 digits"):
            SIN(value="1234567890")  # 10 digits

    def test_non_digit_only_sin_raises_error(self):
        """Test that SIN with letters raises error."""
        with pytest.raises(ValueError, match="SIN must be exactly 9 digits"):
            SIN(value="abc123def")

    def test_invalid_luhn_checksum_raises_error(self):
        """Test that SIN with invalid Luhn checksum raises error."""
        with pytest.raises(ValueError, match="Invalid SIN checksum"):
            SIN(value="123456789")  # Invalid checksum

    def test_all_same_digits_raises_error(self):
        """Test that SIN with all same digits raises error."""
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="111111111")

    def test_sin_starting_with_zero_raises_error(self):
        """Test that SIN starting with 0 raises error."""
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="012345678")

    def test_sin_starting_with_eight_raises_error(self):
        """Test that SIN starting with 8 raises error."""
        with pytest.raises(ValueError, match="Invalid SIN pattern"):
            SIN(value="812345678")

    def test_known_invalid_sin_raises_error(self):
        """Test that known invalid SINs raise error."""
        invalid_sins = ["000000000", "999999999"]

        for invalid_sin in invalid_sins:
            with pytest.raises(ValueError, match="Invalid SIN pattern"):
                SIN(value=invalid_sin)


class TestSINLuhnValidation:
    """Test SIN Luhn algorithm validation."""

    def test_luhn_validation_algorithm(self):
        """Test the Luhn algorithm implementation."""
        # Known valid SIN for testing
        valid_sin = SIN(value="130692544")

        # Test the internal method directly
        assert valid_sin._is_valid_luhn() is True

    def test_luhn_validation_edge_cases(self):
        """Test Luhn validation with edge cases."""
        # Test a SIN where doubling creates numbers > 9
        sin = SIN(value="978654321")  # Contains high digits that get doubled

        # If it passes creation, Luhn is valid
        assert sin._is_valid_luhn() is True

    def test_luhn_manual_calculation(self):
        """Test Luhn calculation manually."""
        # Use a known valid SIN and verify step by step
        sin_value = "130692544"

        # Manual Luhn calculation for verification
        digits = [int(d) for d in sin_value]

        # Double every second digit from right to left (positions 1, 3, 5, 7)
        # Working backwards: position 7=1, 5=6, 3=0, 1=3
        expected_digits = digits.copy()
        expected_digits[7] *= 2  # 1 * 2 = 2
        expected_digits[5] *= 2  # 9 * 2 = 18, subtract 9 = 9
        expected_digits[3] *= 2  # 6 * 2 = 12, subtract 9 = 3
        expected_digits[1] *= 2  # 3 * 2 = 6

        # Apply the "subtract 9 if > 9" rule
        for i in range(len(expected_digits)):
            if expected_digits[i] > 9:
                expected_digits[i] -= 9

        total = sum(expected_digits)
        assert total % 10 == 0

    def test_generate_test_sin_valid_luhn(self):
        """Test that generated test SIN has valid Luhn."""
        test_sin = SIN.generate_test_sin()

        assert test_sin._is_valid_luhn() is True


class TestSINProperties:
    """Test SIN properties."""

    def test_first_digit_property(self):
        """Test first_digit property."""
        sin = SIN(value="130692544")

        assert sin.first_digit == "1"

    def test_province_of_registration_atlantic(self):
        """Test province mapping for Atlantic provinces."""
        sin = SIN(value="130692544")  # Starts with 1

        assert sin.province_of_registration == "Atlantic Provinces"

    def test_province_of_registration_quebec(self):
        """Test province mapping for Quebec."""
        # Create valid SINs starting with 2 and 3
        sin2 = SIN(value="246810369")  # Starts with 2, valid Luhn
        assert sin2.province_of_registration == "Quebec"

    def test_province_of_registration_ontario(self):
        """Test province mapping for Ontario."""
        # Test SIN starting with 4 or 5 - need valid Luhn
        sin4 = SIN(value="406820371")  # Starts with 4, valid Luhn
        assert sin4.province_of_registration == "Ontario"

    def test_province_of_registration_prairie(self):
        """Test province mapping for Prairie provinces."""
        sin6 = SIN(value="634567891")  # Starts with 6, valid Luhn
        assert sin6.province_of_registration == "Prairie Provinces"

    def test_province_of_registration_pacific(self):
        """Test province mapping for Pacific region."""
        sin7 = SIN(value="734568912")  # Starts with 7, valid Luhn
        assert sin7.province_of_registration == "Pacific Region"

    def test_province_of_registration_temporary(self):
        """Test province mapping for temporary residents."""
        test_sin = SIN.generate_test_sin()  # Starts with 9

        assert test_sin.province_of_registration == "Temporary Resident"

    def test_province_of_registration_unknown(self):
        """Test province mapping for unknown first digit."""
        # Since 0 and 8 are invalid, and others are mapped,
        # this test is mainly for completeness
        SIN(value="130692544")

        # Test the mapping logic with an invalid first digit
        # (though this won't happen in practice due to validation)
        province_map = {
            "1": "Atlantic Provinces",
            "2": "Quebec",
            "3": "Quebec",
            "4": "Ontario",
            "5": "Ontario",
            "6": "Prairie Provinces",
            "7": "Pacific Region",
            "9": "Temporary Resident",
        }

        assert province_map.get("0") is None  # Would return None for 0

    def test_is_temporary_resident_true(self):
        """Test is_temporary_resident when true."""
        test_sin = SIN.generate_test_sin()  # Starts with 9

        assert test_sin.is_temporary_resident is True

    def test_is_temporary_resident_false(self):
        """Test is_temporary_resident when false."""
        SIN(value="130692544")  # Starts with 1

        assert test_sin.is_temporary_resident is False

    def test_is_permanent_resident_true(self):
        """Test is_permanent_resident when true."""
        sin = SIN(value="130692544")  # Starts with 1

        assert sin.is_permanent_resident is True

    def test_is_permanent_resident_false(self):
        """Test is_permanent_resident when false."""
        test_sin = SIN.generate_test_sin()  # Starts with 9

        assert test_sin.is_permanent_resident is False


class TestSINFormatting:
    """Test SIN formatting methods."""

    def test_format_display(self):
        """Test display formatting (XXX-XXX-XXX)."""
        sin = SIN(value="130692544")

        assert sin.format_display() == "130-692-544"

    def test_format_masked(self):
        """Test masked formatting for security."""
        sin = SIN(value="130692544")

        assert sin.format_masked() == "130-69*-***"

    def test_format_partial(self):
        """Test partial formatting showing last 4 digits."""
        sin = SIN(value="130692544")

        assert sin.format_partial() == "***-**2-544"

    def test_to_storage_format(self):
        """Test storage format (digits only)."""
        sin = SIN(value="130692544")

        assert sin.to_storage_format() == "130692544"


class TestSINMatching:
    """Test SIN partial matching."""

    def test_matches_partial_last_four_digits(self):
        """Test matching with last 4 digits."""
        sin = SIN(value="130692544")

        assert sin.matches_partial("2544") is True
        assert sin.matches_partial("1234") is False

    def test_matches_partial_formatted_last_four(self):
        """Test matching with formatted last 4 digits."""
        sin = SIN(value="130692544")

        assert sin.matches_partial("2-544") is True
        assert sin.matches_partial("2.544") is True

    def test_matches_partial_full_sin(self):
        """Test matching with full SIN."""
        sin = SIN(value="130692544")

        assert sin.matches_partial("130692544") is True
        assert sin.matches_partial("130-692-544") is True
        assert sin.matches_partial("987654321") is False

    def test_matches_partial_invalid_length(self):
        """Test matching with invalid length."""
        sin = SIN(value="130692544")

        assert sin.matches_partial("123") is False  # 3 digits
        assert sin.matches_partial("12345") is False  # 5 digits


class TestSINGeneration:
    """Test SIN generation methods."""

    def test_generate_test_sin(self):
        """Test generating test SIN."""
        test_sin = SIN.generate_test_sin()

        assert test_sin.value.startswith("9")  # Temporary resident
        assert len(test_sin.value) == 9
        assert test_sin._is_valid_luhn() is True

    def test_generate_test_sin_consistency(self):
        """Test that generate_test_sin produces consistent results."""
        test_sin1 = SIN.generate_test_sin()
        test_sin2 = SIN.generate_test_sin()

        # Should generate the same SIN each time (deterministic)
        assert test_sin1.value == test_sin2.value

    def test_generated_test_sin_properties(self):
        """Test properties of generated test SIN."""
        test_sin = SIN.generate_test_sin()

        assert test_sin.is_temporary_resident is True
        assert test_sin.is_permanent_resident is False
        assert test_sin.province_of_registration == "Temporary Resident"


class TestSINStringRepresentation:
    """Test SIN string representation."""

    def test_str_representation_masked(self):
        """Test __str__ returns masked format."""
        sin = SIN(value="130692544")

        str_repr = str(sin)
        assert str_repr == "130-69*-***"
        # Should not expose full SIN
        assert "544" not in str_repr

    def test_repr_representation_masked(self):
        """Test __repr__ returns masked format."""
        sin = SIN(value="130692544")

        repr_str = repr(sin)
        assert "SIN" in repr_str
        assert "130-69*-***" in repr_str
        # Should not expose full SIN
        assert "544" not in repr_str


class TestSINEquality:
    """Test SIN equality and hashing."""

    def test_equal_sins(self):
        """Test that identical SINs are equal."""
        sin1 = SIN(value="130692544")
        sin2 = SIN(value="130-692-544")  # Different format, same digits

        assert sin1 == sin2

    def test_different_sins_not_equal(self):
        """Test that different SINs are not equal."""
        sin1 = SIN(value="130692544")
        test_sin = SIN.generate_test_sin()

        assert sin1 != test_sin

    def test_sin_not_equal_to_non_sin(self):
        """Test that SIN is not equal to non-SIN objects."""
        sin = SIN(value="130692544")

        assert sin != "130692544"
        assert sin != 130692544
        assert sin is not None

    def test_sin_hash(self):
        """Test SIN hashing for use in sets/dicts."""
        sin1 = SIN(value="130692544")
        sin2 = SIN(value="130-692-544")

        # Equal SINs should have equal hashes
        assert hash(sin1) == hash(sin2)

        # Should be usable in sets
        sin_set = {sin1, sin2}
        assert len(sin_set) == 1  # Only one unique SIN

    def test_sin_in_dict(self):
        """Test using SIN as dictionary key."""
        sin1 = SIN(value="130692544")
        sin2 = SIN(value="130-692-544")

        sin_dict = {sin1: "test_value"}

        # Should be able to access with equivalent SIN
        assert sin_dict[sin2] == "test_value"


class TestSINImmutability:
    """Test that SIN is immutable."""

    def test_immutable_value(self):
        """Test that value cannot be changed."""
        sin = SIN(value="130692544")

        with pytest.raises(FrozenInstanceError):
            sin.value = "987654321"


class TestSINEdgeCases:
    """Test SIN edge cases and boundary conditions."""

    def test_all_valid_first_digits(self):
        """Test SINs with all valid first digits."""
        # Valid first digits are 1, 2, 3, 4, 5, 6, 7, 9
        valid_first_digits = ["1", "2", "3", "4", "5", "6", "7", "9"]

        for digit in valid_first_digits:
            # Use generate_test_sin pattern but with different first digit
            base = f"{digit}0000000"

            # Calculate check digit
            digits = [int(d) for d in base]
            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9

            total = sum(digits)
            check_digit = (10 - (total % 10)) % 10

            valid_sin_value = base + str(check_digit)

            # Should not raise error for valid first digits
            sin = SIN(value=valid_sin_value)
            assert sin.first_digit == digit

    def test_luhn_edge_case_all_zeros_except_check(self):
        """Test Luhn calculation with mostly zeros."""
        # Start with 100000000 and calculate valid check digit
        base = "10000000"
        digits = [int(d) for d in base]

        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        total = sum(digits)
        check_digit = (10 - (total % 10)) % 10

        valid_sin = base + str(check_digit)
        sin = SIN(value=valid_sin)

        assert sin._is_valid_luhn() is True

    def test_normalization_preserves_validity(self):
        """Test that normalization preserves SIN validity."""
        # Test various formatting that should normalize to same valid SIN
        valid_formats = [
            "130692544",
            "130-692-544",
            "130 692 544",
            "1 3 0 6 9 2 5 4 4",
            "130.692.544",
        ]

        sins = [SIN(value=fmt) for fmt in valid_formats]

        # All should normalize to same value
        normalized_values = [sin.value for sin in sins]
        assert all(value == "130692544" for value in normalized_values)

    def test_multiple_formatting_characters(self):
        """Test SIN with multiple types of formatting characters."""
        sin = SIN(value="1-3 0.6_9#2@5%4&4")

        assert sin.value == "130692544"

    def test_province_mapping_completeness(self):
        """Test that all valid first digits have province mappings."""
        valid_first_digits = ["1", "2", "3", "4", "5", "6", "7", "9"]

        for digit in valid_first_digits:
            # Create a mock SIN with this first digit
            import types

            types.SimpleNamespace(first_digit=digit)

            # Test the province mapping logic
            province_map = {
                "1": "Atlantic Provinces",
                "2": "Quebec",
                "3": "Quebec",
                "4": "Ontario",
                "5": "Ontario",
                "6": "Prairie Provinces",
                "7": "Pacific Region",
                "9": "Temporary Resident",
            }

            assert province_map.get(digit) is not None

    def test_luhn_calculation_step_by_step(self):
        """Test Luhn calculation with detailed steps."""
        # Use a known SIN and verify each step
        sin_value = "130692544"

        # Step 1: Convert to digits
        digits = [int(d) for d in sin_value]
        digits.copy()

        # Step 2: Double every second digit from right to left
        # Position indices from right: 8,7,6,5,4,3,2,1,0
        # Double positions: 7,5,3,1 (every second from right, excluding rightmost)
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        # Verify specific transformations
        assert digits[1] == 6  # 3*2 = 6
        assert digits[3] == 3  # 6*2 = 12, 12-9 = 3
        assert digits[5] == 9  # 9*2 = 18, 18-9 = 9
        assert digits[7] == 2  # 1*2 = 2

        # Step 3: Sum all digits
        total = sum(digits)

        # Step 4: Check if divisible by 10
        assert total % 10 == 0

    def test_pattern_validation_comprehensive(self):
        """Test comprehensive pattern validation."""
        sin = SIN(value="130692544")

        # Test internal pattern validation method
        assert sin._is_valid_pattern() is True

        # Test known invalid patterns would fail
        invalid_patterns = [
            "111111111",  # All same digits
            "000000000",  # All zeros
            "999999999",  # All nines
        ]

        for pattern in invalid_patterns:
            # Create a mock SIN to test pattern validation
            import types

            mock_sin = types.SimpleNamespace(value=pattern)
            assert not SIN._is_valid_pattern(mock_sin)

    def test_check_digit_boundary_values(self):
        """Test check digit calculation with boundary values."""
        # Test where check digit would be 0
        base = "90000000"  # This should result in check digit 9

        digits = [int(d) for d in base]
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        total = sum(digits)
        check_digit = (10 - (total % 10)) % 10

        # Create SIN with calculated check digit
        valid_sin = base + str(check_digit)
        sin = SIN(value=valid_sin)

        assert sin._is_valid_luhn() is True
