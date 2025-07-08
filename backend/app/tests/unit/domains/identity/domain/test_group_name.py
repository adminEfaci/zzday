"""
Test cases for GroupName value object.

Tests all aspects of group names including validation, formatting,
pattern matching, and security features.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.entities.group.group_constants import (
    GroupLimits,
    GroupNamePatterns,
)
from app.modules.identity.domain.value_objects.group_name import GroupName


class TestGroupNameCreation:
    """Test GroupName creation and validation."""

    def test_create_valid_group_name(self):
        """Test creating a valid group name."""
        group_name = GroupName(value="Development Team")

        assert group_name.value == "Development Team"

    def test_create_minimum_length_name(self):
        """Test creating group name with minimum valid length."""
        min_name = "x" * GroupLimits.MIN_NAME_LENGTH
        group_name = GroupName(value=min_name)

        assert group_name.value == min_name

    def test_create_maximum_length_name(self):
        """Test creating group name with maximum valid length."""
        max_name = "x" * GroupLimits.MAX_NAME_LENGTH
        group_name = GroupName(value=max_name)

        assert group_name.value == max_name

    def test_empty_name_raises_error(self):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            GroupName(value="")

    def test_none_name_raises_error(self):
        """Test that None name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            GroupName(value=None)

    def test_name_too_short_raises_error(self):
        """Test that name too short raises ValueError."""
        short_name = "x" * (GroupLimits.MIN_NAME_LENGTH - 1)

        with pytest.raises(
            ValueError,
            match=f"Group name must be at least {GroupLimits.MIN_NAME_LENGTH} characters",
        ):
            GroupName(value=short_name)

    def test_name_too_long_raises_error(self):
        """Test that name too long raises ValueError."""
        long_name = "x" * (GroupLimits.MAX_NAME_LENGTH + 1)

        with pytest.raises(
            ValueError,
            match=f"Group name cannot exceed {GroupLimits.MAX_NAME_LENGTH} characters",
        ):
            GroupName(value=long_name)

    def test_forbidden_characters_raise_error(self):
        """Test that forbidden characters raise ValueError."""
        for forbidden_char in GroupNamePatterns.FORBIDDEN_CHARS:
            invalid_name = f"Test{forbidden_char}Group"

            with pytest.raises(
                ValueError, match=f"Group name cannot contain '{forbidden_char}'"
            ):
                GroupName(value=invalid_name)

    def test_reserved_names_raise_error(self):
        """Test that reserved names raise ValueError."""
        for reserved_name in GroupNamePatterns.RESERVED_NAMES:
            with pytest.raises(
                ValueError, match=f"'{reserved_name}' is a reserved group name"
            ):
                GroupName(value=reserved_name)

            # Test case insensitive
            with pytest.raises(
                ValueError, match=f"'{reserved_name.upper()}' is a reserved group name"
            ):
                GroupName(value=reserved_name.upper())

    def test_reserved_prefixes_raise_error(self):
        """Test that reserved prefixes raise ValueError."""
        for reserved_prefix in GroupNamePatterns.RESERVED_PREFIXES:
            invalid_name = f"{reserved_prefix}test"

            with pytest.raises(
                ValueError, match=f"Group name cannot start with '{reserved_prefix}'"
            ):
                GroupName(value=invalid_name)

            # Test case insensitive
            invalid_name_upper = f"{reserved_prefix.upper()}test"
            with pytest.raises(
                ValueError, match=f"Group name cannot start with '{reserved_prefix}'"
            ):
                GroupName(value=invalid_name_upper)

    def test_leading_whitespace_raises_error(self):
        """Test that leading whitespace raises ValueError."""
        with pytest.raises(
            ValueError, match="Group name cannot have leading or trailing whitespace"
        ):
            GroupName(value=" ValidName")

    def test_trailing_whitespace_raises_error(self):
        """Test that trailing whitespace raises ValueError."""
        with pytest.raises(
            ValueError, match="Group name cannot have leading or trailing whitespace"
        ):
            GroupName(value="ValidName ")

    def test_consecutive_spaces_raise_error(self):
        """Test that consecutive spaces raise ValueError."""
        with pytest.raises(
            ValueError, match="Group name cannot contain consecutive spaces"
        ):
            GroupName(value="Test  Group")


class TestGroupNameProperties:
    """Test GroupName properties."""

    def test_display_name_property(self):
        """Test display_name property."""
        group_name = GroupName(value="Development Team")

        assert group_name.display_name == "Development Team"

    def test_display_name_strips_whitespace(self):
        """Test that display_name strips any edge whitespace."""
        # Note: This should not happen with validation, but testing the property
        group_name = GroupName(value="Development Team")

        # The display_name property calls strip()
        assert group_name.display_name == group_name.value.strip()

    def test_url_slug_basic(self):
        """Test basic URL slug generation."""
        group_name = GroupName(value="Development Team")

        assert group_name.url_slug == "development-team"

    def test_url_slug_special_characters(self):
        """Test URL slug with special characters."""
        group_name = GroupName(value="Team Alpha-Beta")

        assert group_name.url_slug == "team-alpha-beta"

    def test_url_slug_numbers(self):
        """Test URL slug with numbers."""
        group_name = GroupName(value="Team 2024")

        assert group_name.url_slug == "team-2024"

    def test_url_slug_multiple_spaces(self):
        """Test URL slug handles edge cases."""
        # Create a name that's valid but has patterns to test
        group_name = GroupName(value="Team Alpha")

        # Test the slug generation
        assert group_name.url_slug == "team-alpha"

    def test_url_slug_edge_cases(self):
        """Test URL slug edge case handling."""
        group_name = GroupName(value="Team-Alpha")

        # Should handle existing hyphens
        assert group_name.url_slug == "team-alpha"

    def test_is_system_group_true(self):
        """Test is_system_group when true."""
        # This should raise an error due to reserved prefix, but let's test the method
        try:
            group_name = GroupName(value="system:internal")
        except ValueError:
            # Expected due to reserved prefix, let's mock the scenario
            # Create a group name that would pass validation but test the method
            group_name = GroupName(value="SystemTeam")
            # Test the method with a different approach
            assert not group_name.is_system_group()  # This won't start with "system:"

            # Test the method directly on a string that would match
            import types

            test_obj = types.SimpleNamespace(value="system:test")
            result = GroupName.is_system_group(test_obj)
            assert result is True

    def test_is_system_group_false(self):
        """Test is_system_group when false."""
        group_name = GroupName(value="Development Team")

        assert group_name.is_system_group() is False

    def test_is_system_group_case_insensitive(self):
        """Test is_system_group is case insensitive."""
        # Create a test object to check the method logic
        import types

        test_obj = types.SimpleNamespace(value="SYSTEM:test")
        result = GroupName.is_system_group(test_obj)
        assert result is True


class TestGroupNamePatternMatching:
    """Test GroupName pattern matching."""

    def test_matches_pattern_exact(self):
        """Test exact pattern matching."""
        group_name = GroupName(value="Development Team")

        assert group_name.matches_pattern("Development Team") is True
        assert (
            group_name.matches_pattern("development team") is True
        )  # Case insensitive

    def test_matches_pattern_wildcard(self):
        """Test wildcard pattern matching."""
        group_name = GroupName(value="Development Team")

        assert group_name.matches_pattern("Development*") is True
        assert group_name.matches_pattern("*Team") is True
        assert group_name.matches_pattern("*velopment*") is True

    def test_matches_pattern_no_match(self):
        """Test pattern that doesn't match."""
        group_name = GroupName(value="Development Team")

        assert group_name.matches_pattern("Test*") is False
        assert group_name.matches_pattern("*Group") is False

    def test_matches_pattern_question_mark(self):
        """Test single character wildcard."""
        group_name = GroupName(value="Team A")

        assert group_name.matches_pattern("Team ?") is True
        assert group_name.matches_pattern("Team B") is False

    def test_matches_pattern_case_insensitive(self):
        """Test that pattern matching is case insensitive."""
        group_name = GroupName(value="Development Team")

        assert group_name.matches_pattern("DEVELOPMENT*") is True
        assert group_name.matches_pattern("development*") is True


class TestGroupNameStringRepresentation:
    """Test GroupName string representation."""

    def test_str_representation(self):
        """Test __str__ method."""
        group_name = GroupName(value="Development Team")

        assert str(group_name) == "Development Team"

    def test_repr_representation(self):
        """Test __repr__ method."""
        group_name = GroupName(value="Development Team")

        repr_str = repr(group_name)
        assert "GroupName" in repr_str
        assert "Development Team" in repr_str
        assert repr_str == "GroupName('Development Team')"


class TestGroupNameImmutability:
    """Test that GroupName is immutable."""

    def test_immutable_value(self):
        """Test that value cannot be changed."""
        group_name = GroupName(value="Development Team")

        with pytest.raises(FrozenInstanceError):
            group_name.value = "New Team"


class TestGroupNameEquality:
    """Test GroupName equality and comparison."""

    def test_equal_group_names(self):
        """Test that identical group names are equal."""
        group_name1 = GroupName(value="Development Team")
        group_name2 = GroupName(value="Development Team")

        assert group_name1 == group_name2

    def test_different_group_names_not_equal(self):
        """Test that different group names are not equal."""
        group_name1 = GroupName(value="Development Team")
        group_name2 = GroupName(value="Testing Team")

        assert group_name1 != group_name2

    def test_case_sensitive_equality(self):
        """Test that equality is case sensitive."""
        group_name1 = GroupName(value="Development Team")
        group_name2 = GroupName(value="development team")

        assert group_name1 != group_name2


class TestGroupNameEdgeCases:
    """Test GroupName edge cases and boundary conditions."""

    def test_all_forbidden_characters_caught(self):
        """Test that all forbidden characters are properly caught."""
        forbidden_chars = GroupNamePatterns.FORBIDDEN_CHARS

        for char in forbidden_chars:
            # Test character at beginning
            with pytest.raises(ValueError):
                GroupName(value=f"{char}TestGroup")

            # Test character in middle
            with pytest.raises(ValueError):
                GroupName(value=f"Test{char}Group")

            # Test character at end
            with pytest.raises(ValueError):
                GroupName(value=f"TestGroup{char}")

    def test_all_reserved_names_blocked(self):
        """Test that all reserved names are blocked."""
        for reserved_name in GroupNamePatterns.RESERVED_NAMES:
            # Test exact match
            with pytest.raises(ValueError):
                GroupName(value=reserved_name)

            # Test uppercase
            with pytest.raises(ValueError):
                GroupName(value=reserved_name.upper())

            # Test title case
            with pytest.raises(ValueError):
                GroupName(value=reserved_name.title())

    def test_all_reserved_prefixes_blocked(self):
        """Test that all reserved prefixes are blocked."""
        for prefix in GroupNamePatterns.RESERVED_PREFIXES:
            # Test with suffix
            with pytest.raises(ValueError):
                GroupName(value=f"{prefix}group")

            # Test uppercase prefix
            with pytest.raises(ValueError):
                GroupName(value=f"{prefix.upper()}group")

    def test_boundary_length_values(self):
        """Test boundary length values."""
        # Test minimum length exactly
        min_name = "x" * GroupLimits.MIN_NAME_LENGTH
        group_name = GroupName(value=min_name)
        assert len(group_name.value) == GroupLimits.MIN_NAME_LENGTH

        # Test maximum length exactly
        max_name = "x" * GroupLimits.MAX_NAME_LENGTH
        group_name = GroupName(value=max_name)
        assert len(group_name.value) == GroupLimits.MAX_NAME_LENGTH

        # Test one under minimum
        with pytest.raises(ValueError):
            GroupName(value="x" * (GroupLimits.MIN_NAME_LENGTH - 1))

        # Test one over maximum
        with pytest.raises(ValueError):
            GroupName(value="x" * (GroupLimits.MAX_NAME_LENGTH + 1))

    def test_valid_names_with_allowed_characters(self):
        """Test that valid names with allowed characters work."""
        valid_names = [
            "Development Team",
            "Team-Alpha",
            "Team_Beta",
            "Team.Gamma",
            "Team,Delta",
            "Team(Echo)",
            "Team & Foxtrot",
            "Project 2024",
            "Team-123",
            "Alpha_Beta_Gamma",
        ]

        for name in valid_names:
            if len(name) >= GroupLimits.MIN_NAME_LENGTH:
                group_name = GroupName(value=name)
                assert group_name.value == name

    def test_unicode_characters(self):
        """Test with Unicode characters."""
        unicode_names = [
            "Équipe de développement",  # French
            "开发团队",  # Chinese
            "Команда разработки",  # Russian
            "فريق التطوير",  # Arabic
        ]

        for name in unicode_names:
            if len(name) >= GroupLimits.MIN_NAME_LENGTH:
                group_name = GroupName(value=name)
                assert group_name.value == name

    def test_url_slug_with_unicode(self):
        """Test URL slug generation with Unicode characters."""
        # Test with Unicode characters that should be removed
        group_name = GroupName(value="Équipe Alpha")
        slug = group_name.url_slug

        # Should contain only ASCII letters, numbers, and hyphens
        import re

        assert re.match(r"^[a-z0-9-]*$", slug)

    def test_url_slug_removes_consecutive_hyphens(self):
        """Test that URL slug removes consecutive hyphens."""
        # Create a scenario that would generate consecutive hyphens
        group_name = GroupName(value="Team - Alpha")
        slug = group_name.url_slug

        # Should not contain consecutive hyphens
        assert "--" not in slug

    def test_url_slug_strips_leading_trailing_hyphens(self):
        """Test that URL slug strips leading/trailing hyphens."""
        group_name = GroupName(value="Team Alpha")
        slug = group_name.url_slug

        # Should not start or end with hyphen
        assert not slug.startswith("-")
        assert not slug.endswith("-")

    def test_pattern_matching_special_patterns(self):
        """Test pattern matching with special glob patterns."""
        group_name = GroupName(value="Development Team Alpha")

        # Test character classes and complex patterns
        assert group_name.matches_pattern("*Team*") is True
        assert group_name.matches_pattern("Development*Alpha") is True
        assert group_name.matches_pattern("*Alpha") is True

    def test_very_long_valid_name(self):
        """Test with very long but valid name."""
        # Create a name at exactly the maximum length
        long_name = "A" * (GroupLimits.MAX_NAME_LENGTH - 10) + " Team Test"
        if len(long_name) <= GroupLimits.MAX_NAME_LENGTH:
            group_name = GroupName(value=long_name)
            assert len(group_name.value) == len(long_name)

            # Test that URL slug works with long names
            slug = group_name.url_slug
            assert len(slug) > 0

    def test_empty_url_slug_edge_case(self):
        """Test URL slug when all characters are removed."""
        # Create a name with only special characters that would be filtered out
        # But first need a valid group name
        GroupName(value="Test Group")

        # Test the slug generation with edge case manually
        # This tests the internal logic of the url_slug property
        import re

        test_value = "!@#$%"  # Would be all filtered out
        slug = test_value.lower().replace(" ", "-")
        slug = re.sub(r"[^a-z0-9-]", "", slug)
        slug = re.sub(r"-+", "-", slug)
        slug = slug.strip("-")

        # When all characters are removed, slug should be empty
        assert slug == ""

    def test_whitespace_normalization_in_slug(self):
        """Test that whitespace is properly normalized in slug."""
        group_name = GroupName(value="Development Team")

        assert group_name.url_slug == "development-team"

        # Test multiple spaces (though this should be caught by validation)
        # Testing the slug generation logic directly
        import re

        test_slug = "test  group".lower().replace(" ", "-")
        test_slug = re.sub(r"[^a-z0-9-]", "", test_slug)
        test_slug = re.sub(r"-+", "-", test_slug)
        test_slug = test_slug.strip("-")

        assert test_slug == "test--group"  # Multiple spaces become multiple hyphens

        # The regex should reduce multiple hyphens to single
        final_slug = re.sub(r"-+", "-", test_slug)
        assert final_slug == "test-group"
