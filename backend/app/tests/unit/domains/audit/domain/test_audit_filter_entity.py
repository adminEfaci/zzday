"""
Comprehensive tests for AuditFilter entity.

This module tests the AuditFilter entity with complete coverage focusing on:
- Filter creation and validation
- Query criteria validation and normalization
- Pagination and sorting validation
- Filter merging and combination logic
- Factory methods for common filter scenarios
- Query parameter conversion
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
)
from app.modules.audit.domain.value_objects.time_range import TimeRange


class TestAuditFilterCreation:
    """Test audit filter creation and initialization."""

    def test_create_audit_filter_with_all_criteria(self):
        """Test creating audit filter with all possible criteria."""
        # Arrange
        time_range = TimeRange.last_days(7)
        user_ids = [uuid4(), uuid4()]
        resource_types = ["user", "document"]
        resource_ids = ["user-123", "doc-456"]
        action_types = ["create", "update"]
        operations = ["register", "profile_update"]
        severities = [AuditSeverity.HIGH, AuditSeverity.CRITICAL]
        categories = [AuditCategory.SECURITY, AuditCategory.DATA_ACCESS]
        statuses = [AuditStatus.ACTIVE]
        outcomes = ["success", "failure"]
        session_ids = [uuid4(), uuid4()]
        correlation_ids = ["corr-123", "corr-456"]
        search_text = "security breach"

        # Act
        audit_filter = AuditFilter(
            time_range=time_range,
            user_ids=user_ids,
            resource_types=resource_types,
            resource_ids=resource_ids,
            action_types=action_types,
            operations=operations,
            severities=severities,
            categories=categories,
            statuses=statuses,
            outcomes=outcomes,
            session_ids=session_ids,
            correlation_ids=correlation_ids,
            search_text=search_text,
            include_system=False,
            limit=50,
            offset=100,
            sort_by="severity",
            sort_order="asc",
        )

        # Assert
        assert audit_filter.time_range == time_range
        assert audit_filter.user_ids == user_ids
        assert audit_filter.resource_types == resource_types
        assert audit_filter.resource_ids == resource_ids
        assert audit_filter.action_types == action_types
        assert audit_filter.operations == operations
        assert audit_filter.severities == severities
        assert audit_filter.categories == categories
        assert audit_filter.statuses == statuses
        assert audit_filter.outcomes == outcomes
        assert audit_filter.session_ids == session_ids
        assert audit_filter.correlation_ids == correlation_ids
        assert audit_filter.search_text == search_text
        assert audit_filter.include_system is False
        assert audit_filter.limit == 50
        assert audit_filter.offset == 100
        assert audit_filter.sort_by == "severity"
        assert audit_filter.sort_order == "asc"

    def test_create_audit_filter_with_minimal_criteria(self):
        """Test creating audit filter with minimal criteria."""
        # Act
        audit_filter = AuditFilter(search_text="test")

        # Assert
        assert audit_filter.time_range is None
        assert audit_filter.user_ids == []
        assert audit_filter.resource_types == []
        assert audit_filter.resource_ids == []
        assert audit_filter.action_types == []
        assert audit_filter.operations == []
        assert audit_filter.severities == []
        assert audit_filter.categories == []
        assert audit_filter.statuses == []
        assert audit_filter.outcomes == []
        assert audit_filter.session_ids == []
        assert audit_filter.correlation_ids == []
        assert audit_filter.search_text == "test"
        assert audit_filter.include_system is True  # Default
        assert audit_filter.limit == AuditFilter.DEFAULT_LIMIT
        assert audit_filter.offset == 0
        assert audit_filter.sort_by == "created_at"  # Default
        assert audit_filter.sort_order == "desc"  # Default

    def test_create_audit_filter_normalizes_string_fields(self):
        """Test that string fields are normalized to lowercase."""
        # Act
        audit_filter = AuditFilter(
            resource_types=["USER", "Document"],
            action_types=["CREATE", "Update"],
            operations=["REGISTER", "Profile_Update"],
            search_text="  Test Search  ",
        )

        # Assert
        assert audit_filter.resource_types == ["user", "document"]
        assert audit_filter.action_types == ["create", "update"]
        assert audit_filter.operations == ["register", "profile_update"]
        assert audit_filter.search_text == "Test Search"  # Trimmed but case preserved

    def test_create_audit_filter_with_none_lists_defaults_to_empty(self):
        """Test that None list parameters default to empty lists."""
        # Act
        audit_filter = AuditFilter(
            user_ids=None, resource_types=None, action_types=None, search_text="test"
        )

        # Assert
        assert audit_filter.user_ids == []
        assert audit_filter.resource_types == []
        assert audit_filter.action_types == []

    def test_create_audit_filter_no_criteria_raises_error(self):
        """Test that filter with no criteria raises ValidationError."""
        # Act & Assert
        with pytest.raises(
            ValidationError, match="At least one filter criterion must be specified"
        ):
            AuditFilter()


class TestAuditFilterValidation:
    """Test audit filter validation and normalization."""

    @pytest.mark.parametrize("invalid_outcome", ["invalid", "complete", "pending", ""])
    def test_create_audit_filter_with_invalid_outcomes_raises_error(
        self, invalid_outcome
    ):
        """Test that invalid outcomes raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid outcome"):
            AuditFilter(outcomes=[invalid_outcome])

    @pytest.mark.parametrize(
        "valid_outcome",
        ["success", "failure", "partial", "SUCCESS", "FAILURE"],  # Should be normalized
    )
    def test_create_audit_filter_with_valid_outcomes(self, valid_outcome):
        """Test that valid outcomes are accepted and normalized."""
        # Act
        audit_filter = AuditFilter(outcomes=[valid_outcome])

        # Assert
        assert valid_outcome.lower() in audit_filter.outcomes

    def test_create_audit_filter_limit_validation(self):
        """Test limit validation and normalization."""
        # Test zero limit
        filter1 = AuditFilter(search_text="test", limit=0)
        assert filter1.limit == AuditFilter.DEFAULT_LIMIT

        # Test negative limit
        filter2 = AuditFilter(search_text="test", limit=-10)
        assert filter2.limit == AuditFilter.DEFAULT_LIMIT

        # Test over max limit
        filter3 = AuditFilter(search_text="test", limit=2000)
        assert filter3.limit == AuditFilter.MAX_LIMIT

        # Test valid limit
        filter4 = AuditFilter(search_text="test", limit=500)
        assert filter4.limit == 500

    def test_create_audit_filter_offset_validation(self):
        """Test offset validation."""
        # Test negative offset (should be normalized to 0)
        audit_filter = AuditFilter(search_text="test", offset=-10)
        assert audit_filter.offset == 0

        # Test positive offset
        audit_filter = AuditFilter(search_text="test", offset=100)
        assert audit_filter.offset == 100

    @pytest.mark.parametrize(
        "invalid_sort_field", ["invalid_field", "name", "description", ""]
    )
    def test_create_audit_filter_with_invalid_sort_field_raises_error(
        self, invalid_sort_field
    ):
        """Test that invalid sort fields raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid sort field"):
            AuditFilter(search_text="test", sort_by=invalid_sort_field)

    @pytest.mark.parametrize(
        "valid_sort_field",
        [
            "created_at",
            "updated_at",
            "severity",
            "category",
            "user_id",
            "resource_type",
            "action_type",
            "CREATED_AT",  # Should be normalized
        ],
    )
    def test_create_audit_filter_with_valid_sort_fields(self, valid_sort_field):
        """Test that valid sort fields are accepted and normalized."""
        # Act
        audit_filter = AuditFilter(search_text="test", sort_by=valid_sort_field)

        # Assert
        assert audit_filter.sort_by == valid_sort_field.lower()

    @pytest.mark.parametrize(
        "invalid_sort_order", ["ascending", "descending", "up", "down", ""]
    )
    def test_create_audit_filter_with_invalid_sort_order_raises_error(
        self, invalid_sort_order
    ):
        """Test that invalid sort orders raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Sort order must be 'asc' or 'desc'"):
            AuditFilter(search_text="test", sort_order=invalid_sort_order)

    @pytest.mark.parametrize(
        "valid_sort_order",
        ["asc", "desc", "ASC", "DESC", "  asc  "],  # Should be normalized
    )
    def test_create_audit_filter_with_valid_sort_orders(self, valid_sort_order):
        """Test that valid sort orders are accepted and normalized."""
        # Act
        audit_filter = AuditFilter(search_text="test", sort_order=valid_sort_order)

        # Assert
        assert audit_filter.sort_order == valid_sort_order.strip().lower()


class TestAuditFilterQueryMethods:
    """Test audit filter query and checking methods."""

    def test_is_empty_when_filter_has_no_criteria(self):
        """Test is_empty returns True when no criteria are set."""
        # This would normally raise an error, but we test the method logic
        audit_filter = AuditFilter.__new__(AuditFilter)
        audit_filter.time_range = None
        audit_filter.user_ids = []
        audit_filter.resource_types = []
        audit_filter.resource_ids = []
        audit_filter.action_types = []
        audit_filter.operations = []
        audit_filter.severities = []
        audit_filter.categories = []
        audit_filter.statuses = []
        audit_filter.outcomes = []
        audit_filter.session_ids = []
        audit_filter.correlation_ids = []
        audit_filter.search_text = None

        # Act & Assert
        assert audit_filter.is_empty()

    def test_is_empty_when_filter_has_criteria(self):
        """Test is_empty returns False when criteria are set."""
        # Act
        audit_filter = AuditFilter(search_text="test")

        # Assert
        assert not audit_filter.is_empty()

    def test_has_time_constraint(self):
        """Test has_time_constraint method."""
        # Without time range
        filter1 = AuditFilter(search_text="test")
        assert not filter1.has_time_constraint()

        # With time range
        filter2 = AuditFilter(time_range=TimeRange.last_days(7))
        assert filter2.has_time_constraint()

    def test_has_user_constraint(self):
        """Test has_user_constraint method."""
        # No user constraints
        filter1 = AuditFilter(search_text="test", include_system=True)
        assert not filter1.has_user_constraint()

        # With user IDs
        filter2 = AuditFilter(user_ids=[uuid4()])
        assert filter2.has_user_constraint()

        # Excluding system
        filter3 = AuditFilter(search_text="test", include_system=False)
        assert filter3.has_user_constraint()

    def test_has_resource_constraint(self):
        """Test has_resource_constraint method."""
        # No resource constraints
        filter1 = AuditFilter(search_text="test")
        assert not filter1.has_resource_constraint()

        # With resource types
        filter2 = AuditFilter(resource_types=["user"])
        assert filter2.has_resource_constraint()

        # With resource IDs
        filter3 = AuditFilter(resource_ids=["user-123"])
        assert filter3.has_resource_constraint()

        # With both
        filter4 = AuditFilter(resource_types=["user"], resource_ids=["user-123"])
        assert filter4.has_resource_constraint()

    def test_has_severity_constraint(self):
        """Test has_severity_constraint method."""
        # No severity constraints
        filter1 = AuditFilter(search_text="test")
        assert not filter1.has_severity_constraint()

        # With severities
        filter2 = AuditFilter(severities=[AuditSeverity.HIGH])
        assert filter2.has_severity_constraint()


class TestAuditFilterPagination:
    """Test pagination functionality."""

    def test_get_page_info(self):
        """Test pagination information retrieval."""
        # First page
        filter1 = AuditFilter(search_text="test", limit=10, offset=0)
        page_info1 = filter1.get_page_info()
        assert page_info1["limit"] == 10
        assert page_info1["offset"] == 0
        assert page_info1["page"] == 1

        # Second page
        filter2 = AuditFilter(search_text="test", limit=10, offset=10)
        page_info2 = filter2.get_page_info()
        assert page_info2["limit"] == 10
        assert page_info2["offset"] == 10
        assert page_info2["page"] == 2

        # Custom page size
        filter3 = AuditFilter(search_text="test", limit=25, offset=50)
        page_info3 = filter3.get_page_info()
        assert page_info3["limit"] == 25
        assert page_info3["offset"] == 50
        assert page_info3["page"] == 3  # (50 / 25) + 1

    def test_next_page(self):
        """Test next page filter generation."""
        # Arrange
        original_filter = AuditFilter(
            search_text="test",
            user_ids=[uuid4()],
            limit=20,
            offset=40,
            sort_by="severity",
        )

        # Act
        next_page_filter = original_filter.next_page()

        # Assert
        assert next_page_filter.search_text == "test"
        assert next_page_filter.user_ids == original_filter.user_ids
        assert next_page_filter.limit == 20
        assert next_page_filter.offset == 60  # 40 + 20
        assert next_page_filter.sort_by == "severity"

        # Original should remain unchanged
        assert original_filter.offset == 40


class TestAuditFilterImmutableMethods:
    """Test immutable modification methods."""

    def test_with_time_range(self):
        """Test creating filter with new time range."""
        # Arrange
        original_filter = AuditFilter(search_text="test", user_ids=[uuid4()], limit=50)
        new_time_range = TimeRange.last_days(30)

        # Act
        new_filter = original_filter.with_time_range(new_time_range)

        # Assert
        assert new_filter.time_range == new_time_range
        assert new_filter.search_text == "test"
        assert new_filter.user_ids == original_filter.user_ids
        assert new_filter.limit == 50

        # Original should remain unchanged
        assert original_filter.time_range is None


class TestAuditFilterMerging:
    """Test filter merging functionality."""

    def test_merge_with_time_ranges(self):
        """Test merging filters with time ranges."""
        # Arrange
        time_range1 = TimeRange(
            datetime(2024, 1, 1, tzinfo=UTC), datetime(2024, 1, 10, tzinfo=UTC)
        )
        time_range2 = TimeRange(
            datetime(2024, 1, 5, tzinfo=UTC), datetime(2024, 1, 15, tzinfo=UTC)
        )

        filter1 = AuditFilter(time_range=time_range1)
        filter2 = AuditFilter(time_range=time_range2)

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.time_range is not None
        assert merged_filter.time_range.start_time == datetime(2024, 1, 5, tzinfo=UTC)
        assert merged_filter.time_range.end_time == datetime(2024, 1, 10, tzinfo=UTC)

    def test_merge_with_overlapping_lists(self):
        """Test merging filters with overlapping list criteria."""
        # Arrange
        filter1 = AuditFilter(
            resource_types=["user", "document"],
            severities=[AuditSeverity.HIGH, AuditSeverity.CRITICAL],
        )
        filter2 = AuditFilter(
            resource_types=["user", "order"],  # "user" overlaps
            severities=[AuditSeverity.MEDIUM, AuditSeverity.HIGH],  # "HIGH" overlaps
        )

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.resource_types == ["user"]  # Intersection
        assert merged_filter.severities == [AuditSeverity.HIGH]  # Intersection

    def test_merge_with_non_overlapping_lists(self):
        """Test merging filters with non-overlapping lists."""
        # Arrange
        filter1 = AuditFilter(resource_types=["user"])
        filter2 = AuditFilter(resource_types=["document"])

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.resource_types == []  # No intersection

    def test_merge_with_one_empty_list(self):
        """Test merging filters where one has empty list."""
        # Arrange
        filter1 = AuditFilter(resource_types=["user", "document"])
        filter2 = AuditFilter(search_text="test")  # No resource_types

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.resource_types == ["user", "document"]  # Use non-empty
        assert merged_filter.search_text == "test"

    def test_merge_with_boolean_flags(self):
        """Test merging filters with boolean flags."""
        # Arrange
        filter1 = AuditFilter(search_text="test1", include_system=True)
        filter2 = AuditFilter(search_text="test2", include_system=False)

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.include_system is False  # AND logic
        assert merged_filter.search_text == "test2"  # filter2 takes precedence

    def test_merge_with_pagination_and_sorting(self):
        """Test merging filters with pagination and sorting."""
        # Arrange
        filter1 = AuditFilter(
            search_text="test",
            limit=100,
            offset=0,
            sort_by="created_at",
            sort_order="desc",
        )
        filter2 = AuditFilter(
            user_ids=[uuid4()],
            limit=50,
            offset=20,
            sort_by="severity",
            sort_order="asc",
        )

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        assert merged_filter.limit == 50  # Minimum
        assert merged_filter.offset == 20  # Maximum
        assert merged_filter.sort_by == "severity"  # filter2 takes precedence
        assert merged_filter.sort_order == "asc"  # filter2 takes precedence


class TestAuditFilterQueryParams:
    """Test query parameter conversion."""

    def test_to_query_params_with_all_fields(self):
        """Test conversion to query parameters with all fields."""
        # Arrange
        time_range = TimeRange.last_days(7)
        user_ids = [uuid4(), uuid4()]
        audit_filter = AuditFilter(
            time_range=time_range,
            user_ids=user_ids,
            resource_types=["user"],
            resource_ids=["user-123"],
            action_types=["create"],
            operations=["register"],
            severities=[AuditSeverity.HIGH],
            categories=[AuditCategory.SECURITY],
            statuses=[AuditStatus.ACTIVE],
            outcomes=["success"],
            session_ids=[uuid4()],
            correlation_ids=["corr-123"],
            search_text="test",
            include_system=False,
            limit=50,
            offset=100,
        )

        # Act
        params = audit_filter.to_query_params()

        # Assert
        assert params["start_time"] == time_range.start_time
        assert params["end_time"] == time_range.end_time
        assert params["user_ids"] == user_ids
        assert params["resource_types"] == ["user"]
        assert params["resource_ids"] == ["user-123"]
        assert params["action_types"] == ["create"]
        assert params["operations"] == ["register"]
        assert params["severities"] == ["high"]
        assert params["categories"] == ["security"]
        assert params["statuses"] == ["active"]
        assert params["outcomes"] == ["success"]
        assert params["search_text"] == "test"
        assert params["include_system"] is False
        assert params["limit"] == 50
        assert params["offset"] == 100

    def test_to_query_params_with_minimal_fields(self):
        """Test conversion to query parameters with minimal fields."""
        # Arrange
        audit_filter = AuditFilter(search_text="test")

        # Act
        params = audit_filter.to_query_params()

        # Assert
        assert "start_time" not in params
        assert "end_time" not in params
        assert "user_ids" not in params
        assert params["search_text"] == "test"
        assert params["include_system"] is True
        assert params["limit"] == AuditFilter.DEFAULT_LIMIT
        assert params["offset"] == 0
        assert params["sort_by"] == "created_at"
        assert params["sort_order"] == "desc"


class TestAuditFilterFactoryMethods:
    """Test factory methods for common filter scenarios."""

    def test_create_for_user(self):
        """Test user-specific filter factory method."""
        # Arrange
        user_id = uuid4()
        custom_time_range = TimeRange.last_days(14)

        # Act
        audit_filter = AuditFilter.create_for_user(
            user_id=user_id, time_range=custom_time_range, limit=200
        )

        # Assert
        assert audit_filter.user_ids == [user_id]
        assert audit_filter.time_range == custom_time_range
        assert audit_filter.limit == 200
        assert audit_filter.include_system is True  # Default

    def test_create_for_user_with_defaults(self):
        """Test user-specific filter with default parameters."""
        # Arrange
        user_id = uuid4()

        # Act
        audit_filter = AuditFilter.create_for_user(user_id)

        # Assert
        assert audit_filter.user_ids == [user_id]
        assert audit_filter.time_range is not None
        assert audit_filter.time_range.duration_days() == 30  # Default last 30 days
        assert audit_filter.limit == AuditFilter.DEFAULT_LIMIT

    def test_create_for_resource(self):
        """Test resource-specific filter factory method."""
        # Arrange
        resource_type = "document"
        resource_id = "doc-123"
        custom_time_range = TimeRange.last_hours(24)

        # Act
        audit_filter = AuditFilter.create_for_resource(
            resource_type=resource_type,
            resource_id=resource_id,
            time_range=custom_time_range,
            limit=75,
        )

        # Assert
        assert audit_filter.resource_types == [resource_type]
        assert audit_filter.resource_ids == [resource_id]
        assert audit_filter.time_range == custom_time_range
        assert audit_filter.limit == 75

    def test_create_for_resource_with_defaults(self):
        """Test resource-specific filter with default parameters."""
        # Arrange
        resource_type = "user"
        resource_id = "user-456"

        # Act
        audit_filter = AuditFilter.create_for_resource(resource_type, resource_id)

        # Assert
        assert audit_filter.resource_types == [resource_type]
        assert audit_filter.resource_ids == [resource_id]
        assert audit_filter.time_range is not None
        assert audit_filter.time_range.duration_days() == 30  # Default
        assert audit_filter.limit == AuditFilter.DEFAULT_LIMIT

    def test_create_for_security_review(self):
        """Test security review filter factory method."""
        # Arrange
        custom_time_range = TimeRange.last_days(3)

        # Act
        audit_filter = AuditFilter.create_for_security_review(
            time_range=custom_time_range, limit=500
        )

        # Assert
        assert AuditSeverity.HIGH in audit_filter.severities
        assert AuditSeverity.CRITICAL in audit_filter.severities
        assert AuditCategory.SECURITY in audit_filter.categories
        assert AuditCategory.AUTHENTICATION in audit_filter.categories
        assert audit_filter.outcomes == ["failure"]
        assert audit_filter.time_range == custom_time_range
        assert audit_filter.limit == 500

    def test_create_for_security_review_with_defaults(self):
        """Test security review filter with default parameters."""
        # Act
        audit_filter = AuditFilter.create_for_security_review()

        # Assert
        assert len(audit_filter.severities) == 2  # HIGH and CRITICAL
        assert len(audit_filter.categories) == 2  # SECURITY and AUTHENTICATION
        assert audit_filter.outcomes == ["failure"]
        assert audit_filter.time_range is not None
        assert audit_filter.time_range.duration_days() == 7  # Default last 7 days
        assert audit_filter.limit == AuditFilter.DEFAULT_LIMIT


class TestAuditFilterEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_filter_with_empty_string_search_text(self):
        """Test filter with empty search text."""
        # Act
        audit_filter = AuditFilter(search_text="")

        # Assert
        assert audit_filter.search_text is None  # Empty string should become None

    def test_create_filter_with_whitespace_only_search_text(self):
        """Test filter with whitespace-only search text."""
        # Act
        audit_filter = AuditFilter(search_text="   ")

        # Assert
        assert audit_filter.search_text is None  # Whitespace should become None

    def test_merge_filters_with_no_overlap_time_ranges(self):
        """Test merging filters with non-overlapping time ranges."""
        # Arrange
        filter1 = AuditFilter(
            time_range=TimeRange(
                datetime(2024, 1, 1, tzinfo=UTC), datetime(2024, 1, 5, tzinfo=UTC)
            )
        )
        filter2 = AuditFilter(
            time_range=TimeRange(
                datetime(2024, 1, 10, tzinfo=UTC), datetime(2024, 1, 15, tzinfo=UTC)
            )
        )

        # Act
        merged_filter = filter1.merge_with(filter2)

        # Assert
        # When there's no overlap, the first filter's time range should be used
        assert merged_filter.time_range == filter1.time_range

    def test_filter_constants(self):
        """Test filter constants are properly defined."""
        # Assert
        assert AuditFilter.MAX_LIMIT == 1000
        assert AuditFilter.DEFAULT_LIMIT == 100
        assert AuditFilter.DEFAULT_LIMIT <= AuditFilter.MAX_LIMIT

    def test_create_filter_with_large_lists(self):
        """Test creating filter with large lists of criteria."""
        # Arrange
        large_user_list = [uuid4() for _ in range(100)]
        large_resource_types = [f"resource_{i}" for i in range(50)]

        # Act
        audit_filter = AuditFilter(
            user_ids=large_user_list, resource_types=large_resource_types
        )

        # Assert
        assert len(audit_filter.user_ids) == 100
        assert len(audit_filter.resource_types) == 50
        assert all(rt.startswith("resource_") for rt in audit_filter.resource_types)

    def test_create_filter_with_duplicate_values_in_lists(self):
        """Test that duplicate values in lists are preserved."""
        # Arrange
        user_ids = [uuid4(), uuid4(), uuid4()]
        user_ids.append(user_ids[0])  # Add duplicate

        # Act
        audit_filter = AuditFilter(user_ids=user_ids)

        # Assert
        assert len(audit_filter.user_ids) == 4  # Duplicates are preserved
        assert audit_filter.user_ids[0] == audit_filter.user_ids[3]
