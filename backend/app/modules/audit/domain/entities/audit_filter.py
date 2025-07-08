"""Audit filter entity.

This module defines the AuditFilter entity used for
querying and filtering audit records.
"""

from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import ValidationError
from app.modules.audit.domain.enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
)
from app.modules.audit.domain.value_objects.time_range import TimeRange


class AuditFilter(Entity):
    """
    Represents a filter for querying audit records.

    This entity encapsulates query criteria for searching and
    filtering audit entries with validation and optimization support.

    Attributes:
        time_range: Time period to search within
        user_ids: Filter by specific user IDs
        resource_types: Filter by resource types
        resource_ids: Filter by specific resource IDs
        action_types: Filter by action types
        operations: Filter by specific operations
        severities: Filter by severity levels
        categories: Filter by categories
        statuses: Filter by record statuses
        outcomes: Filter by action outcomes
        session_ids: Filter by session IDs
        correlation_ids: Filter by correlation IDs
        search_text: Full-text search query
        include_system: Include system-generated entries
        limit: Maximum number of results
        offset: Result offset for pagination
        sort_by: Field to sort by
        sort_order: Sort order (asc/desc)

    Business Rules:
        - At least one filter criterion must be specified
        - Time range is recommended for performance
        - Limit must be reasonable (max 1000)
    """

    MAX_LIMIT = 1000
    DEFAULT_LIMIT = 100

    def __init__(
        self,
        time_range: TimeRange | None = None,
        user_ids: list[UUID] | None = None,
        resource_types: list[str] | None = None,
        resource_ids: list[str] | None = None,
        action_types: list[str] | None = None,
        operations: list[str] | None = None,
        severities: list[AuditSeverity] | None = None,
        categories: list[AuditCategory] | None = None,
        statuses: list[AuditStatus] | None = None,
        outcomes: list[str] | None = None,
        session_ids: list[UUID] | None = None,
        correlation_ids: list[str] | None = None,
        search_text: str | None = None,
        include_system: bool = True,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        entity_id: UUID | None = None,
    ):
        """
        Initialize audit filter.

        Args:
            time_range: Time period filter
            user_ids: User ID filter
            resource_types: Resource type filter
            resource_ids: Resource ID filter
            action_types: Action type filter
            operations: Operation filter
            severities: Severity level filter
            categories: Category filter
            statuses: Status filter
            outcomes: Outcome filter
            session_ids: Session ID filter
            correlation_ids: Correlation ID filter
            search_text: Full-text search
            include_system: Include system entries
            limit: Result limit
            offset: Result offset
            sort_by: Sort field
            sort_order: Sort order
            entity_id: Filter identifier

        Raises:
            ValidationError: If filter criteria are invalid
        """
        super().__init__(entity_id)

        # Set time range
        self.time_range = time_range

        # Set ID filters
        self.user_ids = user_ids or []
        self.session_ids = session_ids or []
        self.correlation_ids = correlation_ids or []

        # Set resource filters
        self.resource_types = [rt.lower() for rt in (resource_types or [])]
        self.resource_ids = resource_ids or []

        # Set action filters
        self.action_types = [at.lower() for at in (action_types or [])]
        self.operations = [op.lower() for op in (operations or [])]

        # Set enum filters
        self.severities = severities or []
        self.categories = categories or []
        self.statuses = statuses or []

        # Set outcome filter
        self.outcomes = self._validate_outcomes(outcomes or [])

        # Set search text
        self.search_text = search_text.strip() if search_text else None

        # Set flags
        self.include_system = include_system

        # Set pagination
        self.limit = self._validate_limit(limit)
        self.offset = max(0, offset)

        # Set sorting
        self.sort_by = self._validate_sort_field(sort_by)
        self.sort_order = self._validate_sort_order(sort_order)

        # Validate that at least one criterion is specified
        if not self._has_criteria():
            raise ValidationError("At least one filter criterion must be specified")

    def _validate_outcomes(self, outcomes: list[str]) -> list[str]:
        """Validate outcome values."""
        valid_outcomes = {"success", "failure", "partial"}
        normalized = []

        for outcome in outcomes:
            normalized_outcome = outcome.lower().strip()
            if normalized_outcome not in valid_outcomes:
                raise ValidationError(f"Invalid outcome: {outcome}")
            normalized.append(normalized_outcome)

        return normalized

    def _validate_limit(self, limit: int) -> int:
        """Validate and normalize limit."""
        if limit <= 0:
            return self.DEFAULT_LIMIT
        if limit > self.MAX_LIMIT:
            return self.MAX_LIMIT
        return limit

    def _validate_sort_field(self, field: str) -> str:
        """Validate sort field."""
        valid_fields = {
            "created_at",
            "updated_at",
            "severity",
            "category",
            "user_id",
            "resource_type",
            "action_type",
        }

        normalized = field.lower().strip()
        if normalized not in valid_fields:
            raise ValidationError(
                f"Invalid sort field: {field}. "
                f"Must be one of: {', '.join(valid_fields)}"
            )

        return normalized

    def _validate_sort_order(self, order: str) -> str:
        """Validate sort order."""
        normalized = order.lower().strip()
        if normalized not in ("asc", "desc"):
            raise ValidationError("Sort order must be 'asc' or 'desc'")
        return normalized

    def _has_criteria(self) -> bool:
        """Check if any filter criteria are specified."""
        return any(
            [
                self.time_range,
                self.user_ids,
                self.resource_types,
                self.resource_ids,
                self.action_types,
                self.operations,
                self.severities,
                self.categories,
                self.statuses,
                self.outcomes,
                self.session_ids,
                self.correlation_ids,
                self.search_text,
            ]
        )

    def is_empty(self) -> bool:
        """Check if filter has no criteria."""
        return not self._has_criteria()

    def has_time_constraint(self) -> bool:
        """Check if filter has time range constraint."""
        return self.time_range is not None

    def has_user_constraint(self) -> bool:
        """Check if filter has user-related constraints."""
        return bool(self.user_ids) or not self.include_system

    def has_resource_constraint(self) -> bool:
        """Check if filter has resource constraints."""
        return bool(self.resource_types or self.resource_ids)

    def has_severity_constraint(self) -> bool:
        """Check if filter has severity constraints."""
        return bool(self.severities)

    def get_page_info(self) -> dict[str, int]:
        """Get pagination information."""
        return {
            "limit": self.limit,
            "offset": self.offset,
            "page": (self.offset // self.limit) + 1 if self.limit > 0 else 1,
        }

    def next_page(self) -> "AuditFilter":
        """Create filter for next page of results."""
        return AuditFilter(
            time_range=self.time_range,
            user_ids=self.user_ids,
            resource_types=self.resource_types,
            resource_ids=self.resource_ids,
            action_types=self.action_types,
            operations=self.operations,
            severities=self.severities,
            categories=self.categories,
            statuses=self.statuses,
            outcomes=self.outcomes,
            session_ids=self.session_ids,
            correlation_ids=self.correlation_ids,
            search_text=self.search_text,
            include_system=self.include_system,
            limit=self.limit,
            offset=self.offset + self.limit,
            sort_by=self.sort_by,
            sort_order=self.sort_order,
        )

    def with_time_range(self, time_range: TimeRange) -> "AuditFilter":
        """Create new filter with specified time range."""
        return AuditFilter(
            time_range=time_range,
            user_ids=self.user_ids,
            resource_types=self.resource_types,
            resource_ids=self.resource_ids,
            action_types=self.action_types,
            operations=self.operations,
            severities=self.severities,
            categories=self.categories,
            statuses=self.statuses,
            outcomes=self.outcomes,
            session_ids=self.session_ids,
            correlation_ids=self.correlation_ids,
            search_text=self.search_text,
            include_system=self.include_system,
            limit=self.limit,
            offset=self.offset,
            sort_by=self.sort_by,
            sort_order=self.sort_order,
        )

    def merge_with(self, other: "AuditFilter") -> "AuditFilter":
        """
        Merge this filter with another (AND logic).

        Args:
            other: Another filter to merge with

        Returns:
            New merged filter
        """
        # Merge time ranges (intersection)
        merged_time_range = None
        if self.time_range and other.time_range:
            merged_time_range = self.time_range.intersection(other.time_range)
            if not merged_time_range:
                # No overlap - will return no results
                merged_time_range = self.time_range
        else:
            merged_time_range = self.time_range or other.time_range

        # Merge lists (intersection where both specified)
        def merge_lists(list1: list, list2: list) -> list:
            if list1 and list2:
                return list(set(list1) & set(list2))
            return list1 or list2

        return AuditFilter(
            time_range=merged_time_range,
            user_ids=merge_lists(self.user_ids, other.user_ids),
            resource_types=merge_lists(self.resource_types, other.resource_types),
            resource_ids=merge_lists(self.resource_ids, other.resource_ids),
            action_types=merge_lists(self.action_types, other.action_types),
            operations=merge_lists(self.operations, other.operations),
            severities=merge_lists(self.severities, other.severities),
            categories=merge_lists(self.categories, other.categories),
            statuses=merge_lists(self.statuses, other.statuses),
            outcomes=merge_lists(self.outcomes, other.outcomes),
            session_ids=merge_lists(self.session_ids, other.session_ids),
            correlation_ids=merge_lists(self.correlation_ids, other.correlation_ids),
            search_text=other.search_text or self.search_text,
            include_system=self.include_system and other.include_system,
            limit=min(self.limit, other.limit),
            offset=max(self.offset, other.offset),
            sort_by=other.sort_by,  # Use other's sorting
            sort_order=other.sort_order,
        )

    def to_query_params(self) -> dict[str, Any]:
        """Convert filter to query parameters."""
        params = {}

        if self.time_range:
            params["start_time"] = self.time_range.start_time
            params["end_time"] = self.time_range.end_time

        if self.user_ids:
            params["user_ids"] = self.user_ids

        if self.resource_types:
            params["resource_types"] = self.resource_types

        if self.resource_ids:
            params["resource_ids"] = self.resource_ids

        if self.action_types:
            params["action_types"] = self.action_types

        if self.operations:
            params["operations"] = self.operations

        if self.severities:
            params["severities"] = [s.value for s in self.severities]

        if self.categories:
            params["categories"] = [c.value for c in self.categories]

        if self.statuses:
            params["statuses"] = [s.value for s in self.statuses]

        if self.outcomes:
            params["outcomes"] = self.outcomes

        if self.session_ids:
            params["session_ids"] = self.session_ids

        if self.correlation_ids:
            params["correlation_ids"] = self.correlation_ids

        if self.search_text:
            params["search_text"] = self.search_text

        params["include_system"] = self.include_system
        params["limit"] = self.limit
        params["offset"] = self.offset
        params["sort_by"] = self.sort_by
        params["sort_order"] = self.sort_order

        return params

    @classmethod
    def create_for_user(
        cls,
        user_id: UUID,
        time_range: TimeRange | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> "AuditFilter":
        """Factory method for user-specific filter."""
        return cls(
            user_ids=[user_id],
            time_range=time_range or TimeRange.last_days(30),
            limit=limit,
        )

    @classmethod
    def create_for_resource(
        cls,
        resource_type: str,
        resource_id: str,
        time_range: TimeRange | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> "AuditFilter":
        """Factory method for resource-specific filter."""
        return cls(
            resource_types=[resource_type],
            resource_ids=[resource_id],
            time_range=time_range or TimeRange.last_days(30),
            limit=limit,
        )

    @classmethod
    def create_for_security_review(
        cls, time_range: TimeRange | None = None, limit: int = DEFAULT_LIMIT
    ) -> "AuditFilter":
        """Factory method for security review filter."""
        return cls(
            severities=[AuditSeverity.HIGH, AuditSeverity.CRITICAL],
            categories=[AuditCategory.SECURITY, AuditCategory.AUTHENTICATION],
            outcomes=["failure"],
            time_range=time_range or TimeRange.last_days(7),
            limit=limit,
        )


__all__ = ["AuditFilter"]
