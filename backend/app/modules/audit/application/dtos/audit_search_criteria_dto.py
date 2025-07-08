"""Audit search criteria DTO.

This module defines the Data Transfer Object for audit search criteria,
providing a structured format for complex audit queries.
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


@dataclass
class AuditSearchCriteriaDTO:
    """
    Data Transfer Object for audit search criteria.

    Provides a comprehensive set of filters for searching audit entries,
    supporting complex queries across multiple dimensions.
    """

    # Time filters
    start_date: datetime | None = None
    end_date: datetime | None = None

    # User filters
    user_ids: list[UUID] = field(default_factory=list)
    user_emails: list[str] = field(default_factory=list)
    include_system_actions: bool = False

    # Resource filters
    resource_types: list[str] = field(default_factory=list)
    resource_ids: list[str] = field(default_factory=list)

    # Action filters
    action_types: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)

    # Result filters
    severities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    outcomes: list[str] = field(default_factory=list)

    # Context filters
    session_ids: list[UUID] = field(default_factory=list)
    correlation_ids: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)

    # Metadata filters
    tags: list[str] = field(default_factory=list)
    compliance_tags: list[str] = field(default_factory=list)

    # Text search
    search_text: str | None = None
    search_fields: list[str] = field(
        default_factory=lambda: ["description", "resource_name", "user_agent"]
    )

    # Performance filters
    min_duration_ms: int | None = None
    max_duration_ms: int | None = None

    # Pagination
    page: int = 1
    page_size: int = 50

    # Sorting
    sort_by: str = "created_at"
    sort_order: str = "desc"

    # Export options
    include_metadata: bool = True
    include_changes: bool = True

    def validate(self) -> list[str]:
        """
        Validate search criteria.

        Returns:
            List of validation errors, empty if valid
        """
        errors = []

        # Validate date range
        if self.start_date and self.end_date:
            if self.start_date > self.end_date:
                errors.append("Start date must be before end date")

        # Validate pagination
        if self.page < 1:
            errors.append("Page must be positive")

        if self.page_size < 1 or self.page_size > 1000:
            errors.append("Page size must be between 1 and 1000")

        # Validate sort order
        if self.sort_order not in ["asc", "desc"]:
            errors.append("Sort order must be 'asc' or 'desc'")

        # Validate sort field
        valid_sort_fields = [
            "created_at",
            "severity",
            "user_id",
            "resource_type",
            "action_type",
            "duration_ms",
        ]
        if self.sort_by not in valid_sort_fields:
            errors.append(f"Invalid sort field: {self.sort_by}")

        # Validate severities
        valid_severities = ["low", "medium", "high", "critical"]
        for severity in self.severities:
            if severity not in valid_severities:
                errors.append(f"Invalid severity: {severity}")

        # Validate categories
        valid_categories = [
            "authentication",
            "authorization",
            "data_access",
            "configuration",
            "system",
            "security",
            "compliance",
            "integration",
        ]
        for category in self.categories:
            if category not in valid_categories:
                errors.append(f"Invalid category: {category}")

        return errors

    def to_filter_dict(self) -> dict:
        """Convert to dictionary for query building."""
        filters = {}

        if self.start_date:
            filters["created_at__gte"] = self.start_date

        if self.end_date:
            filters["created_at__lte"] = self.end_date

        if self.user_ids:
            filters["user_id__in"] = self.user_ids

        if self.resource_types:
            filters["resource_type__in"] = self.resource_types

        if self.resource_ids:
            filters["resource_id__in"] = self.resource_ids

        if self.action_types:
            filters["action_type__in"] = self.action_types

        if self.operations:
            filters["operation__in"] = self.operations

        if self.severities:
            filters["severity__in"] = self.severities

        if self.categories:
            filters["category__in"] = self.categories

        if self.outcomes:
            filters["outcome__in"] = self.outcomes

        if self.session_ids:
            filters["session_id__in"] = self.session_ids

        if self.correlation_ids:
            filters["correlation_id__in"] = self.correlation_ids

        if self.ip_addresses:
            filters["ip_address__in"] = self.ip_addresses

        if self.tags:
            filters["tags__overlap"] = self.tags

        if self.compliance_tags:
            filters["compliance_tags__overlap"] = self.compliance_tags

        if self.min_duration_ms is not None:
            filters["duration_ms__gte"] = self.min_duration_ms

        if self.max_duration_ms is not None:
            filters["duration_ms__lte"] = self.max_duration_ms

        if not self.include_system_actions:
            filters["user_id__isnull"] = False

        return filters

    def get_offset(self) -> int:
        """Calculate offset for pagination."""
        return (self.page - 1) * self.page_size


__all__ = ["AuditSearchCriteriaDTO"]
