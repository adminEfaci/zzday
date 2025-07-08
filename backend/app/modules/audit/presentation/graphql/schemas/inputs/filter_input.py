"""GraphQL filter input types."""

from datetime import datetime

import strawberry

from ..enums import SortOrderEnum


@strawberry.input
class DateRangeInput:
    """Input type for date range filters."""

    start_date: datetime | None = None
    end_date: datetime | None = None

    def validate(self) -> list[str]:
        """Validate date range."""
        errors = []

        if self.start_date and self.end_date:
            if self.start_date > self.end_date:
                errors.append("Start date must be before end date")

        return errors


@strawberry.input
class PaginationInput:
    """Input type for pagination."""

    page: int = 1
    page_size: int = 50

    def validate(self) -> list[str]:
        """Validate pagination parameters."""
        errors = []

        if self.page < 1:
            errors.append("Page must be positive")

        if self.page_size < 1 or self.page_size > 1000:
            errors.append("Page size must be between 1 and 1000")

        return errors

    def get_offset(self) -> int:
        """Calculate offset for database query."""
        return (self.page - 1) * self.page_size


@strawberry.input
class SortInput:
    """Input type for sorting."""

    field: str = "created_at"
    order: SortOrderEnum = SortOrderEnum.DESC

    def validate(self) -> list[str]:
        """Validate sort parameters."""
        errors = []

        valid_fields = [
            "created_at",
            "severity",
            "category",
            "user_id",
            "resource_type",
            "action_type",
            "duration_ms",
            "outcome",
        ]

        if self.field not in valid_fields:
            errors.append(f"Invalid sort field: {self.field}")

        return errors


@strawberry.input
class TextSearchInput:
    """Input type for text search."""

    query: str
    fields: list[str] = strawberry.field(
        default_factory=lambda: ["description", "resource_name", "user_agent"]
    )
    fuzzy: bool = False

    def validate(self) -> list[str]:
        """Validate text search parameters."""
        errors = []

        if not self.query or len(self.query.strip()) < 2:
            errors.append("Search query must be at least 2 characters")

        if len(self.query) > 1000:
            errors.append("Search query too long (max 1000 characters)")

        valid_fields = [
            "description",
            "resource_name",
            "user_agent",
            "operation",
            "error_details",
            "tags",
            "metadata",
        ]

        for field in self.fields:
            if field not in valid_fields:
                errors.append(f"Invalid search field: {field}")

        return errors


@strawberry.input
class PerformanceFilterInput:
    """Input type for performance filters."""

    min_duration_ms: int | None = None
    max_duration_ms: int | None = None
    timeout_only: bool = False
    error_only: bool = False

    def validate(self) -> list[str]:
        """Validate performance filters."""
        errors = []

        if self.min_duration_ms is not None and self.min_duration_ms < 0:
            errors.append("Minimum duration must be non-negative")

        if self.max_duration_ms is not None and self.max_duration_ms < 0:
            errors.append("Maximum duration must be non-negative")

        if (
            self.min_duration_ms is not None
            and self.max_duration_ms is not None
            and self.min_duration_ms > self.max_duration_ms
        ):
            errors.append("Minimum duration must be less than maximum duration")

        return errors


@strawberry.input
class MetadataFilterInput:
    """Input type for metadata filters."""

    tags: list[str] = strawberry.field(default_factory=list)
    compliance_tags: list[str] = strawberry.field(default_factory=list)
    custom_fields: str | None = None

    def validate(self) -> list[str]:
        """Validate metadata filters."""
        errors = []

        # Validate tag format
        for tag in self.tags + self.compliance_tags:
            if not tag or len(tag.strip()) == 0:
                errors.append("Tags cannot be empty")
            elif len(tag) > 100:
                errors.append(f"Tag too long: {tag}")

        return errors


@strawberry.input
class ExportOptionsInput:
    """Input type for export options."""

    format: str = "json"
    include_metadata: bool = True
    include_changes: bool = True
    include_related: bool = False
    max_records: int = 10000

    def validate(self) -> list[str]:
        """Validate export options."""
        errors = []

        valid_formats = ["json", "csv", "pdf", "xlsx"]
        if self.format not in valid_formats:
            errors.append(f"Invalid export format: {self.format}")

        if self.max_records < 1 or self.max_records > 100000:
            errors.append("Max records must be between 1 and 100,000")

        return errors
