"""GraphQL input types for audit search."""


import strawberry

from ..enums import (
    AuditActionTypeEnum,
    AuditCategoryEnum,
    AuditOutcomeEnum,
    AuditResourceTypeEnum,
    AuditSeverityEnum,
)
from .filter_input import (
    DateRangeInput,
    ExportOptionsInput,
    MetadataFilterInput,
    PaginationInput,
    PerformanceFilterInput,
    SortInput,
    TextSearchInput,
)


@strawberry.input
class AuditFilterInput:
    """Input type for audit entry filters."""

    # Time filters
    date_range: DateRangeInput | None = None

    # User filters
    user_ids: list[strawberry.ID] = strawberry.field(default_factory=list)
    user_emails: list[str] = strawberry.field(default_factory=list)
    include_system_actions: bool = False

    # Resource filters
    resource_types: list[AuditResourceTypeEnum] = strawberry.field(default_factory=list)
    resource_ids: list[str] = strawberry.field(default_factory=list)

    # Action filters
    action_types: list[AuditActionTypeEnum] = strawberry.field(default_factory=list)
    operations: list[str] = strawberry.field(default_factory=list)

    # Result filters
    severities: list[AuditSeverityEnum] = strawberry.field(default_factory=list)
    categories: list[AuditCategoryEnum] = strawberry.field(default_factory=list)
    outcomes: list[AuditOutcomeEnum] = strawberry.field(default_factory=list)

    # Context filters
    session_ids: list[strawberry.ID] = strawberry.field(default_factory=list)
    correlation_ids: list[str] = strawberry.field(default_factory=list)
    ip_addresses: list[str] = strawberry.field(default_factory=list)

    # Performance filters
    performance: PerformanceFilterInput | None = None

    # Metadata filters
    metadata: MetadataFilterInput | None = None

    def validate(self) -> list[str]:
        """Validate filter input."""
        errors = []

        # Validate nested filters
        if self.date_range:
            errors.extend(self.date_range.validate())

        if self.performance:
            errors.extend(self.performance.validate())

        if self.metadata:
            errors.extend(self.metadata.validate())

        # Validate IP addresses
        for ip in self.ip_addresses:
            if not self._is_valid_ip(ip):
                errors.append(f"Invalid IP address: {ip}")

        # Validate list sizes
        if len(self.user_ids) > 100:
            errors.append("Too many user IDs (max 100)")

        if len(self.resource_ids) > 100:
            errors.append("Too many resource IDs (max 100)")

        if len(self.operations) > 50:
            errors.append("Too many operations (max 50)")

        return errors

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import re

        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

    def to_criteria_dto(self) -> dict[str, Any]:
        """Convert to search criteria DTO."""
        return {
            "start_date": self.date_range.start_date if self.date_range else None,
            "end_date": self.date_range.end_date if self.date_range else None,
            "user_ids": [str(uid) for uid in self.user_ids],
            "user_emails": self.user_emails,
            "include_system_actions": self.include_system_actions,
            "resource_types": [rt.value for rt in self.resource_types],
            "resource_ids": self.resource_ids,
            "action_types": [at.value for at in self.action_types],
            "operations": self.operations,
            "severities": [s.value for s in self.severities],
            "categories": [c.value for c in self.categories],
            "outcomes": [o.value for o in self.outcomes],
            "session_ids": [str(sid) for sid in self.session_ids],
            "correlation_ids": self.correlation_ids,
            "ip_addresses": self.ip_addresses,
            "tags": self.metadata.tags if self.metadata else [],
            "compliance_tags": self.metadata.compliance_tags if self.metadata else [],
            "min_duration_ms": self.performance.min_duration_ms
            if self.performance
            else None,
            "max_duration_ms": self.performance.max_duration_ms
            if self.performance
            else None,
        }


@strawberry.input
class AuditSearchInput:
    """Input type for comprehensive audit search."""

    # Text search
    text_search: TextSearchInput | None = None

    # Filters
    filters: AuditFilterInput | None = None

    # Pagination and sorting
    pagination: PaginationInput | None = None
    sort: SortInput | None = None

    # Search options
    highlight_matches: bool = True
    include_related: bool = False
    facet_results: bool = True

    # Export options
    export_options: ExportOptionsInput | None = None

    def validate(self) -> list[str]:
        """Validate search input."""
        errors = []

        # Validate nested inputs
        if self.text_search:
            errors.extend(self.text_search.validate())

        if self.filters:
            errors.extend(self.filters.validate())

        if self.pagination:
            errors.extend(self.pagination.validate())

        if self.sort:
            errors.extend(self.sort.validate())

        if self.export_options:
            errors.extend(self.export_options.validate())

        # Require at least some search criteria
        has_text = self.text_search and self.text_search.query
        has_filters = self.filters and self._has_any_filters(self.filters)

        if not has_text and not has_filters:
            errors.append("At least one search criterion is required")

        return errors

    def _has_any_filters(self, filters: AuditFilterInput) -> bool:
        """Check if any filters are specified."""
        return bool(
            filters.date_range
            or filters.user_ids
            or filters.user_emails
            or filters.resource_types
            or filters.resource_ids
            or filters.action_types
            or filters.operations
            or filters.severities
            or filters.categories
            or filters.outcomes
            or filters.session_ids
            or filters.correlation_ids
            or filters.ip_addresses
            or filters.performance
            or filters.metadata
        )

    def to_criteria_dto(self) -> dict[str, Any]:
        """Convert to complete search criteria DTO."""

        criteria = {}

        # Text search
        if self.text_search:
            criteria["search_text"] = self.text_search.query
            criteria["search_fields"] = self.text_search.fields

        # Filters
        if self.filters:
            criteria.update(self.filters.to_criteria_dto())

        # Pagination
        if self.pagination:
            criteria["page"] = self.pagination.page
            criteria["page_size"] = self.pagination.page_size
        else:
            criteria["page"] = 1
            criteria["page_size"] = 50

        # Sorting
        if self.sort:
            criteria["sort_by"] = self.sort.field
            criteria["sort_order"] = self.sort.order.value
        else:
            criteria["sort_by"] = "created_at"
            criteria["sort_order"] = "desc"

        # Options
        criteria["include_metadata"] = True
        criteria["include_changes"] = True

        return criteria


@strawberry.input
class SavedSearchInput:
    """Input type for saving searches."""

    name: str
    description: str | None = None
    search_criteria: AuditSearchInput
    is_alert_enabled: bool = False
    alert_threshold: int | None = None

    def validate(self) -> list[str]:
        """Validate saved search input."""
        errors = []

        if not self.name or len(self.name.strip()) == 0:
            errors.append("Search name is required")

        if len(self.name) > 255:
            errors.append("Search name too long (max 255 characters)")

        if self.description and len(self.description) > 1000:
            errors.append("Description too long (max 1000 characters)")

        # Validate search criteria
        errors.extend(self.search_criteria.validate())

        # Alert validation
        if self.is_alert_enabled:
            if self.alert_threshold is None:
                errors.append("Alert threshold required when alerts enabled")
            elif self.alert_threshold < 1:
                errors.append("Alert threshold must be positive")
            elif self.alert_threshold > 10000:
                errors.append("Alert threshold too high (max 10,000)")

        return errors


@strawberry.input
class AuditSearchExportInput:
    """Input type for exporting search results."""

    search_criteria: AuditSearchInput
    export_format: str = "json"
    include_related: bool = False
    max_records: int = 10000

    def validate(self) -> list[str]:
        """Validate export input."""
        errors = []

        # Validate search criteria
        errors.extend(self.search_criteria.validate())

        # Validate export options
        valid_formats = ["json", "csv", "pdf", "xlsx"]
        if self.export_format not in valid_formats:
            errors.append(f"Invalid export format: {self.export_format}")

        if self.max_records < 1 or self.max_records > 100000:
            errors.append("Max records must be between 1 and 100,000")

        return errors
