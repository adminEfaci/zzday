"""GraphQL types for search results."""


import strawberry

from .audit_entry_type import AuditEntryAggregation, AuditEntryType


@strawberry.type
class SearchHighlightType:
    """GraphQL type for search highlights."""

    field: str
    value: str
    highlights: list[str]


@strawberry.type
class SearchFacetType:
    """GraphQL type for search facets."""

    field: str
    label: str
    values: list["FacetValueType"]

    @strawberry.field
    def total_count(self) -> int:
        """Total count across all facet values."""
        return sum(v.count for v in self.values)


@strawberry.type
class FacetValueType:
    """GraphQL type for facet values."""

    value: str
    label: str
    count: int
    selected: bool = False


@strawberry.type
class SearchMetadataType:
    """GraphQL type for search metadata."""

    total_results: int
    search_time_ms: float
    query_complexity: int
    cached: bool
    suggestions: list[str] = strawberry.field(default_factory=list)


@strawberry.type
class AuditSearchResultType:
    """GraphQL type for audit search results."""

    # Search results
    entries: list[AuditEntryType]

    # Pagination
    total_count: int
    page: int
    page_size: int
    has_next_page: bool
    has_previous_page: bool

    # Search enhancements
    highlights: list[SearchHighlightType] = strawberry.field(default_factory=list)
    facets: list[SearchFacetType] = strawberry.field(default_factory=list)
    aggregations: list[AuditEntryAggregation] = strawberry.field(default_factory=list)

    # Metadata
    search_metadata: SearchMetadataType

    @strawberry.field
    def total_pages(self) -> int:
        """Calculate total pages."""
        if self.page_size == 0:
            return 0
        return (self.total_count + self.page_size - 1) // self.page_size

    @strawberry.field
    def start_index(self) -> int:
        """Calculate start index for current page."""
        return (self.page - 1) * self.page_size + 1

    @strawberry.field
    def end_index(self) -> int:
        """Calculate end index for current page."""
        return min(self.start_index + self.page_size - 1, self.total_count)

    @strawberry.field
    def has_results(self) -> bool:
        """Check if search returned any results."""
        return len(self.entries) > 0

    @strawberry.field
    def result_summary(self) -> str:
        """Generate result summary text."""
        if self.total_count == 0:
            return "No results found"
        if self.total_count == 1:
            return "1 result found"
        return f"{self.total_count:,} results found"
