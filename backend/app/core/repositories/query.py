"""Advanced Query Capabilities

Provides comprehensive query building with pagination, sorting, filtering,
and aggregation support.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.errors import ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)

TEntity = TypeVar("TEntity", bound=Entity)


class SortDirection(str, Enum):
    """Sort direction enumeration."""

    ASC = "asc"
    DESC = "desc"


class AggregateFunction(str, Enum):
    """Aggregate function enumeration."""

    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    COUNT_DISTINCT = "count_distinct"


@dataclass
class SortField:
    """Sort field definition."""

    field: str
    direction: SortDirection = SortDirection.ASC
    null_first: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "field": self.field,
            "direction": self.direction.value,
            "null_first": self.null_first,
        }


@dataclass
class PageInfo:
    """Pagination information."""

    page: int = 1
    size: int = 20
    total: int | None = None

    @property
    def offset(self) -> int:
        """Calculate offset from page number."""
        return (self.page - 1) * self.size

    @property
    def total_pages(self) -> int | None:
        """Calculate total pages."""
        if self.total is None:
            return None
        return (self.total + self.size - 1) // self.size

    @property
    def has_next(self) -> bool:
        """Check if there's a next page."""
        if self.total is None:
            return True  # Unknown, assume there might be more
        return self.page < self.total_pages

    @property
    def has_previous(self) -> bool:
        """Check if there's a previous page."""
        return self.page > 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "page": self.page,
            "size": self.size,
            "total": self.total,
            "total_pages": self.total_pages,
            "has_next": self.has_next,
            "has_previous": self.has_previous,
        }


@dataclass
class CursorInfo:
    """Cursor-based pagination information."""

    cursor: str | None = None
    size: int = 20

    def decode_cursor(self) -> dict[str, Any]:
        """Decode cursor value."""
        if not self.cursor:
            return {}

        try:
            # Base64 decode and parse JSON
            import base64

            decoded = base64.b64decode(self.cursor).decode("utf-8")
            return json.loads(decoded)
        except Exception as e:
            logger.warning(f"Failed to decode cursor: {e}")
            return {}

    @staticmethod
    def encode_cursor(data: dict[str, Any]) -> str:
        """Encode cursor value."""
        import base64

        encoded = json.dumps(data, default=str)
        return base64.b64encode(encoded.encode("utf-8")).decode("utf-8")


@dataclass
class QueryOptions:
    """Comprehensive query options."""

    # Pagination
    page_info: PageInfo | None = None
    cursor_info: CursorInfo | None = None

    # Sorting
    sort_fields: list[SortField] = field(default_factory=list)

    # Filtering
    specification: Specification | None = None
    filters: dict[str, Any] = field(default_factory=dict)

    # Field selection
    include_fields: list[str] | None = None
    exclude_fields: list[str] | None = None

    # Relationships
    include_relations: list[str] = field(default_factory=list)

    # Search
    search_query: str | None = None
    search_fields: list[str] = field(default_factory=list)

    # Aggregation
    group_by: list[str] = field(default_factory=list)
    aggregates: dict[str, AggregateFunction] = field(default_factory=dict)

    # Performance
    use_cache: bool = True
    cache_ttl: int | None = None

    def validate(self) -> None:
        """Validate query options."""
        # Validate pagination
        if self.page_info and self.cursor_info:
            raise ValidationError("Cannot use both page and cursor pagination")

        if self.page_info:
            if self.page_info.page < 1:
                raise ValidationError("Page number must be >= 1")
            if self.page_info.size < 1 or self.page_info.size > 1000:
                raise ValidationError("Page size must be between 1 and 1000")

        if self.cursor_info:
            if self.cursor_info.size < 1 or self.cursor_info.size > 1000:
                raise ValidationError("Cursor size must be between 1 and 1000")

        # Validate field selection
        if self.include_fields and self.exclude_fields:
            raise ValidationError("Cannot use both include and exclude fields")

        # Validate aggregation
        if self.aggregates and not self.group_by:
            raise ValidationError("Aggregates require group_by fields")


@dataclass
class QueryResult:
    """Query result with metadata."""

    items: list[TEntity]
    page_info: PageInfo | None = None
    cursor_info: CursorInfo | None = None
    next_cursor: str | None = None
    aggregates: dict[str, Any] | None = None

    @property
    def count(self) -> int:
        """Get number of items."""
        return len(self.items)

    @property
    def is_empty(self) -> bool:
        """Check if result is empty."""
        return len(self.items) == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "items": [
                item.to_dict() if hasattr(item, "to_dict") else str(item)
                for item in self.items
            ],
            "count": self.count,
        }

        if self.page_info:
            result["page_info"] = self.page_info.to_dict()

        if self.cursor_info:
            result["cursor_info"] = {
                "cursor": self.cursor_info.cursor,
                "size": self.cursor_info.size,
                "next_cursor": self.next_cursor,
            }

        if self.aggregates:
            result["aggregates"] = self.aggregates

        return result


class IQueryBuilder(ABC):
    """Query builder interface."""

    @abstractmethod
    def with_specification(self, spec: Specification) -> "IQueryBuilder":
        """Add specification filter."""

    @abstractmethod
    def with_filter(self, field: str, value: Any) -> "IQueryBuilder":
        """Add field filter."""

    @abstractmethod
    def with_filters(self, filters: dict[str, Any]) -> "IQueryBuilder":
        """Add multiple filters."""

    @abstractmethod
    def with_sort(
        self, field: str, direction: SortDirection = SortDirection.ASC
    ) -> "IQueryBuilder":
        """Add sort field."""

    @abstractmethod
    def with_pagination(self, page: int, size: int) -> "IQueryBuilder":
        """Add pagination."""

    @abstractmethod
    def with_cursor(self, cursor: str | None, size: int) -> "IQueryBuilder":
        """Add cursor pagination."""

    @abstractmethod
    def include_fields(self, fields: list[str]) -> "IQueryBuilder":
        """Include specific fields."""

    @abstractmethod
    def exclude_fields(self, fields: list[str]) -> "IQueryBuilder":
        """Exclude specific fields."""

    @abstractmethod
    def include_relations(self, relations: list[str]) -> "IQueryBuilder":
        """Include related entities."""

    @abstractmethod
    def with_search(self, query: str, fields: list[str]) -> "IQueryBuilder":
        """Add text search."""

    @abstractmethod
    def group_by(self, fields: list[str]) -> "IQueryBuilder":
        """Add group by fields."""

    @abstractmethod
    def with_aggregate(
        self, field: str, function: AggregateFunction
    ) -> "IQueryBuilder":
        """Add aggregate function."""

    @abstractmethod
    def build(self) -> QueryOptions:
        """Build query options."""


class QueryBuilder(IQueryBuilder):
    """Fluent query builder implementation."""

    def __init__(self):
        """Initialize query builder."""
        self._options = QueryOptions()

    def with_specification(self, spec: Specification) -> "QueryBuilder":
        """Add specification filter."""
        self._options.specification = spec
        return self

    def with_filter(self, field: str, value: Any) -> "QueryBuilder":
        """Add field filter."""
        self._options.filters[field] = value
        return self

    def with_filters(self, filters: dict[str, Any]) -> "QueryBuilder":
        """Add multiple filters."""
        self._options.filters.update(filters)
        return self

    def with_sort(
        self,
        field: str,
        direction: SortDirection = SortDirection.ASC,
        null_first: bool = False,
    ) -> "QueryBuilder":
        """Add sort field."""
        self._options.sort_fields.append(SortField(field, direction, null_first))
        return self

    def with_pagination(self, page: int, size: int) -> "QueryBuilder":
        """Add pagination."""
        self._options.page_info = PageInfo(page=page, size=size)
        self._options.cursor_info = None  # Clear cursor if set
        return self

    def with_cursor(self, cursor: str | None, size: int) -> "QueryBuilder":
        """Add cursor pagination."""
        self._options.cursor_info = CursorInfo(cursor=cursor, size=size)
        self._options.page_info = None  # Clear page if set
        return self

    def include_fields(self, fields: list[str]) -> "QueryBuilder":
        """Include specific fields."""
        self._options.include_fields = fields
        self._options.exclude_fields = None  # Clear exclude if set
        return self

    def exclude_fields(self, fields: list[str]) -> "QueryBuilder":
        """Exclude specific fields."""
        self._options.exclude_fields = fields
        self._options.include_fields = None  # Clear include if set
        return self

    def include_relations(self, relations: list[str]) -> "QueryBuilder":
        """Include related entities."""
        self._options.include_relations.extend(relations)
        return self

    def with_search(self, query: str, fields: list[str]) -> "QueryBuilder":
        """Add text search."""
        self._options.search_query = query
        self._options.search_fields = fields
        return self

    def group_by(self, fields: list[str]) -> "QueryBuilder":
        """Add group by fields."""
        self._options.group_by.extend(fields)
        return self

    def with_aggregate(self, field: str, function: AggregateFunction) -> "QueryBuilder":
        """Add aggregate function."""
        self._options.aggregates[field] = function
        return self

    def with_cache(
        self, enabled: bool = True, ttl: int | None = None
    ) -> "QueryBuilder":
        """Configure caching."""
        self._options.use_cache = enabled
        self._options.cache_ttl = ttl
        return self

    def build(self) -> QueryOptions:
        """Build and validate query options."""
        self._options.validate()
        return self._options


def create_query() -> QueryBuilder:
    """Create new query builder."""
    return QueryBuilder()


# Common query patterns


def paginated_query(page: int = 1, size: int = 20) -> QueryBuilder:
    """Create paginated query."""
    return create_query().with_pagination(page, size)


def sorted_query(field: str, desc: bool = False) -> QueryBuilder:
    """Create sorted query."""
    direction = SortDirection.DESC if desc else SortDirection.ASC
    return create_query().with_sort(field, direction)


def filtered_query(filters: dict[str, Any]) -> QueryBuilder:
    """Create filtered query."""
    return create_query().with_filters(filters)


def search_query(query: str, fields: list[str]) -> QueryBuilder:
    """Create search query."""
    return create_query().with_search(query, fields)


__all__ = [
    "AggregateFunction",
    "CursorInfo",
    # Interfaces and implementations
    "IQueryBuilder",
    "PageInfo",
    "QueryBuilder",
    "QueryOptions",
    "QueryResult",
    # Enums
    "SortDirection",
    # Data classes
    "SortField",
    # Factory functions
    "create_query",
    "filtered_query",
    "paginated_query",
    "search_query",
    "sorted_query",
]
