"""Query builder service for constructing complex audit search queries.

This module provides a fluent interface for building search queries
with support for complex conditions and aggregations.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity


class QueryBuilderService:
    """
    Service for building complex search queries.

    Provides a fluent interface for constructing Elasticsearch queries
    with support for various conditions, aggregations, and optimizations.
    """

    def __init__(self):
        """Initialize query builder."""
        self.reset()

    def reset(self) -> "QueryBuilderService":
        """Reset the query builder to initial state."""
        self._must_clauses = []
        self._should_clauses = []
        self._filter_clauses = []
        self._must_not_clauses = []
        self._aggregations = {}
        self._sort_clauses = []
        self._highlight_fields = []
        self._size = 10
        self._from = 0
        self._min_score = None
        return self

    # Time-based queries
    def in_time_range(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> "QueryBuilderService":
        """Add time range filter."""
        if start or end:
            range_clause = {"range": {"created_at": {}}}
            if start:
                range_clause["range"]["created_at"]["gte"] = start.isoformat()
            if end:
                range_clause["range"]["created_at"]["lte"] = end.isoformat()
            self._filter_clauses.append(range_clause)
        return self

    def in_last_hours(self, hours: int) -> "QueryBuilderService":
        """Filter to last N hours."""
        start = datetime.utcnow() - timedelta(hours=hours)
        return self.in_time_range(start=start)

    def in_last_days(self, days: int) -> "QueryBuilderService":
        """Filter to last N days."""
        start = datetime.utcnow() - timedelta(days=days)
        return self.in_time_range(start=start)

    # User-based queries
    def by_user(self, user_id: UUID | list[UUID]) -> "QueryBuilderService":
        """Filter by user ID(s)."""
        if isinstance(user_id, list):
            user_ids = [str(uid) for uid in user_id]
            self._filter_clauses.append({"terms": {"user_id": user_ids}})
        else:
            self._filter_clauses.append({"term": {"user_id": str(user_id)}})
        return self

    def exclude_system(self) -> "QueryBuilderService":
        """Exclude system-generated entries."""
        self._filter_clauses.append({"exists": {"field": "user_id"}})
        return self

    # Resource-based queries
    def for_resource(
        self, resource_type: str | None = None, resource_id: str | None = None
    ) -> "QueryBuilderService":
        """Filter by resource."""
        if resource_type:
            self._filter_clauses.append({"term": {"resource_type": resource_type}})
        if resource_id:
            self._filter_clauses.append({"term": {"resource_id": resource_id}})
        return self

    def for_resources(
        self,
        resource_types: list[str] | None = None,
        resource_ids: list[str] | None = None,
    ) -> "QueryBuilderService":
        """Filter by multiple resources."""
        if resource_types:
            self._filter_clauses.append({"terms": {"resource_type": resource_types}})
        if resource_ids:
            self._filter_clauses.append({"terms": {"resource_id": resource_ids}})
        return self

    # Action-based queries
    def with_action(self, action_type: str) -> "QueryBuilderService":
        """Filter by action type."""
        self._filter_clauses.append({"term": {"action_type": action_type}})
        return self

    def with_actions(self, action_types: list[str]) -> "QueryBuilderService":
        """Filter by multiple action types."""
        self._filter_clauses.append({"terms": {"action_type": action_types}})
        return self

    def with_operation(self, operation: str) -> "QueryBuilderService":
        """Filter by operation."""
        self._filter_clauses.append({"term": {"operation": operation}})
        return self

    # Classification queries
    def with_severity(
        self, severity: AuditSeverity | list[AuditSeverity]
    ) -> "QueryBuilderService":
        """Filter by severity level(s)."""
        if isinstance(severity, list):
            severities = [s.value for s in severity]
            self._filter_clauses.append({"terms": {"severity": severities}})
        else:
            self._filter_clauses.append({"term": {"severity": severity.value}})
        return self

    def minimum_severity(self, severity: AuditSeverity) -> "QueryBuilderService":
        """Filter to minimum severity level and above."""
        valid_severities = [s for s in AuditSeverity if s.value >= severity.value]
        return self.with_severity(valid_severities)

    def with_category(
        self, category: AuditCategory | list[AuditCategory]
    ) -> "QueryBuilderService":
        """Filter by category."""
        if isinstance(category, list):
            categories = [c.value for c in category]
            self._filter_clauses.append({"terms": {"category": categories}})
        else:
            self._filter_clauses.append({"term": {"category": category.value}})
        return self

    # Outcome queries
    def only_failures(self) -> "QueryBuilderService":
        """Filter to only failed operations."""
        self._filter_clauses.append({"term": {"outcome": "failure"}})
        return self

    def only_successes(self) -> "QueryBuilderService":
        """Filter to only successful operations."""
        self._filter_clauses.append({"term": {"outcome": "success"}})
        return self

    def with_outcome(self, outcome: str | list[str]) -> "QueryBuilderService":
        """Filter by outcome(s)."""
        if isinstance(outcome, list):
            self._filter_clauses.append({"terms": {"outcome": outcome}})
        else:
            self._filter_clauses.append({"term": {"outcome": outcome}})
        return self

    # Session queries
    def in_session(self, session_id: UUID) -> "QueryBuilderService":
        """Filter by session ID."""
        self._filter_clauses.append({"term": {"session_id": str(session_id)}})
        return self

    def with_correlation_id(self, correlation_id: str) -> "QueryBuilderService":
        """Filter by correlation ID."""
        self._filter_clauses.append({"term": {"correlation_id": correlation_id}})
        return self

    # Text search
    def search_text(
        self, text: str, fields: list[str] | None = None
    ) -> "QueryBuilderService":
        """Add text search query."""
        if not fields:
            fields = [
                "action_description^2",
                "resource_name^1.5",
                "error_message",
                "user_agent",
            ]

        self._must_clauses.append(
            {
                "multi_match": {
                    "query": text,
                    "fields": fields,
                    "type": "best_fields",
                    "operator": "and",
                }
            }
        )

        # Add fields for highlighting
        self._highlight_fields.extend([f.split("^")[0] for f in fields])

        return self

    def match_phrase(self, field: str, phrase: str) -> "QueryBuilderService":
        """Add phrase match query."""
        self._must_clauses.append({"match_phrase": {field: phrase}})
        return self

    # Complex queries
    def with_error_containing(self, text: str) -> "QueryBuilderService":
        """Filter to entries with errors containing text."""
        self._must_clauses.append(
            {
                "bool": {
                    "must": [
                        {"term": {"outcome": "failure"}},
                        {"match": {"error_message": text}},
                    ]
                }
            }
        )
        return self

    def by_ip_range(self, start_ip: str, end_ip: str) -> "QueryBuilderService":
        """Filter by IP address range."""
        self._filter_clauses.append(
            {"range": {"ip_address": {"gte": start_ip, "lte": end_ip}}}
        )
        return self

    def with_duration_range(
        self, min_ms: int | None = None, max_ms: int | None = None
    ) -> "QueryBuilderService":
        """Filter by duration range."""
        if min_ms is not None or max_ms is not None:
            range_clause = {"range": {"duration_ms": {}}}
            if min_ms is not None:
                range_clause["range"]["duration_ms"]["gte"] = min_ms
            if max_ms is not None:
                range_clause["range"]["duration_ms"]["lte"] = max_ms
            self._filter_clauses.append(range_clause)
        return self

    # Aggregations
    def aggregate_by_field(
        self, field: str, name: str | None = None, size: int = 10
    ) -> "QueryBuilderService":
        """Add field aggregation."""
        agg_name = name or f"{field}_agg"
        self._aggregations[agg_name] = {
            "terms": {"field": field, "size": size, "order": {"_count": "desc"}}
        }
        return self

    def aggregate_timeline(
        self, interval: str = "hour", field: str = "created_at"
    ) -> "QueryBuilderService":
        """Add timeline aggregation."""
        self._aggregations["timeline"] = {
            "date_histogram": {"field": field, "interval": interval, "min_doc_count": 0}
        }
        return self

    def aggregate_stats(
        self, field: str, name: str | None = None
    ) -> "QueryBuilderService":
        """Add statistical aggregation."""
        agg_name = name or f"{field}_stats"
        self._aggregations[agg_name] = {"stats": {"field": field}}
        return self

    def aggregate_percentiles(
        self,
        field: str,
        percentiles: list[float] | None = None,
        name: str | None = None,
    ) -> "QueryBuilderService":
        """Add percentile aggregation."""
        agg_name = name or f"{field}_percentiles"
        agg_def = {"percentiles": {"field": field}}

        if percentiles:
            agg_def["percentiles"]["percents"] = percentiles

        self._aggregations[agg_name] = agg_def
        return self

    # Sorting
    def sort_by(self, field: str, order: str = "desc") -> "QueryBuilderService":
        """Add sort clause."""
        self._sort_clauses.append({field: {"order": order}})
        return self

    def sort_by_score(self) -> "QueryBuilderService":
        """Sort by relevance score."""
        self._sort_clauses.append("_score")
        return self

    # Pagination
    def paginate(self, page: int, size: int) -> "QueryBuilderService":
        """Set pagination parameters."""
        self._from = (page - 1) * size
        self._size = size
        return self

    def limit(self, size: int) -> "QueryBuilderService":
        """Set result limit."""
        self._size = size
        return self

    def offset(self, from_: int) -> "QueryBuilderService":
        """Set result offset."""
        self._from = from_
        return self

    # Score threshold
    def min_score(self, score: float) -> "QueryBuilderService":
        """Set minimum score threshold."""
        self._min_score = score
        return self

    # Build methods
    def build(self) -> dict[str, Any]:
        """Build the complete query."""
        query = {}

        # Build bool query
        bool_query = {}

        if self._must_clauses:
            bool_query["must"] = self._must_clauses

        if self._should_clauses:
            bool_query["should"] = self._should_clauses
            if "must" not in bool_query:
                bool_query["minimum_should_match"] = 1

        if self._filter_clauses:
            bool_query["filter"] = self._filter_clauses

        if self._must_not_clauses:
            bool_query["must_not"] = self._must_not_clauses

        if bool_query:
            query["query"] = {"bool": bool_query}
        else:
            query["query"] = {"match_all": {}}

        # Add aggregations
        if self._aggregations:
            query["aggs"] = self._aggregations

        # Add sorting
        if self._sort_clauses:
            query["sort"] = self._sort_clauses

        # Add highlighting
        if self._highlight_fields:
            query["highlight"] = {
                "fields": {field: {} for field in set(self._highlight_fields)}
            }

        # Add pagination
        query["from"] = self._from
        query["size"] = self._size

        # Add score threshold
        if self._min_score is not None:
            query["min_score"] = self._min_score

        return query

    def build_count_query(self) -> dict[str, Any]:
        """Build query for counting only (no documents returned)."""
        query = self.build()
        query["size"] = 0
        if "sort" in query:
            del query["sort"]
        if "highlight" in query:
            del query["highlight"]
        return query

    def from_filter(self, filter: AuditFilter) -> "QueryBuilderService":
        """Build query from an AuditFilter."""
        self.reset()

        # Time range
        if filter.time_range:
            self.in_time_range(filter.time_range.start_time, filter.time_range.end_time)

        # Users
        if filter.user_ids:
            self.by_user(filter.user_ids)
        elif not filter.include_system:
            self.exclude_system()

        # Resources
        if filter.resource_types or filter.resource_ids:
            self.for_resources(filter.resource_types, filter.resource_ids)

        # Actions
        if filter.action_types:
            self.with_actions(filter.action_types)
        if filter.operations:
            self._filter_clauses.append({"terms": {"operation": filter.operations}})

        # Classification
        if filter.severities:
            self.with_severity(filter.severities)
        if filter.categories:
            self.with_category(filter.categories)

        # Outcome
        if filter.outcomes:
            self.with_outcome(filter.outcomes)

        # Session
        if filter.session_ids:
            for session_id in filter.session_ids:
                self.in_session(session_id)

        # Correlation
        if filter.correlation_ids:
            self._filter_clauses.append(
                {"terms": {"correlation_id": filter.correlation_ids}}
            )

        # Text search
        if filter.search_text:
            self.search_text(filter.search_text)

        # Sorting
        if filter.sort_by:
            self.sort_by(filter.sort_by, filter.sort_order or "desc")

        # Pagination
        self.offset(filter.offset).limit(filter.limit)

        return self


# Import at end to avoid circular imports
from datetime import timedelta

__all__ = ["QueryBuilderService"]
