"""Search audit entries query.

This module implements the query and handler for searching audit entries
with comprehensive filtering and pagination capabilities.
"""

from typing import Any

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_entry_dto import AuditEntryDTO
from app.modules.audit.application.dtos.audit_search_criteria_dto import (
    AuditSearchCriteriaDTO,
)

logger = get_logger(__name__)


class SearchAuditEntriesQuery(Query):
    """
    Query to search audit entries with complex criteria.

    Supports comprehensive filtering, text search, and pagination
    for audit entry retrieval.
    """

    def __init__(self, search_criteria: AuditSearchCriteriaDTO):
        """
        Initialize search audit entries query.

        Args:
            search_criteria: Search criteria and filters
        """
        super().__init__()

        self.search_criteria = self._validate_search_criteria(search_criteria)

        # Set pagination from criteria
        self.page = search_criteria.page
        self.page_size = search_criteria.page_size

        self._freeze()

    def _validate_search_criteria(
        self, criteria: AuditSearchCriteriaDTO
    ) -> AuditSearchCriteriaDTO:
        """Validate search criteria."""
        if not isinstance(criteria, AuditSearchCriteriaDTO):
            raise ValidationError("Invalid search criteria provided")

        # Validate the criteria
        validation_errors = criteria.validate()
        if validation_errors:
            raise ValidationError(
                f"Search criteria validation failed: {'; '.join(validation_errors)}"
            )

        return criteria


class SearchAuditEntriesQueryHandler(
    QueryHandler[SearchAuditEntriesQuery, dict[str, Any]]
):
    """
    Handler for searching audit entries.

    This handler processes complex search queries and returns
    paginated results with metadata.
    """

    def __init__(self, audit_repository: Any, user_service: Any, search_service: Any):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit data access
            user_service: Service for user information lookup
            search_service: Service for advanced search capabilities
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.user_service = user_service
        self.search_service = search_service

    async def handle(self, query: SearchAuditEntriesQuery) -> dict[str, Any]:
        """
        Handle the search audit entries query.

        Args:
            query: Query containing search criteria

        Returns:
            Dictionary containing search results and metadata
        """
        criteria = query.search_criteria

        logger.debug(
            "Searching audit entries",
            criteria_summary=self._get_criteria_summary(criteria),
        )

        # Build search filters
        filters = criteria.to_filter_dict()

        # Add text search if specified
        if criteria.search_text:
            text_filters = await self.search_service.build_text_search_filters(
                criteria.search_text, criteria.search_fields
            )
            filters.update(text_filters)

        # Execute search
        search_result = await self.audit_repository.search_entries(
            filters=filters,
            limit=criteria.page_size,
            offset=criteria.get_offset(),
            order_by=criteria.sort_by,
            order_direction=criteria.sort_order,
        )

        entries = search_result["entries"]
        total_count = search_result["total_count"]

        # Convert to DTOs with user information
        entry_dtos = []
        user_cache = {}  # Cache user info to avoid repeated lookups

        for entry in entries:
            user_info = None
            if entry.user_id:
                if entry.user_id not in user_cache:
                    user_cache[entry.user_id] = await self.user_service.get_user_info(
                        entry.user_id
                    )
                user_info = user_cache[entry.user_id]

            entry_dto = AuditEntryDTO.from_domain(entry, user_info)
            entry_dtos.append(entry_dto.to_dict())

        # Calculate pagination metadata
        total_pages = (total_count + criteria.page_size - 1) // criteria.page_size
        has_next = criteria.page < total_pages
        has_previous = criteria.page > 1

        # Build response
        response = {
            "entries": entry_dtos,
            "pagination": {
                "current_page": criteria.page,
                "page_size": criteria.page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_previous": has_previous,
            },
            "search_metadata": {
                "criteria_applied": self._get_applied_criteria(criteria),
                "search_time_ms": search_result.get("search_time_ms", 0),
                "filters_used": len([k for k, v in filters.items() if v is not None]),
            },
        }

        # Add aggregations if available
        if "aggregations" in search_result:
            response["aggregations"] = search_result["aggregations"]

        logger.debug(
            "Audit entries search completed",
            result_count=len(entry_dtos),
            total_count=total_count,
            page=criteria.page,
        )

        return response

    def _get_criteria_summary(self, criteria: AuditSearchCriteriaDTO) -> dict[str, Any]:
        """Get a summary of applied search criteria."""
        summary = {}

        if criteria.start_date or criteria.end_date:
            summary["date_range"] = {
                "start": criteria.start_date.isoformat()
                if criteria.start_date
                else None,
                "end": criteria.end_date.isoformat() if criteria.end_date else None,
            }

        if criteria.user_ids:
            summary["user_count"] = len(criteria.user_ids)

        if criteria.resource_types:
            summary["resource_types"] = criteria.resource_types

        if criteria.action_types:
            summary["action_types"] = criteria.action_types

        if criteria.severities:
            summary["severities"] = criteria.severities

        if criteria.search_text:
            summary["text_search"] = True

        return summary

    def _get_applied_criteria(self, criteria: AuditSearchCriteriaDTO) -> list[str]:
        """Get list of applied criteria for metadata."""
        applied = []

        if criteria.start_date:
            applied.append("start_date")
        if criteria.end_date:
            applied.append("end_date")
        if criteria.user_ids:
            applied.append("user_filter")
        if criteria.resource_types:
            applied.append("resource_type_filter")
        if criteria.resource_ids:
            applied.append("resource_id_filter")
        if criteria.action_types:
            applied.append("action_type_filter")
        if criteria.operations:
            applied.append("operation_filter")
        if criteria.severities:
            applied.append("severity_filter")
        if criteria.categories:
            applied.append("category_filter")
        if criteria.outcomes:
            applied.append("outcome_filter")
        if criteria.session_ids:
            applied.append("session_filter")
        if criteria.correlation_ids:
            applied.append("correlation_filter")
        if criteria.ip_addresses:
            applied.append("ip_filter")
        if criteria.tags:
            applied.append("tag_filter")
        if criteria.search_text:
            applied.append("text_search")
        if criteria.min_duration_ms is not None:
            applied.append("min_duration_filter")
        if criteria.max_duration_ms is not None:
            applied.append("max_duration_filter")

        return applied

    @property
    def query_type(self) -> type[SearchAuditEntriesQuery]:
        """Get query type this handler processes."""
        return SearchAuditEntriesQuery


__all__ = ["SearchAuditEntriesQuery", "SearchAuditEntriesQueryHandler"]
