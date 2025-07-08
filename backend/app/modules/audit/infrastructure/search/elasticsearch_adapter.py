"""Elasticsearch adapter for audit search functionality.

This module provides integration with Elasticsearch for full-text search
and analytics capabilities on audit data.
"""

from datetime import datetime
from typing import Any

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.entities.audit_filter import AuditFilter

logger = get_logger(__name__)


class ElasticsearchAdapter:
    """
    Elasticsearch adapter for audit search operations.

    Provides full-text search, aggregations, and analytics capabilities
    for audit entries with high performance at scale.
    """

    # Index settings for optimal performance
    INDEX_SETTINGS = {
        "settings": {
            "number_of_shards": 3,
            "number_of_replicas": 1,
            "index": {
                "refresh_interval": "5s",
                "max_result_window": 50000,
                "analysis": {
                    "analyzer": {
                        "audit_analyzer": {
                            "type": "custom",
                            "tokenizer": "standard",
                            "filter": ["lowercase", "stop", "snowball"],
                        },
                        "path_analyzer": {
                            "type": "custom",
                            "tokenizer": "path_hierarchy",
                        },
                    }
                },
            },
        },
        "mappings": {
            "properties": {
                # Identifiers
                "id": {"type": "keyword"},
                "audit_log_id": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "correlation_id": {"type": "keyword"},
                # Action fields
                "action_type": {"type": "keyword"},
                "operation": {"type": "keyword"},
                "action_description": {
                    "type": "text",
                    "analyzer": "audit_analyzer",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                # Resource fields
                "resource_type": {"type": "keyword"},
                "resource_id": {"type": "keyword"},
                "resource_name": {
                    "type": "text",
                    "analyzer": "audit_analyzer",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "resource_path": {
                    "type": "text",
                    "analyzer": "path_analyzer",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                # Context fields
                "ip_address": {"type": "ip"},
                "user_agent": {"type": "text", "analyzer": "audit_analyzer"},
                "request_id": {"type": "keyword"},
                # Classification
                "severity": {"type": "keyword"},
                "category": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                # Performance
                "duration_ms": {"type": "integer"},
                # Timestamps
                "created_at": {"type": "date", "format": "strict_date_time"},
                # Error information
                "error_message": {"type": "text", "analyzer": "audit_analyzer"},
                "error_code": {"type": "keyword"},
                # Additional data
                "metadata": {
                    "type": "object",
                    "enabled": False,  # Store but don't index
                },
                # Nested field changes
                "changes": {
                    "type": "nested",
                    "properties": {
                        "field_name": {"type": "keyword"},
                        "field_path": {"type": "keyword"},
                        "old_value": {"type": "text"},
                        "new_value": {"type": "text"},
                        "is_sensitive": {"type": "boolean"},
                    },
                },
            }
        },
    }

    def __init__(
        self,
        hosts: list[str],
        index_prefix: str = "audit_entries",
        username: str | None = None,
        password: str | None = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
    ):
        """
        Initialize Elasticsearch adapter.

        Args:
            hosts: List of Elasticsearch hosts
            index_prefix: Prefix for index names
            username: Optional username for authentication
            password: Optional password for authentication
            use_ssl: Whether to use SSL
            verify_certs: Whether to verify SSL certificates
        """
        self.hosts = hosts
        self.index_prefix = index_prefix

        # Create client configuration
        client_config = {
            "hosts": hosts,
            "use_ssl": use_ssl,
            "verify_certs": verify_certs,
        }

        if username and password:
            client_config["basic_auth"] = (username, password)

        self.client = AsyncElasticsearch(**client_config)

        # Index alias for current write index
        self.write_alias = f"{index_prefix}_write"
        self.read_alias = f"{index_prefix}_read"

    async def initialize(self) -> None:
        """Initialize Elasticsearch indices and templates."""
        try:
            # Create index template for time-based indices
            template_name = f"{self.index_prefix}_template"

            await self.client.indices.put_index_template(
                name=template_name,
                body={
                    "index_patterns": [f"{self.index_prefix}-*"],
                    "template": self.INDEX_SETTINGS,
                    "priority": 100,
                },
            )

            # Create initial index if it doesn't exist
            current_index = self._get_current_index_name()
            if not await self.client.indices.exists(index=current_index):
                await self.client.indices.create(
                    index=current_index, body=self.INDEX_SETTINGS
                )

            # Update aliases
            await self._update_aliases(current_index)

            logger.info(
                "Elasticsearch initialized",
                index_prefix=self.index_prefix,
                current_index=current_index,
            )

        except Exception as e:
            logger.exception("Failed to initialize Elasticsearch", error=str(e))
            raise InfrastructureError(f"Elasticsearch initialization failed: {e!s}")

    async def index_entry(self, entry: AuditEntry) -> None:
        """Index a single audit entry."""
        try:
            document = self._entry_to_document(entry)

            await self.client.index(
                index=self.write_alias,
                id=str(entry.id),
                body=document,
                refresh=False,  # Don't wait for refresh
            )

        except Exception as e:
            logger.exception(
                "Failed to index audit entry", entry_id=str(entry.id), error=str(e)
            )
            raise InfrastructureError(f"Failed to index entry: {e!s}")

    async def bulk_index_entries(self, entries: list[AuditEntry]) -> tuple[int, int]:
        """
        Bulk index multiple entries for high throughput.

        Returns:
            Tuple of (success_count, failure_count)
        """
        if not entries:
            return 0, 0

        try:
            # Prepare bulk actions
            actions = []
            for entry in entries:
                action = {
                    "_index": self.write_alias,
                    "_id": str(entry.id),
                    "_source": self._entry_to_document(entry),
                }
                actions.append(action)

            # Execute bulk operation
            success_count = 0
            failure_count = 0

            async for ok, result in async_bulk(
                self.client, actions, chunk_size=500, raise_on_error=False
            ):
                if ok:
                    success_count += 1
                else:
                    failure_count += 1
                    logger.warning("Bulk index failure", result=result)

            logger.info(
                "Bulk indexed audit entries",
                total=len(entries),
                success=success_count,
                failures=failure_count,
            )

            return success_count, failure_count

        except Exception as e:
            logger.exception("Bulk indexing failed", count=len(entries), error=str(e))
            raise InfrastructureError(f"Bulk indexing failed: {e!s}")

    async def search_entries(
        self, filter: AuditFilter, highlight: bool = True
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search entries based on filter criteria.

        Returns:
            Tuple of (results, total_count)
        """
        try:
            # Build search query
            query = self._build_search_query(filter)

            # Add highlighting if requested
            if highlight and filter.search_text:
                query["highlight"] = {
                    "fields": {
                        "action_description": {},
                        "resource_name": {},
                        "error_message": {},
                    }
                }

            # Add sorting
            query["sort"] = self._build_sort_clause(filter)

            # Add pagination
            query["from"] = filter.offset
            query["size"] = filter.limit

            # Execute search
            response = await self.client.search(index=self.read_alias, body=query)

            # Extract results
            hits = response["hits"]
            total_count = hits["total"]["value"]

            results = []
            for hit in hits["hits"]:
                result = hit["_source"]
                result["_score"] = hit["_score"]

                if highlight and "highlight" in hit:
                    result["_highlight"] = hit["highlight"]

                results.append(result)

            return results, total_count

        except Exception as e:
            logger.exception("Search failed", error=str(e))
            raise InfrastructureError(f"Search failed: {e!s}")

    async def aggregate_entries(
        self, filter: AuditFilter, aggregations: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Perform aggregations on audit entries.

        Args:
            filter: Filter criteria
            aggregations: Elasticsearch aggregation definitions

        Returns:
            Aggregation results
        """
        try:
            # Build query with aggregations
            query = self._build_search_query(filter)
            query["size"] = 0  # Don't return documents
            query["aggs"] = aggregations

            # Execute aggregation
            response = await self.client.search(index=self.read_alias, body=query)

            return response["aggregations"]

        except Exception as e:
            logger.exception("Aggregation failed", error=str(e))
            raise InfrastructureError(f"Aggregation failed: {e!s}")

    async def get_facets(
        self, filter: AuditFilter, facet_fields: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Get faceted search results for specified fields.

        Args:
            filter: Filter criteria
            facet_fields: Fields to facet on

        Returns:
            Dictionary mapping field names to facet values
        """
        # Build aggregations for facets
        aggregations = {}
        for field in facet_fields:
            aggregations[field] = {
                "terms": {
                    "field": field,
                    "size": 20,  # Top 20 values
                    "order": {"_count": "desc"},
                }
            }

        # Get aggregation results
        agg_results = await self.aggregate_entries(filter, aggregations)

        # Format facet results
        facets = {}
        for field, result in agg_results.items():
            facets[field] = [
                {"value": bucket["key"], "count": bucket["doc_count"]}
                for bucket in result["buckets"]
            ]

        return facets

    async def get_timeline(
        self, filter: AuditFilter, interval: str = "hour"
    ) -> list[dict[str, Any]]:
        """
        Get timeline of audit activity.

        Args:
            filter: Filter criteria
            interval: Time interval (minute, hour, day, week, month)

        Returns:
            Timeline data with counts per interval
        """
        # Build date histogram aggregation
        aggregations = {
            "timeline": {
                "date_histogram": {
                    "field": "created_at",
                    "interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {
                    "severity_breakdown": {"terms": {"field": "severity"}},
                    "outcome_breakdown": {"terms": {"field": "outcome"}},
                },
            }
        }

        # Add bounds if time range specified
        if filter.time_range:
            if filter.time_range.start_time:
                aggregations["timeline"]["date_histogram"]["extended_bounds"] = {
                    "min": filter.time_range.start_time.isoformat()
                }
            if filter.time_range.end_time:
                aggregations["timeline"]["date_histogram"]["extended_bounds"][
                    "max"
                ] = filter.time_range.end_time.isoformat()

        # Get aggregation results
        agg_results = await self.aggregate_entries(filter, aggregations)

        # Format timeline results
        timeline = []
        for bucket in agg_results["timeline"]["buckets"]:
            point = {
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"],
                "severity_breakdown": {
                    item["key"]: item["doc_count"]
                    for item in bucket["severity_breakdown"]["buckets"]
                },
                "outcome_breakdown": {
                    item["key"]: item["doc_count"]
                    for item in bucket["outcome_breakdown"]["buckets"]
                },
            }
            timeline.append(point)

        return timeline

    async def delete_old_entries(
        self, older_than: datetime, batch_size: int = 1000
    ) -> int:
        """
        Delete entries older than specified date.

        Args:
            older_than: Delete entries created before this date
            batch_size: Batch size for deletion

        Returns:
            Number of entries deleted
        """
        try:
            deleted_count = 0

            # Use delete by query
            response = await self.client.delete_by_query(
                index=self.read_alias,
                body={
                    "query": {"range": {"created_at": {"lt": older_than.isoformat()}}}
                },
                scroll_size=batch_size,
                wait_for_completion=True,
            )

            deleted_count = response["deleted"]

            logger.info(
                "Deleted old entries from Elasticsearch",
                count=deleted_count,
                older_than=older_than.isoformat(),
            )

            return deleted_count

        except Exception as e:
            logger.exception("Failed to delete old entries", error=str(e))
            raise InfrastructureError(f"Deletion failed: {e!s}")

    async def roll_over_index(self) -> str:
        """
        Roll over to a new index for better performance.

        Returns:
            Name of the new index
        """
        try:
            # Create new index name
            new_index = self._get_current_index_name()

            # Create new index
            await self.client.indices.create(index=new_index, body=self.INDEX_SETTINGS)

            # Update write alias
            await self._update_aliases(new_index, update_write_only=True)

            logger.info("Rolled over to new index", new_index=new_index)

            return new_index

        except Exception as e:
            logger.exception("Index rollover failed", error=str(e))
            raise InfrastructureError(f"Rollover failed: {e!s}")

    async def close(self) -> None:
        """Close Elasticsearch client connection."""
        await self.client.close()

    def _get_current_index_name(self) -> str:
        """Generate current index name based on date."""
        return f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m')}"

    async def _update_aliases(
        self, index_name: str, update_write_only: bool = False
    ) -> None:
        """Update index aliases."""
        actions = []

        # Update write alias
        actions.append(
            {"remove": {"index": f"{self.index_prefix}-*", "alias": self.write_alias}}
        )
        actions.append({"add": {"index": index_name, "alias": self.write_alias}})

        # Update read alias (includes all indices)
        if not update_write_only:
            actions.append(
                {"add": {"index": f"{self.index_prefix}-*", "alias": self.read_alias}}
            )

        await self.client.indices.update_aliases(body={"actions": actions})

    def _entry_to_document(self, entry: AuditEntry) -> dict[str, Any]:
        """Convert audit entry to Elasticsearch document."""
        doc = {
            "id": str(entry.id),
            "audit_log_id": str(entry.session_id) if entry.session_id else None,
            "session_id": str(entry.session_id) if entry.session_id else None,
            "user_id": str(entry.user_id) if entry.user_id else None,
            "correlation_id": entry.correlation_id,
            # Action
            "action_type": entry.action.action_type,
            "operation": entry.action.operation,
            "action_description": entry.action.description,
            # Resource
            "resource_type": entry.resource.resource_type,
            "resource_id": entry.resource.resource_id,
            "resource_name": entry.resource.get_display_name(),
            # Context
            "ip_address": entry.context.ip_address,
            "user_agent": entry.context.user_agent,
            "request_id": entry.context.request_id,
            # Classification
            "severity": entry.severity.value,
            "category": entry.category.value,
            "outcome": entry.outcome,
            # Performance
            "duration_ms": entry.duration_ms,
            # Timestamp
            "created_at": entry.created_at.isoformat(),
            # Metadata
            "metadata": entry.metadata.to_dict() if entry.metadata else None,
        }

        # Add error information if failed
        if entry.error_details:
            doc["error_message"] = entry.error_details.get("message")
            doc["error_code"] = entry.error_details.get("code")

        # Add changes if present
        if entry.changes:
            doc["changes"] = [
                {
                    "field_name": field.field_name,
                    "field_path": field.field_path,
                    "old_value": field.get_display_value(field.old_value),
                    "new_value": field.get_display_value(field.new_value),
                    "is_sensitive": field.is_sensitive,
                }
                for field in entry.changes
            ]

        return doc

    def _build_search_query(self, filter: AuditFilter) -> dict[str, Any]:
        """Build Elasticsearch query from filter."""
        must_clauses = []
        filter_clauses = []

        # Time range filter
        if filter.time_range:
            range_clause = {"range": {"created_at": {}}}
            if filter.time_range.start_time:
                range_clause["range"]["created_at"][
                    "gte"
                ] = filter.time_range.start_time.isoformat()
            if filter.time_range.end_time:
                range_clause["range"]["created_at"][
                    "lte"
                ] = filter.time_range.end_time.isoformat()
            filter_clauses.append(range_clause)

        # User filters
        if filter.user_ids:
            filter_clauses.append(
                {"terms": {"user_id": [str(uid) for uid in filter.user_ids]}}
            )
        elif not filter.include_system:
            filter_clauses.append({"exists": {"field": "user_id"}})

        # Resource filters
        if filter.resource_types:
            filter_clauses.append({"terms": {"resource_type": filter.resource_types}})
        if filter.resource_ids:
            filter_clauses.append({"terms": {"resource_id": filter.resource_ids}})

        # Action filters
        if filter.action_types:
            filter_clauses.append({"terms": {"action_type": filter.action_types}})
        if filter.operations:
            filter_clauses.append({"terms": {"operation": filter.operations}})

        # Classification filters
        if filter.severities:
            filter_clauses.append(
                {"terms": {"severity": [s.value for s in filter.severities]}}
            )
        if filter.categories:
            filter_clauses.append(
                {"terms": {"category": [c.value for c in filter.categories]}}
            )

        # Outcome filter
        if filter.outcomes:
            filter_clauses.append({"terms": {"outcome": filter.outcomes}})

        # Session filter
        if filter.session_ids:
            filter_clauses.append(
                {"terms": {"session_id": [str(sid) for sid in filter.session_ids]}}
            )

        # Correlation filter
        if filter.correlation_ids:
            filter_clauses.append({"terms": {"correlation_id": filter.correlation_ids}})

        # Text search
        if filter.search_text:
            must_clauses.append(
                {
                    "multi_match": {
                        "query": filter.search_text,
                        "fields": [
                            "action_description^2",
                            "resource_name^1.5",
                            "error_message",
                            "user_agent",
                        ],
                        "type": "best_fields",
                        "operator": "and",
                    }
                }
            )

        # Build final query
        query = {"bool": {}}
        if must_clauses:
            query["bool"]["must"] = must_clauses
        if filter_clauses:
            query["bool"]["filter"] = filter_clauses

        return {"query": query}

    def _build_sort_clause(self, filter: AuditFilter) -> list[dict[str, Any]]:
        """Build sort clause from filter."""
        sort_field = filter.sort_by or "created_at"
        sort_order = filter.sort_order or "desc"

        # Map field names to Elasticsearch fields
        field_mapping = {
            "created_at": "created_at",
            "severity": "severity",
            "duration": "duration_ms",
        }

        es_field = field_mapping.get(sort_field, sort_field)

        return [{es_field: {"order": sort_order}}]


__all__ = ["ElasticsearchAdapter"]
