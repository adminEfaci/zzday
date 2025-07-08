"""Audit search service for complex search operations.

This module provides high-level search functionality combining database
queries with full-text search capabilities.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditSeverity
from app.modules.audit.infrastructure.archival.archival_service import ArchivalService
from app.modules.audit.infrastructure.repositories.audit_entry_repository import (
    AuditEntryRepository,
)
from app.modules.audit.infrastructure.search.elasticsearch_adapter import (
    ElasticsearchAdapter,
)
from app.modules.audit.infrastructure.search.query_builder_service import (
    QueryBuilderService,
)

logger = get_logger(__name__)


class AuditSearchService:
    """
    High-level service for searching audit data.

    Combines database queries, full-text search, and archived data search
    for comprehensive audit trail exploration.
    """

    def __init__(
        self,
        entry_repository: AuditEntryRepository,
        elasticsearch_adapter: ElasticsearchAdapter | None = None,
        archival_service: ArchivalService | None = None,
    ):
        """
        Initialize audit search service.

        Args:
            entry_repository: Repository for audit entries
            elasticsearch_adapter: Optional Elasticsearch adapter for full-text search
            archival_service: Optional archival service for searching archives
        """
        self.entry_repository = entry_repository
        self.es_adapter = elasticsearch_adapter
        self.archival_service = archival_service
        self.query_builder = QueryBuilderService()

    async def search_entries(
        self,
        filter: AuditFilter,
        search_mode: str = "hybrid",
        include_archived: bool = False,
    ) -> tuple[list[AuditEntry], int, dict[str, Any]]:
        """
        Search audit entries with various strategies.

        Args:
            filter: Search filter criteria
            search_mode: 'database', 'fulltext', or 'hybrid'
            include_archived: Whether to search archived data

        Returns:
            Tuple of (entries, total_count, search_metadata)
        """
        search_metadata = {"mode": search_mode, "sources": [], "performance": {}}

        start_time = datetime.utcnow()

        try:
            if search_mode == "database":
                entries, total_count = await self._search_database(filter)
                search_metadata["sources"].append("database")

            elif search_mode == "fulltext":
                if not self.es_adapter:
                    raise InfrastructureError("Full-text search not available")

                entries, total_count = await self._search_elasticsearch(filter)
                search_metadata["sources"].append("elasticsearch")

            else:  # hybrid
                entries, total_count = await self._search_hybrid(filter)
                search_metadata["sources"].extend(["database", "elasticsearch"])

            # Search archives if requested
            if include_archived and self.archival_service:
                archived_entries = await self._search_archives(filter)
                entries.extend(archived_entries)
                total_count += len(archived_entries)
                search_metadata["sources"].append("archives")

            # Calculate performance metrics
            search_metadata["performance"]["duration_ms"] = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            search_metadata["performance"]["result_count"] = len(entries)
            search_metadata["performance"]["total_count"] = total_count

            logger.info(
                "Audit search completed",
                mode=search_mode,
                results=len(entries),
                total=total_count,
                duration_ms=search_metadata["performance"]["duration_ms"],
            )

            return entries, total_count, search_metadata

        except Exception as e:
            logger.exception("Audit search failed", mode=search_mode, error=str(e))
            raise InfrastructureError(f"Search failed: {e!s}")

    async def search_with_facets(
        self, filter: AuditFilter, facet_fields: list[str]
    ) -> dict[str, Any]:
        """
        Search with faceted results for filtering.

        Args:
            filter: Search filter criteria
            facet_fields: Fields to generate facets for

        Returns:
            Search results with facets
        """
        if not self.es_adapter:
            raise InfrastructureError("Faceted search requires Elasticsearch")

        try:
            # Get search results
            results, total_count = await self.es_adapter.search_entries(filter)

            # Get facets
            facets = await self.es_adapter.get_facets(filter, facet_fields)

            return {"results": results, "total_count": total_count, "facets": facets}

        except Exception as e:
            logger.exception("Faceted search failed", error=str(e))
            raise InfrastructureError(f"Faceted search failed: {e!s}")

    async def get_activity_timeline(
        self, filter: AuditFilter, interval: str = "hour"
    ) -> list[dict[str, Any]]:
        """
        Get activity timeline for visualization.

        Args:
            filter: Search filter criteria
            interval: Time interval for grouping

        Returns:
            Timeline data points
        """
        if not self.es_adapter:
            # Fall back to database aggregation
            return await self._get_database_timeline(filter, interval)

        try:
            return await self.es_adapter.get_timeline(filter, interval)

        except Exception as e:
            logger.exception("Timeline generation failed", error=str(e))
            raise InfrastructureError(f"Timeline generation failed: {e!s}")

    async def find_anomalies(
        self, time_window_hours: int = 24, baseline_days: int = 7
    ) -> list[dict[str, Any]]:
        """
        Find anomalous audit activity patterns.

        Args:
            time_window_hours: Recent time window to analyze
            baseline_days: Days of baseline data for comparison

        Returns:
            List of detected anomalies
        """
        anomalies = []

        try:
            # Get recent activity
            recent_start = datetime.utcnow() - timedelta(hours=time_window_hours)
            recent_filter = AuditFilter(
                time_range=TimeRange(start_time=recent_start), limit=10000
            )
            recent_entries, _ = await self.entry_repository.find_by_filter(
                recent_filter
            )

            # Get baseline activity
            baseline_start = datetime.utcnow() - timedelta(days=baseline_days)
            baseline_end = recent_start
            baseline_filter = AuditFilter(
                time_range=TimeRange(start_time=baseline_start, end_time=baseline_end),
                limit=100000,
            )
            baseline_entries, _ = await self.entry_repository.find_by_filter(
                baseline_filter
            )

            # Analyze patterns
            anomalies.extend(
                await self._detect_volume_anomalies(
                    recent_entries, baseline_entries, time_window_hours, baseline_days
                )
            )

            anomalies.extend(
                await self._detect_failure_anomalies(recent_entries, baseline_entries)
            )

            anomalies.extend(
                await self._detect_access_anomalies(recent_entries, baseline_entries)
            )

            logger.info(
                "Anomaly detection completed",
                anomalies_found=len(anomalies),
                time_window_hours=time_window_hours,
                baseline_days=baseline_days,
            )

            return anomalies

        except Exception as e:
            logger.exception("Anomaly detection failed", error=str(e))
            raise InfrastructureError(f"Anomaly detection failed: {e!s}")

    async def get_user_activity_summary(
        self, user_id: UUID, days: int = 30
    ) -> dict[str, Any]:
        """
        Get comprehensive activity summary for a user.

        Args:
            user_id: User ID to analyze
            days: Number of days to include

        Returns:
            User activity summary
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            # Get user entries
            entries = await self.entry_repository.find_by_user(
                user_id, start_date=start_date
            )

            # Calculate statistics
            summary = {
                "user_id": str(user_id),
                "period_days": days,
                "total_actions": len(entries),
                "daily_average": len(entries) / days if days > 0 else 0,
                "action_breakdown": {},
                "resource_breakdown": {},
                "failure_rate": 0,
                "top_resources": [],
                "activity_pattern": {},
                "suspicious_activities": [],
            }

            if entries:
                # Action breakdown
                action_counts = {}
                for entry in entries:
                    action = entry.action.action_type
                    action_counts[action] = action_counts.get(action, 0) + 1
                summary["action_breakdown"] = action_counts

                # Resource breakdown
                resource_counts = {}
                for entry in entries:
                    resource = entry.resource.resource_type
                    resource_counts[resource] = resource_counts.get(resource, 0) + 1
                summary["resource_breakdown"] = resource_counts

                # Failure rate
                failures = sum(1 for e in entries if e.is_failed())
                summary["failure_rate"] = failures / len(entries)

                # Top resources accessed
                resource_access = {}
                for entry in entries:
                    if entry.resource.resource_id:
                        key = f"{entry.resource.resource_type}:{entry.resource.resource_id}"
                        resource_access[key] = resource_access.get(key, 0) + 1

                top_resources = sorted(
                    resource_access.items(), key=lambda x: x[1], reverse=True
                )[:10]
                summary["top_resources"] = [
                    {"resource": k, "count": v} for k, v in top_resources
                ]

                # Activity pattern by hour
                hour_counts = {}
                for entry in entries:
                    hour = entry.created_at.hour
                    hour_counts[hour] = hour_counts.get(hour, 0) + 1
                summary["activity_pattern"] = hour_counts

                # Detect suspicious activities
                summary[
                    "suspicious_activities"
                ] = await self._detect_user_suspicious_activities(entries)

            return summary

        except Exception as e:
            logger.exception(
                "User activity summary failed", user_id=str(user_id), error=str(e)
            )
            raise InfrastructureError(f"Activity summary failed: {e!s}")

    async def _search_database(
        self, filter: AuditFilter
    ) -> tuple[list[AuditEntry], int]:
        """Search using database repository."""
        return await self.entry_repository.find_by_filter(filter, include_fields=True)

    async def _search_elasticsearch(
        self, filter: AuditFilter
    ) -> tuple[list[AuditEntry], int]:
        """Search using Elasticsearch."""
        # Get results from Elasticsearch
        results, total_count = await self.es_adapter.search_entries(filter)

        # Convert to domain entities
        entry_ids = [UUID(result["id"]) for result in results]

        # Fetch full entries from database
        entries = []
        for entry_id in entry_ids:
            entry = await self.entry_repository.find_by_id(entry_id)
            if entry:
                entries.append(entry)

        return entries, total_count

    async def _search_hybrid(self, filter: AuditFilter) -> tuple[list[AuditEntry], int]:
        """Search using hybrid approach."""
        # Use Elasticsearch for text search, database for precise filtering
        if filter.search_text and self.es_adapter:
            return await self._search_elasticsearch(filter)
        return await self._search_database(filter)

    async def _search_archives(self, filter: AuditFilter) -> list[AuditEntry]:
        """Search archived entries."""
        # This is a simplified implementation
        # In practice, would need more sophisticated archive search
        archived_entries = []

        # Search archives within time range
        if filter.time_range:
            archives = await self.archival_service.search_archives(
                start_date=filter.time_range.start_time,
                end_date=filter.time_range.end_time,
            )

            for archive in archives[:5]:  # Limit to avoid too much data
                try:
                    entry_dicts = await self.archival_service.retrieve_archive(
                        archive["key"]
                    )

                    # Convert and filter
                    for entry_dict in entry_dicts:
                        # Apply basic filters
                        if filter.user_ids and entry_dict.get("user_id") not in [
                            str(uid) for uid in filter.user_ids
                        ]:
                            continue

                        # Convert to entity (simplified)
                        # In practice, would need proper deserialization
                        archived_entries.append(entry_dict)

                        if len(archived_entries) >= filter.limit:
                            break

                except Exception as e:
                    logger.warning(
                        "Failed to search archive", archive=archive["key"], error=str(e)
                    )

                if len(archived_entries) >= filter.limit:
                    break

        return archived_entries

    async def _get_database_timeline(
        self, filter: AuditFilter, interval: str
    ) -> list[dict[str, Any]]:
        """Get timeline from database when Elasticsearch not available."""
        # Simplified implementation
        # In practice, would use database-specific date truncation
        timeline = []

        entries, _ = await self.entry_repository.find_by_filter(filter)

        # Group by interval
        interval_groups = {}
        for entry in entries:
            # Simple hourly grouping
            if interval == "hour":
                key = entry.created_at.replace(minute=0, second=0, microsecond=0)
            elif interval == "day":
                key = entry.created_at.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            else:
                key = entry.created_at.replace(minute=0, second=0, microsecond=0)

            if key not in interval_groups:
                interval_groups[key] = {"count": 0, "severities": {}, "outcomes": {}}

            group = interval_groups[key]
            group["count"] += 1

            severity = entry.severity.value
            group["severities"][severity] = group["severities"].get(severity, 0) + 1

            outcome = entry.outcome
            group["outcomes"][outcome] = group["outcomes"].get(outcome, 0) + 1

        # Convert to timeline format
        for timestamp, data in sorted(interval_groups.items()):
            timeline.append(
                {
                    "timestamp": timestamp.isoformat(),
                    "count": data["count"],
                    "severity_breakdown": data["severities"],
                    "outcome_breakdown": data["outcomes"],
                }
            )

        return timeline

    async def _detect_volume_anomalies(
        self,
        recent_entries: list[AuditEntry],
        baseline_entries: list[AuditEntry],
        time_window_hours: int,
        baseline_days: int,
    ) -> list[dict[str, Any]]:
        """Detect volume-based anomalies."""
        anomalies = []

        # Calculate rates
        recent_rate = len(recent_entries) / time_window_hours
        baseline_rate = len(baseline_entries) / (baseline_days * 24)

        # Check for significant increase
        if baseline_rate > 0 and recent_rate > baseline_rate * 3:
            anomalies.append(
                {
                    "type": "high_volume",
                    "severity": "high",
                    "description": f"Activity volume is {recent_rate / baseline_rate:.1f}x higher than baseline",
                    "recent_rate_per_hour": recent_rate,
                    "baseline_rate_per_hour": baseline_rate,
                }
            )

        # Check for significant decrease
        elif baseline_rate > 0 and recent_rate < baseline_rate * 0.1:
            anomalies.append(
                {
                    "type": "low_volume",
                    "severity": "medium",
                    "description": f"Activity volume is {recent_rate / baseline_rate:.1%} of baseline",
                    "recent_rate_per_hour": recent_rate,
                    "baseline_rate_per_hour": baseline_rate,
                }
            )

        return anomalies

    async def _detect_failure_anomalies(
        self, recent_entries: list[AuditEntry], baseline_entries: list[AuditEntry]
    ) -> list[dict[str, Any]]:
        """Detect failure rate anomalies."""
        anomalies = []

        # Calculate failure rates
        recent_failures = sum(1 for e in recent_entries if e.is_failed())
        recent_failure_rate = (
            recent_failures / len(recent_entries) if recent_entries else 0
        )

        baseline_failures = sum(1 for e in baseline_entries if e.is_failed())
        baseline_failure_rate = (
            baseline_failures / len(baseline_entries) if baseline_entries else 0
        )

        # Check for increased failures
        if baseline_failure_rate < 0.05 and recent_failure_rate > 0.2:
            anomalies.append(
                {
                    "type": "high_failure_rate",
                    "severity": "critical",
                    "description": f"Failure rate increased from {baseline_failure_rate:.1%} to {recent_failure_rate:.1%}",
                    "recent_failure_rate": recent_failure_rate,
                    "baseline_failure_rate": baseline_failure_rate,
                    "recent_failure_count": recent_failures,
                }
            )

        return anomalies

    async def _detect_access_anomalies(
        self, recent_entries: list[AuditEntry], baseline_entries: list[AuditEntry]
    ) -> list[dict[str, Any]]:
        """Detect unusual access patterns."""
        anomalies = []

        # Check for new resource types being accessed
        recent_resources = {e.resource.resource_type for e in recent_entries}
        baseline_resources = {e.resource.resource_type for e in baseline_entries}

        new_resources = recent_resources - baseline_resources
        if new_resources:
            anomalies.append(
                {
                    "type": "new_resource_access",
                    "severity": "medium",
                    "description": "Access to new resource types detected",
                    "new_resources": list(new_resources),
                }
            )

        # Check for unusual time patterns
        recent_hours = [e.created_at.hour for e in recent_entries]
        if recent_hours:
            # Check for activity outside business hours
            off_hours = [h for h in recent_hours if h < 6 or h > 22]
            if len(off_hours) > len(recent_hours) * 0.3:
                anomalies.append(
                    {
                        "type": "off_hours_activity",
                        "severity": "medium",
                        "description": f"{len(off_hours) / len(recent_hours):.1%} of activity outside business hours",
                        "off_hours_count": len(off_hours),
                    }
                )

        return anomalies

    async def _detect_user_suspicious_activities(
        self, entries: list[AuditEntry]
    ) -> list[dict[str, Any]]:
        """Detect suspicious activities for a user."""
        suspicious = []

        # High failure rate
        failures = sum(1 for e in entries if e.is_failed())
        if failures > len(entries) * 0.3:
            suspicious.append(
                {
                    "type": "high_failure_rate",
                    "description": f"{failures / len(entries):.1%} of actions failed",
                    "count": failures,
                }
            )

        # Rapid consecutive failures
        sorted_entries = sorted(entries, key=lambda e: e.created_at)
        consecutive_failures = 0
        max_consecutive = 0

        for entry in sorted_entries:
            if entry.is_failed():
                consecutive_failures += 1
                max_consecutive = max(max_consecutive, consecutive_failures)
            else:
                consecutive_failures = 0

        if max_consecutive >= 5:
            suspicious.append(
                {
                    "type": "consecutive_failures",
                    "description": f"{max_consecutive} consecutive failed actions",
                    "count": max_consecutive,
                }
            )

        # Access to sensitive resources
        sensitive_access = [
            e
            for e in entries
            if e.severity in (AuditSeverity.HIGH, AuditSeverity.CRITICAL)
        ]
        if len(sensitive_access) > 10:
            suspicious.append(
                {
                    "type": "high_sensitive_access",
                    "description": f"{len(sensitive_access)} high-severity actions performed",
                    "count": len(sensitive_access),
                }
            )

        return suspicious


# Import at end to avoid circular imports
from datetime import timedelta

from app.modules.audit.domain.value_objects.time_range import TimeRange

__all__ = ["AuditSearchService"]
