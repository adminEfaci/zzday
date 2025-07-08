"""
Comprehensive Audit Queries GraphQL Resolver

This module provides comprehensive audit trail queries with enterprise-grade features:
- Multi-dimensional search and filtering
- Timeline and activity tracking
- Performance analytics and reporting
- Compliance monitoring and validation
- Real-time data aggregation

Features:
- Advanced search with multiple criteria
- Paginated results with cursor-based navigation
- Faceted search results for filtering assistance
- Export capabilities for compliance reporting
- Performance optimizations for large datasets
- Integration with caching and search indexing

Security:
- Authentication and authorization required
- Role-based access control for sensitive audit data
- Rate limiting to prevent abuse
- Input validation and sanitization
- Audit logging for all query operations
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import strawberry

# Core imports
from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.queries.get_audit_log_query import GetAuditLogQuery
from app.modules.audit.application.queries.get_user_activity_query import (
    GetUserActivityQuery,
)
from app.modules.audit.application.queries.search_audit_entries_query import (
    SearchAuditEntriesQuery,
)

# Audit domain imports
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.application.services.reporting_service import ReportingService
from app.modules.audit.presentation.graphql.schemas.inputs.audit_search_input import (
    AuditFilterInput,
    AuditSearchExportInput,
    AuditSearchInput,
)
from app.modules.audit.presentation.graphql.schemas.inputs.report_inputs import (
    AnalyticsQueryInput,
    TimelineQueryInput,
)
from app.modules.audit.presentation.graphql.schemas.types.analytics_type import (
    AuditAnalyticsType,
)

# GraphQL types and inputs
from app.modules.audit.presentation.graphql.schemas.types.audit_entry_type import (
    AuditEntryAggregation,
    AuditEntryConnection,
)
from app.modules.audit.presentation.graphql.schemas.types.audit_report_type import (
    AuditReportType,
    AuditTimelineType,
)
from app.modules.audit.presentation.graphql.schemas.types.search_result_type import (
    AuditSearchResultType,
)

# Mappers
from app.modules.audit.presentation.mappers.audit_mapper import AuditMapper
from app.modules.audit.presentation.mappers.report_mapper import ReportMapper

# Identity imports for authentication
from app.modules.identity.presentation.graphql.decorators import (
    audit_log,
    batch_size_limit,
    cache_result,
    operation_timeout,
    rate_limit,
    require_auth,
    require_permission,
    track_metrics,
)

logger = get_logger(__name__)


@strawberry.type
class AuditQueries:
    """
    Comprehensive audit queries with enterprise features.

    Provides access to audit trail data with advanced search, filtering,
    analytics, and reporting capabilities. Designed for compliance teams,
    security analysts, and system administrators.
    """

    @strawberry.field(
        description="Search audit entries with comprehensive filters and analytics"
    )
    @require_auth()
    @require_permission("audit.entries.read")
    @rate_limit(requests=100, window=60)
    @audit_log("audit.search")
    @track_metrics("audit_search")
    @operation_timeout(30)
    async def search_audit_entries(
        self, info: strawberry.Info, input: AuditSearchInput
    ) -> AuditSearchResultType:
        """
        Advanced audit entry search with faceted results and analytics.

        Features:
        - Multi-dimensional filtering (user, resource, action, time, etc.)
        - Full-text search across audit fields
        - Faceted results for interactive filtering
        - Performance analytics and duration filters
        - Export capabilities for compliance reporting

        Args:
            input: Comprehensive search criteria and options

        Returns:
            Search results with entries, facets, and metadata

        Raises:
            ValidationError: If search criteria are invalid
            AuthorizationError: If user lacks required permissions
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid search criteria: {'; '.join(validation_errors)}"
                )

            # Get audit service from DI container
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )

            # Convert input to criteria DTO
            criteria = input.to_criteria_dto()

            # Apply user context and permissions
            current_user = info.context.get("current_user")
            if not current_user.has_permission("audit.entries.read_all"):
                # Restrict to user's own entries if no elevated permissions
                criteria["user_ids"] = [str(current_user.id)]

            logger.info(
                "Executing audit search",
                user_id=str(current_user.id),
                criteria_summary={
                    "has_text_search": bool(input.text_search),
                    "filter_count": len(
                        [
                            f
                            for f in [
                                input.filters.user_ids,
                                input.filters.resource_types,
                                input.filters.action_types,
                                input.filters.severities,
                            ]
                            if f
                        ]
                    )
                    if input.filters
                    else 0,
                    "page": input.pagination.page if input.pagination else 1,
                },
            )

            # Execute search query
            search_query = SearchAuditEntriesQuery(
                criteria=criteria,
                include_facets=input.facet_results,
                include_highlights=input.highlight_matches,
                include_related=input.include_related,
            )

            search_result = await audit_service.search_entries(search_query)

            # Convert to GraphQL types
            return AuditMapper.search_result_to_graphql(
                search_result,
                include_highlights=input.highlight_matches,
                include_facets=input.facet_results,
            )

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Audit search failed: {e}", exc_info=True)
            raise ValidationError("Search operation failed")

    @strawberry.field(
        description="Get audit entries for specific user with activity timeline"
    )
    @require_auth()
    @require_permission("audit.user_activity.read")
    @rate_limit(requests=50, window=60)
    @audit_log("audit.user_activity")
    @cache_result(ttl=300)
    async def get_user_activity(
        self,
        info: strawberry.Info,
        user_id: strawberry.ID,
        days_back: int = 30,
        include_timeline: bool = True,
        include_statistics: bool = True,
    ) -> AuditReportType:
        """
        Get comprehensive user activity report with timeline and statistics.

        Features:
        - Activity timeline with hourly/daily breakdown
        - Action statistics and patterns
        - Risk scoring and anomaly detection
        - Compliance framework mapping

        Args:
            user_id: Target user ID
            days_back: Number of days to look back (max 365)
            include_timeline: Include activity timeline data
            include_statistics: Include activity statistics

        Returns:
            Comprehensive user activity report

        Raises:
            ValidationError: If parameters are invalid
            AuthorizationError: If user lacks required permissions
        """
        try:
            # Validate parameters
            if days_back < 1 or days_back > 365:
                raise ValidationError("Days back must be between 1 and 365")

            # Check permissions for target user
            current_user = info.context.get("current_user")
            target_user_id = UUID(str(user_id))

            # Allow self-access or admin access
            if str(current_user.id) != str(user_id) and not current_user.has_permission(
                "audit.user_activity.read_all"
            ):
                raise AuthorizationError("Cannot access other user's activity")

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )

            # Build query
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)

            activity_query = GetUserActivityQuery(
                user_id=target_user_id,
                start_date=start_date,
                end_date=end_date,
                include_timeline=include_timeline,
                include_statistics=include_statistics,
                include_risk_analysis=True,
            )

            logger.info(
                "Retrieving user activity",
                target_user_id=str(target_user_id),
                requesting_user_id=str(current_user.id),
                days_back=days_back,
            )

            # Execute query
            activity_report = await audit_service.get_user_activity(activity_query)

            # Convert to GraphQL type
            return ReportMapper.activity_report_to_graphql(activity_report)

        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"User activity query failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve user activity")

    @strawberry.field(description="Get audit log with filtering and pagination")
    @require_auth()
    @require_permission("audit.logs.read")
    @rate_limit(requests=50, window=60)
    @audit_log("audit.log_access")
    @batch_size_limit(max_size=1000)
    async def get_audit_log(
        self,
        info: strawberry.Info,
        log_id: strawberry.ID | None = None,
        filters: AuditFilterInput | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> AuditEntryConnection:
        """
        Get audit log entries with comprehensive filtering and pagination.

        Features:
        - Specific log retrieval or filtered browsing
        - Cursor-based pagination for large datasets
        - Performance optimizations for enterprise scale
        - Export-ready result format

        Args:
            log_id: Specific audit log ID (optional)
            filters: Filter criteria for log entries
            page: Page number for pagination
            page_size: Number of entries per page (max 1000)

        Returns:
            Paginated audit log entries with navigation metadata

        Raises:
            ValidationError: If parameters are invalid
        """
        try:
            # Validate pagination
            if page < 1:
                raise ValidationError("Page must be positive")
            if page_size < 1 or page_size > 1000:
                raise ValidationError("Page size must be between 1 and 1000")

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Build query
            if log_id:
                # Get specific log
                query = GetAuditLogQuery(
                    log_id=UUID(str(log_id)),
                    include_entries=True,
                    page=page,
                    page_size=page_size,
                )
            else:
                # Get filtered logs
                criteria = filters.to_criteria_dto() if filters else {}
                criteria["page"] = page
                criteria["page_size"] = page_size

                # Apply permission restrictions
                if not current_user.has_permission("audit.logs.read_all"):
                    criteria["accessible_by_user"] = str(current_user.id)

                query = GetAuditLogQuery(**criteria)

            logger.info(
                "Retrieving audit log",
                user_id=str(current_user.id),
                log_id=str(log_id) if log_id else None,
                page=page,
                page_size=page_size,
            )

            # Execute query
            log_result = await audit_service.get_audit_log(query)

            # Convert to connection format
            return AuditMapper.log_result_to_connection(log_result)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Audit log query failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve audit log")

    @strawberry.field(description="Get audit analytics and metrics for dashboards")
    @require_auth()
    @require_permission("audit.analytics.read")
    @rate_limit(requests=30, window=60)
    @audit_log("audit.analytics")
    @cache_result(ttl=600)  # Cache for 10 minutes
    async def get_audit_analytics(
        self, info: strawberry.Info, input: AnalyticsQueryInput
    ) -> AuditAnalyticsType:
        """
        Get comprehensive audit analytics for dashboards and reporting.

        Features:
        - Activity trends and patterns
        - Risk scoring and anomaly detection
        - Compliance framework metrics
        - Performance statistics
        - User behavior analytics

        Args:
            input: Analytics query parameters and options

        Returns:
            Comprehensive analytics data for visualization

        Raises:
            ValidationError: If query parameters are invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid analytics query: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            # Apply permission restrictions
            criteria = input.to_criteria_dict()
            if not current_user.has_permission("audit.analytics.read_all"):
                criteria["scope_to_user"] = str(current_user.id)

            logger.info(
                "Generating audit analytics",
                user_id=str(current_user.id),
                time_range=input.time_range,
                metrics=input.metrics,
            )

            # Generate analytics
            analytics_result = await reporting_service.generate_analytics(criteria)

            # Convert to GraphQL type
            return ReportMapper.analytics_to_graphql(analytics_result)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Analytics generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate analytics")

    @strawberry.field(
        description="Get audit timeline for specific time range and entities"
    )
    @require_auth()
    @require_permission("audit.timeline.read")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.timeline")
    async def get_audit_timeline(
        self, info: strawberry.Info, input: TimelineQueryInput
    ) -> AuditTimelineType:
        """
        Get audit timeline with chronological activity visualization.

        Features:
        - Chronological event sequencing
        - Entity relationship tracking
        - Activity correlation analysis
        - Interactive timeline data

        Args:
            input: Timeline query parameters

        Returns:
            Timeline data with events and relationships
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid timeline query: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Apply permission restrictions
            criteria = input.to_criteria_dict()
            if not current_user.has_permission("audit.timeline.read_all"):
                criteria["scope_to_user"] = str(current_user.id)

            logger.info(
                "Generating audit timeline",
                user_id=str(current_user.id),
                time_range=f"{input.start_date} to {input.end_date}",
                entities=input.entity_ids,
            )

            # Generate timeline
            timeline_result = await audit_service.generate_timeline(criteria)

            # Convert to GraphQL type
            return ReportMapper.timeline_to_graphql(timeline_result)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Timeline generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate timeline")

    @strawberry.field(description="Get audit entry aggregations for faceted search")
    @require_auth()
    @require_permission("audit.entries.read")
    @rate_limit(requests=50, window=60)
    @cache_result(ttl=300)
    async def get_audit_aggregations(
        self,
        info: strawberry.Info,
        filters: AuditFilterInput | None = None,
        aggregation_fields: list[str] | None = None,
    ) -> list[AuditEntryAggregation]:
        """
        Get audit entry aggregations for faceted search and filtering.

        Features:
        - Field-based aggregations with counts
        - Percentage calculations
        - Support for nested aggregations
        - Optimized for large datasets

        Args:
            filters: Filter criteria for aggregation base
            aggregation_fields: Fields to aggregate on

        Returns:
            List of aggregation results with counts and percentages
        """
        if aggregation_fields is None:
            aggregation_fields = ["category", "severity", "outcome", "resource_type"]
        try:
            # Validate aggregation fields
            valid_fields = [
                "category",
                "severity",
                "outcome",
                "resource_type",
                "action_type",
                "user_id",
                "hour_of_day",
                "day_of_week",
            ]

            invalid_fields = [f for f in aggregation_fields if f not in valid_fields]
            if invalid_fields:
                raise ValidationError(
                    f"Invalid aggregation fields: {', '.join(invalid_fields)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Build criteria
            criteria = filters.to_criteria_dto() if filters else {}
            if not current_user.has_permission("audit.entries.read_all"):
                criteria["accessible_by_user"] = str(current_user.id)

            logger.info(
                "Generating audit aggregations",
                user_id=str(current_user.id),
                fields=aggregation_fields,
            )

            # Generate aggregations
            aggregations = await audit_service.get_aggregations(
                criteria, aggregation_fields
            )

            # Convert to GraphQL types
            return [AuditMapper.aggregation_to_graphql(agg) for agg in aggregations]

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Aggregation generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate aggregations")

    @strawberry.field(description="Export audit data in various formats")
    @require_auth()
    @require_permission("audit.export")
    @rate_limit(requests=5, window=300)  # 5 exports per 5 minutes
    @audit_log("audit.export")
    @operation_timeout(120)  # 2 minute timeout for exports
    async def export_audit_data(
        self, info: strawberry.Info, input: AuditSearchExportInput
    ) -> str:
        """
        Export audit data for compliance reporting and analysis.

        Features:
        - Multiple export formats (JSON, CSV, PDF, XLSX)
        - Large dataset support with streaming
        - Compliance-ready formatting
        - Audit trail of export operations

        Args:
            input: Export criteria and format options

        Returns:
            Export task ID or download URL

        Raises:
            ValidationError: If export parameters are invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid export request: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Apply permission restrictions
            criteria = input.search_criteria.to_criteria_dto()
            if not current_user.has_permission("audit.export.all"):
                criteria["accessible_by_user"] = str(current_user.id)

            logger.info(
                "Starting audit data export",
                user_id=str(current_user.id),
                format=input.export_format,
                max_records=input.max_records,
            )

            # Initiate export (async operation)
            export_task = await audit_service.export_data(
                criteria=criteria,
                format=input.export_format,
                max_records=input.max_records,
                include_related=input.include_related,
                requested_by=current_user.id,
            )

            return export_task.task_id

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Export initiation failed: {e}", exc_info=True)
            raise ValidationError("Failed to initiate export")

    @strawberry.field(description="Get saved searches for current user")
    @require_auth()
    @rate_limit(requests=30, window=60)
    @cache_result(ttl=60)
    async def get_saved_searches(self, info: strawberry.Info) -> list[dict[str, Any]]:
        """
        Get user's saved audit searches.

        Returns:
            List of saved search configurations
        """
        try:
            current_user = info.context.get("current_user")
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )

            saved_searches = await audit_service.get_saved_searches(current_user.id)

            return [
                {
                    "id": search.id,
                    "name": search.name,
                    "description": search.description,
                    "criteria": search.criteria,
                    "is_alert_enabled": search.is_alert_enabled,
                    "created_at": search.created_at.isoformat(),
                }
                for search in saved_searches
            ]

        except Exception as e:
            logger.error(f"Failed to retrieve saved searches: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve saved searches")
