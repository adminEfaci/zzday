"""
Comprehensive Report Queries GraphQL Resolver

This module provides specialized audit reporting queries with enterprise-grade features:
- Compliance reporting and framework mapping
- Trend analysis and pattern detection
- Executive dashboards and summaries
- Detailed forensic reporting
- Performance analytics

Features:
- Multi-format report generation (PDF, Excel, JSON)
- Scheduled and on-demand reporting
- Compliance framework integration
- Advanced analytics and visualizations
- Export capabilities for compliance teams

Security:
- Authentication and authorization required
- Role-based access to sensitive reports
- Audit logging of all report operations
- Data filtering based on user permissions
"""

from typing import Any
from uuid import UUID

import strawberry

# Core imports
from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.queries.get_audit_report_query import (
    GetAuditReportQuery,
)
from app.modules.audit.application.queries.get_compliance_report_query import (
    GetComplianceReportQuery,
)
from app.modules.audit.application.services.compliance_service import ComplianceService

# Audit domain imports
from app.modules.audit.application.services.reporting_service import ReportingService
from app.modules.audit.presentation.graphql.schemas.inputs.report_inputs import (
    ComplianceReportInput,
    ExecutiveSummaryInput,
    PerformanceReportInput,
    TrendAnalysisInput,
)
from app.modules.audit.presentation.graphql.schemas.types.analytics_type import (
    ReportAnalyticsType,
    TrendAnalysisType,
)

# GraphQL types and inputs
from app.modules.audit.presentation.graphql.schemas.types.audit_report_type import (
    AuditReportType,
    ExecutiveSummaryType,
)
from app.modules.audit.presentation.graphql.schemas.types.compliance_type import (
    ComplianceFrameworkStatusType,
    ComplianceReportType,
)

# Mappers
from app.modules.audit.presentation.mappers.report_mapper import ReportMapper

# Identity imports for authentication
from app.modules.identity.presentation.graphql.decorators import (
    audit_log,
    cache_result,
    operation_timeout,
    rate_limit,
    require_auth,
    require_permission,
)

logger = get_logger(__name__)


@strawberry.type
class ReportQueries:
    """
    Specialized reporting queries for audit compliance and analytics.

    Provides comprehensive reporting capabilities for compliance teams,
    executives, and audit professionals with advanced analytics and
    visualization support.
    """

    @strawberry.field(description="Get comprehensive audit report by ID")
    @require_auth()
    @require_permission("audit.reports.read")
    @rate_limit(requests=50, window=60)
    @audit_log("audit.report.access")
    @cache_result(ttl=300)
    async def get_audit_report(
        self,
        info: strawberry.Info,
        report_id: strawberry.ID,
        include_details: bool = True,
        include_statistics: bool = True,
    ) -> AuditReportType:
        """
        Get detailed audit report by ID.

        Features:
        - Full report metadata and content
        - Statistical summaries and charts
        - Export format options
        - Compliance framework mapping

        Args:
            report_id: Unique report identifier
            include_details: Include detailed report content
            include_statistics: Include statistical analysis

        Returns:
            Comprehensive audit report with metadata

        Raises:
            ValidationError: If report ID is invalid
            AuthorizationError: If user lacks access to report
        """
        try:
            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            # Build query
            query = GetAuditReportQuery(
                report_id=UUID(str(report_id)),
                include_content=include_details,
                include_statistics=include_statistics,
                requested_by=current_user.id,
            )

            logger.info(
                "Retrieving audit report",
                user_id=str(current_user.id),
                report_id=str(report_id),
                include_details=include_details,
            )

            # Execute query with permission check
            report = await reporting_service.get_report(query)

            # Check access permissions
            if not self._can_access_report(current_user, report):
                raise AuthorizationError("Access denied to this report")

            # Convert to GraphQL type
            return ReportMapper.domain_to_graphql(report)

        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Report retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve report")

    @strawberry.field(description="Get compliance report with framework analysis")
    @require_auth()
    @require_permission("audit.compliance.reports.read")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.compliance.report")
    @operation_timeout(60)
    async def get_compliance_report(
        self, info: strawberry.Info, input: ComplianceReportInput
    ) -> ComplianceReportType:
        """
        Generate comprehensive compliance report.

        Features:
        - Multi-framework compliance analysis
        - Violation detection and categorization
        - Risk assessment and scoring
        - Remediation recommendations
        - Executive summary generation

        Args:
            input: Compliance report parameters

        Returns:
            Detailed compliance report with violations and recommendations

        Raises:
            ValidationError: If input parameters are invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid compliance report input: {'; '.join(validation_errors)}"
                )

            # Get compliance service
            compliance_service: ComplianceService = info.context["container"].resolve(
                ComplianceService
            )
            current_user = info.context.get("current_user")

            # Build query
            query = GetComplianceReportQuery(
                frameworks=input.frameworks,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                include_violations=input.include_violations,
                include_recommendations=input.include_recommendations,
                include_risk_assessment=input.include_risk_assessment,
                scope=input.scope,
                requested_by=current_user.id,
            )

            logger.info(
                "Generating compliance report",
                user_id=str(current_user.id),
                frameworks=input.frameworks,
                date_range=f"{input.date_range.start_date} to {input.date_range.end_date}",
            )

            # Execute query
            compliance_report = await compliance_service.generate_compliance_report(
                query
            )

            # Convert to GraphQL type
            return ReportMapper.compliance_report_to_graphql(compliance_report)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Compliance report generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate compliance report")

    @strawberry.field(description="Get executive summary dashboard")
    @require_auth()
    @require_permission("audit.reports.executive")
    @rate_limit(requests=10, window=60)
    @audit_log("audit.executive.summary")
    @cache_result(ttl=1800)  # Cache for 30 minutes
    async def get_executive_summary(
        self, info: strawberry.Info, input: ExecutiveSummaryInput
    ) -> ExecutiveSummaryType:
        """
        Generate executive summary dashboard for leadership.

        Features:
        - High-level security and compliance metrics
        - Trend analysis and risk indicators
        - Key performance indicators (KPIs)
        - Executive-friendly visualizations
        - Action item priorities

        Args:
            input: Executive summary parameters

        Returns:
            Executive dashboard with key metrics and trends
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid executive summary input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Generating executive summary",
                user_id=str(current_user.id),
                time_period=input.time_period,
                include_trends=input.include_trends,
            )

            # Generate executive summary
            summary = await reporting_service.generate_executive_summary(
                time_period=input.time_period,
                include_trends=input.include_trends,
                include_compliance_status=input.include_compliance_status,
                include_risk_metrics=input.include_risk_metrics,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.executive_summary_to_graphql(summary)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate executive summary")

    @strawberry.field(description="Get audit trend analysis")
    @require_auth()
    @require_permission("audit.analytics.trends.read")
    @rate_limit(requests=30, window=60)
    @audit_log("audit.trend.analysis")
    @cache_result(ttl=600)
    async def get_trend_analysis(
        self, info: strawberry.Info, input: TrendAnalysisInput
    ) -> TrendAnalysisType:
        """
        Generate comprehensive trend analysis for audit data.

        Features:
        - Time-series trend analysis
        - Seasonal pattern detection
        - Anomaly identification
        - Predictive analytics
        - Comparative analysis

        Args:
            input: Trend analysis parameters

        Returns:
            Detailed trend analysis with patterns and predictions
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid trend analysis input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Generating trend analysis",
                user_id=str(current_user.id),
                metrics=input.metrics,
                time_granularity=input.time_granularity,
            )

            # Generate trend analysis
            trends = await reporting_service.analyze_trends(
                metrics=input.metrics,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                time_granularity=input.time_granularity,
                include_predictions=input.include_predictions,
                include_anomalies=input.include_anomalies,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.trend_analysis_to_graphql(trends)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Trend analysis failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate trend analysis")

    @strawberry.field(description="Get performance report for audit system")
    @require_auth()
    @require_permission("audit.reports.performance")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.performance.report")
    async def get_performance_report(
        self, info: strawberry.Info, input: PerformanceReportInput
    ) -> ReportAnalyticsType:
        """
        Generate performance report for audit system monitoring.

        Features:
        - System performance metrics
        - Query performance analysis
        - Storage utilization reports
        - Processing time trends
        - Capacity planning insights

        Args:
            input: Performance report parameters

        Returns:
            Comprehensive performance analytics report
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid performance report input: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Generating performance report",
                user_id=str(current_user.id),
                metrics=input.metrics,
                include_recommendations=input.include_recommendations,
            )

            # Generate performance report
            performance_data = await reporting_service.generate_performance_report(
                metrics=input.metrics,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                include_trends=input.include_trends,
                include_recommendations=input.include_recommendations,
                requested_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.performance_report_to_graphql(performance_data)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Performance report generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate performance report")

    @strawberry.field(description="Get available report templates")
    @require_auth()
    @require_permission("audit.reports.read")
    @rate_limit(requests=50, window=60)
    @cache_result(ttl=3600)  # Cache for 1 hour
    async def get_report_templates(
        self, info: strawberry.Info, category: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Get available report templates for generation.

        Features:
        - Categorized template listing
        - Template metadata and descriptions
        - Parameter requirements
        - Access control information

        Args:
            category: Optional category filter

        Returns:
            List of available report templates
        """
        try:
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Retrieving report templates",
                user_id=str(current_user.id),
                category=category,
            )

            # Get available templates
            templates = await reporting_service.get_available_templates(
                category=category, user_permissions=current_user.permissions
            )

            return [
                {
                    "id": template.id,
                    "name": template.name,
                    "description": template.description,
                    "category": template.category,
                    "parameters": template.parameters,
                    "output_formats": template.output_formats,
                    "requires_permissions": template.required_permissions,
                }
                for template in templates
            ]

        except Exception as e:
            logger.error(f"Template retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve templates")

    @strawberry.field(description="Get scheduled reports for current user")
    @require_auth()
    @require_permission("audit.reports.scheduled.read")
    @rate_limit(requests=30, window=60)
    @cache_result(ttl=300)
    async def get_scheduled_reports(
        self, info: strawberry.Info, include_inactive: bool = False
    ) -> list[dict[str, Any]]:
        """
        Get scheduled reports accessible to current user.

        Features:
        - User-specific scheduled reports
        - Schedule status and next run times
        - Report generation history
        - Management capabilities

        Args:
            include_inactive: Include inactive/disabled schedules

        Returns:
            List of scheduled report configurations
        """
        try:
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Retrieving scheduled reports",
                user_id=str(current_user.id),
                include_inactive=include_inactive,
            )

            # Get scheduled reports
            schedules = await reporting_service.get_user_scheduled_reports(
                user_id=current_user.id, include_inactive=include_inactive
            )

            return [
                {
                    "id": str(schedule.id),
                    "name": schedule.name,
                    "description": schedule.description,
                    "frequency": schedule.frequency,
                    "next_run": schedule.next_run.isoformat()
                    if schedule.next_run
                    else None,
                    "last_run": schedule.last_run.isoformat()
                    if schedule.last_run
                    else None,
                    "enabled": schedule.enabled,
                    "report_config": schedule.report_config,
                    "recipients": schedule.recipients,
                }
                for schedule in schedules
            ]

        except Exception as e:
            logger.error(f"Scheduled reports retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve scheduled reports")

    @strawberry.field(description="Get compliance framework status overview")
    @require_auth()
    @require_permission("audit.compliance.status.read")
    @rate_limit(requests=20, window=60)
    @audit_log("audit.compliance.status")
    @cache_result(ttl=900)  # Cache for 15 minutes
    async def get_compliance_framework_status(
        self, info: strawberry.Info, frameworks: list[str] | None = None
    ) -> list[ComplianceFrameworkStatusType]:
        """
        Get current compliance status for all or specific frameworks.

        Features:
        - Framework compliance percentages
        - Recent violation summaries
        - Risk level assessments
        - Trend indicators

        Args:
            frameworks: Optional list of specific frameworks

        Returns:
            Compliance status for each framework
        """
        try:
            compliance_service: ComplianceService = info.context["container"].resolve(
                ComplianceService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Retrieving compliance framework status",
                user_id=str(current_user.id),
                frameworks=frameworks,
            )

            # Get compliance status
            status_data = await compliance_service.get_framework_status(
                frameworks=frameworks, requested_by=current_user.id
            )

            # Convert to GraphQL types
            return [
                ReportMapper.compliance_status_to_graphql(status)
                for status in status_data
            ]

        except Exception as e:
            logger.error(f"Compliance status retrieval failed: {e}", exc_info=True)
            raise ValidationError("Failed to retrieve compliance status")

    # Helper methods
    def _can_access_report(self, user, report) -> bool:
        """Check if user can access the specific report."""
        # Admin can access all reports
        if user.has_permission("audit.reports.read_all"):
            return True

        # Users can access their own reports
        if report.generated_by == user.id:
            return True

        # Users can access public reports
        if getattr(report, "is_public", False):
            return True

        # Check if user has access through team/department
        if hasattr(report, "accessible_by_teams"):
            user_teams = getattr(user, "teams", [])
            if any(team in report.accessible_by_teams for team in user_teams):
                return True

        return False
