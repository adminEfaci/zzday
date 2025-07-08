"""
Get audit statistics query implementation.

Handles retrieval of comprehensive audit statistics including system-wide metrics,
compliance statistics, user behavior analytics, and security trend analysis.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditRepository,
    IComplianceRepository,
    ISecurityRepository,
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import AuditStatisticsResponse
from app.modules.identity.domain.enums import ComplianceFramework
from app.modules.identity.domain.exceptions import (
    AuditStatisticsError,
    InvalidStatisticsParametersError,
    UnauthorizedAccessError,
)


class StatisticsScope(Enum):
    """Scope of audit statistics to generate."""
    SYSTEM_WIDE = "system_wide"
    DEPARTMENT = "department"
    USER_GROUP = "user_group"
    APPLICATION = "application"
    RESOURCE_TYPE = "resource_type"
    COMPLIANCE_FRAMEWORK = "compliance_framework"


class StatisticsType(Enum):
    """Types of statistics to generate."""
    ACTIVITY_SUMMARY = "activity_summary"
    SECURITY_METRICS = "security_metrics"
    COMPLIANCE_METRICS = "compliance_metrics"
    USER_BEHAVIOR = "user_behavior"
    TREND_ANALYSIS = "trend_analysis"
    RISK_ANALYSIS = "risk_analysis"
    PERFORMANCE_METRICS = "performance_metrics"
    COMPARATIVE_ANALYSIS = "comparative_analysis"


class TimeGranularity(Enum):
    """Time granularity for statistical analysis."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


@dataclass
class GetAuditStatisticsQuery(Query[AuditStatisticsResponse]):
    """Query to retrieve audit statistics."""
    
    # Time range
    start_date: datetime
    end_date: datetime
    requester_id: UUID

    time_granularity: TimeGranularity = TimeGranularity.DAILY
    
    # Scope and filters
    scope: StatisticsScope = StatisticsScope.SYSTEM_WIDE
    statistics_types: list[StatisticsType] | None = None
    
    # Entity filters
    user_ids: list[UUID] | None = None
    department_ids: list[UUID] | None = None
    application_ids: list[str] | None = None
    resource_types: list[str] | None = None
    compliance_frameworks: list[ComplianceFramework] | None = None
    
    # Analysis options
    include_trends: bool = True
    include_comparisons: bool = False
    include_predictions: bool = False
    include_benchmarks: bool = False
    comparison_period: int | None = None  # Days for comparison
    
    # Aggregation options
    group_by_user: bool = False
    group_by_department: bool = False
    group_by_application: bool = False
    group_by_risk_level: bool = False
    
    # Output options
    include_charts: bool = False
    include_raw_data: bool = False
    export_format: str | None = None
    
    # Performance options
    use_cached_data: bool = True
    cache_duration_hours: int = 1
    
    # Access control
    requester_permissions: list[str] = field(default_factory=list)


class GetAuditStatisticsQueryHandler(QueryHandler[GetAuditStatisticsQuery, AuditStatisticsResponse]):
    """Handler for audit statistics queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        security_repository: ISecurityRepository,
        compliance_repository: IComplianceRepository
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.security_repository = security_repository
        self.compliance_repository = compliance_repository
    
    @rate_limit(max_calls=20, window_seconds=3600)
    @require_permission("audit.statistics.read")
    @validate_request
    async def handle(self, query: GetAuditStatisticsQuery) -> AuditStatisticsResponse:
        """Handle audit statistics query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_statistics_access(query)
                
                # Validate and normalize time range
                await self._validate_time_range(query)
                
                # Check for cached data if enabled
                cached_result = None
                if query.use_cached_data:
                    cached_result = await self._get_cached_statistics(query)
                    if cached_result:
                        return cached_result
                
                # Initialize statistics types if not specified
                if not query.statistics_types:
                    query.statistics_types = [
                        StatisticsType.ACTIVITY_SUMMARY,
                        StatisticsType.SECURITY_METRICS,
                        StatisticsType.USER_BEHAVIOR
                    ]
                
                # Generate requested statistics
                statistics = {}
                
                if StatisticsType.ACTIVITY_SUMMARY in query.statistics_types:
                    statistics["activity_summary"] = await self._generate_activity_summary(query)
                
                if StatisticsType.SECURITY_METRICS in query.statistics_types:
                    statistics["security_metrics"] = await self._generate_security_metrics(query)
                
                if StatisticsType.COMPLIANCE_METRICS in query.statistics_types:
                    statistics["compliance_metrics"] = await self._generate_compliance_metrics(query)
                
                if StatisticsType.USER_BEHAVIOR in query.statistics_types:
                    statistics["user_behavior"] = await self._generate_user_behavior_statistics(query)
                
                if StatisticsType.TREND_ANALYSIS in query.statistics_types:
                    statistics["trend_analysis"] = await self._generate_trend_analysis(query)
                
                if StatisticsType.RISK_ANALYSIS in query.statistics_types:
                    statistics["risk_analysis"] = await self._generate_risk_analysis(query)
                
                if StatisticsType.PERFORMANCE_METRICS in query.statistics_types:
                    statistics["performance_metrics"] = await self._generate_performance_metrics(query)
                
                if StatisticsType.COMPARATIVE_ANALYSIS in query.statistics_types:
                    statistics["comparative_analysis"] = await self._generate_comparative_analysis(query)
                
                # Generate time series data
                time_series = await self._generate_time_series_data(query)
                
                # Generate comparison data if requested
                comparison_data = None
                if query.include_comparisons and query.comparison_period:
                    comparison_data = await self._generate_comparison_data(query)
                
                # Generate predictions if requested
                predictions = None
                if query.include_predictions:
                    predictions = await self._generate_predictions(query, time_series)
                
                # Generate benchmarks if requested
                benchmarks = None
                if query.include_benchmarks:
                    benchmarks = await self._generate_benchmarks(query)
                
                # Generate charts if requested
                charts = None
                if query.include_charts:
                    charts = await self._generate_charts(query, statistics, time_series)
                
                # Include raw data if requested
                raw_data = None
                if query.include_raw_data:
                    raw_data = await self._get_raw_data(query)
                
                # Generate summary insights
                insights = await self._generate_insights(statistics, time_series)
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        statistics, time_series, query.export_format
                    )
                
                result = AuditStatisticsResponse(
                    time_range={
                        "start_date": query.start_date,
                        "end_date": query.end_date,
                        "granularity": query.time_granularity.value,
                        "duration_days": (query.end_date - query.start_date).days
                    },
                    scope=query.scope.value,
                    statistics=statistics,
                    time_series=time_series,
                    comparison_data=comparison_data,
                    predictions=predictions,
                    benchmarks=benchmarks,
                    insights=insights,
                    charts=charts,
                    raw_data=raw_data,
                    export_data=export_data,
                    generated_at=datetime.now(UTC),
                    cache_info={
                        "cached": False,
                        "cache_duration_hours": query.cache_duration_hours
                    }
                )
                
                # Cache the result if enabled
                if query.use_cached_data:
                    await self._cache_statistics(query, result)
                
                return result
                
        except Exception as e:
            raise AuditStatisticsError(f"Failed to generate audit statistics: {e!s}") from e
    
    async def _validate_statistics_access(self, query: GetAuditStatisticsQuery) -> None:
        """Validate user has appropriate permissions for statistics access."""
        
        # Check basic statistics read permission
        if "audit.statistics.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for audit statistics")
        
        # Check scope-specific permissions
        if query.scope == StatisticsScope.SYSTEM_WIDE:
            if "audit.statistics.system_wide" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for system-wide statistics")
        
        # Check compliance statistics access
        if (StatisticsType.COMPLIANCE_METRICS in (query.statistics_types or []) or
            query.compliance_frameworks):
            if "compliance.statistics" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for compliance statistics")
        
        # Check advanced analytics permissions
        advanced_features = [
            query.include_predictions,
            query.include_benchmarks,
            StatisticsType.RISK_ANALYSIS in (query.statistics_types or [])
        ]
        
        if any(advanced_features):
            if "audit.advanced_analytics" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for advanced analytics")
    
    async def _validate_time_range(self, query: GetAuditStatisticsQuery) -> None:
        """Validate and normalize time range parameters."""
        
        if query.start_date >= query.end_date:
            raise InvalidStatisticsParametersError("Start date must be before end date")
        
        # Limit maximum time range based on granularity
        max_days_by_granularity = {
            TimeGranularity.HOURLY: 7,
            TimeGranularity.DAILY: 90,
            TimeGranularity.WEEKLY: 365,
            TimeGranularity.MONTHLY: 1095,  # 3 years
            TimeGranularity.QUARTERLY: 2190,  # 6 years
            TimeGranularity.YEARLY: 3650  # 10 years
        }
        
        max_days = max_days_by_granularity.get(query.time_granularity, 90)
        actual_days = (query.end_date - query.start_date).days
        
        if actual_days > max_days:
            raise InvalidStatisticsParametersError(
                f"Time range of {actual_days} days exceeds maximum of {max_days} days for {query.time_granularity.value} granularity"
            )
    
    async def _generate_activity_summary(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate activity summary statistics."""
        
        # Get basic activity counts
        total_activities = await self.audit_repository.count_activities(
            query.start_date, query.end_date
        )
        
        # Get activity breakdown by type
        activity_breakdown = await self.audit_repository.get_activity_breakdown_by_type(
            query.start_date, query.end_date
        )
        
        # Get user activity statistics
        user_activity_stats = await self.audit_repository.get_user_activity_statistics(
            query.start_date, query.end_date
        )
        
        # Get resource access statistics
        resource_stats = await self.audit_repository.get_resource_access_statistics(
            query.start_date, query.end_date
        )
        
        # Calculate daily averages
        days = max((query.end_date - query.start_date).days, 1)
        daily_average = total_activities / days
        
        return {
            "total_activities": total_activities,
            "daily_average": daily_average,
            "activity_breakdown": activity_breakdown,
            "unique_users_active": user_activity_stats.get("unique_users", 0),
            "total_sessions": user_activity_stats.get("total_sessions", 0),
            "unique_resources_accessed": resource_stats.get("unique_resources", 0),
            "top_activities": await self._get_top_activities(query),
            "peak_activity_hours": await self._get_peak_activity_hours(query)
        }
    
    async def _generate_security_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate security-related metrics."""
        
        # Get security events
        security_events = await self.security_repository.get_security_events_statistics(
            query.start_date, query.end_date
        )
        
        # Get failed authentication attempts
        failed_auth = await self.audit_repository.count_failed_authentications(
            query.start_date, query.end_date
        )
        
        # Get privilege escalation events
        privilege_escalations = await self.audit_repository.count_privilege_escalations(
            query.start_date, query.end_date
        )
        
        # Get suspicious activities
        suspicious_activities = await self.security_repository.count_suspicious_activities(
            query.start_date, query.end_date
        )
        
        # Get risk distribution
        risk_distribution = await self.security_repository.get_risk_distribution(
            query.start_date, query.end_date
        )
        
        return {
            "total_security_events": security_events.get("total", 0),
            "security_event_breakdown": security_events.get("breakdown", {}),
            "failed_authentication_attempts": failed_auth,
            "privilege_escalation_events": privilege_escalations,
            "suspicious_activities": suspicious_activities,
            "risk_distribution": risk_distribution,
            "security_incidents_created": await self._count_security_incidents(query),
            "threat_detection_alerts": await self._count_threat_alerts(query)
        }
    
    async def _generate_compliance_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate compliance-related metrics."""
        
        compliance_metrics = {}
        
        # If specific frameworks are requested, analyze them
        frameworks = query.compliance_frameworks or [
            ComplianceFramework.GDPR,
            ComplianceFramework.HIPAA,
            ComplianceFramework.SOX
        ]
        
        for framework in frameworks:
            framework_metrics = await self.compliance_repository.get_compliance_metrics(
                framework, query.start_date, query.end_date
            )
            compliance_metrics[framework.value] = framework_metrics
        
        # Get overall compliance statistics
        compliance_violations = await self.compliance_repository.count_violations(
            query.start_date, query.end_date
        )
        
        compliance_audits = await self.compliance_repository.count_audits(
            query.start_date, query.end_date
        )
        
        return {
            "framework_metrics": compliance_metrics,
            "total_compliance_violations": compliance_violations,
            "compliance_audits_performed": compliance_audits,
            "data_retention_compliance": await self._check_data_retention_compliance(query),
            "access_review_compliance": await self._check_access_review_compliance(query)
        }
    
    async def _generate_user_behavior_statistics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate user behavior statistics."""
        
        # Get login patterns
        login_patterns = await self.audit_repository.get_login_patterns(
            query.start_date, query.end_date
        )
        
        # Get session statistics
        session_stats = await self.session_repository.get_session_statistics(
            query.start_date, query.end_date
        )
        
        # Get user activity patterns
        activity_patterns = await self.audit_repository.get_user_activity_patterns(
            query.start_date, query.end_date
        )
        
        # Get location analysis
        location_analysis = await self.audit_repository.get_location_analysis(
            query.start_date, query.end_date
        )
        
        return {
            "login_patterns": login_patterns,
            "session_statistics": session_stats,
            "activity_patterns": activity_patterns,
            "location_analysis": location_analysis,
            "device_usage_patterns": await self._analyze_device_usage_patterns(query),
            "time_of_day_analysis": await self._analyze_time_of_day_patterns(query)
        }
    
    async def _generate_trend_analysis(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate trend analysis."""
        
        # Get activity trends
        activity_trends = await self.audit_repository.get_activity_trends(
            query.start_date, query.end_date, query.time_granularity
        )
        
        # Get security trends
        security_trends = await self.security_repository.get_security_trends(
            query.start_date, query.end_date, query.time_granularity
        )
        
        # Get user engagement trends
        user_trends = await self.user_repository.get_user_engagement_trends(
            query.start_date, query.end_date, query.time_granularity
        )
        
        return {
            "activity_trends": activity_trends,
            "security_trends": security_trends,
            "user_engagement_trends": user_trends,
            "growth_metrics": await self._calculate_growth_metrics(query),
            "seasonal_patterns": await self._identify_seasonal_patterns(query)
        }
    
    async def _generate_risk_analysis(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate risk analysis statistics."""
        
        # Get risk distribution
        risk_distribution = await self.security_repository.get_detailed_risk_distribution(
            query.start_date, query.end_date
        )
        
        # Get risk trends
        risk_trends = await self.security_repository.get_risk_trends(
            query.start_date, query.end_date, query.time_granularity
        )
        
        # Get top risk factors
        top_risk_factors = await self.security_repository.get_top_risk_factors(
            query.start_date, query.end_date
        )
        
        return {
            "risk_distribution": risk_distribution,
            "risk_trends": risk_trends,
            "top_risk_factors": top_risk_factors,
            "risk_mitigation_effectiveness": await self._analyze_risk_mitigation(query),
            "emerging_risks": await self._identify_emerging_risks(query)
        }
    
    async def _generate_performance_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate performance-related metrics."""
        
        # Get system performance metrics
        system_metrics = await self.audit_repository.get_system_performance_metrics(
            query.start_date, query.end_date
        )
        
        # Get audit performance metrics
        audit_metrics = await self.audit_repository.get_audit_performance_metrics(
            query.start_date, query.end_date
        )
        
        return {
            "system_performance": system_metrics,
            "audit_performance": audit_metrics,
            "data_processing_metrics": await self._get_data_processing_metrics(query),
            "storage_metrics": await self._get_storage_metrics(query)
        }
    
    async def _generate_comparative_analysis(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate comparative analysis."""
        
        if not query.comparison_period:
            return {}
        
        # Calculate comparison period
        comparison_start = query.start_date - timedelta(days=query.comparison_period)
        comparison_end = query.start_date
        
        # Get current period data
        current_data = await self.audit_repository.get_summary_statistics(
            query.start_date, query.end_date
        )
        
        # Get comparison period data
        comparison_data = await self.audit_repository.get_summary_statistics(
            comparison_start, comparison_end
        )
        
        # Calculate changes
        changes = {}
        for key in current_data:
            if key in comparison_data:
                current_val = current_data[key]
                comparison_val = comparison_data[key]
                if comparison_val > 0:
                    change_pct = ((current_val - comparison_val) / comparison_val) * 100
                    changes[key] = {
                        "current": current_val,
                        "previous": comparison_val,
                        "change_percentage": change_pct,
                        "change_direction": "increase" if change_pct > 0 else "decrease"
                    }
        
        return {
            "comparison_period": {
                "start": comparison_start,
                "end": comparison_end,
                "duration_days": query.comparison_period
            },
            "changes": changes,
            "significant_changes": await self._identify_significant_changes(changes)
        }
    
    async def _generate_time_series_data(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate time series data based on granularity."""
        
        time_series = await self.audit_repository.get_time_series_data(
            query.start_date, query.end_date, query.time_granularity
        )
        
        return {
            "granularity": query.time_granularity.value,
            "data_points": time_series,
            "interpolated": await self._interpolate_missing_points(time_series),
            "smoothed": await self._apply_smoothing(time_series)
        }
    
    # Helper methods (placeholder implementations)
    async def _get_cached_statistics(self, query: GetAuditStatisticsQuery) -> AuditStatisticsResponse | None:
        """Get cached statistics if available."""
        return None
    
    async def _cache_statistics(self, query: GetAuditStatisticsQuery, result: AuditStatisticsResponse) -> None:
        """Cache statistics result."""
    
    async def _generate_comparison_data(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate comparison data for the specified period."""
        return {}
    
    async def _generate_predictions(self, query: GetAuditStatisticsQuery, time_series: dict[str, Any]) -> dict[str, Any]:
        """Generate predictions based on historical data."""
        return {"forecast_days": 7, "predicted_activities": 1000}
    
    async def _generate_benchmarks(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Generate benchmark comparisons."""
        return {"industry_average": 500, "percentile": 75}
    
    async def _generate_charts(self, query: GetAuditStatisticsQuery, statistics: dict[str, Any], time_series: dict[str, Any]) -> dict[str, Any]:
        """Generate chart data."""
        return {"chart_type": "line", "data_url": "/charts/audit_statistics"}
    
    async def _get_raw_data(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        """Get raw data if requested."""
        return {"raw_events": 100, "data_size_mb": 2.5}
    
    async def _generate_insights(self, statistics: dict[str, Any], time_series: dict[str, Any]) -> list[str]:
        """Generate insights from the statistics."""
        return [
            "Activity levels are within normal range",
            "Security events have decreased by 15%",
            "User engagement is trending upward"
        ]
    
    async def _prepare_export_data(self, statistics: dict[str, Any], time_series: dict[str, Any], export_format: str) -> dict[str, Any]:
        """Prepare statistics for export."""
        return {
            "format": export_format,
            "content": f"Audit statistics in {export_format} format",
            "filename": f"audit_statistics_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}"
        }
    
    # Additional placeholder methods
    async def _get_top_activities(self, query: GetAuditStatisticsQuery) -> list[dict[str, Any]]:
        return [{"activity": "login", "count": 500}, {"activity": "data_access", "count": 300}]
    
    async def _get_peak_activity_hours(self, query: GetAuditStatisticsQuery) -> list[int]:
        return [9, 10, 14, 15]
    
    async def _count_security_incidents(self, query: GetAuditStatisticsQuery) -> int:
        return 5
    
    async def _count_threat_alerts(self, query: GetAuditStatisticsQuery) -> int:
        return 25
    
    async def _check_data_retention_compliance(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"compliant": True, "violations": 0}
    
    async def _check_access_review_compliance(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"compliant": True, "overdue_reviews": 2}
    
    async def _analyze_device_usage_patterns(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"mobile": 40, "desktop": 60}
    
    async def _analyze_time_of_day_patterns(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"peak_hours": [9, 10, 14, 15], "low_hours": [22, 23, 0, 1]}
    
    async def _calculate_growth_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"user_growth": 5.2, "activity_growth": 8.1}
    
    async def _identify_seasonal_patterns(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"patterns": ["increased_activity_weekdays", "decreased_activity_holidays"]}
    
    async def _analyze_risk_mitigation(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"effectiveness": 85.5, "improvements": ["enhanced_monitoring"]}
    
    async def _identify_emerging_risks(self, query: GetAuditStatisticsQuery) -> list[str]:
        return ["credential_stuffing_increase", "unusual_access_patterns"]
    
    async def _get_data_processing_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"processing_time_ms": 250, "throughput": 1000}
    
    async def _get_storage_metrics(self, query: GetAuditStatisticsQuery) -> dict[str, Any]:
        return {"storage_used_gb": 125.5, "growth_rate": 2.3}
    
    async def _identify_significant_changes(self, changes: dict[str, Any]) -> list[str]:
        return ["login_failures_increased", "data_access_decreased"]
    
    async def _interpolate_missing_points(self, time_series: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return time_series
    
    async def _apply_smoothing(self, time_series: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return time_series