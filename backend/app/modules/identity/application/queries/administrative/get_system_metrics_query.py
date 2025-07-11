"""Get system metrics query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SystemMetricsResponse
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.security_event_repository import (
    ISecurityRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


class MetricGranularity(Enum):
    """Metric time granularity."""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


@dataclass
class GetSystemMetricsQuery(Query[SystemMetricsResponse]):
    """Query to get system metrics."""

    requester_permissions: list[str] = field(default_factory=list)
    metric_types: list[str] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    granularity: MetricGranularity = MetricGranularity.HOUR
    include_predictions: bool = False



class GetSystemMetricsQueryHandler(QueryHandler[GetSystemMetricsQuery, SystemMetricsResponse]):
    """Handler for system metrics queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        audit_repository: IAuditRepository,
        security_repository: ISecurityRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.audit_repository = audit_repository
        self.security_repository = security_repository
    
    @rate_limit(max_calls=50, window_seconds=300)
    @require_permission("admin.metrics.read")
    @validate_request
    async def handle(self, query: GetSystemMetricsQuery) -> SystemMetricsResponse:
        """Handle system metrics query."""
        
        async with self.uow:
            # Set default date range if not provided
            if not query.end_date:
                query.end_date = datetime.now(UTC)
            if not query.start_date:
                query.start_date = query.end_date - timedelta(days=7)
            
            # Determine which metrics to collect
            requested_metrics = query.metric_types or [
                "users", "sessions", "authentication", "security", "performance"
            ]
            
            metrics = {}
            
            # User metrics
            if "users" in requested_metrics:
                metrics["users"] = await self._collect_user_metrics(
                    query.start_date,
                    query.end_date,
                    query.granularity
                )
            
            # Session metrics
            if "sessions" in requested_metrics:
                metrics["sessions"] = await self._collect_session_metrics(
                    query.start_date,
                    query.end_date,
                    query.granularity
                )
            
            # Authentication metrics
            if "authentication" in requested_metrics:
                metrics["authentication"] = await self._collect_auth_metrics(
                    query.start_date,
                    query.end_date,
                    query.granularity
                )
            
            # Security metrics
            if "security" in requested_metrics:
                metrics["security"] = await self._collect_security_metrics(
                    query.start_date,
                    query.end_date,
                    query.granularity
                )
            
            # Performance metrics
            if "performance" in requested_metrics:
                metrics["performance"] = await self._collect_performance_metrics(
                    query.start_date,
                    query.end_date,
                    query.granularity
                )
            
            # Generate predictions if requested
            predictions = {}
            if query.include_predictions:
                predictions = self._generate_predictions(metrics)
            
            # Calculate summary statistics
            summary = self._calculate_summary(metrics)
            
            return SystemMetricsResponse(
                metrics=metrics,
                summary=summary,
                predictions=predictions,
                start_date=query.start_date,
                end_date=query.end_date,
                granularity=query.granularity.value,
                retrieved_at=datetime.now(UTC)
            )
    
    async def _collect_user_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: MetricGranularity
    ) -> dict[str, Any]:
        """Collect user-related metrics."""
        # Total users
        total_users = await self.user_repository.count_users({})
        active_users = await self.user_repository.count_active_users()
        
        # User growth
        new_users = await self.user_repository.count_users({
            "created_at__gte": start_date,
            "created_at__lte": end_date
        })
        
        # User engagement trends
        engagement_data = await self.user_repository.get_user_engagement_trends(
            start_date,
            end_date,
            granularity.value
        )
        
        return {
            "total": total_users,
            "active": active_users,
            "new": new_users,
            "growth_rate": (new_users / total_users * 100) if total_users > 0 else 0,
            "engagement_trend": engagement_data,
            "churn_rate": self._calculate_churn_rate(total_users, active_users)
        }
    
    async def _collect_session_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: MetricGranularity
    ) -> dict[str, Any]:
        """Collect session-related metrics."""
        # Session statistics
        session_stats = await self.session_repository.get_session_statistics(
            start_date,
            end_date
        )
        
        # Active sessions
        active_sessions = await self.session_repository.count_user_sessions(
            user_id=None,
            active_only=True
        )
        
        return {
            "active": active_sessions,
            "total_created": session_stats.get("total_created", 0),
            "average_duration_minutes": session_stats.get("avg_duration_minutes", 0),
            "unique_users": session_stats.get("unique_users", 0),
            "sessions_per_user": session_stats.get("avg_sessions_per_user", 0),
            "peak_concurrent": session_stats.get("peak_concurrent", 0),
            "device_breakdown": session_stats.get("device_types", {})
        }
    
    async def _collect_auth_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: MetricGranularity
    ) -> dict[str, Any]:
        """Collect authentication metrics."""
        # Login statistics
        total_logins = await self.audit_repository.count_activities(start_date, end_date)
        failed_logins = await self.audit_repository.count_failed_authentications(
            start_date,
            end_date
        )
        
        # Authentication methods breakdown
        activity_breakdown = await self.audit_repository.get_activity_breakdown_by_type(
            start_date,
            end_date
        )
        
        # Login patterns
        login_patterns = await self.audit_repository.get_login_patterns(
            start_date,
            end_date
        )
        
        return {
            "total_attempts": total_logins,
            "successful": total_logins - failed_logins,
            "failed": failed_logins,
            "success_rate": ((total_logins - failed_logins) / total_logins * 100) if total_logins > 0 else 0,
            "methods_used": activity_breakdown,
            "peak_hours": login_patterns.get("peak_hours", []),
            "geographic_distribution": login_patterns.get("geographic", {})
        }
    
    async def _collect_security_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: MetricGranularity
    ) -> dict[str, Any]:
        """Collect security metrics."""
        # Security events
        security_stats = await self.security_repository.get_security_events_statistics(
            start_date,
            end_date
        )
        
        # Risk assessment
        risk_distribution = await self.security_repository.get_detailed_risk_distribution(
            start_date,
            end_date
        )
        
        # Suspicious activities
        suspicious_count = await self.security_repository.count_suspicious_activities(
            start_date,
            end_date
        )
        
        # Policy violations
        violations = await self.security_repository.get_policy_violations(
            start_date,
            end_date
        )
        
        return {
            "total_events": security_stats.get("total", 0),
            "suspicious_activities": suspicious_count,
            "blocked_attempts": security_stats.get("blocked", 0),
            "risk_distribution": risk_distribution,
            "policy_violations": len(violations),
            "threat_level": self._calculate_threat_level(security_stats),
            "top_threats": security_stats.get("top_threats", [])
        }
    
    async def _collect_performance_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: MetricGranularity
    ) -> dict[str, Any]:
        """Collect performance metrics."""
        # Audit performance metrics
        perf_metrics = await self.audit_repository.get_audit_performance_metrics(
            start_date,
            end_date
        )
        
        # System performance
        system_perf = await self.audit_repository.get_system_performance_metrics(
            start_date,
            end_date
        )
        
        return {
            "response_time_ms": {
                "average": perf_metrics.get("avg_response_time", 0),
                "p50": perf_metrics.get("p50_response_time", 0),
                "p95": perf_metrics.get("p95_response_time", 0),
                "p99": perf_metrics.get("p99_response_time", 0)
            },
            "throughput": {
                "requests_per_second": system_perf.get("avg_rps", 0),
                "peak_rps": system_perf.get("peak_rps", 0)
            },
            "error_rate": system_perf.get("error_rate", 0),
            "availability": system_perf.get("availability", 99.9),
            "resource_usage": {
                "cpu": system_perf.get("avg_cpu", 0),
                "memory": system_perf.get("avg_memory", 0),
                "storage": system_perf.get("storage_usage", 0)
            }
        }
    
    def _calculate_churn_rate(self, total: int, active: int) -> float:
        """Calculate user churn rate."""
        if total == 0:
            return 0.0
        inactive = total - active
        return (inactive / total) * 100
    
    def _calculate_threat_level(self, security_stats: dict[str, Any]) -> str:
        """Calculate overall threat level."""
        severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1
        }
        
        score = 0
        for severity, count in security_stats.get("by_severity", {}).items():
            score += severity_weights.get(severity, 0) * count
        
        if score >= 100:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 20:
            return "medium"
        return "low"
    
    def _generate_predictions(self, metrics: dict[str, Any]) -> dict[str, Any]:
        """Generate predictions based on current metrics."""
        # This would use ML models in production
        # For now, simple trend analysis
        predictions = {}
        
        if "users" in metrics:
            growth_rate = metrics["users"].get("growth_rate", 0)
            predictions["user_growth_next_month"] = growth_rate * 4.3  # Weekly to monthly
        
        if "security" in metrics:
            threat_trend = "increasing" if metrics["security"]["suspicious_activities"] > 10 else "stable"
            predictions["threat_trend"] = threat_trend
        
        return predictions
    
    def _calculate_summary(self, metrics: dict[str, Any]) -> dict[str, Any]:
        """Calculate summary statistics."""
        summary = {
            "health_score": 0,
            "key_insights": [],
            "recommendations": []
        }
        
        # Calculate health score (0-100)
        scores = []
        
        if "users" in metrics:
            # User health based on active percentage
            active_pct = (metrics["users"]["active"] / metrics["users"]["total"] * 100) if metrics["users"]["total"] > 0 else 0
            scores.append(min(active_pct, 100))
        
        if "authentication" in metrics:
            # Auth health based on success rate
            scores.append(metrics["authentication"].get("success_rate", 0))
        
        if "security" in metrics:
            # Security health inversely related to incidents
            threat_score = 100 - min(metrics["security"]["suspicious_activities"], 100)
            scores.append(threat_score)
        
        if "performance" in metrics:
            # Performance health based on availability
            scores.append(metrics["performance"].get("availability", 0))
        
        summary["health_score"] = sum(scores) / len(scores) if scores else 0
        
        # Generate insights
        if "users" in metrics and metrics["users"]["growth_rate"] > 10:
            summary["key_insights"].append("High user growth rate detected")
        
        if "security" in metrics and metrics["security"]["suspicious_activities"] > 50:
            summary["key_insights"].append("Elevated security activity detected")
        
        # Generate recommendations
        if summary["health_score"] < 70:
            summary["recommendations"].append("System health below optimal levels")
        
        return summary