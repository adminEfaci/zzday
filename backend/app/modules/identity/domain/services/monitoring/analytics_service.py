"""
Analytics Domain Service

Implements comprehensive analytics and metrics collection for the identity system.
"""

import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from app.utils.date import format_relative_time, get_date_range_buckets
from app.utils.math import calculate_percentile, calculate_trend
from app.utils.validation import validate_uuid

from ...interfaces.repositories.analytics_repository import IAnalyticsRepository
from ...interfaces.services.infrastructure.cache_port import ICachePort
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort
from ...interfaces.services.monitoring.analytics_port import IAnalyticsPort
from ...enums import UserStatus, SessionStatus, AuthenticationMethod


class MetricType(Enum):
    """Types of metrics collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricData:
    """Metric data structure."""
    name: str
    value: float
    metric_type: MetricType
    tags: Dict[str, str]
    timestamp: datetime


@dataclass
class AnalyticsReport:
    """Analytics report structure."""
    report_id: str
    period_start: datetime
    period_end: datetime
    metrics: Dict[str, Any]
    trends: Dict[str, Any]
    insights: List[str]
    generated_at: datetime


@dataclass
class UserMetrics:
    """User-related metrics."""
    total_users: int
    active_users: int
    new_users: int
    suspended_users: int
    user_growth_rate: float
    activation_rate: float


@dataclass
class AuthenticationMetrics:
    """Authentication-related metrics."""
    total_logins: int
    successful_logins: int
    failed_logins: int
    success_rate: float
    avg_session_duration: float
    mfa_usage_rate: float
    authentication_methods: Dict[str, int]


@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    security_events: int
    high_risk_events: int
    blocked_attempts: int
    password_resets: int
    account_lockouts: int
    suspicious_activities: int


class AnalyticsService(IAnalyticsPort):
    """Domain service for analytics and metrics collection."""
    
    def __init__(
        self,
        analytics_repository: IAnalyticsRepository,
        cache_port: ICachePort,
        configuration_port: IConfigurationPort
    ) -> None:
        self._analytics_repository = analytics_repository
        self._cache = cache_port
        self._config = configuration_port
        
    async def track_event(
        self,
        event_name: str,
        properties: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Track an analytics event."""
        
        if not event_name:
            raise ValueError("Event name is required")
        
        if user_id and not validate_uuid(str(user_id)):
            raise ValueError("Invalid user ID format")
        
        # Prepare event data
        event_data = {
            "event_name": event_name,
            "properties": properties or {},
            "user_id": str(user_id) if user_id else None,
            "session_id": session_id,
            "timestamp": datetime.utcnow()
        }
        
        # Store event
        await self._analytics_repository.store_event(event_data)
        
        # Update real-time metrics cache
        await self._update_realtime_metrics(event_name, properties)
        
    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: Optional[Dict[str, str]] = None,
        metric_type: str = "gauge"
    ) -> None:
        """Record a custom metric."""
        
        if not metric_name:
            raise ValueError("Metric name is required")
        
        try:
            metric_type_enum = MetricType(metric_type.lower())
        except ValueError:
            metric_type_enum = MetricType.GAUGE
        
        # Create metric data
        metric_data = MetricData(
            name=metric_name,
            value=value,
            metric_type=metric_type_enum,
            tags=tags or {},
            timestamp=datetime.utcnow()
        )
        
        # Store metric
        await self._analytics_repository.store_metric(metric_data)
        
        # Update metric aggregations
        await self._update_metric_aggregations(metric_data)
        
    async def get_user_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """Get user-related metrics for date range."""
        
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
        
        # Check cache first
        cache_key = f"user_metrics:{start_date.date()}:{end_date.date()}:{granularity}"
        cached_metrics = await self._cache.get(cache_key)
        if cached_metrics:
            return cached_metrics
        
        # Get user data from repository
        user_data = await self._analytics_repository.get_user_analytics(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity
        )
        
        # Calculate user metrics
        metrics = await self._calculate_user_metrics(user_data, start_date, end_date)
        
        # Generate time series data
        time_series = self._generate_user_time_series(user_data, granularity)
        
        result = {
            "metrics": {
                "total_users": metrics.total_users,
                "active_users": metrics.active_users,
                "new_users": metrics.new_users,
                "suspended_users": metrics.suspended_users,
                "user_growth_rate": metrics.user_growth_rate,
                "activation_rate": metrics.activation_rate
            },
            "time_series": time_series,
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "granularity": granularity
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Cache for 30 minutes
        await self._cache.set(cache_key, result, expiry_seconds=1800)
        
        return result
        
    async def get_authentication_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """Get authentication-related metrics."""
        
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
        
        # Check cache first
        cache_key = f"auth_metrics:{start_date.date()}:{end_date.date()}:{granularity}"
        cached_metrics = await self._cache.get(cache_key)
        if cached_metrics:
            return cached_metrics
        
        # Get authentication data
        auth_data = await self._analytics_repository.get_authentication_analytics(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity
        )
        
        # Calculate authentication metrics
        metrics = await self._calculate_authentication_metrics(auth_data)
        
        # Generate time series data
        time_series = self._generate_auth_time_series(auth_data, granularity)
        
        result = {
            "metrics": {
                "total_logins": metrics.total_logins,
                "successful_logins": metrics.successful_logins,
                "failed_logins": metrics.failed_logins,
                "success_rate": metrics.success_rate,
                "avg_session_duration": metrics.avg_session_duration,
                "mfa_usage_rate": metrics.mfa_usage_rate,
                "authentication_methods": metrics.authentication_methods
            },
            "time_series": time_series,
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "granularity": granularity
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Cache for 30 minutes
        await self._cache.set(cache_key, result, expiry_seconds=1800)
        
        return result
        
    async def get_security_metrics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Get security-related metrics."""
        
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
        
        # Check cache first
        cache_key = f"security_metrics:{start_date.date()}:{end_date.date()}"
        cached_metrics = await self._cache.get(cache_key)
        if cached_metrics:
            return cached_metrics
        
        # Get security data
        security_data = await self._analytics_repository.get_security_analytics(
            start_date=start_date,
            end_date=end_date
        )
        
        # Calculate security metrics
        metrics = await self._calculate_security_metrics(security_data)
        
        result = {
            "metrics": {
                "security_events": metrics.security_events,
                "high_risk_events": metrics.high_risk_events,
                "blocked_attempts": metrics.blocked_attempts,
                "password_resets": metrics.password_resets,
                "account_lockouts": metrics.account_lockouts,
                "suspicious_activities": metrics.suspicious_activities
            },
            "risk_assessment": {
                "overall_risk_score": self._calculate_overall_risk_score(metrics),
                "risk_level": self._determine_risk_level(metrics),
                "trending": self._analyze_security_trends(security_data)
            },
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Cache for 15 minutes (security metrics should be more current)
        await self._cache.set(cache_key, result, expiry_seconds=900)
        
        return result
        
    async def generate_analytics_report(
        self,
        report_type: str,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive analytics report."""
        
        if not report_type:
            raise ValueError("Report type is required")
        
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
        
        # Get appropriate metrics based on report type
        if report_type == "user_overview":
            metrics = await self.get_user_metrics(start_date, end_date)
        elif report_type == "authentication_summary":
            metrics = await self.get_authentication_metrics(start_date, end_date)
        elif report_type == "security_dashboard":
            metrics = await self.get_security_metrics(start_date, end_date)
        elif report_type == "comprehensive":
            metrics = await self._get_comprehensive_metrics(start_date, end_date)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Generate insights and trends
        insights = await self._generate_insights(metrics, report_type)
        trends = await self._analyze_trends(metrics, start_date, end_date)
        
        report = AnalyticsReport(
            report_id=f"{report_type}_{start_date.date()}_{end_date.date()}",
            period_start=start_date,
            period_end=end_date,
            metrics=metrics,
            trends=trends,
            insights=insights,
            generated_at=datetime.utcnow()
        )
        
        return {
            "report_id": report.report_id,
            "report_type": report_type,
            "period": {
                "start_date": report.period_start.isoformat(),
                "end_date": report.period_end.isoformat(),
                "duration_days": (report.period_end - report.period_start).days
            },
            "metrics": report.metrics,
            "trends": report.trends,
            "insights": report.insights,
            "filters": filters or {},
            "generated_at": report.generated_at.isoformat()
        }
        
    async def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time system metrics."""
        
        # Check cache for real-time metrics
        cache_key = "realtime_metrics"
        cached_metrics = await self._cache.get(cache_key)
        if cached_metrics:
            return cached_metrics
        
        # Get current metrics from repository
        current_metrics = await self._analytics_repository.get_current_metrics()
        
        # Format real-time metrics
        metrics = {
            "active_sessions": current_metrics.get("active_sessions", 0),
            "active_users": current_metrics.get("active_users", 0),
            "logins_last_hour": current_metrics.get("logins_last_hour", 0),
            "failed_logins_last_hour": current_metrics.get("failed_logins_last_hour", 0),
            "security_alerts": current_metrics.get("security_alerts", 0),
            "system_load": current_metrics.get("system_load", 0.0),
            "response_time_avg": current_metrics.get("response_time_avg", 0.0),
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Cache for 1 minute
        await self._cache.set(cache_key, metrics, expiry_seconds=60)
        
        return metrics
        
    # Private helper methods
    
    async def _update_realtime_metrics(self, event_name: str, properties: Optional[Dict[str, Any]]) -> None:
        """Update real-time metrics cache."""
        cache_key = "realtime_events"
        current_events = await self._cache.get(cache_key) or {}
        
        # Increment event counter
        current_events[event_name] = current_events.get(event_name, 0) + 1
        
        # Cache for 5 minutes
        await self._cache.set(cache_key, current_events, expiry_seconds=300)
        
    async def _update_metric_aggregations(self, metric_data: MetricData) -> None:
        """Update metric aggregations for fast queries."""
        
        # Update hourly aggregations
        hour_key = f"metric_hour:{metric_data.name}:{metric_data.timestamp.strftime('%Y-%m-%d-%H')}"
        hourly_data = await self._cache.get(hour_key) or {"count": 0, "sum": 0.0, "min": float('inf'), "max": float('-inf')}
        
        hourly_data["count"] += 1
        hourly_data["sum"] += metric_data.value
        hourly_data["min"] = min(hourly_data["min"], metric_data.value)
        hourly_data["max"] = max(hourly_data["max"], metric_data.value)
        hourly_data["avg"] = hourly_data["sum"] / hourly_data["count"]
        
        # Cache for 2 hours
        await self._cache.set(hour_key, hourly_data, expiry_seconds=7200)
        
    async def _calculate_user_metrics(
        self, 
        user_data: Dict[str, Any], 
        start_date: datetime, 
        end_date: datetime
    ) -> UserMetrics:
        """Calculate user metrics from raw data."""
        
        total_users = user_data.get("total_users", 0)
        active_users = user_data.get("active_users", 0)
        new_users = user_data.get("new_users", 0)
        suspended_users = user_data.get("suspended_users", 0)
        
        # Calculate growth rate (comparing to previous period)
        period_days = (end_date - start_date).days
        previous_start = start_date - timedelta(days=period_days)
        previous_data = await self._analytics_repository.get_user_analytics(
            start_date=previous_start,
            end_date=start_date,
            granularity="day"
        )
        
        previous_total = previous_data.get("total_users", total_users)
        user_growth_rate = ((total_users - previous_total) / previous_total * 100) if previous_total > 0 else 0.0
        
        # Calculate activation rate
        activation_rate = (active_users / total_users * 100) if total_users > 0 else 0.0
        
        return UserMetrics(
            total_users=total_users,
            active_users=active_users,
            new_users=new_users,
            suspended_users=suspended_users,
            user_growth_rate=round(user_growth_rate, 2),
            activation_rate=round(activation_rate, 2)
        )
        
    async def _calculate_authentication_metrics(self, auth_data: Dict[str, Any]) -> AuthenticationMetrics:
        """Calculate authentication metrics from raw data."""
        
        total_logins = auth_data.get("total_logins", 0)
        successful_logins = auth_data.get("successful_logins", 0)
        failed_logins = auth_data.get("failed_logins", 0)
        
        success_rate = (successful_logins / total_logins * 100) if total_logins > 0 else 0.0
        
        # Calculate average session duration
        session_durations = auth_data.get("session_durations", [])
        avg_session_duration = statistics.mean(session_durations) if session_durations else 0.0
        
        # Calculate MFA usage rate
        mfa_logins = auth_data.get("mfa_logins", 0)
        mfa_usage_rate = (mfa_logins / successful_logins * 100) if successful_logins > 0 else 0.0
        
        # Authentication methods breakdown
        authentication_methods = auth_data.get("authentication_methods", {})
        
        return AuthenticationMetrics(
            total_logins=total_logins,
            successful_logins=successful_logins,
            failed_logins=failed_logins,
            success_rate=round(success_rate, 2),
            avg_session_duration=round(avg_session_duration, 2),
            mfa_usage_rate=round(mfa_usage_rate, 2),
            authentication_methods=authentication_methods
        )
        
    async def _calculate_security_metrics(self, security_data: Dict[str, Any]) -> SecurityMetrics:
        """Calculate security metrics from raw data."""
        
        return SecurityMetrics(
            security_events=security_data.get("security_events", 0),
            high_risk_events=security_data.get("high_risk_events", 0),
            blocked_attempts=security_data.get("blocked_attempts", 0),
            password_resets=security_data.get("password_resets", 0),
            account_lockouts=security_data.get("account_lockouts", 0),
            suspicious_activities=security_data.get("suspicious_activities", 0)
        )
        
    def _generate_user_time_series(self, user_data: Dict[str, Any], granularity: str) -> List[Dict[str, Any]]:
        """Generate time series data for user metrics."""
        time_series_data = user_data.get("time_series", [])
        
        formatted_series = []
        for data_point in time_series_data:
            formatted_series.append({
                "timestamp": data_point.get("timestamp"),
                "total_users": data_point.get("total_users", 0),
                "active_users": data_point.get("active_users", 0),
                "new_users": data_point.get("new_users", 0)
            })
        
        return formatted_series
        
    def _generate_auth_time_series(self, auth_data: Dict[str, Any], granularity: str) -> List[Dict[str, Any]]:
        """Generate time series data for authentication metrics."""
        time_series_data = auth_data.get("time_series", [])
        
        formatted_series = []
        for data_point in time_series_data:
            formatted_series.append({
                "timestamp": data_point.get("timestamp"),
                "total_logins": data_point.get("total_logins", 0),
                "successful_logins": data_point.get("successful_logins", 0),
                "failed_logins": data_point.get("failed_logins", 0)
            })
        
        return formatted_series
        
    def _calculate_overall_risk_score(self, metrics: SecurityMetrics) -> float:
        """Calculate overall security risk score."""
        
        # Weight different security events
        risk_score = 0.0
        
        if metrics.security_events > 0:
            high_risk_ratio = metrics.high_risk_events / metrics.security_events
            risk_score += high_risk_ratio * 40  # Up to 40 points for high-risk events
            
        if metrics.blocked_attempts > 10:
            risk_score += min(metrics.blocked_attempts / 100 * 20, 20)  # Up to 20 points for blocked attempts
            
        if metrics.suspicious_activities > 0:
            risk_score += min(metrics.suspicious_activities * 5, 25)  # Up to 25 points for suspicious activities
            
        if metrics.account_lockouts > 5:
            risk_score += min(metrics.account_lockouts / 10 * 15, 15)  # Up to 15 points for lockouts
        
        return min(risk_score, 100.0)
        
    def _determine_risk_level(self, metrics: SecurityMetrics) -> str:
        """Determine risk level based on security metrics."""
        risk_score = self._calculate_overall_risk_score(metrics)
        
        if risk_score >= 75:
            return "high"
        elif risk_score >= 50:
            return "medium"
        else:
            return "low"
            
    def _analyze_security_trends(self, security_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze security trends."""
        
        # Get time series data if available
        time_series = security_data.get("time_series", [])
        
        if len(time_series) < 2:
            return {"trend": "insufficient_data", "direction": "unknown"}
        
        # Calculate trend for security events
        security_events = [point.get("security_events", 0) for point in time_series]
        trend_direction = calculate_trend(security_events) if len(security_events) > 1 else "stable"
        
        return {
            "trend": "improving" if trend_direction == "decreasing" else "worsening" if trend_direction == "increasing" else "stable",
            "direction": trend_direction
        }
        
    async def _get_comprehensive_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get comprehensive metrics for all areas."""
        
        user_metrics = await self.get_user_metrics(start_date, end_date)
        auth_metrics = await self.get_authentication_metrics(start_date, end_date)
        security_metrics = await self.get_security_metrics(start_date, end_date)
        
        return {
            "user_metrics": user_metrics,
            "authentication_metrics": auth_metrics,
            "security_metrics": security_metrics
        }
        
    async def _generate_insights(self, metrics: Dict[str, Any], report_type: str) -> List[str]:
        """Generate insights based on metrics."""
        insights = []
        
        if report_type == "user_overview":
            user_data = metrics.get("metrics", {})
            if user_data.get("user_growth_rate", 0) > 10:
                insights.append("Strong user growth detected - consider scaling infrastructure")
            if user_data.get("activation_rate", 0) < 50:
                insights.append("Low user activation rate - review onboarding process")
                
        elif report_type == "authentication_summary":
            auth_data = metrics.get("metrics", {})
            if auth_data.get("success_rate", 0) < 95:
                insights.append("Authentication success rate below optimal - investigate failure causes")
            if auth_data.get("mfa_usage_rate", 0) < 70:
                insights.append("MFA adoption could be improved for better security")
                
        elif report_type == "security_dashboard":
            security_data = metrics.get("metrics", {})
            if security_data.get("high_risk_events", 0) > 0:
                insights.append("High-risk security events detected - immediate attention required")
            if security_data.get("suspicious_activities", 0) > 10:
                insights.append("Elevated suspicious activity - consider additional monitoring")
        
        return insights
        
    async def _analyze_trends(self, metrics: Dict[str, Any], start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Analyze trends in metrics."""
        
        # Get previous period data for comparison
        period_days = (end_date - start_date).days
        previous_start = start_date - timedelta(days=period_days)
        
        # This would implement trend analysis comparing current vs previous periods
        # For now, return placeholder trends
        return {
            "user_growth": "increasing",
            "authentication_success": "stable",
            "security_incidents": "decreasing"
        }
