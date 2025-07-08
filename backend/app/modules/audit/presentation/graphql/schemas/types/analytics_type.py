"""GraphQL types for audit analytics."""

from datetime import datetime

import strawberry

from ..enums import TrendDirectionEnum


@strawberry.type
class AuditMetricsType:
    """GraphQL type for audit metrics."""

    # Volume metrics
    total_events: int
    events_per_day: float
    events_per_hour: float

    # User activity metrics
    active_users: int
    unique_users_today: int
    top_user_activity_count: int

    # Performance metrics
    average_response_time_ms: float
    slowest_operation_ms: int
    fastest_operation_ms: int
    timeout_rate: float

    # Error metrics
    total_errors: int
    error_rate: float
    critical_errors: int

    # Security metrics
    failed_logins: int
    unauthorized_attempts: int
    suspicious_activities: int
    security_incidents: int

    # Compliance metrics
    compliance_violations: int
    policy_breaches: int
    data_access_violations: int

    @strawberry.field
    def overall_health_score(self) -> float:
        """Calculate overall system health score."""
        # Base score starts at 100
        score = 100.0

        # Deduct for high error rate
        if self.error_rate > 0.05:  # 5%
            score -= (self.error_rate * 100) * 2

        # Deduct for security issues
        if self.security_incidents > 0:
            score -= min(20, self.security_incidents * 5)

        # Deduct for compliance violations
        if self.compliance_violations > 0:
            score -= min(15, self.compliance_violations * 3)

        # Deduct for performance issues
        if self.timeout_rate > 0.01:  # 1%
            score -= (self.timeout_rate * 100) * 3

        return max(0.0, score)

    @strawberry.field
    def security_risk_level(self) -> str:
        """Assess security risk level."""
        risk_score = 0

        if self.failed_logins > 100:
            risk_score += 2
        elif self.failed_logins > 50:
            risk_score += 1

        if self.unauthorized_attempts > 10:
            risk_score += 3
        elif self.unauthorized_attempts > 5:
            risk_score += 2

        if self.security_incidents > 5:
            risk_score += 4
        elif self.security_incidents > 0:
            risk_score += 2

        if risk_score >= 7:
            return "critical"
        if risk_score >= 5:
            return "high"
        if risk_score >= 3:
            return "medium"
        return "low"

    @strawberry.field
    def performance_grade(self) -> str:
        """Calculate performance grade."""
        avg_time = self.average_response_time_ms

        if avg_time <= 100:
            return "A"
        if avg_time <= 250:
            return "B"
        if avg_time <= 500:
            return "C"
        if avg_time <= 1000:
            return "D"
        return "F"


@strawberry.type
class MetricTrendType:
    """GraphQL type for metric trends."""

    metric_name: str
    current_value: float
    previous_value: float
    change_percentage: float
    trend_direction: TrendDirectionEnum
    period: str  # "hour", "day", "week", "month"

    @strawberry.field
    def absolute_change(self) -> float:
        """Calculate absolute change in metric."""
        return self.current_value - self.previous_value

    @strawberry.field
    def is_improvement(self) -> bool:
        """Determine if trend represents improvement."""
        # For most metrics, decreasing is good (errors, violations, etc.)
        improvement_metrics = [
            "error_rate",
            "timeout_rate",
            "failed_logins",
            "unauthorized_attempts",
            "compliance_violations",
            "average_response_time_ms",
        ]

        if self.metric_name in improvement_metrics:
            return self.trend_direction == TrendDirectionEnum.DECREASING
        return self.trend_direction == TrendDirectionEnum.INCREASING


@strawberry.type
class ActivityPatternType:
    """GraphQL type for activity patterns."""

    pattern_type: str  # "hourly", "daily", "weekly", "monthly"
    peak_hour: int
    peak_day: str
    lowest_activity_hour: int
    lowest_activity_day: str
    activity_distribution: str  # JSON string of distribution data

    @strawberry.field
    def peak_activity_time(self) -> str:
        """Return formatted peak activity time."""
        if self.pattern_type == "hourly":
            return f"{self.peak_hour:02d}:00"
        return self.peak_day

    @strawberry.field
    def activity_variance(self) -> float:
        """Calculate activity variance (coefficient of variation)."""
        import json

        try:
            data = json.loads(self.activity_distribution)
            values = list(data.values())
            if not values:
                return 0.0

            mean = sum(values) / len(values)
            if mean == 0:
                return 0.0

            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std_dev = variance**0.5

            return std_dev / mean  # Coefficient of variation
        except (json.JSONDecodeError, ZeroDivisionError):
            return 0.0


@strawberry.type
class AnomalyDetectionType:
    """GraphQL type for anomaly detection results."""

    anomaly_id: strawberry.ID
    detected_at: datetime
    anomaly_type: str  # "volume", "pattern", "security", "performance"
    description: str
    severity: str
    confidence_score: float
    affected_metrics: list[str]
    recommended_actions: list[str]

    @strawberry.field
    def formatted_detected_at(self) -> str:
        """Return formatted detection timestamp."""
        return self.detected_at.isoformat()

    @strawberry.field
    def is_high_confidence(self) -> bool:
        """Check if anomaly has high confidence."""
        return self.confidence_score >= 0.8

    @strawberry.field
    def requires_immediate_action(self) -> bool:
        """Check if anomaly requires immediate action."""
        return (
            self.severity in ["high", "critical"]
            and self.confidence_score >= 0.7
            and self.anomaly_type in ["security", "performance"]
        )


@strawberry.type
class UserActivityAnalyticsType:
    """GraphQL type for user activity analytics."""

    user_id: strawberry.ID
    user_email: str
    total_actions: int
    unique_resources_accessed: int
    peak_activity_hour: int
    failed_attempts: int
    risk_score: float
    last_activity: datetime

    @strawberry.field
    def formatted_last_activity(self) -> str:
        """Return formatted last activity timestamp."""
        return self.last_activity.isoformat()

    @strawberry.field
    def activity_level(self) -> str:
        """Categorize user activity level."""
        if self.total_actions >= 1000:
            return "very_high"
        if self.total_actions >= 500:
            return "high"
        if self.total_actions >= 100:
            return "medium"
        if self.total_actions >= 10:
            return "low"
        return "very_low"

    @strawberry.field
    def is_suspicious(self) -> bool:
        """Check if user activity is suspicious."""
        return self.risk_score >= 7.0 or self.failed_attempts >= 10


@strawberry.type
class ResourceAccessAnalyticsType:
    """GraphQL type for resource access analytics."""

    resource_type: str
    resource_id: str
    total_accesses: int
    unique_users: int
    failed_access_attempts: int
    peak_access_hour: int
    average_session_duration_ms: float

    @strawberry.field
    def access_success_rate(self) -> float:
        """Calculate access success rate."""
        total_attempts = self.total_accesses + self.failed_access_attempts
        if total_attempts == 0:
            return 0.0
        return (self.total_accesses / total_attempts) * 100

    @strawberry.field
    def popularity_level(self) -> str:
        """Categorize resource popularity."""
        if self.total_accesses >= 10000:
            return "very_high"
        if self.total_accesses >= 1000:
            return "high"
        if self.total_accesses >= 100:
            return "medium"
        if self.total_accesses >= 10:
            return "low"
        return "very_low"


@strawberry.type
class AuditAnalyticsType:
    """GraphQL type for comprehensive audit analytics."""

    # Time range
    analysis_start: datetime
    analysis_end: datetime

    # Core metrics
    metrics: AuditMetricsType

    # Trends
    metric_trends: list[MetricTrendType]

    # Patterns
    activity_patterns: list[ActivityPatternType]

    # Anomalies
    detected_anomalies: list[AnomalyDetectionType]

    # User analytics
    top_users: list[UserActivityAnalyticsType]
    suspicious_users: list[UserActivityAnalyticsType]

    # Resource analytics
    most_accessed_resources: list[ResourceAccessAnalyticsType]

    # Summary insights
    key_insights: list[str]
    recommendations: list[str]

    @strawberry.field
    def analysis_period_days(self) -> int:
        """Calculate analysis period in days."""
        delta = self.analysis_end - self.analysis_start
        return delta.days

    @strawberry.field
    def overall_security_posture(self) -> str:
        """Assess overall security posture."""
        health_score = self.metrics.overall_health_score
        risk_level = self.metrics.security_risk_level

        if health_score >= 90 and risk_level == "low":
            return "excellent"
        if health_score >= 80 and risk_level in ["low", "medium"]:
            return "good"
        if health_score >= 70:
            return "fair"
        return "poor"

    @strawberry.field
    def critical_issues_count(self) -> int:
        """Count critical issues requiring attention."""
        critical_count = 0

        # Count critical anomalies
        critical_count += len(
            [a for a in self.detected_anomalies if a.severity == "critical"]
        )

        # Count high-risk users
        critical_count += len([u for u in self.suspicious_users if u.risk_score >= 8.0])

        # Count performance issues
        if self.metrics.timeout_rate > 0.05:  # 5%
            critical_count += 1

        # Count security incidents
        if self.metrics.security_incidents > 0:
            critical_count += self.metrics.security_incidents

        return critical_count


@strawberry.type
class UserBehaviorAnalyticsType:
    """GraphQL type for user behavior analytics."""

    user_id: strawberry.ID
    analysis_period: str
    baseline_activity: float
    current_activity: float
    anomaly_score: float
    risk_score: float
    behavior_patterns: list[str]
    detected_anomalies: list[str]
    peer_comparison: str | None = None

    @strawberry.field
    def activity_deviation(self) -> float:
        """Calculate deviation from baseline."""
        if self.baseline_activity == 0:
            return 0.0
        return (
            (self.current_activity - self.baseline_activity) / self.baseline_activity
        ) * 100

    @strawberry.field
    def is_anomalous(self) -> bool:
        """Check if behavior is anomalous."""
        return self.anomaly_score >= 0.7


@strawberry.type
class SystemPerformanceType:
    """GraphQL type for system performance analytics."""

    analysis_period: str
    metrics: list[str]
    performance_data: str  # JSON string
    trends: list[MetricTrendType]
    recommendations: list[str]
    capacity_insights: list[str]

    @strawberry.field
    def overall_performance_score(self) -> float:
        """Calculate overall performance score."""
        # This would be calculated based on the metrics
        return 85.0  # Placeholder


@strawberry.type
class RiskAnalyticsType:
    """GraphQL type for risk analytics."""

    analysis_period: str
    overall_risk_score: float
    risk_categories: list[str]
    threat_analysis: str | None = None
    vulnerability_assessment: str | None = None
    mitigation_recommendations: list[str]
    threat_intelligence: str | None = None

    @strawberry.field
    def risk_level(self) -> str:
        """Return risk level based on score."""
        if self.overall_risk_score >= 8.0:
            return "critical"
        if self.overall_risk_score >= 6.0:
            return "high"
        if self.overall_risk_score >= 4.0:
            return "medium"
        return "low"


@strawberry.type
class PredictiveAnalyticsType:
    """GraphQL type for predictive analytics."""

    forecast_period: str
    confidence_level: float
    metrics: list[str]
    predictions: str  # JSON string of predictions
    scenarios: str | None = None  # JSON string of scenarios
    accuracy_metrics: str  # JSON string

    @strawberry.field
    def forecast_reliability(self) -> str:
        """Assess forecast reliability."""
        if self.confidence_level >= 0.95:
            return "very_high"
        if self.confidence_level >= 0.85:
            return "high"
        if self.confidence_level >= 0.75:
            return "medium"
        return "low"


@strawberry.type
class AuditTrendType:
    """GraphQL type for audit trends (enhanced)."""

    metric_name: str
    time_period: str
    data_points: str  # JSON string
    trend_direction: TrendDirectionEnum
    change_percentage: float
    seasonality_detected: bool
    anomalies_count: int

    @strawberry.field
    def trend_strength(self) -> str:
        """Assess trend strength."""
        abs_change = abs(self.change_percentage)
        if abs_change >= 50:
            return "very_strong"
        if abs_change >= 25:
            return "strong"
        if abs_change >= 10:
            return "moderate"
        return "weak"
