"""GraphQL types for audit reports."""

from datetime import datetime

import strawberry

from ..enums import ExportFormatEnum, ReportTypeEnum, TrendDirectionEnum


@strawberry.type
class AuditStatisticsType:
    """GraphQL type for audit statistics."""

    # Basic counts
    total_entries: int

    # Breakdowns
    by_severity: str  # JSON string of severity counts
    by_category: str  # JSON string of category counts
    by_outcome: str  # JSON string of outcome counts
    by_user: str  # JSON string of user counts
    by_resource_type: str  # JSON string of resource type counts

    # Time-based statistics
    entries_by_hour: str  # JSON string of hourly counts
    entries_by_day: str  # JSON string of daily counts

    # Performance metrics
    average_duration_ms: float | None = None
    max_duration_ms: int | None = None
    min_duration_ms: int | None = None

    # Error statistics
    error_rate: float
    errors_by_type: str  # JSON string of error type counts

    @strawberry.field
    def severity_breakdown(self) -> list["StatBreakdownType"]:
        """Parse and return severity breakdown."""
        import json

        data = json.loads(self.by_severity)
        return [
            StatBreakdownType(
                label=k, count=v, percentage=(v / self.total_entries) * 100
            )
            for k, v in data.items()
        ]

    @strawberry.field
    def category_breakdown(self) -> list["StatBreakdownType"]:
        """Parse and return category breakdown."""
        import json

        data = json.loads(self.by_category)
        return [
            StatBreakdownType(
                label=k, count=v, percentage=(v / self.total_entries) * 100
            )
            for k, v in data.items()
        ]

    @strawberry.field
    def performance_summary(self) -> "PerformanceSummaryType":
        """Return performance summary."""
        return PerformanceSummaryType(
            average_duration=self.average_duration_ms,
            max_duration=self.max_duration_ms,
            min_duration=self.min_duration_ms,
            total_entries=self.total_entries,
        )


@strawberry.type
class StatBreakdownType:
    """GraphQL type for statistic breakdowns."""

    label: str
    count: int
    percentage: float


@strawberry.type
class PerformanceSummaryType:
    """GraphQL type for performance summary."""

    average_duration: float | None
    max_duration: int | None
    min_duration: int | None
    total_entries: int


@strawberry.type
class AuditTrendType:
    """GraphQL type for audit trends."""

    period: str  # "hour", "day", "week", "month"
    data_points: str  # JSON string of data points
    trend_direction: TrendDirectionEnum
    change_percentage: float

    @strawberry.field
    def parsed_data_points(self) -> list["TrendDataPointType"]:
        """Parse and return trend data points."""
        import json

        data = json.loads(self.data_points)
        return [
            TrendDataPointType(
                timestamp=point.get("timestamp", ""),
                value=point.get("value", 0),
                label=point.get("label", ""),
            )
            for point in data
        ]


@strawberry.type
class TrendDataPointType:
    """GraphQL type for trend data points."""

    timestamp: str
    value: int
    label: str


@strawberry.type
class AuditAnomalyType:
    """GraphQL type for detected anomalies."""

    anomaly_type: str
    description: str
    severity: str
    detected_at: datetime
    affected_resources: list[str]
    confidence_score: float

    @strawberry.field
    def formatted_detected_at(self) -> str:
        """Return formatted detection timestamp."""
        return self.detected_at.isoformat()


@strawberry.type
class TopItemType:
    """GraphQL type for top items (users, resources, actions)."""

    item_id: str
    item_name: str
    count: int
    percentage: float
    risk_score: float | None = None


@strawberry.type
class SecurityEventSummaryType:
    """GraphQL type for security event summary."""

    event_type: str
    count: int
    severity: str
    last_occurrence: datetime
    affected_users: list[str]

    @strawberry.field
    def formatted_last_occurrence(self) -> str:
        """Return formatted last occurrence timestamp."""
        return self.last_occurrence.isoformat()


@strawberry.type
class AuditReportType:
    """GraphQL type for audit reports."""

    # Report identity
    report_id: strawberry.ID
    report_type: ReportTypeEnum
    generated_at: datetime
    generated_by: strawberry.ID | None = None

    # Report parameters
    title: str
    description: str | None = None
    time_range_start: datetime
    time_range_end: datetime
    filters_applied: str  # JSON string of applied filters

    # Statistics
    statistics: AuditStatisticsType

    # Trends
    trends: list[AuditTrendType]

    # Key findings
    key_findings: list[str]
    anomalies_detected: list[AuditAnomalyType]

    # Top items
    top_users: list[TopItemType]
    top_resources: list[TopItemType]
    top_actions: list[TopItemType]

    # Compliance summary
    compliance_summary: str  # JSON string of compliance data

    # Security insights
    security_events: list[SecurityEventSummaryType]
    risk_score: float | None = None

    # Export formats
    available_formats: list[ExportFormatEnum]

    @strawberry.field
    def formatted_generated_at(self) -> str:
        """Return formatted generation timestamp."""
        return self.generated_at.isoformat()

    @strawberry.field
    def time_range_duration_days(self) -> int:
        """Calculate duration of time range in days."""
        delta = self.time_range_end - self.time_range_start
        return delta.days

    @strawberry.field
    def parsed_filters(self) -> str:
        """Parse and return applied filters as formatted JSON."""
        import json

        try:
            filters = json.loads(self.filters_applied)
            return json.dumps(filters, indent=2)
        except json.JSONDecodeError:
            return "{}"

    @strawberry.field
    def parsed_compliance_summary(self) -> "ComplianceSummaryType":
        """Parse and return compliance summary."""
        import json

        try:
            data = json.loads(self.compliance_summary)
            return ComplianceSummaryType(
                overall_score=data.get("overall_score", 0.0),
                compliant_controls=data.get("compliant_controls", 0),
                total_controls=data.get("total_controls", 0),
                frameworks=data.get("frameworks", []),
            )
        except json.JSONDecodeError:
            return ComplianceSummaryType(
                overall_score=0.0, compliant_controls=0, total_controls=0, frameworks=[]
            )

    @strawberry.field
    def executive_summary(self) -> str:
        """Generate executive summary."""
        total_entries = self.statistics.total_entries
        duration_days = self.time_range_duration_days
        risk_level = (
            "Low"
            if (self.risk_score or 0) < 3.0
            else "Medium"
            if (self.risk_score or 0) < 7.0
            else "High"
        )

        return f"""
        Audit Report Summary:
        - Period: {duration_days} days ({self.time_range_start.strftime('%Y-%m-%d')} to {self.time_range_end.strftime('%Y-%m-%d')})
        - Total Events: {total_entries:,}
        - Risk Level: {risk_level}
        - Anomalies Detected: {len(self.anomalies_detected)}
        - Security Events: {len(self.security_events)}
        - Key Findings: {len(self.key_findings)} items identified
        """.strip()


@strawberry.type
class ComplianceSummaryType:
    """GraphQL type for compliance summary in reports."""

    overall_score: float
    compliant_controls: int
    total_controls: int
    frameworks: list[str]

    @strawberry.field
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.compliant_controls / self.total_controls) * 100


@strawberry.type
class ReportExportType:
    """GraphQL type for report export information."""

    format: ExportFormatEnum
    download_url: str
    file_size_bytes: int
    generated_at: datetime
    expires_at: datetime

    @strawberry.field
    def file_size_mb(self) -> float:
        """Return file size in MB."""
        return round(self.file_size_bytes / (1024 * 1024), 2)


@strawberry.type
class ExecutiveSummaryType:
    """GraphQL type for executive summary."""

    summary_period: str
    key_metrics: str  # JSON string
    compliance_status: str
    risk_assessment: str
    trends: list[AuditTrendType]
    action_items: list[str]
    recommendations: list[str]

    @strawberry.field
    def summary_score(self) -> float:
        """Overall summary score."""
        return 85.0  # Placeholder


@strawberry.type
class TrendAnalysisType:
    """GraphQL type for trend analysis."""

    analysis_period: str
    metrics: list[str]
    trends: list[AuditTrendType]
    patterns: list[str]
    predictions: str | None = None
    anomalies: list[str] = strawberry.field(default_factory=list)

    @strawberry.field
    def trend_summary(self) -> str:
        """Summary of trends."""
        return "Overall trends show improvement in security metrics"


@strawberry.type
class PatternAnalysisType:
    """GraphQL type for pattern analysis."""

    pattern_type: str
    description: str
    confidence: float
    affected_metrics: list[str]
    recommendations: list[str]


@strawberry.type
class ReportAnalyticsType:
    """GraphQL type for report analytics."""

    report_type: str
    metrics: list[str]
    performance_data: str  # JSON string
    trends: list[TrendAnalysisType]
    patterns: list[PatternAnalysisType]
    recommendations: list[str]


@strawberry.type
class AuditTimelineType:
    """GraphQL type for audit timeline."""

    timeline_id: strawberry.ID
    start_date: datetime
    end_date: datetime
    events: str  # JSON string of timeline events
    entity_relationships: str  # JSON string
    correlation_analysis: str  # JSON string

    @strawberry.field
    def event_count(self) -> int:
        """Count of events in timeline."""
        import json

        try:
            events = json.loads(self.events)
            return len(events) if isinstance(events, list) else 0
        except json.JSONDecodeError:
            return 0

    @strawberry.field
    def timeline_duration_days(self) -> int:
        """Duration of timeline in days."""
        delta = self.end_date - self.start_date
        return delta.days


@strawberry.type
class AuditSummaryType:
    """GraphQL type for audit summary."""

    total_entries: int
    unique_users: int
    unique_resources: int
    time_range: str
    key_statistics: str  # JSON string
    highlights: list[str]
