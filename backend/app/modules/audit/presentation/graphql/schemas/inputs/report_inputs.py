"""
Comprehensive GraphQL input types for reporting operations.

This module provides input types for generating reports, analytics, and compliance
assessments with comprehensive validation and configuration options.
"""

from datetime import datetime
from typing import Any

import strawberry

from ..enums import ComplianceFrameworkEnum, ExportFormatEnum, ReportTypeEnum
from .filter_input import DateRangeInput


@strawberry.input
class ReportGenerationInput:
    """Input type for generating audit reports."""

    # Report configuration
    report_type: ReportTypeEnum
    title: str
    description: str | None = None

    # Time range
    date_range: DateRangeInput

    # Filters
    filters: "AuditFilterInput" | None = None

    # Report options
    include_statistics: bool = True
    include_timeline: bool = False
    include_recommendations: bool = True

    # Compliance options
    compliance_frameworks: list[ComplianceFrameworkEnum] = strawberry.field(
        default_factory=list
    )

    # Export options
    export_format: ExportFormatEnum = ExportFormatEnum.PDF

    def validate(self) -> list[str]:
        """Validate report generation input."""
        errors = []

        if not self.title or len(self.title.strip()) == 0:
            errors.append("Report title is required")
        elif len(self.title) > 255:
            errors.append("Report title too long (max 255 characters)")

        if self.description and len(self.description) > 1000:
            errors.append("Report description too long (max 1000 characters)")

        # Validate date range
        errors.extend(self.date_range.validate())

        # Validate filters if provided
        if self.filters:
            errors.extend(self.filters.validate())

        return errors


@strawberry.input
class ScheduleReportInput:
    """Input type for scheduling recurring reports."""

    # Schedule configuration
    name: str
    description: str | None = None
    frequency: str  # "daily", "weekly", "monthly", "quarterly"

    # Report configuration
    report_config: ReportGenerationInput

    # Delivery options
    recipients: list[str] = strawberry.field(default_factory=list)
    delivery_format: ExportFormatEnum = ExportFormatEnum.PDF

    # Schedule options
    enabled: bool = True
    start_date: datetime | None = None
    end_date: datetime | None = None

    def validate(self) -> list[str]:
        """Validate report scheduling input."""
        errors = []

        if not self.name or len(self.name.strip()) == 0:
            errors.append("Schedule name is required")
        elif len(self.name) > 255:
            errors.append("Schedule name too long (max 255 characters)")

        if self.description and len(self.description) > 1000:
            errors.append("Schedule description too long (max 1000 characters)")

        valid_frequencies = ["daily", "weekly", "monthly", "quarterly"]
        if self.frequency not in valid_frequencies:
            errors.append(
                f"Invalid frequency. Must be one of: {', '.join(valid_frequencies)}"
            )

        # Validate recipients
        if not self.recipients:
            errors.append("At least one recipient is required")
        elif len(self.recipients) > 50:
            errors.append("Too many recipients (max 50)")

        for recipient in self.recipients:
            if not self._is_valid_email(recipient):
                errors.append(f"Invalid email address: {recipient}")

        # Validate date range
        if self.start_date and self.end_date:
            if self.start_date >= self.end_date:
                errors.append("Start date must be before end date")

        # Validate report configuration
        errors.extend(self.report_config.validate())

        return errors

    def _is_valid_email(self, email: str) -> bool:
        """Validate email address format."""
        import re

        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))


@strawberry.input
class ComplianceReportInput:
    """Input type for compliance report generation."""

    # Compliance configuration
    frameworks: list[ComplianceFrameworkEnum]

    # Time range
    date_range: DateRangeInput

    # Report options
    include_violations: bool = True
    include_recommendations: bool = True
    include_risk_assessment: bool = True

    # Scope
    scope: str | None = None  # "organization", "department", "project"

    def validate(self) -> list[str]:
        """Validate compliance report input."""
        errors = []

        if not self.frameworks:
            errors.append("At least one compliance framework is required")
        elif len(self.frameworks) > 10:
            errors.append("Too many frameworks (max 10)")

        # Validate date range
        errors.extend(self.date_range.validate())

        # Validate scope
        if self.scope:
            valid_scopes = ["organization", "department", "project", "user"]
            if self.scope not in valid_scopes:
                errors.append(
                    f"Invalid scope. Must be one of: {', '.join(valid_scopes)}"
                )

        return errors


@strawberry.input
class ComplianceCheckInput:
    """Input type for compliance check operations."""

    # Check configuration
    frameworks: list[ComplianceFrameworkEnum]

    # Time range
    date_range: DateRangeInput

    # Check options
    include_recommendations: bool = True

    # Scope
    scope: str | None = None

    def validate(self) -> list[str]:
        """Validate compliance check input."""
        errors = []

        if not self.frameworks:
            errors.append("At least one compliance framework is required")

        # Validate date range
        errors.extend(self.date_range.validate())

        return errors


@strawberry.input
class AnalyticsQueryInput:
    """Input type for analytics queries."""

    # Analytics configuration
    time_range: str  # "1h", "24h", "7d", "30d", "90d"
    metrics: list[str]

    # Options
    include_trends: bool = True
    include_comparisons: bool = False
    aggregation_level: str = "day"  # "hour", "day", "week", "month"

    def validate(self) -> list[str]:
        """Validate analytics query input."""
        errors = []

        valid_time_ranges = ["1h", "6h", "12h", "24h", "7d", "30d", "90d", "365d"]
        if self.time_range not in valid_time_ranges:
            errors.append(
                f"Invalid time range. Must be one of: {', '.join(valid_time_ranges)}"
            )

        if not self.metrics:
            errors.append("At least one metric is required")
        elif len(self.metrics) > 20:
            errors.append("Too many metrics (max 20)")

        valid_aggregations = ["hour", "day", "week", "month"]
        if self.aggregation_level not in valid_aggregations:
            errors.append(
                f"Invalid aggregation level. Must be one of: {', '.join(valid_aggregations)}"
            )

        return errors

    def to_criteria_dict(self) -> dict[str, Any]:
        """Convert to criteria dictionary."""
        return {
            "time_range": self.time_range,
            "metrics": self.metrics,
            "include_trends": self.include_trends,
            "include_comparisons": self.include_comparisons,
            "aggregation_level": self.aggregation_level,
        }


@strawberry.input
class MetricsQueryInput:
    """Input type for metrics queries."""

    # Metrics configuration
    time_range: str = "24h"
    metrics: list[str] = strawberry.field(default_factory=list)

    # Options
    include_trends: bool = True
    include_comparisons: bool = False
    aggregation_level: str = "hour"

    def validate(self) -> list[str]:
        """Validate metrics query input."""
        errors = []

        valid_time_ranges = ["1h", "6h", "12h", "24h", "7d", "30d"]
        if self.time_range not in valid_time_ranges:
            errors.append(
                f"Invalid time range. Must be one of: {', '.join(valid_time_ranges)}"
            )

        valid_aggregations = ["minute", "hour", "day"]
        if self.aggregation_level not in valid_aggregations:
            errors.append(
                f"Invalid aggregation level. Must be one of: {', '.join(valid_aggregations)}"
            )

        return errors

    def to_criteria_dict(self) -> dict[str, Any]:
        """Convert to criteria dictionary."""
        return {
            "time_range": self.time_range,
            "metrics": self.metrics
            if self.metrics
            else ["total_events", "error_rate", "response_time"],
            "include_trends": self.include_trends,
            "include_comparisons": self.include_comparisons,
            "aggregation_level": self.aggregation_level,
        }


@strawberry.input
class TrendAnalysisInput:
    """Input type for trend analysis."""

    # Analysis configuration
    date_range: DateRangeInput
    metrics: list[str]

    # Options
    time_granularity: str = "day"  # "hour", "day", "week", "month"
    include_predictions: bool = False
    include_anomalies: bool = True

    def validate(self) -> list[str]:
        """Validate trend analysis input."""
        errors = []

        # Validate date range
        errors.extend(self.date_range.validate())

        if not self.metrics:
            errors.append("At least one metric is required")
        elif len(self.metrics) > 10:
            errors.append("Too many metrics (max 10)")

        valid_granularities = ["hour", "day", "week", "month"]
        if self.time_granularity not in valid_granularities:
            errors.append(
                f"Invalid time granularity. Must be one of: {', '.join(valid_granularities)}"
            )

        return errors


@strawberry.input
class UserBehaviorInput:
    """Input type for user behavior analysis."""

    # User selection
    user_ids: list[strawberry.ID] = strawberry.field(default_factory=list)

    # Analysis configuration
    date_range: DateRangeInput
    analysis_period: str = "30d"  # "7d", "30d", "90d"

    # Options
    include_anomalies: bool = True
    include_risk_scoring: bool = True
    include_peer_comparison: bool = False

    def validate(self) -> list[str]:
        """Validate user behavior input."""
        errors = []

        if len(self.user_ids) > 100:
            errors.append("Too many users (max 100)")

        # Validate date range
        errors.extend(self.date_range.validate())

        valid_periods = ["7d", "30d", "90d", "365d"]
        if self.analysis_period not in valid_periods:
            errors.append(
                f"Invalid analysis period. Must be one of: {', '.join(valid_periods)}"
            )

        return errors


@strawberry.input
class SystemPerformanceInput:
    """Input type for system performance analysis."""

    # Analysis configuration
    date_range: DateRangeInput
    metrics: list[str]

    # Options
    time_granularity: str = "hour"
    include_trends: bool = True
    include_predictions: bool = False
    include_recommendations: bool = True

    def validate(self) -> list[str]:
        """Validate system performance input."""
        errors = []

        # Validate date range
        errors.extend(self.date_range.validate())

        if not self.metrics:
            errors.append("At least one metric is required")

        valid_granularities = ["minute", "hour", "day"]
        if self.time_granularity not in valid_granularities:
            errors.append(
                f"Invalid time granularity. Must be one of: {', '.join(valid_granularities)}"
            )

        return errors


@strawberry.input
class RiskAnalysisInput:
    """Input type for risk analysis."""

    # Analysis configuration
    date_range: DateRangeInput
    risk_categories: list[str]

    # Options
    include_threat_analysis: bool = True
    include_vulnerability_assessment: bool = True
    include_mitigation_recommendations: bool = True
    threat_intelligence_sources: list[str] = strawberry.field(default_factory=list)

    def validate(self) -> list[str]:
        """Validate risk analysis input."""
        errors = []

        # Validate date range
        errors.extend(self.date_range.validate())

        if not self.risk_categories:
            errors.append("At least one risk category is required")

        valid_categories = [
            "authentication",
            "authorization",
            "data_access",
            "system_security",
            "compliance",
            "operational",
            "technical",
            "business",
        ]

        for category in self.risk_categories:
            if category not in valid_categories:
                errors.append(f"Invalid risk category: {category}")

        return errors


@strawberry.input
class TimelineQueryInput:
    """Input type for timeline queries."""

    # Time range
    start_date: datetime
    end_date: datetime

    # Entity selection
    entity_ids: list[str] = strawberry.field(default_factory=list)
    entity_types: list[str] = strawberry.field(default_factory=list)

    # Options
    include_relationships: bool = True
    include_correlation: bool = True
    max_events: int = 1000

    def validate(self) -> list[str]:
        """Validate timeline query input."""
        errors = []

        if self.start_date >= self.end_date:
            errors.append("Start date must be before end date")

        # Limit timeline range
        delta = self.end_date - self.start_date
        if delta.days > 365:
            errors.append("Timeline range too large (max 365 days)")

        if self.max_events < 1 or self.max_events > 10000:
            errors.append("Max events must be between 1 and 10,000")

        if len(self.entity_ids) > 100:
            errors.append("Too many entity IDs (max 100)")

        return errors

    def to_criteria_dict(self) -> dict[str, Any]:
        """Convert to criteria dictionary."""
        return {
            "start_date": self.start_date,
            "end_date": self.end_date,
            "entity_ids": self.entity_ids,
            "entity_types": self.entity_types,
            "include_relationships": self.include_relationships,
            "include_correlation": self.include_correlation,
            "max_events": self.max_events,
        }


@strawberry.input
class ExecutiveSummaryInput:
    """Input type for executive summary generation."""

    # Summary configuration
    time_period: str = "30d"  # "7d", "30d", "90d", "365d"

    # Options
    include_trends: bool = True
    include_compliance_status: bool = True
    include_risk_metrics: bool = True

    def validate(self) -> list[str]:
        """Validate executive summary input."""
        errors = []

        valid_periods = ["7d", "30d", "90d", "365d"]
        if self.time_period not in valid_periods:
            errors.append(
                f"Invalid time period. Must be one of: {', '.join(valid_periods)}"
            )

        return errors


@strawberry.input
class PerformanceReportInput:
    """Input type for performance report generation."""

    # Report configuration
    date_range: DateRangeInput
    metrics: list[str]

    # Options
    include_trends: bool = True
    include_recommendations: bool = True

    def validate(self) -> list[str]:
        """Validate performance report input."""
        errors = []

        # Validate date range
        errors.extend(self.date_range.validate())

        if not self.metrics:
            errors.append("At least one metric is required")

        return errors
