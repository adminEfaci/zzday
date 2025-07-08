"""Audit report DTO.

This module defines the Data Transfer Object for audit reports,
providing structured report data for external consumption.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AuditStatisticsDTO:
    """DTO for audit statistics."""

    total_entries: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_outcome: dict[str, int]
    by_user: dict[str, int]
    by_resource_type: dict[str, int]

    # Time-based statistics
    entries_by_hour: dict[str, int]
    entries_by_day: dict[str, int]

    # Performance metrics
    average_duration_ms: float | None
    max_duration_ms: int | None
    min_duration_ms: int | None

    # Error statistics
    error_rate: float
    errors_by_type: dict[str, int]


@dataclass(frozen=True)
class AuditTrendDTO:
    """DTO for audit trends."""

    period: str  # "hour", "day", "week", "month"
    data_points: list[dict[str, Any]]
    trend_direction: str  # "increasing", "decreasing", "stable"
    change_percentage: float


@dataclass(frozen=True)
class AuditReportDTO:
    """
    Data Transfer Object for audit reports.

    Provides comprehensive audit analytics and insights
    for reporting and monitoring purposes.
    """

    # Report identity
    report_id: UUID
    report_type: str
    generated_at: datetime
    generated_by: UUID | None

    # Report parameters
    title: str
    description: str | None
    time_range_start: datetime
    time_range_end: datetime
    filters_applied: dict[str, Any]

    # Statistics
    statistics: AuditStatisticsDTO

    # Trends
    trends: list[AuditTrendDTO] = field(default_factory=list)

    # Key findings
    key_findings: list[str] = field(default_factory=list)
    anomalies_detected: list[dict[str, Any]] = field(default_factory=list)

    # Top items
    top_users: list[dict[str, Any]] = field(default_factory=list)
    top_resources: list[dict[str, Any]] = field(default_factory=list)
    top_actions: list[dict[str, Any]] = field(default_factory=list)

    # Compliance summary
    compliance_summary: dict[str, Any] = field(default_factory=dict)

    # Security insights
    security_events: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float | None = None

    # Export formats
    available_formats: list[str] = field(default_factory=lambda: ["json", "pdf", "csv"])

    @classmethod
    def from_domain(cls, report: Any) -> "AuditReportDTO":
        """
        Create DTO from domain report entity.

        Args:
            report: Domain audit report

        Returns:
            AuditReportDTO instance
        """
        # Build statistics DTO
        stats = AuditStatisticsDTO(
            total_entries=report.statistics.get("total_entries", 0),
            by_severity=report.statistics.get("by_severity", {}),
            by_category=report.statistics.get("by_category", {}),
            by_outcome=report.statistics.get("by_outcome", {}),
            by_user=report.statistics.get("by_user", {}),
            by_resource_type=report.statistics.get("by_resource_type", {}),
            entries_by_hour=report.statistics.get("entries_by_hour", {}),
            entries_by_day=report.statistics.get("entries_by_day", {}),
            average_duration_ms=report.statistics.get("average_duration_ms"),
            max_duration_ms=report.statistics.get("max_duration_ms"),
            min_duration_ms=report.statistics.get("min_duration_ms"),
            error_rate=report.statistics.get("error_rate", 0.0),
            errors_by_type=report.statistics.get("errors_by_type", {}),
        )

        # Build trend DTOs
        trends = []
        for trend in report.trends:
            trends.append(
                AuditTrendDTO(
                    period=trend["period"],
                    data_points=trend["data_points"],
                    trend_direction=trend["trend_direction"],
                    change_percentage=trend["change_percentage"],
                )
            )

        return cls(
            report_id=report.id,
            report_type=report.report_type,
            generated_at=report.generated_at,
            generated_by=report.generated_by,
            title=report.title,
            description=report.description,
            time_range_start=report.time_range.start,
            time_range_end=report.time_range.end,
            filters_applied=report.filters,
            statistics=stats,
            trends=trends,
            key_findings=report.key_findings,
            anomalies_detected=report.anomalies,
            top_users=report.top_users[:10],
            top_resources=report.top_resources[:10],
            top_actions=report.top_actions[:10],
            compliance_summary=report.compliance_summary,
            security_events=report.security_events,
            risk_score=report.risk_score,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "report_id": str(self.report_id),
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": str(self.generated_by) if self.generated_by else None,
            "title": self.title,
            "description": self.description,
            "time_range": {
                "start": self.time_range_start.isoformat(),
                "end": self.time_range_end.isoformat(),
            },
            "filters_applied": self.filters_applied,
            "statistics": {
                "total_entries": self.statistics.total_entries,
                "by_severity": self.statistics.by_severity,
                "by_category": self.statistics.by_category,
                "by_outcome": self.statistics.by_outcome,
                "by_user": self.statistics.by_user,
                "by_resource_type": self.statistics.by_resource_type,
                "entries_by_hour": self.statistics.entries_by_hour,
                "entries_by_day": self.statistics.entries_by_day,
                "average_duration_ms": self.statistics.average_duration_ms,
                "max_duration_ms": self.statistics.max_duration_ms,
                "min_duration_ms": self.statistics.min_duration_ms,
                "error_rate": self.statistics.error_rate,
                "errors_by_type": self.statistics.errors_by_type,
            },
            "trends": [
                {
                    "period": t.period,
                    "data_points": t.data_points,
                    "trend_direction": t.trend_direction,
                    "change_percentage": t.change_percentage,
                }
                for t in self.trends
            ],
            "key_findings": self.key_findings,
            "anomalies_detected": self.anomalies_detected,
            "top_users": self.top_users,
            "top_resources": self.top_resources,
            "top_actions": self.top_actions,
            "compliance_summary": self.compliance_summary,
            "security_events": self.security_events,
            "risk_score": self.risk_score,
            "available_formats": self.available_formats,
        }


__all__ = ["AuditReportDTO", "AuditStatisticsDTO", "AuditTrendDTO"]
