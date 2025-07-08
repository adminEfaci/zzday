"""Audit report entity.

This module defines the AuditReport entity for generating
and managing audit reports.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.time_range import TimeRange


class AuditReport(Entity):
    """
    Represents a generated audit report.

    This entity encapsulates audit report generation, including
    summary statistics, aggregations, and formatted output.

    Attributes:
        report_type: Type of report (summary, detailed, compliance, etc.)
        title: Report title
        description: Report description
        time_range: Time period covered
        filters: Filters used to generate report
        generated_by: User who generated the report
        total_entries: Total number of audit entries
        summary_stats: Summary statistics
        aggregations: Data aggregations
        findings: Key findings or anomalies
        format: Output format (pdf, csv, json, etc.)
        file_path: Path to generated file (if applicable)
        status: Report generation status
        error_message: Error message if generation failed

    Business Rules:
        - Reports must have a valid time range
        - Summary stats must be consistent with total entries
        - Completed reports cannot be modified
    """

    # Report types
    REPORT_SUMMARY = "summary"
    REPORT_DETAILED = "detailed"
    REPORT_COMPLIANCE = "compliance"
    REPORT_SECURITY = "security"
    REPORT_USER_ACTIVITY = "user_activity"
    REPORT_RESOURCE_ACCESS = "resource_access"

    # Report formats
    FORMAT_JSON = "json"
    FORMAT_CSV = "csv"
    FORMAT_PDF = "pdf"
    FORMAT_HTML = "html"

    # Report statuses
    STATUS_PENDING = "pending"
    STATUS_GENERATING = "generating"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"

    def __init__(
        self,
        report_type: str,
        title: str,
        time_range: TimeRange,
        filters: AuditFilter,
        generated_by: UUID,
        description: str | None = None,
        format: str = FORMAT_JSON,
        entity_id: UUID | None = None,
    ):
        """
        Initialize audit report.

        Args:
            report_type: Type of report
            title: Report title
            time_range: Time period covered
            filters: Filters used
            generated_by: User generating report
            description: Optional description
            format: Output format
            entity_id: Report identifier

        Raises:
            ValidationError: If required fields are invalid
        """
        super().__init__(entity_id)

        # Validate and set report type
        self.report_type = self._validate_report_type(report_type)

        # Set basic fields
        self.validate_not_empty(title, "title")
        self.title = title.strip()
        self.description = description.strip() if description else None

        # Set time range and filters
        self.time_range = time_range
        self.filters = filters

        # Set user and format
        self.generated_by = generated_by
        self.format = self._validate_format(format)

        # Initialize statistics
        self.total_entries = 0
        self.summary_stats: dict[str, Any] = {}
        self.aggregations: dict[str, Any] = {}
        self.findings: list[dict[str, Any]] = []

        # Initialize status
        self.status = self.STATUS_PENDING
        self.file_path: str | None = None
        self.error_message: str | None = None

        # Generation timestamps
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None

    def _validate_report_type(self, report_type: str) -> str:
        """Validate report type."""
        valid_types = {
            self.REPORT_SUMMARY,
            self.REPORT_DETAILED,
            self.REPORT_COMPLIANCE,
            self.REPORT_SECURITY,
            self.REPORT_USER_ACTIVITY,
            self.REPORT_RESOURCE_ACCESS,
        }

        normalized = report_type.lower().strip()
        if normalized not in valid_types:
            raise ValidationError(
                f"Invalid report type: {report_type}. "
                f"Must be one of: {', '.join(valid_types)}"
            )

        return normalized

    def _validate_format(self, format: str) -> str:
        """Validate output format."""
        valid_formats = {
            self.FORMAT_JSON,
            self.FORMAT_CSV,
            self.FORMAT_PDF,
            self.FORMAT_HTML,
        }

        normalized = format.lower().strip()
        if normalized not in valid_formats:
            raise ValidationError(
                f"Invalid format: {format}. "
                f"Must be one of: {', '.join(valid_formats)}"
            )

        return normalized

    def start_generation(self) -> None:
        """Mark report generation as started."""
        if self.status != self.STATUS_PENDING:
            raise DomainError(f"Cannot start generation from status: {self.status}")

        self.status = self.STATUS_GENERATING
        self.started_at = datetime.utcnow()
        self.mark_modified()

    def complete_generation(
        self,
        total_entries: int,
        summary_stats: dict[str, Any],
        aggregations: dict[str, Any],
        findings: list[dict[str, Any]],
        file_path: str | None = None,
    ) -> None:
        """
        Mark report generation as completed.

        Args:
            total_entries: Total entries processed
            summary_stats: Summary statistics
            aggregations: Data aggregations
            findings: Key findings
            file_path: Path to generated file

        Raises:
            DomainError: If report is not in generating status
        """
        if self.status != self.STATUS_GENERATING:
            raise DomainError(f"Cannot complete generation from status: {self.status}")

        self.total_entries = total_entries
        self.summary_stats = summary_stats
        self.aggregations = aggregations
        self.findings = findings
        self.file_path = file_path

        self.status = self.STATUS_COMPLETED
        self.completed_at = datetime.utcnow()
        self.mark_modified()

    def fail_generation(self, error_message: str) -> None:
        """
        Mark report generation as failed.

        Args:
            error_message: Error description

        Raises:
            DomainError: If report is not in generating status
        """
        if self.status != self.STATUS_GENERATING:
            raise DomainError(f"Cannot fail generation from status: {self.status}")

        self.status = self.STATUS_FAILED
        self.error_message = error_message
        self.completed_at = datetime.utcnow()
        self.mark_modified()

    def is_pending(self) -> bool:
        """Check if report is pending generation."""
        return self.status == self.STATUS_PENDING

    def is_generating(self) -> bool:
        """Check if report is being generated."""
        return self.status == self.STATUS_GENERATING

    def is_completed(self) -> bool:
        """Check if report generation is completed."""
        return self.status == self.STATUS_COMPLETED

    def is_failed(self) -> bool:
        """Check if report generation failed."""
        return self.status == self.STATUS_FAILED

    def get_generation_duration(self) -> float | None:
        """
        Get generation duration in seconds.

        Returns:
            Duration in seconds, or None if not completed
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def get_severity_distribution(self) -> dict[str, int]:
        """Get distribution of entries by severity."""
        return self.aggregations.get("severity_distribution", {})

    def get_category_distribution(self) -> dict[str, int]:
        """Get distribution of entries by category."""
        return self.aggregations.get("category_distribution", {})

    def get_top_users(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get top users by activity."""
        users = self.aggregations.get("user_activity", [])
        return sorted(users, key=lambda x: x.get("count", 0), reverse=True)[:limit]

    def get_top_resources(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get top accessed resources."""
        resources = self.aggregations.get("resource_access", [])
        return sorted(resources, key=lambda x: x.get("count", 0), reverse=True)[:limit]

    def get_failure_rate(self) -> float:
        """Get overall failure rate."""
        if self.total_entries == 0:
            return 0.0

        failures = self.summary_stats.get("failure_count", 0)
        return (failures / self.total_entries) * 100

    def has_critical_findings(self) -> bool:
        """Check if report has critical findings."""
        return any(
            finding.get("severity") == AuditSeverity.CRITICAL.value
            for finding in self.findings
        )

    def get_finding_count_by_severity(self) -> dict[str, int]:
        """Get count of findings by severity."""
        counts = {}
        for finding in self.findings:
            severity = finding.get("severity", "unknown")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def add_finding(
        self,
        title: str,
        description: str,
        severity: AuditSeverity,
        affected_count: int,
        recommendation: str | None = None,
    ) -> None:
        """
        Add a finding to the report.

        Args:
            title: Finding title
            description: Finding description
            severity: Finding severity
            affected_count: Number of affected entries
            recommendation: Optional recommendation

        Raises:
            DomainError: If report is already completed
        """
        if self.status == self.STATUS_COMPLETED:
            raise DomainError("Cannot add findings to completed report")

        finding = {
            "title": title,
            "description": description,
            "severity": severity.value,
            "affected_count": affected_count,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if recommendation:
            finding["recommendation"] = recommendation

        self.findings.append(finding)
        self.mark_modified()

    def to_summary_dict(self) -> dict[str, Any]:
        """Get summary representation of the report."""
        summary = {
            "id": str(self.id),
            "type": self.report_type,
            "title": self.title,
            "description": self.description,
            "time_range": {
                "start": self.time_range.start_time.isoformat(),
                "end": self.time_range.end_time.isoformat(),
                "duration": self.time_range.format_duration(),
            },
            "status": self.status,
            "format": self.format,
            "generated_by": str(self.generated_by),
            "created_at": self.created_at.isoformat(),
        }

        if self.is_completed():
            summary.update(
                {
                    "total_entries": self.total_entries,
                    "failure_rate": self.get_failure_rate(),
                    "critical_findings": self.has_critical_findings(),
                    "finding_count": len(self.findings),
                    "generation_duration": self.get_generation_duration(),
                }
            )

        if self.is_failed():
            summary["error_message"] = self.error_message

        return summary

    @classmethod
    def create_compliance_report(
        cls,
        title: str,
        time_range: TimeRange,
        regulations: list[str],
        generated_by: UUID,
    ) -> "AuditReport":
        """Factory method for compliance reports."""
        # Create filter for compliance-relevant categories
        filters = AuditFilter(
            time_range=time_range,
            categories=[
                AuditCategory.AUTHENTICATION,
                AuditCategory.AUTHORIZATION,
                AuditCategory.DATA_ACCESS,
                AuditCategory.SECURITY,
            ],
        )

        description = f"Compliance report for regulations: {', '.join(regulations)}"

        return cls(
            report_type=cls.REPORT_COMPLIANCE,
            title=title,
            description=description,
            time_range=time_range,
            filters=filters,
            generated_by=generated_by,
            format=cls.FORMAT_PDF,
        )

    @classmethod
    def create_security_report(
        cls, time_range: TimeRange, generated_by: UUID
    ) -> "AuditReport":
        """Factory method for security reports."""
        filters = AuditFilter.create_for_security_review(time_range)

        return cls(
            report_type=cls.REPORT_SECURITY,
            title=f"Security Audit Report - {time_range.format_duration()}",
            description="Analysis of security-related audit events",
            time_range=time_range,
            filters=filters,
            generated_by=generated_by,
            format=cls.FORMAT_PDF,
        )


__all__ = ["AuditReport"]
