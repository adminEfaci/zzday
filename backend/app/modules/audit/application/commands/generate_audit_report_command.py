"""Generate audit report command.

This module implements the command and handler for generating audit reports,
supporting various report types and formats.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_report import AuditReport
from app.modules.audit.domain.value_objects.time_range import TimeRange

logger = get_logger(__name__)


class GenerateAuditReportCommand(Command):
    """
    Command to generate an audit report.

    Supports various report types including compliance,
    security, and performance analytics.
    """

    def __init__(
        self,
        report_type: str,
        title: str,
        time_range_start: datetime,
        time_range_end: datetime,
        description: str | None = None,
        filters: dict[str, Any] | None = None,
        include_statistics: bool = True,
        include_trends: bool = True,
        include_anomalies: bool = False,
        format: str = "json",
        requester_id: UUID | None = None,
    ):
        """
        Initialize generate audit report command.

        Args:
            report_type: Type of report to generate
            title: Report title
            time_range_start: Start of reporting period
            time_range_end: End of reporting period
            description: Optional report description
            filters: Additional filters to apply
            include_statistics: Include statistical analysis
            include_trends: Include trend analysis
            include_anomalies: Include anomaly detection
            format: Output format (json, pdf, csv)
            requester_id: User requesting the report
        """
        super().__init__()

        self.report_type = self._validate_report_type(report_type)
        self.title = self._validate_title(title)
        self.time_range_start = self._validate_datetime(time_range_start, "start date")
        self.time_range_end = self._validate_datetime(time_range_end, "end date")
        self.description = description
        self.filters = filters or {}
        self.include_statistics = include_statistics
        self.include_trends = include_trends
        self.include_anomalies = include_anomalies
        self.format = self._validate_format(format)
        self.requester_id = requester_id

        # Validate date range
        if self.time_range_start >= self.time_range_end:
            raise ValidationError("Start date must be before end date")

        self._freeze()

    def _validate_report_type(self, report_type: str) -> str:
        """Validate report type."""
        valid_types = [
            "security",
            "compliance",
            "activity",
            "performance",
            "user_activity",
            "system_events",
            "data_access",
            "administrative",
            "error_analysis",
        ]
        if report_type not in valid_types:
            raise ValidationError(
                f"Invalid report type: {report_type}. Must be one of: {valid_types}"
            )
        return report_type

    def _validate_title(self, title: str) -> str:
        """Validate title."""
        if not title or not title.strip():
            raise ValidationError("Report title cannot be empty")
        return title.strip()

    def _validate_datetime(self, dt: datetime, field_name: str) -> datetime:
        """Validate datetime."""
        if not isinstance(dt, datetime):
            raise ValidationError(f"{field_name} must be a valid datetime")
        return dt

    def _validate_format(self, format: str) -> str:
        """Validate output format."""
        valid_formats = ["json", "pdf", "csv", "xlsx", "html"]
        if format not in valid_formats:
            raise ValidationError(
                f"Invalid format: {format}. Must be one of: {valid_formats}"
            )
        return format


class GenerateAuditReportCommandHandler(
    CommandHandler[GenerateAuditReportCommand, AuditReport]
):
    """
    Handler for generating audit reports.

    This handler creates comprehensive audit reports with
    various analytics and insights.
    """

    def __init__(
        self,
        audit_repository: Any,
        reporting_service: Any,
        analytics_service: Any,
        event_publisher: Any,
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit data access
            reporting_service: Service for report generation
            analytics_service: Service for statistical analysis
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.reporting_service = reporting_service
        self.analytics_service = analytics_service
        self.event_publisher = event_publisher

    async def handle(self, command: GenerateAuditReportCommand) -> AuditReport:
        """
        Handle the generate audit report command.

        Args:
            command: Command containing report parameters

        Returns:
            Generated audit report
        """
        logger.info(
            "Generating audit report",
            report_type=command.report_type,
            time_range=f"{command.time_range_start} to {command.time_range_end}",
            requester_id=command.requester_id,
        )

        # Create time range
        time_range = TimeRange(
            start=command.time_range_start, end=command.time_range_end
        )

        # Create report entity
        report = AuditReport(
            report_type=command.report_type,
            title=command.title,
            description=command.description,
            time_range=time_range,
            filters=command.filters,
            generated_by=command.requester_id,
        )

        # Fetch audit data
        audit_entries = await self._fetch_audit_data(time_range, command.filters)

        # Generate statistics if requested
        if command.include_statistics:
            statistics = await self.analytics_service.generate_statistics(
                audit_entries, report_type=command.report_type
            )
            report.set_statistics(statistics)

        # Generate trends if requested
        if command.include_trends:
            trends = await self.analytics_service.analyze_trends(
                audit_entries, time_range=time_range
            )
            report.set_trends(trends)

        # Detect anomalies if requested
        if command.include_anomalies:
            anomalies = await self.analytics_service.detect_anomalies(
                audit_entries, sensitivity="medium"
            )
            report.set_anomalies(anomalies)

        # Generate report-specific content
        await self._populate_report_content(report, audit_entries, command)

        # Save report
        report.mark_completed()
        await self.audit_repository.save_report(report)

        # Generate output in requested format
        if command.format != "json":
            output_data = await self.reporting_service.format_report(
                report, format=command.format
            )
            report.set_output_data(command.format, output_data)
            await self.audit_repository.save_report(report)

        # Publish domain events
        for event in report.collect_events():
            await self.event_publisher.publish(event)

        logger.info(
            "Audit report generated successfully",
            report_id=report.id,
            entry_count=len(audit_entries),
            format=command.format,
        )

        return report

    async def _fetch_audit_data(
        self, time_range: TimeRange, filters: dict[str, Any]
    ) -> list[Any]:
        """
        Fetch audit data for the report.

        Args:
            time_range: Time range to fetch data for
            filters: Additional filters to apply

        Returns:
            List of audit entries
        """
        # Build query filters
        query_filters = {
            "created_at__gte": time_range.start,
            "created_at__lte": time_range.end,
        }
        query_filters.update(filters)

        # Fetch entries
        return await self.audit_repository.find_entries(query_filters)

    async def _populate_report_content(
        self,
        report: AuditReport,
        audit_entries: list[Any],
        command: GenerateAuditReportCommand,
    ) -> None:
        """
        Populate report with type-specific content.

        Args:
            report: Report entity to populate
            audit_entries: Audit entries to analyze
            command: Original command
        """
        if command.report_type == "security":
            await self._populate_security_content(report, audit_entries)
        elif command.report_type == "compliance":
            await self._populate_compliance_content(report, audit_entries)
        elif command.report_type == "user_activity":
            await self._populate_user_activity_content(report, audit_entries)
        elif command.report_type == "performance":
            await self._populate_performance_content(report, audit_entries)
        else:
            await self._populate_general_content(report, audit_entries)

    async def _populate_security_content(
        self, report: AuditReport, entries: list[Any]
    ) -> None:
        """Populate security-specific report content."""
        # Security events analysis
        security_events = [e for e in entries if e.category.value == "security"]

        # Failed authentication attempts
        failed_auth = [
            e
            for e in entries
            if e.action.action_type == "authenticate" and e.outcome == "failure"
        ]

        # Privilege escalations
        privilege_changes = [
            e
            for e in entries
            if e.action.action_type in ["grant_permission", "revoke_permission"]
        ]

        report.add_key_finding(f"Total security events: {len(security_events)}")
        report.add_key_finding(f"Failed authentication attempts: {len(failed_auth)}")
        report.add_key_finding(f"Privilege changes: {len(privilege_changes)}")

        # Set security metrics
        report.set_custom_metric("security_events_count", len(security_events))
        report.set_custom_metric("failed_auth_count", len(failed_auth))
        report.set_custom_metric("privilege_changes_count", len(privilege_changes))

    async def _populate_compliance_content(
        self, report: AuditReport, entries: list[Any]
    ) -> None:
        """Populate compliance-specific report content."""
        # Data access events
        data_access = [e for e in entries if e.category.value == "data_access"]

        # Administrative actions
        admin_actions = [e for e in entries if e.category.value == "configuration"]

        report.add_key_finding(f"Data access events: {len(data_access)}")
        report.add_key_finding(f"Administrative actions: {len(admin_actions)}")

        # Compliance metrics
        report.set_custom_metric("data_access_count", len(data_access))
        report.set_custom_metric("admin_actions_count", len(admin_actions))

    async def _populate_user_activity_content(
        self, report: AuditReport, entries: list[Any]
    ) -> None:
        """Populate user activity report content."""
        # User activity analysis
        user_entries = [e for e in entries if e.user_id is not None]
        unique_users = len({e.user_id for e in user_entries})

        report.add_key_finding(f"Active users: {unique_users}")
        report.add_key_finding(f"User actions: {len(user_entries)}")

        report.set_custom_metric("active_users", unique_users)
        report.set_custom_metric("user_actions", len(user_entries))

    async def _populate_performance_content(
        self, report: AuditReport, entries: list[Any]
    ) -> None:
        """Populate performance report content."""
        # Performance analysis
        timed_entries = [e for e in entries if e.duration_ms is not None]

        if timed_entries:
            avg_duration = sum(e.duration_ms for e in timed_entries) / len(
                timed_entries
            )
            max_duration = max(e.duration_ms for e in timed_entries)

            report.add_key_finding(f"Average operation duration: {avg_duration:.2f}ms")
            report.add_key_finding(f"Maximum operation duration: {max_duration}ms")

            report.set_custom_metric("avg_duration_ms", avg_duration)
            report.set_custom_metric("max_duration_ms", max_duration)

    async def _populate_general_content(
        self, report: AuditReport, entries: list[Any]
    ) -> None:
        """Populate general report content."""
        report.add_key_finding(f"Total audit entries: {len(entries)}")

        # Success rate
        successful = len([e for e in entries if e.outcome == "success"])
        success_rate = (successful / len(entries)) * 100 if entries else 0

        report.add_key_finding(f"Success rate: {success_rate:.1f}%")
        report.set_custom_metric("success_rate", success_rate)

    @property
    def command_type(self) -> type[GenerateAuditReportCommand]:
        """Get command type this handler processes."""
        return GenerateAuditReportCommand


__all__ = ["GenerateAuditReportCommand", "GenerateAuditReportCommandHandler"]
