"""Get audit report query.

This module implements the query and handler for retrieving generated audit reports
with optional format conversion.
"""

from datetime import datetime
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_report_dto import AuditReportDTO

logger = get_logger(__name__)


class GetAuditReportQuery(Query):
    """
    Query to retrieve a generated audit report.

    Supports retrieving reports in various formats
    and with different levels of detail.
    """

    def __init__(
        self,
        report_id: UUID,
        format: str = "json",
        include_raw_data: bool = False,
        include_charts: bool = False,
    ):
        """
        Initialize get audit report query.

        Args:
            report_id: ID of the report to retrieve
            format: Output format (json, pdf, csv, xlsx)
            include_raw_data: Whether to include raw audit data
            include_charts: Whether to include chart data
        """
        super().__init__()

        self.report_id = self._validate_report_id(report_id)
        self.format = self._validate_format(format)
        self.include_raw_data = include_raw_data
        self.include_charts = include_charts

        self._freeze()

    def _validate_report_id(self, report_id: UUID) -> UUID:
        """Validate report ID."""
        if not isinstance(report_id, UUID):
            raise ValidationError("Report ID must be a valid UUID")
        return report_id

    def _validate_format(self, format: str) -> str:
        """Validate output format."""
        valid_formats = ["json", "pdf", "csv", "xlsx", "html"]
        if format not in valid_formats:
            raise ValidationError(
                f"Invalid format: {format}. Must be one of: {valid_formats}"
            )
        return format


class GetAuditReportQueryHandler(QueryHandler[GetAuditReportQuery, dict]):
    """
    Handler for retrieving audit reports.

    This handler fetches generated reports and optionally
    converts them to different formats.
    """

    def __init__(
        self, audit_repository: Any, reporting_service: Any, chart_service: Any
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for report persistence
            reporting_service: Service for format conversion
            chart_service: Service for chart generation
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.reporting_service = reporting_service
        self.chart_service = chart_service

    async def handle(self, query: GetAuditReportQuery) -> dict:
        """
        Handle the get audit report query.

        Args:
            query: Query containing retrieval parameters

        Returns:
            Dictionary containing report data

        Raises:
            NotFoundError: If report not found
        """
        logger.debug(
            "Retrieving audit report", report_id=query.report_id, format=query.format
        )

        # Retrieve report
        report = await self.audit_repository.find_report_by_id(query.report_id)
        if not report:
            raise NotFoundError(f"Audit report not found: {query.report_id}")

        # Convert to DTO
        report_dto = AuditReportDTO.from_domain(report)

        # Build base response
        response = {
            "report": report_dto.to_dict(),
            "metadata": {
                "retrieved_at": datetime.utcnow().isoformat(),
                "format": query.format,
                "report_status": report.status,
            },
        }

        # Include raw data if requested
        if query.include_raw_data:
            raw_data = await self._get_raw_report_data(report)
            response["raw_data"] = raw_data

        # Include charts if requested
        if query.include_charts:
            charts = await self._generate_report_charts(report)
            response["charts"] = charts

        # Convert to requested format if not JSON
        if query.format != "json":
            formatted_data = await self.reporting_service.format_report(
                report, format=query.format, include_charts=query.include_charts
            )

            if query.format in ["pdf", "xlsx"]:
                # For binary formats, return metadata and download info
                response["download"] = {
                    "format": query.format,
                    "size_bytes": len(formatted_data),
                    "filename": f"audit_report_{report.id}.{query.format}",
                    "content_type": self._get_content_type(query.format),
                }
                # Store the binary data for download
                response["binary_data"] = formatted_data
            else:
                # For text formats, include in response
                response["formatted_content"] = formatted_data

        logger.debug(
            "Audit report retrieved successfully",
            report_id=query.report_id,
            format=query.format,
            include_raw_data=query.include_raw_data,
        )

        return response

    async def _get_raw_report_data(self, report: Any) -> dict:
        """
        Get raw data used to generate the report.

        Args:
            report: Report entity

        Returns:
            Raw report data
        """
        # Fetch the original audit entries used for the report
        filters = report.filters.copy()
        filters.update(
            {
                "created_at__gte": report.time_range.start,
                "created_at__lte": report.time_range.end,
            }
        )

        entries = await self.audit_repository.find_entries(filters)

        return {
            "audit_entries": [entry.to_dict() for entry in entries],
            "query_filters": filters,
            "entry_count": len(entries),
        }

    async def _generate_report_charts(self, report: Any) -> dict:
        """
        Generate chart data for the report.

        Args:
            report: Report entity

        Returns:
            Chart data
        """
        charts = {}

        # Generate charts based on report type
        if report.report_type in ["security", "compliance"]:
            charts["severity_distribution"] = await self.chart_service.create_pie_chart(
                data=report.statistics.get("by_severity", {}),
                title="Events by Severity",
            )

            charts["category_distribution"] = await self.chart_service.create_pie_chart(
                data=report.statistics.get("by_category", {}),
                title="Events by Category",
            )

        if report.report_type == "activity":
            charts["activity_timeline"] = await self.chart_service.create_line_chart(
                data=report.statistics.get("entries_by_hour", {}),
                title="Activity Timeline",
                x_label="Time",
                y_label="Number of Events",
            )

        # Add trend charts if available
        if hasattr(report, "trends") and report.trends:
            for trend in report.trends:
                chart_name = f"trend_{trend['period']}"
                charts[chart_name] = await self.chart_service.create_trend_chart(
                    data=trend["data_points"],
                    title=f"Trend Analysis - {trend['period']}",
                    trend_direction=trend["trend_direction"],
                )

        return charts

    def _get_content_type(self, format: str) -> str:
        """Get MIME content type for format."""
        content_types = {
            "pdf": "application/pdf",
            "csv": "text/csv",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "html": "text/html",
            "json": "application/json",
        }
        return content_types.get(format, "application/octet-stream")

    @property
    def query_type(self) -> type[GetAuditReportQuery]:
        """Get query type this handler processes."""
        return GetAuditReportQuery


__all__ = ["GetAuditReportQuery", "GetAuditReportQueryHandler"]
