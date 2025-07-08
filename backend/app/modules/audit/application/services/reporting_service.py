"""Reporting service.

This module provides audit reporting functionality including
report generation, formatting, and export capabilities.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


class ReportingService:
    """
    Application service for audit reporting.

    Provides comprehensive reporting capabilities including
    various formats, templates, and distribution options.
    """

    def __init__(
        self, audit_repository: Any, template_engine: Any, export_service: Any
    ):
        """
        Initialize reporting service.

        Args:
            audit_repository: Repository for audit data
            template_engine: Template engine for report formatting
            export_service: Service for export operations
        """
        self.audit_repository = audit_repository
        self.template_engine = template_engine
        self.export_service = export_service

    async def generate_standard_report(
        self,
        report_type: str,
        start_date: datetime,
        end_date: datetime,
        filters: dict[str, Any] | None = None,
        format: str = "json",
    ) -> dict[str, Any]:
        """
        Generate a standard audit report.

        Args:
            report_type: Type of report to generate
            start_date: Report period start
            end_date: Report period end
            filters: Additional filters
            format: Output format

        Returns:
            Generated report data
        """
        logger.info(
            "Generating standard report", report_type=report_type, format=format
        )

        # Validate report type
        if report_type not in self._get_supported_report_types():
            raise ValidationError(f"Unsupported report type: {report_type}")

        # Build query filters
        query_filters = {"created_at__gte": start_date, "created_at__lte": end_date}

        if filters:
            query_filters.update(filters)

        # Fetch audit data
        audit_entries = await self.audit_repository.find_entries(query_filters)

        # Generate report based on type
        report_data = await self._generate_report_by_type(
            report_type, audit_entries, start_date, end_date
        )

        # Format report if not JSON
        if format != "json":
            formatted_data = await self.format_report_output(report_data, format)
            return {
                "report": report_data,
                "formatted_output": formatted_data,
                "format": format,
            }

        return {"report": report_data, "format": format}

    async def generate_custom_report(
        self,
        template_id: str,
        data_query: dict[str, Any],
        parameters: dict[str, Any] | None = None,
        format: str = "json",
    ) -> dict[str, Any]:
        """
        Generate a custom report using a template.

        Args:
            template_id: Report template identifier
            data_query: Query for collecting data
            parameters: Template parameters
            format: Output format

        Returns:
            Generated custom report
        """
        logger.info("Generating custom report", template_id=template_id)

        # Get template
        template = await self._get_report_template(template_id)
        if not template:
            raise ValidationError(f"Report template not found: {template_id}")

        # Execute data query
        report_data = await self._execute_data_query(data_query)

        # Apply template
        rendered_report = await self.template_engine.render(
            template, data=report_data, parameters=parameters or {}
        )

        # Format output
        if format != "json":
            formatted_output = await self.format_report_output(rendered_report, format)
            return {
                "report": rendered_report,
                "formatted_output": formatted_output,
                "format": format,
            }

        return {"report": rendered_report, "format": format}

    async def format_report_output(
        self, report_data: dict[str, Any], format: str
    ) -> str | bytes:
        """
        Format report data to specified output format.

        Args:
            report_data: Report data to format
            format: Target format

        Returns:
            Formatted report content
        """
        logger.debug("Formatting report output", format=format)

        if format == "json":
            return json.dumps(report_data, indent=2, default=str)

        if format == "csv":
            return await self._format_as_csv(report_data)

        if format == "pdf":
            return await self._format_as_pdf(report_data)

        if format == "xlsx":
            return await self._format_as_xlsx(report_data)

        if format == "html":
            return await self._format_as_html(report_data)

        raise ValidationError(f"Unsupported format: {format}")

    async def schedule_report(
        self,
        report_config: dict[str, Any],
        schedule: str,
        recipients: list[str],
        delivery_options: dict[str, Any] | None = None,
    ) -> UUID:
        """
        Schedule a recurring report.

        Args:
            report_config: Report configuration
            schedule: Schedule expression (cron format)
            recipients: List of recipient email addresses
            delivery_options: Delivery configuration

        Returns:
            Scheduled report ID
        """
        logger.info("Scheduling report", recipients=recipients)

        # Validate schedule expression
        if not self._validate_schedule_expression(schedule):
            raise ValidationError(f"Invalid schedule expression: {schedule}")

        # Create scheduled report record
        scheduled_report = {
            "id": UUID(),
            "report_config": report_config,
            "schedule": schedule,
            "recipients": recipients,
            "delivery_options": delivery_options or {},
            "created_at": datetime.utcnow(),
            "is_active": True,
            "last_run": None,
            "next_run": self._calculate_next_run(schedule),
        }

        # Save scheduled report
        await self.audit_repository.save_scheduled_report(scheduled_report)

        logger.info(
            "Report scheduled successfully",
            report_id=scheduled_report["id"],
            schedule=schedule,
        )

        return scheduled_report["id"]

    async def get_report_templates(self) -> list[dict[str, Any]]:
        """
        Get available report templates.

        Returns:
            List of available templates
        """
        return [
            {
                "id": "security_summary",
                "name": "Security Summary Report",
                "description": "Summary of security events and incidents",
                "parameters": ["severity_filter", "include_incidents"],
                "supported_formats": ["json", "pdf", "html"],
            },
            {
                "id": "compliance_audit",
                "name": "Compliance Audit Report",
                "description": "Detailed compliance assessment report",
                "parameters": ["framework", "scope", "assessment_period"],
                "supported_formats": ["json", "pdf", "docx"],
            },
            {
                "id": "user_activity",
                "name": "User Activity Report",
                "description": "Analysis of user activities and behaviors",
                "parameters": ["user_filter", "activity_types", "anomaly_detection"],
                "supported_formats": ["json", "csv", "xlsx"],
            },
            {
                "id": "system_performance",
                "name": "System Performance Report",
                "description": "System audit and performance metrics",
                "parameters": ["metrics", "thresholds", "trend_analysis"],
                "supported_formats": ["json", "pdf", "html"],
            },
            {
                "id": "data_access",
                "name": "Data Access Report",
                "description": "Data access patterns and compliance",
                "parameters": [
                    "data_categories",
                    "access_patterns",
                    "privacy_controls",
                ],
                "supported_formats": ["json", "pdf", "csv"],
            },
        ]

    async def export_audit_data(
        self,
        export_config: dict[str, Any],
        format: str = "csv",
        compression: bool = False,
    ) -> dict[str, Any]:
        """
        Export audit data for external analysis.

        Args:
            export_config: Export configuration and filters
            format: Export format
            compression: Whether to compress the export

        Returns:
            Export metadata and download information
        """
        logger.info("Exporting audit data", format=format)

        # Validate export configuration
        self._validate_export_config(export_config)

        # Fetch data based on configuration
        audit_data = await self._fetch_export_data(export_config)

        # Format data
        formatted_data = await self.format_report_output(audit_data, format)

        # Compress if requested
        if compression:
            formatted_data = await self.export_service.compress_data(
                formatted_data,
                f"audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            )

        # Store export file
        return await self.export_service.store_export(
            formatted_data,
            metadata={
                "export_config": export_config,
                "format": format,
                "compressed": compression,
                "record_count": len(audit_data.get("entries", [])),
                "exported_at": datetime.utcnow().isoformat(),
            },
        )

    def _get_supported_report_types(self) -> list[str]:
        """Get list of supported report types."""
        return [
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

    async def _generate_report_by_type(
        self,
        report_type: str,
        audit_entries: list[Any],
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any]:
        """Generate report based on type."""
        base_report = {
            "report_type": report_type,
            "generated_at": datetime.utcnow().isoformat(),
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "entry_count": len(audit_entries),
        }

        if report_type == "security":
            return await self._generate_security_report(base_report, audit_entries)
        if report_type == "compliance":
            return await self._generate_compliance_report(base_report, audit_entries)
        if report_type == "user_activity":
            return await self._generate_user_activity_report(base_report, audit_entries)
        if report_type == "performance":
            return await self._generate_performance_report(base_report, audit_entries)
        return await self._generate_general_report(base_report, audit_entries)

    async def _generate_security_report(
        self, base_report: dict[str, Any], entries: list[Any]
    ) -> dict[str, Any]:
        """Generate security-focused report."""
        security_entries = [e for e in entries if e.category.value == "security"]

        # Security metrics
        failed_auth = len(
            [
                e
                for e in security_entries
                if "authenticate" in e.action.action_type.lower()
                and e.outcome == "failure"
            ]
        )

        privilege_changes = len(
            [
                e
                for e in security_entries
                if "permission" in e.action.action_type.lower()
            ]
        )

        critical_events = len(
            [e for e in security_entries if e.severity.value == "critical"]
        )

        base_report.update(
            {
                "security_metrics": {
                    "total_security_events": len(security_entries),
                    "failed_authentications": failed_auth,
                    "privilege_changes": privilege_changes,
                    "critical_security_events": critical_events,
                },
                "top_security_events": self._get_top_events(
                    security_entries, "action_type"
                ),
                "severity_distribution": self._get_severity_distribution(
                    security_entries
                ),
                "security_recommendations": self._generate_security_recommendations(
                    security_entries
                ),
            }
        )

        return base_report

    async def _generate_compliance_report(
        self, base_report: dict[str, Any], entries: list[Any]
    ) -> dict[str, Any]:
        """Generate compliance-focused report."""
        compliance_entries = [e for e in entries if e.category.value == "compliance"]
        data_access_entries = [e for e in entries if e.category.value == "data_access"]

        base_report.update(
            {
                "compliance_metrics": {
                    "compliance_events": len(compliance_entries),
                    "data_access_events": len(data_access_entries),
                    "violations": len(
                        [e for e in compliance_entries if e.outcome == "failure"]
                    ),
                    "data_breach_indicators": len(
                        [
                            e
                            for e in data_access_entries
                            if e.severity.value in ["high", "critical"]
                        ]
                    ),
                },
                "compliance_categories": self._get_category_distribution(
                    compliance_entries
                ),
                "data_access_patterns": self._analyze_data_access_patterns(
                    data_access_entries
                ),
                "compliance_recommendations": self._generate_compliance_recommendations(
                    entries
                ),
            }
        )

        return base_report

    async def _generate_user_activity_report(
        self, base_report: dict[str, Any], entries: list[Any]
    ) -> dict[str, Any]:
        """Generate user activity report."""
        user_entries = [e for e in entries if e.user_id is not None]

        # User metrics
        unique_users = len({e.user_id for e in user_entries})
        user_activity = {}
        for entry in user_entries:
            user_id = str(entry.user_id)
            if user_id not in user_activity:
                user_activity[user_id] = {"total": 0, "success": 0, "failure": 0}

            user_activity[user_id]["total"] += 1
            if entry.outcome == "success":
                user_activity[user_id]["success"] += 1
            else:
                user_activity[user_id]["failure"] += 1

        # Top active users
        top_users = sorted(
            user_activity.items(), key=lambda x: x[1]["total"], reverse=True
        )[:10]

        base_report.update(
            {
                "user_metrics": {
                    "unique_active_users": unique_users,
                    "total_user_actions": len(user_entries),
                    "average_actions_per_user": len(user_entries)
                    / max(1, unique_users),
                },
                "top_active_users": [
                    {"user_id": uid, "activity": stats} for uid, stats in top_users
                ],
                "activity_patterns": self._analyze_activity_patterns(user_entries),
                "user_recommendations": self._generate_user_recommendations(
                    user_entries
                ),
            }
        )

        return base_report

    async def _generate_performance_report(
        self, base_report: dict[str, Any], entries: list[Any]
    ) -> dict[str, Any]:
        """Generate performance report."""
        timed_entries = [e for e in entries if e.duration_ms is not None]

        if timed_entries:
            durations = [e.duration_ms for e in timed_entries]
            avg_duration = sum(durations) / len(durations)
            max_duration = max(durations)
            min_duration = min(durations)

            # Performance thresholds
            slow_operations = len([d for d in durations if d > 5000])  # > 5 seconds
            very_slow_operations = len(
                [d for d in durations if d > 30000]
            )  # > 30 seconds
        else:
            avg_duration = max_duration = min_duration = 0
            slow_operations = very_slow_operations = 0

        base_report.update(
            {
                "performance_metrics": {
                    "total_timed_operations": len(timed_entries),
                    "average_duration_ms": round(avg_duration, 2),
                    "max_duration_ms": max_duration,
                    "min_duration_ms": min_duration,
                    "slow_operations": slow_operations,
                    "very_slow_operations": very_slow_operations,
                },
                "performance_trends": self._analyze_performance_trends(timed_entries),
                "slowest_operations": self._get_slowest_operations(timed_entries),
                "performance_recommendations": self._generate_performance_recommendations(
                    timed_entries
                ),
            }
        )

        return base_report

    async def _generate_general_report(
        self, base_report: dict[str, Any], entries: list[Any]
    ) -> dict[str, Any]:
        """Generate general audit report."""
        base_report.update(
            {
                "general_metrics": {
                    "total_entries": len(entries),
                    "success_rate": (
                        len([e for e in entries if e.outcome == "success"])
                        / len(entries)
                        * 100
                    )
                    if entries
                    else 0,
                    "categories": self._get_category_distribution(entries),
                    "severity_levels": self._get_severity_distribution(entries),
                },
                "top_actions": self._get_top_events(entries, "action_type"),
                "top_resources": self._get_top_events(entries, "resource_type"),
                "temporal_analysis": self._analyze_temporal_patterns(entries),
            }
        )

        return base_report

    # Helper methods for report generation

    def _get_top_events(self, entries: list[Any], field: str) -> list[dict[str, Any]]:
        """Get top events by specified field."""
        event_counts = {}
        for entry in entries:
            if field == "action_type":
                key = entry.action.action_type
            elif field == "resource_type":
                key = entry.resource.resource_type
            else:
                continue

            event_counts[key] = event_counts.get(key, 0) + 1

        return [
            {"type": event_type, "count": count}
            for event_type, count in sorted(
                event_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

    def _get_severity_distribution(self, entries: list[Any]) -> dict[str, int]:
        """Get distribution of entries by severity."""
        distribution = {}
        for entry in entries:
            severity = entry.severity.value
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution

    def _get_category_distribution(self, entries: list[Any]) -> dict[str, int]:
        """Get distribution of entries by category."""
        distribution = {}
        for entry in entries:
            category = entry.category.value
            distribution[category] = distribution.get(category, 0) + 1
        return distribution

    def _analyze_data_access_patterns(self, entries: list[Any]) -> dict[str, Any]:
        """Analyze data access patterns."""
        if not entries:
            return {"message": "No data access entries found"}

        # Group by resource type
        by_resource_type = {}
        for entry in entries:
            resource_type = entry.resource.resource_type
            by_resource_type[resource_type] = by_resource_type.get(resource_type, 0) + 1

        return {
            "total_data_access_events": len(entries),
            "by_resource_type": by_resource_type,
            "unique_resources_accessed": len(
                {entry.resource.resource_id for entry in entries}
            ),
        }

    def _analyze_activity_patterns(self, entries: list[Any]) -> dict[str, Any]:
        """Analyze user activity patterns."""
        if not entries:
            return {"message": "No user activity entries found"}

        # Analyze by hour of day
        hourly_activity = {}
        for entry in entries:
            hour = entry.created_at.hour
            hourly_activity[hour] = hourly_activity.get(hour, 0) + 1

        peak_hour = (
            max(hourly_activity.items(), key=lambda x: x[1])[0]
            if hourly_activity
            else None
        )

        return {
            "hourly_distribution": hourly_activity,
            "peak_activity_hour": peak_hour,
            "activity_spread": len(
                hourly_activity
            ),  # How many different hours had activity
        }

    def _analyze_performance_trends(self, entries: list[Any]) -> dict[str, Any]:
        """Analyze performance trends."""
        if not entries:
            return {"message": "No performance data available"}

        # Group by hour and calculate average duration
        hourly_performance = {}
        for entry in entries:
            hour_key = entry.created_at.strftime("%Y-%m-%d %H:00")
            if hour_key not in hourly_performance:
                hourly_performance[hour_key] = []
            hourly_performance[hour_key].append(entry.duration_ms)

        # Calculate averages
        hourly_averages = {
            hour: sum(durations) / len(durations)
            for hour, durations in hourly_performance.items()
        }

        return {"hourly_averages": hourly_averages, "data_points": len(hourly_averages)}

    def _get_slowest_operations(self, entries: list[Any]) -> list[dict[str, Any]]:
        """Get slowest operations."""
        if not entries:
            return []

        sorted_entries = sorted(entries, key=lambda e: e.duration_ms, reverse=True)

        return [
            {
                "action_type": entry.action.action_type,
                "resource_type": entry.resource.resource_type,
                "duration_ms": entry.duration_ms,
                "created_at": entry.created_at.isoformat(),
            }
            for entry in sorted_entries[:10]
        ]

    def _analyze_temporal_patterns(self, entries: list[Any]) -> dict[str, Any]:
        """Analyze temporal patterns in audit data."""
        if not entries:
            return {"message": "No entries to analyze"}

        # Group by date
        daily_counts = {}
        for entry in entries:
            date_key = entry.created_at.date().isoformat()
            daily_counts[date_key] = daily_counts.get(date_key, 0) + 1

        return {
            "daily_activity": daily_counts,
            "active_days": len(daily_counts),
            "average_daily_activity": sum(daily_counts.values()) / len(daily_counts)
            if daily_counts
            else 0,
        }

    # Recommendation generators

    def _generate_security_recommendations(self, entries: list[Any]) -> list[str]:
        """Generate security recommendations."""
        recommendations = []

        failed_auth_count = len(
            [
                e
                for e in entries
                if "authenticate" in e.action.action_type.lower()
                and e.outcome == "failure"
            ]
        )

        if failed_auth_count > 10:
            recommendations.append(
                "High number of failed authentication attempts detected - consider implementing account lockout policies"
            )

        critical_count = len([e for e in entries if e.severity.value == "critical"])
        if critical_count > 0:
            recommendations.append(
                f"{critical_count} critical security events require immediate investigation"
            )

        recommendations.append("Enable real-time security monitoring and alerting")

        return recommendations

    def _generate_compliance_recommendations(self, entries: list[Any]) -> list[str]:
        """Generate compliance recommendations."""
        recommendations = []

        violation_count = len([e for e in entries if e.outcome == "failure"])
        if violation_count > 0:
            recommendations.append(
                f"Address {violation_count} compliance violations identified"
            )

        recommendations.extend(
            [
                "Implement continuous compliance monitoring",
                "Document all compliance procedures and controls",
                "Conduct regular compliance assessments",
            ]
        )

        return recommendations

    def _generate_user_recommendations(self, entries: list[Any]) -> list[str]:
        """Generate user activity recommendations."""
        recommendations = []

        if entries:
            unique_users = len({e.user_id for e in entries})
            if unique_users > 100:
                recommendations.append(
                    "Consider implementing user behavior analytics for large user base"
                )

        recommendations.extend(
            [
                "Monitor for unusual user activity patterns",
                "Implement user access reviews",
                "Provide security awareness training",
            ]
        )

        return recommendations

    def _generate_performance_recommendations(self, entries: list[Any]) -> list[str]:
        """Generate performance recommendations."""
        recommendations = []

        if entries:
            slow_ops = len([e for e in entries if e.duration_ms > 5000])
            if slow_ops > 0:
                recommendations.append(
                    f"Investigate {slow_ops} slow operations for performance optimization"
                )

        recommendations.extend(
            [
                "Implement performance monitoring and alerting",
                "Set up automated performance baselines",
                "Regular performance optimization reviews",
            ]
        )

        return recommendations

    # Format-specific methods

    async def _format_as_csv(self, report_data: dict[str, Any]) -> str:
        """Format report as CSV."""
        output = io.StringIO()

        # Extract tabular data from report
        if "entries" in report_data:
            # Format as audit entries
            writer = csv.writer(output)

            # Write header
            writer.writerow(
                [
                    "timestamp",
                    "user_id",
                    "action_type",
                    "resource_type",
                    "resource_id",
                    "outcome",
                    "severity",
                    "category",
                ]
            )

            # Write data rows
            for entry in report_data["entries"]:
                writer.writerow(
                    [
                        entry.get("created_at", ""),
                        entry.get("user_id", ""),
                        entry.get("action_type", ""),
                        entry.get("resource_type", ""),
                        entry.get("resource_id", ""),
                        entry.get("outcome", ""),
                        entry.get("severity", ""),
                        entry.get("category", ""),
                    ]
                )
        else:
            # Format as key-value pairs
            writer = csv.writer(output)
            writer.writerow(["Metric", "Value"])

            def write_dict(data, prefix=""):
                for key, value in data.items():
                    if isinstance(value, dict):
                        write_dict(value, f"{prefix}{key}.")
                    elif isinstance(value, list):
                        writer.writerow([f"{prefix}{key}", f"[{len(value)} items]"])
                    else:
                        writer.writerow([f"{prefix}{key}", str(value)])

            write_dict(report_data)

        return output.getvalue()

    async def _format_as_pdf(self, report_data: dict[str, Any]) -> bytes:
        """Format report as PDF."""
        # This would use a PDF generation library
        # For now, return placeholder
        pdf_content = f"PDF Report Generated at {datetime.utcnow()}\n\n"
        pdf_content += json.dumps(report_data, indent=2, default=str)

        return pdf_content.encode("utf-8")

    async def _format_as_xlsx(self, report_data: dict[str, Any]) -> bytes:
        """Format report as Excel file."""
        # This would use a library like openpyxl
        # For now, return placeholder
        excel_content = f"Excel Report Generated at {datetime.utcnow()}\n\n"
        excel_content += json.dumps(report_data, indent=2, default=str)

        return excel_content.encode("utf-8")

    async def _format_as_html(self, report_data: dict[str, Any]) -> str:
        """Format report as HTML."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 10px; }
                .metric { margin: 10px 0; padding: 5px; border-left: 3px solid #007acc; }
                .data { background-color: #f9f9f9; padding: 10px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Audit Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            <div class="content">
                {content}
            </div>
        </body>
        </html>
        """

        # Convert report data to HTML
        content = self._dict_to_html(report_data)

        return html_template.format(
            timestamp=datetime.utcnow().isoformat(), content=content
        )

    def _dict_to_html(self, data: dict[str, Any], level: int = 0) -> str:
        """Convert dictionary to HTML representation."""
        html = ""

        for key, value in data.items():
            if isinstance(value, dict):
                html += f"<div class='metric'><h{min(6, level+2)}>{key}</h{min(6, level+2)}>"
                html += self._dict_to_html(value, level + 1)
                html += "</div>"
            elif isinstance(value, list):
                html += f"<div class='metric'><strong>{key}:</strong> [{len(value)} items]</div>"
            else:
                html += f"<div class='metric'><strong>{key}:</strong> {value}</div>"

        return html

    # Utility methods

    async def _get_report_template(self, template_id: str) -> dict[str, Any] | None:
        """Get report template by ID."""
        # This would fetch from template repository
        # For now, return a simple template
        return {
            "id": template_id,
            "name": f"Template {template_id}",
            "content": "Report template content",
        }

    async def _execute_data_query(self, query: dict[str, Any]) -> dict[str, Any]:
        """Execute data query for custom reports."""
        # Execute the query against audit repository
        return await self.audit_repository.execute_custom_query(query)

    def _validate_schedule_expression(self, schedule: str) -> bool:
        """Validate cron schedule expression."""
        # Simple validation - would use proper cron parser
        parts = schedule.split()
        return len(parts) == 5  # Basic cron format check

    def _calculate_next_run(self, schedule: str) -> datetime:
        """Calculate next run time from schedule."""
        # Simplified - would use proper cron library
        return datetime.utcnow() + timedelta(hours=24)

    def _validate_export_config(self, config: dict[str, Any]) -> None:
        """Validate export configuration."""
        required_fields = ["filters", "fields"]
        for field in required_fields:
            if field not in config:
                raise ValidationError(f"Missing required export config field: {field}")

    async def _fetch_export_data(self, config: dict[str, Any]) -> dict[str, Any]:
        """Fetch data for export based on configuration."""
        filters = config.get("filters", {})
        fields = config.get("fields", [])

        entries = await self.audit_repository.find_entries(filters)

        # Project only requested fields if specified
        if fields:
            projected_entries = []
            for entry in entries:
                projected_entry = {}
                for field in fields:
                    if hasattr(entry, field):
                        projected_entry[field] = getattr(entry, field)
                projected_entries.append(projected_entry)
            entries = projected_entries

        return {
            "entries": entries,
            "metadata": {
                "total_count": len(entries),
                "exported_at": datetime.utcnow().isoformat(),
                "config": config,
            },
        }


__all__ = ["ReportingService"]
