"""GraphQL input types for report generation."""

from typing import Any

import strawberry

from ..enums import ExportFormatEnum, ReportTypeEnum
from .filter_input import DateRangeInput


@strawberry.input
class ReportParametersInput:
    """Input type for report parameters."""

    # Time range
    time_range: DateRangeInput

    # Report scope
    include_user_activity: bool = True
    include_system_events: bool = True
    include_security_events: bool = True
    include_compliance_data: bool = True
    include_performance_metrics: bool = True

    # Filtering
    user_ids: list[strawberry.ID] = strawberry.field(default_factory=list)
    resource_types: list[str] = strawberry.field(default_factory=list)
    severity_threshold: str | None = None  # Minimum severity to include

    # Analytics options
    include_trends: bool = True
    include_anomalies: bool = True
    include_recommendations: bool = True
    trend_period: str = "day"  # "hour", "day", "week", "month"

    # Grouping options
    group_by_user: bool = False
    group_by_resource: bool = False
    group_by_time: bool = True

    def validate(self) -> list[str]:
        """Validate report parameters."""
        errors = []

        # Validate time range
        errors.extend(self.time_range.validate())

        # Validate severity threshold
        if self.severity_threshold:
            valid_severities = ["low", "medium", "high", "critical"]
            if self.severity_threshold not in valid_severities:
                errors.append(f"Invalid severity threshold: {self.severity_threshold}")

        # Validate trend period
        valid_periods = ["hour", "day", "week", "month"]
        if self.trend_period not in valid_periods:
            errors.append(f"Invalid trend period: {self.trend_period}")

        # Validate list sizes
        if len(self.user_ids) > 1000:
            errors.append("Too many user IDs (max 1000)")

        if len(self.resource_types) > 100:
            errors.append("Too many resource types (max 100)")

        # Ensure at least some content is included
        if not any(
            [
                self.include_user_activity,
                self.include_system_events,
                self.include_security_events,
                self.include_compliance_data,
                self.include_performance_metrics,
            ]
        ):
            errors.append("At least one content type must be included")

        return errors


@strawberry.input
class ReportCustomizationInput:
    """Input type for report customization."""

    # Appearance
    include_charts: bool = True
    include_executive_summary: bool = True
    include_detailed_findings: bool = True
    include_raw_data: bool = False

    # Sections
    custom_sections: list[str] = strawberry.field(default_factory=list)
    exclude_sections: list[str] = strawberry.field(default_factory=list)

    # Branding
    company_name: str | None = None
    logo_url: str | None = None
    custom_footer: str | None = None

    # Layout
    page_orientation: str = "portrait"  # "portrait", "landscape"
    chart_style: str = "modern"  # "modern", "classic", "minimal"

    def validate(self) -> list[str]:
        """Validate customization options."""
        errors = []

        # Validate orientation
        if self.page_orientation not in ["portrait", "landscape"]:
            errors.append("Page orientation must be 'portrait' or 'landscape'")

        # Validate chart style
        if self.chart_style not in ["modern", "classic", "minimal"]:
            errors.append("Chart style must be 'modern', 'classic', or 'minimal'")

        # Validate custom sections
        valid_sections = [
            "overview",
            "security",
            "compliance",
            "performance",
            "users",
            "resources",
            "trends",
            "recommendations",
        ]

        for section in self.custom_sections + self.exclude_sections:
            if section not in valid_sections:
                errors.append(f"Invalid section: {section}")

        # Validate text lengths
        if self.company_name and len(self.company_name) > 255:
            errors.append("Company name too long (max 255 characters)")

        if self.custom_footer and len(self.custom_footer) > 1000:
            errors.append("Custom footer too long (max 1000 characters)")

        return errors


@strawberry.input
class ReportDeliveryInput:
    """Input type for report delivery options."""

    # Delivery method
    email_recipients: list[str] = strawberry.field(default_factory=list)
    webhook_url: str | None = None

    # Scheduling
    is_scheduled: bool = False
    schedule_expression: str | None = None  # Cron expression

    # Notifications
    notify_on_completion: bool = True
    notify_on_failure: bool = True

    def validate(self) -> list[str]:
        """Validate delivery options."""
        errors = []

        # Validate email addresses
        import re

        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        for email in self.email_recipients:
            if not re.match(email_pattern, email):
                errors.append(f"Invalid email address: {email}")

        if len(self.email_recipients) > 50:
            errors.append("Too many email recipients (max 50)")

        # Validate webhook URL
        if self.webhook_url:
            if not self.webhook_url.startswith(("http://", "https://")):
                errors.append("Webhook URL must use HTTP or HTTPS")

        # Validate schedule expression
        if self.is_scheduled and not self.schedule_expression:
            errors.append("Schedule expression required for scheduled reports")
            # Basic cron validation could be added here

        return errors


@strawberry.input
class ReportGenerationInput:
    """Input type for comprehensive report generation."""

    # Report identity
    title: str
    description: str | None = None
    report_type: ReportTypeEnum = ReportTypeEnum.SUMMARY

    # Parameters
    parameters: ReportParametersInput

    # Customization
    customization: ReportCustomizationInput | None = None

    # Export options
    export_formats: list[ExportFormatEnum] = strawberry.field(
        default_factory=lambda: [ExportFormatEnum.PDF, ExportFormatEnum.JSON]
    )

    # Delivery
    delivery: ReportDeliveryInput | None = None

    # Processing options
    priority: str = "normal"  # "low", "normal", "high", "urgent"
    background_processing: bool = True

    def validate(self) -> list[str]:
        """Validate report generation input."""
        errors = []

        # Validate basic fields
        if not self.title or len(self.title.strip()) == 0:
            errors.append("Report title is required")

        if len(self.title) > 255:
            errors.append("Report title too long (max 255 characters)")

        if self.description and len(self.description) > 2000:
            errors.append("Report description too long (max 2000 characters)")

        # Validate nested inputs
        errors.extend(self.parameters.validate())

        if self.customization:
            errors.extend(self.customization.validate())

        if self.delivery:
            errors.extend(self.delivery.validate())

        # Validate export formats
        if not self.export_formats:
            errors.append("At least one export format is required")

        if len(self.export_formats) > 5:
            errors.append("Too many export formats (max 5)")

        # Validate priority
        valid_priorities = ["low", "normal", "high", "urgent"]
        if self.priority not in valid_priorities:
            errors.append(f"Invalid priority: {self.priority}")

        return errors

    def to_command_dict(self) -> dict[str, Any]:
        """Convert to command dictionary for application layer."""
        return {
            "title": self.title,
            "description": self.description,
            "report_type": self.report_type.value,
            "time_range_start": self.parameters.time_range.start_date,
            "time_range_end": self.parameters.time_range.end_date,
            "include_user_activity": self.parameters.include_user_activity,
            "include_system_events": self.parameters.include_system_events,
            "include_security_events": self.parameters.include_security_events,
            "include_compliance_data": self.parameters.include_compliance_data,
            "include_performance_metrics": self.parameters.include_performance_metrics,
            "user_ids": [str(uid) for uid in self.parameters.user_ids],
            "resource_types": self.parameters.resource_types,
            "severity_threshold": self.parameters.severity_threshold,
            "include_trends": self.parameters.include_trends,
            "include_anomalies": self.parameters.include_anomalies,
            "include_recommendations": self.parameters.include_recommendations,
            "trend_period": self.parameters.trend_period,
            "export_formats": [fmt.value for fmt in self.export_formats],
            "priority": self.priority,
            "background_processing": self.background_processing,
            "customization": {
                "include_charts": self.customization.include_charts
                if self.customization
                else True,
                "include_executive_summary": self.customization.include_executive_summary
                if self.customization
                else True,
                "page_orientation": self.customization.page_orientation
                if self.customization
                else "portrait",
                "chart_style": self.customization.chart_style
                if self.customization
                else "modern",
            },
            "delivery": {
                "email_recipients": self.delivery.email_recipients
                if self.delivery
                else [],
                "webhook_url": self.delivery.webhook_url if self.delivery else None,
                "notify_on_completion": self.delivery.notify_on_completion
                if self.delivery
                else True,
            },
        }


@strawberry.input
class ScheduledReportInput:
    """Input type for scheduled reports."""

    name: str
    description: str | None = None
    report_template: ReportGenerationInput
    schedule_expression: str  # Cron expression
    timezone: str = "UTC"
    is_active: bool = True

    def validate(self) -> list[str]:
        """Validate scheduled report input."""
        errors = []

        if not self.name or len(self.name.strip()) == 0:
            errors.append("Scheduled report name is required")

        if len(self.name) > 255:
            errors.append("Name too long (max 255 characters)")

        if not self.schedule_expression:
            errors.append("Schedule expression is required")

        # Validate timezone
        try:
            import pytz

            pytz.timezone(self.timezone)
        except (pytz.UnknownTimeZoneError, AttributeError, ImportError):
            errors.append(f"Invalid timezone: {self.timezone}")

        # Validate report template
        errors.extend(self.report_template.validate())

        return errors
