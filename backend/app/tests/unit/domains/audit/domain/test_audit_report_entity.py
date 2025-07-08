"""
Comprehensive tests for AuditReport entity.

This module tests the AuditReport entity with complete coverage focusing on:
- Report creation and initialization
- Report type and format validation
- Generation workflow and status management
- Data aggregation and findings
- Factory methods for specific report types
- Business rule enforcement
"""

from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.core.errors import DomainError, ValidationError
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.entities.audit_report import AuditReport
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.time_range import TimeRange


class TestAuditReportCreation:
    """Test audit report creation and initialization."""

    @pytest.fixture
    def sample_time_range(self):
        """Create sample time range for testing."""
        start_time = datetime.utcnow() - timedelta(days=30)
        end_time = datetime.utcnow()
        return TimeRange(start_time=start_time, end_time=end_time)

    @pytest.fixture
    def sample_filter(self, sample_time_range):
        """Create sample audit filter for testing."""
        return AuditFilter(
            time_range=sample_time_range,
            severities=[AuditSeverity.HIGH, AuditSeverity.CRITICAL],
            categories=[AuditCategory.SECURITY, AuditCategory.AUTHENTICATION],
        )

    def test_create_audit_report_with_required_fields(
        self, sample_time_range, sample_filter
    ):
        """Test creating audit report with required fields only."""
        # Arrange
        report_type = AuditReport.REPORT_SUMMARY
        title = "Test Audit Report"
        generated_by = uuid4()

        # Act
        report = AuditReport(
            report_type=report_type,
            title=title,
            time_range=sample_time_range,
            filters=sample_filter,
            generated_by=generated_by,
        )

        # Assert
        assert report.report_type == report_type
        assert report.title == title
        assert report.time_range == sample_time_range
        assert report.filters == sample_filter
        assert report.generated_by == generated_by
        assert report.format == AuditReport.FORMAT_JSON  # Default
        assert report.description is None
        assert report.status == AuditReport.STATUS_PENDING
        assert report.total_entries == 0
        assert report.summary_stats == {}
        assert report.aggregations == {}
        assert report.findings == []
        assert report.started_at is None
        assert report.completed_at is None

    def test_create_audit_report_with_all_fields(
        self, sample_time_range, sample_filter
    ):
        """Test creating audit report with all fields."""
        # Arrange
        report_type = AuditReport.REPORT_DETAILED
        title = "Detailed Test Report"
        description = "Comprehensive audit analysis report"
        format = AuditReport.FORMAT_PDF
        generated_by = uuid4()
        report_id = uuid4()

        # Act
        report = AuditReport(
            report_type=report_type,
            title=title,
            time_range=sample_time_range,
            filters=sample_filter,
            generated_by=generated_by,
            description=description,
            format=format,
            entity_id=report_id,
        )

        # Assert
        assert report.report_type == report_type
        assert report.title == title
        assert report.description == description
        assert report.format == format
        assert report.id == report_id

    def test_create_audit_report_strips_whitespace(
        self, sample_time_range, sample_filter
    ):
        """Test that title and description whitespace is stripped."""
        # Arrange
        title = "  Test Report  "
        description = "  Report description  "

        # Act
        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title=title,
            time_range=sample_time_range,
            filters=sample_filter,
            generated_by=uuid4(),
            description=description,
        )

        # Assert
        assert report.title == "Test Report"
        assert report.description == "Report description"

    @pytest.mark.parametrize("invalid_title", ["", "   ", None])
    def test_create_audit_report_with_invalid_title_raises_error(
        self, invalid_title, sample_time_range, sample_filter
    ):
        """Test that invalid titles raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="title"):
            AuditReport(
                report_type=AuditReport.REPORT_SUMMARY,
                title=invalid_title,
                time_range=sample_time_range,
                filters=sample_filter,
                generated_by=uuid4(),
            )

    @pytest.mark.parametrize(
        "invalid_report_type", ["invalid_type", "unknown", "", "custom_report"]
    )
    def test_create_audit_report_with_invalid_type_raises_error(
        self, invalid_report_type, sample_time_range, sample_filter
    ):
        """Test that invalid report types raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid report type"):
            AuditReport(
                report_type=invalid_report_type,
                title="Test Report",
                time_range=sample_time_range,
                filters=sample_filter,
                generated_by=uuid4(),
            )

    @pytest.mark.parametrize("invalid_format", ["invalid_format", "xml", "excel", ""])
    def test_create_audit_report_with_invalid_format_raises_error(
        self, invalid_format, sample_time_range, sample_filter
    ):
        """Test that invalid formats raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid format"):
            AuditReport(
                report_type=AuditReport.REPORT_SUMMARY,
                title="Test Report",
                time_range=sample_time_range,
                filters=sample_filter,
                generated_by=uuid4(),
                format=invalid_format,
            )


class TestAuditReportValidation:
    """Test audit report validation and business rules."""

    @pytest.fixture
    def sample_time_range(self):
        """Create sample time range for testing."""
        start_time = datetime.utcnow() - timedelta(days=7)
        end_time = datetime.utcnow()
        return TimeRange(start_time=start_time, end_time=end_time)

    @pytest.fixture
    def sample_filter(self, sample_time_range):
        """Create sample audit filter for testing."""
        return AuditFilter(time_range=sample_time_range)

    def test_valid_report_types(self, sample_time_range, sample_filter):
        """Test that all valid report types are accepted."""
        # Arrange
        valid_types = [
            AuditReport.REPORT_SUMMARY,
            AuditReport.REPORT_DETAILED,
            AuditReport.REPORT_COMPLIANCE,
            AuditReport.REPORT_SECURITY,
            AuditReport.REPORT_USER_ACTIVITY,
            AuditReport.REPORT_RESOURCE_ACCESS,
        ]

        for report_type in valid_types:
            # Act
            report = AuditReport(
                report_type=report_type,
                title=f"Test {report_type} Report",
                time_range=sample_time_range,
                filters=sample_filter,
                generated_by=uuid4(),
            )

            # Assert
            assert report.report_type == report_type

    def test_valid_formats(self, sample_time_range, sample_filter):
        """Test that all valid formats are accepted."""
        # Arrange
        valid_formats = [
            AuditReport.FORMAT_JSON,
            AuditReport.FORMAT_CSV,
            AuditReport.FORMAT_PDF,
            AuditReport.FORMAT_HTML,
        ]

        for format in valid_formats:
            # Act
            report = AuditReport(
                report_type=AuditReport.REPORT_SUMMARY,
                title="Test Report",
                time_range=sample_time_range,
                filters=sample_filter,
                generated_by=uuid4(),
                format=format,
            )

            # Assert
            assert report.format == format

    def test_report_type_case_insensitive_validation(
        self, sample_time_range, sample_filter
    ):
        """Test that report type validation is case insensitive."""
        # Act
        report = AuditReport(
            report_type="SUMMARY",  # Uppercase
            title="Test Report",
            time_range=sample_time_range,
            filters=sample_filter,
            generated_by=uuid4(),
        )

        # Assert
        assert report.report_type == AuditReport.REPORT_SUMMARY

    def test_format_case_insensitive_validation(self, sample_time_range, sample_filter):
        """Test that format validation is case insensitive."""
        # Act
        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Test Report",
            time_range=sample_time_range,
            filters=sample_filter,
            generated_by=uuid4(),
            format="PDF",  # Uppercase
        )

        # Assert
        assert report.format == AuditReport.FORMAT_PDF


class TestAuditReportGenerationWorkflow:
    """Test audit report generation workflow and status management."""

    @pytest.fixture
    def pending_report(self):
        """Create a pending audit report for testing."""
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(days=1), end_time=datetime.utcnow()
        )
        filters = AuditFilter(time_range=time_range)

        return AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

    def test_start_generation_from_pending_status(self, pending_report):
        """Test starting generation from pending status."""
        # Arrange
        assert pending_report.is_pending()

        # Act
        pending_report.start_generation()

        # Assert
        assert pending_report.is_generating()
        assert pending_report.status == AuditReport.STATUS_GENERATING
        assert pending_report.started_at is not None
        assert pending_report.completed_at is None

    def test_start_generation_from_invalid_status_raises_error(self, pending_report):
        """Test that starting generation from invalid status raises error."""
        # Arrange
        pending_report.start_generation()  # Move to generating

        # Act & Assert
        with pytest.raises(DomainError, match="Cannot start generation from status"):
            pending_report.start_generation()

    def test_complete_generation_successfully(self, pending_report):
        """Test completing generation successfully."""
        # Arrange
        pending_report.start_generation()

        total_entries = 150
        summary_stats = {
            "success_count": 140,
            "failure_count": 10,
            "average_duration": 250.5,
        }
        aggregations = {
            "severity_distribution": {"high": 5, "medium": 15, "low": 130},
            "category_distribution": {"security": 20, "data_access": 130},
        }
        findings = [
            {
                "title": "High failure rate detected",
                "description": "Authentication failures increased by 200%",
                "severity": "high",
                "affected_count": 10,
            }
        ]
        file_path = "/reports/test_report.pdf"

        # Act
        pending_report.complete_generation(
            total_entries=total_entries,
            summary_stats=summary_stats,
            aggregations=aggregations,
            findings=findings,
            file_path=file_path,
        )

        # Assert
        assert pending_report.is_completed()
        assert pending_report.status == AuditReport.STATUS_COMPLETED
        assert pending_report.total_entries == total_entries
        assert pending_report.summary_stats == summary_stats
        assert pending_report.aggregations == aggregations
        assert pending_report.findings == findings
        assert pending_report.file_path == file_path
        assert pending_report.completed_at is not None
        assert pending_report.error_message is None

    def test_complete_generation_from_invalid_status_raises_error(self, pending_report):
        """Test that completing generation from invalid status raises error."""
        # Act & Assert - Try to complete from pending status
        with pytest.raises(DomainError, match="Cannot complete generation from status"):
            pending_report.complete_generation(
                total_entries=0, summary_stats={}, aggregations={}, findings=[]
            )

    def test_fail_generation(self, pending_report):
        """Test failing generation with error message."""
        # Arrange
        pending_report.start_generation()
        error_message = "Database connection timeout during report generation"

        # Act
        pending_report.fail_generation(error_message)

        # Assert
        assert pending_report.is_failed()
        assert pending_report.status == AuditReport.STATUS_FAILED
        assert pending_report.error_message == error_message
        assert pending_report.completed_at is not None

    def test_fail_generation_from_invalid_status_raises_error(self, pending_report):
        """Test that failing generation from invalid status raises error."""
        # Act & Assert - Try to fail from pending status
        with pytest.raises(DomainError, match="Cannot fail generation from status"):
            pending_report.fail_generation("Test error")

    def test_generation_duration_calculation(self, pending_report):
        """Test generation duration calculation."""
        # Arrange
        pending_report.start_generation()

        # Simulate some processing time
        import time

        time.sleep(0.01)  # 10ms

        # Act
        pending_report.complete_generation(
            total_entries=10, summary_stats={}, aggregations={}, findings=[]
        )

        # Assert
        duration = pending_report.get_generation_duration()
        assert duration is not None
        assert duration > 0
        assert duration < 1.0  # Should be less than 1 second

    def test_generation_duration_when_not_completed(self, pending_report):
        """Test generation duration when report is not completed."""
        # Act & Assert
        assert pending_report.get_generation_duration() is None

        # Start generation but don't complete
        pending_report.start_generation()
        assert pending_report.get_generation_duration() is None


class TestAuditReportStatusChecks:
    """Test audit report status check methods."""

    @pytest.fixture
    def report(self):
        """Create a basic audit report for testing."""
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        return AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Status Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

    def test_status_checks_for_pending_report(self, report):
        """Test status checks for pending report."""
        assert report.is_pending()
        assert not report.is_generating()
        assert not report.is_completed()
        assert not report.is_failed()

    def test_status_checks_for_generating_report(self, report):
        """Test status checks for generating report."""
        # Arrange
        report.start_generation()

        # Assert
        assert not report.is_pending()
        assert report.is_generating()
        assert not report.is_completed()
        assert not report.is_failed()

    def test_status_checks_for_completed_report(self, report):
        """Test status checks for completed report."""
        # Arrange
        report.start_generation()
        report.complete_generation(
            total_entries=50, summary_stats={}, aggregations={}, findings=[]
        )

        # Assert
        assert not report.is_pending()
        assert not report.is_generating()
        assert report.is_completed()
        assert not report.is_failed()

    def test_status_checks_for_failed_report(self, report):
        """Test status checks for failed report."""
        # Arrange
        report.start_generation()
        report.fail_generation("Test failure")

        # Assert
        assert not report.is_pending()
        assert not report.is_generating()
        assert not report.is_completed()
        assert report.is_failed()


class TestAuditReportDataAnalysis:
    """Test audit report data analysis and aggregation methods."""

    @pytest.fixture
    def completed_report(self):
        """Create a completed audit report with sample data."""
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(days=7), end_time=datetime.utcnow()
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_DETAILED,
            title="Analysis Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        # Complete the report with sample data
        report.start_generation()
        report.complete_generation(
            total_entries=1000,
            summary_stats={
                "success_count": 800,
                "failure_count": 200,
                "average_duration": 150.5,
            },
            aggregations={
                "severity_distribution": {
                    "low": 600,
                    "medium": 300,
                    "high": 80,
                    "critical": 20,
                },
                "category_distribution": {
                    "authentication": 200,
                    "data_access": 500,
                    "security": 150,
                    "system": 150,
                },
                "user_activity": [
                    {"user_id": "user1", "count": 150},
                    {"user_id": "user2", "count": 120},
                    {"user_id": "user3", "count": 100},
                ],
                "resource_access": [
                    {"resource": "database", "count": 400},
                    {"resource": "api", "count": 300},
                    {"resource": "file_system", "count": 200},
                ],
            },
            findings=[
                {
                    "title": "Critical security breach detected",
                    "description": "Unauthorized access attempts",
                    "severity": AuditSeverity.CRITICAL.value,
                    "affected_count": 20,
                },
                {
                    "title": "High authentication failure rate",
                    "description": "Authentication failures above threshold",
                    "severity": AuditSeverity.HIGH.value,
                    "affected_count": 80,
                },
            ],
        )

        return report

    def test_get_severity_distribution(self, completed_report):
        """Test getting severity distribution."""
        # Act
        distribution = completed_report.get_severity_distribution()

        # Assert
        assert distribution["low"] == 600
        assert distribution["medium"] == 300
        assert distribution["high"] == 80
        assert distribution["critical"] == 20

    def test_get_category_distribution(self, completed_report):
        """Test getting category distribution."""
        # Act
        distribution = completed_report.get_category_distribution()

        # Assert
        assert distribution["authentication"] == 200
        assert distribution["data_access"] == 500
        assert distribution["security"] == 150
        assert distribution["system"] == 150

    def test_get_top_users(self, completed_report):
        """Test getting top users by activity."""
        # Act
        top_users = completed_report.get_top_users(limit=2)

        # Assert
        assert len(top_users) == 2
        assert top_users[0]["user_id"] == "user1"
        assert top_users[0]["count"] == 150
        assert top_users[1]["user_id"] == "user2"
        assert top_users[1]["count"] == 120

    def test_get_top_resources(self, completed_report):
        """Test getting top accessed resources."""
        # Act
        top_resources = completed_report.get_top_resources(limit=2)

        # Assert
        assert len(top_resources) == 2
        assert top_resources[0]["resource"] == "database"
        assert top_resources[0]["count"] == 400
        assert top_resources[1]["resource"] == "api"
        assert top_resources[1]["count"] == 300

    def test_get_failure_rate(self, completed_report):
        """Test calculating failure rate."""
        # Act
        failure_rate = completed_report.get_failure_rate()

        # Assert
        assert failure_rate == 20.0  # 200 failures out of 1000 total = 20%

    def test_get_failure_rate_with_zero_entries(self):
        """Test failure rate calculation with zero entries."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Empty Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        # Act
        failure_rate = report.get_failure_rate()

        # Assert
        assert failure_rate == 0.0

    def test_has_critical_findings(self, completed_report):
        """Test checking for critical findings."""
        # Act & Assert
        assert completed_report.has_critical_findings()

    def test_get_finding_count_by_severity(self, completed_report):
        """Test getting finding count by severity."""
        # Act
        counts = completed_report.get_finding_count_by_severity()

        # Assert
        assert counts[AuditSeverity.CRITICAL.value] == 1
        assert counts[AuditSeverity.HIGH.value] == 1
        assert counts.get(AuditSeverity.MEDIUM.value, 0) == 0


class TestAuditReportFindings:
    """Test audit report findings management."""

    @pytest.fixture
    def generating_report(self):
        """Create a generating audit report for testing."""
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SECURITY,
            title="Findings Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        report.start_generation()
        return report

    def test_add_finding_to_generating_report(self, generating_report):
        """Test adding finding to generating report."""
        # Arrange
        title = "Suspicious activity detected"
        description = "Multiple failed login attempts from unknown IP"
        severity = AuditSeverity.HIGH
        affected_count = 25
        recommendation = "Block IP address and notify security team"

        # Act
        generating_report.add_finding(
            title=title,
            description=description,
            severity=severity,
            affected_count=affected_count,
            recommendation=recommendation,
        )

        # Assert
        assert len(generating_report.findings) == 1
        finding = generating_report.findings[0]
        assert finding["title"] == title
        assert finding["description"] == description
        assert finding["severity"] == severity.value
        assert finding["affected_count"] == affected_count
        assert finding["recommendation"] == recommendation
        assert "timestamp" in finding

    def test_add_finding_without_recommendation(self, generating_report):
        """Test adding finding without recommendation."""
        # Act
        generating_report.add_finding(
            title="Normal activity",
            description="Standard user activity detected",
            severity=AuditSeverity.LOW,
            affected_count=100,
        )

        # Assert
        finding = generating_report.findings[0]
        assert "recommendation" not in finding

    def test_add_finding_to_completed_report_raises_error(self, generating_report):
        """Test that adding finding to completed report raises error."""
        # Arrange
        generating_report.complete_generation(
            total_entries=10, summary_stats={}, aggregations={}, findings=[]
        )

        # Act & Assert
        with pytest.raises(
            DomainError, match="Cannot add findings to completed report"
        ):
            generating_report.add_finding(
                title="Test finding",
                description="Test description",
                severity=AuditSeverity.MEDIUM,
                affected_count=5,
            )

    def test_add_multiple_findings(self, generating_report):
        """Test adding multiple findings."""
        # Act
        for i in range(3):
            generating_report.add_finding(
                title=f"Finding {i+1}",
                description=f"Description for finding {i+1}",
                severity=AuditSeverity.MEDIUM,
                affected_count=10 + i,
            )

        # Assert
        assert len(generating_report.findings) == 3
        for i, finding in enumerate(generating_report.findings):
            assert finding["title"] == f"Finding {i+1}"
            assert finding["affected_count"] == 10 + i


class TestAuditReportSummary:
    """Test audit report summary generation."""

    @pytest.fixture
    def completed_report(self):
        """Create a completed audit report for testing."""
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(days=1), end_time=datetime.utcnow()
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_COMPLIANCE,
            title="Summary Test Report",
            description="Test report for summary generation",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
            format=AuditReport.FORMAT_PDF,
        )

        report.start_generation()
        report.complete_generation(
            total_entries=500,
            summary_stats={"failure_count": 50},
            aggregations={},
            findings=[
                {
                    "title": "Critical issue",
                    "severity": AuditSeverity.CRITICAL.value,
                    "affected_count": 10,
                }
            ],
        )

        return report

    def test_to_summary_dict_for_completed_report(self, completed_report):
        """Test summary dictionary for completed report."""
        # Act
        summary = completed_report.to_summary_dict()

        # Assert
        assert summary["id"] == str(completed_report.id)
        assert summary["type"] == completed_report.report_type
        assert summary["title"] == completed_report.title
        assert summary["description"] == completed_report.description
        assert summary["status"] == AuditReport.STATUS_COMPLETED
        assert summary["format"] == AuditReport.FORMAT_PDF
        assert summary["generated_by"] == str(completed_report.generated_by)
        assert "created_at" in summary

        # Completed report specific fields
        assert summary["total_entries"] == 500
        assert summary["failure_rate"] == 10.0  # 50/500 * 100
        assert summary["critical_findings"] is True
        assert summary["finding_count"] == 1
        assert "generation_duration" in summary

        # Time range information
        assert "time_range" in summary
        assert "start" in summary["time_range"]
        assert "end" in summary["time_range"]
        assert "duration" in summary["time_range"]

    def test_to_summary_dict_for_failed_report(self):
        """Test summary dictionary for failed report."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Failed Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        report.start_generation()
        report.fail_generation("Database connection failed")

        # Act
        summary = report.to_summary_dict()

        # Assert
        assert summary["status"] == AuditReport.STATUS_FAILED
        assert summary["error_message"] == "Database connection failed"
        assert "total_entries" not in summary
        assert "failure_rate" not in summary

    def test_to_summary_dict_for_pending_report(self):
        """Test summary dictionary for pending report."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Pending Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        # Act
        summary = report.to_summary_dict()

        # Assert
        assert summary["status"] == AuditReport.STATUS_PENDING
        assert "total_entries" not in summary
        assert "failure_rate" not in summary
        assert "error_message" not in summary


class TestAuditReportFactoryMethods:
    """Test audit report factory methods."""

    def test_create_compliance_report(self):
        """Test creating compliance report using factory method."""
        # Arrange
        title = "SOX Compliance Report"
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(days=365),
            end_time=datetime.utcnow(),
        )
        regulations = ["SOX", "GDPR", "HIPAA"]
        generated_by = uuid4()

        # Act
        report = AuditReport.create_compliance_report(
            title=title,
            time_range=time_range,
            regulations=regulations,
            generated_by=generated_by,
        )

        # Assert
        assert report.report_type == AuditReport.REPORT_COMPLIANCE
        assert report.title == title
        assert report.time_range == time_range
        assert report.generated_by == generated_by
        assert report.format == AuditReport.FORMAT_PDF
        assert "SOX, GDPR, HIPAA" in report.description

        # Check that filters include compliance-relevant categories
        filter_categories = report.filters.categories
        assert AuditCategory.AUTHENTICATION in filter_categories
        assert AuditCategory.AUTHORIZATION in filter_categories
        assert AuditCategory.DATA_ACCESS in filter_categories
        assert AuditCategory.SECURITY in filter_categories

    def test_create_security_report(self):
        """Test creating security report using factory method."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(days=30),
            end_time=datetime.utcnow(),
        )
        generated_by = uuid4()

        # Act
        report = AuditReport.create_security_report(
            time_range=time_range, generated_by=generated_by
        )

        # Assert
        assert report.report_type == AuditReport.REPORT_SECURITY
        assert report.time_range == time_range
        assert report.generated_by == generated_by
        assert report.format == AuditReport.FORMAT_PDF
        assert "Security Audit Report" in report.title
        assert report.description == "Analysis of security-related audit events"

        # Check that filters are configured for security review
        assert report.filters is not None


class TestAuditReportBehavior:
    """Test audit report behavioral patterns and edge cases."""

    def test_report_inherits_from_entity(self):
        """Test that AuditReport inherits from Entity."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        # Act & Assert
        from app.core.domain.base import Entity

        assert isinstance(report, Entity)
        assert hasattr(report, "id")
        assert hasattr(report, "created_at")
        assert hasattr(report, "updated_at")

    def test_report_has_unique_id(self):
        """Test that each report gets a unique ID."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        # Act
        report1 = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Report 1",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        report2 = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Report 2",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        # Assert
        assert report1.id != report2.id
        assert isinstance(report1.id, UUID)
        assert isinstance(report2.id, UUID)

    def test_report_modification_tracking(self):
        """Test that report modifications are tracked."""
        # Arrange
        time_range = TimeRange(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )
        filters = AuditFilter(time_range=time_range)

        report = AuditReport(
            report_type=AuditReport.REPORT_SUMMARY,
            title="Test Report",
            time_range=time_range,
            filters=filters,
            generated_by=uuid4(),
        )

        original_updated_at = report.updated_at

        # Act
        report.start_generation()

        # Assert
        assert report.updated_at > original_updated_at
