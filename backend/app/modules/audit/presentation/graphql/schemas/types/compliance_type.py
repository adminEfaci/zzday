"""GraphQL types for compliance reporting."""

from datetime import datetime

import strawberry

from ..enums import ComplianceFrameworkEnum, ComplianceStatusEnum, RiskLevelEnum


@strawberry.type
class ComplianceViolationType:
    """GraphQL type for compliance violations."""

    violation_id: strawberry.ID
    rule_id: str
    rule_name: str
    severity: str
    detected_at: datetime
    resource_type: str
    resource_id: str
    user_id: strawberry.ID | None = None
    description: str
    remediation_status: str
    remediation_notes: str | None = None

    @strawberry.field
    def formatted_detected_at(self) -> str:
        """Return formatted detection timestamp."""
        return self.detected_at.isoformat()

    @strawberry.field
    def is_critical(self) -> bool:
        """Check if violation is critical severity."""
        return self.severity.lower() == "critical"

    @strawberry.field
    def days_since_detection(self) -> int:
        """Calculate days since violation was detected."""
        from datetime import datetime

        delta = datetime.now() - self.detected_at.replace(tzinfo=None)
        return delta.days

    @strawberry.field
    def risk_score(self) -> float:
        """Calculate risk score for violation."""
        severity_scores = {"low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}

        base_score = severity_scores.get(self.severity.lower(), 5.0)

        # Increase score based on time unresolved
        days_open = self.days_since_detection
        if days_open > 30:
            base_score *= 1.5
        elif days_open > 7:
            base_score *= 1.2

        # Adjust based on remediation status
        if self.remediation_status == "not_started":
            base_score *= 1.3
        elif self.remediation_status == "in_progress":
            base_score *= 1.1
        elif self.remediation_status == "completed":
            base_score *= 0.5

        return min(10.0, base_score)


@strawberry.type
class ComplianceControlType:
    """GraphQL type for compliance controls."""

    control_id: str
    control_name: str
    framework: ComplianceFrameworkEnum
    status: ComplianceStatusEnum
    last_assessed: datetime
    evidence_count: int
    findings: list[str]
    recommendations: list[str]

    @strawberry.field
    def formatted_last_assessed(self) -> str:
        """Return formatted last assessment timestamp."""
        return self.last_assessed.isoformat()

    @strawberry.field
    def is_compliant(self) -> bool:
        """Check if control is compliant."""
        return self.status == ComplianceStatusEnum.COMPLIANT

    @strawberry.field
    def has_evidence(self) -> bool:
        """Check if control has evidence."""
        return self.evidence_count > 0

    @strawberry.field
    def assessment_age_days(self) -> int:
        """Calculate days since last assessment."""
        from datetime import datetime

        delta = datetime.now() - self.last_assessed.replace(tzinfo=None)
        return delta.days

    @strawberry.field
    def needs_reassessment(self) -> bool:
        """Check if control needs reassessment (>90 days old)."""
        return self.assessment_age_days > 90

    @strawberry.field
    def control_effectiveness(self) -> str:
        """Assess control effectiveness."""
        if self.status == ComplianceStatusEnum.COMPLIANT and self.evidence_count > 0:
            return "effective"
        if self.status == ComplianceStatusEnum.PARTIAL:
            return "partially_effective"
        if self.status == ComplianceStatusEnum.NON_COMPLIANT:
            return "ineffective"
        return "not_assessed"


@strawberry.type
class ComplianceMetricsType:
    """GraphQL type for compliance metrics."""

    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    partial_controls: int
    not_applicable_controls: int

    @strawberry.field
    def compliance_percentage(self) -> float:
        """Calculate overall compliance percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.compliant_controls / self.total_controls) * 100

    @strawberry.field
    def non_compliance_percentage(self) -> float:
        """Calculate non-compliance percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.non_compliant_controls / self.total_controls) * 100

    @strawberry.field
    def partial_compliance_percentage(self) -> float:
        """Calculate partial compliance percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.partial_controls / self.total_controls) * 100


@strawberry.type
class ComplianceFrameworkSummaryType:
    """GraphQL type for compliance framework summary."""

    framework: ComplianceFrameworkEnum
    total_controls: int
    compliant_controls: int
    compliance_score: float
    last_assessment: datetime
    certification_status: str

    @strawberry.field
    def is_certified(self) -> bool:
        """Check if framework is certified."""
        return self.certification_status == "certified"

    @strawberry.field
    def compliance_grade(self) -> str:
        """Return compliance grade."""
        score = self.compliance_score
        if score >= 95:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 85:
            return "B+"
        if score >= 80:
            return "B"
        if score >= 75:
            return "C+"
        if score >= 70:
            return "C"
        return "F"


@strawberry.type
class ComplianceReportType:
    """GraphQL type for compliance reports."""

    # Report identity
    report_id: strawberry.ID
    generated_at: datetime
    generated_by: strawberry.ID | None = None

    # Report scope
    title: str
    framework: ComplianceFrameworkEnum
    reporting_period_start: datetime
    reporting_period_end: datetime
    scope_description: str

    # Overall compliance status
    overall_status: ComplianceStatusEnum
    compliance_score: float
    risk_level: RiskLevelEnum

    # Controls assessment
    controls_metrics: ComplianceMetricsType
    controls: list[ComplianceControlType]

    # Violations
    total_violations: int
    critical_violations: int
    high_violations: int
    medium_violations: int
    low_violations: int
    violations: list[ComplianceViolationType]

    # Evidence summary
    total_evidence_items: int
    evidence_by_type: str  # JSON string
    evidence_coverage: float

    # Key metrics
    metrics: str  # JSON string

    # Executive summary
    executive_summary: str
    key_findings: list[str]
    recommendations: list[str]

    # Audit trail
    data_sources: list[str]
    audit_methodology: str
    limitations: list[str]

    # Certification info
    certifiable: bool
    certification_gaps: list[str]
    estimated_remediation_time: str | None = None

    @strawberry.field
    def formatted_generated_at(self) -> str:
        """Return formatted generation timestamp."""
        return self.generated_at.isoformat()

    @strawberry.field
    def reporting_period_days(self) -> int:
        """Calculate reporting period in days."""
        delta = self.reporting_period_end - self.reporting_period_start
        return delta.days

    @strawberry.field
    def violation_severity_breakdown(self) -> list["ViolationSeverityBreakdownType"]:
        """Return violation breakdown by severity."""
        total = self.total_violations
        if total == 0:
            return []

        return [
            ViolationSeverityBreakdownType(
                severity="critical",
                count=self.critical_violations,
                percentage=(self.critical_violations / total) * 100,
            ),
            ViolationSeverityBreakdownType(
                severity="high",
                count=self.high_violations,
                percentage=(self.high_violations / total) * 100,
            ),
            ViolationSeverityBreakdownType(
                severity="medium",
                count=self.medium_violations,
                percentage=(self.medium_violations / total) * 100,
            ),
            ViolationSeverityBreakdownType(
                severity="low",
                count=self.low_violations,
                percentage=(self.low_violations / total) * 100,
            ),
        ]

    @strawberry.field
    def framework_summary(self) -> ComplianceFrameworkSummaryType:
        """Return framework summary."""
        return ComplianceFrameworkSummaryType(
            framework=self.framework,
            total_controls=self.controls_metrics.total_controls,
            compliant_controls=self.controls_metrics.compliant_controls,
            compliance_score=self.compliance_score,
            last_assessment=self.generated_at,
            certification_status="certified" if self.certifiable else "not_certified",
        )

    @strawberry.field
    def open_violations_count(self) -> int:
        """Count violations that are not remediated."""
        return len([v for v in self.violations if v.remediation_status != "completed"])

    @strawberry.field
    def compliance_trend(self) -> str:
        """Return compliance trend (requires historical data)."""
        # This would typically require comparing with previous reports
        # For now, return based on current score
        if self.compliance_score >= 90:
            return "excellent"
        if self.compliance_score >= 80:
            return "good"
        if self.compliance_score >= 70:
            return "fair"
        return "poor"

    @strawberry.field
    def next_assessment_due(self) -> str:
        """Calculate when next assessment is due."""
        from datetime import timedelta

        # Typically compliance assessments are quarterly or annually
        if self.framework in [
            ComplianceFrameworkEnum.SOC2,
            ComplianceFrameworkEnum.ISO27001,
        ]:
            next_due = self.generated_at + timedelta(days=90)  # Quarterly
        else:
            next_due = self.generated_at + timedelta(days=365)  # Annually

        return next_due.isoformat()


@strawberry.type
class ViolationSeverityBreakdownType:
    """GraphQL type for violation severity breakdown."""

    severity: str
    count: int
    percentage: float


@strawberry.type
class ComplianceTimelineType:
    """GraphQL type for compliance timeline."""

    date: datetime
    event_type: str  # "violation", "remediation", "assessment", "certification"
    description: str
    framework: ComplianceFrameworkEnum
    impact: str  # "positive", "negative", "neutral"

    @strawberry.field
    def formatted_date(self) -> str:
        """Return formatted date."""
        return self.date.isoformat()


@strawberry.type
class SecurityIncidentType:
    """GraphQL type for security incidents."""

    incident_id: strawberry.ID
    incident_type: str
    severity: str
    detected_at: datetime
    description: str
    affected_users: list[str]
    affected_resources: list[str]
    threat_level: str
    source_ip: str | None = None
    status: str
    remediation_steps: list[str]

    @strawberry.field
    def formatted_detected_at(self) -> str:
        """Return formatted detection timestamp."""
        return self.detected_at.isoformat()

    @strawberry.field
    def is_active(self) -> bool:
        """Check if incident is still active."""
        return self.status in ["open", "investigating", "in_progress"]


@strawberry.type
class ComplianceFrameworkStatusType:
    """GraphQL type for compliance framework status."""

    framework: ComplianceFrameworkEnum
    overall_score: float
    compliant_controls: int
    total_controls: int
    last_assessment: datetime
    violations_count: int
    risk_level: RiskLevelEnum
    trends: str  # JSON string

    @strawberry.field
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.compliant_controls / self.total_controls) * 100

    @strawberry.field
    def status_grade(self) -> str:
        """Return status grade."""
        percentage = self.compliance_percentage
        if percentage >= 95:
            return "A+"
        if percentage >= 90:
            return "A"
        if percentage >= 85:
            return "B+"
        if percentage >= 80:
            return "B"
        if percentage >= 75:
            return "C+"
        if percentage >= 70:
            return "C"
        return "F"


@strawberry.type
class ComplianceTrendType:
    """GraphQL type for compliance trends."""

    framework: ComplianceFrameworkEnum
    metric: str
    time_period: str
    trend_data: str  # JSON string
    direction: str
    change_percentage: float

    @strawberry.field
    def is_improving(self) -> bool:
        """Check if trend is improving."""
        return self.direction == "improving"


@strawberry.type
class CompliancePolicyType:
    """GraphQL type for compliance policies."""

    policy_id: strawberry.ID
    policy_name: str
    framework: ComplianceFrameworkEnum
    description: str
    enforcement_level: str
    violations_count: int
    last_updated: datetime
    status: str

    @strawberry.field
    def formatted_last_updated(self) -> str:
        """Return formatted last update timestamp."""
        return self.last_updated.isoformat()

    @strawberry.field
    def is_active(self) -> bool:
        """Check if policy is active."""
        return self.status == "active"
