"""Compliance report DTO.

This module defines the Data Transfer Object for compliance reports,
providing structured compliance audit data for regulatory requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class ComplianceViolationDTO:
    """DTO for compliance violations."""

    violation_id: UUID
    rule_id: str
    rule_name: str
    severity: str
    detected_at: datetime
    resource_type: str
    resource_id: str
    user_id: UUID | None
    description: str
    remediation_status: str
    remediation_notes: str | None


@dataclass(frozen=True)
class ComplianceControlDTO:
    """DTO for compliance controls."""

    control_id: str
    control_name: str
    framework: str  # "SOC2", "HIPAA", "GDPR", "PCI-DSS"
    status: str  # "compliant", "non-compliant", "partial", "not-applicable"
    last_assessed: datetime
    evidence_count: int
    findings: list[str]
    recommendations: list[str]


@dataclass(frozen=True)
class ComplianceReportDTO:
    """
    Data Transfer Object for compliance reports.

    Provides comprehensive compliance audit information
    for regulatory and certification requirements.
    """

    # Report identity
    report_id: UUID
    generated_at: datetime
    generated_by: UUID | None

    # Report scope
    title: str
    framework: str  # Primary compliance framework
    reporting_period_start: datetime
    reporting_period_end: datetime
    scope_description: str

    # Overall compliance status
    overall_status: str  # "compliant", "non-compliant", "partial"
    compliance_score: float  # 0.0 to 100.0
    risk_level: str  # "low", "medium", "high", "critical"

    # Controls assessment
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    partial_controls: int
    not_applicable_controls: int
    controls: list[ComplianceControlDTO] = field(default_factory=list)

    # Violations
    total_violations: int
    critical_violations: int
    high_violations: int
    medium_violations: int
    low_violations: int
    violations: list[ComplianceViolationDTO] = field(default_factory=list)

    # Evidence summary
    total_evidence_items: int
    evidence_by_type: dict[str, int] = field(default_factory=dict)
    evidence_coverage: float = 0.0  # Percentage of controls with evidence

    # Key metrics
    metrics: dict[str, Any] = field(default_factory=dict)

    # Executive summary
    executive_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Audit trail
    data_sources: list[str] = field(default_factory=list)
    audit_methodology: str = ""
    limitations: list[str] = field(default_factory=list)

    # Certification info
    certifiable: bool = False
    certification_gaps: list[str] = field(default_factory=list)
    estimated_remediation_time: str | None = None

    # Export options
    available_formats: list[str] = field(
        default_factory=lambda: ["json", "pdf", "docx", "xlsx"]
    )

    @classmethod
    def from_domain(cls, report: Any) -> "ComplianceReportDTO":
        """
        Create DTO from domain compliance report.

        Args:
            report: Domain compliance report

        Returns:
            ComplianceReportDTO instance
        """
        # Build control DTOs
        controls = []
        for control in report.controls:
            controls.append(
                ComplianceControlDTO(
                    control_id=control.control_id,
                    control_name=control.control_name,
                    framework=control.framework,
                    status=control.status,
                    last_assessed=control.last_assessed,
                    evidence_count=control.evidence_count,
                    findings=control.findings,
                    recommendations=control.recommendations,
                )
            )

        # Build violation DTOs
        violations = []
        for violation in report.violations:
            violations.append(
                ComplianceViolationDTO(
                    violation_id=violation.id,
                    rule_id=violation.rule_id,
                    rule_name=violation.rule_name,
                    severity=violation.severity,
                    detected_at=violation.detected_at,
                    resource_type=violation.resource_type,
                    resource_id=violation.resource_id,
                    user_id=violation.user_id,
                    description=violation.description,
                    remediation_status=violation.remediation_status,
                    remediation_notes=violation.remediation_notes,
                )
            )

        return cls(
            report_id=report.id,
            generated_at=report.generated_at,
            generated_by=report.generated_by,
            title=report.title,
            framework=report.framework,
            reporting_period_start=report.period_start,
            reporting_period_end=report.period_end,
            scope_description=report.scope_description,
            overall_status=report.overall_status,
            compliance_score=report.compliance_score,
            risk_level=report.risk_level,
            total_controls=report.total_controls,
            compliant_controls=report.compliant_controls,
            non_compliant_controls=report.non_compliant_controls,
            partial_controls=report.partial_controls,
            not_applicable_controls=report.not_applicable_controls,
            controls=controls,
            total_violations=report.total_violations,
            critical_violations=report.critical_violations,
            high_violations=report.high_violations,
            medium_violations=report.medium_violations,
            low_violations=report.low_violations,
            violations=violations,
            total_evidence_items=report.total_evidence_items,
            evidence_by_type=report.evidence_by_type,
            evidence_coverage=report.evidence_coverage,
            metrics=report.metrics,
            executive_summary=report.executive_summary,
            key_findings=report.key_findings,
            recommendations=report.recommendations,
            data_sources=report.data_sources,
            audit_methodology=report.audit_methodology,
            limitations=report.limitations,
            certifiable=report.certifiable,
            certification_gaps=report.certification_gaps,
            estimated_remediation_time=report.estimated_remediation_time,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "report_id": str(self.report_id),
            "generated_at": self.generated_at.isoformat(),
            "generated_by": str(self.generated_by) if self.generated_by else None,
            "title": self.title,
            "framework": self.framework,
            "reporting_period": {
                "start": self.reporting_period_start.isoformat(),
                "end": self.reporting_period_end.isoformat(),
            },
            "scope_description": self.scope_description,
            "compliance_status": {
                "overall_status": self.overall_status,
                "compliance_score": self.compliance_score,
                "risk_level": self.risk_level,
            },
            "controls_summary": {
                "total": self.total_controls,
                "compliant": self.compliant_controls,
                "non_compliant": self.non_compliant_controls,
                "partial": self.partial_controls,
                "not_applicable": self.not_applicable_controls,
                "details": [
                    {
                        "control_id": c.control_id,
                        "control_name": c.control_name,
                        "framework": c.framework,
                        "status": c.status,
                        "last_assessed": c.last_assessed.isoformat(),
                        "evidence_count": c.evidence_count,
                        "findings": c.findings,
                        "recommendations": c.recommendations,
                    }
                    for c in self.controls
                ],
            },
            "violations_summary": {
                "total": self.total_violations,
                "by_severity": {
                    "critical": self.critical_violations,
                    "high": self.high_violations,
                    "medium": self.medium_violations,
                    "low": self.low_violations,
                },
                "details": [
                    {
                        "violation_id": str(v.violation_id),
                        "rule_id": v.rule_id,
                        "rule_name": v.rule_name,
                        "severity": v.severity,
                        "detected_at": v.detected_at.isoformat(),
                        "resource_type": v.resource_type,
                        "resource_id": v.resource_id,
                        "user_id": str(v.user_id) if v.user_id else None,
                        "description": v.description,
                        "remediation_status": v.remediation_status,
                        "remediation_notes": v.remediation_notes,
                    }
                    for v in self.violations
                ],
            },
            "evidence_summary": {
                "total_items": self.total_evidence_items,
                "by_type": self.evidence_by_type,
                "coverage_percentage": self.evidence_coverage,
            },
            "metrics": self.metrics,
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "recommendations": self.recommendations,
            "audit_info": {
                "data_sources": self.data_sources,
                "methodology": self.audit_methodology,
                "limitations": self.limitations,
            },
            "certification": {
                "certifiable": self.certifiable,
                "gaps": self.certification_gaps,
                "estimated_remediation_time": self.estimated_remediation_time,
            },
            "available_formats": self.available_formats,
        }


__all__ = ["ComplianceControlDTO", "ComplianceReportDTO", "ComplianceViolationDTO"]
