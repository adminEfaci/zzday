"""Get compliance report query.

This module implements the query and handler for retrieving compliance reports
with regulatory framework analysis and violation tracking.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.compliance_report_dto import ComplianceReportDTO

logger = get_logger(__name__)


class GetComplianceReportQuery(Query):
    """
    Query to retrieve or generate compliance reports.

    Supports various compliance frameworks and provides
    detailed regulatory compliance analysis.
    """

    def __init__(
        self,
        framework: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        report_id: UUID | None = None,
        generate_new: bool = False,
        include_evidence: bool = True,
        include_violations: bool = True,
        scope_filters: dict[str, Any] | None = None,
    ):
        """
        Initialize get compliance report query.

        Args:
            framework: Compliance framework (SOC2, HIPAA, GDPR, PCI-DSS)
            start_date: Start of reporting period
            end_date: End of reporting period
            report_id: Specific report ID to retrieve
            generate_new: Force generation of new report
            include_evidence: Include compliance evidence
            include_violations: Include violation details
            scope_filters: Additional scope filters
        """
        super().__init__()

        self.framework = self._validate_framework(framework)
        self.start_date = start_date or (datetime.utcnow() - timedelta(days=90))
        self.end_date = end_date or datetime.utcnow()
        self.report_id = report_id
        self.generate_new = generate_new
        self.include_evidence = include_evidence
        self.include_violations = include_violations
        self.scope_filters = scope_filters or {}

        # Validate date range
        if self.start_date >= self.end_date:
            raise ValidationError("Start date must be before end date")

        self._freeze()

    def _validate_framework(self, framework: str) -> str:
        """Validate compliance framework."""
        valid_frameworks = ["SOC2", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]
        if framework not in valid_frameworks:
            raise ValidationError(
                f"Invalid framework: {framework}. Must be one of: {valid_frameworks}"
            )
        return framework


class GetComplianceReportQueryHandler(
    QueryHandler[GetComplianceReportQuery, dict[str, Any]]
):
    """
    Handler for retrieving compliance reports.

    This handler manages compliance report generation and retrieval,
    including regulatory framework analysis and violation tracking.
    """

    def __init__(
        self,
        audit_repository: Any,
        compliance_service: Any,
        violation_service: Any,
        evidence_service: Any,
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit and report data
            compliance_service: Service for compliance analysis
            violation_service: Service for violation tracking
            evidence_service: Service for evidence collection
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.compliance_service = compliance_service
        self.violation_service = violation_service
        self.evidence_service = evidence_service

    async def handle(self, query: GetComplianceReportQuery) -> dict[str, Any]:
        """
        Handle the get compliance report query.

        Args:
            query: Query containing report parameters

        Returns:
            Dictionary containing compliance report data
        """
        logger.debug(
            "Retrieving compliance report",
            framework=query.framework,
            report_id=query.report_id,
            generate_new=query.generate_new,
        )

        # Try to retrieve existing report if ID provided and not forcing new generation
        if query.report_id and not query.generate_new:
            existing_report = await self.audit_repository.find_compliance_report_by_id(
                query.report_id
            )
            if existing_report:
                report_dto = ComplianceReportDTO.from_domain(existing_report)
                return {
                    "report": report_dto.to_dict(),
                    "metadata": {
                        "retrieved_from": "existing_report",
                        "report_age_hours": (
                            datetime.utcnow() - existing_report.generated_at
                        ).total_seconds()
                        / 3600,
                    },
                }

        # Generate new compliance report
        logger.info(
            "Generating new compliance report",
            framework=query.framework,
            period=f"{query.start_date} to {query.end_date}",
        )

        # Get compliance controls for the framework
        controls = await self.compliance_service.get_framework_controls(query.framework)

        # Assess each control
        control_assessments = []
        total_controls = len(controls)
        compliant_count = 0
        non_compliant_count = 0
        partial_count = 0
        not_applicable_count = 0

        for control in controls:
            assessment = await self._assess_control(
                control,
                query.framework,
                query.start_date,
                query.end_date,
                query.scope_filters,
            )
            control_assessments.append(assessment)

            # Count by status
            if assessment["status"] == "compliant":
                compliant_count += 1
            elif assessment["status"] == "non_compliant":
                non_compliant_count += 1
            elif assessment["status"] == "partial":
                partial_count += 1
            else:
                not_applicable_count += 1

        # Calculate overall compliance score
        scorable_controls = total_controls - not_applicable_count
        if scorable_controls > 0:
            compliance_score = (
                (compliant_count + (partial_count * 0.5)) / scorable_controls
            ) * 100
        else:
            compliance_score = 100.0

        # Determine overall status and risk level
        overall_status = self._determine_overall_status(compliance_score)
        risk_level = self._determine_risk_level(compliance_score, non_compliant_count)

        # Get violations if requested
        violations = []
        if query.include_violations:
            violations = await self._get_compliance_violations(
                query.framework, query.start_date, query.end_date
            )

        # Get evidence summary if requested
        evidence_summary = {}
        if query.include_evidence:
            evidence_summary = await self._get_evidence_summary(
                query.framework, control_assessments
            )

        # Build compliance report
        report_data = {
            "report_id": str(UUID()),
            "generated_at": datetime.utcnow().isoformat(),
            "framework": query.framework,
            "reporting_period": {
                "start": query.start_date.isoformat(),
                "end": query.end_date.isoformat(),
            },
            "title": f"{query.framework} Compliance Report",
            "scope_description": self._build_scope_description(query.scope_filters),
            "overall_status": overall_status,
            "compliance_score": round(compliance_score, 2),
            "risk_level": risk_level,
            "controls_summary": {
                "total": total_controls,
                "compliant": compliant_count,
                "non_compliant": non_compliant_count,
                "partial": partial_count,
                "not_applicable": not_applicable_count,
            },
            "controls": control_assessments,
            "violations_summary": {
                "total": len(violations),
                "by_severity": self._group_violations_by_severity(violations),
            },
            "violations": violations if query.include_violations else [],
            "evidence_summary": evidence_summary,
            "key_findings": self._generate_key_findings(
                compliance_score, control_assessments, violations
            ),
            "recommendations": self._generate_recommendations(
                control_assessments, violations
            ),
            "executive_summary": self._generate_executive_summary(
                query.framework, compliance_score, len(violations), overall_status
            ),
        }

        logger.info(
            "Compliance report generated successfully",
            framework=query.framework,
            compliance_score=compliance_score,
            violation_count=len(violations),
        )

        return {
            "report": report_data,
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generation_method": "real_time",
                "framework": query.framework,
                "controls_assessed": total_controls,
            },
        }

    async def _assess_control(
        self,
        control: dict[str, Any],
        framework: str,
        start_date: datetime,
        end_date: datetime,
        scope_filters: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Assess a single compliance control.

        Args:
            control: Control definition
            framework: Compliance framework
            start_date: Assessment period start
            end_date: Assessment period end
            scope_filters: Scope filters

        Returns:
            Control assessment result
        """
        control_id = control["control_id"]

        # Get evidence for this control
        evidence = await self.evidence_service.get_control_evidence(
            control_id, start_date, end_date, scope_filters
        )

        # Assess control status based on evidence
        assessment_result = await self.compliance_service.assess_control_compliance(
            control, evidence, framework
        )

        return {
            "control_id": control_id,
            "control_name": control["name"],
            "framework": framework,
            "status": assessment_result["status"],
            "last_assessed": datetime.utcnow().isoformat(),
            "evidence_count": len(evidence),
            "findings": assessment_result.get("findings", []),
            "recommendations": assessment_result.get("recommendations", []),
            "risk_score": assessment_result.get("risk_score", 0),
            "next_assessment_due": assessment_result.get("next_assessment_due"),
        }

    async def _get_compliance_violations(
        self, framework: str, start_date: datetime, end_date: datetime
    ) -> list[dict[str, Any]]:
        """
        Get compliance violations for the framework and period.

        Args:
            framework: Compliance framework
            start_date: Period start
            end_date: Period end

        Returns:
            List of violations
        """
        violations = await self.violation_service.get_violations(
            framework=framework, start_date=start_date, end_date=end_date
        )

        violation_data = []
        for violation in violations:
            violation_data.append(
                {
                    "violation_id": str(violation.id),
                    "rule_id": violation.rule_id,
                    "rule_name": violation.rule_name,
                    "severity": violation.severity,
                    "detected_at": violation.detected_at.isoformat(),
                    "resource_type": violation.resource_type,
                    "resource_id": violation.resource_id,
                    "user_id": str(violation.user_id) if violation.user_id else None,
                    "description": violation.description,
                    "remediation_status": violation.remediation_status,
                    "remediation_notes": violation.remediation_notes,
                }
            )

        return violation_data

    async def _get_evidence_summary(
        self, framework: str, control_assessments: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Get evidence summary for the framework.

        Args:
            framework: Compliance framework
            control_assessments: Control assessment results

        Returns:
            Evidence summary
        """
        total_evidence = sum(c["evidence_count"] for c in control_assessments)
        controls_with_evidence = len(
            [c for c in control_assessments if c["evidence_count"] > 0]
        )
        total_controls = len(control_assessments)

        evidence_coverage = (
            (controls_with_evidence / total_controls) * 100 if total_controls > 0 else 0
        )

        # Get evidence by type
        evidence_by_type = await self.evidence_service.get_evidence_types_summary(
            framework
        )

        return {
            "total_evidence_items": total_evidence,
            "controls_with_evidence": controls_with_evidence,
            "evidence_coverage_percentage": round(evidence_coverage, 2),
            "evidence_by_type": evidence_by_type,
            "automated_evidence_percentage": await self.evidence_service.get_automation_percentage(
                framework
            ),
        }

    def _determine_overall_status(self, compliance_score: float) -> str:
        """Determine overall compliance status."""
        if compliance_score >= 95:
            return "compliant"
        if compliance_score >= 80:
            return "partial"
        return "non_compliant"

    def _determine_risk_level(
        self, compliance_score: float, non_compliant_count: int
    ) -> str:
        """Determine risk level."""
        if compliance_score >= 95 and non_compliant_count == 0:
            return "low"
        if compliance_score >= 80 and non_compliant_count <= 2:
            return "medium"
        if compliance_score >= 60:
            return "high"
        return "critical"

    def _group_violations_by_severity(
        self, violations: list[dict[str, Any]]
    ) -> dict[str, int]:
        """Group violations by severity."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for violation in violations:
            severity = violation.get("severity", "medium")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        return by_severity

    def _build_scope_description(self, scope_filters: dict[str, Any]) -> str:
        """Build scope description from filters."""
        if not scope_filters:
            return "All systems and processes within the organization"

        descriptions = []
        if "systems" in scope_filters:
            descriptions.append(f"Systems: {', '.join(scope_filters['systems'])}")
        if "departments" in scope_filters:
            descriptions.append(
                f"Departments: {', '.join(scope_filters['departments'])}"
            )
        if "data_types" in scope_filters:
            descriptions.append(f"Data types: {', '.join(scope_filters['data_types'])}")

        return (
            "; ".join(descriptions) if descriptions else "Standard organizational scope"
        )

    def _generate_key_findings(
        self,
        compliance_score: float,
        controls: list[dict[str, Any]],
        violations: list[dict[str, Any]],
    ) -> list[str]:
        """Generate key findings."""
        findings = []

        findings.append(f"Overall compliance score: {compliance_score:.1f}%")

        non_compliant_controls = [c for c in controls if c["status"] == "non_compliant"]
        if non_compliant_controls:
            findings.append(f"{len(non_compliant_controls)} controls are non-compliant")

        critical_violations = [v for v in violations if v.get("severity") == "critical"]
        if critical_violations:
            findings.append(f"{len(critical_violations)} critical violations detected")

        if compliance_score >= 95:
            findings.append("Organization demonstrates strong compliance posture")
        elif compliance_score < 70:
            findings.append("Significant compliance gaps require immediate attention")

        return findings

    def _generate_recommendations(
        self, controls: list[dict[str, Any]], violations: list[dict[str, Any]]
    ) -> list[str]:
        """Generate recommendations."""
        recommendations = []

        non_compliant_controls = [c for c in controls if c["status"] == "non_compliant"]
        if non_compliant_controls:
            recommendations.append(
                f"Address {len(non_compliant_controls)} non-compliant controls immediately"
            )

        partial_controls = [c for c in controls if c["status"] == "partial"]
        if partial_controls:
            recommendations.append(
                f"Improve {len(partial_controls)} partially compliant controls"
            )

        open_violations = [
            v for v in violations if v.get("remediation_status") != "resolved"
        ]
        if open_violations:
            recommendations.append(
                f"Resolve {len(open_violations)} outstanding violations"
            )

        recommendations.append(
            "Implement continuous monitoring for compliance controls"
        )
        recommendations.append("Schedule regular compliance assessments")

        return recommendations

    def _generate_executive_summary(
        self,
        framework: str,
        compliance_score: float,
        violation_count: int,
        overall_status: str,
    ) -> str:
        """Generate executive summary."""
        status_text = {
            "compliant": "meets",
            "partial": "partially meets",
            "non_compliant": "does not meet",
        }

        summary = f"This compliance assessment evaluates the organization's adherence to {framework} requirements. "
        summary += f"The organization currently {status_text.get(overall_status, 'has unknown status for')} "
        summary += f"compliance requirements with an overall score of {compliance_score:.1f}%. "

        if violation_count > 0:
            summary += f"The assessment identified {violation_count} compliance violations requiring attention. "
        else:
            summary += "No compliance violations were identified during this assessment period. "

        if compliance_score >= 95:
            summary += "The organization demonstrates strong compliance controls and practices."
        elif compliance_score >= 80:
            summary += "While generally compliant, some areas require improvement to achieve full compliance."
        else:
            summary += "Significant compliance gaps exist that require immediate remediation efforts."

        return summary

    @property
    def query_type(self) -> type[GetComplianceReportQuery]:
        """Get query type this handler processes."""
        return GetComplianceReportQuery


__all__ = ["GetComplianceReportQuery", "GetComplianceReportQueryHandler"]
