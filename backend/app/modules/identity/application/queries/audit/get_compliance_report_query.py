"""
Get compliance report query implementation.

Handles retrieval of compliance reports for various regulatory frameworks
including GDPR, HIPAA, SOX, PCI-DSS, and custom compliance requirements.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditRepository,
    IComplianceRepository,
    ISecurityRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import ComplianceReportResponse
from app.modules.identity.domain.enums import ComplianceFramework, ComplianceStatus
from app.modules.identity.domain.exceptions import (
    ComplianceQueryError,
    InvalidReportParametersError,
    UnauthorizedAccessError,
)


class ReportPeriod(Enum):
    """Compliance report time periods."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"
    CUSTOM = "custom"


class ReportFormat(Enum):
    """Compliance report output formats."""
    SUMMARY = "summary"
    DETAILED = "detailed"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    REGULATORY = "regulatory"


@dataclass
class GetComplianceReportQuery(Query[ComplianceReportResponse]):
    """Query to retrieve compliance reports."""

    # Access control
    requester_id: UUID

    # Report parameters
    framework: ComplianceFramework
    report_period: ReportPeriod
    start_date: datetime | None = None
    end_date: datetime | None = None
    report_format: ReportFormat = ReportFormat.SUMMARY
    
    # Scope filters
    user_ids: list[UUID] | None = None
    department_ids: list[UUID] | None = None
    system_components: list[str] | None = None
    data_categories: list[str] | None = None
    
    # Report options
    include_recommendations: bool = True
    include_remediation_plan: bool = False
    include_executive_summary: bool = True
    include_risk_assessment: bool = True
    include_trend_analysis: bool = False
    
    # Output options
    export_format: str | None = None
    language: str = "en"
    timezone: str = "UTC"
    
    # Access control
    requester_permissions: list[str] = field(default_factory=list)


class GetComplianceReportQueryHandler(QueryHandler[GetComplianceReportQuery, ComplianceReportResponse]):
    """Handler for compliance report queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        compliance_repository: IComplianceRepository,
        user_repository: IUserRepository,
        security_repository: ISecurityRepository
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.compliance_repository = compliance_repository
        self.user_repository = user_repository
        self.security_repository = security_repository
    
    @rate_limit(max_calls=20, window_seconds=3600)
    @require_permission("compliance.read")
    @validate_request
    async def handle(self, query: GetComplianceReportQuery) -> ComplianceReportResponse:
        """Handle compliance report query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_compliance_access(query)
                
                # Normalize date range
                start_date, end_date = await self._normalize_date_range(query)
                
                # Generate compliance assessment
                compliance_status = await self._assess_compliance_status(
                    query.framework, start_date, end_date, query
                )
                
                # Generate findings
                findings = await self._generate_compliance_findings(
                    query.framework, start_date, end_date, query
                )
                
                # Generate metrics
                metrics = await self._generate_compliance_metrics(
                    query.framework, start_date, end_date, query
                )
                
                # Generate recommendations if requested
                recommendations = []
                if query.include_recommendations:
                    recommendations = await self._generate_recommendations(
                        compliance_status, findings, query.framework
                    )
                
                # Generate remediation plan if requested
                remediation_plan = None
                if query.include_remediation_plan:
                    remediation_plan = await self._generate_remediation_plan(
                        findings, query.framework
                    )
                
                # Generate executive summary if requested
                executive_summary = None
                if query.include_executive_summary:
                    executive_summary = await self._generate_executive_summary(
                        compliance_status, findings, metrics
                    )
                
                # Generate risk assessment if requested
                risk_assessment = None
                if query.include_risk_assessment:
                    risk_assessment = await self._generate_risk_assessment(
                        findings, query.framework
                    )
                
                # Generate trend analysis if requested
                trend_analysis = None
                if query.include_trend_analysis:
                    trend_analysis = await self._generate_trend_analysis(
                        query.framework, start_date, end_date
                    )
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        compliance_status, findings, metrics, query.export_format
                    )
                
                return ComplianceReportResponse(
                    framework=query.framework,
                    report_period=query.report_period,
                    start_date=start_date,
                    end_date=end_date,
                    compliance_status=compliance_status,
                    findings=findings,
                    metrics=metrics,
                    recommendations=recommendations,
                    remediation_plan=remediation_plan,
                    executive_summary=executive_summary,
                    risk_assessment=risk_assessment,
                    trend_analysis=trend_analysis,
                    export_data=export_data,
                    generated_at=datetime.now(UTC),
                    report_id=str(UUID.uuid4())
                )
                
        except Exception as e:
            raise ComplianceQueryError(f"Failed to generate compliance report: {e!s}") from e
    
    async def _validate_compliance_access(self, query: GetComplianceReportQuery) -> None:
        """Validate user has appropriate permissions for compliance reporting."""
        
        # Check basic compliance read permission
        if "compliance.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for compliance access")
        
        # Check framework-specific permissions
        framework_permission = f"compliance.{query.framework.value}.read"
        if framework_permission not in query.requester_permissions:
            raise UnauthorizedAccessError(f"No access to {query.framework.value} compliance data")
        
        # Check admin access for detailed reports
        if query.report_format in [ReportFormat.TECHNICAL, ReportFormat.DETAILED]:
            if "compliance.admin" not in query.requester_permissions:
                raise UnauthorizedAccessError("Admin permissions required for detailed reports")
    
    async def _normalize_date_range(self, query: GetComplianceReportQuery) -> tuple[datetime, datetime]:
        """Normalize and validate date range for the report."""
        
        if query.start_date and query.end_date:
            start_date, end_date = query.start_date, query.end_date
        else:
            # Calculate based on report period
            end_date = datetime.now(UTC)
            
            if query.report_period == ReportPeriod.DAILY:
                start_date = end_date - timedelta(days=1)
            elif query.report_period == ReportPeriod.WEEKLY:
                start_date = end_date - timedelta(weeks=1)
            elif query.report_period == ReportPeriod.MONTHLY:
                start_date = end_date - timedelta(days=30)
            elif query.report_period == ReportPeriod.QUARTERLY:
                start_date = end_date - timedelta(days=90)
            elif query.report_period == ReportPeriod.ANNUALLY:
                start_date = end_date - timedelta(days=365)
            else:
                raise InvalidReportParametersError("Custom period requires start_date and end_date")
        
        # Validate date range
        if start_date >= end_date:
            raise InvalidReportParametersError("Start date must be before end date")
        
        if (end_date - start_date).days > 365:
            raise InvalidReportParametersError("Report period cannot exceed 365 days")
        
        return start_date, end_date
    
    async def _assess_compliance_status(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime,
        query: GetComplianceReportQuery
    ) -> dict[str, Any]:
        """Assess overall compliance status for the framework."""
        
        # Get framework requirements
        requirements = await self.compliance_repository.get_framework_requirements(framework)
        
        # Assess each requirement
        requirement_statuses = []
        overall_score = 0
        
        for requirement in requirements:
            status = await self._assess_requirement_compliance(
                requirement, start_date, end_date, query
            )
            requirement_statuses.append(status)
            overall_score += status["score"]
        
        # Calculate overall compliance percentage
        if requirements:
            overall_percentage = (overall_score / len(requirements)) * 100
        else:
            overall_percentage = 100
        
        # Determine compliance level
        if overall_percentage >= 95:
            compliance_level = ComplianceStatus.COMPLIANT
        elif overall_percentage >= 80:
            compliance_level = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            compliance_level = ComplianceStatus.NON_COMPLIANT
        
        return {
            "framework": framework.value,
            "overall_percentage": overall_percentage,
            "compliance_level": compliance_level.value,
            "requirements_assessed": len(requirements),
            "requirements_met": len([r for r in requirement_statuses if r["score"] >= 80]),
            "requirement_statuses": requirement_statuses,
            "assessment_date": datetime.now(UTC)
        }
    
    async def _assess_requirement_compliance(
        self,
        requirement: dict[str, Any],
        start_date: datetime,
        end_date: datetime,
        query: GetComplianceReportQuery
    ) -> dict[str, Any]:
        """Assess compliance for a specific requirement."""
        
        # Get relevant audit data for the requirement
        audit_data = await self.audit_repository.get_compliance_audit_data(
            requirement["id"], start_date, end_date
        )
        
        # Apply requirement-specific assessment logic
        score = await self._calculate_requirement_score(requirement, audit_data)
        
        # Determine status
        if score >= 95:
            status = "compliant"
        elif score >= 80:
            status = "partially_compliant"
        else:
            status = "non_compliant"
        
        # Identify evidence
        evidence = await self._collect_requirement_evidence(requirement, audit_data)
        
        # Identify gaps
        gaps = await self._identify_requirement_gaps(requirement, audit_data, score)
        
        return {
            "requirement_id": requirement["id"],
            "requirement_name": requirement["name"],
            "requirement_description": requirement["description"],
            "score": score,
            "status": status,
            "evidence": evidence,
            "gaps": gaps,
            "last_assessed": datetime.now(UTC)
        }
    
    async def _generate_compliance_findings(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime,
        query: GetComplianceReportQuery
    ) -> list[dict[str, Any]]:
        """Generate compliance findings and violations."""
        
        findings = []
        
        # Get compliance violations
        violations = await self.compliance_repository.get_violations(
            framework, start_date, end_date
        )
        
        for violation in violations:
            finding = {
                "id": str(UUID.uuid4()),
                "type": "violation",
                "severity": violation.get("severity", "medium"),
                "title": violation.get("title", "Compliance Violation"),
                "description": violation.get("description", ""),
                "requirement": violation.get("requirement", ""),
                "detected_at": violation.get("detected_at"),
                "affected_users": violation.get("affected_users", []),
                "remediation_status": violation.get("remediation_status", "open"),
                "risk_level": violation.get("risk_level", "medium")
            }
            findings.append(finding)
        
        # Get policy violations
        policy_violations = await self.security_repository.get_policy_violations(
            start_date, end_date
        )
        
        for violation in policy_violations:
            if self._is_compliance_relevant(violation, framework):
                finding = {
                    "id": str(UUID.uuid4()),
                    "type": "policy_violation",
                    "severity": violation.get("severity", "medium"),
                    "title": f"Policy Violation: {violation.get('policy_name', 'Unknown')}",
                    "description": violation.get("description", ""),
                    "requirement": self._map_to_compliance_requirement(violation, framework),
                    "detected_at": violation.get("detected_at"),
                    "affected_users": violation.get("affected_users", []),
                    "remediation_status": "open",
                    "risk_level": violation.get("risk_level", "medium")
                }
                findings.append(finding)
        
        return findings
    
    async def _generate_compliance_metrics(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime,
        query: GetComplianceReportQuery
    ) -> dict[str, Any]:
        """Generate compliance metrics and KPIs."""
        
        # Get basic metrics
        total_users = await self.user_repository.count_active_users()
        total_audited_events = await self.audit_repository.count_events(start_date, end_date)
        
        # Get compliance-specific metrics
        compliance_events = await self.compliance_repository.get_compliance_events(
            framework, start_date, end_date
        )
        
        # Calculate metrics
        return {
            "period": {
                "start_date": start_date,
                "end_date": end_date,
                "duration_days": (end_date - start_date).days
            },
            "user_metrics": {
                "total_active_users": total_users,
                "users_with_violations": len({
                    event.get("user_id") for event in compliance_events 
                    if event.get("type") == "violation"
                }),
                "compliance_training_completion": await self._get_training_metrics(framework)
            },
            "audit_metrics": {
                "total_events": total_audited_events,
                "compliance_events": len(compliance_events),
                "violation_events": len([e for e in compliance_events if e.get("type") == "violation"]),
                "remediation_events": len([e for e in compliance_events if e.get("type") == "remediation"])
            },
            "time_metrics": {
                "average_detection_time": await self._calculate_average_detection_time(compliance_events),
                "average_remediation_time": await self._calculate_average_remediation_time(compliance_events),
                "compliance_review_frequency": await self._get_review_frequency(framework)
            },
            "risk_metrics": {
                "high_risk_findings": len([e for e in compliance_events if e.get("risk_level") == "high"]),
                "medium_risk_findings": len([e for e in compliance_events if e.get("risk_level") == "medium"]),
                "low_risk_findings": len([e for e in compliance_events if e.get("risk_level") == "low"])
            }
        }
        
    
    async def _generate_recommendations(
        self,
        compliance_status: dict[str, Any],
        findings: list[dict[str, Any]],
        framework: ComplianceFramework
    ) -> list[dict[str, Any]]:
        """Generate compliance improvement recommendations."""
        
        recommendations = []
        
        # Analyze compliance gaps
        for requirement in compliance_status.get("requirement_statuses", []):
            if requirement["score"] < 95:
                for gap in requirement.get("gaps", []):
                    recommendation = {
                        "id": str(UUID.uuid4()),
                        "priority": self._determine_priority(gap, requirement["score"]),
                        "category": "requirement_gap",
                        "title": f"Address {requirement['requirement_name']} Gap",
                        "description": gap.get("description", ""),
                        "suggested_actions": gap.get("suggested_actions", []),
                        "estimated_effort": gap.get("estimated_effort", "medium"),
                        "expected_impact": gap.get("expected_impact", "medium"),
                        "timeline": gap.get("timeline", "30 days")
                    }
                    recommendations.append(recommendation)
        
        # Analyze findings patterns
        high_severity_findings = [f for f in findings if f.get("severity") == "high"]
        if high_severity_findings:
            recommendation = {
                "id": str(UUID.uuid4()),
                "priority": "high",
                "category": "immediate_action",
                "title": "Address High Severity Findings",
                "description": f"Immediate attention required for {len(high_severity_findings)} high severity findings",
                "suggested_actions": [
                    "Review and remediate high severity violations immediately",
                    "Implement additional monitoring controls",
                    "Conduct root cause analysis"
                ],
                "estimated_effort": "high",
                "expected_impact": "high",
                "timeline": "7 days"
            }
            recommendations.append(recommendation)
        
        return recommendations
    
    async def _generate_remediation_plan(
        self,
        findings: list[dict[str, Any]],
        framework: ComplianceFramework
    ) -> dict[str, Any]:
        """Generate a remediation plan for compliance issues."""
        
        # Group findings by priority and type
        high_priority = [f for f in findings if f.get("severity") == "high"]
        medium_priority = [f for f in findings if f.get("severity") == "medium"]
        low_priority = [f for f in findings if f.get("severity") == "low"]
        
        # Create action items
        action_items = []
        
        # High priority actions (immediate)
        for finding in high_priority:
            action_items.append({
                "id": str(UUID.uuid4()),
                "priority": "high",
                "title": f"Remediate: {finding['title']}",
                "description": finding.get("description", ""),
                "timeline": "1-7 days",
                "assigned_to": "Security Team",
                "dependencies": [],
                "success_criteria": f"Resolve violation for requirement {finding.get('requirement', '')}"
            })
        
        # Medium priority actions (short term)
        for finding in medium_priority:
            action_items.append({
                "id": str(UUID.uuid4()),
                "priority": "medium",
                "title": f"Address: {finding['title']}",
                "description": finding.get("description", ""),
                "timeline": "1-4 weeks",
                "assigned_to": "Compliance Team",
                "dependencies": [],
                "success_criteria": f"Improve compliance score for {finding.get('requirement', '')}"
            })
        
        return {
            "plan_id": str(UUID.uuid4()),
            "framework": framework.value,
            "created_at": datetime.now(UTC),
            "total_actions": len(action_items),
            "high_priority_actions": len(high_priority),
            "medium_priority_actions": len(medium_priority),
            "low_priority_actions": len(low_priority),
            "estimated_completion": await self._estimate_completion_date(action_items),
            "action_items": action_items
        }
    
    async def _generate_executive_summary(
        self,
        compliance_status: dict[str, Any],
        findings: list[dict[str, Any]],
        metrics: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate executive summary of compliance status."""
        
        return {
            "overall_status": compliance_status.get("compliance_level", "unknown"),
            "compliance_percentage": compliance_status.get("overall_percentage", 0),
            "key_metrics": {
                "total_findings": len(findings),
                "high_risk_findings": len([f for f in findings if f.get("severity") == "high"]),
                "total_users_assessed": metrics.get("user_metrics", {}).get("total_active_users", 0),
                "audit_events_reviewed": metrics.get("audit_metrics", {}).get("total_events", 0)
            },
            "top_concerns": await self._identify_top_concerns(findings),
            "recommended_actions": await self._get_executive_recommendations(compliance_status, findings),
            "compliance_trend": await self._get_compliance_trend(compliance_status),
            "next_review_date": await self._calculate_next_review_date(compliance_status)
        }
    
    # Helper methods (placeholder implementations)
    async def _calculate_requirement_score(self, requirement: dict[str, Any], audit_data: list[dict[str, Any]]) -> float:
        """Calculate compliance score for a requirement."""
        # Implementation would depend on requirement type and audit data
        return 85.0
    
    async def _collect_requirement_evidence(self, requirement: dict[str, Any], audit_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Collect evidence for requirement compliance."""
        return []
    
    async def _identify_requirement_gaps(self, requirement: dict[str, Any], audit_data: list[dict[str, Any]], score: float) -> list[dict[str, Any]]:
        """Identify gaps in requirement compliance."""
        return []
    
    async def _is_compliance_relevant(self, violation: dict[str, Any], framework: ComplianceFramework) -> bool:
        """Check if violation is relevant to the compliance framework."""
        return True
    
    async def _map_to_compliance_requirement(self, violation: dict[str, Any], framework: ComplianceFramework) -> str:
        """Map violation to compliance requirement."""
        return "General Security"
    
    async def _get_training_metrics(self, framework: ComplianceFramework) -> dict[str, Any]:
        """Get compliance training metrics."""
        return {"completion_rate": 85.0, "total_trained": 100}
    
    async def _calculate_average_detection_time(self, events: list[dict[str, Any]]) -> float:
        """Calculate average detection time for compliance events."""
        return 2.5  # hours
    
    async def _calculate_average_remediation_time(self, events: list[dict[str, Any]]) -> float:
        """Calculate average remediation time."""
        return 24.0  # hours
    
    async def _get_review_frequency(self, framework: ComplianceFramework) -> str:
        """Get compliance review frequency."""
        return "monthly"
    
    async def _determine_priority(self, gap: dict[str, Any], score: float) -> str:
        """Determine priority based on gap and score."""
        if score < 70:
            return "high"
        if score < 85:
            return "medium"
        return "low"
    
    async def _estimate_completion_date(self, action_items: list[dict[str, Any]]) -> datetime:
        """Estimate completion date for remediation plan."""
        return datetime.now(UTC) + timedelta(days=30)
    
    async def _identify_top_concerns(self, findings: list[dict[str, Any]]) -> list[str]:
        """Identify top compliance concerns."""
        return ["Data access controls", "Audit trail completeness", "User access reviews"]
    
    async def _get_executive_recommendations(self, compliance_status: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
        """Get executive-level recommendations."""
        return ["Implement automated compliance monitoring", "Increase audit frequency", "Enhance staff training"]
    
    async def _get_compliance_trend(self, compliance_status: dict[str, Any]) -> str:
        """Get compliance trend direction."""
        return "improving"
    
    async def _calculate_next_review_date(self, compliance_status: dict[str, Any]) -> datetime:
        """Calculate next compliance review date."""
        return datetime.now(UTC) + timedelta(days=90)
    
    async def _prepare_export_data(
        self,
        compliance_status: dict[str, Any],
        findings: list[dict[str, Any]],
        metrics: dict[str, Any],
        export_format: str
    ) -> dict[str, Any]:
        """Prepare compliance report for export."""
        return {
            "format": export_format,
            "content": f"Compliance report in {export_format} format",
            "filename": f"compliance_report_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}"
        }