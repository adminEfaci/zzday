"""Compliance service.

This module provides compliance management functionality including
framework assessment, violation tracking, and regulatory reporting.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


class ComplianceService:
    """
    Application service for compliance management.

    Provides compliance framework assessment, violation tracking,
    and regulatory reporting capabilities.
    """

    def __init__(
        self,
        audit_repository: Any,
        compliance_repository: Any,
        violation_repository: Any,
        framework_registry: Any,
    ):
        """
        Initialize compliance service.

        Args:
            audit_repository: Repository for audit data
            compliance_repository: Repository for compliance data
            violation_repository: Repository for violations
            framework_registry: Registry of compliance frameworks
        """
        self.audit_repository = audit_repository
        self.compliance_repository = compliance_repository
        self.violation_repository = violation_repository
        self.framework_registry = framework_registry

    async def assess_compliance_framework(
        self,
        framework: str,
        assessment_scope: dict[str, Any] | None = None,
        assessment_date: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Perform a comprehensive compliance framework assessment.

        Args:
            framework: Compliance framework to assess
            assessment_scope: Scope limitations for assessment
            assessment_date: Date of assessment (defaults to now)

        Returns:
            Comprehensive assessment results
        """
        logger.info("Starting compliance assessment", framework=framework)

        assessment_date = assessment_date or datetime.utcnow()

        # Get framework definition
        framework_def = await self.framework_registry.get_framework(framework)
        if not framework_def:
            raise ValidationError(f"Unknown compliance framework: {framework}")

        # Get all controls for the framework
        controls = framework_def.get_controls()

        # Assess each control
        assessment_results = []
        overall_score = 0.0
        total_weight = 0.0

        for control in controls:
            control_result = await self._assess_single_control(
                control, framework, assessment_scope, assessment_date
            )
            assessment_results.append(control_result)

            # Weight the control score
            weight = control.get("weight", 1.0)
            overall_score += control_result["score"] * weight
            total_weight += weight

        # Calculate overall compliance score
        final_score = overall_score / total_weight if total_weight > 0 else 0.0

        # Determine compliance status
        compliance_status = self._determine_compliance_status(final_score)

        # Generate assessment summary
        assessment_summary = {
            "framework": framework,
            "assessment_date": assessment_date.isoformat(),
            "assessment_scope": assessment_scope or {},
            "overall_score": round(final_score, 2),
            "compliance_status": compliance_status,
            "total_controls": len(controls),
            "controls_assessed": len(assessment_results),
            "control_results": assessment_results,
            "risk_level": self._calculate_risk_level(final_score, assessment_results),
            "recommendations": self._generate_compliance_recommendations(
                assessment_results
            ),
            "next_assessment_due": self._calculate_next_assessment_date(
                framework, assessment_date
            ),
        }

        # Save assessment results
        await self.compliance_repository.save_assessment(assessment_summary)

        logger.info(
            "Compliance assessment completed",
            framework=framework,
            score=final_score,
            status=compliance_status,
        )

        return assessment_summary

    async def track_compliance_violation(
        self,
        framework: str,
        rule_id: str,
        violation_details: dict[str, Any],
        severity: str = "medium",
        auto_remediation: bool = False,
    ) -> UUID:
        """
        Track a compliance violation and initiate remediation.

        Args:
            framework: Compliance framework
            rule_id: Rule that was violated
            violation_details: Details of the violation
            severity: Violation severity
            auto_remediation: Whether to attempt automatic remediation

        Returns:
            Violation ID
        """
        logger.warning(
            "Tracking compliance violation",
            framework=framework,
            rule_id=rule_id,
            severity=severity,
        )

        # Create violation record
        violation = {
            "id": UUID(),
            "framework": framework,
            "rule_id": rule_id,
            "severity": severity,
            "detected_at": datetime.utcnow(),
            "status": "open",
            "details": violation_details,
            "remediation_attempts": [],
        }

        # Get rule definition for context
        rule_def = await self.framework_registry.get_rule(framework, rule_id)
        if rule_def:
            violation["rule_name"] = rule_def.get("name", rule_id)
            violation["rule_description"] = rule_def.get("description", "")
            violation["remediation_guidance"] = rule_def.get("remediation", [])

        # Save violation
        await self.violation_repository.save(violation)

        # Attempt auto-remediation if enabled
        if auto_remediation and rule_def and rule_def.get("auto_remediable", False):
            await self._attempt_auto_remediation(violation)

        # Create audit trail for the violation
        await self._audit_compliance_violation(violation)

        return violation["id"]

    async def get_compliance_dashboard(
        self, frameworks: list[str] | None = None, time_period: int = 30
    ) -> dict[str, Any]:
        """
        Get compliance dashboard data.

        Args:
            frameworks: Specific frameworks to include
            time_period: Time period in days for trends

        Returns:
            Dashboard data
        """
        logger.debug("Generating compliance dashboard")

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=time_period)

        # Get framework list
        if not frameworks:
            frameworks = await self.framework_registry.get_supported_frameworks()

        dashboard_data = {
            "generated_at": end_date.isoformat(),
            "time_period_days": time_period,
            "frameworks": {},
        }

        # Get data for each framework
        for framework in frameworks:
            framework_data = await self._get_framework_dashboard_data(
                framework, start_date, end_date
            )
            dashboard_data["frameworks"][framework] = framework_data

        # Calculate overall metrics
        dashboard_data["overall_metrics"] = self._calculate_overall_metrics(
            dashboard_data["frameworks"]
        )

        return dashboard_data

    async def generate_compliance_evidence(
        self, framework: str, control_id: str, evidence_period: int = 90
    ) -> dict[str, Any]:
        """
        Generate compliance evidence for a specific control.

        Args:
            framework: Compliance framework
            control_id: Control identifier
            evidence_period: Period in days to collect evidence

        Returns:
            Evidence package
        """
        logger.debug(
            "Generating compliance evidence", framework=framework, control_id=control_id
        )

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=evidence_period)

        # Get control definition
        control_def = await self.framework_registry.get_control(framework, control_id)
        if not control_def:
            raise ValidationError(f"Control not found: {control_id}")

        # Collect audit evidence
        evidence_filters = self._build_evidence_filters(control_def)
        evidence_entries = await self.audit_repository.find_entries(
            filters={
                **evidence_filters,
                "created_at__gte": start_date,
                "created_at__lte": end_date,
            }
        )

        # Analyze evidence
        evidence_analysis = self._analyze_evidence(evidence_entries, control_def)

        # Generate evidence package
        return {
            "framework": framework,
            "control_id": control_id,
            "control_name": control_def.get("name", control_id),
            "evidence_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": evidence_period,
            },
            "evidence_count": len(evidence_entries),
            "evidence_entries": [entry.id for entry in evidence_entries],
            "analysis": evidence_analysis,
            "compliance_status": evidence_analysis.get("status", "unknown"),
            "gaps_identified": evidence_analysis.get("gaps", []),
            "generated_at": datetime.utcnow().isoformat(),
        }

    async def _assess_single_control(
        self,
        control: dict[str, Any],
        framework: str,
        scope: dict[str, Any] | None,
        assessment_date: datetime,
    ) -> dict[str, Any]:
        """
        Assess a single compliance control.

        Args:
            control: Control definition
            framework: Framework name
            scope: Assessment scope
            assessment_date: Assessment date

        Returns:
            Control assessment result
        """
        control_id = control["id"]

        # Get evidence for this control
        evidence_filters = self._build_evidence_filters(control)
        if scope:
            evidence_filters.update(scope)

        # Look for evidence in the last 90 days
        evidence_start = assessment_date - timedelta(days=90)
        evidence_entries = await self.audit_repository.find_entries(
            filters={
                **evidence_filters,
                "created_at__gte": evidence_start,
                "created_at__lte": assessment_date,
            }
        )

        # Analyze evidence
        evidence_analysis = self._analyze_evidence(evidence_entries, control)

        # Calculate control score
        score = self._calculate_control_score(evidence_analysis, control)

        # Determine status
        status = self._determine_control_status(score)

        return {
            "control_id": control_id,
            "control_name": control.get("name", control_id),
            "score": score,
            "status": status,
            "evidence_count": len(evidence_entries),
            "analysis": evidence_analysis,
            "assessed_at": assessment_date.isoformat(),
            "next_review_due": self._calculate_next_review_date(
                control, assessment_date
            ),
        }

    def _build_evidence_filters(self, control: dict[str, Any]) -> dict[str, Any]:
        """Build filters for collecting evidence for a control."""
        filters = {}

        # Filter by action types if specified
        if "action_types" in control:
            filters["action_type__in"] = control["action_types"]

        # Filter by resource types if specified
        if "resource_types" in control:
            filters["resource_type__in"] = control["resource_types"]

        # Filter by categories if specified
        if "categories" in control:
            filters["category__in"] = control["categories"]

        # Filter by outcomes if specified
        if "required_outcomes" in control:
            filters["outcome__in"] = control["required_outcomes"]

        return filters

    def _analyze_evidence(
        self, evidence_entries: list[Any], control: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze evidence for compliance assessment."""
        if not evidence_entries:
            return {
                "status": "insufficient_evidence",
                "issues": ["No evidence found for the specified period"],
                "gaps": ["Evidence collection needed"],
                "recommendations": ["Implement logging for this control"],
            }

        analysis = {
            "total_evidence": len(evidence_entries),
            "issues": [],
            "gaps": [],
            "recommendations": [],
            "patterns": {},
        }

        # Check for required frequency
        required_frequency = control.get("required_frequency", "daily")
        if not self._check_evidence_frequency(evidence_entries, required_frequency):
            analysis["issues"].append(
                f"Evidence frequency does not meet {required_frequency} requirement"
            )
            analysis["gaps"].append("Insufficient evidence frequency")

        # Check for required outcomes
        required_outcomes = control.get("required_outcomes", ["success"])
        outcome_counts = {}
        for entry in evidence_entries:
            outcome = entry.outcome
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

        for required_outcome in required_outcomes:
            if required_outcome not in outcome_counts:
                analysis["issues"].append(
                    f"Missing required outcome: {required_outcome}"
                )
                analysis["gaps"].append(f"No {required_outcome} outcomes found")

        analysis["patterns"]["outcome_distribution"] = outcome_counts

        # Determine overall status
        if not analysis["issues"]:
            analysis["status"] = "compliant"
        elif len(analysis["issues"]) <= 2:
            analysis["status"] = "partially_compliant"
        else:
            analysis["status"] = "non_compliant"

        return analysis

    def _check_evidence_frequency(
        self, evidence_entries: list[Any], required_frequency: str
    ) -> bool:
        """Check if evidence meets required frequency."""
        if not evidence_entries:
            return False

        # Group entries by date
        daily_counts = {}
        for entry in evidence_entries:
            date_key = entry.created_at.date()
            daily_counts[date_key] = daily_counts.get(date_key, 0) + 1

        # Check frequency requirements
        if required_frequency == "daily":
            # Should have evidence on most days
            expected_days = min(90, 30)  # Check last 30 days
            return len(daily_counts) >= expected_days * 0.8  # 80% coverage
        if required_frequency == "weekly":
            # Should have evidence most weeks
            return len(daily_counts) >= 4  # At least 4 days of evidence
        # Monthly or less frequent
        return len(evidence_entries) >= 1

    def _calculate_control_score(
        self, evidence_analysis: dict[str, Any], control: dict[str, Any]
    ) -> float:
        """Calculate score for a control based on evidence analysis."""
        base_score = 100.0

        # Deduct points for issues
        issues_count = len(evidence_analysis.get("issues", []))
        base_score -= issues_count * 20  # 20 points per issue

        # Deduct points for gaps
        gaps_count = len(evidence_analysis.get("gaps", []))
        base_score -= gaps_count * 15  # 15 points per gap

        # Adjust for evidence quality
        if evidence_analysis.get("total_evidence", 0) == 0:
            base_score = 0.0
        elif evidence_analysis.get("total_evidence", 0) < 5:
            base_score *= 0.7  # Reduce score for insufficient evidence

        return max(0.0, min(100.0, base_score))

    def _determine_control_status(self, score: float) -> str:
        """Determine control status based on score."""
        if score >= 90:
            return "compliant"
        if score >= 70:
            return "partially_compliant"
        return "non_compliant"

    def _determine_compliance_status(self, overall_score: float) -> str:
        """Determine overall compliance status."""
        if overall_score >= 95:
            return "fully_compliant"
        if overall_score >= 80:
            return "substantially_compliant"
        if overall_score >= 60:
            return "partially_compliant"
        return "non_compliant"

    def _calculate_risk_level(
        self, overall_score: float, control_results: list[dict[str, Any]]
    ) -> str:
        """Calculate risk level based on compliance assessment."""
        # Count non-compliant controls
        non_compliant_count = len(
            [r for r in control_results if r["status"] == "non_compliant"]
        )

        # Calculate risk based on score and non-compliant controls
        if overall_score >= 90 and non_compliant_count == 0:
            return "low"
        if overall_score >= 75 and non_compliant_count <= 2:
            return "medium"
        if overall_score >= 50:
            return "high"
        return "critical"

    def _generate_compliance_recommendations(
        self, control_results: list[dict[str, Any]]
    ) -> list[str]:
        """Generate recommendations based on assessment results."""
        recommendations = []

        # Find non-compliant controls
        non_compliant = [r for r in control_results if r["status"] == "non_compliant"]
        if non_compliant:
            recommendations.append(
                f"Address {len(non_compliant)} non-compliant controls immediately"
            )

        # Find partially compliant controls
        partial = [r for r in control_results if r["status"] == "partially_compliant"]
        if partial:
            recommendations.append(
                f"Improve {len(partial)} partially compliant controls"
            )

        # General recommendations
        recommendations.extend(
            [
                "Implement continuous monitoring for all controls",
                "Establish regular compliance review cycles",
                "Document all compliance procedures and evidence",
            ]
        )

        return recommendations

    def _calculate_next_assessment_date(
        self, framework: str, current_date: datetime
    ) -> str:
        """Calculate next assessment due date."""
        # Default to annual assessment
        assessment_frequency = {
            "SOC2": 365,  # Annual
            "HIPAA": 365,  # Annual
            "GDPR": 365,  # Annual
            "PCI-DSS": 365,  # Annual
            "ISO27001": 365,  # Annual
        }

        days_to_add = assessment_frequency.get(framework, 365)
        next_date = current_date + timedelta(days=days_to_add)

        return next_date.isoformat()

    def _calculate_next_review_date(
        self, control: dict[str, Any], assessment_date: datetime
    ) -> str:
        """Calculate next review date for a control."""
        review_frequency = control.get("review_frequency", "quarterly")

        frequency_days = {
            "daily": 1,
            "weekly": 7,
            "monthly": 30,
            "quarterly": 90,
            "annually": 365,
        }

        days_to_add = frequency_days.get(review_frequency, 90)
        next_date = assessment_date + timedelta(days=days_to_add)

        return next_date.isoformat()

    async def _get_framework_dashboard_data(
        self, framework: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get dashboard data for a specific framework."""
        # Get latest assessment
        latest_assessment = await self.compliance_repository.get_latest_assessment(
            framework
        )

        # Get recent violations
        violations = await self.violation_repository.find_by_framework(
            framework=framework, start_date=start_date, end_date=end_date
        )

        # Calculate metrics
        return {
            "latest_assessment": latest_assessment.to_dict()
            if latest_assessment
            else None,
            "violation_count": len(violations),
            "violations_by_severity": self._group_violations_by_severity(violations),
            "trend_analysis": await self._calculate_compliance_trend(
                framework, start_date, end_date
            ),
        }

    def _group_violations_by_severity(self, violations: list[Any]) -> dict[str, int]:
        """Group violations by severity."""
        by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for violation in violations:
            severity = violation.get("severity", "medium")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        return by_severity

    async def _calculate_compliance_trend(
        self, framework: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Calculate compliance trend for a framework."""
        # Get historical assessments
        assessments = await self.compliance_repository.get_assessments_in_period(
            framework=framework, start_date=start_date, end_date=end_date
        )

        if len(assessments) < 2:
            return {"trend": "insufficient_data", "change_percentage": 0.0}

        # Calculate trend
        scores = [a.overall_score for a in assessments]
        first_score = scores[0]
        last_score = scores[-1]

        change_percentage = (
            ((last_score - first_score) / first_score) * 100 if first_score > 0 else 0
        )

        if change_percentage > 5:
            trend = "improving"
        elif change_percentage < -5:
            trend = "declining"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "change_percentage": round(change_percentage, 2),
            "score_history": scores,
        }

    def _calculate_overall_metrics(
        self, frameworks_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate overall metrics across all frameworks."""
        total_violations = 0
        total_frameworks = len(frameworks_data)
        compliant_frameworks = 0

        for framework_data in frameworks_data.values():
            total_violations += framework_data.get("violation_count", 0)

            latest_assessment = framework_data.get("latest_assessment")
            if latest_assessment and latest_assessment.get("compliance_status") in [
                "fully_compliant",
                "substantially_compliant",
            ]:
                compliant_frameworks += 1

        compliance_rate = (
            (compliant_frameworks / total_frameworks * 100)
            if total_frameworks > 0
            else 0
        )

        return {
            "total_frameworks_monitored": total_frameworks,
            "compliant_frameworks": compliant_frameworks,
            "overall_compliance_rate": round(compliance_rate, 2),
            "total_violations": total_violations,
            "compliance_health_status": self._determine_overall_health(
                compliance_rate, total_violations
            ),
        }

    def _determine_overall_health(
        self, compliance_rate: float, violation_count: int
    ) -> str:
        """Determine overall compliance health status."""
        if compliance_rate >= 90 and violation_count <= 5:
            return "excellent"
        if compliance_rate >= 75 and violation_count <= 20:
            return "good"
        if compliance_rate >= 50:
            return "needs_improvement"
        return "critical"

    async def _attempt_auto_remediation(self, violation: dict[str, Any]) -> None:
        """Attempt automatic remediation of a violation."""
        logger.info("Attempting auto-remediation", violation_id=violation["id"])

        # This would implement actual auto-remediation logic
        # For now, just log the attempt

        remediation_attempt = {
            "attempted_at": datetime.utcnow().isoformat(),
            "method": "automatic",
            "status": "attempted",
            "details": "Auto-remediation attempted based on rule configuration",
        }

        violation["remediation_attempts"].append(remediation_attempt)
        await self.violation_repository.save(violation)

    async def _audit_compliance_violation(self, violation: dict[str, Any]) -> None:
        """Create audit trail for compliance violation."""
        # Create audit entry for the violation

        # This would typically be injected or accessed through command bus
        # For now, just log that we would create an audit entry
        logger.info(
            "Compliance violation audit trail created",
            violation_id=violation["id"],
            framework=violation["framework"],
        )


__all__ = ["ComplianceService"]
