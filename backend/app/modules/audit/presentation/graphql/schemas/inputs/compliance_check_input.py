"""GraphQL input types for compliance checking."""

from datetime import datetime
from typing import Any

import strawberry

from ..enums import ComplianceFrameworkEnum, RiskLevelEnum
from .filter_input import DateRangeInput


@strawberry.input
class ComplianceRuleInput:
    """Input type for compliance rule definition."""

    rule_id: str
    rule_name: str
    description: str
    framework: ComplianceFrameworkEnum
    severity: str = "medium"

    # Rule conditions
    conditions: str  # JSON string defining rule conditions

    # Remediation
    remediation_guidance: str | None = None
    remediation_url: str | None = None

    def validate(self) -> list[str]:
        """Validate compliance rule input."""
        errors = []

        if not self.rule_id or len(self.rule_id.strip()) == 0:
            errors.append("Rule ID is required")

        if len(self.rule_id) > 100:
            errors.append("Rule ID too long (max 100 characters)")

        if not self.rule_name or len(self.rule_name.strip()) == 0:
            errors.append("Rule name is required")

        if len(self.rule_name) > 255:
            errors.append("Rule name too long (max 255 characters)")

        if len(self.description) > 2000:
            errors.append("Description too long (max 2000 characters)")

        # Validate severity
        valid_severities = ["low", "medium", "high", "critical"]
        if self.severity not in valid_severities:
            errors.append(f"Invalid severity: {self.severity}")

        # Validate JSON conditions
        if self.conditions:
            try:
                import json

                json.loads(self.conditions)
            except json.JSONDecodeError:
                errors.append("Conditions must be valid JSON")

        # Validate URLs
        if self.remediation_url:
            if not self.remediation_url.startswith(("http://", "https://")):
                errors.append("Remediation URL must use HTTP or HTTPS")

        return errors


@strawberry.input
class ComplianceControlInput:
    """Input type for compliance control assessment."""

    control_id: str
    control_name: str
    framework: ComplianceFrameworkEnum
    description: str

    # Assessment criteria
    assessment_criteria: str  # JSON string
    evidence_requirements: list[str] = strawberry.field(default_factory=list)

    # Frequency
    assessment_frequency_days: int = 90

    def validate(self) -> list[str]:
        """Validate compliance control input."""
        errors = []

        if not self.control_id or len(self.control_id.strip()) == 0:
            errors.append("Control ID is required")

        if not self.control_name or len(self.control_name.strip()) == 0:
            errors.append("Control name is required")

        if len(self.description) > 2000:
            errors.append("Description too long (max 2000 characters)")

        # Validate assessment frequency
        if self.assessment_frequency_days < 1:
            errors.append("Assessment frequency must be positive")

        if self.assessment_frequency_days > 365:
            errors.append("Assessment frequency too long (max 365 days)")

        # Validate JSON
        if self.assessment_criteria:
            try:
                import json

                json.loads(self.assessment_criteria)
            except json.JSONDecodeError:
                errors.append("Assessment criteria must be valid JSON")

        return errors


@strawberry.input
class ComplianceCheckParametersInput:
    """Input type for compliance check parameters."""

    # Scope
    frameworks: list[ComplianceFrameworkEnum] = strawberry.field(default_factory=list)
    specific_controls: list[str] = strawberry.field(default_factory=list)
    specific_rules: list[str] = strawberry.field(default_factory=list)

    # Time range for data analysis
    time_range: DateRangeInput

    # Filtering
    resource_types: list[str] = strawberry.field(default_factory=list)
    user_ids: list[strawberry.ID] = strawberry.field(default_factory=list)
    severity_threshold: str | None = None

    # Analysis options
    include_historical_violations: bool = True
    include_remediated_violations: bool = False
    include_evidence_collection: bool = True
    include_gap_analysis: bool = True

    # Reporting options
    generate_recommendations: bool = True
    include_remediation_timeline: bool = True
    include_cost_estimates: bool = False

    def validate(self) -> list[str]:
        """Validate compliance check parameters."""
        errors = []

        # Validate time range
        errors.extend(self.time_range.validate())

        # Ensure at least some scope is defined
        if not any([self.frameworks, self.specific_controls, self.specific_rules]):
            errors.append("At least one framework, control, or rule must be specified")

        # Validate severity threshold
        if self.severity_threshold:
            valid_severities = ["low", "medium", "high", "critical"]
            if self.severity_threshold not in valid_severities:
                errors.append(f"Invalid severity threshold: {self.severity_threshold}")

        # Validate list sizes
        if len(self.specific_controls) > 100:
            errors.append("Too many specific controls (max 100)")

        if len(self.specific_rules) > 100:
            errors.append("Too many specific rules (max 100)")

        if len(self.user_ids) > 1000:
            errors.append("Too many user IDs (max 1000)")

        return errors


@strawberry.input
class ComplianceAssessmentInput:
    """Input type for manual compliance assessment."""

    control_id: str
    assessor_id: strawberry.ID
    assessment_date: datetime

    # Assessment results
    status: str  # "compliant", "non_compliant", "partial", "not_applicable"
    findings: list[str] = strawberry.field(default_factory=list)
    evidence_items: list[str] = strawberry.field(default_factory=list)

    # Risk assessment
    risk_level: RiskLevelEnum = RiskLevelEnum.LOW
    risk_description: str | None = None

    # Recommendations
    recommendations: list[str] = strawberry.field(default_factory=list)
    next_assessment_due: datetime | None = None

    def validate(self) -> list[str]:
        """Validate compliance assessment input."""
        errors = []

        if not self.control_id or len(self.control_id.strip()) == 0:
            errors.append("Control ID is required")

        # Validate status
        valid_statuses = ["compliant", "non_compliant", "partial", "not_applicable"]
        if self.status not in valid_statuses:
            errors.append(f"Invalid status: {self.status}")

        # Validate assessment date
        if self.assessment_date > datetime.utcnow():
            errors.append("Assessment date cannot be in the future")

        # Validate next assessment date
        if (
            self.next_assessment_due
            and self.next_assessment_due <= self.assessment_date
        ):
            errors.append("Next assessment date must be after current assessment")

        # Validate text lengths
        if self.risk_description and len(self.risk_description) > 2000:
            errors.append("Risk description too long (max 2000 characters)")

        # Validate findings
        for finding in self.findings:
            if len(finding) > 1000:
                errors.append("Finding too long (max 1000 characters)")

        if len(self.findings) > 50:
            errors.append("Too many findings (max 50)")

        return errors


@strawberry.input
class ComplianceCheckInput:
    """Input type for comprehensive compliance checking."""

    # Check identity
    check_name: str
    description: str | None = None

    # Parameters
    parameters: ComplianceCheckParametersInput

    # Custom rules and controls
    custom_rules: list[ComplianceRuleInput] = strawberry.field(default_factory=list)
    custom_controls: list[ComplianceControlInput] = strawberry.field(
        default_factory=list
    )

    # Processing options
    priority: str = "normal"  # "low", "normal", "high", "urgent"
    background_processing: bool = True
    notify_on_completion: bool = True

    # Output options
    generate_report: bool = True
    export_format: str = "pdf"
    include_raw_data: bool = False

    def validate(self) -> list[str]:
        """Validate compliance check input."""
        errors = []

        # Validate basic fields
        if not self.check_name or len(self.check_name.strip()) == 0:
            errors.append("Check name is required")

        if len(self.check_name) > 255:
            errors.append("Check name too long (max 255 characters)")

        if self.description and len(self.description) > 2000:
            errors.append("Description too long (max 2000 characters)")

        # Validate parameters
        errors.extend(self.parameters.validate())

        # Validate custom rules and controls
        for rule in self.custom_rules:
            errors.extend(rule.validate())

        for control in self.custom_controls:
            errors.extend(control.validate())

        # Validate priority
        valid_priorities = ["low", "normal", "high", "urgent"]
        if self.priority not in valid_priorities:
            errors.append(f"Invalid priority: {self.priority}")

        # Validate export format
        valid_formats = ["json", "pdf", "xlsx", "csv"]
        if self.export_format not in valid_formats:
            errors.append(f"Invalid export format: {self.export_format}")

        return errors

    def to_command_dict(self) -> dict[str, Any]:
        """Convert to command dictionary for application layer."""
        return {
            "check_name": self.check_name,
            "description": self.description,
            "frameworks": [f.value for f in self.parameters.frameworks],
            "specific_controls": self.parameters.specific_controls,
            "specific_rules": self.parameters.specific_rules,
            "time_range_start": self.parameters.time_range.start_date,
            "time_range_end": self.parameters.time_range.end_date,
            "resource_types": self.parameters.resource_types,
            "user_ids": [str(uid) for uid in self.parameters.user_ids],
            "severity_threshold": self.parameters.severity_threshold,
            "include_historical_violations": self.parameters.include_historical_violations,
            "include_remediated_violations": self.parameters.include_remediated_violations,
            "include_evidence_collection": self.parameters.include_evidence_collection,
            "include_gap_analysis": self.parameters.include_gap_analysis,
            "generate_recommendations": self.parameters.generate_recommendations,
            "include_remediation_timeline": self.parameters.include_remediation_timeline,
            "custom_rules": [
                {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "description": rule.description,
                    "framework": rule.framework.value,
                    "severity": rule.severity,
                    "conditions": rule.conditions,
                }
                for rule in self.custom_rules
            ],
            "custom_controls": [
                {
                    "control_id": control.control_id,
                    "control_name": control.control_name,
                    "framework": control.framework.value,
                    "description": control.description,
                    "assessment_criteria": control.assessment_criteria,
                }
                for control in self.custom_controls
            ],
            "priority": self.priority,
            "background_processing": self.background_processing,
            "generate_report": self.generate_report,
            "export_format": self.export_format,
        }


@strawberry.input
class ViolationRemediationInput:
    """Input type for violation remediation."""

    violation_id: strawberry.ID
    remediation_action: str
    remediation_notes: str | None = None
    estimated_completion: datetime | None = None
    assigned_to: strawberry.ID | None = None

    def validate(self) -> list[str]:
        """Validate remediation input."""
        errors = []

        if not self.remediation_action or len(self.remediation_action.strip()) == 0:
            errors.append("Remediation action is required")

        if len(self.remediation_action) > 1000:
            errors.append("Remediation action too long (max 1000 characters)")

        if self.remediation_notes and len(self.remediation_notes) > 2000:
            errors.append("Remediation notes too long (max 2000 characters)")

        if self.estimated_completion and self.estimated_completion <= datetime.utcnow():
            errors.append("Estimated completion must be in the future")

        return errors
