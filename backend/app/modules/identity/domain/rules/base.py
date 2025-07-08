"""
Base Business Rule

Foundation for all business rules in the identity domain.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class ViolationSeverity(Enum):
    """Severity levels for policy violations."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class RemediationAction:
    """Represents a remediation action for a policy violation."""
    action_type: str
    description: str
    automated: bool = False
    user_action_required: bool = True
    estimated_time_minutes: int | None = None
    help_url: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyViolation:
    """Represents a policy violation with enhanced context and remediation guidance."""
    rule_name: str
    description: str
    severity: str | ViolationSeverity
    current_value: Any
    expected_value: Any
    context: dict[str, Any] = field(default_factory=dict)
    
    # Enhanced fields
    violation_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    remediation_actions: list[RemediationAction] = field(default_factory=list)
    impact_level: str = "medium"  # low, medium, high, critical
    compliance_frameworks: list[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Normalize severity to enum."""
        if isinstance(self.severity, str):
            try:
                self.severity = ViolationSeverity(self.severity)
            except ValueError:
                self.severity = ViolationSeverity.ERROR
    
    def add_remediation_action(self, action: RemediationAction) -> None:
        """Add a remediation action."""
        self.remediation_actions.append(action)
    
    def get_severity_level(self) -> int:
        """Get numeric severity level for sorting."""
        severity_levels = {
            ViolationSeverity.INFO: 1,
            ViolationSeverity.WARNING: 2,
            ViolationSeverity.ERROR: 3,
            ViolationSeverity.CRITICAL: 4
        }
        return severity_levels.get(self.severity, 2)
    
    def is_blocking(self) -> bool:
        """Check if this violation is blocking."""
        return self.severity in [ViolationSeverity.ERROR, ViolationSeverity.CRITICAL]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "violation_id": self.violation_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "impact_level": self.impact_level,
            "compliance_frameworks": self.compliance_frameworks,
            "remediation_actions": [
                {
                    "action_type": action.action_type,
                    "description": action.description,
                    "automated": action.automated,
                    "user_action_required": action.user_action_required,
                    "estimated_time_minutes": action.estimated_time_minutes,
                    "help_url": action.help_url,
                    "parameters": action.parameters
                }
                for action in self.remediation_actions
            ]
        }


@dataclass
class PolicyValidationResult:
    """Result of policy validation with comprehensive information."""
    policy_name: str
    is_compliant: bool
    violations: list[PolicyViolation]
    validation_timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    validation_duration_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def get_violations_by_severity(self, severity: ViolationSeverity) -> list[PolicyViolation]:
        """Get violations by severity level."""
        return [v for v in self.violations if v.severity == severity]
    
    def has_blocking_violations(self) -> bool:
        """Check if there are blocking violations."""
        return any(v.is_blocking() for v in self.violations)
    
    def get_violation_summary(self) -> dict[str, int]:
        """Get summary of violations by severity."""
        summary = {severity.value: 0 for severity in ViolationSeverity}
        for violation in self.violations:
            summary[violation.severity.value] += 1
        return summary


class BusinessRule(ABC):
    """Enhanced base class for business rules with better context and remediation."""
    
    def __init__(self, rule_name: str | None = None):
        self.rule_name = rule_name or self.__class__.__name__
        self.version = "1.0.0"
        self.description = self.__doc__ or "Business rule validation"
    
    @abstractmethod
    def validate(self, *args, **kwargs) -> list[PolicyViolation]:
        """Validate the rule and return any violations."""
    
    def is_compliant(self, *args, **kwargs) -> bool:
        """Check if the rule is compliant."""
        violations = self.validate(*args, **kwargs)
        return not self.has_blocking_violations(violations)
    
    def validate_with_result(self, *args, **kwargs) -> PolicyValidationResult:
        """Validate and return comprehensive result."""
        start_time = datetime.now(UTC)
        violations = self.validate(*args, **kwargs)
        end_time = datetime.now(UTC)
        
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        return PolicyValidationResult(
            policy_name=self.rule_name,
            is_compliant=not self.has_blocking_violations(violations),
            violations=violations,
            validation_duration_ms=duration_ms,
            metadata={
                "rule_version": self.version,
                "rule_description": self.description
            }
        )
    
    def get_violations_by_severity(self, violations: list[PolicyViolation], 
                                 severity: ViolationSeverity) -> list[PolicyViolation]:
        """Get violations by severity level."""
        return [v for v in violations if v.severity == severity]
    
    def get_error_violations(self, violations: list[PolicyViolation]) -> list[PolicyViolation]:
        """Get only error-level violations."""
        return self.get_violations_by_severity(violations, ViolationSeverity.ERROR)
    
    def get_critical_violations(self, violations: list[PolicyViolation]) -> list[PolicyViolation]:
        """Get only critical-level violations."""
        return self.get_violations_by_severity(violations, ViolationSeverity.CRITICAL)
    
    def has_blocking_violations(self, violations: list[PolicyViolation]) -> bool:
        """Check if there are any blocking violations (error or critical)."""
        return any(v.is_blocking() for v in violations)
    
    def create_violation(self, rule_name: str, description: str, 
                        severity: ViolationSeverity, current_value: Any, 
                        expected_value: Any, **kwargs) -> PolicyViolation:
        """Helper method to create a policy violation with consistent formatting."""
        violation = PolicyViolation(
            rule_name=f"{self.rule_name}.{rule_name}",
            description=description,
            severity=severity,
            current_value=current_value,
            expected_value=expected_value,
            context=kwargs.get('context', {}),
            impact_level=kwargs.get('impact_level', 'medium'),
            compliance_frameworks=kwargs.get('compliance_frameworks', [])
        )
        
        # Add default remediation actions if provided
        if 'remediation_actions' in kwargs:
            for action in kwargs['remediation_actions']:
                violation.add_remediation_action(action)
        
        return violation
    
    def get_rule_metadata(self) -> dict[str, Any]:
        """Get metadata about this rule."""
        return {
            "name": self.rule_name,
            "version": self.version,
            "description": self.description,
            "class": self.__class__.__name__
        }
