"""
Compliance Record Value Object

Represents a compliance record with immutable properties.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from .base import ValueObject
from ..enums import ComplianceStatus


@dataclass(frozen=True)
class ComplianceRecord(ValueObject):
    """
    Immutable compliance record value object.
    
    Represents a compliance record for regulatory tracking
    and audit purposes.
    """
    
    id: str
    framework: str
    requirement_id: str
    user_id: Optional[UUID]
    organization_id: Optional[str]
    status: ComplianceStatus
    assessment_date: datetime
    evidence: List[str]
    gaps: List[str]
    remediation_actions: List[str]
    next_review_date: Optional[datetime]
    assessor_id: Optional[UUID]
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        """Validate compliance record data."""
        if not self.id:
            raise ValueError("Compliance record ID is required")
        
        if not self.framework:
            raise ValueError("Framework is required")
        
        if not self.requirement_id:
            raise ValueError("Requirement ID is required")
        
        if not isinstance(self.evidence, list):
            raise ValueError("Evidence must be a list")
        
        if not isinstance(self.gaps, list):
            raise ValueError("Gaps must be a list")
        
        if not isinstance(self.remediation_actions, list):
            raise ValueError("Remediation actions must be a list")
    
    @property
    def is_compliant(self) -> bool:
        """Check if record represents compliance."""
        return self.status == ComplianceStatus.COMPLIANT
    
    @property
    def is_overdue_for_review(self) -> bool:
        """Check if record is overdue for review."""
        if not self.next_review_date:
            return False
        return datetime.utcnow() > self.next_review_date
    
    @property
    def has_critical_gaps(self) -> bool:
        """Check if record has critical compliance gaps."""
        critical_keywords = ["critical", "mandatory", "required", "violation"]
        return any(
            keyword in gap.lower()
            for gap in self.gaps
            for keyword in critical_keywords
        )
    
    @property
    def risk_score(self) -> float:
        """Calculate risk score based on gaps and status."""
        base_score = 0.0
        
        # Base score from status
        status_scores = {
            ComplianceStatus.COMPLIANT: 0.0,
            ComplianceStatus.PARTIALLY_COMPLIANT: 0.3,
            ComplianceStatus.NON_COMPLIANT: 0.7,
            ComplianceStatus.NOT_ASSESSED: 0.5
        }
        base_score = status_scores.get(self.status, 0.5)
        
        # Add risk for gaps
        gap_score = min(len(self.gaps) * 0.1, 0.3)
        
        # Add risk for critical gaps
        if self.has_critical_gaps:
            gap_score += 0.2
        
        # Add risk for overdue review
        if self.is_overdue_for_review:
            gap_score += 0.1
        
        return min(base_score + gap_score, 1.0)
    
    @property
    def completion_percentage(self) -> float:
        """Calculate completion percentage."""
        if self.status == ComplianceStatus.COMPLIANT:
            return 100.0
        elif self.status == ComplianceStatus.PARTIALLY_COMPLIANT:
            # Estimate based on evidence vs gaps
            total_items = len(self.evidence) + len(self.gaps)
            if total_items == 0:
                return 50.0
            return (len(self.evidence) / total_items) * 100.0
        elif self.status == ComplianceStatus.NON_COMPLIANT:
            return 0.0
        else:  # NOT_ASSESSED
            return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "framework": self.framework,
            "requirement_id": self.requirement_id,
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": self.organization_id,
            "status": self.status.value,
            "assessment_date": self.assessment_date.isoformat(),
            "evidence": self.evidence,
            "gaps": self.gaps,
            "remediation_actions": self.remediation_actions,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "assessor_id": str(self.assessor_id) if self.assessor_id else None,
            "metadata": self.metadata,
            "is_compliant": self.is_compliant,
            "is_overdue_for_review": self.is_overdue_for_review,
            "has_critical_gaps": self.has_critical_gaps,
            "risk_score": self.risk_score,
            "completion_percentage": self.completion_percentage
        }
    
    def with_updated_status(self, new_status: ComplianceStatus) -> "ComplianceRecord":
        """Create new compliance record with updated status."""
        return ComplianceRecord(
            id=self.id,
            framework=self.framework,
            requirement_id=self.requirement_id,
            user_id=self.user_id,
            organization_id=self.organization_id,
            status=new_status,
            assessment_date=datetime.utcnow(),  # Update assessment date
            evidence=self.evidence,
            gaps=self.gaps,
            remediation_actions=self.remediation_actions,
            next_review_date=self.next_review_date,
            assessor_id=self.assessor_id,
            metadata=self.metadata
        )
    
    def with_additional_evidence(self, new_evidence: List[str]) -> "ComplianceRecord":
        """Create new compliance record with additional evidence."""
        updated_evidence = list(self.evidence) + new_evidence
        
        return ComplianceRecord(
            id=self.id,
            framework=self.framework,
            requirement_id=self.requirement_id,
            user_id=self.user_id,
            organization_id=self.organization_id,
            status=self.status,
            assessment_date=self.assessment_date,
            evidence=updated_evidence,
            gaps=self.gaps,
            remediation_actions=self.remediation_actions,
            next_review_date=self.next_review_date,
            assessor_id=self.assessor_id,
            metadata=self.metadata
        )
    
    def with_resolved_gaps(self, resolved_gaps: List[str]) -> "ComplianceRecord":
        """Create new compliance record with resolved gaps."""
        remaining_gaps = [gap for gap in self.gaps if gap not in resolved_gaps]
        
        # Update status if all gaps resolved
        new_status = self.status
        if not remaining_gaps and self.status != ComplianceStatus.COMPLIANT:
            new_status = ComplianceStatus.COMPLIANT
        elif remaining_gaps and len(remaining_gaps) < len(self.gaps):
            new_status = ComplianceStatus.PARTIALLY_COMPLIANT
        
        return ComplianceRecord(
            id=self.id,
            framework=self.framework,
            requirement_id=self.requirement_id,
            user_id=self.user_id,
            organization_id=self.organization_id,
            status=new_status,
            assessment_date=datetime.utcnow(),
            evidence=self.evidence,
            gaps=remaining_gaps,
            remediation_actions=self.remediation_actions,
            next_review_date=self.next_review_date,
            assessor_id=self.assessor_id,
            metadata=self.metadata
        )
    
    def with_remediation_action(self, action: str) -> "ComplianceRecord":
        """Create new compliance record with additional remediation action."""
        updated_actions = list(self.remediation_actions) + [action]
        
        return ComplianceRecord(
            id=self.id,
            framework=self.framework,
            requirement_id=self.requirement_id,
            user_id=self.user_id,
            organization_id=self.organization_id,
            status=self.status,
            assessment_date=self.assessment_date,
            evidence=self.evidence,
            gaps=self.gaps,
            remediation_actions=updated_actions,
            next_review_date=self.next_review_date,
            assessor_id=self.assessor_id,
            metadata=self.metadata
        )
    
    def schedule_next_review(self, review_date: datetime) -> "ComplianceRecord":
        """Create new compliance record with scheduled review date."""
        return ComplianceRecord(
            id=self.id,
            framework=self.framework,
            requirement_id=self.requirement_id,
            user_id=self.user_id,
            organization_id=self.organization_id,
            status=self.status,
            assessment_date=self.assessment_date,
            evidence=self.evidence,
            gaps=self.gaps,
            remediation_actions=self.remediation_actions,
            next_review_date=review_date,
            assessor_id=self.assessor_id,
            metadata=self.metadata
        )
    
    def matches_criteria(self, criteria: Dict[str, Any]) -> bool:
        """Check if compliance record matches given criteria."""
        
        # Check framework filter
        if "framework" in criteria and criteria["framework"]:
            if self.framework != criteria["framework"]:
                return False
        
        # Check status filter
        if "status" in criteria and criteria["status"]:
            if self.status != criteria["status"]:
                return False
        
        # Check risk threshold
        if "min_risk_score" in criteria:
            if self.risk_score < criteria["min_risk_score"]:
                return False
        
        # Check overdue filter
        if "overdue_only" in criteria and criteria["overdue_only"]:
            if not self.is_overdue_for_review:
                return False
        
        # Check critical gaps filter
        if "critical_gaps_only" in criteria and criteria["critical_gaps_only"]:
            if not self.has_critical_gaps:
                return False
        
        return True
    
    def __str__(self) -> str:
        """String representation of compliance record."""
        return f"ComplianceRecord(id={self.id}, framework={self.framework}, status={self.status.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"ComplianceRecord(id='{self.id}', framework='{self.framework}', "
            f"requirement_id='{self.requirement_id}', status={self.status}, "
            f"risk_score={self.risk_score:.2f})"
        )
