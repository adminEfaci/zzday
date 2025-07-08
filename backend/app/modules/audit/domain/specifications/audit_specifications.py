"""
Audit Domain Specifications

Specification pattern implementations for audit domain queries
and business rule validation.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.enums.audit_enums import AuditSeverity


class Specification(ABC):
    """Base specification interface."""

    @abstractmethod
    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        """Check if the candidate satisfies this specification."""

    def and_(self, other: "Specification") -> "AndSpecification":
        """Combine with another specification using AND logic."""
        return AndSpecification(self, other)

    def or_(self, other: "Specification") -> "OrSpecification":
        """Combine with another specification using OR logic."""
        return OrSpecification(self, other)

    def not_(self) -> "NotSpecification":
        """Negate this specification."""
        return NotSpecification(self)


class AndSpecification(Specification):
    """Specification that combines two specifications with AND logic."""

    def __init__(self, left: Specification, right: Specification):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return self.left.is_satisfied_by(candidate) and self.right.is_satisfied_by(candidate)


class OrSpecification(Specification):
    """Specification that combines two specifications with OR logic."""

    def __init__(self, left: Specification, right: Specification):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return self.left.is_satisfied_by(candidate) or self.right.is_satisfied_by(candidate)


class NotSpecification(Specification):
    """Specification that negates another specification."""

    def __init__(self, spec: Specification):
        self.spec = spec

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return not self.spec.is_satisfied_by(candidate)


class AuditEntryByUserSpec(Specification):
    """Specification for filtering audit entries by user."""

    def __init__(self, user_id: UUID):
        self.user_id = user_id

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return candidate.user_id == self.user_id


class AuditEntryByDateRangeSpec(Specification):
    """Specification for filtering audit entries by date range."""

    def __init__(self, start_date: datetime, end_date: datetime):
        self.start_date = start_date
        self.end_date = end_date

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return self.start_date <= candidate.created_at <= self.end_date


class AuditEntryBySeveritySpec(Specification):
    """Specification for filtering audit entries by severity."""

    def __init__(self, severity: AuditSeverity):
        self.severity = severity

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return candidate.severity == self.severity


class HighRiskAuditSpec(Specification):
    """Specification for identifying high-risk audit entries."""

    def __init__(self, risk_threshold: int = 70):
        self.risk_threshold = risk_threshold

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return candidate.risk_score >= self.risk_threshold


class SecurityRelatedAuditSpec(Specification):
    """Specification for identifying security-related audit entries."""

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return candidate.category.is_security_related()


class FailedAuditSpec(Specification):
    """Specification for identifying failed audit entries."""

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        return candidate.is_failed()


class RecentAuditSpec(Specification):
    """Specification for identifying recent audit entries."""

    def __init__(self, hours: int = 24):
        self.hours = hours

    def is_satisfied_by(self, candidate: AuditEntry) -> bool:
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=self.hours)
        return candidate.created_at >= cutoff
