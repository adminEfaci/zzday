"""
Audit Entry Value Object

Represents an audit log entry with immutable properties.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from .base import ValueObject
from ..enums import RiskLevel


@dataclass(frozen=True)
class AuditEntry(ValueObject):
    """
    Immutable audit entry value object.
    
    Represents a single audit log entry with all necessary
    information for compliance and security monitoring.
    """
    
    id: str
    event_type: str
    user_id: Optional[UUID]
    resource_type: Optional[str]
    resource_id: Optional[str]
    action: str
    details: Dict[str, Any]
    context: Dict[str, Any]
    severity: str
    timestamp: datetime
    risk_level: Optional[RiskLevel]
    compliance_relevant: bool
    retention_period: int  # days
    
    def __post_init__(self):
        """Validate audit entry data."""
        if not self.id:
            raise ValueError("Audit entry ID is required")
        
        if not self.event_type:
            raise ValueError("Event type is required")
        
        if not self.action:
            raise ValueError("Action is required")
        
        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError("Invalid severity level")
        
        if self.retention_period <= 0:
            raise ValueError("Retention period must be positive")
    
    @property
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk audit entry."""
        return (
            self.risk_level == RiskLevel.HIGH or
            self.severity in ["high", "critical"]
        )
    
    @property
    def is_security_related(self) -> bool:
        """Check if this audit entry is security-related."""
        security_events = [
            "login_failed", "permission_denied", "security_violation",
            "suspicious_activity", "account_locked", "password_breach"
        ]
        return any(event in self.event_type.lower() for event in security_events)
    
    @property
    def requires_investigation(self) -> bool:
        """Check if this audit entry requires investigation."""
        return (
            self.is_high_risk or
            self.severity == "critical" or
            "violation" in self.event_type.lower()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "user_id": str(self.user_id) if self.user_id else None,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "details": self.details,
            "context": self.context,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "risk_level": self.risk_level.value if self.risk_level else None,
            "compliance_relevant": self.compliance_relevant,
            "retention_period": self.retention_period,
            "is_high_risk": self.is_high_risk,
            "is_security_related": self.is_security_related,
            "requires_investigation": self.requires_investigation
        }
    
    def with_updated_risk(self, new_risk_level: RiskLevel) -> "AuditEntry":
        """Create new audit entry with updated risk level."""
        return AuditEntry(
            id=self.id,
            event_type=self.event_type,
            user_id=self.user_id,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            action=self.action,
            details=self.details,
            context=self.context,
            severity=self.severity,
            timestamp=self.timestamp,
            risk_level=new_risk_level,
            compliance_relevant=self.compliance_relevant,
            retention_period=self.retention_period
        )
    
    def with_additional_context(self, additional_context: Dict[str, Any]) -> "AuditEntry":
        """Create new audit entry with additional context."""
        updated_context = {**self.context, **additional_context}
        
        return AuditEntry(
            id=self.id,
            event_type=self.event_type,
            user_id=self.user_id,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            action=self.action,
            details=self.details,
            context=updated_context,
            severity=self.severity,
            timestamp=self.timestamp,
            risk_level=self.risk_level,
            compliance_relevant=self.compliance_relevant,
            retention_period=self.retention_period
        )
    
    def matches_filter(self, filters: Dict[str, Any]) -> bool:
        """Check if audit entry matches given filters."""
        
        # Check user ID filter
        if "user_id" in filters and filters["user_id"]:
            if self.user_id != filters["user_id"]:
                return False
        
        # Check event type filter
        if "event_types" in filters and filters["event_types"]:
            if self.event_type not in filters["event_types"]:
                return False
        
        # Check severity filter
        if "severity" in filters and filters["severity"]:
            if self.severity != filters["severity"]:
                return False
        
        # Check risk level filter
        if "risk_level" in filters and filters["risk_level"]:
            if not self.risk_level or self.risk_level.value != filters["risk_level"]:
                return False
        
        # Check compliance relevance filter
        if "compliance_relevant" in filters:
            if self.compliance_relevant != filters["compliance_relevant"]:
                return False
        
        return True
    
    def __str__(self) -> str:
        """String representation of audit entry."""
        return f"AuditEntry(id={self.id}, event={self.event_type}, severity={self.severity})"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"AuditEntry(id='{self.id}', event_type='{self.event_type}', "
            f"user_id={self.user_id}, action='{self.action}', "
            f"severity='{self.severity}', timestamp={self.timestamp})"
        )
