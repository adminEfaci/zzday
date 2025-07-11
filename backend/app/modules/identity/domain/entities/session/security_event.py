"""
Security Event Entity

Represents security-related events for monitoring and analysis.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity

from ...enums import RiskLevel, SecurityEventType
from ...enums_security import SecurityEventStatus
from ...value_objects import Geolocation, IpAddress


@dataclass
class SecurityEvent(Entity):
    """Security event entity for tracking and analyzing security incidents."""
    
    id: UUID
    event_type: SecurityEventType
    risk_level: RiskLevel
    status: SecurityEventStatus
    timestamp: datetime
    user_id: UUID | None = None
    ip_address: IpAddress | None = None
    user_agent: str | None = None
    device_id: UUID | None = None
    session_id: UUID | None = None
    
    # Event details
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    affected_resources: list[str] = field(default_factory=list)
    
    # Location information
    country: str | None = None
    city: str | None = None
    geolocation: Geolocation | None = None
    
    # Investigation and response
    investigated_by: UUID | None = None
    investigation_notes: list[dict[str, Any]] = field(default_factory=list)
    resolved_at: datetime | None = None
    resolved_by: UUID | None = None
    resolution: str | None = None
    false_positive_reason: str | None = None
    
    # Correlation
    correlation_id: str | None = None
    related_event_ids: list[UUID] = field(default_factory=list)
    attack_pattern: str | None = None
    
    # Metadata
    source_system: str = "identity"
    alert_sent: bool = False
    auto_mitigated: bool = False
    requires_review: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize security event entity."""
        super().__post_init__()
        
        # Set geolocation from IP if available
        if self.ip_address and not self.country:
            self.country = self.ip_address.country
            self.city = self.ip_address.city
    
    @classmethod
    def create(
        cls,
        event_type: SecurityEventType,
        risk_level: RiskLevel,
        user_id: UUID | None = None,
        ip_address: IpAddress | None = None,
        description: str = "",
        details: dict[str, Any] | None = None
    ) -> 'SecurityEvent':
        """Create a new security event."""
        return cls(
            id=uuid4(),
            event_type=event_type,
            risk_level=risk_level,
            status=SecurityEventStatus.PENDING,
            timestamp=datetime.now(UTC),
            user_id=user_id,
            ip_address=ip_address,
            description=description,
            details=details or {},
            requires_review=risk_level >= RiskLevel.HIGH
        )
    
    def mark_investigating(self, investigator_id: UUID) -> None:
        """Mark event as under investigation."""
        self.status = SecurityEventStatus.INVESTIGATING
        self.investigated_by = investigator_id
        self.add_investigation_note(investigator_id, "Investigation started")
    
    def mark_resolved(self, resolved_by: UUID, resolution: str) -> None:
        """Mark event as resolved."""
        self.status = SecurityEventStatus.RESOLVED
        self.resolved_at = datetime.now(UTC)
        self.resolved_by = resolved_by
        self.resolution = resolution
        self.requires_review = False
    
    def mark_false_positive(self, marked_by: UUID, reason: str) -> None:
        """Mark event as false positive."""
        self.status = SecurityEventStatus.FALSE_POSITIVE
        self.resolved_at = datetime.now(UTC)
        self.resolved_by = marked_by
        self.false_positive_reason = reason
        self.requires_review = False
    
    def escalate(self, escalated_by: UUID, reason: str) -> None:
        """Escalate the security event."""
        self.status = SecurityEventStatus.ESCALATED
        self.risk_level = RiskLevel.CRITICAL
        self.add_investigation_note(escalated_by, f"Escalated: {reason}")
    
    def add_investigation_note(self, investigator_id: UUID, note: str) -> None:
        """Add an investigation note."""
        self.investigation_notes.append({
            "investigator_id": str(investigator_id),
            "timestamp": datetime.now(UTC).isoformat(),
            "note": note
        })
    
    def correlate_with(self, event_id: UUID) -> None:
        """Correlate with another security event."""
        if event_id not in self.related_event_ids:
            self.related_event_ids.append(event_id)
    
    def is_high_risk(self) -> bool:
        """Check if event is high risk."""
        return self.risk_level >= RiskLevel.HIGH
    
    def is_critical(self) -> bool:
        """Check if event is critical."""
        return self.risk_level == RiskLevel.CRITICAL
    
    def is_resolved(self) -> bool:
        """Check if event is resolved."""
        return self.status in [
            SecurityEventStatus.RESOLVED,
            SecurityEventStatus.FALSE_POSITIVE,
            SecurityEventStatus.MITIGATED
        ]
    
    def needs_immediate_attention(self) -> bool:
        """Check if event needs immediate attention."""
        if self.is_resolved():
            return False
        
        # Critical events always need attention
        if self.is_critical():
            return True
        
        # High risk unresolved events
        if self.is_high_risk() and self.status == SecurityEventStatus.PENDING:
            return True
        
        # Specific event types that need immediate attention
        immediate_types = {
            SecurityEventType.BRUTE_FORCE_ATTACK,
            SecurityEventType.CREDENTIAL_STUFFING,
            SecurityEventType.PRIVILEGE_ESCALATION,
            SecurityEventType.DATA_EXFILTRATION,
            SecurityEventType.UNAUTHORIZED_ACCESS
        }
        
        return self.event_type in immediate_types
    
    def get_severity_score(self) -> float:
        """Calculate severity score (0.0 to 1.0)."""
        base_score = self.risk_level.value / 4  # 0.25 to 1.0
        
        # Adjust based on event type
        type_multipliers = {
            SecurityEventType.DATA_EXFILTRATION: 1.5,
            SecurityEventType.PRIVILEGE_ESCALATION: 1.4,
            SecurityEventType.UNAUTHORIZED_ACCESS: 1.3,
            SecurityEventType.BRUTE_FORCE_ATTACK: 1.2,
            SecurityEventType.CREDENTIAL_STUFFING: 1.2,
            SecurityEventType.MALWARE_DETECTION: 1.3,
            SecurityEventType.ANOMALOUS_BEHAVIOR: 1.1,
            SecurityEventType.SUSPICIOUS_LOGIN: 1.0,
            SecurityEventType.MULTIPLE_FAILED_ATTEMPTS: 0.9,
            SecurityEventType.UNUSUAL_LOCATION: 0.8,
            SecurityEventType.IMPOSSIBLE_TRAVEL: 1.1,
            SecurityEventType.NEW_DEVICE: 0.7
        }
        
        multiplier = type_multipliers.get(self.event_type, 1.0)
        
        # Adjust based on auto-mitigation
        if self.auto_mitigated:
            multiplier *= 0.8
        
        return min(base_score * multiplier, 1.0)
    
    def get_response_priority(self) -> int:
        """Get response priority (1-5, 1 being highest)."""
        severity = self.get_severity_score()
        
        if severity >= 0.9:
            return 1
        if severity >= 0.7:
            return 2
        if severity >= 0.5:
            return 3
        if severity >= 0.3:
            return 4
        return 5
    
    def to_alert_format(self) -> dict[str, Any]:
        """Convert to alert notification format."""
        return {
            "event_id": str(self.id),
            "event_type": self.event_type.get_display_name(),
            "risk_level": self.risk_level.get_display_name(),
            "severity_score": round(self.get_severity_score(), 2),
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "user_id": str(self.user_id) if self.user_id else None,
            "ip_address": self.ip_address.value if self.ip_address else None,
            "location": {
                "country": self.country,
                "city": self.city
            } if self.country else None,
            "requires_immediate_attention": self.needs_immediate_attention(),
            "response_priority": self.get_response_priority()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "event_type": self.event_type.value,
            "risk_level": self.risk_level.value,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": str(self.user_id) if self.user_id else None,
            "ip_address": self.ip_address.to_dict() if self.ip_address else None,
            "user_agent": self.user_agent,
            "device_id": str(self.device_id) if self.device_id else None,
            "session_id": str(self.session_id) if self.session_id else None,
            "description": self.description,
            "details": self.details,
            "affected_resources": self.affected_resources,
            "country": self.country,
            "city": self.city,
            "geolocation": self.geolocation.to_dict() if self.geolocation else None,
            "investigated_by": str(self.investigated_by) if self.investigated_by else None,
            "investigation_notes": self.investigation_notes,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": str(self.resolved_by) if self.resolved_by else None,
            "resolution": self.resolution,
            "false_positive_reason": self.false_positive_reason,
            "correlation_id": self.correlation_id,
            "related_event_ids": [str(eid) for eid in self.related_event_ids],
            "attack_pattern": self.attack_pattern,
            "source_system": self.source_system,
            "alert_sent": self.alert_sent,
            "auto_mitigated": self.auto_mitigated,
            "requires_review": self.requires_review,
            "metadata": self.metadata,
            "severity_score": self.get_severity_score(),
            "response_priority": self.get_response_priority()
        }