"""
IP Reputation Value Object

Represents IP address reputation analysis results.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class IpReputation(ValueObject):
    """
    Value object representing IP address reputation analysis.
    
    Encapsulates reputation score, threat categories, and security
    indicators for IP-based security decisions.
    """
    
    reputation_score: float  # 0.0 to 1.0 (0 = malicious, 1 = clean)
    is_blocklisted: bool
    is_allowlisted: bool
    threat_categories: list[str]
    last_seen_malicious: datetime | None = None
    confidence: float = 1.0  # 0.0 to 1.0
    sources: list[str] | None = None
    metadata: dict[str, Any] | None = None
    
    def __post_init__(self) -> None:
        """Validate IP reputation data."""
        if not 0.0 <= self.reputation_score <= 1.0:
            raise ValueError("Reputation score must be between 0.0 and 1.0")
        
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
    
    def is_malicious(self) -> bool:
        """Check if IP is considered malicious."""
        return self.is_blocklisted or self.reputation_score < 0.3
    
    def is_suspicious(self) -> bool:
        """Check if IP is suspicious."""
        return 0.3 <= self.reputation_score < 0.7 or len(self.threat_categories) > 0
    
    def is_clean(self) -> bool:
        """Check if IP is considered clean."""
        return (
            not self.is_blocklisted and 
            self.reputation_score >= 0.7 and 
            len(self.threat_categories) == 0
        )
    
    def should_block(self) -> bool:
        """Check if IP should be blocked."""
        return self.is_blocklisted or self.is_malicious()
    
    def get_risk_level(self) -> str:
        """Get human-readable risk level."""
        if self.is_malicious():
            return "High"
        if self.is_suspicious():
            return "Medium"
        return "Low"
