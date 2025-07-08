"""
Risk Assessment Value Object

Represents the result of a risk assessment operation.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject

from ..enums import RiskLevel


@dataclass(frozen=True)
class RiskAssessment(ValueObject):
    """
    Value object representing a risk assessment result.
    
    Encapsulates risk level, score, and contributing factors
    for security decision making.
    """
    
    level: RiskLevel
    score: float  # 0.0 to 1.0
    factors: dict[str, Any]
    confidence: float = 1.0  # 0.0 to 1.0
    
    def __post_init__(self) -> None:
        """Validate risk assessment data."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
        
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
    
    def is_high_risk(self) -> bool:
        """Check if this represents a high risk scenario."""
        return self.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    
    def requires_additional_verification(self) -> bool:
        """Check if additional verification is recommended."""
        return self.score >= 0.7 or self.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
