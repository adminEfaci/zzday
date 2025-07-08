"""
Location Risk Assessment Value Object

Represents location-based risk assessment results.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject

from ..enums import RiskLevel


@dataclass(frozen=True)
class LocationRiskAssessment(ValueObject):
    """
    Value object representing location-based risk assessment.
    
    Encapsulates location risk analysis, suspicious indicators,
    and risk factors for security decision making.
    """
    
    is_suspicious: bool
    risk_level: RiskLevel
    risk_score: float  # 0.0 to 1.0
    distance_from_usual: float | None = None  # kilometers
    is_new_location: bool = False
    is_high_risk_country: bool = False
    vpn_detected: bool = False
    tor_detected: bool = False
    factors: dict[str, Any] | None = None
    
    def __post_init__(self) -> None:
        """Validate location risk assessment data."""
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
        
        if self.distance_from_usual is not None and self.distance_from_usual < 0:
            raise ValueError("Distance cannot be negative")
    
    def is_high_risk(self) -> bool:
        """Check if location represents high risk."""
        return self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    
    def requires_verification(self) -> bool:
        """Check if location requires additional verification."""
        return (
            self.is_suspicious or 
            self.is_high_risk() or 
            self.risk_score >= 0.7
        )
    
    def get_risk_factors(self) -> list[str]:
        """Get list of risk factors."""
        factors = []
        if self.is_new_location:
            factors.append("New location")
        if self.is_high_risk_country:
            factors.append("High-risk country")
        if self.vpn_detected:
            factors.append("VPN detected")
        if self.tor_detected:
            factors.append("Tor detected")
        if self.distance_from_usual and self.distance_from_usual > 1000:
            factors.append("Unusual distance")
        return factors
