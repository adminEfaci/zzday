"""
Risk Assessment Service Interface

Protocol for risk assessment and fraud detection operations.
"""

from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from ....value_objects.ip_address import IpAddress

if TYPE_CHECKING:
    from ....value_objects.risk_assessment import RiskAssessment


class IRiskAssessmentService(Protocol):
    """Protocol for risk assessment operations."""
    
    async def assess_login_risk(
        self, 
        user_id: UUID,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None = None
    ) -> "RiskAssessment":
        """
        Assess risk for login attempt.
        
        Args:
            user_id: User identifier
            ip_address: Client IP address
            user_agent: Client user agent string
            device_fingerprint: Optional device fingerprint
            
        Returns:
            RiskAssessment value object containing level, score, and factors
        """
        ...
    
    async def assess_transaction_risk(
        self,
        user_id: UUID,
        transaction_type: str,
        transaction_data: dict[str, Any]
    ) -> "RiskAssessment":
        """
        Assess risk for transaction.
        
        Args:
            user_id: User identifier
            transaction_type: Type of transaction
            transaction_data: Transaction details
            
        Returns:
            RiskAssessment value object containing level, score, and factors
        """
        ...
    
    async def update_risk_profile(
        self,
        user_id: UUID,
        factors: dict[str, Any],
        event_type: str
    ) -> None:
        """
        Update user risk profile.
        
        Args:
            user_id: User identifier
            factors: Risk factors to update
            event_type: Type of event triggering update
        """
        ...
    
    async def get_risk_recommendations(
        self,
        user_id: UUID,
        risk_score: float
    ) -> list[dict[str, Any]]:
        """
        Get risk mitigation recommendations.
        
        Args:
            user_id: User identifier
            risk_score: Current risk score
            
        Returns:
            List of recommendations with priorities
        """
        ...
    
    async def calculate_adaptive_thresholds(
        self,
        user_id: UUID
    ) -> dict[str, float]:
        """
        Calculate adaptive risk thresholds.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict of threshold values by risk type
        """
        ...
