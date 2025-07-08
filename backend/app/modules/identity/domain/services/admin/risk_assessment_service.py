"""
Risk Assessment Domain Service

Pure domain service for comprehensive risk assessment using policy objects.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ...aggregates.user import User
from ...enums import RiskLevel
from ...errors import ValidationError
from ...interfaces.repositories.user.user_repository import IUserRepository
from ...interfaces.services.security.risk_assessment_service import (
    IRiskAssessmentService,
)
from ...rules.risk_policy import RiskAssessmentPolicy
from ...value_objects.ip_address import IpAddress


@dataclass(frozen=True)
class RiskProfile:
    """Domain value object for user risk profile."""
    user_id: UUID
    risk_level: RiskLevel
    risk_score: float
    risk_factors: dict[str, Any]
    assessed_at: datetime
    
    def is_high_risk(self) -> bool:
        """Check if user is high risk."""
        return self.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    def requires_additional_verification(self) -> bool:
        """Check if additional verification is required."""
        return self.risk_score > 0.6


class RiskAssessmentService(IRiskAssessmentService):
    """Pure domain service for risk assessment business logic.
    
    Coordinates risk policies with user aggregates.
    No infrastructure concerns - only business rules.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        risk_policy: RiskAssessmentPolicy
    ) -> None:
        self._user_repository = user_repository
        self._risk_policy = risk_policy
    
    async def assess_login_risk(
        self, 
        user_id: UUID,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None = None
    ) -> tuple[RiskLevel, float, dict[str, Any]]:
        """Assess login risk using domain policies."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Use risk policy to assess login
        risk_assessment = self._risk_policy.assess_login_risk(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint
        )
        
        # Calculate domain risk factors
        risk_factors = self._calculate_login_risk_factors(
            user, ip_address, user_agent, device_fingerprint
        )
        
        return risk_assessment.level, risk_assessment.score, risk_factors
    
    async def assess_transaction_risk(
        self,
        user_id: UUID,
        transaction_type: str,
        transaction_data: dict[str, Any]
    ) -> tuple[RiskLevel, float, dict[str, Any]]:
        """Assess transaction risk using domain rules."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Use risk policy to assess transaction
        risk_assessment = self._risk_policy.assess_transaction_risk(
            user=user,
            transaction_type=transaction_type,
            transaction_data=transaction_data
        )
        
        # Calculate domain risk factors
        risk_factors = self._calculate_transaction_risk_factors(
            user, transaction_type, transaction_data
        )
        
        return risk_assessment.level, risk_assessment.score, risk_factors
    
    async def update_risk_profile(
        self,
        user_id: UUID,
        factors: dict[str, Any],
        event_type: str
    ) -> None:
        """Update user risk profile using domain logic."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Update risk profile through aggregate
        user.update_risk_profile(factors, event_type)
        
        # Save updated aggregate
        await self._user_repository.save(user)
    
    async def get_risk_recommendations(
        self,
        user_id: UUID,
        risk_score: float
    ) -> list[dict[str, Any]]:
        """Get risk mitigation recommendations using domain rules."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return []
        
        # Use risk policy to generate recommendations
        recommendations = self._risk_policy.generate_recommendations(user, risk_score)
        
        return [
            {
                "type": rec.type,
                "priority": rec.priority,
                "action": rec.action,
                "description": rec.description
            }
            for rec in recommendations
        ]
    
    async def calculate_adaptive_thresholds(
        self,
        user_id: UUID
    ) -> dict[str, float]:
        """Calculate adaptive risk thresholds using domain logic."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return {}
        
        # Use risk policy to calculate thresholds
        thresholds = self._risk_policy.calculate_adaptive_thresholds(user)
        
        return {
            "login": thresholds.login_threshold,
            "transaction": thresholds.transaction_threshold,
            "admin_action": thresholds.admin_threshold,
            "data_export": thresholds.export_threshold
        }
    
    # Pure domain helper methods
    
    def _calculate_login_risk_factors(
        self,
        user: User,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None
    ) -> dict[str, Any]:
        """Calculate login-specific risk factors."""
        
        risk_factors = {}
        
        # Account-based factors
        if not user.is_email_verified():
            risk_factors["unverified_email"] = True
        
        if not user.is_mfa_enabled():
            risk_factors["no_mfa"] = True
        
        # IP-based factors
        if ip_address.is_suspicious():
            risk_factors["suspicious_ip"] = True
        
        # Device factors
        if device_fingerprint and not user.is_device_trusted(device_fingerprint):
            risk_factors["unknown_device"] = True
        
        # Time-based factors
        if self._is_off_hours():
            risk_factors["off_hours"] = True
        
        return risk_factors
    
    def _calculate_transaction_risk_factors(
        self,
        user: User,
        transaction_type: str,
        transaction_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate transaction-specific risk factors."""
        
        risk_factors = {}
        
        # Transaction type risk
        if transaction_type in ["delete_user", "grant_admin", "export_data"]:
            risk_factors["high_privilege_operation"] = True
        
        # Amount-based risk
        amount = transaction_data.get("amount", 0)
        if amount > 10000:
            risk_factors["high_value_transaction"] = True
        
        # Frequency risk
        recent_count = transaction_data.get("recent_similar_count", 0)
        if recent_count > 5:
            risk_factors["unusual_frequency"] = True
        
        # Time-based risk
        if self._is_off_hours():
            risk_factors["off_hours_transaction"] = True
        
        return risk_factors
    
    def _is_off_hours(self) -> bool:
        """Check if current time is off-hours."""
        current_hour = datetime.now(UTC).hour
        return current_hour < 6 or current_hour > 22