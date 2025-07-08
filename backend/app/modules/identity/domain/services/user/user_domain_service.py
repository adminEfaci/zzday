"""
User Domain Service

Contains domain service logic for user operations.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User


class RiskCalculationPolicy(Protocol):
    """Protocol for risk calculation policies."""
    
    @abstractmethod
    def calculate_risk_score(self, user: User) -> float:
        """Calculate user risk score based on domain rules."""
        ...


class PasswordPolicy(Protocol):
    """Protocol for password policy validation."""
    
    @abstractmethod
    def validate_password(self, password: str, user: User) -> list[str]:
        """Validate password against domain policy."""
        ...


class UserDomainService:
    """Domain service for complex user operations with dependency injection."""
    
    def __init__(
        self,
        risk_policy: RiskCalculationPolicy,
        password_policy: PasswordPolicy,
    ) -> None:
        self._risk_policy = risk_policy
        self._password_policy = password_policy
    
    def calculate_risk_score(self, user: User) -> float:
        """Calculate user risk score based on domain rules."""
        return self._risk_policy.calculate_risk_score(user)
    
    def validate_password_policy(self, password: str, user: User) -> list[str]:
        """Validate password against domain policy."""
        return self._password_policy.validate_password(password, user)