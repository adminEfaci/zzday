"""
User Domain Service Interface

Port for user domain service operations including risk calculation,
password policy validation, and other cross-cutting user concerns.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User


class IUserDomainService(ABC):
    """Port for user domain service operations."""
    
    @abstractmethod
    def calculate_risk_score(self, user: "User") -> float:
        """
        Calculate user risk score based on domain rules.
        
        Args:
            user: User aggregate to assess
            
        Returns:
            Risk score between 0.0 (low risk) and 1.0 (high risk)
        """
        ...
    
    @abstractmethod
    def validate_password_policy(self, password: str, user: "User") -> list[str]:
        """
        Validate password against domain policy.
        
        Args:
            password: Password to validate
            user: User context for validation
            
        Returns:
            List of validation errors (empty if valid)
        """
        ...
    
    @abstractmethod
    def can_perform_sensitive_action(self, user: "User", action: str) -> bool:
        """
        Check if user can perform a sensitive action based on risk and status.
        
        Args:
            user: User attempting the action
            action: Name of the sensitive action
            
        Returns:
            True if allowed, False otherwise
        """
        ...
    
    @abstractmethod
    def should_require_mfa(self, user: "User", context: dict) -> bool:
        """
        Determine if MFA should be required based on user and context.
        
        Args:
            user: User to check
            context: Request context (IP, device, location, etc.)
            
        Returns:
            True if MFA should be required
        """
        ...