"""
Password Service Interface

Port for comprehensive password management operations including validation,
strength analysis, generation, and security checks.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from ...value_objects.password_strength import PasswordStrength
    from ...value_objects.password_validation_result import PasswordValidationResult


class IPasswordService(ABC):
    """Port for password management operations."""
    
    @abstractmethod
    async def validate_password(
        self,
        password: str,
        user_context: dict[str, Any] | None = None,
        check_breach: bool = True
    ) -> "PasswordValidationResult":
        """
        Validate password against all policies.
        
        Args:
            password: Password to validate
            user_context: User context for validation (username, email, etc.)
            check_breach: Whether to check against known breaches
            
        Returns:
            PasswordValidationResult value object containing validation details
        """
    
    @abstractmethod
    async def calculate_strength(self, password: str) -> "PasswordStrength":
        """
        Calculate password strength with detailed breakdown.
        
        Args:
            password: Password to analyze
            
        Returns:
            PasswordStrength value object containing score and analysis
        """
    
    @abstractmethod
    async def generate_secure_password(
        self,
        length: int = 16,
        include_symbols: bool = True,
        exclude_ambiguous: bool = True,
        pronounceable: bool = False
    ) -> str:
        """
        Generate a secure password.
        
        Args:
            length: Password length
            include_symbols: Include special characters
            exclude_ambiguous: Exclude ambiguous characters (0O1lI)
            pronounceable: Generate pronounceable password
            
        Returns:
            Generated secure password
        """
    
    @abstractmethod
    async def check_password_history(
        self,
        user_id: UUID,
        password: str,
        min_distance: int = 3
    ) -> bool:
        """
        Check if password is too similar to previous passwords.
        
        Args:
            user_id: User identifier
            password: New password to check
            min_distance: Minimum edit distance required
            
        Returns:
            True if password is sufficiently different
        """
    
    @abstractmethod
    async def estimate_crack_time(self, password: str) -> dict[str, Any]:
        """
        Estimate time to crack password under various scenarios.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dict with entropy_bits, possible_combinations, crack_times
        """
    
    @abstractmethod
    async def suggest_improvements(self, password: str) -> list[str]:
        """
        Suggest improvements for password.
        
        Args:
            password: Password to analyze
            
        Returns:
            List of improvement suggestions
        """
    
    @abstractmethod
    async def check_breach_status(self, password: str) -> tuple[bool, int]:
        """
        Check if password has been in known data breaches.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_breached, breach_count)
        """
    
    @abstractmethod
    async def validate_password_policy(
        self,
        password: str,
        user_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Validate password against organization policy.
        
        Args:
            password: Password to validate
            user_context: User context for validation
            
        Returns:
            Dict with validation results and policy details
        """
