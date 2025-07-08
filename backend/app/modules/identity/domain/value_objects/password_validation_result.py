"""
Password Validation Result Value Object

Represents the result of password validation operations.
"""

from dataclasses import dataclass

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PasswordValidationResult(ValueObject):
    """
    Value object representing password validation result.
    
    Encapsulates validation status, violations, and suggestions
    for password policy enforcement.
    """
    
    is_valid: bool
    score: float  # 0.0 to 1.0
    violations: list[str]
    suggestions: list[str]
    is_breached: bool = False
    breach_count: int = 0
    
    def __post_init__(self) -> None:
        """Validate password validation result data."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("Password score must be between 0.0 and 1.0")
        
        if self.breach_count < 0:
            raise ValueError("Breach count cannot be negative")
    
    def has_violations(self) -> bool:
        """Check if password has policy violations."""
        return len(self.violations) > 0
    
    def is_strong(self) -> bool:
        """Check if password is considered strong."""
        return self.is_valid and self.score >= 0.8 and not self.is_breached
    
    def requires_improvement(self) -> bool:
        """Check if password requires improvement."""
        return not self.is_valid or self.score < 0.6 or self.is_breached
