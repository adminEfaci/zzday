"""
Password Strength Value Object

Represents password strength analysis results.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PasswordStrength(ValueObject):
    """
    Value object representing password strength analysis.
    
    Encapsulates strength metrics, entropy, and detailed analysis
    for password security assessment.
    """
    
    score: float  # 0.0 to 1.0
    entropy_bits: float
    character_diversity: float
    length_score: float
    pattern_score: float
    dictionary_score: float
    crack_time_seconds: float
    analysis: dict[str, Any]
    
    def __post_init__(self) -> None:
        """Validate password strength data."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("Strength score must be between 0.0 and 1.0")
        
        if self.entropy_bits < 0:
            raise ValueError("Entropy bits cannot be negative")
        
        if self.crack_time_seconds < 0:
            raise ValueError("Crack time cannot be negative")
    
    def is_weak(self) -> bool:
        """Check if password is weak."""
        return self.score < 0.3
    
    def is_moderate(self) -> bool:
        """Check if password is moderate strength."""
        return 0.3 <= self.score < 0.7
    
    def is_strong(self) -> bool:
        """Check if password is strong."""
        return self.score >= 0.7
    
    def get_strength_label(self) -> str:
        """Get human-readable strength label."""
        if self.is_weak():
            return "Weak"
        if self.is_moderate():
            return "Moderate"
        return "Strong"
    
    def get_crack_time_human(self) -> str:
        """Get human-readable crack time estimate."""
        seconds = self.crack_time_seconds
        
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        if seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        if seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        if seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        return f"{seconds/31536000:.0f} years"
