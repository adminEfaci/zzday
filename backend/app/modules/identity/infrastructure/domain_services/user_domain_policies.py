"""
Domain Policy Implementations for User Domain Services

Infrastructure layer implementations of domain policy protocols.
These implement the business rules that can be configured and injected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...domain.aggregates.user import User


class DefaultRiskCalculationPolicy:
    """Default implementation of risk calculation policy."""
    
    def calculate_risk_score(self, user: User) -> float:
        """Calculate user risk score based on domain rules."""
        risk = 0.0
        
        # Account age factor
        if user.get_account_age_days() < 7:
            risk += 0.2
        
        # Failed login attempts
        if user.failed_login_count > 3:
            risk += min(user.failed_login_count * 0.1, 0.3)
        
        # Unverified contact methods
        if not user.email_verified:
            risk += 0.2
        
        if user.phone_number and not user.phone_verified:
            risk += 0.1
        
        # No MFA
        if not user.mfa_enabled:
            risk += 0.1
        
        return min(risk, 1.0)


class DefaultPasswordPolicy:
    """Default implementation of password policy."""
    
    # Policy constants
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    SPECIAL_CHARS = "!@#$%^&*(),.?\":{}|<>"
    
    def validate_password(self, password: str, user: User) -> list[str]:
        """Validate password against domain policy."""
        violations = []
        
        if len(password) < self.MIN_LENGTH:
            violations.append(f"Password must be at least {self.MIN_LENGTH} characters")
        
        if len(password) > self.MAX_LENGTH:
            violations.append(f"Password cannot exceed {self.MAX_LENGTH} characters")
        
        if self.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")
        
        if self.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")
        
        if self.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one digit")
        
        if self.REQUIRE_SPECIAL_CHARS and not any(c in self.SPECIAL_CHARS for c in password):
            violations.append("Password must contain at least one special character")
        
        return violations


class EnterprisePasswordPolicy:
    """Enterprise-grade password policy implementation."""
    
    # Stricter policy constants
    MIN_LENGTH = 12
    MAX_LENGTH = 256
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    SPECIAL_CHARS = "!@#$%^&*(),.?\":{}|<>[]{}~`"
    REQUIRE_NON_DICTIONARY_WORDS = True
    
    def __init__(self, dictionary_words: set[str] | None = None) -> None:
        self.dictionary_words = dictionary_words or set()
    
    def validate_password(self, password: str, user: User) -> list[str]:
        """Validate password against enterprise policy."""
        violations = []
        
        # Basic length and character requirements
        if len(password) < self.MIN_LENGTH:
            violations.append(f"Password must be at least {self.MIN_LENGTH} characters")
        
        if len(password) > self.MAX_LENGTH:
            violations.append(f"Password cannot exceed {self.MAX_LENGTH} characters")
        
        if self.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")
        
        if self.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")
        
        if self.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one digit")
        
        if self.REQUIRE_SPECIAL_CHARS and not any(c in self.SPECIAL_CHARS for c in password):
            violations.append("Password must contain at least one special character")
        
        # Dictionary word check
        if self.REQUIRE_NON_DICTIONARY_WORDS and self.dictionary_words:
            password_lower = password.lower()
            for word in self.dictionary_words:
                if word.lower() in password_lower:
                    violations.append("Password cannot contain common dictionary words")
                    break
        
        # User-specific checks
        if user.username and user.username.lower() in password.lower():
            violations.append("Password cannot contain your username")
        
        if user.email and user.email.local_part.lower() in password.lower():
            violations.append("Password cannot contain parts of your email address")
        
        return violations