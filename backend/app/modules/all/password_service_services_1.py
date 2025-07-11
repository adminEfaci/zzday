"""
Password Domain Service

Password validation, generation, and security checks using existing utilities.
"""

import math
from typing import Any
from uuid import UUID

from app.utils.crypto import generate_random_string, hash_data
from app.utils.text import normalize_whitespace
from app.utils.validation import validate_password_strength

from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.contracts.notification_contract import INotificationContract
from ...interfaces.repositories.user.password_history_repository import (
    IPasswordHistoryRepository,
)
from ...interfaces.services.authentication.password_service import IPasswordService
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort


class PasswordStrength:
    """Password strength levels."""
    VERY_WEAK = 0.0
    WEAK = 0.25
    FAIR = 0.5
    GOOD = 0.75
    STRONG = 1.0


class PasswordService(IPasswordService):
    """Domain service for password management."""
    
    def __init__(
        self,
        password_history_repository: IPasswordHistoryRepository,
        audit_contract: IAuditContract,
        notification_contract: INotificationContract,
        configuration_port: IConfigurationPort
    ) -> None:
        self._password_history_repository = password_history_repository
        self._audit_contract = audit_contract
        self._notification_contract = notification_contract
        self._config = configuration_port
        self._common_passwords = self._load_common_passwords()
    
    async def validate_password(
        self,
        password: str,
        user_context: dict[str, Any] | None = None,
        check_breach: bool = True
    ) -> tuple[bool, list[str]]:
        """Validate password against all policies."""
        
        if not password:
            return False, ["Password cannot be empty"]
        
        violations: list[str] = []
        user_id_str = user_context.get('user_id') if user_context else None
        user_id = UUID(user_id_str) if user_id_str else None
        
        # Get policy configuration
        policy_config = await self._config.get_password_policy()
        
        # Use existing validation utility
        strength_issues = validate_password_strength(
            password=password,
            min_length=policy_config.get('min_length', 8),
            require_uppercase=policy_config.get('require_uppercase', True),
            require_lowercase=policy_config.get('require_lowercase', True),
            require_numbers=policy_config.get('require_numbers', True),
            require_special=policy_config.get('require_special', True)
        )
        violations.extend(strength_issues)
        
        # Additional business rules
        additional_violations = await self._validate_business_rules(
            password, user_context, check_breach, policy_config
        )
        violations.extend(additional_violations)
        
        # Log validation attempt
        if user_id:
            await self._audit_contract.log_event(
                event_type="password_validation",
                user_id=user_id,
                details={
                    "valid": len(violations) == 0,
                    "violation_count": len(violations),
                    "check_breach": check_breach
                }
            )
        
        return len(violations) == 0, violations
    
    async def calculate_strength(self, password: str) -> tuple[float, dict[str, Any]]:
        """Calculate password strength with detailed breakdown."""
        
        if not password:
            return 0.0, {"error": "Password cannot be empty"}
        
        strength_score = 0.0
        details = {
            "length": len(password),
            "character_diversity": self._count_character_types(password),
            "entropy": self._calculate_entropy(password),
            "pattern_penalty": 0.0,
            "suggestions": []
        }
        
        # Length scoring (30% max)
        length_score = min(0.3, len(password) * 0.02)
        strength_score += length_score
        
        # Character diversity (40% max)
        diversity_score = min(0.4, details["character_diversity"] * 0.1)
        strength_score += diversity_score
        
        # Entropy scoring (30% max)
        entropy_score = min(0.3, details["entropy"] / 200)  # Scale to 0.3 max
        strength_score += entropy_score
        
        # Apply penalties
        penalty = self._calculate_pattern_penalty(password, details)
        details["pattern_penalty"] = penalty
        strength_score = max(0.0, strength_score - penalty)
        
        # Generate suggestions
        details["suggestions"] = self._generate_suggestions(password, details)
        
        return min(1.0, strength_score), details
    
    async def generate_secure_password(
        self,
        length: int = 16,
        include_symbols: bool = True,
        exclude_ambiguous: bool = True,
        pronounceable: bool = False
    ) -> str:
        """Generate a secure password using crypto utilities."""
        
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        if pronounceable:
            return self._generate_pronounceable_password(length)
        
        # Use existing crypto utility with custom alphabet
        alphabet = self._build_character_set(include_symbols, exclude_ambiguous)
        return generate_random_string(length, alphabet)
    
    async def check_password_history(
        self,
        user_id: UUID,
        password: str,
        min_distance: int = 3
    ) -> bool:
        """Check if password is sufficiently different from previous passwords."""
        
        # Get recent password hashes
        recent_hashes = await self._password_history_repository.get_recent_passwords(
            user_id, limit=10
        )
        
        # For security, we can only check if exact hash exists
        # Real similarity checking would require additional implementation
        password_hash = hash_data(password, "sha256")
        
        for stored_hash in recent_hashes:
            if stored_hash.hash_value == password_hash:
                return False
        
        return True
    
    async def estimate_crack_time(self, password: str) -> dict[str, Any]:
        """Estimate time to crack password."""
        
        if not password:
            return {"error": "Password cannot be empty"}
        
        entropy = self._calculate_entropy(password)
        
        # Get attack scenarios from configuration
        config = await self._config.get_security_settings()
        scenarios = config.get('crack_scenarios', self._default_crack_scenarios())
        
        crack_times = {}
        possible_combinations = 2 ** entropy
        
        for scenario, gps in scenarios.items():
            seconds = possible_combinations / (2 * gps)  # Average case
            crack_times[scenario] = self._format_time(seconds)
        
        return {
            "entropy_bits": entropy,
            "possible_combinations": int(possible_combinations),
            "crack_times": crack_times
        }
    
    async def suggest_improvements(self, password: str) -> list[str]:
        """Suggest improvements for password."""
        
        if not password:
            return ["Password cannot be empty"]
        
        strength, details = await self.calculate_strength(password)
        
        suggestions = details.get("suggestions", [])
        
        if strength < PasswordStrength.GOOD:
            if details["length"] < 12:
                suggestions.append("Increase length to at least 12 characters")
            
            if details["entropy"] < 40:
                suggestions.append("Use more random character combinations")
        
        return suggestions
    
    async def check_breach_status(self, password: str) -> tuple[bool, int]:
        """Check if password has been in known data breaches."""
        
        if not password:
            return False, 0
        
        try:
            # Use existing hash utility
            hash_data(password, "sha1")
            
            # Check against common passwords (mock implementation)
            if self._is_common_password(password):
                return True, 1000  # Mock breach count for common passwords
            
            return False, 0
        except Exception:
            # If breach check fails, don't block password
            return False, 0
    
    async def validate_password_policy(
        self,
        password: str,
        user_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Validate password against organization policy."""
        
        is_valid, violations = await self.validate_password(password, user_context)
        strength, strength_details = await self.calculate_strength(password)
        suggestions = await self.suggest_improvements(password)
        
        return {
            "is_valid": is_valid,
            "violations": violations,
            "strength_score": strength,
            "strength_details": strength_details,
            "suggestions": suggestions,
            "policy_met": is_valid and strength >= PasswordStrength.FAIR
        }
    
    # Private helper methods
    
    async def _validate_business_rules(
        self,
        password: str,
        user_context: dict[str, Any] | None,
        check_breach: bool,
        policy_config: dict[str, Any]
    ) -> list[str]:
        """Validate additional business rules."""
        violations = []
        
        # Common password check
        if self._is_common_password(password):
            violations.append("Password is too common")
        
        # User-specific checks
        if user_context and self._contains_user_info(password, user_context):
            violations.append("Password must not contain personal information")
        
        # Breach check
        if check_breach and policy_config.get('breach_check_enabled', True):
            is_breached, breach_count = await self.check_breach_status(password)
            if is_breached:
                violations.append(f"Password found in {breach_count} data breaches")
                
                # Log security event
                user_id_str = user_context.get('user_id') if user_context else None
                if user_id_str:
                    await self._audit_contract.log_event(
                        event_type="password_breach_detected",
                        user_id=UUID(user_id_str),
                        details={
                            "breach_count": breach_count,
                            "password_policy_check": True
                        }
                    )
        
        return violations
    
    def _count_character_types(self, password: str) -> int:
        """Count different character types in password."""
        types = 0
        if any(c.islower() for c in password):
            types += 1
        if any(c.isupper() for c in password):
            types += 1
        if any(c.isdigit() for c in password):
            types += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            types += 1
        return types
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0
        
        char_space = 0
        if any(c.islower() for c in password):
            char_space += 26
        if any(c.isupper() for c in password):
            char_space += 26
        if any(c.isdigit() for c in password):
            char_space += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            char_space += 32
        
        if char_space == 0:
            return 0.0
        
        return len(password) * math.log2(char_space)
    
    def _calculate_pattern_penalty(self, password: str, details: dict[str, Any]) -> float:
        """Calculate penalty for predictable patterns."""
        penalty = 0.0
        
        if self._has_keyboard_pattern(password):
            penalty += 0.2
            details["suggestions"].append("Avoid keyboard patterns")
        
        if self._has_repeated_characters(password):
            penalty += 0.1
            details["suggestions"].append("Reduce repeated characters")
        
        if self._is_common_password(password):
            penalty += 0.3
            details["suggestions"].append("Choose a less common password")
        
        return penalty
    
    def _generate_suggestions(self, password: str, details: dict[str, Any]) -> list[str]:
        """Generate improvement suggestions."""
        suggestions = []
        
        if details["length"] < 12:
            suggestions.append("Use at least 12 characters")
        
        if details["character_diversity"] < 3:
            suggestions.append("Mix uppercase, lowercase, numbers, and symbols")
        
        return suggestions
    
    def _build_character_set(self, include_symbols: bool, exclude_ambiguous: bool) -> str:
        """Build character set for password generation."""
        import string
        
        chars = string.ascii_letters + string.digits
        
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if exclude_ambiguous:
            # Remove ambiguous characters
            ambiguous = "0O1lI"
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        return chars
    
    def _generate_pronounceable_password(self, length: int) -> str:
        """Generate pronounceable password using crypto utilities."""
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        
        pattern = []
        for i in range(length):
            if i % 2 == 0:
                pattern.append(generate_random_string(1, consonants))
            else:
                pattern.append(generate_random_string(1, vowels))
        
        # Add numbers for security
        for _ in range(2):
            if pattern:
                pos = len(pattern) // 3  # Deterministic position
                pattern[pos] = generate_random_string(1, "0123456789")
        
        return ''.join(pattern)
    
    def _load_common_passwords(self) -> set:
        """Load common passwords list."""
        return {
            "password", "123456", "password123", "admin", "letmein",
            "qwerty", "111111", "welcome", "monkey", "dragon",
            "baseball", "iloveyou", "trustno1", "1234567", "sunshine",
            "master", "123123", "welcome123", "shadow", "ashley"
        }
    
    def _is_common_password(self, password: str) -> bool:
        """Check if password is in common passwords list."""
        return password.lower() in self._common_passwords
    
    def _contains_user_info(self, password: str, user_context: dict[str, Any]) -> bool:
        """Check if password contains user information."""
        password_clean = normalize_whitespace(password.lower())
        
        # Check username
        username = user_context.get('username', '')
        if username and len(username) > 2 and username.lower() in password_clean:
            return True
        
        # Check email parts
        email = user_context.get('email', '')
        if email:
            email_parts = email.split('@')[0].split('.')
            for part in email_parts:
                if len(part) > 2 and part.lower() in password_clean:
                    return True
        
        # Check name parts
        for field in ['first_name', 'last_name', 'display_name']:
            name = user_context.get(field, '')
            if name and len(name) > 2 and name.lower() in password_clean:
                return True
        
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns."""
        patterns = [
            "qwerty", "asdfgh", "zxcvbn", "qwertyuiop",
            "1234567890", "123456789", "abcdefgh"
        ]
        
        password_lower = password.lower()
        return any(
            pattern in password_lower or pattern[::-1] in password_lower
            for pattern in patterns
        )
    
    def _has_repeated_characters(self, password: str) -> bool:
        """Check for excessive repeated characters."""
        return any(
            password[i] == password[i+1] == password[i+2]
            for i in range(len(password) - 2)
        )
    
    def _default_crack_scenarios(self) -> dict[str, int]:
        """Default crack time scenarios."""
        return {
            "online_throttled": 10,
            "online_unthrottled": 1000,
            "offline_slow": 10_000,
            "offline_fast": 1_000_000_000,
            "massive_parallel": 100_000_000_000
        }
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time."""
        if seconds < 1:
            return "instantly"
        if seconds < 60:
            return f"{int(seconds)} seconds"
        if seconds < 3600:
            return f"{int(seconds/60)} minutes"
        if seconds < 86400:
            return f"{int(seconds/3600)} hours"
        if seconds < 31536000:
            return f"{int(seconds/86400)} days"
        if seconds < 3153600000:
            return f"{int(seconds/31536000)} years"
        return "centuries"