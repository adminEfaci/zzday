"""
Password Policy

Business rules for password validation and strength requirements.
"""

import re
from datetime import datetime
from typing import Any

from app.core.config import PolicyConfigManager

from .base import BusinessRule, PolicyViolation, RemediationAction, ViolationSeverity


class PasswordPolicy(BusinessRule):
    """Password strength and policy validation."""
    
    def __init__(self, policy_config: dict[str, Any] | None = None):
        super().__init__("PasswordPolicy")
        if policy_config:
            self.config = policy_config
        else:
            config_manager = PolicyConfigManager()
            password_config = config_manager.get_password_config()
            self.config = password_config.__dict__
    
    def validate(self, password: str, user_context: dict[str, Any] | None = None) -> list[PolicyViolation]:
        """Validate password against policy."""
        violations = []
        
        # Length validation
        violations.extend(self._validate_length(password))
        
        # Character requirements
        violations.extend(self._validate_character_requirements(password))
        
        # Complexity validation
        violations.extend(self._validate_complexity(password))
        
        # Common password check
        violations.extend(self._validate_common_passwords(password))
        
        # Pattern detection
        violations.extend(self._validate_patterns(password))
        
        # Context-based validation
        if user_context:
            violations.extend(self._validate_context_rules(password, user_context))
        
        return violations
    
    def is_compliant(self, password: str, user_context: dict[str, Any] | None = None) -> bool:
        """Check if password is compliant with policy."""
        violations = self.validate(password, user_context)
        return not self.has_blocking_violations(violations)
    
    def _validate_length(self, password: str) -> list[PolicyViolation]:
        """Validate password length requirements."""
        violations = []
        
        if len(password) < self.config["min_length"]:
            violation = self.create_violation(
                rule_name="min_length",
                description=f"Password must be at least {self.config['min_length']} characters",
                severity=ViolationSeverity.ERROR,
                current_value=len(password),
                expected_value=self.config["min_length"],
                impact_level="high",
                compliance_frameworks=["NIST", "ISO27001"],
                remediation_actions=[
                    RemediationAction(
                        action_type="password_change",
                        description="Change your password to meet security requirements",
                        user_action_required=True,
                        estimated_time_minutes=5,
                        help_url="/help/password-requirements"
                    )
                ]
            )
            violations.append(violation)
        
        if len(password) > self.config["max_length"]:
            violations.append(PolicyViolation(
                rule_name="password_max_length",
                description=f"Password must be no more than {self.config['max_length']} characters",
                severity="error",
                current_value=len(password),
                expected_value=self.config["max_length"]
            ))
        
        return violations
    
    def _validate_character_requirements(self, password: str) -> list[PolicyViolation]:
        """Validate character type requirements."""
        violations = []
        
        if self.config["require_uppercase"] and not re.search(r"[A-Z]", password):
            violations.append(PolicyViolation(
                rule_name="password_uppercase",
                description="Password must contain at least one uppercase letter",
                severity="error",
                current_value=False,
                expected_value=True
            ))
        
        if self.config["require_lowercase"] and not re.search(r"[a-z]", password):
            violations.append(PolicyViolation(
                rule_name="password_lowercase",
                description="Password must contain at least one lowercase letter",
                severity="error",
                current_value=False,
                expected_value=True
            ))
        
        if self.config["require_digits"] and not re.search(r"\d", password):
            violations.append(PolicyViolation(
                rule_name="password_digits",
                description="Password must contain at least one digit",
                severity="error",
                current_value=False,
                expected_value=True
            ))
        
        special_chars = self.config.get("special_chars", "!@#$%^&*()_+-=[]{}|;:,.<>?")
        if self.config["require_special_chars"] and not re.search(f"[{re.escape(special_chars)}]", password):
            violations.append(PolicyViolation(
                rule_name="password_special_chars",
                description="Password must contain at least one special character",
                severity="error",
                current_value=False,
                expected_value=True
            ))
        
        return violations
    
    def _validate_complexity(self, password: str) -> list[PolicyViolation]:
        """Validate password complexity requirements."""
        violations = []
        
        complexity_score = self._calculate_complexity_score(password)
        min_score = self.config.get("complexity_score_threshold", 0.6)
        
        if complexity_score < min_score:
            violations.append(PolicyViolation(
                rule_name="password_complexity",
                description="Password complexity score too low",
                severity="warning",
                current_value=round(complexity_score, 2),
                expected_value=min_score
            ))
        
        # Check character variety
        unique_chars = len(set(password))
        min_unique = max(4, len(password) // 4)
        
        if unique_chars < min_unique:
            violations.append(PolicyViolation(
                rule_name="password_variety",
                description="Password lacks character variety",
                severity="warning",
                current_value=unique_chars,
                expected_value=min_unique
            ))
        
        return violations
    
    def _validate_common_passwords(self, password: str) -> list[PolicyViolation]:
        """Check against common passwords."""
        violations = []
        
        # Basic common password list (in production, use larger database)
        common_passwords = {
            "password", "12345678", "qwerty", "abc123", "password123",
            "admin", "letmein", "welcome", "monkey", "dragon"
        }
        
        if password.lower() in common_passwords:
            violations.append(PolicyViolation(
                rule_name="common_password",
                description="Password is too common and easily guessable",
                severity="error",
                current_value=True,
                expected_value=False
            ))
        
        return violations
    
    def _validate_patterns(self, password: str) -> list[PolicyViolation]:
        """Detect and validate against common patterns."""
        violations = []
        
        # Repeated characters
        if re.search(r"(.)\1{2,}", password):
            violations.append(PolicyViolation(
                rule_name="repeated_characters",
                description="Password contains repeated characters",
                severity="warning",
                current_value=True,
                expected_value=False
            ))
        
        # Sequential characters
        if self._has_sequential_characters(password):
            violations.append(PolicyViolation(
                rule_name="sequential_characters",
                description="Password contains sequential characters",
                severity="warning",
                current_value=True,
                expected_value=False
            ))
        
        # Keyboard patterns
        if self._has_keyboard_pattern(password):
            violations.append(PolicyViolation(
                rule_name="keyboard_pattern",
                description="Password follows a keyboard pattern",
                severity="warning",
                current_value=True,
                expected_value=False
            ))
        
        return violations
    
    def _validate_context_rules(self, password: str, user_context: dict[str, Any]) -> list[PolicyViolation]:
        """Validate context-specific password rules."""
        violations = []
        password_lower = password.lower()
        
        # Check name inclusion
        if "name" in user_context:
            name = user_context["name"].lower()
            if len(name) > 2 and name in password_lower:
                violations.append(PolicyViolation(
                    rule_name="password_contains_name",
                    description="Password should not contain your name",
                    severity="warning",
                    current_value=True,
                    expected_value=False
                ))
        
        # Check email inclusion
        if "email" in user_context:
            email_username = user_context["email"].split("@")[0].lower()
            if len(email_username) > 2 and email_username in password_lower:
                violations.append(PolicyViolation(
                    rule_name="password_contains_email",
                    description="Password should not contain your email username",
                    severity="warning",
                    current_value=True,
                    expected_value=False
                ))
        
        # Check username inclusion
        if "username" in user_context:
            username = user_context["username"].lower()
            if len(username) > 2 and username in password_lower:
                violations.append(PolicyViolation(
                    rule_name="password_contains_username",
                    description="Password should not contain your username",
                    severity="warning",
                    current_value=True,
                    expected_value=False
                ))
        
        # Check birth date patterns
        if user_context.get("birth_date"):
            birth_date = user_context["birth_date"]
            if isinstance(birth_date, str):
                birth_date = datetime.fromisoformat(birth_date)
            
            # Check various date formats
            date_patterns = [
                birth_date.strftime("%Y%m%d"),
                birth_date.strftime("%d%m%Y"),
                birth_date.strftime("%m%d%Y"),
                birth_date.strftime("%Y"),
                birth_date.strftime("%y"),
            ]
            
            for pattern in date_patterns:
                if pattern in password:
                    violations.append(PolicyViolation(
                        rule_name="password_contains_birthdate",
                        description="Password should not contain your birth date",
                        severity="warning",
                        current_value=True,
                        expected_value=False
                    ))
                    break
        
        return violations
    
    def _calculate_complexity_score(self, password: str) -> float:
        """Calculate password complexity score (0.0 to 1.0)."""
        score = 0.0
        
        # Length factor (up to 0.3)
        length_factor = min(len(password) / 20, 1.0) * 0.3
        score += length_factor
        
        # Character variety (up to 0.4)
        variety_score = 0.0
        if re.search(r"[a-z]", password):
            variety_score += 0.1
        if re.search(r"[A-Z]", password):
            variety_score += 0.1
        if re.search(r"\d", password):
            variety_score += 0.1
        if re.search(f"[{re.escape('!@#$%^&*()_+-=[]{}|;:,.<>?')}]", password):
            variety_score += 0.1
        score += variety_score
        
        # Entropy approximation (up to 0.3)
        unique_chars = len(set(password))
        entropy_factor = min(unique_chars / len(password), 1.0) * 0.3
        score += entropy_factor
        
        return min(score, 1.0)
    
    def _has_sequential_characters(self, password: str) -> bool:
        """Check for sequential characters."""
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789"
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password_lower or seq[i:i+3][::-1] in password_lower:
                    return True
        
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns."""
        keyboard_patterns = [
            "qwerty", "asdfgh", "zxcvbn",
            "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "1234567890", "!@#$%^&*()"
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    def check_password_history(self, password: str, password_history: list[str], history_count: int = 5) -> list[PolicyViolation]:
        """Check password against history."""
        violations = []
        
        # Check exact matches in history
        recent_history = password_history[:history_count]
        if password in recent_history:
            violations.append(PolicyViolation(
                rule_name="password_reuse",
                description=f"Password was used recently (within last {history_count} passwords)",
                severity="error",
                current_value=True,
                expected_value=False
            ))
        
        # Check similarity to recent passwords
        for idx, old_password in enumerate(recent_history):
            similarity = self._calculate_similarity(password, old_password)
            if similarity > 0.8:  # 80% similar
                violations.append(PolicyViolation(
                    rule_name="password_too_similar",
                    description="Password is too similar to a recently used password",
                    severity="warning",
                    current_value=similarity,
                    expected_value=0.8,
                    context={"position": idx + 1}
                ))
                break
        
        return violations
    
    def _calculate_similarity(self, password1: str, password2: str) -> float:
        """Calculate similarity between two passwords (0.0 to 1.0)."""
        if password1 == password2:
            return 1.0
        
        # Simple Levenshtein distance-based similarity
        longer = max(len(password1), len(password2))
        if longer == 0:
            return 1.0
        
        distance = self._levenshtein_distance(password1, password2)
        return (longer - distance) / longer
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
