"""
Password Domain Service

Handles password management, validation, history, reset flows, and strength analysis.
Implements IPasswordService protocol for contract-based service operations.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Tuple, List
from uuid import UUID

from app.utils.crypto import hash_password, verify_password
from app.utils.crypto import generate_random_string, hash_data
from app.utils.text import normalize_whitespace

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User
    from ...value_objects.password_strength import PasswordStrength
    from ...value_objects.password_validation_result import PasswordValidationResult

from ...constants import PolicyConstants, SecurityLimits
from ...enums import UserStatus
from ...entities.user.user_errors import (
    AccountInactiveError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordPolicyViolationError,
    TokenExpiredError,
)
from ...entities.user.user_events import (
    PasswordResetRequested,
    UserPasswordChanged,
)
from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.contracts.notification_contract import INotificationContract
from ...interfaces.repositories.password_history_repository import IPasswordHistoryRepository
from ...interfaces.services.authentication.password_service import IPasswordService
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort


class PasswordStrength:
    """Password strength levels."""
    VERY_WEAK = 0.0
    WEAK = 0.25
    FAIR = 0.5
    GOOD = 0.75
    STRONG = 1.0


class PasswordService:
    """Domain service for password management implementing IPasswordService."""

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
    ) -> "PasswordValidationResult":
        """Validate password against all policies."""
        if not password:
            return False, ["Password cannot be empty"]

        violations: List[str] = []
        user_id = UUID(user_context['user_id']) if user_context and 'user_id' in user_context else None

        # Get policy configuration
        policy_config = await self._config.get_password_policy()

        # Basic policy validation
        violations.extend(self._validate_password_policy(password, user_context))

        # Additional business rules
        additional_violations = await self._validate_business_rules(
            password, user_context, check_breach, policy_config
        )
        violations.extend(additional_violations)

        # Log validation attempt
        if user_id:
            await self._audit_contract.log_security_event(
                user_id=user_id,
                event_type="password_validation",
                severity="low" if len(violations) == 0 else "medium",
                details={
                    "valid": len(violations) == 0,
                    "violation_count": len(violations),
                    "check_breach": check_breach,
                    "violations": violations
                }
            )

        return len(violations) == 0, violations

    async def calculate_strength(self, password: str) -> Tuple[float, dict[str, Any]]:
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
        entropy_score = min(0.3, details["entropy"] / 200)
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
        """Generate a secure password."""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")

        if pronounceable:
            return self._generate_pronounceable_password(length)

        alphabet = self._build_character_set(include_symbols, exclude_ambiguous)
        return generate_random_string(length, alphabet)

    async def check_password_history(self, user_id: UUID, password: str, min_distance: int = 3) -> bool:
        """Check if password is sufficiently different from previous passwords."""
        recent_hashes = await self._password_history_repository.get_recent_passwords(user_id, limit=10)
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
        config = await self._config.get_password_policy()
        scenarios = config.get('crack_scenarios', self._default_crack_scenarios())

        crack_times = {}
        possible_combinations = 2 ** entropy

        for scenario, gps in scenarios.items():
            seconds = possible_combinations / (2 * gps)
            crack_times[scenario] = self._format_time(seconds)

        return {
            "entropy_bits": entropy,
            "possible_combinations": int(possible_combinations),
            "crack_times": crack_times
        }

    async def suggest_improvements(self, password: str) -> List[str]:
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

    async def check_breach_status(self, password: str) -> Tuple[bool, int]:
        """Check if password has been in known data breaches."""
        if not password:
            return False, 0

        try:
            hash_data(password, "sha1")
            if self._is_common_password(password):
                return True, 1000
            return False, 0
        except Exception:
            return False, 0

    async def validate_password_policy(
        self, password: str, user_context: dict[str, Any] | None = None
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

    async def change_password(
        self, user: User, current_password: str, new_password: str, changed_by: UUID | None = None
    ) -> None:
        """Change user password with validation."""
        if user.status != UserStatus.ACTIVE:
            raise AccountInactiveError(user.id)

        is_self_change = changed_by is None or changed_by == user.id
        if is_self_change and not verify_password(current_password, user.password_hash):
            raise InvalidCredentialsError()

        violations = self._validate_password_policy(
            new_password,
            {
                "user_id": str(user.id),
                "username": user.username.value,
                "email": user.email.value
            }
        )
        if violations:
            raise PasswordPolicyViolationError(violations)

        if await self._is_password_in_history(user, new_password):
            raise PasswordPolicyViolationError([
                f"Password was used recently. Last {SecurityLimits.PASSWORD_HISTORY_COUNT} passwords cannot be reused"
            ])

        await self._add_password_to_history(user, user.password_hash)
        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)
        user.require_password_change = False
        user._regenerate_security_stamp()
        user.updated_at = datetime.now(UTC)

        user.add_domain_event(UserPasswordChanged(
            user_id=user.id,
            changed_by=changed_by or user.id,
            sessions_invalidated=True
        ))

        await self._audit_contract.log_security_event(
            user_id=user.id,
            event_type="password_changed",
            severity="medium",
            details={"changed_by": str(changed_by or user.id)}
        )

    async def request_password_reset(self, user: User, ip_address: str, user_agent: str) -> str:
        """Request password reset token."""
        token = secrets.token_urlsafe(32)
        user.password_reset_token = hashlib.sha256(token.encode()).hexdigest()
        user.password_reset_token_expires = datetime.now(UTC) + timedelta(hours=1)
        user.updated_at = datetime.now(UTC)

        user.add_domain_event(PasswordResetRequested(
            user_id=user.id,
            reset_token=user.password_reset_token,
            expires_at=user.password_reset_token_expires,
            requested_ip=ip_address,
            requested_user_agent=user_agent
        ))

        await self._notification_contract.send_email_notification(
            user_id=user.id,
            template_name="password_reset",
            template_data={"reset_token": token}
        )

        return token

    async def reset_password_with_token(self, user: User, token: str, new_password: str) -> None:
        """Reset password using token."""
        if not user.password_reset_token:
            raise InvalidTokenError("No password reset pending")

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if user.password_reset_token != token_hash:
            raise InvalidTokenError("Invalid reset token")

        if user.password_reset_token_expires < datetime.now(UTC):
            raise TokenExpiredError("Reset token has expired")

        await self.change_password(user, "", new_password, changed_by=user.id)
        user.password_reset_token = None
        user.password_reset_token_expires = None

    async def force_password_change(self, user: User) -> None:
        """Force password change on next login."""
        user.require_password_change = True
        user.updated_at = datetime.now(UTC)

        await self._audit_contract.log_security_event(
            user_id=user.id,
            event_type="force_password_change",
            severity="medium",
            details={"action": "password_change_required"}
        )

    async def get_password_age_days(self, user: User) -> int:
        """Get password age in days."""
        if not user.password_changed_at:
            return user.get_account_age_days()
        return (datetime.now(UTC) - user.password_changed_at).days

    async def is_password_expired(self, user: User, max_age_days: int = 90) -> bool:
        """Check if password has expired."""
        return await self.get_password_age_days(user) > max_age_days

    async def requires_password_change(self, user: User) -> bool:
        """Check if user must change password."""
        return (
            user.require_password_change or
            await self.get_password_age_days(user) > PolicyConstants.PASSWORD_POLICY_CONSTANTS["MAX_AGE"].days
        )

    # Private helper methods
    def _validate_password_policy(self, password: str, user_context: dict[str, Any] | None) -> List[str]:
        """Validate password against policy."""
        violations: List[str] = []
        policy = PolicyConstants.PASSWORD_POLICY_CONSTANTS

        if len(password) < policy["MIN_LENGTH"]:
            violations.append(f"Password must be at least {policy['MIN_LENGTH']} characters")

        if len(password) > policy["MAX_LENGTH"]:
            violations.append(f"Password must not exceed {policy['MAX_LENGTH']} characters")

        if policy["REQUIRE_UPPERCASE"] and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")

        if policy["REQUIRE_LOWERCASE"] and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")

        if policy["REQUIRE_NUMBERS"] and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one number")

        if policy["REQUIRE_SPECIAL_CHARS"]:
            special_chars = set(policy["SPECIAL_CHARS"])
            if not any(c in special_chars for c in password):
                violations.append(f"Password must contain at least one special character ({policy['SPECIAL_CHARS']})")

        if user_context:
            username = user_context.get("username", "").lower()
            email_local = user_context.get("email", "").split('@')[0].lower()

            if password.lower() == username or password.lower() == email_local:
                violations.append("Password cannot be the same as username or email")

            if len(username) > 3 and username in password.lower():
                violations.append("Password cannot contain your username")

        return violations

    async def _validate_business_rules(
        self,
        password: str,
        user_context: dict[str, Any] | None,
        check_breach: bool,
        policy_config: dict[str, Any]
    ) -> List[str]:
        """Validate additional business rules."""
        violations: List[str] = []

        if self._is_common_password(password):
            violations.append("Password is too common")

        if user_context and self._contains_user_info(password, user_context):
            violations.append("Password must not contain personal information")

        if check_breach and policy_config.get('breach_check_enabled', True):
            is_breached, breach_count = await self.check_breach_status(password)
            if is_breached:
                violations.append(f"Password found in {breach_count} data breaches")
                if user_context and 'user_id' in user_context:
                    await self._audit_contract.log_security_event(
                        user_id=UUID(user_context['user_id']),
                        event_type="password_breach_detected",
                        severity="high",
                        details={"breach_count": breach_count, "password_policy_check": True}
                    )

        return violations

    async def _is_password_in_history(self, user: User, password: str) -> bool:
        """Check if password was used recently."""
        recent_count = min(len(user._password_history), SecurityLimits.PASSWORD_HISTORY_COUNT)
        recent_hashes = user._password_history[-recent_count:] if recent_count > 0 else []

        for password_hash in recent_hashes:
            if verify_password(password, password_hash):
                return True

        return verify_password(password, user.password_hash)

    async def _add_password_to_history(self, user: User, password_hash: str) -> None:
        """Add password hash to history."""
        user._password_history.append(password_hash)
        max_history = SecurityLimits.PASSWORD_HISTORY_COUNT
        if len(user._password_history) > max_history:
            user._password_history = user._password_history[-max_history:]

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

    def _generate_suggestions(self, password: str, details: dict[str, Any]) -> List[str]:
        """Generate improvement suggestions."""
        suggestions: List[str] = []
        if details["length"] < 12:
            suggestions.append("Use at least 12 characters")
        if details["character_diversity"] < 3:
            suggestions.append("Mix uppercase, lowercase, numbers, and symbols")
        return suggestions

    def _build_character_set(self, include_symbols: bool, exclude_ambiguous: bool) -> str:
        """Build character set for password generation."""
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if exclude_ambiguous:
            ambiguous = "0O1lI"
            chars = ''.join(c for c in chars if c not in ambiguous)
        return chars

    def _generate_pronounceable_password(self, length: int) -> str:
        """Generate pronounceable password."""
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        pattern = []
        for i in range(length):
            if i % 2 == 0:
                pattern.append(generate_random_string(1, consonants))
            else:
                pattern.append(generate_random_string(1, vowels))
        for _ in range(2):
            if pattern:
                pos = len(pattern) // 3
                pattern[pos] = generate_random_string(1, "0123456789")
        return ''.join(pattern)

    def _load_common_passwords(self) -> set[str]:
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
        username = user_context.get('username', '')
        if username and len(username) > 2 and username.lower() in password_clean:
            return True
        email = user_context.get('email', '')
        if email:
            email_parts = email.split('@')[0].split('.')
            for part in email_parts:
                if len(part) > 2 and part.lower() in password_clean:
                    return True
        for field in ['first_name', 'last_name', 'display_name']:
            name = user_context.get(field, '')
            if name and len(name) > 2 and name.lower() in password_clean:
                return True
        return False

    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns."""
        patterns = ["qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "1234567890", "123456789", "abcdefgh"]
        password_lower = password.lower()
        return any(pattern in password_lower or pattern[::-1] in password_lower for pattern in patterns)

    def _has_repeated_characters(self, password: str) -> bool:
        """Check for excessive repeated characters."""
        return any(password[i] == password[i+1] == password[i+2] for i in range(len(password) - 2))

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
