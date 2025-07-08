"""
Validate password command implementation.

Handles password validation against security policies.
"""

import hashlib
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IBreachDetectionService,
    ICacheService,
    IPasswordHistoryRepository,
    IPasswordPolicyRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import rate_limit, validate_request
from app.modules.identity.application.dtos.request import ValidatePasswordRequest
from app.modules.identity.application.dtos.response import PasswordValidationResponse
from app.modules.identity.domain.entities import PasswordPolicy, User
from app.modules.identity.domain.exceptions import UserNotFoundError
from app.modules.identity.domain.services import PasswordService, SecurityService


class ValidatePasswordCommand(Command[PasswordValidationResponse]):
    """Command to validate password."""
    
    def __init__(
        self,
        password: str,
        user_id: UUID | None = None,
        username: str | None = None,
        email: str | None = None,
        check_breach: bool = True,
        check_history: bool = True,
        policy_name: str | None = None
    ):
        self.password = password
        self.user_id = user_id
        self.username = username
        self.email = email
        self.check_breach = check_breach
        self.check_history = check_history
        self.policy_name = policy_name


class ValidatePasswordCommandHandler(CommandHandler[ValidatePasswordCommand, PasswordValidationResponse]):
    """Handler for password validation."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        password_policy_repository: IPasswordPolicyRepository,
        password_history_repository: IPasswordHistoryRepository,
        password_service: PasswordService,
        security_service: SecurityService,
        breach_detection_service: IBreachDetectionService,
        cache_service: ICacheService,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._password_policy_repository = password_policy_repository
        self._password_history_repository = password_history_repository
        self._password_service = password_service
        self._security_service = security_service
        self._breach_detection_service = breach_detection_service
        self._cache_service = cache_service
        self._unit_of_work = unit_of_work
    
    @validate_request(ValidatePasswordRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=300,
        strategy='ip'
    )
    async def handle(self, command: ValidatePasswordCommand) -> PasswordValidationResponse:
        """
        Validate password against policies.
        
        Process:
        1. Load user if provided
        2. Get applicable password policy
        3. Check basic requirements
        4. Check complexity rules
        5. Check against user info
        6. Check password history
        7. Check for breaches
        8. Calculate strength score
        
        Returns:
            PasswordValidationResponse with validation details
        """
        async with self._unit_of_work:
            # 1. Load user if user_id provided
            user = None
            if command.user_id:
                user = await self._user_repository.get_by_id(command.user_id)
                if not user:
                    raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Get password policy
            policy = await self._get_password_policy(command.policy_name, user)
            
            # 3. Initialize validation results
            validation_errors = []
            warnings = []
            strength_score = 100  # Start with perfect score
            
            # 4. Check minimum length
            if len(command.password) < policy.min_length:
                validation_errors.append(
                    f"Password must be at least {policy.min_length} characters long"
                )
                strength_score -= 20
            
            # 5. Check maximum length
            if policy.max_length and len(command.password) > policy.max_length:
                validation_errors.append(
                    f"Password must not exceed {policy.max_length} characters"
                )
            
            # 6. Check character requirements
            char_errors, char_score = self._check_character_requirements(
                password=command.password,
                policy=policy
            )
            validation_errors.extend(char_errors)
            strength_score -= char_score
            
            # 7. Check complexity
            complexity_errors, complexity_score = self._check_complexity(
                password=command.password,
                policy=policy
            )
            validation_errors.extend(complexity_errors)
            strength_score -= complexity_score
            
            # 8. Check against user information
            if user or command.username or command.email:
                user_info_errors, user_info_score = await self._check_user_info(
                    password=command.password,
                    user=user,
                    username=command.username,
                    email=command.email,
                    policy=policy
                )
                validation_errors.extend(user_info_errors)
                strength_score -= user_info_score
            
            # 9. Check password history
            if command.check_history and user:
                history_errors = await self._check_password_history(
                    password=command.password,
                    user_id=user.id,
                    policy=policy
                )
                validation_errors.extend(history_errors)
                if history_errors:
                    strength_score -= 15
            
            # 10. Check for breaches
            breach_info = None
            if command.check_breach:
                breach_info = await self._check_breach(command.password)
                if breach_info['is_breached']:
                    if policy.block_breached_passwords:
                        validation_errors.append(
                            "This password has been found in data breaches and cannot be used"
                        )
                        strength_score = 0
                    else:
                        warnings.append(
                            f"This password has appeared in {breach_info['breach_count']} data breaches"
                        )
                        strength_score -= 30
            
            # 11. Check common patterns
            pattern_warnings, pattern_score = self._check_common_patterns(
                command.password
            )
            warnings.extend(pattern_warnings)
            strength_score -= pattern_score
            
            # 12. Calculate entropy
            entropy = self._calculate_entropy(command.password)
            
            # 13. Determine strength level
            strength_score = max(0, min(100, strength_score))
            strength_level = self._get_strength_level(strength_score)
            
            # 14. Generate suggestions
            suggestions = self._generate_suggestions(
                validation_errors=validation_errors,
                warnings=warnings,
                policy=policy,
                entropy=entropy
            )
            
            is_valid = len(validation_errors) == 0
            
            return PasswordValidationResponse(
                is_valid=is_valid,
                strength_score=strength_score,
                strength_level=strength_level,
                entropy=entropy,
                validation_errors=validation_errors,
                warnings=warnings,
                suggestions=suggestions,
                breach_info=breach_info,
                policy_requirements={
                    'min_length': policy.min_length,
                    'max_length': policy.max_length,
                    'require_uppercase': policy.require_uppercase,
                    'require_lowercase': policy.require_lowercase,
                    'require_numbers': policy.require_numbers,
                    'require_special': policy.require_special,
                    'min_unique_chars': policy.min_unique_chars
                },
                success=True,
                message="Password validation completed"
            )
    
    async def _get_password_policy(
        self,
        policy_name: str | None,
        user: User | None
    ) -> PasswordPolicy:
        """Get applicable password policy."""
        # Try specific policy name
        if policy_name:
            policy = await self._password_policy_repository.get_by_name(policy_name)
            if policy:
                return policy
        
        # Try user-specific policy
        if user:
            policy = await self._password_policy_repository.get_for_user(user.id)
            if policy:
                return policy
        
        # Get default policy
        return await self._password_policy_repository.get_default()
    
    def _check_character_requirements(
        self,
        password: str,
        policy: PasswordPolicy
    ) -> tuple[list[str], int]:
        """Check character type requirements."""
        errors = []
        score_penalty = 0
        
        if policy.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
            score_penalty += 10
        
        if policy.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
            score_penalty += 10
        
        if policy.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
            score_penalty += 10
        
        if policy.require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")
                score_penalty += 10
        
        return errors, score_penalty
    
    def _check_complexity(
        self,
        password: str,
        policy: PasswordPolicy
    ) -> tuple[list[str], int]:
        """Check password complexity."""
        errors = []
        score_penalty = 0
        
        # Check unique characters
        unique_chars = len(set(password))
        if policy.min_unique_chars and unique_chars < policy.min_unique_chars:
            errors.append(
                f"Password must contain at least {policy.min_unique_chars} unique characters"
            )
            score_penalty += 15
        
        # Check for repeated characters
        if policy.block_repeated_chars:
            for i in range(len(password) - 2):
                if password[i] == password[i+1] == password[i+2]:
                    errors.append("Password cannot contain 3 or more repeated characters")
                    score_penalty += 10
                    break
        
        # Check for sequential characters
        if policy.block_sequential_chars:
            sequences = [
                "abcdefghijklmnopqrstuvwxyz",
                "0123456789",
                "qwertyuiop",
                "asdfghjkl",
                "zxcvbnm"
            ]
            
            password_lower = password.lower()
            for seq in sequences:
                for i in range(len(seq) - 3):
                    if seq[i:i+4] in password_lower:
                        errors.append("Password cannot contain sequential characters")
                        score_penalty += 10
                        break
        
        return errors, score_penalty
    
    async def _check_user_info(
        self,
        password: str,
        user: User | None,
        username: str | None,
        email: str | None,
        policy: PasswordPolicy
    ) -> tuple[list[str], int]:
        """Check password against user information."""
        errors = []
        score_penalty = 0
        
        if not policy.block_user_info_in_password:
            return errors, score_penalty
        
        password_lower = password.lower()
        
        # Check username
        check_username = username or (user.username if user else None)
        if check_username and check_username.lower() in password_lower:
            errors.append("Password cannot contain your username")
            score_penalty += 20
        
        # Check email
        check_email = email or (user.email if user else None)
        if check_email:
            email_prefix = check_email.split('@')[0].lower()
            if email_prefix in password_lower:
                errors.append("Password cannot contain parts of your email")
                score_penalty += 20
        
        # Check name
        if user and user.full_name:
            name_parts = user.full_name.lower().split()
            for part in name_parts:
                if len(part) > 2 and part in password_lower:
                    errors.append("Password cannot contain parts of your name")
                    score_penalty += 15
                    break
        
        return errors, score_penalty
    
    async def _check_password_history(
        self,
        password: str,
        user_id: UUID,
        policy: PasswordPolicy
    ) -> list[str]:
        """Check against password history."""
        errors = []
        
        if not policy.password_history_count:
            return errors
        
        # Get password history
        history = await self._password_history_repository.get_recent(
            user_id=user_id,
            count=policy.password_history_count
        )
        
        # Check against each historical password
        for hist_entry in history:
            is_match = await self._password_service.verify_password(
                password,
                hist_entry.password_hash
            )
            
            if is_match:
                errors.append(
                    f"Password cannot be the same as your last {policy.password_history_count} passwords"
                )
                break
        
        return errors
    
    async def _check_breach(self, password: str) -> dict[str, Any]:
        """Check if password has been breached."""
        try:
            # Check cache first
            cache_key = f"breach_check:{hashlib.sha256(password.encode()).hexdigest()[:16]}"
            cached = await self._cache_service.get(cache_key)
            
            if cached:
                return cached
            
            # Check breach service
            breach_result = await self._breach_detection_service.check_password(password)
            
            result = {
                'is_breached': breach_result['found'],
                'breach_count': breach_result.get('count', 0),
                'first_seen': breach_result.get('first_seen'),
                'last_seen': breach_result.get('last_seen')
            }
            
            # Cache result for 1 hour
            await self._cache_service.set(cache_key, result, ttl=3600)
            
            return result
            
        except Exception:
            # Don't fail validation if breach check fails
            return {
                'is_breached': False,
                'breach_count': 0,
                'check_failed': True
            }
    
    def _check_common_patterns(self, password: str) -> tuple[list[str], int]:
        """Check for common password patterns."""
        warnings = []
        score_penalty = 0
        
        password_lower = password.lower()
        
        # Check for common words
        common_words = [
            'password', 'admin', 'user', 'login', 'welcome',
            'test', 'demo', 'sample', 'example', 'temp'
        ]
        
        for word in common_words:
            if word in password_lower:
                warnings.append(f"Password contains common word: '{word}'")
                score_penalty += 10
                break
        
        # Check for dates
        import re
        date_patterns = [
            r'\d{4}',  # Year
            r'\d{1,2}[/-]\d{1,2}',  # MM/DD or MM-DD
            r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)',  # Months
        ]
        
        for pattern in date_patterns:
            if re.search(pattern, password_lower):
                warnings.append("Password appears to contain date information")
                score_penalty += 5
                break
        
        # Check for keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv',
            '1234', '4321', '1111',
            'abcd', 'aaaa'
        ]
        
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                warnings.append("Password contains keyboard pattern")
                score_penalty += 15
                break
        
        return warnings, score_penalty
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        charset_size = 0
        
        # Determine character set size
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            charset_size += 32
        
        # Calculate entropy: log2(charset_size^length)
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        return round(entropy, 2)
    
    def _get_strength_level(self, score: int) -> str:
        """Determine password strength level."""
        if score >= 80:
            return "strong"
        if score >= 60:
            return "good"
        if score >= 40:
            return "fair"
        if score >= 20:
            return "weak"
        return "very_weak"
    
    def _generate_suggestions(
        self,
        validation_errors: list[str],
        warnings: list[str],
        policy: PasswordPolicy,
        entropy: float
    ) -> list[str]:
        """Generate password improvement suggestions."""
        suggestions = []
        
        if entropy < 50:
            suggestions.append("Consider using a longer password or more character types")
        
        if warnings:
            suggestions.append("Avoid using common words, patterns, or personal information")
        
        if not validation_errors and entropy < 70:
            suggestions.append("Add more unique characters to increase password strength")
        
        if policy.min_length < 12:
            suggestions.append("Consider using a passphrase of 4+ random words")
        
        return suggestions