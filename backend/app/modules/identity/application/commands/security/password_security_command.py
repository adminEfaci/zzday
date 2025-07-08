"""
Password security command implementation.

Handles password-related security operations including policy enforcement,
breach detection, strength analysis, and security recommendations.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IBreachRepository,
    IEmailService,
    INotificationService,
    IPasswordRepository,
    ISecurityRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import PasswordSecurityRequest
from app.modules.identity.application.dtos.response import PasswordSecurityResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    PasswordStrength,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import (
    PasswordBreachDetected,
    WeakPasswordDetected,
)
from app.modules.identity.domain.exceptions import (
    PasswordSecurityError,
    PasswordValidationError,
)
from app.modules.identity.domain.services import (
    BreachDetectionService,
    PasswordService,
    SecurityService,
    ValidationService,
)


class PasswordOperation(Enum):
    """Type of password security operation."""
    ANALYZE_STRENGTH = "analyze_strength"
    CHECK_POLICY_COMPLIANCE = "check_policy_compliance"
    DETECT_BREACHES = "detect_breaches"
    SCAN_ORGANIZATION = "scan_organization"
    GENERATE_SECURE = "generate_secure"
    AUDIT_PASSWORDS = "audit_passwords"
    ENFORCE_POLICY = "enforce_policy"
    GENERATE_REPORT = "generate_report"


class BreachSource(Enum):
    """Source of password breach data."""
    HAVEIBEENPWNED = "haveibeenpwned"
    INTERNAL_DATABASE = "internal_database"
    SECURITY_FEEDS = "security_feeds"
    CUSTOM_LISTS = "custom_lists"
    ALL_SOURCES = "all_sources"


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1
    prevent_common_passwords: bool = True
    prevent_personal_info: bool = True
    prevent_keyboard_patterns: bool = True
    prevent_dictionary_words: bool = True
    prevent_repeated_chars: int = 3
    prevent_sequential_chars: bool = True
    password_history_count: int = 12
    max_age_days: int = 90
    min_age_hours: int = 24
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 30
    breach_check_enabled: bool = True
    strength_requirement: PasswordStrength = PasswordStrength.STRONG


@dataclass
class PasswordAnalysis:
    """Result of password analysis."""
    password_hash: str
    strength_score: float
    strength_level: PasswordStrength
    policy_violations: list[str]
    breach_detected: bool
    breach_sources: list[str]
    entropy_bits: float
    character_diversity: float
    pattern_analysis: dict[str, Any]
    recommendations: list[str]
    estimated_crack_time: str


class PasswordSecurityCommand(Command[PasswordSecurityResponse]):
    """Command to handle password security operations."""
    
    def __init__(
        self,
        operation_type: PasswordOperation,
        user_id: UUID | None = None,
        password: str | None = None,
        password_hash: str | None = None,
        organization_id: UUID | None = None,
        password_policy: PasswordPolicy | None = None,
        check_breaches: bool = True,
        breach_sources: list[BreachSource] | None = None,
        include_user_info: bool = True,
        analyze_patterns: bool = True,
        generate_recommendations: bool = True,
        batch_user_ids: list[UUID] | None = None,
        scan_depth: str = "standard",  # "basic", "standard", "comprehensive"
        policy_enforcement_mode: str = "warn",  # "warn", "block", "force_change"
        notification_settings: dict[str, Any] | None = None,
        report_format: str = "json",  # "json", "pdf", "csv"
        include_historical_data: bool = False,
        anonymize_results: bool = True,
        dry_run: bool = False,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.user_id = user_id
        self.password = password
        self.password_hash = password_hash
        self.organization_id = organization_id
        self.password_policy = password_policy or PasswordPolicy()
        self.check_breaches = check_breaches
        self.breach_sources = breach_sources or [BreachSource.ALL_SOURCES]
        self.include_user_info = include_user_info
        self.analyze_patterns = analyze_patterns
        self.generate_recommendations = generate_recommendations
        self.batch_user_ids = batch_user_ids or []
        self.scan_depth = scan_depth
        self.policy_enforcement_mode = policy_enforcement_mode
        self.notification_settings = notification_settings or {}
        self.report_format = report_format
        self.include_historical_data = include_historical_data
        self.anonymize_results = anonymize_results
        self.dry_run = dry_run
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class PasswordSecurityCommandHandler(CommandHandler[PasswordSecurityCommand, PasswordSecurityResponse]):
    """Handler for password security operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        password_repository: IPasswordRepository,
        security_repository: ISecurityRepository,
        breach_repository: IBreachRepository,
        password_service: PasswordService,
        security_service: SecurityService,
        validation_service: ValidationService,
        breach_detection_service: BreachDetectionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._password_repository = password_repository
        self._security_repository = security_repository
        self._breach_repository = breach_repository
        self._password_service = password_service
        self._security_service = security_service
        self._validation_service = validation_service
        self._breach_detection_service = breach_detection_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_SECURITY_CHECK,
        resource_type="password_security",
        include_request=True,
        include_response=True
    )
    @validate_request(PasswordSecurityRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("security.password.analyze")
    async def handle(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """
        Handle password security operations.
        
        Supports multiple operations:
        - analyze_strength: Analyze password strength and security
        - check_policy_compliance: Check password against policy
        - detect_breaches: Check password against breach databases
        - scan_organization: Scan all organizational passwords
        - generate_secure: Generate secure password recommendations
        - audit_passwords: Audit password security across system
        - enforce_policy: Enforce password policy compliance
        - generate_report: Generate password security report
        
        Returns:
            PasswordSecurityResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == PasswordOperation.ANALYZE_STRENGTH:
                return await self._handle_strength_analysis(command)
            if command.operation_type == PasswordOperation.CHECK_POLICY_COMPLIANCE:
                return await self._handle_policy_compliance_check(command)
            if command.operation_type == PasswordOperation.DETECT_BREACHES:
                return await self._handle_breach_detection(command)
            if command.operation_type == PasswordOperation.SCAN_ORGANIZATION:
                return await self._handle_organization_scan(command)
            if command.operation_type == PasswordOperation.GENERATE_SECURE:
                return await self._handle_secure_generation(command)
            if command.operation_type == PasswordOperation.AUDIT_PASSWORDS:
                return await self._handle_password_audit(command)
            if command.operation_type == PasswordOperation.ENFORCE_POLICY:
                return await self._handle_policy_enforcement(command)
            if command.operation_type == PasswordOperation.GENERATE_REPORT:
                return await self._handle_report_generation(command)
            raise PasswordSecurityError(f"Unsupported operation type: {command.operation_type.value}")
    
    async def _handle_strength_analysis(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password strength analysis."""
        # 1. Validate input
        if not command.password and not command.password_hash:
            raise PasswordValidationError("Password or password hash is required for strength analysis")
        
        # 2. Load user context if provided
        user = None
        if command.user_id:
            user = await self._user_repository.get_by_id(command.user_id)
        
        # 3. Perform comprehensive password analysis
        analysis_result = await self._analyze_password_security(
            command.password,
            command.password_hash,
            user,
            command.password_policy,
            command.check_breaches,
            command.breach_sources,
            command.analyze_patterns
        )
        
        # 4. Generate recommendations if requested
        recommendations = []
        if command.generate_recommendations:
            recommendations = await self._generate_security_recommendations(
                analysis_result,
                command.password_policy,
                user
            )
        
        # 5. Check for security events that need attention
        security_events = await self._identify_security_events(analysis_result, command)
        
        # 6. Log analysis
        await self._log_password_analysis(analysis_result, user, command)
        
        # 7. Send notifications if configured
        if command.notification_settings and security_events:
            await self._send_security_notifications(
                analysis_result,
                security_events,
                user,
                command.notification_settings
            )
        
        # 8. Publish domain events
        if analysis_result.strength_level in [PasswordStrength.WEAK, PasswordStrength.VERY_WEAK]:
            await self._event_bus.publish(
                WeakPasswordDetected(
                    aggregate_id=user.id if user else UUID(),
                    user_id=user.id if user else None,
                    strength_score=analysis_result.strength_score,
                    strength_level=analysis_result.strength_level.value,
                    policy_violations=analysis_result.policy_violations,
                    breach_detected=analysis_result.breach_detected,
                    detected_by=command.initiated_by
                )
            )
        
        if analysis_result.breach_detected:
            await self._event_bus.publish(
                PasswordBreachDetected(
                    aggregate_id=user.id if user else UUID(),
                    user_id=user.id if user else None,
                    breach_sources=analysis_result.breach_sources,
                    password_hash=analysis_result.password_hash,
                    detected_by=command.initiated_by
                )
            )
        
        # 9. Commit transaction
        await self._unit_of_work.commit()
        
        # 10. Generate response
        return PasswordSecurityResponse(
            success=True,
            operation_type=command.operation_type.value,
            user_id=user.id if user else None,
            analysis_result=self._serialize_analysis_result(analysis_result, command.anonymize_results),
            recommendations=recommendations,
            security_events=security_events,
            policy_compliant=len(analysis_result.policy_violations) == 0,
            breach_detected=analysis_result.breach_detected,
            risk_level=self._calculate_password_risk_level(analysis_result),
            message="Password strength analysis completed"
        )
    
    async def _analyze_password_security(
        self,
        password: str | None,
        password_hash: str | None,
        user: User | None,
        policy: PasswordPolicy,
        check_breaches: bool,
        breach_sources: list[BreachSource],
        analyze_patterns: bool
    ) -> PasswordAnalysis:
        """Perform comprehensive password security analysis."""
        # Use password hash if password not provided
        if password:
            pwd_hash = self._password_service.hash_password(password)
        else:
            pwd_hash = password_hash
            password = None  # Don't store plaintext
        
        # 1. Calculate password strength
        strength_analysis = await self._calculate_password_strength(password, user)
        
        # 2. Check policy compliance
        policy_violations = await self._check_policy_violations(password, policy, user)
        
        # 3. Check for breaches if enabled
        breach_result = {"detected": False, "sources": []}
        if check_breaches:
            breach_result = await self._check_password_breaches(pwd_hash, breach_sources)
        
        # 4. Analyze patterns if requested
        pattern_analysis = {}
        if analyze_patterns and password:
            pattern_analysis = await self._analyze_password_patterns(password, user)
        
        # 5. Generate recommendations
        recommendations = await self._generate_improvement_recommendations(
            strength_analysis,
            policy_violations,
            breach_result,
            pattern_analysis
        )
        
        # 6. Estimate crack time
        crack_time = await self._estimate_crack_time(
            strength_analysis["entropy_bits"],
            strength_analysis["character_diversity"]
        )
        
        return PasswordAnalysis(
            password_hash=pwd_hash,
            strength_score=strength_analysis["score"],
            strength_level=strength_analysis["level"],
            policy_violations=policy_violations,
            breach_detected=breach_result["detected"],
            breach_sources=breach_result["sources"],
            entropy_bits=strength_analysis["entropy_bits"],
            character_diversity=strength_analysis["character_diversity"],
            pattern_analysis=pattern_analysis,
            recommendations=recommendations,
            estimated_crack_time=crack_time
        )
    
    async def _calculate_password_strength(self, password: str | None, user: User | None) -> dict[str, Any]:
        """Calculate password strength metrics."""
        if not password:
            return {
                "score": 0.0,
                "level": PasswordStrength.UNKNOWN,
                "entropy_bits": 0.0,
                "character_diversity": 0.0
            }
        
        # Calculate entropy
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        import math
        entropy_bits = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        # Calculate character diversity
        unique_chars = len(set(password))
        character_diversity = unique_chars / len(password) if len(password) > 0 else 0
        
        # Calculate base score from entropy
        base_score = min(entropy_bits / 60.0, 1.0)  # Normalize to 0-1
        
        # Adjust score based on various factors
        score_adjustments = 0
        
        # Length bonus/penalty
        if len(password) >= 12:
            score_adjustments += 0.1
        elif len(password) < 8:
            score_adjustments -= 0.2
        
        # Character diversity bonus
        if character_diversity > 0.7:
            score_adjustments += 0.1
        elif character_diversity < 0.4:
            score_adjustments -= 0.1
        
        # Pattern penalties
        if self._has_common_patterns(password):
            score_adjustments -= 0.15
        
        if self._has_repeated_characters(password):
            score_adjustments -= 0.1
        
        # Personal information penalty
        if user and self._contains_personal_info(password, user):
            score_adjustments -= 0.25
        
        final_score = max(0.0, min(1.0, base_score + score_adjustments))
        
        # Determine strength level
        if final_score >= 0.8:
            level = PasswordStrength.VERY_STRONG
        elif final_score >= 0.6:
            level = PasswordStrength.STRONG
        elif final_score >= 0.4:
            level = PasswordStrength.MEDIUM
        elif final_score >= 0.2:
            level = PasswordStrength.WEAK
        else:
            level = PasswordStrength.VERY_WEAK
        
        return {
            "score": final_score,
            "level": level,
            "entropy_bits": entropy_bits,
            "character_diversity": character_diversity
        }
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common password patterns."""
        common_patterns = [
            r'123',
            r'abc',
            r'qwerty',
            r'password',
            r'admin',
            r'(.)\1{2,}',  # Repeated characters
            r'(01|12|23|34|45|56|67|78|89|90)',  # Sequential numbers
        ]
        
        password_lower = password.lower()
        return any(re.search(pattern, password_lower) for pattern in common_patterns)
    
    def _has_repeated_characters(self, password: str, max_repeats: int = 3) -> bool:
        """Check for repeated characters."""
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count >= max_repeats:
                    return True
            else:
                count = 1
        return False
    
    def _contains_personal_info(self, password: str, user: User) -> bool:
        """Check if password contains personal information."""
        password_lower = password.lower()
        
        # Check username
        if user.username and user.username.lower() in password_lower:
            return True
        
        # Check email parts
        if user.email:
            email_parts = user.email.lower().split('@')[0]
            if email_parts in password_lower:
                return True
        
        # Check name parts
        if user.first_name and len(user.first_name) > 2:
            if user.first_name.lower() in password_lower:
                return True
        
        if user.last_name and len(user.last_name) > 2:
            if user.last_name.lower() in password_lower:
                return True
        
        return False
    
    async def _check_policy_violations(
        self,
        password: str | None,
        policy: PasswordPolicy,
        user: User | None
    ) -> list[str]:
        """Check password against policy requirements."""
        if not password:
            return ["Password is required"]
        
        violations = []
        
        # Length checks
        if len(password) < policy.min_length:
            violations.append(f"Password must be at least {policy.min_length} characters long")
        
        if len(password) > policy.max_length:
            violations.append(f"Password must not exceed {policy.max_length} characters")
        
        # Character requirements
        if policy.require_uppercase and not re.search(r'[A-Z]', password):
            violations.append("Password must contain at least one uppercase letter")
        
        if policy.require_lowercase and not re.search(r'[a-z]', password):
            violations.append("Password must contain at least one lowercase letter")
        
        if policy.require_numbers and not re.search(r'\d', password):
            violations.append("Password must contain at least one number")
        
        if policy.require_special_chars:
            special_chars = re.findall(r'[!@#$%^&*(),.?":{}|<>]', password)
            if len(special_chars) < policy.min_special_chars:
                violations.append(f"Password must contain at least {policy.min_special_chars} special character(s)")
        
        # Pattern checks
        if policy.prevent_repeated_chars and self._has_repeated_characters(password, policy.prevent_repeated_chars):
            violations.append(f"Password cannot have more than {policy.prevent_repeated_chars-1} repeated characters")
        
        if policy.prevent_sequential_chars and self._has_sequential_characters(password):
            violations.append("Password cannot contain sequential characters")
        
        if policy.prevent_keyboard_patterns and self._has_keyboard_patterns(password):
            violations.append("Password cannot contain keyboard patterns")
        
        if policy.prevent_common_passwords and await self._is_common_password(password):
            violations.append("Password is too common and cannot be used")
        
        if policy.prevent_dictionary_words and await self._contains_dictionary_words(password):
            violations.append("Password cannot contain dictionary words")
        
        if policy.prevent_personal_info and user and self._contains_personal_info(password, user):
            violations.append("Password cannot contain personal information")
        
        # Password history check
        if user and policy.password_history_count > 0:
            if await self._is_in_password_history(password, user.id, policy.password_history_count):
                violations.append(f"Password cannot be one of the last {policy.password_history_count} passwords")
        
        return violations
    
    def _has_sequential_characters(self, password: str) -> bool:
        """Check for sequential characters."""
        for i in range(len(password) - 2):
            chars = password[i:i+3]
            if all(ord(chars[j+1]) == ord(chars[j]) + 1 for j in range(len(chars)-1)):
                return True
            if all(ord(chars[j+1]) == ord(chars[j]) - 1 for j in range(len(chars)-1)):
                return True
        return False
    
    def _has_keyboard_patterns(self, password: str) -> bool:
        """Check for keyboard patterns."""
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'qwertyuiop',
            'asdfghjkl', 'zxcvbnm', '1234567890'
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    async def _is_common_password(self, password: str) -> bool:
        """Check if password is in common passwords list."""
        # This would check against a database of common passwords
        common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '123456789', 'password1'
        }
        return password.lower() in common_passwords
    
    async def _contains_dictionary_words(self, password: str) -> bool:
        """Check if password contains dictionary words."""
        # This would check against a dictionary API or database
        # For now, simple implementation
        common_words = {
            'password', 'computer', 'internet', 'security', 'admin',
            'user', 'login', 'access', 'system', 'network'
        }
        password_lower = password.lower()
        return any(word in password_lower for word in common_words if len(word) > 3)
    
    async def _is_in_password_history(self, password: str, user_id: UUID, history_count: int) -> bool:
        """Check if password is in user's password history."""
        self._password_service.hash_password(password)
        recent_passwords = await self._password_repository.get_recent_passwords(user_id, history_count)
        
        for historical_password in recent_passwords:
            if self._password_service.verify_password(password, historical_password.password_hash):
                return True
        
        return False
    
    async def _check_password_breaches(
        self,
        password_hash: str,
        breach_sources: list[BreachSource]
    ) -> dict[str, Any]:
        """Check password against breach databases."""
        breach_results = {
            "detected": False,
            "sources": []
        }
        
        for source in breach_sources:
            if source == BreachSource.ALL_SOURCES:
                # Check all available sources
                all_sources = [BreachSource.HAVEIBEENPWNED, BreachSource.INTERNAL_DATABASE]
                for src in all_sources:
                    result = await self._check_single_breach_source(password_hash, src)
                    if result["detected"]:
                        breach_results["detected"] = True
                        breach_results["sources"].append(src.value)
            else:
                result = await self._check_single_breach_source(password_hash, source)
                if result["detected"]:
                    breach_results["detected"] = True
                    breach_results["sources"].append(source.value)
        
        return breach_results
    
    async def _check_single_breach_source(self, password_hash: str, source: BreachSource) -> dict[str, Any]:
        """Check password against a single breach source."""
        try:
            if source == BreachSource.HAVEIBEENPWNED:
                return await self._breach_detection_service.check_haveibeenpwned(password_hash)
            if source == BreachSource.INTERNAL_DATABASE:
                return await self._breach_detection_service.check_internal_database(password_hash)
            if source == BreachSource.SECURITY_FEEDS:
                return await self._breach_detection_service.check_security_feeds(password_hash)
            return {"detected": False, "error": f"Unsupported breach source: {source.value}"}
        except Exception as e:
            return {"detected": False, "error": str(e)}
    
    async def _analyze_password_patterns(self, password: str, user: User | None) -> dict[str, Any]:
        """Analyze password patterns and characteristics."""
        analysis = {
            "length_analysis": {
                "total_length": len(password),
                "unique_characters": len(set(password)),
                "character_frequency": {}
            },
            "character_classes": {
                "uppercase_count": len(re.findall(r'[A-Z]', password)),
                "lowercase_count": len(re.findall(r'[a-z]', password)),
                "digit_count": len(re.findall(r'\d', password)),
                "special_char_count": len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password)),
                "space_count": password.count(' ')
            },
            "pattern_detection": {
                "has_repeated_chars": self._has_repeated_characters(password),
                "has_sequential_chars": self._has_sequential_characters(password),
                "has_keyboard_patterns": self._has_keyboard_patterns(password),
                "has_common_patterns": self._has_common_patterns(password)
            },
            "structure_analysis": {
                "starts_with_capital": password[0].isupper() if password else False,
                "ends_with_number": password[-1].isdigit() if password else False,
                "contains_years": bool(re.search(r'19\d{2}|20\d{2}', password)),
                "contains_dates": bool(re.search(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', password))
            }
        }
        
        # Character frequency analysis
        for char in password:
            analysis["length_analysis"]["character_frequency"][char] = analysis["length_analysis"]["character_frequency"].get(char, 0) + 1
        
        # Personal information analysis
        if user:
            analysis["personal_info_risks"] = {
                "contains_username": user.username.lower() in password.lower() if user.username else False,
                "contains_email_prefix": user.email.split('@')[0].lower() in password.lower() if user.email else False,
                "contains_first_name": user.first_name.lower() in password.lower() if user.first_name else False,
                "contains_last_name": user.last_name.lower() in password.lower() if user.last_name else False
            }
        
        return analysis
    
    async def _generate_improvement_recommendations(
        self,
        strength_analysis: dict[str, Any],
        policy_violations: list[str],
        breach_result: dict[str, Any],
        pattern_analysis: dict[str, Any]
    ) -> list[str]:
        """Generate recommendations for password improvement."""
        recommendations = []
        
        # Strength-based recommendations
        if strength_analysis["score"] < 0.6:
            recommendations.append("Increase password length to at least 12 characters")
            recommendations.append("Use a mix of uppercase, lowercase, numbers, and special characters")
        
        if strength_analysis["character_diversity"] < 0.5:
            recommendations.append("Increase character diversity by using more unique characters")
        
        if strength_analysis["entropy_bits"] < 40:
            recommendations.append("Add more randomness to increase password entropy")
        
        # Policy violation recommendations
        if policy_violations:
            recommendations.append("Address policy violations:")
            for violation in policy_violations[:3]:  # Limit to top 3
                recommendations.append(f"  - {violation}")
        
        # Breach-based recommendations
        if breach_result["detected"]:
            recommendations.append("CRITICAL: Password found in data breaches - change immediately")
            recommendations.append("Use a unique password that hasn't been compromised")
        
        # Pattern-based recommendations
        if pattern_analysis:
            if pattern_analysis.get("pattern_detection", {}).get("has_repeated_chars"):
                recommendations.append("Avoid repeated characters")
            
            if pattern_analysis.get("pattern_detection", {}).get("has_sequential_chars"):
                recommendations.append("Avoid sequential characters like 'abc' or '123'")
            
            if pattern_analysis.get("pattern_detection", {}).get("has_keyboard_patterns"):
                recommendations.append("Avoid keyboard patterns like 'qwerty'")
            
            if pattern_analysis.get("personal_info_risks"):
                personal_risks = pattern_analysis["personal_info_risks"]
                if any(personal_risks.values()):
                    recommendations.append("Remove personal information from password")
        
        # General security recommendations
        recommendations.extend([
            "Consider using a password manager to generate and store strong passwords",
            "Enable two-factor authentication for additional security",
            "Regularly update passwords, especially for critical accounts"
        ])
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    async def _estimate_crack_time(self, entropy_bits: float, character_diversity: float) -> str:
        """Estimate time to crack password."""
        if entropy_bits == 0:
            return "Instantly"
        
        # Assume 1 billion guesses per second (modern GPU)
        guesses_per_second = 1_000_000_000
        
        # Calculate average number of guesses needed
        total_combinations = 2 ** entropy_bits
        avg_guesses = total_combinations / 2
        
        # Adjust for character diversity
        diversity_factor = max(0.5, character_diversity)
        adjusted_guesses = avg_guesses * diversity_factor
        
        crack_time_seconds = adjusted_guesses / guesses_per_second
        
        # Convert to human-readable format
        if crack_time_seconds < 1:
            return "Less than 1 second"
        if crack_time_seconds < 60:
            return f"{crack_time_seconds:.1f} seconds"
        if crack_time_seconds < 3600:
            return f"{crack_time_seconds/60:.1f} minutes"
        if crack_time_seconds < 86400:
            return f"{crack_time_seconds/3600:.1f} hours"
        if crack_time_seconds < 2592000:
            return f"{crack_time_seconds/86400:.1f} days"
        if crack_time_seconds < 31536000:
            return f"{crack_time_seconds/2592000:.1f} months"
        years = crack_time_seconds / 31536000
        if years > 1_000_000:
            return "Millions of years"
        if years > 1_000:
            return f"{years/1000:.1f}K years"
        return f"{years:.1f} years"
    
    def _calculate_password_risk_level(self, analysis: PasswordAnalysis) -> str:
        """Calculate overall risk level for password."""
        risk_score = 0
        
        # Strength-based risk
        if analysis.strength_level == PasswordStrength.VERY_WEAK:
            risk_score += 40
        elif analysis.strength_level == PasswordStrength.WEAK:
            risk_score += 30
        elif analysis.strength_level == PasswordStrength.MEDIUM:
            risk_score += 20
        elif analysis.strength_level == PasswordStrength.STRONG:
            risk_score += 10
        
        # Policy violations
        risk_score += len(analysis.policy_violations) * 5
        
        # Breach detection
        if analysis.breach_detected:
            risk_score += 50
        
        # Pattern analysis
        if analysis.pattern_analysis:
            pattern_risks = analysis.pattern_analysis.get("pattern_detection", {})
            if pattern_risks.get("has_repeated_chars"):
                risk_score += 10
            if pattern_risks.get("has_sequential_chars"):
                risk_score += 10
            if pattern_risks.get("has_keyboard_patterns"):
                risk_score += 15
            if pattern_risks.get("has_common_patterns"):
                risk_score += 15
        
        # Determine risk level
        if risk_score >= 70:
            return RiskLevel.CRITICAL.value
        if risk_score >= 50:
            return RiskLevel.HIGH.value
        if risk_score >= 30:
            return RiskLevel.MEDIUM.value
        return RiskLevel.LOW.value
    
    def _serialize_analysis_result(self, analysis: PasswordAnalysis, anonymize: bool) -> dict[str, Any]:
        """Serialize analysis result for response."""
        result = {
            "strength_score": analysis.strength_score,
            "strength_level": analysis.strength_level.value,
            "policy_violations": analysis.policy_violations,
            "breach_detected": analysis.breach_detected,
            "breach_sources": analysis.breach_sources,
            "entropy_bits": analysis.entropy_bits,
            "character_diversity": analysis.character_diversity,
            "recommendations": analysis.recommendations,
            "estimated_crack_time": analysis.estimated_crack_time
        }
        
        if not anonymize:
            result["password_hash"] = analysis.password_hash
            result["pattern_analysis"] = analysis.pattern_analysis
        
        return result
    
    async def _generate_security_recommendations(
        self,
        analysis: PasswordAnalysis,
        policy: PasswordPolicy,
        user: User | None
    ) -> list[str]:
        """Generate security recommendations based on analysis."""
        return analysis.recommendations
    
    async def _identify_security_events(
        self,
        analysis: PasswordAnalysis,
        command: PasswordSecurityCommand
    ) -> list[dict[str, Any]]:
        """Identify security events that need attention."""
        events = []
        
        if analysis.breach_detected:
            events.append({
                "type": SecurityEventType.PASSWORD_BREACH_DETECTED.value,
                "severity": "critical",
                "description": f"Password found in {len(analysis.breach_sources)} breach database(s)",
                "breach_sources": analysis.breach_sources
            })
        
        if analysis.strength_level in [PasswordStrength.VERY_WEAK, PasswordStrength.WEAK]:
            events.append({
                "type": SecurityEventType.WEAK_PASSWORD_DETECTED.value,
                "severity": "high" if analysis.strength_level == PasswordStrength.VERY_WEAK else "medium",
                "description": f"Password strength is {analysis.strength_level.value}",
                "strength_score": analysis.strength_score
            })
        
        if len(analysis.policy_violations) > 0:
            events.append({
                "type": SecurityEventType.POLICY_VIOLATION.value,
                "severity": "medium",
                "description": f"Password violates {len(analysis.policy_violations)} policy requirement(s)",
                "violations": analysis.policy_violations
            })
        
        return events
    
    async def _send_security_notifications(
        self,
        analysis: PasswordAnalysis,
        security_events: list[dict[str, Any]],
        user: User | None,
        notification_settings: dict[str, Any]
    ) -> None:
        """Send security notifications based on events."""
        if not user or not notification_settings.get("enabled", False):
            return
        
        critical_events = [e for e in security_events if e.get("severity") == "critical"]
        if critical_events and notification_settings.get("immediate_alerts", False):
            # Send immediate notification for critical events
            await self._notification_service.create_notification(
                NotificationContext(
                    notification_id=UUID(),
                    recipient_id=user.id,
                    notification_type=NotificationType.SECURITY_ALERT,
                    channel="email",
                    template_id="password_security_alert",
                    template_data={
                        "username": user.username,
                        "events": critical_events,
                        "analysis_summary": {
                            "strength_level": analysis.strength_level.value,
                            "breach_detected": analysis.breach_detected,
                            "policy_violations_count": len(analysis.policy_violations)
                        }
                    },
                    priority="critical"
                )
            )
    
    async def _log_password_analysis(
        self,
        analysis: PasswordAnalysis,
        user: User | None,
        command: PasswordSecurityCommand
    ) -> None:
        """Log password analysis operation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.PASSWORD_ANALYZED,
                actor_id=command.initiated_by,
                resource_type="password_security",
                resource_id=user.id if user else None,
                details={
                    "operation_type": command.operation_type.value,
                    "strength_level": analysis.strength_level.value,
                    "strength_score": analysis.strength_score,
                    "policy_violations_count": len(analysis.policy_violations),
                    "breach_detected": analysis.breach_detected,
                    "breach_sources": analysis.breach_sources,
                    "entropy_bits": analysis.entropy_bits,
                    "character_diversity": analysis.character_diversity,
                    "check_breaches": command.check_breaches,
                    "analyze_patterns": command.analyze_patterns
                },
                risk_level=self._calculate_password_risk_level(analysis)
            )
        )
    
    # Placeholder implementations for other operations
    async def _handle_policy_compliance_check(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password policy compliance check."""
        raise NotImplementedError("Policy compliance check not yet implemented")
    
    async def _handle_breach_detection(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password breach detection."""
        raise NotImplementedError("Breach detection not yet implemented")
    
    async def _handle_organization_scan(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle organization-wide password scan."""
        raise NotImplementedError("Organization scan not yet implemented")
    
    async def _handle_secure_generation(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle secure password generation."""
        raise NotImplementedError("Secure password generation not yet implemented")
    
    async def _handle_password_audit(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password audit."""
        raise NotImplementedError("Password audit not yet implemented")
    
    async def _handle_policy_enforcement(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password policy enforcement."""
        raise NotImplementedError("Policy enforcement not yet implemented")
    
    async def _handle_report_generation(self, command: PasswordSecurityCommand) -> PasswordSecurityResponse:
        """Handle password security report generation."""
        raise NotImplementedError("Report generation not yet implemented")