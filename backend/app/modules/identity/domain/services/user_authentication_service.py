"""Basic implementation of UserAuthenticationService."""

import re
from datetime import datetime, timedelta
from typing import Any

from ..aggregates.user import User
from ..interfaces.services.user_authentication_service import (
    AuthenticationContext,
    IUserAuthenticationService,
    LoginAttemptResult,
    PasswordValidationResult,
    SecurityAssessmentResult,
)


class UserAuthenticationService(IUserAuthenticationService):
    """Basic implementation of user authentication service.
    
    This service implements core authentication logic that was extracted
    from the User aggregate to follow DDD principles.
    """
    
    def validate_password_policy(self, password: str, user: User) -> PasswordValidationResult:
        """Validate password against security policies."""
        errors = []
        suggestions = []
        
        # Basic password validation
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
            suggestions.append("Use a longer password")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
            suggestions.append("Add numbers")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
            suggestions.append("Add special characters")
        
        # Check for common passwords
        common_passwords = ['password', '123456', 'qwerty', 'abc123', 'password123']
        if password.lower() in common_passwords:
            errors.append("Password is too common")
            suggestions.append("Use a more unique password")
        
        # Check if password contains user information
        if user.username.value.lower() in password.lower():
            errors.append("Password should not contain your username")
            suggestions.append("Avoid using personal information")
        
        # Calculate strength score
        strength_score = self.evaluate_password_strength(password)
        
        return PasswordValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            strength_score=strength_score,
            meets_policy=len(errors) == 0,
            suggestions=suggestions
        )
    
    def process_login_attempt(self, user: User, success: bool, context: AuthenticationContext) -> LoginAttemptResult:
        """Process a login attempt and determine security actions."""
        if success:
            return LoginAttemptResult(
                success=True,
                should_lock_account=False,
                lock_duration=None,
                remaining_attempts=5,
                risk_score=0.1,
                metadata={"success": True}
            )
        
        # Calculate remaining attempts
        remaining_attempts = max(0, 5 - user.failed_login_count - 1)
        
        # Determine if account should be locked
        should_lock = user.failed_login_count + 1 >= 5
        
        # Calculate lock duration with exponential backoff
        lock_duration = self.calculate_lock_duration(user, user.failed_login_count + 1)
        
        # Calculate risk score based on various factors
        risk_score = min(1.0, 0.2 + (user.failed_login_count * 0.15))
        
        return LoginAttemptResult(
            success=False,
            should_lock_account=should_lock,
            lock_duration=lock_duration if should_lock else None,
            remaining_attempts=remaining_attempts,
            risk_score=risk_score,
            metadata={"attempt_count": user.failed_login_count + 1}
        )
    
    def assess_authentication_risk(self, user: User, context: AuthenticationContext) -> SecurityAssessmentResult:
        """Assess the risk level of an authentication attempt."""
        risk_factors = []
        risk_score = 0.0
        
        # Check account age
        if user.get_account_age_days() < 7:
            risk_factors.append("New account")
            risk_score += 0.2
        
        # Check failed login attempts
        if user.failed_login_count > 0:
            risk_factors.append(f"Recent failed login attempts: {user.failed_login_count}")
            risk_score += user.failed_login_count * 0.1
        
        # Check if account is locked
        if user.is_locked():
            risk_factors.append("Account currently locked")
            risk_score += 0.5
        
        # Check MFA status
        if not user.mfa_enabled:
            risk_factors.append("Multi-factor authentication not enabled")
            risk_score += 0.3
        
        # Check email verification
        if not user.email_verified:
            risk_factors.append("Email not verified")
            risk_score += 0.2
        
        # Normalize risk score
        risk_score = min(1.0, risk_score)
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        recommendations = []
        if not user.mfa_enabled:
            recommendations.append("Enable multi-factor authentication")
        if not user.email_verified:
            recommendations.append("Verify email address")
        if user.failed_login_count > 0:
            recommendations.append("Monitor for suspicious activity")
        
        return SecurityAssessmentResult(
            risk_level=risk_level,
            risk_score=risk_score,
            factors=risk_factors,
            recommendations=recommendations,
            requires_additional_verification=risk_score >= 0.6
        )
    
    def should_require_mfa(self, user: User, context: AuthenticationContext) -> bool:
        """Determine if MFA should be required for this authentication."""
        # Always require MFA if enabled
        if user.mfa_enabled:
            return True
        
        # Require MFA for high-risk situations
        risk_assessment = self.assess_authentication_risk(user, context)
        return risk_assessment.risk_level in ["high", "critical"]
    
    def calculate_lock_duration(self, user: User, failed_attempts: int) -> timedelta:
        """Calculate how long an account should be locked."""
        # Exponential backoff: 15 minutes, 30 minutes, 1 hour, 2 hours, 4 hours
        base_minutes = 15
        multiplier = 2 ** (failed_attempts - 5)  # Start exponential after 5 attempts
        
        minutes = min(base_minutes * multiplier, 240)  # Cap at 4 hours
        return timedelta(minutes=minutes)
    
    def should_unlock_account(self, user: User, unlock_context: AuthenticationContext) -> bool:
        """Determine if an account should be unlocked."""
        # Allow unlock if lock period has expired
        if user.locked_until and datetime.now() >= user.locked_until:
            return True
        
        # Additional business logic can be added here
        return False
    
    def evaluate_password_strength(self, password: str) -> float:
        """Evaluate password strength on a scale of 0.0 to 1.0."""
        score = 0.0
        
        # Length score
        if len(password) >= 8:
            score += 0.2
        if len(password) >= 12:
            score += 0.1
        if len(password) >= 16:
            score += 0.1
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 0.1
        if re.search(r'[A-Z]', password):
            score += 0.1
        if re.search(r'\d', password):
            score += 0.1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 0.2
        
        # Complexity bonus
        if len(set(password)) > len(password) * 0.7:  # Good character diversity
            score += 0.1
        
        return min(1.0, score)
    
    def get_security_recommendations(self, user: User) -> list[str]:
        """Get security recommendations for a user."""
        recommendations = []
        
        if not user.mfa_enabled:
            recommendations.append("Enable multi-factor authentication for better security")
        
        if not user.email_verified:
            recommendations.append("Verify your email address to improve account security")
        
        if user.failed_login_count > 0:
            recommendations.append("Review recent login activity for suspicious attempts")
        
        # Check password age
        if user.password_changed_at:
            days_since_change = (datetime.now() - user.password_changed_at).days
            if days_since_change > 90:
                recommendations.append("Consider changing your password (last changed over 90 days ago)")
        
        return recommendations
    
    def should_regenerate_security_stamp(self, user: User, operation: str) -> bool:
        """Determine if security stamp should be regenerated."""
        # Always regenerate for these critical operations
        critical_operations = {"password_change", "email_change", "mfa_enable", "mfa_disable"}
        return operation in critical_operations
    
    def validate_account_status(self, user: User) -> tuple[bool, str]:
        """Validate if account is in a valid state for authentication."""
        if user.status.value == "DELETED":
            return False, "Account has been deleted"
        
        if user.is_locked():
            return False, "Account is currently locked"
        
        if user.is_suspended():
            return False, "Account is currently suspended"
        
        if user.status.value != "ACTIVE":
            return False, f"Account status is {user.status.value}"
        
        return True, "Account is valid for authentication"
    
    def track_security_event(self, user: User, event_type: str, context: AuthenticationContext) -> None:
        """Track security-related events for monitoring."""
        # In a real implementation, this would log to a security monitoring system
        # For now, we'll just store basic information
        print(f"Security event tracked: {event_type} for user {user.id}")
    
    def detect_anomalous_behavior(self, user: User, context: AuthenticationContext) -> bool:
        """Detect if authentication attempt shows anomalous behavior."""
        # Basic anomaly detection
        if user.failed_login_count > 3:
            return True
        
        # In a real implementation, this would check:
        # - Geographic location changes
        # - Device fingerprint changes
        # - Time-based patterns
        # - Behavioral patterns
        
        return False
    
    def get_authentication_history(self, user: User, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent authentication history for a user."""
        history = []
        
        if user.last_login:
            history.append({
                "timestamp": user.last_login.isoformat(),
                "event": "successful_login",
                "ip_address": "unknown",
                "user_agent": "unknown"
            })
        
        if user.last_failed_login:
            history.append({
                "timestamp": user.last_failed_login.isoformat(),
                "event": "failed_login",
                "ip_address": "unknown",
                "user_agent": "unknown"
            })
        
        # Sort by timestamp descending
        history.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return history[:limit]