"""
Password Domain Service

Handles password management including validation, history, and reset flows.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from app.core.security import hash_password, verify_password

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...constants import PolicyConstants, SecurityLimits
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


class PasswordService:
    """Domain service for password operations."""
    
    @staticmethod
    def validate_password_policy(password: str, user: User | None = None) -> list[str]:
        """
        Validate password against policy.
        
        Returns list of policy violations (empty if valid).
        """
        violations = []
        policy = PolicyConstants.PASSWORD_POLICY_CONSTANTS
        
        # Length check
        if len(password) < policy["MIN_LENGTH"]:
            violations.append(f"Password must be at least {policy['MIN_LENGTH']} characters")
        
        if len(password) > policy["MAX_LENGTH"]:
            violations.append(f"Password must not exceed {policy['MAX_LENGTH']} characters")
        
        # Complexity checks
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
        
        # Check against common passwords
        if password.lower() in policy["COMMON_PASSWORDS"]:
            violations.append("Password is too common. Please choose a more unique password")
        
        # User-specific checks
        if user:
            # Check similarity to username/email
            username = user.username.value.lower()
            email_local = user.email.value.split('@')[0].lower()
            
            if password.lower() == username or password.lower() == email_local:
                violations.append("Password cannot be the same as username or email")
            
            # Check if contains username
            if len(username) > 3 and username in password.lower():
                violations.append("Password cannot contain your username")
        
        return violations
    
    @staticmethod
    def change_password(
        user: User,
        current_password: str,
        new_password: str,
        changed_by: UUID | None = None
    ) -> None:
        """
        Change user password with proper validation and security measures.
        """
        # Ensure account is active
        if user.status != user.UserStatus.ACTIVE:
            raise AccountInactiveError()
        
        # Verify current password (unless admin reset)
        is_self_change = changed_by is None or changed_by == user.id
        if is_self_change and not verify_password(current_password, user.password_hash):
            raise InvalidCredentialsError()
        
        # Validate new password against policy
        violations = PasswordService.validate_password_policy(new_password, user)
        if violations:
            raise PasswordPolicyViolationError(violations)
        
        # Check password history
        if PasswordService._is_password_in_history(user, new_password):
            raise PasswordPolicyViolationError([
                f"Password was used recently. Last {SecurityLimits.PASSWORD_HISTORY_COUNT} passwords cannot be reused"
            ])
        
        # Update password
        PasswordService._add_password_to_history(user, user.password_hash)
        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)
        user.require_password_change = False
        user._regenerate_security_stamp()
        user.updated_at = datetime.now(UTC)
        
        # Record domain event
        user.add_domain_event(UserPasswordChanged(
            user_id=user.id,
            changed_by=changed_by or user.id,
            sessions_invalidated=True
        ))
    
    @staticmethod
    def _is_password_in_history(user: User, password: str) -> bool:
        """Check if password was used recently."""
        # Check against recent password hashes
        recent_count = min(len(user._password_history), SecurityLimits.PASSWORD_HISTORY_COUNT)
        recent_hashes = user._password_history[-recent_count:] if recent_count > 0 else []
        
        for password_hash in recent_hashes:
            if verify_password(password, password_hash):
                return True
        
        # Also check current password
        return verify_password(password, user.password_hash)
    
    @staticmethod
    def _add_password_to_history(user: User, password_hash: str) -> None:
        """Add password hash to history, maintaining size limit."""
        user._password_history.append(password_hash)
        
        # Keep only the last N passwords
        max_history = SecurityLimits.PASSWORD_HISTORY_COUNT
        if len(user._password_history) > max_history:
            user._password_history = user._password_history[-max_history:]
    
    @staticmethod
    def request_password_reset(
        user: User,
        ip_address: str,
        user_agent: str
    ) -> str:
        """Request password reset token."""
        # Generate reset token
        token = secrets.token_urlsafe(32)
        user.password_reset_token = hashlib.sha256(token.encode()).hexdigest()
        user.password_reset_token_expires = datetime.now(UTC) + timedelta(hours=1)
        user.updated_at = datetime.now(UTC)
        
        user.add_domain_event(PasswordResetRequested(
            user_id=user.id,
            reset_token=user.password_reset_token,  # Store hash in event
            expires_at=user.password_reset_token_expires,
            requested_ip=ip_address,
            requested_user_agent=user_agent
        ))
        
        return token  # Return unhashed token to send to user
    
    @staticmethod
    def reset_password_with_token(
        user: User,
        token: str,
        new_password: str
    ) -> None:
        """Reset password using token."""
        if not user.password_reset_token:
            raise InvalidTokenError("No password reset pending")
        
        # Hash the provided token and compare
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if user.password_reset_token != token_hash:
            raise InvalidTokenError("Invalid reset token")
        
        if user.password_reset_token_expires < datetime.now(UTC):
            raise TokenExpiredError("Reset token has expired")
        
        # Reset password without requiring current password
        PasswordService.change_password(user, "", new_password, changed_by=user.id)
        
        # Clear reset token
        user.password_reset_token = None
        user.password_reset_token_expires = None
    
    @staticmethod
    def force_password_change(user: User) -> None:
        """Force password change on next login."""
        user.require_password_change = True
        user.updated_at = datetime.now(UTC)
    
    @staticmethod
    def get_password_age_days(user: User) -> int:
        """Get password age in days."""
        if not user.password_changed_at:
            return user.get_account_age_days()
        return (datetime.now(UTC) - user.password_changed_at).days
    
    @staticmethod
    def is_password_expired(user: User, max_age_days: int = 90) -> bool:
        """Check if password has expired."""
        return PasswordService.get_password_age_days(user) > max_age_days
    
    @staticmethod
    def requires_password_change(user: User) -> bool:
        """Check if user must change password."""
        return (
            user.require_password_change or
            PasswordService.get_password_age_days(user) > PolicyConstants.PASSWORD_POLICY_CONSTANTS["MAX_AGE"].days
        )