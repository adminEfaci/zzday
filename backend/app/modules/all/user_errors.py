"""
User Entity Errors

Domain-specific exceptions for user-related business rules and constraints.
"""

from datetime import datetime
from uuid import UUID

from ...errors import AuthenticationError, IdentityDomainError


class UserNotFoundError(IdentityDomainError):
    """User does not exist."""
    
    def __init__(self, user_id: UUID | None = None, username: str | None = None, email: str | None = None):
        identifier = user_id or username or email
        super().__init__(
            f"User not found: {identifier}",
            code="USER_NOT_FOUND"
        )
        if user_id:
            self.details["user_id"] = str(user_id)
        if username:
            self.details["username"] = username
        if email:
            self.details["email"] = email


class UserAlreadyExistsError(IdentityDomainError):
    """User with given email or username already exists."""
    
    def __init__(self, field: str, value: str):
        super().__init__(
            f"User with {field} '{value}' already exists",
            code="USER_ALREADY_EXISTS"
        )
        self.details["field"] = field
        self.details["value"] = value


class AccountInactiveError(AuthenticationError):
    """Raised when attempting to use an inactive account."""
    
    def __init__(self, user_id: UUID, reason: str | None = None):
        message = "Account is inactive"
        if reason:
            message += f": {reason}"
        super().__init__(
            message,
            code="ACCOUNT_INACTIVE",
            user_message="Your account is inactive. Please contact support for assistance."
        )
        self.details["user_id"] = str(user_id)
        if reason:
            self.details["reason"] = reason


class UsernameAlreadyExistsError(IdentityDomainError):
    """Raised when username already exists."""
    
    def __init__(self, username: str):
        super().__init__(
            f"Username '{username}' is already taken",
            code="USERNAME_ALREADY_EXISTS",
            user_message="This username is already taken. Please choose another one."
        )
        self.details["username"] = username


class InvalidCredentialsError(AuthenticationError):
    """Invalid username or password."""
    
    def __init__(self):
        super().__init__(
            "Invalid credentials provided",
            code="INVALID_CREDENTIALS",
            user_message="Invalid username or password"
        )


class AccountLockedError(AuthenticationError):
    """Account is locked due to security reasons."""
    
    def __init__(self, locked_until: datetime | None = None, reason: str | None = None):
        message = "Account is locked"
        user_message = "Your account has been locked for security reasons"
        
        if locked_until:
            message += f" until {locked_until.isoformat()}"
            user_message += f" until {locked_until.strftime('%Y-%m-%d %H:%M UTC')}"
        
        super().__init__(
            message,
            code="ACCOUNT_LOCKED",
            user_message=user_message
        )
        
        if locked_until:
            self.details["locked_until"] = locked_until.isoformat()
        if reason:
            self.details["reason"] = reason


class AccountSuspendedError(AuthenticationError):
    """Account is suspended."""
    
    def __init__(self, reason: str, suspended_until: datetime | None = None):
        message = f"Account suspended: {reason}"
        super().__init__(
            message,
            code="ACCOUNT_SUSPENDED",
            user_message="Your account has been suspended. Please contact support."
        )
        self.details["reason"] = reason
        if suspended_until:
            self.details["suspended_until"] = suspended_until.isoformat()


class EmailNotVerifiedError(AuthenticationError):
    """Email address not verified."""
    
    def __init__(self):
        super().__init__(
            "Email address not verified",
            code="EMAIL_NOT_VERIFIED",
            user_message="Please verify your email address before continuing"
        )


class PasswordExpiredError(AuthenticationError):
    """Password has expired."""
    
    def __init__(self, expired_at: datetime):
        super().__init__(
            f"Password expired on {expired_at.isoformat()}",
            code="PASSWORD_EXPIRED",
            user_message="Your password has expired. Please reset your password."
        )
        self.details["expired_at"] = expired_at.isoformat()


class WeakPasswordError(IdentityDomainError):
    """Password does not meet security requirements."""
    
    def __init__(self, violations: list[str]):
        super().__init__(
            "Password does not meet security requirements",
            code="WEAK_PASSWORD",
            user_message="Password does not meet security requirements"
        )
        self.details["violations"] = violations


class InvalidMFACodeError(AuthenticationError):
    """Invalid MFA code provided."""
    
    def __init__(self):
        super().__init__(
            "Invalid MFA code",
            code="INVALID_MFA_CODE",
            user_message="Invalid verification code. Please try again."
        )


class MFARequiredError(AuthenticationError):
    """MFA is required for this action."""
    
    def __init__(self, mfa_methods: list[str]):
        super().__init__(
            "Multi-factor authentication required",
            code="MFA_REQUIRED"
        )
        self.details["available_methods"] = mfa_methods


class TooManyLoginAttemptsError(AuthenticationError):
    """Too many failed login attempts."""
    
    def __init__(self, retry_after: datetime):
        retry_in = int((retry_after - datetime.utcnow()).total_seconds())
        super().__init__(
            "Too many failed login attempts",
            code="TOO_MANY_LOGIN_ATTEMPTS",
            user_message=f"Too many failed login attempts. Please try again in {retry_in} seconds."
        )
        self.details["retry_after"] = retry_after.isoformat()
        self.details["retry_in_seconds"] = retry_in


class PasswordPolicyViolationError(IdentityDomainError):
    """Password violates policy requirements."""
    
    def __init__(self, violations: list[str]):
        super().__init__(
            f"Password policy violations: {', '.join(violations)}",
            code="PASSWORD_POLICY_VIOLATION",
            user_message="Password does not meet security requirements"
        )
        self.details["violations"] = violations


class InvalidTokenError(AuthenticationError):
    """Invalid or malformed token."""
    
    def __init__(self, message: str = "Invalid token"):
        super().__init__(
            message,
            code="INVALID_TOKEN",
            user_message="The provided token is invalid or has expired"
        )


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(
            message,
            code="TOKEN_EXPIRED",
            user_message="The token has expired. Please request a new one."
        )


# Export all errors (alphabetically sorted)
__all__ = [
    'AccountInactiveError',
    'AccountLockedError',
    'AccountSuspendedError',
    'EmailNotVerifiedError',
    'InvalidCredentialsError',
    'InvalidMFACodeError',
    'InvalidTokenError',
    'MFARequiredError',
    'PasswordExpiredError',
    'PasswordPolicyViolationError',
    'TokenExpiredError',
    'TooManyLoginAttemptsError',
    'UserAlreadyExistsError',
    'UserNotFoundError',
    'UsernameAlreadyExistsError',
    'WeakPasswordError'
]