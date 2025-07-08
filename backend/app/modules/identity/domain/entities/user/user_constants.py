"""
User Entity Constants

Business constants specific to user operations, authentication, and profile management.
"""

from datetime import timedelta


class LoginLimits:
    """Login attempt limits and timeouts."""
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    RATE_LIMIT_WINDOW = timedelta(minutes=1)
    MAX_REQUESTS_PER_WINDOW = 10
    PROGRESSIVE_DELAY_BASE = 2  # seconds
    MAX_PROGRESSIVE_DELAY = 300  # 5 minutes


class ContactLimits:
    """Emergency contact limits."""
    MAX_EMERGENCY_CONTACTS = 5
    MIN_EMERGENCY_CONTACTS = 1
    VERIFICATION_CODE_EXPIRY = timedelta(minutes=10)
    MAX_VERIFICATION_ATTEMPTS = 3


class ProfileLimits:
    """User profile limits."""
    BIO_MAX_LENGTH = 500
    DISPLAY_NAME_MAX_LENGTH = 100
    AVATAR_MAX_SIZE_MB = 5
    CUSTOM_FIELDS_LIMIT = 20
    MAX_SKILLS = 20
    MAX_CERTIFICATIONS = 10
    JOB_TITLE_MAX_LENGTH = 100
    PHONE_NUMBER_MIN_LENGTH = 10
    PHONE_NUMBER_MAX_LENGTH = 15


class PasswordPolicy:
    """Password policy constants."""
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    HISTORY_LIMIT = 24
    MIN_AGE = timedelta(hours=1)
    MAX_AGE = timedelta(days=90)
    COMPLEXITY_SCORE_THRESHOLD = 0.6
    
    # Enhanced validation rules
    MIN_UNIQUE_CHARS = 4
    MAX_REPEATED_CHARS = 3
    FORBIDDEN_PATTERNS = [
        "password", "123456", "qwerty", "admin", "user",
        "login", "welcome", "secret", "default"
    ]
    REQUIRE_NON_SEQUENTIAL = True
    
    @classmethod
    def validate_complexity(cls, password: str) -> tuple[bool, list[str]]:
        """Validate password complexity and return violations."""
        violations = []
        
        if len(password) < cls.MIN_LENGTH:
            violations.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        
        if len(password) > cls.MAX_LENGTH:
            violations.append(f"Password cannot exceed {cls.MAX_LENGTH} characters")
        
        if cls.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            violations.append("Password must contain at least one uppercase letter")
        
        if cls.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            violations.append("Password must contain at least one lowercase letter")
        
        if cls.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            violations.append("Password must contain at least one digit")
        
        if cls.REQUIRE_SPECIAL_CHARS and not any(c in cls.SPECIAL_CHARS for c in password):
            violations.append("Password must contain at least one special character")
        
        # Check for forbidden patterns
        password_lower = password.lower()
        for pattern in cls.FORBIDDEN_PATTERNS:
            if pattern in password_lower:
                violations.append(f"Password cannot contain common pattern: {pattern}")
        
        # Check character diversity
        unique_chars = len(set(password))
        if unique_chars < cls.MIN_UNIQUE_CHARS:
            violations.append(f"Password must contain at least {cls.MIN_UNIQUE_CHARS} unique characters")
        
        # Check for excessive repetition
        for i in range(len(password) - cls.MAX_REPEATED_CHARS):
            if password[i] == password[i + 1] == password[i + 2]:
                violations.append(f"Password cannot have more than {cls.MAX_REPEATED_CHARS} consecutive identical characters")
                break
        
        return len(violations) == 0, violations


class AccountLockoutPolicy:
    """Account lockout policy constants."""
    MAX_FAILED_ATTEMPTS = LoginLimits.MAX_FAILED_ATTEMPTS
    LOCKOUT_DURATION = LoginLimits.LOCKOUT_DURATION
    PROGRESSIVE_DELAYS = True
    NOTIFY_ON_LOCKOUT = True
    ADMIN_UNLOCK_REQUIRED = False


class PasswordHistoryPolicy:
    """Password history policy constants."""
    DEFAULT_EXPIRY_DAYS = 730  # 2 years
    MIN_REUSE_AGE_DAYS = 90
    MAX_HISTORY_ENTRIES = 24


class SecurityThresholds:
    """Security decision thresholds."""
    BLOCK_THRESHOLD = 0.9
    ADDITIONAL_VERIFICATION_THRESHOLD = 0.7
    MFA_REQUIRED_THRESHOLD = 0.5
    MONITOR_THRESHOLD = 0.3
    
    HIGH_RISK_SCORE = 0.8
    MEDIUM_RISK_SCORE = 0.6
    LOW_RISK_SCORE = 0.4
    MINIMAL_RISK_SCORE = 0.2


class NotificationLimits:
    """Notification system limits."""
    MAX_SETTINGS_PER_USER = 50
    MAX_METADATA_SIZE_KB = 10
    BATCH_SIZE_LIMIT = 100
    RETRY_ATTEMPTS = 3
    RETRY_DELAY_SECONDS = 5


class PreferenceLimits:
    """User preference limits."""
    MAX_CUSTOM_THEMES = 10
    MAX_NOTIFICATION_CATEGORIES = 20
    MAX_PRIVACY_RULES = 15
    METADATA_VALUE_MAX_LENGTH = 1000


# Export all constants
__all__ = [
    'AccountLockoutPolicy',
    'ContactLimits',
    'LoginLimits',
    'NotificationLimits',
    'PasswordPolicy',
    'PasswordHistoryPolicy',
    'PreferenceLimits',
    'ProfileLimits',
    'SecurityThresholds'
]