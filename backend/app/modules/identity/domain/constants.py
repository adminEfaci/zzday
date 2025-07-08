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


class PasswordHistoryPolicy:
    """Password history policy constants."""
    DEFAULT_EXPIRY_DAYS = 730  # 2 years
    MIN_REUSE_AGE_DAYS = 90
    MAX_HISTORY_ENTRIES = 24


class AccountLockoutPolicy:
    """Account lockout policy constants."""
    MAX_FAILED_ATTEMPTS = LoginLimits.MAX_FAILED_ATTEMPTS
    LOCKOUT_DURATION = LoginLimits.LOCKOUT_DURATION
    PROGRESSIVE_DELAYS = True
    NOTIFY_ON_LOCKOUT = True
    ADMIN_UNLOCK_REQUIRED = False


class SecurityThresholds:
    """Security decision thresholds."""
    BLOCK_THRESHOLD = 0.9
    ADDITIONAL_VERIFICATION_THRESHOLD = 0.7
    MFA_REQUIRED_THRESHOLD = 0.5
    MONITOR_THRESHOLD = 0.3
    SUSPICIOUS_THRESHOLD = 0.7
    
    # Risk level boundaries
    CRITICAL_RISK_SCORE = 0.8
    HIGH_RISK_SCORE = 0.6
    MEDIUM_RISK_SCORE = 0.4
    LOW_RISK_SCORE = 0.2
    
    # Risk factor weights
    LOCATION_WEIGHT = 0.3
    DEVICE_WEIGHT = 0.2
    BEHAVIORAL_WEIGHT = 0.3
    ATTACK_WEIGHT = 0.2


class LocationRisk:
    """Location-based risk scores."""
    UNKNOWN_LOCATION = 0.5
    KNOWN_LOCATION = 0.1
    HIGH_RISK_COUNTRY = 0.8
    NEW_LOCATION = 0.4


class DeviceRisk:
    """Device-based risk scores."""
    UNKNOWN_DEVICE = 0.6
    TRUSTED_DEVICE = 0.1
    KNOWN_DEVICE = 0.2
    NEW_DEVICE = 0.7


class BehavioralLimits:
    """Behavioral analysis thresholds and penalties."""
    HIGH_VELOCITY_THRESHOLD = 10
    HIGH_VELOCITY_PENALTY = 0.3
    
    MULTIPLE_FAILURES_THRESHOLD = 5
    MULTIPLE_FAILURES_PENALTY = 0.4
    
    UNUSUAL_TIME_PENALTY = 0.2
    
    CREDENTIAL_STUFFING_THRESHOLD = 20
    CREDENTIAL_STUFFING_PENALTY = 0.6
    
    BRUTE_FORCE_THRESHOLD = 10
    BRUTE_FORCE_PENALTY = 0.5
    
    BOT_INDICATORS = ["bot", "crawler", "spider"]
    BOT_PENALTY = 0.8


class TokenExpiry:
    """Token expiration constants."""
    ACCESS_TOKEN = timedelta(hours=1)
    REFRESH_TOKEN = timedelta(days=30)
    VERIFICATION_TOKEN = timedelta(hours=24)
    RESET_TOKEN = timedelta(hours=2)
    MFA_TOKEN = timedelta(minutes=5)
    API_KEY = timedelta(days=365)  # 1 year default


class SecurityLimits:
    """Security-related limits and thresholds."""
    # Password security
    PASSWORD_HISTORY_LIMIT = 24
    PASSWORD_MIN_AGE = timedelta(hours=1)
    PASSWORD_MAX_AGE = timedelta(days=90)
    PASSWORD_COMPLEXITY_SCORE_MIN = 0.6
    PASSWORD_HISTORY_COUNT = 12
    
    # Account lockout
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES = 15
    TOKEN_EXPIRY_HOURS = 24
    
    # Session management
    SESSION_TIMEOUT = timedelta(hours=8)
    SESSION_ABSOLUTE_TIMEOUT = timedelta(hours=24)
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
    MAX_CONCURRENT_SESSIONS = 5
    MAX_SESSIONS_PER_DEVICE = 2
    MAX_SESSIONS_PER_IP = 3
    
    # MFA and device management
    MFA_DEVICE_LIMIT = 5
    MFA_BACKUP_CODES_COUNT = 10
    DEVICE_TRUST_DURATION = timedelta(days=30)
    TRUSTED_DEVICE_LIMIT = 10
    
    # API and token limits
    API_KEY_LIMIT = 10
    MAX_REFRESH_TOKENS_PER_USER = 10
    MAX_API_KEYS_PER_USER = 10
    MAX_VERIFICATION_TOKENS_PER_USER = 5
    
    # Risk assessment
    RISK_SCORE_THRESHOLD = 0.7
    RISK_SCORE_MFA_REQUIRED = 0.5
    RISK_SCORE_BLOCK_ACCESS = 0.9
    
    # Rate limiting - Authentication
    LOGIN_ATTEMPTS_PER_MINUTE = 5
    LOGIN_ATTEMPTS_PER_HOUR = 20
    MFA_ATTEMPTS_PER_MINUTE = 3
    MFA_ATTEMPTS_PER_HOUR = 10
    
    # Rate limiting - Password operations
    PASSWORD_RESET_ATTEMPTS_PER_HOUR = 3
    PASSWORD_CHANGE_ATTEMPTS_PER_HOUR = 5
    
    # Rate limiting - Verification
    VERIFICATION_ATTEMPTS_PER_MINUTE = 3
    VERIFICATION_ATTEMPTS_PER_HOUR = 10
    EMAIL_VERIFICATION_ATTEMPTS_PER_HOUR = 5
    SMS_VERIFICATION_ATTEMPTS_PER_HOUR = 3
    
    # Account lockout
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
    PROGRESSIVE_LOCKOUT_MULTIPLIER = 2
    MAX_LOCKOUT_DURATION = timedelta(hours=24)
    
    # IP-based limits
    MAX_FAILED_ATTEMPTS_PER_IP = 20
    IP_BLOCK_DURATION_HOURS = 24
    MAX_ACCOUNTS_PER_IP_PER_HOUR = 5


class DefaultValues:
    """Default values for domain entities."""
    DEFAULT_USER_ROLE = "user"
    DEFAULT_SESSION_TYPE = "web"
    DEFAULT_MFA_METHOD = "totp"
    DEFAULT_VERIFICATION_STATUS = "pending"
    DEFAULT_RISK_LEVEL = "low"
    DEFAULT_NOTIFICATION_PREFERENCES = {
        "email": True,
        "sms": False,
        "push": True,
        "in_app": True
    }
    DEFAULT_PRIVACY_SETTINGS = {
        "profile_visibility": "private",
        "contact_info_visible": False,
        "activity_tracking": True,
        "marketing_emails": False
    }


class ValidationRules:
    """Validation rules and patterns."""
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL_CHARS = True
    PASSWORD_SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 50
    USERNAME_PATTERN = r"^[a-zA-Z0-9_-]+$"
    
    NAME_MIN_LENGTH = 1
    NAME_MAX_LENGTH = 100
    NAME_PATTERN = r"^[a-zA-Z\s\-'\.]+$"
    
    PHONE_PATTERN = r"^\+?1?[0-9]{10,15}$"
    
    VERIFICATION_CODE_LENGTH = 6
    VERIFICATION_CODE_PATTERN = r"^[0-9]{6}$"
    
    API_KEY_LENGTH = 32
    TOKEN_LENGTH = 64


class ErrorMessages:
    """Standard error messages for domain operations."""
    
    # Authentication Errors
    INVALID_CREDENTIALS = "Invalid email or password"
    ACCOUNT_LOCKED = "Account is locked due to multiple failed login attempts"
    ACCOUNT_SUSPENDED = "Account is temporarily suspended"
    MFA_REQUIRED = "Multi-factor authentication is required"
    SESSION_EXPIRED = "Your session has expired. Please log in again"
    
    # Authorization Errors
    PERMISSION_DENIED = "You don't have permission to perform this action"
    INSUFFICIENT_PRIVILEGES = "Insufficient privileges for this operation"
    
    # Validation Errors
    PASSWORD_TOO_WEAK = "Password does not meet security requirements"
    EMAIL_ALREADY_EXISTS = "An account with this email already exists"
    INVALID_EMAIL_FORMAT = "Please enter a valid email address"
    PHONE_INVALID_FORMAT = "Please enter a valid phone number"
    
    # Limits Exceeded
    MAX_CONTACTS_EXCEEDED = f"Maximum of {ContactLimits.MAX_EMERGENCY_CONTACTS} emergency contacts allowed"
    MAX_DEVICES_EXCEEDED = f"Maximum of {SecurityLimits.MFA_DEVICE_LIMIT} MFA devices allowed"
    MAX_SESSIONS_EXCEEDED = f"Maximum of {SecurityLimits.MAX_CONCURRENT_SESSIONS} concurrent sessions allowed"


class PolicyConstants:
    """Security and compliance policy constants."""
    
    # Password Policy
    PASSWORD_POLICY_CONSTANTS = {
        "MIN_LENGTH": 8,
        "MAX_LENGTH": 128,
        "REQUIRE_UPPERCASE": True,
        "REQUIRE_LOWERCASE": True,
        "REQUIRE_DIGITS": True,
        "REQUIRE_SPECIAL_CHARS": True,
        "SPECIAL_CHARS": "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "PASSWORD_HISTORY_COUNT": 12,
        "HISTORY_LIMIT": 24,
        "MIN_AGE": timedelta(hours=1),
        "MAX_AGE": timedelta(days=90),
        "COMPLEXITY_SCORE_THRESHOLD": 0.6
    }
    
    # Session Policy
    SESSION_POLICY = {
        "timeout": SecurityLimits.SESSION_TIMEOUT,
        "absolute_timeout": SecurityLimits.SESSION_ABSOLUTE_TIMEOUT,
        "max_concurrent": SecurityLimits.MAX_CONCURRENT_SESSIONS,
        "require_mfa_for_sensitive": True,
        "track_device_fingerprint": True,
        "extend_on_activity": True
    }
    
    # MFA Policy
    MFA_POLICY = {
        "require_for_admin": True,
        "require_for_high_risk": True,
        "max_devices": SecurityLimits.MFA_DEVICE_LIMIT,
        "backup_codes_required": True,
        "remember_device_duration": SecurityLimits.DEVICE_TRUST_DURATION,
        "allowed_methods": ["totp", "sms", "hardware_token", "biometric"]
    }
    
    # Risk Assessment Policy
    RISK_POLICY = {
        "threshold_medium": 0.3,
        "threshold_high": 0.6,
        "threshold_critical": 0.8,
        "factors": {
            "unknown_device": 0.3,
            "unknown_location": 0.2,
            "off_hours_access": 0.1,
            "suspicious_ip": 0.4,
            "multiple_failed_attempts": 0.3,
            "no_mfa": 0.2,
            "admin_access": 0.1
        }
    }


class ComplianceConstants:
    """Compliance and regulatory constants."""
    
    # Data retention periods (GDPR, SOX, etc.)
    DATA_RETENTION = {
        # User data
        "user_profile": timedelta(days=2555),  # 7 years
        "user_preferences": timedelta(days=1095),  # 3 years
        "contact_information": timedelta(days=2555),  # 7 years
        
        # Authentication data
        "password_history": timedelta(days=730),  # 2 years
        "login_attempts": timedelta(days=90),
        "session_data": timedelta(days=90),
        "mfa_devices": timedelta(days=1095),  # 3 years
        
        # Audit and security
        "audit_logs": timedelta(days=2555),  # 7 years
        "security_events": timedelta(days=2555),  # 7 years
        "access_logs": timedelta(days=1095),  # 3 years
        "admin_actions": timedelta(days=2555),  # 7 years
        
        # Financial and legal
        "financial_data": timedelta(days=2555),  # 7 years
        "legal_documents": timedelta(days=2555),  # 7 years
        "contracts": timedelta(days=2555),  # 7 years
        
        # Temporary data
        "verification_tokens": timedelta(hours=24),
        "reset_tokens": timedelta(hours=2),
        "temporary_files": timedelta(days=7),
        "cache_data": timedelta(hours=24)
    }
    
    # Data classification levels
    DATA_CLASSIFICATION_LEVELS = {
        "public": 0,
        "internal": 1,
        "confidential": 2,
        "restricted": 3,
        "top_secret": 4
    }
    
    # Highly sensitive data fields requiring special handling
    HIGHLY_SENSITIVE_FIELDS = [
        "password_hash",
        "ssn",
        "tax_id",
        "credit_card_number",
        "bank_account_number",
        "biometric_template",
        "medical_record_number",
        "government_id",
        "passport_number",
        "driver_license"
    ]
    
    # PII fields requiring consent and special handling
    PII_FIELDS = [
        "email",
        "phone_number",
        "full_name",
        "first_name",
        "last_name",
        "address",
        "city",
        "state",
        "postal_code",
        "country",
        "date_of_birth",
        "ip_address",
        "device_id",
        "user_agent",
        "location_data",
        "profile_photo"
    ]
    
    # Fields that require explicit consent
    EXPLICIT_CONSENT_FIELDS = [
        "marketing_emails",
        "analytics_tracking",
        "location_tracking",
        "behavioral_analysis",
        "third_party_sharing",
        "advertising_personalization"
    ]
    
    # Minimum age requirements by jurisdiction
    MINIMUM_AGE_REQUIREMENTS = {
        "default": 13,
        "EU": 16,  # GDPR
        "US": 13,  # COPPA
        "CA": 13,  # PIPEDA
        "AU": 13,  # Privacy Act
        "UK": 13   # UK GDPR
    }
    
    # Data subject rights (GDPR Article 15-22)
    DATA_SUBJECT_RIGHTS = [
        "right_to_access",
        "right_to_rectification", 
        "right_to_erasure",
        "right_to_restrict_processing",
        "right_to_data_portability",
        "right_to_object",
        "right_not_to_be_subject_to_automated_decision_making"
    ]


class AuditConstants:
    """Audit and logging constants."""
    
    # Audit Retention
    AUDIT_RETENTION = {
        "security_events": timedelta(days=2555),  # 7 years
        "user_actions": timedelta(days=2555),     # 7 years
        "admin_actions": timedelta(days=2555),    # 7 years
        "system_events": timedelta(days=365),     # 1 year
        "performance_logs": timedelta(days=30)
    }
    
    # High-Risk Actions (require detailed audit)
    HIGH_RISK_ACTIONS = [
        "user_create",
        "user_delete",
        "permission_grant",
        "permission_revoke",
        "role_assign",
        "role_unassign",
        "admin_access",
        "security_policy_change",
        "data_export",
        "bulk_operations"
    ]
    
    # Compliance Actions (require special handling)
    COMPLIANCE_ACTIONS = [
        "data_access",
        "data_modification",
        "data_deletion",
        "consent_change",
        "privacy_setting_change",
        "data_export_request",
        "data_deletion_request"
    ]


class RegexPatterns:
    """Regular expression patterns for validation."""
    
    EMAIL = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    PHONE_INTERNATIONAL = r"^\+?[1-9]\d{1,14}$"
    PHONE_US = r"^(\+1)?[2-9]\d{2}[2-9]\d{2}\d{4}$"
    
    # Password strength patterns
    UPPERCASE = r"[A-Z]"
    LOWERCASE = r"[a-z]"
    DIGITS = r"\d"
    SPECIAL_CHARS = r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]"
    
    # User input patterns
    USERNAME = ValidationRules.USERNAME_PATTERN
    NAME = ValidationRules.NAME_PATTERN
    VERIFICATION_CODE = ValidationRules.VERIFICATION_CODE_PATTERN
    
    # Security patterns
    JWT_TOKEN = r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$"
    UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    API_KEY = r"^[A-Za-z0-9]{32}$"
    
    # IP Address patterns
    IPV4 = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    IPV6 = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"


# Export all constants
__all__ = [
    'AccountLockoutPolicy',
    'AuditConstants',
    'BehavioralLimits',
    'ComplianceConstants',
    'ContactLimits',
    'DefaultValues',
    'DeviceRisk',
    'ErrorMessages',
    'LocationRisk',
    'LoginLimits',
    'PasswordHistoryPolicy',
    'PasswordPolicy',
    'PolicyConstants',
    'ProfileLimits',
    'RegexPatterns',
    'SecurityLimits',
    'SecurityThresholds',
    'TokenExpiry',
    'ValidationRules'
]