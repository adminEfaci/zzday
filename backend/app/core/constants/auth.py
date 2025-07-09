"""Authentication and JWT Constants.

Centralized constants for authentication, JWT tokens, and OAuth flows
to eliminate hardcoded security-sensitive strings across the application.

This module follows Domain-Driven Design principles by providing
a single source of truth for authentication-related constants.
"""

from enum import Enum


class TokenType(Enum):
    """JWT Token types following OAuth 2.0 specifications."""
    BEARER = "Bearer"
    MAC = "MAC"
    BASIC = "Basic"


class JWTClaims(Enum):
    """Standard JWT claims constants."""
    # Standard claims (RFC 7519)
    ISSUER = "iss"
    SUBJECT = "sub"
    AUDIENCE = "aud"
    EXPIRATION_TIME = "exp"
    NOT_BEFORE = "nbf"
    ISSUED_AT = "iat"
    JWT_ID = "jti"
    
    # Custom claims for EzzDay
    USER_ID = "user_id"
    EMAIL = "email"
    ROLES = "roles"
    PERMISSIONS = "permissions"
    SESSION_ID = "session_id"
    MFA_VERIFIED = "mfa_verified"
    DEVICE_ID = "device_id"
    
    # Token-specific claims
    ACCESS_JTI = "access_jti"
    REFRESH_JTI = "refresh_jti"
    TOKEN_TYPE = "token_type"


class AuthenticationMethod(Enum):
    """Authentication methods supported by the system."""
    PASSWORD = "password"
    MFA_TOTP = "mfa_totp"
    MFA_SMS = "mfa_sms"
    MFA_EMAIL = "mfa_email"
    MFA_HARDWARE_KEY = "mfa_hardware_key"
    SOCIAL_GOOGLE = "social_google"
    SOCIAL_MICROSOFT = "social_microsoft"
    SOCIAL_GITHUB = "social_github"
    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"


class TokenScope(Enum):
    """OAuth 2.0 scope constants."""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    USER_PROFILE = "user:profile"
    USER_EMAIL = "user:email"
    USER_ROLES = "user:roles"


# Time constants (in seconds)
class TokenExpiry:
    """Token expiration time constants."""
    ACCESS_TOKEN_DEFAULT = 3600  # 1 hour
    ACCESS_TOKEN_SHORT = 900     # 15 minutes
    ACCESS_TOKEN_EXTENDED = 7200  # 2 hours
    
    REFRESH_TOKEN_DEFAULT = 86400 * 7  # 7 days
    REFRESH_TOKEN_EXTENDED = 86400 * 30  # 30 days
    
    MFA_CHALLENGE_TIMEOUT = 300   # 5 minutes
    PASSWORD_RESET_TIMEOUT = 3600  # 1 hour
    EMAIL_VERIFICATION_TIMEOUT = 86400  # 24 hours
    
    REMEMBER_ME_DURATION = 86400 * 30  # 30 days


# Security constants
class SecurityConstants:
    """Security-related constants for authentication."""
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    
    # Rate limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_DURATION = 900  # 15 minutes
    
    # MFA
    MFA_CODE_LENGTH = 6
    MFA_BACKUP_CODES_COUNT = 10
    MFA_BACKUP_CODE_LENGTH = 8
    
    # Session security
    SESSION_TIMEOUT = 3600  # 1 hour of inactivity
    CONCURRENT_SESSIONS_LIMIT = 5
    
    # CSRF protection
    CSRF_TOKEN_LENGTH = 32
    
    # API rate limiting
    API_RATE_LIMIT_REQUESTS = 1000
    API_RATE_LIMIT_WINDOW = 3600  # 1 hour


# Authentication error codes
class AuthErrorCode(Enum):
    """Standardized authentication error codes."""
    INVALID_CREDENTIALS = "auth.invalid_credentials"
    ACCOUNT_LOCKED = "auth.account_locked"
    ACCOUNT_DISABLED = "auth.account_disabled"
    EMAIL_NOT_VERIFIED = "auth.email_not_verified"
    MFA_REQUIRED = "auth.mfa_required"
    INVALID_MFA_CODE = "auth.invalid_mfa_code"
    TOKEN_EXPIRED = "auth.token_expired"
    TOKEN_INVALID = "auth.token_invalid"
    INSUFFICIENT_PERMISSIONS = "auth.insufficient_permissions"
    RATE_LIMIT_EXCEEDED = "auth.rate_limit_exceeded"
    PASSWORD_POLICY_VIOLATION = "auth.password_policy_violation"


# Convenient access patterns
class AUTH_CONSTANTS:
    """Main authentication constants namespace."""
    
    # Token types
    TOKEN_TYPE_BEARER = TokenType.BEARER.value
    TOKEN_TYPE_BASIC = TokenType.BASIC.value
    
    # Default expiration times
    DEFAULT_ACCESS_TOKEN_EXPIRY = TokenExpiry.ACCESS_TOKEN_DEFAULT
    DEFAULT_REFRESH_TOKEN_EXPIRY = TokenExpiry.REFRESH_TOKEN_DEFAULT
    
    # JWT claims
    CLAIM_USER_ID = JWTClaims.USER_ID.value
    CLAIM_EMAIL = JWTClaims.EMAIL.value
    CLAIM_ROLES = JWTClaims.ROLES.value
    CLAIM_SESSION_ID = JWTClaims.SESSION_ID.value
    CLAIM_ACCESS_JTI = JWTClaims.ACCESS_JTI.value
    CLAIM_REFRESH_JTI = JWTClaims.REFRESH_JTI.value
    CLAIM_TOKEN_TYPE = JWTClaims.TOKEN_TYPE.value
    CLAIM_MFA_VERIFIED = JWTClaims.MFA_VERIFIED.value
    
    # Authentication methods
    AUTH_METHOD_PASSWORD = AuthenticationMethod.PASSWORD.value
    AUTH_METHOD_MFA_TOTP = AuthenticationMethod.MFA_TOTP.value
    AUTH_METHOD_MFA_SMS = AuthenticationMethod.MFA_SMS.value
    AUTH_METHOD_MFA_EMAIL = AuthenticationMethod.MFA_EMAIL.value
    AUTH_METHOD_SOCIAL_GOOGLE = AuthenticationMethod.SOCIAL_GOOGLE.value
    
    # Security constants
    MIN_PASSWORD_LENGTH = SecurityConstants.MIN_PASSWORD_LENGTH
    MAX_LOGIN_ATTEMPTS = SecurityConstants.MAX_LOGIN_ATTEMPTS
    SESSION_TIMEOUT = SecurityConstants.SESSION_TIMEOUT
    
    # Error codes
    ERROR_INVALID_CREDENTIALS = AuthErrorCode.INVALID_CREDENTIALS.value
    ERROR_MFA_REQUIRED = AuthErrorCode.MFA_REQUIRED.value
    ERROR_TOKEN_EXPIRED = AuthErrorCode.TOKEN_EXPIRED.value


# Export commonly used constants for easy importing
__all__ = [
    "AUTH_CONSTANTS",
    "TokenType", 
    "JWTClaims",
    "AuthenticationMethod",
    "TokenScope",
    "TokenExpiry",
    "SecurityConstants", 
    "AuthErrorCode",
] 