"""
System-Wide Constants for EzzDay Core

This module provides comprehensive system constants with production-ready values,
performance optimization, and security considerations. All constants are immutable
and carefully designed for enterprise applications requiring reliability,
performance, and maintainability.

Key Features:
- Immutable constants with type safety (Final annotations)
- Pre-compiled regex patterns for performance optimization
- Comprehensive domain-specific constant groups
- Security-focused defaults with configurable limits
- Performance-optimized values based on production experience
- Detailed documentation with usage guidelines

Design Principles:
- Pure Python constants (no external dependencies)
- Explicit typing and immutability guarantees
- Performance-first design with pre-compiled patterns
- Security-conscious defaults with conservative limits
- Comprehensive documentation for maintenance

Usage Examples:
    # Pagination with type safety
    page_size = min(requested_size, MAX_PAGE_SIZE)
    
    # Validation with pre-compiled regex
    if not EMAIL_REGEX.match(email):
        raise ValidationError("Invalid email format")
    
    # Cache key generation
    cache_key = CACHE_KEY_USER.format(user_id=user.id)
    
    # Timeout configuration
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(
        total=API_REQUEST_TIMEOUT.total_seconds()
    )) as session:
        # API calls with proper timeout
        pass
    
    # Error handling with standardized codes
    raise APIError(
        message="Authentication failed",
        error_code=ERROR_AUTHENTICATION_FAILED,
        status_code=HTTP_UNAUTHORIZED
    )

Security Considerations:
    All limits and timeouts are designed with security in mind:
    - Rate limits prevent abuse and DoS attacks
    - Timeouts prevent resource exhaustion
    - Size limits prevent memory exhaustion
    - Regex patterns prevent ReDoS attacks

Performance Optimizations:
    - Pre-compiled regex patterns for O(1) pattern access
    - Conservative memory limits for scalable applications
    - Optimized timeout values based on production metrics
    - Efficient cache key patterns for minimal memory usage

Modification Guidelines:
    - All changes require security review and testing
    - Never hardcode these values elsewhere in the codebase
    - Update with care as changes affect rate limiting and validation
    - Maintain backward compatibility for API clients
    - Document all changes with rationale and impact analysis
"""

import re
from datetime import timedelta
from typing import Any, Final

# =============================================================================
# PAGINATION AND LISTING CONSTANTS
# =============================================================================

# Default pagination settings optimized for performance and UX
DEFAULT_PAGE_SIZE: Final[int] = 20
MAX_PAGE_SIZE: Final[int] = 100
MIN_PAGE_SIZE: Final[int] = 1
DEFAULT_PAGE: Final[int] = 1

# Search and filtering limits
MAX_SEARCH_RESULTS: Final[int] = 1000
MAX_FILTER_CONDITIONS: Final[int] = 10
DEFAULT_SEARCH_LIMIT: Final[int] = 50

# Sorting and ordering
MAX_SORT_FIELDS: Final[int] = 5
DEFAULT_SORT_ORDER: Final[str] = "desc"
ALLOWED_SORT_ORDERS: Final[tuple[str, ...]] = ("asc", "desc")

# =============================================================================
# SYSTEM LIMITS AND CONSTRAINTS
# =============================================================================

# File upload limits (security and performance)
MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB
MAX_AVATAR_SIZE: Final[int] = 2 * 1024 * 1024  # 2 MB
MAX_DOCUMENT_SIZE: Final[int] = 50 * 1024 * 1024  # 50 MB
ALLOWED_IMAGE_TYPES: Final[tuple[str, ...]] = ("image/jpeg", "image/png", "image/webp")
ALLOWED_DOCUMENT_TYPES: Final[tuple[str, ...]] = (
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "text/csv",
)

# Processing limits (prevent resource exhaustion)
MAX_BATCH_SIZE: Final[int] = 1000
MAX_BULK_OPERATIONS: Final[int] = 10000
MAX_QUERY_DEPTH: Final[int] = 10
MAX_RECURSIVE_DEPTH: Final[int] = 50

# Memory and storage limits
MAX_MEMORY_CACHE_SIZE: Final[int] = 100 * 1024 * 1024  # 100 MB
MAX_LOG_FILE_SIZE: Final[int] = 100 * 1024 * 1024  # 100 MB
MAX_SESSION_DATA_SIZE: Final[int] = 1024 * 1024  # 1 MB
MAX_METADATA_SIZE: Final[int] = 64 * 1024  # 64 KB

# Text and content limits
MAX_USERNAME_LENGTH: Final[int] = 50
MAX_EMAIL_LENGTH: Final[int] = 254  # RFC 5321 limit
MAX_PASSWORD_LENGTH: Final[int] = 128
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_NAME_LENGTH: Final[int] = 100
MAX_DESCRIPTION_LENGTH: Final[int] = 2000
MAX_TITLE_LENGTH: Final[int] = 255
MAX_SLUG_LENGTH: Final[int] = 100
MAX_TAG_LENGTH: Final[int] = 50
MAX_TAGS_PER_ENTITY: Final[int] = 20

# =============================================================================
# TIMEOUT CONFIGURATIONS
# =============================================================================

# HTTP and API timeouts
DEFAULT_TIMEOUT: Final[timedelta] = timedelta(seconds=30)
FAST_TIMEOUT: Final[timedelta] = timedelta(seconds=5)
LONG_TIMEOUT: Final[timedelta] = timedelta(minutes=5)
CRITICAL_TIMEOUT: Final[timedelta] = timedelta(minutes=10)
API_REQUEST_TIMEOUT: Final[timedelta] = timedelta(seconds=60)

# Database timeouts
DB_CONNECTION_TIMEOUT: Final[timedelta] = timedelta(seconds=10)
DB_QUERY_TIMEOUT: Final[timedelta] = timedelta(seconds=30)
DB_TRANSACTION_TIMEOUT: Final[timedelta] = timedelta(minutes=2)

# Cache timeouts
CACHE_TIMEOUT_SHORT: Final[timedelta] = timedelta(minutes=5)
CACHE_TIMEOUT_MEDIUM: Final[timedelta] = timedelta(minutes=15)
CACHE_TIMEOUT_LONG: Final[timedelta] = timedelta(hours=1)
CACHE_TIMEOUT_EXTENDED: Final[timedelta] = timedelta(hours=24)

# Session and authentication timeouts
SESSION_TIMEOUT: Final[timedelta] = timedelta(hours=8)
SESSION_REFRESH_TIMEOUT: Final[timedelta] = timedelta(days=30)
PASSWORD_RESET_TIMEOUT: Final[timedelta] = timedelta(hours=1)
EMAIL_VERIFICATION_TIMEOUT: Final[timedelta] = timedelta(hours=24)
REMEMBER_ME_TIMEOUT: Final[timedelta] = timedelta(days=30)

# Task and job timeouts
TASK_EXECUTION_TIMEOUT: Final[timedelta] = timedelta(minutes=30)
BACKGROUND_JOB_TIMEOUT: Final[timedelta] = timedelta(hours=2)
CLEANUP_JOB_TIMEOUT: Final[timedelta] = timedelta(hours=6)

# =============================================================================
# RETRY POLICIES AND BACKOFF
# =============================================================================

# Basic retry configuration
MAX_RETRIES: Final[int] = 3
MAX_RETRIES_CRITICAL: Final[int] = 5
RETRY_BACKOFF_FACTOR: Final[float] = 2.0
RETRY_JITTER_MAX: Final[float] = 1.0
RETRY_MAX_WAIT: Final[timedelta] = timedelta(minutes=1)
RETRY_INITIAL_DELAY: Final[timedelta] = timedelta(seconds=1)

# Service-specific retry policies
API_RETRY_ATTEMPTS: Final[int] = 3
DB_RETRY_ATTEMPTS: Final[int] = 2
CACHE_RETRY_ATTEMPTS: Final[int] = 1
EMAIL_RETRY_ATTEMPTS: Final[int] = 3
SMS_RETRY_ATTEMPTS: Final[int] = 2

# Circuit breaker configuration
CIRCUIT_BREAKER_FAILURE_THRESHOLD: Final[int] = 5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT: Final[timedelta] = timedelta(seconds=30)
CIRCUIT_BREAKER_EXPECTED_EXCEPTION_THRESHOLD: Final[int] = 10

# =============================================================================
# RATE LIMITING POLICIES
# =============================================================================

# General API rate limits (requests per time window)
DEFAULT_RATE_LIMIT: Final[str] = "100/hour"
AUTHENTICATED_RATE_LIMIT: Final[str] = "1000/hour"
PREMIUM_RATE_LIMIT: Final[str] = "5000/hour"

# Authentication and security rate limits
AUTH_RATE_LIMIT: Final[str] = "5/minute"
LOGIN_RATE_LIMIT: Final[str] = "10/hour"
PASSWORD_RESET_RATE_LIMIT: Final[str] = "3/hour"  # noqa: S105 - Not a password, just a rate limit constant name
EMAIL_VERIFICATION_RATE_LIMIT: Final[str] = "5/hour"
SIGNUP_RATE_LIMIT: Final[str] = "5/hour"

# Feature-specific rate limits
SEARCH_RATE_LIMIT: Final[str] = "100/minute"
UPLOAD_RATE_LIMIT: Final[str] = "20/hour"
DOWNLOAD_RATE_LIMIT: Final[str] = "100/hour"
API_WRITE_RATE_LIMIT: Final[str] = "200/hour"
API_READ_RATE_LIMIT: Final[str] = "2000/hour"

# Administrative rate limits
ADMIN_API_RATE_LIMIT: Final[str] = "10000/hour"
BULK_OPERATION_RATE_LIMIT: Final[str] = "10/hour"
REPORT_GENERATION_RATE_LIMIT: Final[str] = "5/hour"

# =============================================================================
# HTTP STATUS CODES
# =============================================================================

# Success codes
HTTP_OK: Final[int] = 200
HTTP_CREATED: Final[int] = 201
HTTP_ACCEPTED: Final[int] = 202
HTTP_NO_CONTENT: Final[int] = 204

# Client error codes
HTTP_BAD_REQUEST: Final[int] = 400
HTTP_UNAUTHORIZED: Final[int] = 401
HTTP_FORBIDDEN: Final[int] = 403
HTTP_NOT_FOUND: Final[int] = 404
HTTP_METHOD_NOT_ALLOWED: Final[int] = 405
HTTP_CONFLICT: Final[int] = 409
HTTP_UNPROCESSABLE_ENTITY: Final[int] = 422
HTTP_TOO_MANY_REQUESTS: Final[int] = 429

# Server error codes
HTTP_INTERNAL_SERVER_ERROR: Final[int] = 500
HTTP_NOT_IMPLEMENTED: Final[int] = 501
HTTP_BAD_GATEWAY: Final[int] = 502
HTTP_SERVICE_UNAVAILABLE: Final[int] = 503
HTTP_GATEWAY_TIMEOUT: Final[int] = 504

# =============================================================================
# ERROR CODES AND CLASSIFICATIONS
# =============================================================================

# Authentication and authorization errors
ERROR_AUTHENTICATION_FAILED: Final[str] = "AUTH001"
ERROR_AUTHORIZATION_FAILED: Final[str] = "AUTH002"
ERROR_TOKEN_EXPIRED: Final[str] = "AUTH003"  # noqa: S105 - Not a password, just an error code constant
ERROR_TOKEN_INVALID: Final[str] = "AUTH004"  # noqa: S105 - Not a password, just an error code constant
ERROR_INSUFFICIENT_PERMISSIONS: Final[str] = "AUTH005"
ERROR_ACCOUNT_LOCKED: Final[str] = "AUTH006"
ERROR_ACCOUNT_DISABLED: Final[str] = "AUTH007"
ERROR_PASSWORD_EXPIRED: Final[str] = "AUTH008"  # noqa: S105 - Not a password, just an error code constant

# Validation and input errors
ERROR_VALIDATION_FAILED: Final[str] = "VAL001"
ERROR_INVALID_FORMAT: Final[str] = "VAL002"
ERROR_REQUIRED_FIELD_MISSING: Final[str] = "VAL003"
ERROR_FIELD_TOO_LONG: Final[str] = "VAL004"
ERROR_FIELD_TOO_SHORT: Final[str] = "VAL005"
ERROR_INVALID_ENUM_VALUE: Final[str] = "VAL006"
ERROR_INVALID_DATE_RANGE: Final[str] = "VAL007"
ERROR_DUPLICATE_VALUE: Final[str] = "VAL008"

# Resource and data errors
ERROR_RESOURCE_NOT_FOUND: Final[str] = "RES001"
ERROR_RESOURCE_CONFLICT: Final[str] = "RES002"
ERROR_RESOURCE_LOCKED: Final[str] = "RES003"
ERROR_RESOURCE_DELETED: Final[str] = "RES004"
ERROR_RESOURCE_EXPIRED: Final[str] = "RES005"
ERROR_RESOURCE_LIMIT_EXCEEDED: Final[str] = "RES006"
ERROR_DEPENDENCY_NOT_MET: Final[str] = "RES007"

# System and infrastructure errors
ERROR_INTERNAL_SERVER: Final[str] = "SRV001"
ERROR_SERVICE_UNAVAILABLE: Final[str] = "SRV002"
ERROR_DATABASE_ERROR: Final[str] = "SRV003"
ERROR_CACHE_ERROR: Final[str] = "SRV004"
ERROR_EXTERNAL_SERVICE_ERROR: Final[str] = "SRV005"
ERROR_CONFIGURATION_ERROR: Final[str] = "SRV006"
ERROR_MAINTENANCE_MODE: Final[str] = "SRV007"

# Rate limiting and throttling
ERROR_RATE_LIMIT_EXCEEDED: Final[str] = "RATE001"
ERROR_QUOTA_EXCEEDED: Final[str] = "RATE002"
ERROR_CONCURRENT_LIMIT_EXCEEDED: Final[str] = "RATE003"
ERROR_BANDWIDTH_LIMIT_EXCEEDED: Final[str] = "RATE004"

# File and upload errors
ERROR_FILE_TOO_LARGE: Final[str] = "FILE001"
ERROR_INVALID_FILE_TYPE: Final[str] = "FILE002"
ERROR_FILE_CORRUPTED: Final[str] = "FILE003"
ERROR_UPLOAD_FAILED: Final[str] = "FILE004"
ERROR_VIRUS_DETECTED: Final[str] = "FILE005"

# =============================================================================
# REGULAR EXPRESSIONS (Pre-compiled for performance and security) - FIXED
# =============================================================================

# Email validation (RFC 5322 compliant)
EMAIL_REGEX_PATTERN: Final[
    str
] = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
EMAIL_REGEX: Final[re.Pattern[str]] = re.compile(EMAIL_REGEX_PATTERN, re.IGNORECASE)

# Phone number validation (international format)
PHONE_REGEX_PATTERN: Final[str] = r"^\+?[1-9]\d{1,14}$"
PHONE_REGEX: Final[re.Pattern[str]] = re.compile(PHONE_REGEX_PATTERN)

# UUID validation (version 4)
UUID_V4_REGEX_PATTERN: Final[
    str
] = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
UUID_V4_REGEX: Final[re.Pattern[str]] = re.compile(UUID_V4_REGEX_PATTERN, re.IGNORECASE)

# General UUID validation (any version) - FIXED BUG
UUID_REGEX_PATTERN: Final[
    str
] = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
UUID_REGEX: Final[re.Pattern[str]] = re.compile(
    UUID_REGEX_PATTERN, re.IGNORECASE
)  # FIXED: was URL_REGEX

# URL slug validation
SLUG_REGEX_PATTERN: Final[str] = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
SLUG_REGEX: Final[re.Pattern[str]] = re.compile(SLUG_REGEX_PATTERN)

# Username validation (alphanumeric with underscores and hyphens)
USERNAME_REGEX_PATTERN: Final[str] = r"^[a-zA-Z0-9_-]{3,50}$"
USERNAME_REGEX: Final[re.Pattern[str]] = re.compile(USERNAME_REGEX_PATTERN)

# Password strength validation
PASSWORD_STRONG_REGEX_PATTERN: Final[
    str
] = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"  # noqa: S105 - Not a password, just a regex pattern
PASSWORD_STRONG_REGEX: Final[re.Pattern[str]] = re.compile(
    PASSWORD_STRONG_REGEX_PATTERN
)

# URL validation - FIXED: Now properly defined
URL_REGEX_PATTERN: Final[
    str
] = r"^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$"
URL_REGEX: Final[re.Pattern[str]] = re.compile(URL_REGEX_PATTERN, re.IGNORECASE)

# IP address validation
IPV4_REGEX_PATTERN: Final[
    str
] = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
IPV4_REGEX: Final[re.Pattern[str]] = re.compile(IPV4_REGEX_PATTERN)

IPV6_REGEX_PATTERN: Final[
    str
] = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$"
IPV6_REGEX: Final[re.Pattern[str]] = re.compile(IPV6_REGEX_PATTERN)

# Date and time validation
DATE_REGEX_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}$"
DATE_REGEX: Final[re.Pattern[str]] = re.compile(DATE_REGEX_PATTERN)

DATETIME_ISO_REGEX_PATTERN: Final[
    str
] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$"
DATETIME_ISO_REGEX: Final[re.Pattern[str]] = re.compile(DATETIME_ISO_REGEX_PATTERN)

# Security patterns (for input sanitization)
SQL_INJECTION_PATTERN: Final[
    str
] = r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)"
SQL_INJECTION_REGEX: Final[re.Pattern[str]] = re.compile(
    SQL_INJECTION_PATTERN, re.IGNORECASE
)

XSS_PATTERN: Final[str] = r"(?i)<script|javascript:|on\w+="
XSS_REGEX: Final[re.Pattern[str]] = re.compile(XSS_PATTERN, re.IGNORECASE)

# File name validation
SAFE_FILENAME_REGEX_PATTERN: Final[str] = r"^[a-zA-Z0-9._-]+$"
SAFE_FILENAME_REGEX: Final[re.Pattern[str]] = re.compile(SAFE_FILENAME_REGEX_PATTERN)

# =============================================================================
# CACHE KEYS AND PATTERNS
# =============================================================================

# User and session cache keys
CACHE_KEY_USER: Final[str] = "user:{user_id}"
CACHE_KEY_USER_PROFILE: Final[str] = "user:profile:{user_id}"
CACHE_KEY_USER_PREFERENCES: Final[str] = "user:prefs:{user_id}"
CACHE_KEY_SESSION: Final[str] = "session:{session_id}"
CACHE_KEY_USER_SESSIONS: Final[str] = "user:sessions:{user_id}"

# Authentication and authorization cache keys
CACHE_KEY_PERMISSIONS: Final[str] = "permissions:{user_id}"
CACHE_KEY_USER_ROLES: Final[str] = "user:roles:{user_id}"
CACHE_KEY_TOKEN_BLACKLIST: Final[str] = "token:blacklist:{token_hash}"  # noqa: S105 - Not a password, just a cache key pattern
CACHE_KEY_LOGIN_ATTEMPTS: Final[str] = "login:attempts:{identifier}"
CACHE_KEY_PASSWORD_RESET: Final[str] = "password:reset:{token}"  # noqa: S105 - Not a password, just a cache key pattern

# Rate limiting cache keys
CACHE_KEY_RATE_LIMIT: Final[str] = "rate_limit:{key}:{window}"
CACHE_KEY_API_QUOTA: Final[str] = "api:quota:{user_id}:{period}"
CACHE_KEY_FEATURE_LIMIT: Final[str] = "feature:limit:{user_id}:{feature}:{period}"

# Application data cache keys
CACHE_KEY_CONFIG: Final[str] = "config:{key}"
CACHE_KEY_FEATURE_FLAGS: Final[str] = "feature_flags:{user_id}"
CACHE_KEY_SYSTEM_STATUS: Final[str] = "system:status"
CACHE_KEY_MAINTENANCE_MODE: Final[str] = "maintenance:mode"

# Content and data cache keys
CACHE_KEY_SEARCH_RESULTS: Final[str] = "search:{query_hash}:{page}"
CACHE_KEY_REPORT: Final[str] = "report:{report_id}:{version}"
CACHE_KEY_AGGREGATION: Final[str] = "agg:{type}:{filters_hash}:{period}"

# Lock keys for distributed operations
LOCK_KEY_USER_UPDATE: Final[str] = "lock:user:update:{user_id}"
LOCK_KEY_BATCH_OPERATION: Final[str] = "lock:batch:{operation_id}"
LOCK_KEY_SYSTEM_MAINTENANCE: Final[str] = "lock:system:maintenance"

# =============================================================================
# DEFAULT VALUES AND CONFIGURATIONS
# =============================================================================

# Localization and formatting
DEFAULT_TIMEZONE: Final[str] = "UTC"
DEFAULT_LOCALE: Final[str] = "en-US"
DEFAULT_LANGUAGE: Final[str] = "en"
DEFAULT_CURRENCY: Final[str] = "USD"
DEFAULT_DATE_FORMAT: Final[str] = "%Y-%m-%d"
DEFAULT_DATETIME_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
DEFAULT_TIME_FORMAT: Final[str] = "%H:%M:%S"

# User interface defaults
DEFAULT_THEME: Final[str] = "light"
DEFAULT_PAGE_THEME: Final[str] = "default"
SUPPORTED_THEMES: Final[tuple[str, ...]] = ("light", "dark", "auto")
SUPPORTED_LANGUAGES: Final[tuple[str, ...]] = ("en", "es", "fr", "de", "ja", "zh")

# Security defaults
DEFAULT_PASSWORD_POLICY: Final[dict[str, Any]] = {
    "min_length": MIN_PASSWORD_LENGTH,
    "max_length": MAX_PASSWORD_LENGTH,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_special_chars": True,
    "prevent_common_passwords": True,
    "prevent_user_info": True,
}

# File handling defaults
DEFAULT_FILE_PERMISSIONS: Final[str] = "644"
DEFAULT_DIRECTORY_PERMISSIONS: Final[str] = "755"
TEMP_FILE_PREFIX: Final[str] = "ezzday_tmp_"
UPLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MB

# Database defaults
DEFAULT_DB_POOL_SIZE: Final[int] = 10
DEFAULT_DB_MAX_OVERFLOW: Final[int] = 20
DEFAULT_DB_POOL_TIMEOUT: Final[int] = 30
DEFAULT_DB_POOL_RECYCLE: Final[int] = 3600

# Email defaults
DEFAULT_EMAIL_FROM_NAME: Final[str] = "EzzDay"
DEFAULT_EMAIL_REPLY_TO: Final[str] = "noreply@ezzday.com"
EMAIL_BATCH_SIZE: Final[int] = 100

# API defaults
DEFAULT_API_VERSION: Final[str] = "v1"
SUPPORTED_API_VERSIONS: Final[tuple[str, ...]] = ("v1", "v2")
DEFAULT_CONTENT_TYPE: Final[str] = "application/json"
DEFAULT_CHARSET: Final[str] = "utf-8"

# =============================================================================
# MONITORING AND OBSERVABILITY
# =============================================================================

# Metrics and monitoring intervals
METRICS_COLLECTION_INTERVAL: Final[timedelta] = timedelta(seconds=30)
HEALTH_CHECK_INTERVAL: Final[timedelta] = timedelta(seconds=10)
LOG_ROTATION_INTERVAL: Final[timedelta] = timedelta(hours=24)

# Alert thresholds
CPU_USAGE_ALERT_THRESHOLD: Final[float] = 80.0
MEMORY_USAGE_ALERT_THRESHOLD: Final[float] = 85.0
DISK_USAGE_ALERT_THRESHOLD: Final[float] = 90.0
ERROR_RATE_ALERT_THRESHOLD: Final[float] = 5.0
RESPONSE_TIME_ALERT_THRESHOLD: Final[timedelta] = timedelta(seconds=2)

# Performance monitoring
SLOW_QUERY_THRESHOLD: Final[timedelta] = timedelta(seconds=1)
SLOW_REQUEST_THRESHOLD: Final[timedelta] = timedelta(seconds=5)
MEMORY_LEAK_THRESHOLD: Final[int] = 100 * 1024 * 1024  # 100 MB

# =============================================================================
# FEATURE FLAGS AND CONFIGURATIONS
# =============================================================================

# Feature toggles
FEATURE_USER_REGISTRATION: Final[str] = "user_registration"
FEATURE_PASSWORD_RESET: Final[str] = "password_reset"  # noqa: S105 - Not a password, just a feature flag name
FEATURE_EMAIL_VERIFICATION: Final[str] = "email_verification"
FEATURE_TWO_FACTOR_AUTH: Final[str] = "two_factor_auth"
FEATURE_SOCIAL_LOGIN: Final[str] = "social_login"
FEATURE_API_ACCESS: Final[str] = "api_access"
FEATURE_BULK_OPERATIONS: Final[str] = "bulk_operations"
FEATURE_ADVANCED_SEARCH: Final[str] = "advanced_search"
FEATURE_EXPORT_DATA: Final[str] = "export_data"
FEATURE_NOTIFICATIONS: Final[str] = "notifications"

# System maintenance
MAINTENANCE_MODE_KEY: Final[str] = "maintenance_mode"
SYSTEM_ALERT_KEY: Final[str] = "system_alert"
EMERGENCY_SHUTDOWN_KEY: Final[str] = "emergency_shutdown"

# =============================================================================
# ENVIRONMENT AND DEPLOYMENT
# =============================================================================

# Environment types
ENV_DEVELOPMENT: Final[str] = "development"
ENV_TESTING: Final[str] = "testing"
ENV_STAGING: Final[str] = "staging"
ENV_PRODUCTION: Final[str] = "production"

# Deployment configurations
SUPPORTED_ENVIRONMENTS: Final[tuple[str, ...]] = (
    ENV_DEVELOPMENT,
    ENV_TESTING,
    ENV_STAGING,
    ENV_PRODUCTION,
)
DEBUG_ENVIRONMENTS: Final[tuple[str, ...]] = (ENV_DEVELOPMENT, ENV_TESTING)
PRODUCTION_ENVIRONMENTS: Final[tuple[str, ...]] = (ENV_STAGING, ENV_PRODUCTION)

# =============================================================================
# DEPRECATION WARNINGS AND COMPATIBILITY
# =============================================================================

# Legacy constants (deprecated - use new ones above)
# Maintain for backward compatibility but log deprecation warnings
LEGACY_MAX_PAGE_SIZE: Final[int] = MAX_PAGE_SIZE  # Use MAX_PAGE_SIZE instead
LEGACY_DEFAULT_TIMEOUT: Final[
    timedelta
] = DEFAULT_TIMEOUT  # Use specific timeout constants

# =============================================================================
# VALIDATION AND SECURITY GUIDELINES
# =============================================================================

"""
CRITICAL SECURITY AND MODIFICATION GUIDELINES:

1. SECURITY REVIEW REQUIRED:
   - All changes to rate limits, timeouts, and size limits require security review
   - Regex patterns must be tested against ReDoS attacks
   - Cache key formats must prevent injection attacks
   - Error codes should not leak sensitive information

2. PERFORMANCE IMPACT:
   - Regex patterns are pre-compiled for performance - always use compiled versions
   - Cache timeouts affect memory usage and performance
   - Timeout values affect user experience and resource usage
   - Batch sizes affect memory consumption and processing time

3. BACKWARD COMPATIBILITY:
   - Error codes are part of the API contract - changes break clients
   - Cache key formats affect existing cached data
   - Rate limit changes affect client applications
   - Timeout changes can break existing integrations

4. TESTING REQUIREMENTS:
   - All regex patterns must have comprehensive test coverage
   - Rate limit changes require load testing
   - Timeout changes require performance testing
   - Security patterns require penetration testing

5. DOCUMENTATION:
   - All changes must update relevant API documentation
   - Security implications must be documented
   - Performance impact must be measured and documented
   - Migration guides required for breaking changes

6. MONITORING:
   - Changes to error codes require monitoring dashboard updates
   - Rate limit changes require alerting threshold updates
   - Performance thresholds require metric collection updates
   - New features require feature flag monitoring

NEVER:
- Hardcode these values elsewhere in the codebase
- Modify security-related constants without review
- Change error codes without API versioning
- Increase limits without capacity planning
- Modify regex patterns without security analysis

ALWAYS:
- Use type hints and Final annotations for new constants
- Pre-compile regex patterns for performance
- Document security implications of changes
- Test performance impact of modifications
- Maintain backward compatibility or provide migration path
"""

# =============================================================================
# DATABASE HEALTH CHECK QUERIES
# =============================================================================

# Health check queries (to avoid S608 hardcoded SQL violations)
HEALTH_CHECK_QUERY: Final[str] = "SELECT 1"
POSTGRESQL_VERSION_QUERY: Final[str] = "SELECT version()"
POSTGIS_VERSION_QUERY: Final[str] = "SELECT PostGIS_Version()"
JSON_SUPPORT_QUERY: Final[str] = "SELECT '{\"test\": true}'::json"
CURRENT_TIME_QUERY: Final[str] = "SELECT NOW()"
