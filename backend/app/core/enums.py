"""Shared enums for the EzzDay application.

This module contains all shared enumeration classes used across different
modules to avoid duplication and maintain consistency.

Design Principles:
- Single source of truth for enum values
- Rich enum implementations with additional methods
- Framework-agnostic design
- Clear documentation for each enum value
"""

from enum import Enum


class Environment(Enum):
    """Application environment types."""

    DEVELOPMENT = "dev"
    TESTING = "test"
    STAGING = "staging"
    PRODUCTION = "prod"

    @property
    def is_production(self) -> bool:
        """Check if environment is production."""
        return self == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        """Check if environment is development."""
        return self == Environment.DEVELOPMENT

    @property
    def is_testing(self) -> bool:
        """Check if environment is testing."""
        return self == Environment.TESTING

    @property
    def requires_security_hardening(self) -> bool:
        """Check if environment requires security hardening."""
        return self in (Environment.STAGING, Environment.PRODUCTION)

    @property
    def allows_debug_logging(self) -> bool:
        """Check if environment allows debug logging."""
        return self in (Environment.DEVELOPMENT, Environment.TESTING)


class LogLevel(Enum):
    """Logging levels with priority mapping."""

    DEBUG = ("DEBUG", 10)
    INFO = ("INFO", 20)
    WARNING = ("WARNING", 30)
    ERROR = ("ERROR", 40)
    CRITICAL = ("CRITICAL", 50)

    def __init__(self, level_name: str, priority: int):
        self.level_name = level_name
        self.priority = priority

    @classmethod
    def from_string(cls, level_str: str) -> "LogLevel":
        """Create LogLevel from string representation."""
        level_str = level_str.upper()
        for level in cls:
            if level.level_name == level_str:
                return level
        raise ValueError(f"Invalid log level: {level_str}")

    def to_logging_level(self) -> int:
        """Convert to standard logging module level."""
        return self.priority

    @property
    def is_debug_or_higher(self) -> bool:
        """Check if level is debug or higher."""
        return self.priority >= LogLevel.DEBUG.priority


class JWTAlgorithm(Enum):
    """JWT signing algorithms."""

    HS256 = "HS256"
    HS512 = "HS512"
    RS256 = "RS256"
    ES256 = "ES256"

    @property
    def is_symmetric(self) -> bool:
        """Check if algorithm uses symmetric keys."""
        return self in (JWTAlgorithm.HS256, JWTAlgorithm.HS512)

    @property
    def is_asymmetric(self) -> bool:
        """Check if algorithm uses asymmetric keys."""
        return not self.is_symmetric


class Provider(Enum):
    """Service provider types."""

    SENDGRID = "sendgrid"
    SMTP = "smtp"
    MOCK = "mock"
    TWILIO = "twilio"
    S3 = "s3"
    LOCAL = "local"

    @classmethod
    def email_providers(cls) -> set["Provider"]:
        """Get all email provider types."""
        return {cls.SENDGRID, cls.SMTP, cls.MOCK}

    @classmethod
    def sms_providers(cls) -> set["Provider"]:
        """Get all SMS provider types."""
        return {cls.TWILIO, cls.MOCK}

    @classmethod
    def storage_providers(cls) -> set["Provider"]:
        """Get all storage provider types."""
        return {cls.S3, cls.LOCAL}


class LogFormat(Enum):
    """Log output formats."""

    JSON = "json"
    CONSOLE = "console"
    PLAIN = "plain"

    @property
    def is_structured(self) -> bool:
        """Check if format is structured (machine readable)."""
        return self == LogFormat.JSON

    @property
    def is_human_readable(self) -> bool:
        """Check if format is primarily for human reading."""
        return self in (LogFormat.CONSOLE, LogFormat.PLAIN)


class APIDocumentationFormat(Enum):
    """API documentation output formats."""

    JSON = "json"
    YAML = "yaml"
    MARKDOWN = "markdown"
    HTML = "html"

    @property
    def is_machine_readable(self) -> bool:
        """Check if format is machine readable."""
        return self in (APIDocumentationFormat.JSON, APIDocumentationFormat.YAML)

    @property
    def is_presentation_format(self) -> bool:
        """Check if format is for presentation."""
        return self in (APIDocumentationFormat.MARKDOWN, APIDocumentationFormat.HTML)


class ValidationSeverity(Enum):
    """Validation issue severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def blocks_operation(self) -> bool:
        """Check if severity level should block the operation."""
        return self in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)

    @property
    def requires_attention(self) -> bool:
        """Check if severity level requires immediate attention."""
        return self == ValidationSeverity.CRITICAL


# === DEPENDENCY INJECTION ENUMS ===


class ServiceLifetime(Enum):
    """Service lifetime management strategies."""

    TRANSIENT = "transient"  # New instance every time
    SINGLETON = "singleton"  # Single instance for container lifetime
    SCOPED = "scoped"  # Single instance per scope (request/session)
    FACTORY = "factory"  # Factory function that returns instances

    @property
    def is_shared(self) -> bool:
        """Check if lifetime strategy creates shared instances."""
        return self in (ServiceLifetime.SINGLETON, ServiceLifetime.SCOPED)

    @property
    def requires_disposal(self) -> bool:
        """Check if lifetime strategy requires resource disposal."""
        return self != ServiceLifetime.TRANSIENT


class ServiceState(Enum):
    """Service registration states."""

    REGISTERED = "registered"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    ERROR = "error"
    DISPOSED = "disposed"

    @property
    def is_active(self) -> bool:
        """Check if service is in an active state."""
        return self in (ServiceState.REGISTERED, ServiceState.INITIALIZED)

    @property
    def is_available(self) -> bool:
        """Check if service is available for resolution."""
        return self == ServiceState.INITIALIZED

    @property
    def has_error(self) -> bool:
        """Check if service is in an error state."""
        return self == ServiceState.ERROR


# === DATABASE ENUMS ===


class PoolType(Enum):
    """Database connection pool types."""

    QUEUE_POOL = "queue"
    NULL_POOL = "null"
    STATIC_POOL = "static"

    @property
    def supports_pooling(self) -> bool:
        """Check if pool type supports connection pooling."""
        return self != PoolType.NULL_POOL

    @property
    def is_thread_safe(self) -> bool:
        """Check if pool type is thread-safe."""
        return self in (PoolType.QUEUE_POOL, PoolType.STATIC_POOL)


class HealthStatus(Enum):
    """System health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

    @property
    def is_operational(self) -> bool:
        """Check if status indicates operational system."""
        return self in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)

    @property
    def requires_attention(self) -> bool:
        """Check if status requires immediate attention."""
        return self in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED)

    @property
    def is_critical(self) -> bool:
        """Check if status is critical."""
        return self == HealthStatus.UNHEALTHY


# === CACHE-RELATED ENUMS ===


class CacheBackendType(Enum):
    """Physical cache backend implementations.

    Represents the actual storage technology used for caching.
    """

    MEMORY = "memory"  # In-process memory cache
    REDIS = "redis"  # Redis server cache
    MEMCACHED = "memcached"  # Memcached server cache
    HYBRID = "hybrid"  # Multi-tier cache (e.g., memory + redis)

    @property
    def is_distributed(self) -> bool:
        """Check if backend is distributed across multiple processes."""
        return self in (
            CacheBackendType.REDIS,
            CacheBackendType.MEMCACHED,
            CacheBackendType.HYBRID,
        )

    @property
    def is_persistent(self) -> bool:
        """Check if backend persists data across restarts."""
        return self == CacheBackendType.REDIS

    @property
    def supports_clustering(self) -> bool:
        """Check if backend supports clustering."""
        return self in (CacheBackendType.REDIS, CacheBackendType.HYBRID)


class CacheStrategy(Enum):
    """High-level cache strategies and patterns.

    Represents how the application interacts with the cache layer.
    """

    NO_CACHE = "no_cache"  # Disable caching entirely
    CACHE_ASIDE = "cache_aside"  # Manual cache management (lazy loading)
    WRITE_THROUGH = "write_through"  # Write to cache and storage simultaneously
    WRITE_BEHIND = "write_behind"  # Write to cache, async write to storage
    WRITE_AROUND = "write_around"  # Write only to storage, invalidate cache
    READ_THROUGH = "read_through"  # Cache loads data on cache miss
    REFRESH_AHEAD = "refresh_ahead"  # Proactively refresh cache before expiry

    @property
    def requires_storage_backend(self) -> bool:
        """Check if strategy requires a persistent storage backend."""
        return self != CacheStrategy.NO_CACHE

    @property
    def is_write_strategy(self) -> bool:
        """Check if strategy defines write behavior."""
        return self in (
            CacheStrategy.WRITE_THROUGH,
            CacheStrategy.WRITE_BEHIND,
            CacheStrategy.WRITE_AROUND,
        )

    @property
    def is_read_strategy(self) -> bool:
        """Check if strategy defines read behavior."""
        return self in (
            CacheStrategy.CACHE_ASIDE,
            CacheStrategy.READ_THROUGH,
            CacheStrategy.REFRESH_AHEAD,
        )

    @property
    def provides_strong_consistency(self) -> bool:
        """Check if strategy provides strong consistency."""
        return self in (CacheStrategy.WRITE_THROUGH, CacheStrategy.WRITE_AROUND)


class SerializationFormat(Enum):
    """Supported serialization formats for cache values."""

    JSON = "json"  # JSON serialization (human readable, limited types)
    PICKLE = "pickle"  # Python pickle (full Python object support)
    MSGPACK = "msgpack"  # MessagePack (compact binary format)
    AUTO = "auto"  # Automatically choose best format

    @property
    def is_binary(self) -> bool:
        """Check if format produces binary output."""
        return self in (SerializationFormat.PICKLE, SerializationFormat.MSGPACK)

    @property
    def is_cross_language(self) -> bool:
        """Check if format is usable across different programming languages."""
        return self in (SerializationFormat.JSON, SerializationFormat.MSGPACK)

    @property
    def supports_complex_types(self) -> bool:
        """Check if format supports complex Python types."""
        return self == SerializationFormat.PICKLE


class EvictionPolicy(Enum):
    """Cache eviction policies for managing cache capacity."""

    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live (expire oldest by time)
    FIFO = "fifo"  # First In First Out
    RANDOM = "random"  # Random eviction

    @property
    def is_time_based(self) -> bool:
        """Check if policy is based on time."""
        return self in (EvictionPolicy.TTL, EvictionPolicy.FIFO)

    @property
    def is_usage_based(self) -> bool:
        """Check if policy is based on usage patterns."""
        return self in (EvictionPolicy.LRU, EvictionPolicy.LFU)

    @property
    def requires_access_tracking(self) -> bool:
        """Check if policy requires tracking access patterns."""
        return self in (EvictionPolicy.LRU, EvictionPolicy.LFU)


# === MONITORING-RELATED ENUMS ===


class MetricType(Enum):
    """Prometheus metric types."""

    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    SUMMARY = "summary"
    INFO = "info"


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def requires_immediate_action(self) -> bool:
        """Check if severity requires immediate action."""
        return self in (AlertSeverity.ERROR, AlertSeverity.CRITICAL)

    @property
    def is_informational(self) -> bool:
        """Check if severity is informational."""
        return self in (AlertSeverity.INFO, AlertSeverity.WARNING)


# === SECURITY-RELATED ENUMS ===


class HashAlgorithm(Enum):
    """Supported password hashing algorithms."""

    ARGON2ID = "argon2id"
    ARGON2I = "argon2i"
    ARGON2D = "argon2d"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    PBKDF2 = "pbkdf2"

    @property
    def is_argon2(self) -> bool:
        """Check if algorithm is an Argon2 variant."""
        return self in (
            HashAlgorithm.ARGON2ID,
            HashAlgorithm.ARGON2I,
            HashAlgorithm.ARGON2D,
        )

    @property
    def is_recommended(self) -> bool:
        """Check if algorithm is currently recommended for new implementations."""
        return self in (
            HashAlgorithm.ARGON2ID,
            HashAlgorithm.BCRYPT,
            HashAlgorithm.SCRYPT,
        )

    @property
    def supports_memory_cost(self) -> bool:
        """Check if algorithm supports memory cost parameters."""
        return self.is_argon2 or self == HashAlgorithm.SCRYPT


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""

    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    AES_128_GCM = "aes-128-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"

    @property
    def is_authenticated(self) -> bool:
        """Check if algorithm provides authenticated encryption."""
        return self in (
            EncryptionAlgorithm.AES_256_GCM,
            EncryptionAlgorithm.AES_128_GCM,
            EncryptionAlgorithm.CHACHA20_POLY1305,
        )

    @property
    def key_size_bits(self) -> int:
        """Get the key size in bits."""
        if "256" in self.value:
            return 256
        if "128" in self.value:
            return 128
        if self == EncryptionAlgorithm.CHACHA20_POLY1305:
            return 256
        return 256  # Default to strongest


class AuthMethod(Enum):
    """Authentication method types."""

    PASSWORD = "password"  # noqa: S105 - Not a password, just an enum value for auth type
    OAUTH2 = "oauth2"
    SAML = "saml"
    MFA = "mfa"
    API_KEY = "api_key"
    JWT = "jwt"
    SESSION = "session"
    CERTIFICATE = "certificate"
    BIOMETRIC = "biometric"

    @property
    def is_single_factor(self) -> bool:
        """Check if method represents single-factor authentication."""
        return self in (AuthMethod.PASSWORD, AuthMethod.API_KEY, AuthMethod.CERTIFICATE)

    @property
    def is_multi_factor(self) -> bool:
        """Check if method represents multi-factor authentication."""
        return self == AuthMethod.MFA

    @property
    def is_token_based(self) -> bool:
        """Check if method uses tokens."""
        return self in (AuthMethod.JWT, AuthMethod.API_KEY, AuthMethod.OAUTH2)

    @property
    def requires_external_provider(self) -> bool:
        """Check if method requires external authentication provider."""
        return self in (AuthMethod.OAUTH2, AuthMethod.SAML)


class PasswordStrength(Enum):
    """Password strength assessment levels."""

    VERY_WEAK = ("very_weak", 0)
    WEAK = ("weak", 25)
    MEDIUM = ("medium", 50)
    STRONG = ("strong", 75)
    VERY_STRONG = ("very_strong", 100)

    def __init__(self, level: str, score: int):
        self.level = level
        self.score = score

    @classmethod
    def from_score(cls, score: int) -> "PasswordStrength":
        """Get password strength from numeric score."""
        if score >= 90:
            return cls.VERY_STRONG
        if score >= 70:
            return cls.STRONG
        if score >= 50:
            return cls.MEDIUM
        if score >= 25:
            return cls.WEAK
        return cls.VERY_WEAK

    @property
    def is_acceptable(self) -> bool:
        """Check if password strength is acceptable for production use."""
        return self.score >= 50

    @property
    def meets_security_policy(self) -> bool:
        """Check if strength meets typical security policy requirements."""
        return self.score >= 75


class SecurityLevel(Enum):
    """Security requirement levels for different operations."""

    PUBLIC = ("public", 0)
    LOW = ("low", 25)
    MEDIUM = ("medium", 50)
    HIGH = ("high", 75)
    CRITICAL = ("critical", 100)

    def __init__(self, level: str, score: int):
        self.level = level
        self.score = score

    @property
    def requires_authentication(self) -> bool:
        """Check if security level requires user authentication."""
        return self.score > 0

    @property
    def requires_mfa(self) -> bool:
        """Check if security level requires multi-factor authentication."""
        return self.score >= 75

    @property
    def requires_audit_logging(self) -> bool:
        """Check if security level requires audit logging."""
        return self.score >= 50

    @property
    def allows_caching(self) -> bool:
        """Check if security level allows response caching."""
        return self.score < 75


class MFAType(Enum):
    """Multi-factor authentication types."""

    SMS = "sms"
    EMAIL = "email"
    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, etc.)
    HOTP = "hotp"  # HMAC-based One-Time Password
    HARDWARE_TOKEN = "hardware_token"  # noqa: S105 - Not a password, just an enum value for MFA type
    PUSH_NOTIFICATION = "push_notification"
    BIOMETRIC = "biometric"
    BACKUP_CODES = "backup_codes"

    @property
    def is_time_based(self) -> bool:
        """Check if MFA type is time-based."""
        return self == MFAType.TOTP

    @property
    def is_device_bound(self) -> bool:
        """Check if MFA type is bound to a specific device."""
        return self in (
            MFAType.TOTP,
            MFAType.HARDWARE_TOKEN,
            MFAType.PUSH_NOTIFICATION,
            MFAType.BIOMETRIC,
        )

    @property
    def is_phishing_resistant(self) -> bool:
        """Check if MFA type is resistant to phishing attacks."""
        return self in (
            MFAType.HARDWARE_TOKEN,
            MFAType.BIOMETRIC,
            MFAType.PUSH_NOTIFICATION,
        )

    @property
    def requires_network(self) -> bool:
        """Check if MFA type requires network connectivity."""
        return self in (MFAType.SMS, MFAType.EMAIL, MFAType.PUSH_NOTIFICATION)


class SessionType(Enum):
    """User session types."""

    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    ADMIN = "admin"
    SERVICE = "service"
    TEMPORARY = "temporary"

    @property
    def is_interactive(self) -> bool:
        """Check if session type is for interactive users."""
        return self in (SessionType.WEB, SessionType.MOBILE, SessionType.ADMIN)

    @property
    def is_machine_to_machine(self) -> bool:
        """Check if session type is for machine-to-machine communication."""
        return self in (SessionType.API, SessionType.SERVICE)

    @property
    def requires_elevated_security(self) -> bool:
        """Check if session type requires elevated security measures."""
        return self in (SessionType.ADMIN, SessionType.SERVICE)

    @property
    def supports_long_duration(self) -> bool:
        """Check if session type supports long-duration sessions."""
        return self in (SessionType.API, SessionType.SERVICE)


class SecurityEventType(Enum):
    """Security event types for audit logging."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"  # noqa: S105 - Not a password, just an enum value for audit action
    PASSWORD_RESET = "password_reset"  # noqa: S105 - Not a password, just an enum value for audit action
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"

    @property
    def is_authentication_event(self) -> bool:
        """Check if event is related to authentication."""
        return self in (
            SecurityEventType.LOGIN_SUCCESS,
            SecurityEventType.LOGIN_FAILURE,
            SecurityEventType.LOGOUT,
            SecurityEventType.MFA_ENABLED,
            SecurityEventType.MFA_DISABLED,
        )

    @property
    def is_authorization_event(self) -> bool:
        """Check if event is related to authorization."""
        return self in (
            SecurityEventType.PERMISSION_GRANTED,
            SecurityEventType.PERMISSION_REVOKED,
        )

    @property
    def is_data_event(self) -> bool:
        """Check if event is related to data access or modification."""
        return self in (
            SecurityEventType.DATA_ACCESS,
            SecurityEventType.DATA_MODIFICATION,
        )

    @property
    def requires_immediate_attention(self) -> bool:
        """Check if event requires immediate security attention."""
        return self in (
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            SecurityEventType.SECURITY_VIOLATION,
            SecurityEventType.ACCOUNT_LOCKED,
        )


class ThreatLevel(Enum):
    """Threat assessment levels."""

    MINIMAL = ("minimal", 10)
    LOW = ("low", 25)
    MEDIUM = ("medium", 50)
    HIGH = ("high", 75)
    CRITICAL = ("critical", 90)
    SEVERE = ("severe", 100)

    def __init__(self, level: str, score: int):
        self.level = level
        self.score = score

    @property
    def requires_immediate_action(self) -> bool:
        """Check if threat level requires immediate action."""
        return self.score >= 75

    @property
    def triggers_alerting(self) -> bool:
        """Check if threat level should trigger security alerts."""
        return self.score >= 50

    @property
    def allows_automatic_mitigation(self) -> bool:
        """Check if threat level allows automatic mitigation measures."""
        return self.score >= 25


class AccessLevel(Enum):
    """Access permission levels."""

    NONE = ("none", 0)
    READ = ("read", 25)
    WRITE = ("write", 50)
    ADMIN = ("admin", 75)
    OWNER = ("owner", 100)

    def __init__(self, level: str, score: int):
        self.level = level
        self.score = score

    @property
    def can_read(self) -> bool:
        """Check if access level allows read operations."""
        return self.score >= 25

    @property
    def can_write(self) -> bool:
        """Check if access level allows write operations."""
        return self.score >= 50

    @property
    def can_admin(self) -> bool:
        """Check if access level allows administrative operations."""
        return self.score >= 75

    @property
    def can_transfer_ownership(self) -> bool:
        """Check if access level allows transferring ownership."""
        return self.score >= 100

    def includes(self, other: "AccessLevel") -> bool:
        """Check if this access level includes another level."""
        return self.score >= other.score


# Utility functions for enum operations
def get_enum_values(enum_class: type[Enum]) -> list[str]:
    """Get all enum values as a list."""
    return [member.value for member in enum_class]


def get_enum_display_names(enum_class: type[Enum]) -> dict[str, str]:
    """Get mapping of enum values to display names."""
    result = {}
    for member in enum_class:
        if hasattr(member, 'get_display_name'):
            result[member.value] = member.get_display_name()
        else:
            result[member.value] = member.value.title()
    return result


def validate_enum_value(enum_class: type[Enum], value: str) -> bool:
    """Validate if a value is valid for the given enum."""
    try:
        enum_class(value)
    except ValueError:
        return False
    else:
        return True


def get_enum_by_value(enum_class: type[Enum], value: str) -> Enum | None:
    """Get enum member by value, returns None if not found."""
    try:
        return enum_class(value)
    except ValueError:
        return None


__all__ = [
    "APIDocumentationFormat",
    "AccessLevel",
    "AlertSeverity",
    "AuthMethod",
    # Cache-related enums
    "CacheBackendType",
    "CacheStrategy",
    "EncryptionAlgorithm",
    # Core application enums
    "Environment",
    "EvictionPolicy",
    # Security-related enums
    "HashAlgorithm",
    "HealthStatus",
    "JWTAlgorithm",
    "LogFormat",
    "LogLevel",
    "MFAType",
    # Monitoring-related enums
    "MetricType",
    "PasswordStrength",
    # Database enums
    "PoolType",
    "Provider",
    "SecurityEventType",
    "SecurityLevel",
    "SerializationFormat",
    # Dependency injection enums
    "ServiceLifetime",
    "ServiceState",
    "SessionType",
    "ThreatLevel",
    "ValidationSeverity",
    "get_enum_by_value",
    "get_enum_display_names",
    # Utility functions
    "get_enum_values",
    "validate_enum_value",
]
