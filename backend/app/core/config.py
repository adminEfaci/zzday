"""Application configuration management following pure Python principles.

This module provides comprehensive configuration management for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are
framework-agnostic and use validated configuration loading.

The configuration system handles environment variables, validation, type conversion,
and provides structured access to all application settings with comprehensive
error handling and security features.

Design Principles:
- Pure Python classes with explicit validation using utils/validation.py
- Framework-agnostic design for maximum portability
- No circular dependencies (ValidationError is the only import from core)
- Environment-specific configuration management
- Security-focused credential handling
- Rich error handling and logging
- Performance optimizations with caching

Architecture:
- EnvironmentLoader: Environment variable loading using validation utilities
- SecurityConfig: Security-specific configuration with validation
- DatabaseConfig: Database connection configuration with comprehensive validation
- CacheConfig: Cache and Redis configuration with strategy support
- CachePolicy: Cache behavior configuration and policies
- MetricsConfig: Monitoring and metrics configuration
- APIDocumentationConfig: API documentation configuration
- Settings: Main configuration class with all application settings
"""

import os
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from functools import lru_cache
from typing import Any

try:
    from app.config.api_docs import APIDocumentationConfig
except ImportError:
    # Fallback implementation
    from dataclasses import dataclass
    
    @dataclass
    class APIDocumentationConfig:
        cache_enabled: bool = True
        include_examples: bool = True
        include_security_analysis: bool = False
        max_path_length: int = 100
        output_directory: str = "docs/api"
        generation_timeout: int = 300
# Import from utils/shared modules for better modularity
try:
    from app.core.enums import (
        CacheBackendType,
        CacheStrategy,
        EncryptionAlgorithm,
        Environment,
        EvictionPolicy,
        HashAlgorithm,
        JWTAlgorithm,
        LogLevel,
        PoolType,
        Provider,
        SerializationFormat,
    )
except ImportError:
    # Fallback local definitions
    from enum import Enum
    
    class Environment(Enum):
        DEVELOPMENT = "development"
        TESTING = "testing"
        STAGING = "staging"
        PRODUCTION = "production"
    
    class LogLevel(Enum):
        DEBUG = 10
        INFO = 20
        WARNING = 30
        ERROR = 40
        CRITICAL = 50
    
    class HashAlgorithm(Enum):
        ARGON2ID = "argon2id"
        BCRYPT = "bcrypt"
        SCRYPT = "scrypt"
    
    class JWTAlgorithm(Enum):
        HS256 = "HS256"
        HS384 = "HS384"
        HS512 = "HS512"
        RS256 = "RS256"
    
    class EncryptionAlgorithm(Enum):
        AES_256_GCM = "aes_256_gcm"
        AES_256_CBC = "aes_256_cbc"
        CHACHA20_POLY1305 = "chacha20_poly1305"
    
    class CacheBackendType(Enum):
        MEMORY = "memory"
        REDIS = "redis"
        MEMCACHED = "memcached"
        HYBRID = "hybrid"
        
        @property
        def is_distributed(self) -> bool:
            return self in {self.REDIS, self.MEMCACHED}
    
    class CacheStrategy(Enum):
        NO_CACHE = "no_cache"
        CACHE_ASIDE = "cache_aside"
        WRITE_THROUGH = "write_through"
        WRITE_BEHIND = "write_behind"
        REFRESH_AHEAD = "refresh_ahead"
        
        @property
        def requires_storage_backend(self) -> bool:
            return self in {self.WRITE_BEHIND, self.REFRESH_AHEAD}
        
        @property
        def provides_strong_consistency(self) -> bool:
            return self in {self.WRITE_THROUGH, self.WRITE_BEHIND}
    
    class EvictionPolicy(Enum):
        LRU = "lru"
        LFU = "lfu"
        FIFO = "fifo"
        LIFO = "lifo"
        TTL = "ttl"
        RANDOM = "random"
        
        @property
        def requires_access_tracking(self) -> bool:
            return self in {self.LRU, self.LFU}
    
    class SerializationFormat(Enum):
        JSON = "json"
        PICKLE = "pickle"
        MSGPACK = "msgpack"
        AUTO = "auto"
    
    class PoolType(Enum):
        QUEUE_POOL = "queue_pool"
        NULL_POOL = "null_pool"
        STATIC_POOL = "static_pool"
    
    class Provider(Enum):
        SENDGRID = "sendgrid"
        TWILIO = "twilio"
        S3 = "s3"
        SMTP = "smtp"
        SES = "ses"

# Only import ValidationError from core to avoid circular dependencies
from app.core.errors import ConfigurationError

# Import policy-related enums
try:
    from app.modules.identity.domain.enums import MFAMethod, RiskLevel, UserRole
except ImportError:
    # Fallback definitions for policy enums
    from enum import Enum
    
    class MFAMethod(Enum):
        TOTP = "totp"
        SMS = "sms"
        EMAIL = "email"
        HARDWARE_KEY = "hardware_key"
        BACKUP_CODE = "backup_code"
        API_KEY = "api_key"
        CERTIFICATE = "certificate"
    
    class RiskLevel(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class UserRole(Enum):
        USER = "user"
        ADMIN = "admin"
        SUPER_ADMIN = "super_admin"
        SERVICE = "service"

# Import validation utilities (no circular dependency)
try:
    from app.utils.validation import (
        validate_boolean,
        validate_email,
        validate_enum,
        validate_float,
        validate_integer,
        validate_list,
        validate_string,
        validate_url,
    )
except ImportError:
    # Fallback validation functions
    def validate_string(value, key, required=False, **kwargs):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        return str(value)
    
    def validate_integer(value, key, required=False, min_value=None, max_value=None, **kwargs):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        val = int(value)
        if min_value is not None and val < min_value:
            raise ConfigurationError(f"{key} must be >= {min_value}")
        if max_value is not None and val > max_value:
            raise ConfigurationError(f"{key} must be <= {max_value}")
        return val
    
    def validate_float(value, key, required=False, min_value=None, max_value=None, **kwargs):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        val = float(value)
        if min_value is not None and val < min_value:
            raise ConfigurationError(f"{key} must be >= {min_value}")
        if max_value is not None and val > max_value:
            raise ConfigurationError(f"{key} must be <= {max_value}")
        return val
    
    def validate_boolean(value, key, required=False):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    
    
    def validate_url(value, key, required=False, **kwargs):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        # Basic URL validation
        if not value.startswith(('http://', 'https://', 'redis://', 'postgresql://')):
            raise ConfigurationError(f"{key} must be a valid URL")
        return value
    
    def validate_email(value, key, required=False):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        # Basic email validation
        if '@' not in value or '.' not in value.split('@')[1]:
            raise ConfigurationError(f"{key} must be a valid email")
        return value
    
    def validate_list(value, key, required=False, **kwargs):
        if value is None and not required:
            return None
        if value is None and required:
            raise ConfigurationError(f"{key} is required")
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        return list(value)

# =====================================================================================
# ENVIRONMENT LOADER
# =====================================================================================


class EnvironmentLoader:
    """
    Environment variable loader with type conversion and validation.

    Provides framework-agnostic environment variable loading using the validation
    utilities from app.utils.validation, with automatic type conversion and
    sensible defaults.

    Design Features:
    - Uses validation utilities (no circular dependencies)
    - Comprehensive type conversion
    - Default value handling
    - Environment file support
    - Clear error messages
    """

    def __init__(self, env_file: str = ".env"):
        """
        Initialize environment loader.

        Args:
            env_file: Optional environment file to load
        """
        self.env_file = env_file
        self._load_env_file()

    def _load_env_file(self) -> None:
        """Load environment variables from file if it exists."""
        if not os.path.exists(self.env_file):
            return

        try:
            with open(self.env_file, encoding="utf-8") as f:
                for _line_num, raw_line in enumerate(f, 1):
                    line = raw_line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Parse key=value pairs
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip()

                        # Remove quotes if present
                        if (value.startswith('"') and value.endswith('"')) or (
                            value.startswith("'") and value.endswith("'")
                        ):
                            value = value[1:-1]

                        # Only set if not already in environment
                        if key not in os.environ:
                            os.environ[key] = value

        except Exception as e:
            raise ConfigurationError(
                f"Failed to load environment file {self.env_file}: {e}"
            ) from e

    def get_string(
        self, key: str, default: str | None = None, required: bool = False, **kwargs
    ) -> str | None:
        """Get string value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_string(value, key, required, **kwargs)

    def get_integer(
        self, key: str, default: int | None = None, required: bool = False, **kwargs
    ) -> int | None:
        """Get integer value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_integer(value, key, required, **kwargs)

    def get_float(
        self, key: str, default: float | None = None, required: bool = False, **kwargs
    ) -> float | None:
        """Get float value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_float(value, key, required, **kwargs)

    def get_boolean(
        self, key: str, default: bool | None = None, required: bool = False
    ) -> bool | None:
        """Get boolean value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_boolean(value, key, required)

    def get_enum(
        self,
        key: str,
        enum_class: type[Enum],
        default: Enum | None = None,
        required: bool = False,
    ) -> Enum | None:
        """Get enum value from environment using validation utilities."""
        value = os.environ.get(key, default.value if default else None)
        from app.utils.validation import ConfigValidationUtils
        return ConfigValidationUtils.validate_enum(value, enum_class, key, required)

    def get_url(
        self, key: str, default: str | None = None, required: bool = False, **kwargs
    ) -> str | None:
        """Get URL value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_url(value, key, required, **kwargs)

    def get_email(
        self, key: str, default: str | None = None, required: bool = False
    ) -> str | None:
        """Get email value from environment using validation utilities."""
        value = os.environ.get(key, default)
        return validate_email(value, key, required)

    def get_list(
        self,
        key: str,
        default: list[Any] | None = None,
        required: bool = False,
        **kwargs,
    ) -> list[Any] | None:
        """Get list value from environment using validation utilities."""
        value = os.environ.get(key)
        if value is None:
            value = default
        return validate_list(value, key, required=required, **kwargs)


# =====================================================================================
# POLICY CONFIGURATION CLASSES
# =====================================================================================


class PolicyEnvironment(Enum):
    """Policy environment types."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class PasswordPolicyConfig:
    """Password policy configuration."""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    history_limit: int = 24
    min_age_hours: int = 1
    max_age_days: int = 90
    complexity_score_threshold: float = 0.6
    min_unique_chars: int = 4
    max_repeated_chars: int = 3
    forbidden_patterns: list[str] = field(default_factory=lambda: [
        "password", "123456", "qwerty", "admin", "user"
    ])
    require_non_sequential: bool = True


@dataclass
class SessionPolicyConfig:
    """Session policy configuration."""
    absolute_timeout_minutes: int = 480  # 8 hours
    idle_timeout_minutes: int = 30
    max_concurrent_sessions: int = 5
    max_sessions_per_device: int = 2
    max_sessions_per_ip: int = 3
    require_trusted_device_for_admin: bool = True
    session_extension_threshold: float = 0.7
    risk_threshold_for_additional_auth: float = 0.6
    
    # Type-specific timeouts
    timeout_by_type: dict[str, int] = field(default_factory=lambda: {
        "web": 480,      # 8 hours
        "mobile": 43200, # 30 days
        "api": 1440,     # 24 hours
        "admin": 240,    # 4 hours
        "service": 525600 # 1 year
    })


@dataclass
class MFAPolicyConfig:
    """MFA policy configuration."""
    require_for_admin: bool = True
    require_for_high_risk: bool = True
    require_for_service_accounts: bool = True
    enforce_for_all: bool = False
    grace_period_days: int = 30
    min_active_devices: int = 1
    require_backup_method: bool = True
    require_method_diversity: bool = False
    min_unique_methods: int = 2
    risk_score_threshold: float = 0.7
    adaptive_mfa_enabled: bool = True
    
    # Role-specific requirements
    role_requirements: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        "admin": {"required": True, "allowed_methods": ["totp", "hardware_key", "backup_code"]},
        "super_admin": {"required": True, "allowed_methods": ["hardware_key", "backup_code"]},
        "service": {"required": True, "allowed_methods": ["api_key", "certificate"]}
    })
    
    # Sensitive permissions requiring MFA
    sensitive_permissions: list[str] = field(default_factory=lambda: [
        "delete_user", "grant_permission", "system_admin", "modify_roles",
        "access_audit_logs", "system_config", "financial_access"
    ])


@dataclass
class LockoutPolicyConfig:
    """Account lockout policy configuration."""
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    progressive_lockout_enabled: bool = True
    max_attempts_per_minute: int = 10
    max_attempts_per_ip_per_hour: int = 20
    ip_block_duration_hours: int = 24
    
    # Progressive lockout thresholds
    progressive_thresholds: list[dict[str, int]] = field(default_factory=lambda: [
        {"lockout_count": 3, "duration_minutes": 60},
        {"lockout_count": 5, "duration_minutes": 240},
        {"lockout_count": 10, "duration_minutes": 1440}  # 24 hours
    ])


@dataclass
class RiskPolicyConfig:
    """Risk assessment policy configuration."""
    low_risk_threshold: float = 0.3
    medium_risk_threshold: float = 0.6
    high_risk_threshold: float = 0.8
    require_mfa_above_score: float = 0.5
    block_above_score: float = 0.9
    alert_security_team_above: float = 0.7
    
    # Risk factor weights
    risk_weights: dict[str, float] = field(default_factory=lambda: {
        "new_device": 0.2,
        "new_location": 0.15,
        "unusual_time": 0.1,
        "rapid_location_change": 0.4,
        "high_risk_country": 0.3,
        "vpn_detected": 0.25,
        "tor_detected": 0.5,
        "multiple_failed_attempts": 0.35,
        "credential_stuffing_pattern": 0.6,
        "account_age": 0.1,
        "unusual_behavior": 0.3
    })
    
    # High risk countries (ISO codes)
    high_risk_countries: list[str] = field(default_factory=lambda: [
        'KP', 'IR', 'SY', 'CU', 'VE'
    ])


@dataclass
class CompliancePolicyConfig:
    """Compliance policy configuration."""
    minimum_age: int = 13
    parental_consent_age: int = 16
    require_explicit_consent: bool = True
    allow_consent_withdrawal: bool = True
    data_portability_enabled: bool = True
    right_to_deletion_enabled: bool = True
    automated_data_minimization: bool = True
    
    # Data retention periods (in days)
    retention_periods: dict[str, int] = field(default_factory=lambda: {
        "basic_identity": 365 * 7,  # 7 years
        "contact_info": 365 * 7,
        "authentication": 365 * 2,  # 2 years
        "financial": 365 * 7,
        "behavioral": 365 * 2,
        "biometric": 90,
        "location": 180,
        "device": 365,
        "sensitive": 30
    })


@dataclass
class PolicyConfiguration:
    """Master policy configuration."""
    environment: PolicyEnvironment = PolicyEnvironment.PRODUCTION
    version: str = "1.0.0"
    
    # Individual policy configs
    password: PasswordPolicyConfig = field(default_factory=PasswordPolicyConfig)
    session: SessionPolicyConfig = field(default_factory=SessionPolicyConfig)
    mfa: MFAPolicyConfig = field(default_factory=MFAPolicyConfig)
    lockout: LockoutPolicyConfig = field(default_factory=LockoutPolicyConfig)
    risk: RiskPolicyConfig = field(default_factory=RiskPolicyConfig)
    compliance: CompliancePolicyConfig = field(default_factory=CompliancePolicyConfig)
    
    # Global settings
    strict_mode: bool = True
    audit_all_violations: bool = True
    fail_open_on_policy_error: bool = False


class PolicyConfigManager:
    """Manages policy configuration with environment-specific overrides."""
    
    def __init__(self, environment: PolicyEnvironment = PolicyEnvironment.PRODUCTION):
        self.environment = environment
        self._config = self._load_base_config()
        self._apply_environment_overrides()
    
    def _load_base_config(self) -> PolicyConfiguration:
        """Load base configuration."""
        return PolicyConfiguration(environment=self.environment)
    
    def _apply_environment_overrides(self) -> None:
        """Apply environment-specific configuration overrides."""
        if self.environment == PolicyEnvironment.DEVELOPMENT:
            self._apply_development_overrides()
        elif self.environment == PolicyEnvironment.TESTING:
            self._apply_testing_overrides()
        elif self.environment == PolicyEnvironment.STAGING:
            self._apply_staging_overrides()
    
    def _apply_development_overrides(self) -> None:
        """Apply development environment overrides."""
        # Relaxed password requirements for development
        self._config.password.min_length = 6
        self._config.password.require_special_chars = False
        self._config.password.complexity_score_threshold = 0.3
        
        # Shorter session timeouts for testing
        self._config.session.absolute_timeout_minutes = 60
        self._config.session.idle_timeout_minutes = 15
        
        # Relaxed MFA requirements
        self._config.mfa.grace_period_days = 365
        self._config.mfa.require_for_admin = False
        
        # More lenient lockout policy
        self._config.lockout.max_failed_attempts = 10
        self._config.lockout.progressive_lockout_enabled = False
    
    def _apply_testing_overrides(self) -> None:
        """Apply testing environment overrides."""
        # Fast timeouts for testing
        self._config.session.absolute_timeout_minutes = 5
        self._config.session.idle_timeout_minutes = 2
        
        # Immediate lockout for testing
        self._config.lockout.max_failed_attempts = 3
        self._config.lockout.lockout_duration_minutes = 1
        
        # Strict mode for testing
        self._config.strict_mode = True
        self._config.fail_open_on_policy_error = False
    
    def _apply_staging_overrides(self) -> None:
        """Apply staging environment overrides."""
        # Production-like but with some relaxed settings
        self._config.mfa.grace_period_days = 7
        self._config.risk.alert_security_team_above = 0.8
    
    def get_config(self) -> PolicyConfiguration:
        """Get the current configuration."""
        return self._config
    
    def get_password_config(self) -> PasswordPolicyConfig:
        """Get password policy configuration."""
        return self._config.password
    
    def get_session_config(self) -> SessionPolicyConfig:
        """Get session policy configuration."""
        return self._config.session
    
    def get_mfa_config(self) -> MFAPolicyConfig:
        """Get MFA policy configuration."""
        return self._config.mfa
    
    def get_lockout_config(self) -> LockoutPolicyConfig:
        """Get lockout policy configuration."""
        return self._config.lockout
    
    def get_risk_config(self) -> RiskPolicyConfig:
        """Get risk policy configuration."""
        return self._config.risk
    
    def get_compliance_config(self) -> CompliancePolicyConfig:
        """Get compliance policy configuration."""
        return self._config.compliance
    
    def update_config(self, **kwargs) -> None:
        """Update configuration with provided values."""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "environment": self.environment.value,
            "version": self._config.version,
            "password": self._config.password.__dict__,
            "session": self._config.session.__dict__,
            "mfa": self._config.mfa.__dict__,
            "lockout": self._config.lockout.__dict__,
            "risk": self._config.risk.__dict__,
            "compliance": self._config.compliance.__dict__,
            "strict_mode": self._config.strict_mode,
            "audit_all_violations": self._config.audit_all_violations,
            "fail_open_on_policy_error": self._config.fail_open_on_policy_error
        }


# =====================================================================================
# CONFIGURATION CLASSES
# =====================================================================================


@dataclass
class SecurityConfig:
    """
    Comprehensive security configuration with validation.

    Consolidates all security-related configuration including password hashing,
    JWT tokens, MFA, session management, and encryption settings.
    """

    # Password hashing configuration
    password_algorithm: HashAlgorithm = field(default=HashAlgorithm.ARGON2ID)
    argon2_time_cost: int = field(default=2)
    argon2_memory_cost: int = field(default=65536)  # 64 MB
    argon2_parallelism: int = field(default=1)
    argon2_hash_len: int = field(default=32)
    argon2_salt_len: int = field(default=16)

    # JWT configuration
    access_token_secret: str = field(default=None)
    refresh_token_secret: str = field(default=None)
    access_token_expire_minutes: int = field(default=15)
    refresh_token_expire_days: int = field(default=30)
    jwt_algorithm: JWTAlgorithm = field(default=JWTAlgorithm.HS256)
    jwt_issuer: str = field(default="ezzday")
    jwt_audience: str = field(default="ezzday-users")
    jwt_clock_skew_seconds: int = field(default=30)

    # Token generation configuration
    default_token_bytes: int = field(default=32)
    verification_code_length: int = field(default=6)
    verification_code_expire_minutes: int = field(default=10)

    # Rate limiting and security policies
    max_password_attempts: int = field(default=5)
    password_attempt_window_minutes: int = field(default=15)
    account_lockout_duration_minutes: int = field(default=30)

    # Password policy configuration
    require_strong_passwords: bool = field(default=True)
    min_password_length: int = field(default=8)
    max_password_length: int = field(default=128)
    password_require_uppercase: bool = field(default=True)
    password_require_lowercase: bool = field(default=True)
    password_require_numbers: bool = field(default=True)
    password_require_special_chars: bool = field(default=True)
    password_prevent_common: bool = field(default=True)
    password_prevent_user_info: bool = field(default=True)
    password_history_count: int = field(default=5)
    password_expiry_days: int | None = field(default=None)

    # Session management configuration
    session_timeout_hours: int = field(default=8)
    session_refresh_threshold_hours: int = field(default=1)
    max_concurrent_sessions: int = field(default=5)
    session_cookie_secure: bool = field(default=True)
    session_cookie_httponly: bool = field(default=True)
    session_cookie_samesite: str = field(default="Strict")

    # MFA configuration
    mfa_enabled_by_default: bool = field(default=False)
    mfa_required_for_admin: bool = field(default=True)
    mfa_backup_codes_count: int = field(default=10)
    mfa_totp_window: int = field(default=1)  # Time windows for TOTP validation
    mfa_remember_device_days: int = field(default=30)

    # Encryption configuration
    encryption_algorithm: EncryptionAlgorithm = field(
        default=EncryptionAlgorithm.AES_256_GCM
    )
    encryption_key_rotation_days: int = field(default=90)

    # API security configuration
    api_key_length: int = field(default=32)
    api_key_prefix: str = field(default="ezd_")
    api_rate_limit_enabled: bool = field(default=True)

    # Audit and monitoring configuration
    audit_login_events: bool = field(default=True)
    audit_permission_changes: bool = field(default=True)
    audit_data_access: bool = field(default=True)
    security_event_retention_days: int = field(default=365)

    # Security headers configuration
    enable_security_headers: bool = field(default=True)
    hsts_max_age_seconds: int = field(default=31536000)  # 1 year
    content_security_policy: str | None = field(default=None)

    def __post_init__(self):
        """Validate security configuration after initialization."""
        self._validate_password_config()
        self._validate_jwt_config()
        self._validate_session_config()
        self._validate_mfa_config()
        self._validate_general_config()

    def _validate_password_config(self) -> None:
        """Validate password-related configuration."""
        # Argon2 validation
        if not 1 <= self.argon2_time_cost <= 10:
            raise ConfigurationError("Argon2 time cost must be between 1 and 10")

        if not 8192 <= self.argon2_memory_cost <= 1048576:  # 8 MB - 1 GB
            raise ConfigurationError(
                "Argon2 memory cost must be between 8192 and 1048576 KiB"
            )

        if not 1 <= self.argon2_parallelism <= 8:
            raise ConfigurationError("Argon2 parallelism must be between 1 and 8")

        if not 16 <= self.argon2_hash_len <= 64:
            raise ConfigurationError(
                "Argon2 hash length must be between 16 and 64 bytes"
            )

        if not 8 <= self.argon2_salt_len <= 32:
            raise ConfigurationError(
                "Argon2 salt length must be between 8 and 32 bytes"
            )

        # Password policy validation
        if not 4 <= self.min_password_length <= 32:
            raise ConfigurationError("Minimum password length must be between 4 and 32")

        if not 32 <= self.max_password_length <= 512:
            raise ConfigurationError(
                "Maximum password length must be between 32 and 512"
            )

        if self.min_password_length >= self.max_password_length:
            raise ConfigurationError(
                "Minimum password length must be less than maximum"
            )

        if not 0 <= self.password_history_count <= 24:
            raise ConfigurationError("Password history count must be between 0 and 24")

        if self.password_expiry_days is not None and not 30 <= self.password_expiry_days <= 365:
            raise ConfigurationError(
                "Password expiry must be between 30 and 365 days"
            )

    def _validate_jwt_config(self) -> None:
        """Validate JWT configuration parameters."""
        if not self.access_token_secret:
            raise ConfigurationError("Access token secret is required")

        if not self.refresh_token_secret:
            raise ConfigurationError("Refresh token secret is required")

        if len(self.access_token_secret) < 32:
            raise ConfigurationError(
                "Access token secret must be at least 32 characters"
            )

        if len(self.refresh_token_secret) < 32:
            raise ConfigurationError(
                "Refresh token secret must be at least 32 characters"
            )

        if self.access_token_secret == self.refresh_token_secret:
            raise ConfigurationError(
                "Access and refresh token secrets must be different"
            )

        if not 1 <= self.access_token_expire_minutes <= 1440:  # 1 minute to 1 day
            raise ConfigurationError(
                "Access token expiration must be between 1 and 1440 minutes"
            )

        if not 1 <= self.refresh_token_expire_days <= 365:  # 1 day to 1 year
            raise ConfigurationError(
                "Refresh token expiration must be between 1 and 365 days"
            )

        if not 0 <= self.jwt_clock_skew_seconds <= 300:  # 0 to 5 minutes
            raise ConfigurationError("JWT clock skew must be between 0 and 300 seconds")

    def _validate_session_config(self) -> None:
        """Validate session management configuration."""
        if not 1 <= self.session_timeout_hours <= 168:  # 1 hour to 1 week
            raise ConfigurationError("Session timeout must be between 1 and 168 hours")

        if not 0 <= self.session_refresh_threshold_hours <= self.session_timeout_hours:
            raise ConfigurationError(
                "Session refresh threshold must be less than session timeout"
            )

        if not 1 <= self.max_concurrent_sessions <= 50:
            raise ConfigurationError("Max concurrent sessions must be between 1 and 50")

        valid_samesite_values = ["Strict", "Lax", "None"]
        if self.session_cookie_samesite not in valid_samesite_values:
            raise ConfigurationError(
                f"Session cookie SameSite must be one of: {valid_samesite_values}"
            )

    def _validate_mfa_config(self) -> None:
        """Validate MFA configuration."""
        if not 5 <= self.mfa_backup_codes_count <= 20:
            raise ConfigurationError("MFA backup codes count must be between 5 and 20")

        if not 0 <= self.mfa_totp_window <= 10:
            raise ConfigurationError("MFA TOTP window must be between 0 and 10")

        if not 1 <= self.mfa_remember_device_days <= 365:
            raise ConfigurationError(
                "MFA remember device days must be between 1 and 365"
            )

    def _validate_general_config(self) -> None:
        """Validate general security configuration."""
        if not 16 <= self.default_token_bytes <= 64:
            raise ConfigurationError("Default token bytes must be between 16 and 64")

        if not 4 <= self.verification_code_length <= 12:
            raise ConfigurationError(
                "Verification code length must be between 4 and 12"
            )

        if not 1 <= self.verification_code_expire_minutes <= 60:
            raise ConfigurationError(
                "Verification code expiry must be between 1 and 60 minutes"
            )

        if not 1 <= self.max_password_attempts <= 20:
            raise ConfigurationError("Max password attempts must be between 1 and 20")

        if not 1 <= self.password_attempt_window_minutes <= 1440:
            raise ConfigurationError(
                "Password attempt window must be between 1 and 1440 minutes"
            )

        if not 1 <= self.account_lockout_duration_minutes <= 10080:  # 1 week
            raise ConfigurationError(
                "Account lockout duration must be between 1 and 10080 minutes"
            )

        if not 16 <= self.api_key_length <= 128:
            raise ConfigurationError("API key length must be between 16 and 128")

        if not 1 <= self.security_event_retention_days <= 2555:  # ~7 years
            raise ConfigurationError(
                "Security event retention must be between 1 and 2555 days"
            )

        if not 86400 <= self.hsts_max_age_seconds <= 63072000:  # 1 day to 2 years
            raise ConfigurationError(
                "HSTS max age must be between 86400 and 63072000 seconds"
            )

    def get_password_policy(self) -> dict[str, Any]:
        """Get password policy configuration as dictionary."""
        return {
            "min_length": self.min_password_length,
            "max_length": self.max_password_length,
            "require_uppercase": self.password_require_uppercase,
            "require_lowercase": self.password_require_lowercase,
            "require_numbers": self.password_require_numbers,
            "require_special_chars": self.password_require_special_chars,
            "prevent_common_passwords": self.password_prevent_common,
            "prevent_user_info": self.password_prevent_user_info,
            "history_count": self.password_history_count,
            "expiry_days": self.password_expiry_days,
        }

    def get_session_config(self) -> dict[str, Any]:
        """Get session configuration as dictionary."""
        return {
            "timeout_hours": self.session_timeout_hours,
            "refresh_threshold_hours": self.session_refresh_threshold_hours,
            "max_concurrent": self.max_concurrent_sessions,
            "cookie_secure": self.session_cookie_secure,
            "cookie_httponly": self.session_cookie_httponly,
            "cookie_samesite": self.session_cookie_samesite,
        }

    def get_mfa_config(self) -> dict[str, Any]:
        """Get MFA configuration as dictionary."""
        return {
            "enabled_by_default": self.mfa_enabled_by_default,
            "required_for_admin": self.mfa_required_for_admin,
            "backup_codes_count": self.mfa_backup_codes_count,
            "totp_window": self.mfa_totp_window,
            "remember_device_days": self.mfa_remember_device_days,
        }


@dataclass
class DatabaseConfig:
    """
    Database configuration with comprehensive validation and environment-specific defaults.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Environment-specific configuration defaults
    - Comprehensive connection parameter management
    - Security-focused credential handling
    - Performance tuning options
    - Framework-agnostic implementation

    Usage Example:
        config = DatabaseConfig(
            url="postgresql+asyncpg://user:pass@localhost/db",
            environment=Environment.PRODUCTION,
            pool_size=20,
            max_overflow=40
        )

        # Validate configuration
        config.validate()

        # Get environment-specific settings
        pool_class = config.get_pool_class()
    """

    # Core connection settings
    url: str
    environment: Environment = field(default=Environment.DEVELOPMENT)

    # Pool configuration
    pool_type: PoolType = field(default=PoolType.QUEUE_POOL)
    pool_size: int = field(default=10)
    max_overflow: int = field(default=20)
    pool_timeout: int = field(default=30)
    pool_recycle: int = field(default=3600)  # 1 hour
    pool_pre_ping: bool = field(default=True)

    # Connection settings
    connect_timeout: int = field(default=10)
    command_timeout: int = field(default=60)
    query_timeout: int = field(default=30)

    # Performance settings
    echo: bool = field(default=False)
    echo_pool: bool = field(default=False)
    enable_logging: bool = field(default=True)

    # Health check settings
    health_check_interval: int = field(default=60)  # seconds
    max_health_check_failures: int = field(default=3)
    health_check_timeout: int = field(default=5)

    # Retry settings
    max_retries: int = field(default=3)
    retry_delay: float = field(default=1.0)
    exponential_backoff: bool = field(default=True)

    def __post_init__(self):
        """Post-initialization validation and setup."""
        self.validate()
        self._apply_environment_defaults()

    def validate(self) -> None:
        """
        Validate database configuration parameters.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate URL
        if not self.url or not isinstance(self.url, str):
            raise ConfigurationError("Database URL is required and must be a string")

        if not self.url.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite://")):
            raise ConfigurationError(
                "Database URL must use async driver (asyncpg or aiosqlite)"
            )

        # Validate pool settings
        if self.pool_size < 1:
            raise ConfigurationError("Pool size must be at least 1")

        if self.max_overflow < 0:
            raise ConfigurationError("Max overflow cannot be negative")

        if self.pool_timeout < 1:
            raise ConfigurationError("Pool timeout must be at least 1 second")

        # Validate timeout settings
        if self.connect_timeout < 1:
            raise ConfigurationError("Connect timeout must be at least 1 second")

        if self.command_timeout < 1:
            raise ConfigurationError("Command timeout must be at least 1 second")

        # Validate health check settings
        if self.health_check_interval < 10:
            raise ConfigurationError(
                "Health check interval must be at least 10 seconds"
            )

        if self.max_health_check_failures < 1:
            raise ConfigurationError("Max health check failures must be at least 1")

    def _apply_environment_defaults(self) -> None:
        """Apply environment-specific defaults."""
        if self.environment == Environment.TESTING:
            # Test environment: No pooling, faster timeouts
            self.pool_type = PoolType.NULL_POOL
            self.pool_size = 1
            self.max_overflow = 0
            self.pool_timeout = 5
            self.connect_timeout = 5
            self.health_check_interval = 30

        elif self.environment == Environment.PRODUCTION:
            # Production environment: Conservative settings
            self.pool_size = max(self.pool_size, 20)
            self.max_overflow = max(self.max_overflow, 40)
            self.pool_timeout = max(self.pool_timeout, 30)
            self.pool_recycle = 3600  # 1 hour
            self.health_check_interval = 60

        elif self.environment == Environment.STAGING:
            # Staging environment: Production-like but smaller
            self.pool_size = max(self.pool_size, 10)
            self.max_overflow = max(self.max_overflow, 20)
            self.health_check_interval = 45

    def get_pool_class(self) -> str:
        """
        Get SQLAlchemy pool class name based on configuration.

        Returns:
            str: Pool class name for SQLAlchemy engine
        """
        if self.pool_type == PoolType.NULL_POOL:
            return "NullPool"
        if self.pool_type == PoolType.STATIC_POOL:
            return "StaticPool"
        return "QueuePool"

    def get_engine_kwargs(self) -> dict[str, Any]:
        """
        Get engine configuration parameters.

        Returns:
            dict[str, Any]: Engine configuration
        """
        return {
            "echo": self.echo,
            "echo_pool": self.echo_pool,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout,
            "pool_recycle": self.pool_recycle,
            "pool_pre_ping": self.pool_pre_ping,
            "poolclass": self.get_pool_class(),
            "future": True,
            "connect_args": {
                "command_timeout": self.command_timeout,
                "server_settings": {
                    "application_name": "ezzday_backend",
                    "statement_timeout": f"{self.query_timeout}s",
                },
            },
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary (excluding sensitive data)."""
        # Mask credentials in URL
        safe_url = self.url
        if "@" in safe_url:
            parts = safe_url.split("@")
            if len(parts) >= 2:
                # Replace credentials with masked version
                credential_part = parts[0].split("://")[-1]
                if ":" in credential_part:
                    user = credential_part.split(":")[0]
                    safe_url = safe_url.replace(credential_part, f"{user}:***")

        return {
            "url": safe_url,
            "environment": self.environment.value,
            "pool_type": self.pool_type.value,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout,
            "pool_recycle": self.pool_recycle,
            "connect_timeout": self.connect_timeout,
            "command_timeout": self.command_timeout,
            "query_timeout": self.query_timeout,
            "health_check_interval": self.health_check_interval,
            "max_health_check_failures": self.max_health_check_failures,
        }


@dataclass
class CachePolicy:
    """
    Cache behavior configuration and policies.

    Defines how the cache should behave including TTL, eviction policies,
    serialization preferences, and performance settings.
    """

    # Basic settings
    default_ttl: timedelta | None = field(default_factory=lambda: timedelta(minutes=15))
    max_key_length: int = 250
    max_value_size: int = 1024 * 1024  # 1MB

    # Serialization
    serialization_format: SerializationFormat = SerializationFormat.AUTO
    compress_threshold: int = 1024  # Compress values larger than this

    # Eviction and capacity
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    max_entries: int | None = 10000
    memory_limit: int | None = None  # Bytes

    # Performance settings
    enable_compression: bool = True
    enable_encryption: bool = False
    batch_size: int = 100
    connection_timeout: int = 5

    # Monitoring
    track_statistics: bool = True
    enable_metrics: bool = True
    log_cache_events: bool = False

    def __post_init__(self):
        """Validate policy configuration."""
        if self.max_key_length < 1:
            raise ConfigurationError("Max key length must be positive")

        if self.max_value_size < 1:
            raise ConfigurationError("Max value size must be positive")

        if self.max_entries is not None and self.max_entries < 1:
            raise ConfigurationError("Max entries must be positive")

        # Validate eviction policy requirements
        if self.eviction_policy.requires_access_tracking and not self.track_statistics:
            # Import here to avoid circular dependency at module level
            from app.core.logging import get_logger

            logger = get_logger(__name__)
            logger.warning(
                f"Eviction policy {self.eviction_policy.value} requires access tracking, "
                "enabling track_statistics"
            )
            self.track_statistics = True


@dataclass
class CacheConfig:
    """
    Cache configuration for different backends with strategy support.

    Provides configuration for all supported cache backends with
    connection settings, authentication, and backend-specific options.
    Now includes high-level caching strategy configuration.
    """

    # Backend selection
    backend_type: CacheBackendType = CacheBackendType.MEMORY
    fallback_backend: CacheBackendType | None = None

    # Cache strategy configuration
    cache_strategy: CacheStrategy = CacheStrategy.CACHE_ASIDE

    # Redis configuration
    redis_url: str | None = None
    redis_password: str | None = None
    redis_db: int = 0
    redis_pool_size: int = 10
    redis_timeout: int = 5

    # Memcached configuration
    memcached_servers: list[str] = field(default_factory=list)
    memcached_timeout: int = 5

    # Memory cache configuration
    memory_max_size: int = 100 * 1024 * 1024  # 100MB
    memory_cleanup_interval: int = 300  # 5 minutes

    # Common settings
    key_prefix: str = "ezzday"
    namespace_separator: str = ":"
    enable_health_checks: bool = True
    health_check_interval: int = 60

    def __post_init__(self):
        """Validate configuration after initialization."""
        # Validate cache strategy compatibility
        if self.cache_strategy == CacheStrategy.NO_CACHE:
            # No cache strategy doesn't need backend validation
            from app.core.logging import get_logger

            logger = get_logger(__name__)
            logger.info("Cache strategy set to NO_CACHE, caching will be disabled")
            return

        # Validate backend and strategy compatibility
        if self.backend_type == CacheBackendType.MEMORY and self.cache_strategy in (
            CacheStrategy.WRITE_BEHIND,
            CacheStrategy.REFRESH_AHEAD,
        ):
            # Memory backend has limitations with some strategies
            raise ConfigurationError(
                f"Memory backend doesn't support {self.cache_strategy.value} strategy. "
                f"Consider using CACHE_ASIDE or WRITE_THROUGH instead."
            )

        # Validate Redis configuration if Redis backend is selected
        if self.backend_type == CacheBackendType.REDIS and not self.redis_url:
            raise ConfigurationError("Redis URL required when using Redis backend")

        # Validate Memcached configuration
        if self.backend_type == CacheBackendType.MEMCACHED and not self.memcached_servers:
            raise ConfigurationError(
                "Memcached servers required when using Memcached backend"
            )

        # Validate hybrid configuration
        if self.backend_type == CacheBackendType.HYBRID:
            if not self.fallback_backend:
                raise ConfigurationError(
                    "Fallback backend required when using Hybrid backend"
                )

            if self.fallback_backend == self.backend_type:
                raise ConfigurationError(
                    "Fallback backend cannot be the same as primary backend"
                )

        # Validate strategy requirements
        if (
            self.cache_strategy.requires_storage_backend
            and self.backend_type == CacheBackendType.MEMORY
        ):
            from app.core.logging import get_logger

            logger = get_logger(__name__)
            logger.warning(
                f"Cache strategy {self.cache_strategy.value} typically requires persistent storage, "
                f"but using memory backend. Consider Redis for better persistence."
            )

    @property
    def requires_persistent_storage(self) -> bool:
        """Check if configuration requires persistent storage backend."""
        return self.cache_strategy.requires_storage_backend

    @property
    def supports_distributed_caching(self) -> bool:
        """Check if configuration supports distributed caching."""
        return self.backend_type.is_distributed

    @property
    def is_caching_enabled(self) -> bool:
        """Check if caching is enabled."""
        return self.cache_strategy != CacheStrategy.NO_CACHE


@dataclass
class MetricsConfig:
    """
    Monitoring and metrics configuration with comprehensive validation.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Environment-specific configuration defaults
    - Security-focused metric collection
    - Performance optimization settings
    - Framework-agnostic implementation

    Usage Example:
        config = MetricsConfig(
            environment=Environment.PRODUCTION,
            enable_prometheus=True,
            collection_interval=30,
            retention_period=3600
        )

        # Validate configuration
        config.validate()

        # Apply environment-specific settings
        config.apply_environment_defaults()
    """

    # Core monitoring settings
    environment: Environment = field(default=Environment.DEVELOPMENT)
    enable_monitoring: bool = field(default=True)
    enable_prometheus: bool = field(default=True)
    enable_health_checks: bool = field(default=True)
    enable_performance_tracking: bool = field(default=True)

    # Collection settings
    collection_interval: int = field(default=60)  # seconds
    retention_period: int = field(default=3600)  # seconds (1 hour)
    max_metric_history: int = field(default=1000)
    batch_size: int = field(default=100)

    # Prometheus settings
    prometheus_port: int = field(default=8001)
    prometheus_host: str = field(default="127.0.0.1")
    prometheus_endpoint: str = field(default="/metrics")
    enable_multiprocess_mode: bool = field(default=False)

    # Performance settings
    enable_statistical_analysis: bool = field(default=True)
    enable_trend_detection: bool = field(default=True)
    enable_anomaly_detection: bool = field(default=False)

    # Health monitoring settings
    health_check_interval: int = field(default=30)  # seconds
    health_check_timeout: int = field(default=5)  # seconds
    max_health_failures: int = field(default=3)

    # Security settings
    enable_metric_filtering: bool = field(default=True)
    mask_sensitive_labels: bool = field(default=True)
    allowed_label_patterns: list[str] = field(default_factory=lambda: ["*"])
    blocked_label_patterns: list[str] = field(default_factory=list)

    # Storage settings
    enable_persistent_storage: bool = field(default=False)
    storage_path: str | None = field(default=None)
    compression_enabled: bool = field(default=True)

    def __post_init__(self):
        """Post-initialization validation and setup."""
        self.validate()
        self.apply_environment_defaults()

    def validate(self) -> None:
        """
        Validate monitoring configuration parameters.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate intervals
        if self.collection_interval < 1:
            raise ConfigurationError("Collection interval must be at least 1 second")

        if self.retention_period < 60:
            raise ConfigurationError("Retention period must be at least 60 seconds")

        if self.max_metric_history < 10:
            raise ConfigurationError("Max metric history must be at least 10")

        # Validate Prometheus settings
        if self.prometheus_port < 1024 or self.prometheus_port > 65535:
            raise ConfigurationError("Prometheus port must be between 1024 and 65535")

        if not self.prometheus_host:
            raise ConfigurationError("Prometheus host cannot be empty")

        if not self.prometheus_endpoint.startswith("/"):
            raise ConfigurationError("Prometheus endpoint must start with '/'")

        # Validate health check settings
        if self.health_check_interval < 5:
            raise ConfigurationError("Health check interval must be at least 5 seconds")

        if self.health_check_timeout < 1:
            raise ConfigurationError("Health check timeout must be at least 1 second")

        if self.max_health_failures < 1:
            raise ConfigurationError("Max health failures must be at least 1")

        # Validate batch size
        if self.batch_size < 1:
            raise ConfigurationError("Batch size must be at least 1")

        # Validate storage settings
        if self.enable_persistent_storage and not self.storage_path:
            raise ConfigurationError(
                "Storage path is required when persistent storage is enabled"
            )

    def apply_environment_defaults(self) -> None:
        """Apply environment-specific defaults and optimizations."""
        if self.environment == Environment.DEVELOPMENT:
            # Development: Frequent collection, shorter retention
            self.collection_interval = 30
            self.retention_period = 1800  # 30 minutes
            self.enable_prometheus = True
            self.enable_anomaly_detection = False
            self.health_check_interval = 60

        elif self.environment == Environment.TESTING:
            # Testing: Minimal monitoring, fast collection
            self.collection_interval = 10
            self.retention_period = 300  # 5 minutes
            self.enable_prometheus = False
            self.enable_performance_tracking = False
            self.enable_anomaly_detection = False
            self.health_check_interval = 30
            self.max_metric_history = 50

        elif self.environment == Environment.STAGING:
            # Staging: Production-like but with shorter retention
            self.collection_interval = 30
            self.retention_period = 7200  # 2 hours
            self.enable_prometheus = True
            self.enable_anomaly_detection = True
            self.health_check_interval = 30

        elif self.environment == Environment.PRODUCTION:
            # Production: Optimized for performance and retention
            self.collection_interval = 60
            self.retention_period = 86400  # 24 hours
            self.enable_prometheus = True
            self.enable_multiprocess_mode = True
            self.enable_anomaly_detection = True
            self.enable_persistent_storage = True
            self.health_check_interval = 30
            self.max_metric_history = 2000

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "environment": self.environment.value,
            "enable_monitoring": self.enable_monitoring,
            "enable_prometheus": self.enable_prometheus,
            "enable_health_checks": self.enable_health_checks,
            "collection_interval": self.collection_interval,
            "retention_period": self.retention_period,
            "max_metric_history": self.max_metric_history,
            "prometheus_port": self.prometheus_port,
            "prometheus_host": self.prometheus_host,
            "prometheus_endpoint": self.prometheus_endpoint,
            "health_check_interval": self.health_check_interval,
            "enable_statistical_analysis": self.enable_statistical_analysis,
            "enable_trend_detection": self.enable_trend_detection,
            "enable_anomaly_detection": self.enable_anomaly_detection,
            "enable_metric_filtering": self.enable_metric_filtering,
            "enable_persistent_storage": self.enable_persistent_storage,
        }


# =====================================================================================
# MAIN SETTINGS CLASS
# =====================================================================================


class Settings:
    """
    Main application settings following pure Python principles.

    Comprehensive configuration management with environment variable loading,
    validation using utils/validation.py, type conversion, and structured access
    to all application settings.

    Design Features:
    - Pure Python implementation using validation utilities
    - Framework-agnostic design
    - No circular dependencies
    - Environment-specific defaults
    - Security-focused credential handling
    - Performance optimizations
    - Rich error handling

    Usage Example:
        # Initialize with environment variables
        settings = Settings()

        # Access configuration
        db_url = settings.database.url
        jwt_secret = settings.security.access_token_secret
        environment = settings.environment

        # Get provider-specific configuration
        celery_config = settings.get_celery_config()
        cache_policy = settings.get_cache_policy()
    """

    def __init__(self, env_file: str = ".env"):
        """
        Initialize settings with environment variable loading.

        Args:
            env_file: Environment file to load variables from
        """
        self.env_loader = EnvironmentLoader(env_file)

        # Load all configuration sections
        self._load_application_config()
        self._load_security_config()
        self._load_database_config()
        self._load_cache_config()
        self._load_service_config()
        self._load_monitoring_config()
        self._load_metrics_config()
        self._load_feature_flags()
        self._load_api_docs_config()
        self._load_policy_config()

        # Validate complete configuration
        self._validate_configuration()

    def _load_application_config(self) -> None:
        """Load core application configuration."""
        self.app_name = self.env_loader.get_string(
            "APP_NAME", "EzzDay Backend", required=False
        )
        self.app_version = self.env_loader.get_string(
            "APP_VERSION", "0.1.0", required=False
        )

        self.environment = self.env_loader.get_enum(
            "ENVIRONMENT", Environment, Environment.DEVELOPMENT, required=False
        )

        self.debug = self.env_loader.get_boolean("DEBUG", False, required=False)

        self.log_level = self.env_loader.get_enum(
            "LOG_LEVEL", LogLevel, LogLevel.INFO, required=False
        )

    def _load_security_config(self) -> None:
        """Load comprehensive security configuration."""
        self.security = SecurityConfig(
            # Password hashing settings
            password_algorithm=self.env_loader.get_enum(
                "PASSWORD_ALGORITHM", HashAlgorithm, HashAlgorithm.ARGON2ID
            ),
            argon2_time_cost=self.env_loader.get_integer(
                "ARGON2_TIME_COST", 2, min_value=1, max_value=10
            ),
            argon2_memory_cost=self.env_loader.get_integer(
                "ARGON2_MEMORY_COST", 65536, min_value=8192, max_value=1048576
            ),
            argon2_parallelism=self.env_loader.get_integer(
                "ARGON2_PARALLELISM", 1, min_value=1, max_value=8
            ),
            argon2_hash_len=self.env_loader.get_integer(
                "ARGON2_HASH_LEN", 32, min_value=16, max_value=64
            ),
            argon2_salt_len=self.env_loader.get_integer(
                "ARGON2_SALT_LEN", 16, min_value=8, max_value=32
            ),
            # JWT settings
            access_token_secret=self.env_loader.get_string(
                "ACCESS_TOKEN_SECRET", required=True, min_length=32
            ),
            refresh_token_secret=self.env_loader.get_string(
                "REFRESH_TOKEN_SECRET", required=True, min_length=32
            ),
            access_token_expire_minutes=self.env_loader.get_integer(
                "ACCESS_TOKEN_EXPIRE_MINUTES", 15, min_value=1, max_value=1440
            ),
            refresh_token_expire_days=self.env_loader.get_integer(
                "REFRESH_TOKEN_EXPIRE_DAYS", 30, min_value=1, max_value=365
            ),
            jwt_algorithm=self.env_loader.get_enum(
                "JWT_ALGORITHM", JWTAlgorithm, JWTAlgorithm.HS256
            ),
            jwt_issuer=self.env_loader.get_string("JWT_ISSUER", "ezzday", min_length=1),
            jwt_audience=self.env_loader.get_string(
                "JWT_AUDIENCE", "ezzday-users", min_length=1
            ),
            jwt_clock_skew_seconds=self.env_loader.get_integer(
                "JWT_CLOCK_SKEW_SECONDS", 30, min_value=0, max_value=300
            ),
            # Token generation
            default_token_bytes=self.env_loader.get_integer(
                "DEFAULT_TOKEN_BYTES", 32, min_value=16, max_value=64
            ),
            verification_code_length=self.env_loader.get_integer(
                "VERIFICATION_CODE_LENGTH", 6, min_value=4, max_value=12
            ),
            verification_code_expire_minutes=self.env_loader.get_integer(
                "VERIFICATION_CODE_EXPIRE_MINUTES", 10, min_value=1, max_value=60
            ),
            # Security policies
            max_password_attempts=self.env_loader.get_integer(
                "MAX_PASSWORD_ATTEMPTS", 5, min_value=1, max_value=20
            ),
            password_attempt_window_minutes=self.env_loader.get_integer(
                "PASSWORD_ATTEMPT_WINDOW_MINUTES", 15, min_value=1, max_value=1440
            ),
            account_lockout_duration_minutes=self.env_loader.get_integer(
                "ACCOUNT_LOCKOUT_DURATION_MINUTES", 30, min_value=1, max_value=10080
            ),
            # Password policies
            require_strong_passwords=self.env_loader.get_boolean(
                "REQUIRE_STRONG_PASSWORDS", True
            ),
            min_password_length=self.env_loader.get_integer(
                "MIN_PASSWORD_LENGTH", 8, min_value=4, max_value=32
            ),
            max_password_length=self.env_loader.get_integer(
                "MAX_PASSWORD_LENGTH", 128, min_value=32, max_value=512
            ),
            password_require_uppercase=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_UPPERCASE", True
            ),
            password_require_lowercase=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_LOWERCASE", True
            ),
            password_require_numbers=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_NUMBERS", True
            ),
            password_require_special_chars=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_SPECIAL_CHARS", True
            ),
            password_prevent_common=self.env_loader.get_boolean(
                "PASSWORD_PREVENT_COMMON", True
            ),
            password_prevent_user_info=self.env_loader.get_boolean(
                "PASSWORD_PREVENT_USER_INFO", True
            ),
            password_history_count=self.env_loader.get_integer(
                "PASSWORD_HISTORY_COUNT", 5, min_value=0, max_value=24
            ),
            password_expiry_days=self.env_loader.get_integer(
                "PASSWORD_EXPIRY_DAYS", None, min_value=30, max_value=365
            ),
            # Session management
            session_timeout_hours=self.env_loader.get_integer(
                "SESSION_TIMEOUT_HOURS", 8, min_value=1, max_value=168
            ),
            session_refresh_threshold_hours=self.env_loader.get_integer(
                "SESSION_REFRESH_THRESHOLD_HOURS", 1, min_value=0, max_value=24
            ),
            max_concurrent_sessions=self.env_loader.get_integer(
                "MAX_CONCURRENT_SESSIONS", 5, min_value=1, max_value=50
            ),
            session_cookie_secure=self.env_loader.get_boolean(
                "SESSION_COOKIE_SECURE", True
            ),
            session_cookie_httponly=self.env_loader.get_boolean(
                "SESSION_COOKIE_HTTPONLY", True
            ),
            session_cookie_samesite=self.env_loader.get_string(
                "SESSION_COOKIE_SAMESITE", "Strict"
            ),
            # MFA configuration
            mfa_enabled_by_default=self.env_loader.get_boolean(
                "MFA_ENABLED_BY_DEFAULT", False
            ),
            mfa_required_for_admin=self.env_loader.get_boolean(
                "MFA_REQUIRED_FOR_ADMIN", True
            ),
            mfa_backup_codes_count=self.env_loader.get_integer(
                "MFA_BACKUP_CODES_COUNT", 10, min_value=5, max_value=20
            ),
            mfa_totp_window=self.env_loader.get_integer(
                "MFA_TOTP_WINDOW", 1, min_value=0, max_value=10
            ),
            mfa_remember_device_days=self.env_loader.get_integer(
                "MFA_REMEMBER_DEVICE_DAYS", 30, min_value=1, max_value=365
            ),
            # Encryption
            encryption_algorithm=self.env_loader.get_enum(
                "ENCRYPTION_ALGORITHM",
                EncryptionAlgorithm,
                EncryptionAlgorithm.AES_256_GCM,
            ),
            encryption_key_rotation_days=self.env_loader.get_integer(
                "ENCRYPTION_KEY_ROTATION_DAYS", 90, min_value=1, max_value=365
            ),
            # API security
            api_key_length=self.env_loader.get_integer(
                "API_KEY_LENGTH", 32, min_value=16, max_value=128
            ),
            api_key_prefix=self.env_loader.get_string("API_KEY_PREFIX", "ezd_"),
            api_rate_limit_enabled=self.env_loader.get_boolean(
                "API_RATE_LIMIT_ENABLED", True
            ),
            # Audit and monitoring
            audit_login_events=self.env_loader.get_boolean("AUDIT_LOGIN_EVENTS", True),
            audit_permission_changes=self.env_loader.get_boolean(
                "AUDIT_PERMISSION_CHANGES", True
            ),
            audit_data_access=self.env_loader.get_boolean("AUDIT_DATA_ACCESS", True),
            security_event_retention_days=self.env_loader.get_integer(
                "SECURITY_EVENT_RETENTION_DAYS", 365, min_value=1, max_value=2555
            ),
            # Security headers
            enable_security_headers=self.env_loader.get_boolean(
                "ENABLE_SECURITY_HEADERS", True
            ),
            hsts_max_age_seconds=self.env_loader.get_integer(
                "HSTS_MAX_AGE_SECONDS", 31536000, min_value=86400, max_value=63072000
            ),
            content_security_policy=self.env_loader.get_string(
                "CONTENT_SECURITY_POLICY", None
            ),
        )

    def _load_database_config(self) -> None:
        """Load comprehensive database configuration."""
        self.database = DatabaseConfig(
            url=self.env_loader.get_string("DATABASE_URL", required=True),
            environment=self.environment,
            pool_type=self.env_loader.get_enum(
                "DATABASE_POOL_TYPE", PoolType, PoolType.QUEUE_POOL
            ),
            pool_size=self.env_loader.get_integer(
                "DATABASE_POOL_SIZE", 20, min_value=1
            ),
            max_overflow=self.env_loader.get_integer(
                "DATABASE_MAX_OVERFLOW", 40, min_value=0
            ),
            pool_timeout=self.env_loader.get_integer(
                "DATABASE_POOL_TIMEOUT", 30, min_value=1
            ),
            pool_recycle=self.env_loader.get_integer(
                "DATABASE_POOL_RECYCLE", 3600, min_value=300
            ),
            pool_pre_ping=self.env_loader.get_boolean("DATABASE_POOL_PRE_PING", True),
            connect_timeout=self.env_loader.get_integer(
                "DATABASE_CONNECT_TIMEOUT", 10, min_value=1
            ),
            command_timeout=self.env_loader.get_integer(
                "DATABASE_COMMAND_TIMEOUT", 60, min_value=1
            ),
            query_timeout=self.env_loader.get_integer(
                "DATABASE_QUERY_TIMEOUT", 30, min_value=1
            ),
            echo=self.env_loader.get_boolean("DATABASE_ECHO", False),
            echo_pool=self.env_loader.get_boolean("DATABASE_ECHO_POOL", False),
            enable_logging=self.env_loader.get_boolean("DATABASE_ENABLE_LOGGING", True),
            health_check_interval=self.env_loader.get_integer(
                "DATABASE_HEALTH_CHECK_INTERVAL", 60, min_value=10
            ),
            max_health_check_failures=self.env_loader.get_integer(
                "DATABASE_MAX_HEALTH_CHECK_FAILURES", 3, min_value=1
            ),
            health_check_timeout=self.env_loader.get_integer(
                "DATABASE_HEALTH_CHECK_TIMEOUT", 5, min_value=1
            ),
            max_retries=self.env_loader.get_integer(
                "DATABASE_MAX_RETRIES", 3, min_value=0
            ),
            retry_delay=self.env_loader.get_float(
                "DATABASE_RETRY_DELAY", 1.0, min_value=0.1
            ),
            exponential_backoff=self.env_loader.get_boolean(
                "DATABASE_EXPONENTIAL_BACKOFF", True
            ),
        )

    def _load_cache_config(self) -> None:
        """Load comprehensive cache configuration."""
        self.cache = CacheConfig(
            # Backend configuration
            backend_type=self.env_loader.get_enum(
                "CACHE_BACKEND_TYPE", CacheBackendType, CacheBackendType.MEMORY
            ),
            fallback_backend=self.env_loader.get_enum(
                "CACHE_FALLBACK_BACKEND", CacheBackendType, None
            ),
            cache_strategy=self.env_loader.get_enum(
                "CACHE_STRATEGY", CacheStrategy, CacheStrategy.CACHE_ASIDE
            ),
            # Redis configuration
            redis_url=self.env_loader.get_string("REDIS_URL"),
            redis_password=self.env_loader.get_string("REDIS_PASSWORD"),
            redis_db=self.env_loader.get_integer("REDIS_DB", 0, min_value=0),
            redis_pool_size=self.env_loader.get_integer(
                "REDIS_POOL_SIZE", 10, min_value=1
            ),
            redis_timeout=self.env_loader.get_integer("REDIS_TIMEOUT", 5, min_value=1),
            # Memcached configuration
            memcached_servers=self.env_loader.get_list("MEMCACHED_SERVERS", []),
            memcached_timeout=self.env_loader.get_integer(
                "MEMCACHED_TIMEOUT", 5, min_value=1
            ),
            # Memory cache configuration
            memory_max_size=self.env_loader.get_integer(
                "CACHE_MEMORY_MAX_SIZE", 100 * 1024 * 1024, min_value=1024 * 1024
            ),
            memory_cleanup_interval=self.env_loader.get_integer(
                "CACHE_MEMORY_CLEANUP_INTERVAL", 300, min_value=10
            ),
            # Common settings
            key_prefix=self.env_loader.get_string(
                "CACHE_KEY_PREFIX", "ezzday", min_length=1
            ),
            namespace_separator=self.env_loader.get_string(
                "CACHE_NAMESPACE_SEPARATOR", ":", min_length=1
            ),
            enable_health_checks=self.env_loader.get_boolean(
                "CACHE_ENABLE_HEALTH_CHECKS", True
            ),
            health_check_interval=self.env_loader.get_integer(
                "CACHE_HEALTH_CHECK_INTERVAL", 60, min_value=10
            ),
        )

    def _load_service_config(self) -> None:
        """Load external service configuration."""
        # Celery
        self.celery_broker_url = self.env_loader.get_string(
            "CELERY_BROKER_URL", required=True
        )
        self.celery_result_backend = self.env_loader.get_string(
            "CELERY_RESULT_BACKEND", required=True
        )
        self.celery_task_always_eager = self.env_loader.get_boolean(
            "CELERY_TASK_ALWAYS_EAGER", False
        )

        # Email
        self.email_provider = self.env_loader.get_enum(
            "EMAIL_PROVIDER", Provider, Provider.SENDGRID
        )
        self.sendgrid_api_key = self.env_loader.get_string(
            "SENDGRID_API_KEY", required=self.email_provider == Provider.SENDGRID
        )
        self.email_from_address = self.env_loader.get_email(
            "EMAIL_FROM_ADDRESS", "noreply@ezzday.com"
        )
        self.email_from_name = self.env_loader.get_string("EMAIL_FROM_NAME", "EzzDay")

        # SMS
        self.sms_provider = self.env_loader.get_enum(
            "SMS_PROVIDER", Provider, Provider.TWILIO
        )
        self.twilio_account_sid = self.env_loader.get_string(
            "TWILIO_ACCOUNT_SID", required=self.sms_provider == Provider.TWILIO
        )
        self.twilio_auth_token = self.env_loader.get_string(
            "TWILIO_AUTH_TOKEN", required=self.sms_provider == Provider.TWILIO
        )
        self.twilio_from_number = self.env_loader.get_string(
            "TWILIO_FROM_NUMBER", required=self.sms_provider == Provider.TWILIO
        )

        # Storage
        self.storage_provider = self.env_loader.get_enum(
            "STORAGE_PROVIDER", Provider, Provider.S3
        )
        self.aws_access_key_id = self.env_loader.get_string(
            "AWS_ACCESS_KEY_ID", required=self.storage_provider == Provider.S3
        )
        self.aws_secret_access_key = self.env_loader.get_string(
            "AWS_SECRET_ACCESS_KEY", required=self.storage_provider == Provider.S3
        )
        self.aws_region = self.env_loader.get_string("AWS_REGION", "us-east-1")
        self.s3_bucket_name = self.env_loader.get_string(
            "S3_BUCKET_NAME", required=self.storage_provider == Provider.S3
        )

    def _load_monitoring_config(self) -> None:
        """Load monitoring and observability configuration."""
        self.sentry_dsn = self.env_loader.get_string("SENTRY_DSN")
        self.prometheus_enabled = self.env_loader.get_boolean(
            "PROMETHEUS_ENABLED", True
        )
        self.jaeger_enabled = self.env_loader.get_boolean("JAEGER_ENABLED", False)
        self.jaeger_agent_host = self.env_loader.get_string(
            "JAEGER_AGENT_HOST", "localhost"
        )
        self.jaeger_agent_port = self.env_loader.get_integer(
            "JAEGER_AGENT_PORT", 6831, min_value=1, max_value=65535
        )

        # Rate limiting
        self.rate_limit_enabled = self.env_loader.get_boolean(
            "RATE_LIMIT_ENABLED", True
        )
        self.rate_limit_default = self.env_loader.get_string(
            "RATE_LIMIT_DEFAULT", "100/hour"
        )
        self.rate_limit_auth = self.env_loader.get_string("RATE_LIMIT_AUTH", "5/minute")

        # CORS
        self.cors_origins = self.env_loader.get_list(
            "CORS_ORIGINS", ["http://localhost:3000"]
        )
        self.cors_allow_credentials = self.env_loader.get_boolean(
            "CORS_ALLOW_CREDENTIALS", True
        )
        self.allowed_hosts = self.env_loader.get_list("ALLOWED_HOSTS", ["*"])

    def _load_metrics_config(self) -> None:
        """Load metrics and monitoring configuration."""
        self.metrics = MetricsConfig(
            environment=self.environment,
            enable_monitoring=self.env_loader.get_boolean(
                "METRICS_ENABLE_MONITORING", True
            ),
            enable_prometheus=self.env_loader.get_boolean(
                "METRICS_ENABLE_PROMETHEUS", True
            ),
            enable_health_checks=self.env_loader.get_boolean(
                "METRICS_ENABLE_HEALTH_CHECKS", True
            ),
            enable_performance_tracking=self.env_loader.get_boolean(
                "METRICS_ENABLE_PERFORMANCE_TRACKING", True
            ),
            # Collection settings
            collection_interval=self.env_loader.get_integer(
                "METRICS_COLLECTION_INTERVAL", 60, min_value=1
            ),
            retention_period=self.env_loader.get_integer(
                "METRICS_RETENTION_PERIOD", 3600, min_value=60
            ),
            max_metric_history=self.env_loader.get_integer(
                "METRICS_MAX_HISTORY", 1000, min_value=10
            ),
            batch_size=self.env_loader.get_integer(
                "METRICS_BATCH_SIZE", 100, min_value=1
            ),
            # Prometheus settings
            prometheus_port=self.env_loader.get_integer(
                "METRICS_PROMETHEUS_PORT", 8001, min_value=1024, max_value=65535
            ),
            prometheus_host=self.env_loader.get_string(
                "METRICS_PROMETHEUS_HOST", "127.0.0.1"
            ),
            prometheus_endpoint=self.env_loader.get_string(
                "METRICS_PROMETHEUS_ENDPOINT", "/metrics"
            ),
            enable_multiprocess_mode=self.env_loader.get_boolean(
                "METRICS_ENABLE_MULTIPROCESS_MODE", False
            ),
            # Performance settings
            enable_statistical_analysis=self.env_loader.get_boolean(
                "METRICS_ENABLE_STATISTICAL_ANALYSIS", True
            ),
            enable_trend_detection=self.env_loader.get_boolean(
                "METRICS_ENABLE_TREND_DETECTION", True
            ),
            enable_anomaly_detection=self.env_loader.get_boolean(
                "METRICS_ENABLE_ANOMALY_DETECTION", False
            ),
            # Health monitoring settings
            health_check_interval=self.env_loader.get_integer(
                "METRICS_HEALTH_CHECK_INTERVAL", 30, min_value=5
            ),
            health_check_timeout=self.env_loader.get_integer(
                "METRICS_HEALTH_CHECK_TIMEOUT", 5, min_value=1
            ),
            max_health_failures=self.env_loader.get_integer(
                "METRICS_MAX_HEALTH_FAILURES", 3, min_value=1
            ),
            # Security settings
            enable_metric_filtering=self.env_loader.get_boolean(
                "METRICS_ENABLE_FILTERING", True
            ),
            mask_sensitive_labels=self.env_loader.get_boolean(
                "METRICS_MASK_SENSITIVE_LABELS", True
            ),
            allowed_label_patterns=self.env_loader.get_list(
                "METRICS_ALLOWED_LABEL_PATTERNS", ["*"]
            ),
            blocked_label_patterns=self.env_loader.get_list(
                "METRICS_BLOCKED_LABEL_PATTERNS", []
            ),
            # Storage settings
            enable_persistent_storage=self.env_loader.get_boolean(
                "METRICS_ENABLE_PERSISTENT_STORAGE", False
            ),
            storage_path=self.env_loader.get_string("METRICS_STORAGE_PATH"),
            compression_enabled=self.env_loader.get_boolean(
                "METRICS_COMPRESSION_ENABLED", True
            ),
        )

    def _load_feature_flags(self) -> None:
        """Load feature flags configuration."""
        self.feature_mfa_enabled = self.env_loader.get_boolean(
            "FEATURE_MFA_ENABLED", True
        )
        self.feature_social_login = self.env_loader.get_boolean(
            "FEATURE_SOCIAL_LOGIN", False
        )
        self.feature_audit_logging = self.env_loader.get_boolean(
            "FEATURE_AUDIT_LOGGING", True
        )

    def _load_api_docs_config(self) -> None:
        """Load API documentation configuration."""
        self.api_docs = APIDocumentationConfig(
            cache_enabled=self.env_loader.get_boolean("API_DOCS_CACHE_ENABLED", True),
            include_examples=self.env_loader.get_boolean(
                "API_DOCS_INCLUDE_EXAMPLES", True
            ),
            include_security_analysis=self.env_loader.get_boolean(
                "API_DOCS_SECURITY_ANALYSIS", self.environment == Environment.PRODUCTION
            ),
            max_path_length=self.env_loader.get_integer(
                "API_DOCS_MAX_PATH_LENGTH", 100, min_value=10
            ),
            output_directory=self.env_loader.get_string(
                "API_DOCS_OUTPUT_DIR", "docs/api"
            ),
            generation_timeout=self.env_loader.get_integer(
                "API_DOCS_TIMEOUT", 300, min_value=30
            ),
        )

    def _load_policy_config(self) -> None:
        """Load policy configuration."""
        # Map environment to policy environment
        policy_env_mapping = {
            Environment.DEVELOPMENT: PolicyEnvironment.DEVELOPMENT,
            Environment.TESTING: PolicyEnvironment.TESTING,
            Environment.STAGING: PolicyEnvironment.STAGING,
            Environment.PRODUCTION: PolicyEnvironment.PRODUCTION,
        }
        
        policy_environment = policy_env_mapping.get(self.environment, PolicyEnvironment.PRODUCTION)
        self.policy_manager = PolicyConfigManager(policy_environment)
        
        # Load individual policy configurations with environment overrides
        self.password_policy = self._load_password_policy_config()
        self.session_policy = self._load_session_policy_config()
        self.mfa_policy = self._load_mfa_policy_config()
        self.lockout_policy = self._load_lockout_policy_config()
        self.risk_policy = self._load_risk_policy_config()
        self.compliance_policy = self._load_compliance_policy_config()

    def _load_password_policy_config(self) -> PasswordPolicyConfig:
        """Load password policy configuration from environment."""
        base_config = self.policy_manager.get_password_config()
        
        return PasswordPolicyConfig(
            min_length=self.env_loader.get_integer(
                "PASSWORD_MIN_LENGTH", base_config.min_length, min_value=4, max_value=32
            ),
            max_length=self.env_loader.get_integer(
                "PASSWORD_MAX_LENGTH", base_config.max_length, min_value=32, max_value=512
            ),
            require_uppercase=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_UPPERCASE", base_config.require_uppercase
            ),
            require_lowercase=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_LOWERCASE", base_config.require_lowercase
            ),
            require_digits=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_DIGITS", base_config.require_digits
            ),
            require_special_chars=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_SPECIAL_CHARS", base_config.require_special_chars
            ),
            special_chars=self.env_loader.get_string(
                "PASSWORD_SPECIAL_CHARS", base_config.special_chars
            ),
            history_limit=self.env_loader.get_integer(
                "PASSWORD_HISTORY_LIMIT", base_config.history_limit, min_value=0, max_value=50
            ),
            min_age_hours=self.env_loader.get_integer(
                "PASSWORD_MIN_AGE_HOURS", base_config.min_age_hours, min_value=0
            ),
            max_age_days=self.env_loader.get_integer(
                "PASSWORD_MAX_AGE_DAYS", base_config.max_age_days, min_value=1, max_value=365
            ),
            complexity_score_threshold=self.env_loader.get_float(
                "PASSWORD_COMPLEXITY_THRESHOLD", base_config.complexity_score_threshold, 
                min_value=0.0, max_value=1.0
            ),
            min_unique_chars=self.env_loader.get_integer(
                "PASSWORD_MIN_UNIQUE_CHARS", base_config.min_unique_chars, min_value=1
            ),
            max_repeated_chars=self.env_loader.get_integer(
                "PASSWORD_MAX_REPEATED_CHARS", base_config.max_repeated_chars, min_value=1
            ),
            forbidden_patterns=self.env_loader.get_list(
                "PASSWORD_FORBIDDEN_PATTERNS", base_config.forbidden_patterns
            ),
            require_non_sequential=self.env_loader.get_boolean(
                "PASSWORD_REQUIRE_NON_SEQUENTIAL", base_config.require_non_sequential
            ),
        )

    def _load_session_policy_config(self) -> SessionPolicyConfig:
        """Load session policy configuration from environment."""
        base_config = self.policy_manager.get_session_config()
        
        return SessionPolicyConfig(
            absolute_timeout_minutes=self.env_loader.get_integer(
                "SESSION_ABSOLUTE_TIMEOUT_MINUTES", base_config.absolute_timeout_minutes, min_value=1
            ),
            idle_timeout_minutes=self.env_loader.get_integer(
                "SESSION_IDLE_TIMEOUT_MINUTES", base_config.idle_timeout_minutes, min_value=1
            ),
            max_concurrent_sessions=self.env_loader.get_integer(
                "SESSION_MAX_CONCURRENT", base_config.max_concurrent_sessions, min_value=1
            ),
            max_sessions_per_device=self.env_loader.get_integer(
                "SESSION_MAX_PER_DEVICE", base_config.max_sessions_per_device, min_value=1
            ),
            max_sessions_per_ip=self.env_loader.get_integer(
                "SESSION_MAX_PER_IP", base_config.max_sessions_per_ip, min_value=1
            ),
            require_trusted_device_for_admin=self.env_loader.get_boolean(
                "SESSION_REQUIRE_TRUSTED_DEVICE_ADMIN", base_config.require_trusted_device_for_admin
            ),
            session_extension_threshold=self.env_loader.get_float(
                "SESSION_EXTENSION_THRESHOLD", base_config.session_extension_threshold,
                min_value=0.0, max_value=1.0
            ),
            risk_threshold_for_additional_auth=self.env_loader.get_float(
                "SESSION_RISK_THRESHOLD_ADDITIONAL_AUTH", base_config.risk_threshold_for_additional_auth,
                min_value=0.0, max_value=1.0
            ),
            timeout_by_type=base_config.timeout_by_type,  # Use defaults for now
        )

    def _load_mfa_policy_config(self) -> MFAPolicyConfig:
        """Load MFA policy configuration from environment."""
        base_config = self.policy_manager.get_mfa_config()
        
        return MFAPolicyConfig(
            require_for_admin=self.env_loader.get_boolean(
                "MFA_REQUIRE_FOR_ADMIN", base_config.require_for_admin
            ),
            require_for_high_risk=self.env_loader.get_boolean(
                "MFA_REQUIRE_FOR_HIGH_RISK", base_config.require_for_high_risk
            ),
            require_for_service_accounts=self.env_loader.get_boolean(
                "MFA_REQUIRE_FOR_SERVICE_ACCOUNTS", base_config.require_for_service_accounts
            ),
            enforce_for_all=self.env_loader.get_boolean(
                "MFA_ENFORCE_FOR_ALL", base_config.enforce_for_all
            ),
            grace_period_days=self.env_loader.get_integer(
                "MFA_GRACE_PERIOD_DAYS", base_config.grace_period_days, min_value=0
            ),
            min_active_devices=self.env_loader.get_integer(
                "MFA_MIN_ACTIVE_DEVICES", base_config.min_active_devices, min_value=1
            ),
            require_backup_method=self.env_loader.get_boolean(
                "MFA_REQUIRE_BACKUP_METHOD", base_config.require_backup_method
            ),
            require_method_diversity=self.env_loader.get_boolean(
                "MFA_REQUIRE_METHOD_DIVERSITY", base_config.require_method_diversity
            ),
            min_unique_methods=self.env_loader.get_integer(
                "MFA_MIN_UNIQUE_METHODS", base_config.min_unique_methods, min_value=1
            ),
            risk_score_threshold=self.env_loader.get_float(
                "MFA_RISK_SCORE_THRESHOLD", base_config.risk_score_threshold,
                min_value=0.0, max_value=1.0
            ),
            adaptive_mfa_enabled=self.env_loader.get_boolean(
                "MFA_ADAPTIVE_ENABLED", base_config.adaptive_mfa_enabled
            ),
            role_requirements=base_config.role_requirements,  # Use defaults for now
            sensitive_permissions=base_config.sensitive_permissions,  # Use defaults for now
        )

    def _load_lockout_policy_config(self) -> LockoutPolicyConfig:
        """Load lockout policy configuration from environment."""
        base_config = self.policy_manager.get_lockout_config()
        
        return LockoutPolicyConfig(
            max_failed_attempts=self.env_loader.get_integer(
                "LOCKOUT_MAX_FAILED_ATTEMPTS", base_config.max_failed_attempts, min_value=1
            ),
            lockout_duration_minutes=self.env_loader.get_integer(
                "LOCKOUT_DURATION_MINUTES", base_config.lockout_duration_minutes, min_value=1
            ),
            progressive_lockout_enabled=self.env_loader.get_boolean(
                "LOCKOUT_PROGRESSIVE_ENABLED", base_config.progressive_lockout_enabled
            ),
            max_attempts_per_minute=self.env_loader.get_integer(
                "LOCKOUT_MAX_ATTEMPTS_PER_MINUTE", base_config.max_attempts_per_minute, min_value=1
            ),
            max_attempts_per_ip_per_hour=self.env_loader.get_integer(
                "LOCKOUT_MAX_ATTEMPTS_PER_IP_PER_HOUR", base_config.max_attempts_per_ip_per_hour, min_value=1
            ),
            ip_block_duration_hours=self.env_loader.get_integer(
                "LOCKOUT_IP_BLOCK_DURATION_HOURS", base_config.ip_block_duration_hours, min_value=1
            ),
            progressive_thresholds=base_config.progressive_thresholds,  # Use defaults for now
        )

    def _load_risk_policy_config(self) -> RiskPolicyConfig:
        """Load risk policy configuration from environment."""
        base_config = self.policy_manager.get_risk_config()
        
        return RiskPolicyConfig(
            low_risk_threshold=self.env_loader.get_float(
                "RISK_LOW_THRESHOLD", base_config.low_risk_threshold, min_value=0.0, max_value=1.0
            ),
            medium_risk_threshold=self.env_loader.get_float(
                "RISK_MEDIUM_THRESHOLD", base_config.medium_risk_threshold, min_value=0.0, max_value=1.0
            ),
            high_risk_threshold=self.env_loader.get_float(
                "RISK_HIGH_THRESHOLD", base_config.high_risk_threshold, min_value=0.0, max_value=1.0
            ),
            require_mfa_above_score=self.env_loader.get_float(
                "RISK_REQUIRE_MFA_ABOVE_SCORE", base_config.require_mfa_above_score, min_value=0.0, max_value=1.0
            ),
            block_above_score=self.env_loader.get_float(
                "RISK_BLOCK_ABOVE_SCORE", base_config.block_above_score, min_value=0.0, max_value=1.0
            ),
            alert_security_team_above=self.env_loader.get_float(
                "RISK_ALERT_SECURITY_TEAM_ABOVE", base_config.alert_security_team_above, min_value=0.0, max_value=1.0
            ),
            risk_weights=base_config.risk_weights,  # Use defaults for now
            high_risk_countries=self.env_loader.get_list(
                "RISK_HIGH_RISK_COUNTRIES", base_config.high_risk_countries
            ),
        )

    def _load_compliance_policy_config(self) -> CompliancePolicyConfig:
        """Load compliance policy configuration from environment."""
        base_config = self.policy_manager.get_compliance_config()
        
        return CompliancePolicyConfig(
            minimum_age=self.env_loader.get_integer(
                "COMPLIANCE_MINIMUM_AGE", base_config.minimum_age, min_value=1, max_value=21
            ),
            parental_consent_age=self.env_loader.get_integer(
                "COMPLIANCE_PARENTAL_CONSENT_AGE", base_config.parental_consent_age, min_value=1, max_value=21
            ),
            require_explicit_consent=self.env_loader.get_boolean(
                "COMPLIANCE_REQUIRE_EXPLICIT_CONSENT", base_config.require_explicit_consent
            ),
            allow_consent_withdrawal=self.env_loader.get_boolean(
                "COMPLIANCE_ALLOW_CONSENT_WITHDRAWAL", base_config.allow_consent_withdrawal
            ),
            data_portability_enabled=self.env_loader.get_boolean(
                "COMPLIANCE_DATA_PORTABILITY_ENABLED", base_config.data_portability_enabled
            ),
            right_to_deletion_enabled=self.env_loader.get_boolean(
                "COMPLIANCE_RIGHT_TO_DELETION_ENABLED", base_config.right_to_deletion_enabled
            ),
            automated_data_minimization=self.env_loader.get_boolean(
                "COMPLIANCE_AUTOMATED_DATA_MINIMIZATION", base_config.automated_data_minimization
            ),
            retention_periods=base_config.retention_periods,  # Use defaults for now
        )

    def _validate_configuration(self) -> None:
        """Validate complete configuration consistency."""
        # Environment-specific validations
        if self.environment == Environment.PRODUCTION:
            if self.debug:
                raise ConfigurationError(
                    "Debug mode should not be enabled in production"
                )

            if self.log_level == LogLevel.DEBUG:
                raise ConfigurationError(
                    "Debug logging should not be enabled in production"
                )

        # Provider-specific validations
        if self.email_provider == Provider.SENDGRID and not self.sendgrid_api_key:
            raise ConfigurationError(
                "SendGrid API key is required when using SendGrid provider"
            )

        if self.sms_provider == Provider.TWILIO and not all(
            [
                self.twilio_account_sid,
                self.twilio_auth_token,
                self.twilio_from_number,
            ]
        ):
            raise ConfigurationError(
                "Twilio credentials are required when using Twilio provider"
            )

        if self.storage_provider == Provider.S3 and not all(
            [
                self.aws_access_key_id,
                self.aws_secret_access_key,
                self.s3_bucket_name,
            ]
        ):
            raise ConfigurationError(
                "AWS credentials and S3 bucket are required when using S3 provider"
            )

        # Cache-specific validations
        if (
            self.cache.backend_type == CacheBackendType.REDIS
            and not self.cache.redis_url
        ):
            raise ConfigurationError(
                "Redis URL is required when using Redis cache backend"
            )

        if (
            self.cache.backend_type == CacheBackendType.MEMCACHED
            and not self.cache.memcached_servers
        ):
            raise ConfigurationError(
                "Memcached servers are required when using Memcached cache backend"
            )

    def get_cache_policy(self) -> CachePolicy:
        """
        Get cache policy configuration from environment variables.

        Returns:
            CachePolicy: Cache policy configuration
        """
        return CachePolicy(
            # Basic settings
            default_ttl=timedelta(
                minutes=self.env_loader.get_integer(
                    "CACHE_DEFAULT_TTL_MINUTES", 15, min_value=1
                )
            ),
            max_key_length=self.env_loader.get_integer(
                "CACHE_MAX_KEY_LENGTH", 250, min_value=1
            ),
            max_value_size=self.env_loader.get_integer(
                "CACHE_MAX_VALUE_SIZE", 1024 * 1024, min_value=1024
            ),
            # Serialization
            serialization_format=self.env_loader.get_enum(
                "CACHE_SERIALIZATION_FORMAT",
                SerializationFormat,
                SerializationFormat.AUTO,
            ),
            compress_threshold=self.env_loader.get_integer(
                "CACHE_COMPRESS_THRESHOLD", 1024, min_value=0
            ),
            # Eviction and capacity
            eviction_policy=self.env_loader.get_enum(
                "CACHE_EVICTION_POLICY", EvictionPolicy, EvictionPolicy.LRU
            ),
            max_entries=self.env_loader.get_integer(
                "CACHE_MAX_ENTRIES", 10000, min_value=1
            ),
            memory_limit=self.env_loader.get_integer(
                "CACHE_MEMORY_LIMIT", None, min_value=1024 * 1024
            ),
            # Performance settings
            enable_compression=self.env_loader.get_boolean(
                "CACHE_ENABLE_COMPRESSION", True
            ),
            enable_encryption=self.env_loader.get_boolean(
                "CACHE_ENABLE_ENCRYPTION", False
            ),
            batch_size=self.env_loader.get_integer(
                "CACHE_BATCH_SIZE", 100, min_value=1
            ),
            connection_timeout=self.env_loader.get_integer(
                "CACHE_CONNECTION_TIMEOUT", 5, min_value=1
            ),
            # Monitoring
            track_statistics=self.env_loader.get_boolean(
                "CACHE_TRACK_STATISTICS", True
            ),
            enable_metrics=self.env_loader.get_boolean("CACHE_ENABLE_METRICS", True),
            log_cache_events=self.env_loader.get_boolean("CACHE_LOG_EVENTS", False),
        )

    def get_celery_config(self) -> dict[str, Any]:
        """
        Get Celery configuration dictionary.

        Returns:
            dict[str, Any]: Celery configuration
        """
        return {
            "broker_url": self.celery_broker_url,
            "result_backend": self.celery_result_backend,
            "task_serializer": "json",
            "accept_content": ["json"],
            "result_serializer": "json",
            "timezone": "UTC",
            "enable_utc": True,
            "task_track_started": True,
            "task_time_limit": 30 * 60,  # 30 minutes
            "task_soft_time_limit": 25 * 60,  # 25 minutes
            "task_acks_late": True,
            "worker_prefetch_multiplier": 1,
            "task_always_eager": self.celery_task_always_eager,
        }

    def get_policy_config(self) -> PolicyConfiguration:
        """Get the current policy configuration."""
        return self.policy_manager.get_config()

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """
        Convert settings to dictionary.

        Args:
            include_secrets: Whether to include secret values

        Returns:
            dict[str, Any]: Settings dictionary
        """
        data = {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "environment": self.environment.value,
            "debug": self.debug,
            "log_level": self.log_level.value,
            # Database (without credentials)
            "database_pool_size": self.database.pool_size,
            "database_max_overflow": self.database.max_overflow,
            "database_pool_timeout": self.database.pool_timeout,
            "database_pool_type": self.database.pool_type.value,
            # Cache
            "cache_backend_type": self.cache.backend_type.value,
            "cache_strategy": self.cache.cache_strategy.value,
            "cache_key_prefix": self.cache.key_prefix,
            "cache_is_enabled": self.cache.is_caching_enabled,
            # Metrics
            "metrics_enabled": self.metrics.enable_monitoring,
            "prometheus_enabled": self.metrics.enable_prometheus,
            "health_checks_enabled": self.metrics.enable_health_checks,
            # Security
            "password_algorithm": self.security.password_algorithm.value,
            "jwt_algorithm": self.security.jwt_algorithm.value,
            "mfa_enabled_by_default": self.security.mfa_enabled_by_default,
            "require_strong_passwords": self.security.require_strong_passwords,
            "enable_security_headers": self.security.enable_security_headers,
            # Services
            "email_provider": self.email_provider.value,
            "sms_provider": self.sms_provider.value,
            "storage_provider": self.storage_provider.value,
            # Monitoring
            "jaeger_enabled": self.jaeger_enabled,
            "rate_limit_enabled": self.rate_limit_enabled,
            # Features
            "feature_mfa_enabled": self.feature_mfa_enabled,
            "feature_social_login": self.feature_social_login,
            "feature_audit_logging": self.feature_audit_logging,
            # Policy configuration
            "policy_environment": self.policy_manager.environment.value,
            "policy_strict_mode": self.policy_manager.get_config().strict_mode,
            "password_policy_min_length": self.password_policy.min_length,
            "mfa_policy_require_for_admin": self.mfa_policy.require_for_admin,
            "session_policy_timeout": self.session_policy.absolute_timeout_minutes,
        }

        if include_secrets:
            data.update(
                {
                    "database_url": self.database.url,
                    "redis_url": self.cache.redis_url,
                    "access_token_secret": self.security.access_token_secret,
                    "refresh_token_secret": self.security.refresh_token_secret,
                }
            )

        return data


# =====================================================================================
# FACTORY FUNCTIONS
# =====================================================================================


@lru_cache
def get_settings(env_file: str = ".env") -> Settings:
    """
    Get cached settings instance.

    Args:
        env_file: Environment file to load

    Returns:
        Settings: Application settings
    """
    return Settings(env_file)


# Create global settings instance
settings = get_settings()


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "CacheConfig",
    "CachePolicy",
    "CompliancePolicyConfig",
    "DatabaseConfig",
    # Utilities
    "EnvironmentLoader",
    "LockoutPolicyConfig",
    "MFAPolicyConfig",
    "MetricsConfig",
    "PasswordPolicyConfig",
    "PolicyConfigManager",
    "PolicyConfiguration",
    # Policy configuration classes
    "PolicyEnvironment",
    "RiskPolicyConfig",
    "SecurityConfig",
    "SessionPolicyConfig",
    # Main classes
    "Settings",
    # Factory functions
    "get_settings",
    # Global instance
    "settings",
]
