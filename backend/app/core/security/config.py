"""
Security Configuration

Centralized security configuration for the application.
Includes security headers, authentication settings, and security policies.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SecurityHeaders:
    """Security headers configuration."""
    
    # Content Security Policy
    content_security_policy: str = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # HTTP Strict Transport Security
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = True
    
    # X-Frame-Options
    x_frame_options: str = "DENY"
    
    # X-Content-Type-Options
    x_content_type_options: str = "nosniff"
    
    # X-XSS-Protection
    x_xss_protection: str = "1; mode=block"
    
    # Referrer Policy
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    # Permissions Policy
    permissions_policy: str = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "accelerometer=(), "
        "gyroscope=(), "
        "magnetometer=()"
    )
    
    # Cross-Origin-Embedder-Policy
    cross_origin_embedder_policy: str = "require-corp"
    
    # Cross-Origin-Opener-Policy
    cross_origin_opener_policy: str = "same-origin"
    
    # Cross-Origin-Resource-Policy
    cross_origin_resource_policy: str = "same-origin"


@dataclass
class AuthenticationConfig:
    """Authentication configuration."""
    
    # Password policy
    min_password_length: int = 12
    max_password_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    password_history_count: int = 5
    
    # Account lockout
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    lockout_threshold_minutes: int = 15
    
    # Session management
    session_timeout_minutes: int = 30
    max_concurrent_sessions: int = 3
    session_regeneration_interval_minutes: int = 15
    
    # Token configuration
    jwt_expiration_minutes: int = 15
    refresh_token_expiration_days: int = 30
    jwt_algorithm: str = "HS256"
    
    # Multi-factor authentication
    mfa_enabled: bool = True
    mfa_required_for_admin: bool = True
    mfa_backup_codes_count: int = 10
    totp_issuer: str = "EzzDay"
    totp_period: int = 30
    totp_digits: int = 6
    
    # OAuth/SSO
    oauth_state_expiration_minutes: int = 10
    oauth_allowed_providers: List[str] = None
    
    def __post_init__(self):
        if self.oauth_allowed_providers is None:
            self.oauth_allowed_providers = ["google", "github", "microsoft"]


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    
    # General API rate limits
    api_requests_per_minute: int = 100
    api_requests_per_hour: int = 1000
    api_requests_per_day: int = 10000
    
    # Authentication rate limits
    login_attempts_per_minute: int = 5
    login_attempts_per_hour: int = 20
    registration_attempts_per_hour: int = 10
    password_reset_attempts_per_hour: int = 5
    
    # File upload rate limits
    upload_requests_per_minute: int = 10
    upload_requests_per_hour: int = 50
    max_file_size_mb: int = 50
    max_files_per_request: int = 5
    
    # Search rate limits
    search_requests_per_minute: int = 30
    search_requests_per_hour: int = 200
    
    # Admin rate limits
    admin_requests_per_minute: int = 200
    admin_requests_per_hour: int = 2000


@dataclass
class ValidationConfig:
    """Input validation configuration."""
    
    # String validation
    max_string_length: int = 1000
    max_text_length: int = 10000
    max_description_length: int = 5000
    max_name_length: int = 100
    max_email_length: int = 254
    
    # File validation
    allowed_file_extensions: List[str] = None
    max_filename_length: int = 255
    scan_uploads_for_viruses: bool = True
    
    # URL validation
    allowed_url_schemes: List[str] = None
    max_url_length: int = 2048
    
    # Input sanitization
    strip_html_tags: bool = True
    encode_html_entities: bool = True
    remove_sql_keywords: bool = True
    
    # Content validation
    profanity_filter_enabled: bool = True
    spam_detection_enabled: bool = True
    
    def __post_init__(self):
        if self.allowed_file_extensions is None:
            self.allowed_file_extensions = [
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".txt", ".csv", ".json", ".xml", ".zip", ".tar", ".gz"
            ]
        
        if self.allowed_url_schemes is None:
            self.allowed_url_schemes = ["http", "https", "ftp", "ftps"]


@dataclass
class EncryptionConfig:
    """Encryption configuration."""
    
    # Database encryption
    encrypt_sensitive_fields: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    key_rotation_days: int = 90
    
    # Password hashing
    password_hash_algorithm: str = "bcrypt"
    bcrypt_rounds: int = 12
    
    # Data at rest encryption
    encrypt_database: bool = True
    encrypt_file_storage: bool = True
    encrypt_logs: bool = True
    
    # Data in transit encryption
    force_https: bool = True
    tls_min_version: str = "1.2"
    tls_cipher_suites: List[str] = None
    
    # Key management
    key_storage_backend: str = "environment"  # environment, vault, hsm
    key_backup_enabled: bool = True
    key_escrow_enabled: bool = False
    
    def __post_init__(self):
        if self.tls_cipher_suites is None:
            self.tls_cipher_suites = [
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ]


@dataclass
class AuditConfig:
    """Security audit configuration."""
    
    # Audit logging
    log_authentication_events: bool = True
    log_authorization_events: bool = True
    log_data_access_events: bool = True
    log_configuration_changes: bool = True
    log_privileged_operations: bool = True
    
    # Log retention
    audit_log_retention_days: int = 365
    security_log_retention_days: int = 90
    access_log_retention_days: int = 30
    
    # Alerting
    alert_on_brute_force: bool = True
    alert_on_privilege_escalation: bool = True
    alert_on_data_exfiltration: bool = True
    alert_on_suspicious_activity: bool = True
    
    # Monitoring
    monitor_failed_logins: bool = True
    monitor_admin_actions: bool = True
    monitor_data_exports: bool = True
    monitor_api_abuse: bool = True
    
    # Compliance
    gdpr_compliance: bool = True
    ccpa_compliance: bool = True
    hipaa_compliance: bool = False
    sox_compliance: bool = False


@dataclass
class SecurityConfig:
    """Comprehensive security configuration."""
    
    headers: SecurityHeaders = None
    authentication: AuthenticationConfig = None
    rate_limits: RateLimitConfig = None
    validation: ValidationConfig = None
    encryption: EncryptionConfig = None
    audit: AuditConfig = None
    
    # Environment settings
    environment: str = "production"  # development, staging, production
    debug_mode: bool = False
    
    # Security features
    enable_csrf_protection: bool = True
    enable_cors_protection: bool = True
    enable_sql_injection_protection: bool = True
    enable_xss_protection: bool = True
    enable_clickjacking_protection: bool = True
    
    # Security scanning
    vulnerability_scanning_enabled: bool = True
    dependency_scanning_enabled: bool = True
    code_scanning_enabled: bool = True
    
    # Incident response
    incident_response_enabled: bool = True
    auto_block_suspicious_ips: bool = True
    quarantine_malicious_uploads: bool = True
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = SecurityHeaders()
        
        if self.authentication is None:
            self.authentication = AuthenticationConfig()
        
        if self.rate_limits is None:
            self.rate_limits = RateLimitConfig()
        
        if self.validation is None:
            self.validation = ValidationConfig()
        
        if self.encryption is None:
            self.encryption = EncryptionConfig()
        
        if self.audit is None:
            self.audit = AuditConfig()
        
        # Adjust settings based on environment
        if self.environment == "development":
            self.debug_mode = True
            self.headers.hsts_max_age = 0
            self.encryption.force_https = False
            self.rate_limits.api_requests_per_minute = 1000
        elif self.environment == "staging":
            self.debug_mode = False
            self.headers.hsts_max_age = 3600  # 1 hour
            self.encryption.force_https = True
        elif self.environment == "production":
            self.debug_mode = False
            self.headers.hsts_max_age = 31536000  # 1 year
            self.encryption.force_https = True
            self.audit.log_authentication_events = True
            self.audit.log_authorization_events = True
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers as dictionary."""
        headers = {}
        
        if self.headers.content_security_policy:
            headers["Content-Security-Policy"] = self.headers.content_security_policy
        
        if self.encryption.force_https and self.headers.hsts_max_age > 0:
            hsts_value = f"max-age={self.headers.hsts_max_age}"
            if self.headers.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.headers.hsts_preload:
                hsts_value += "; preload"
            headers["Strict-Transport-Security"] = hsts_value
        
        if self.headers.x_frame_options:
            headers["X-Frame-Options"] = self.headers.x_frame_options
        
        if self.headers.x_content_type_options:
            headers["X-Content-Type-Options"] = self.headers.x_content_type_options
        
        if self.headers.x_xss_protection:
            headers["X-XSS-Protection"] = self.headers.x_xss_protection
        
        if self.headers.referrer_policy:
            headers["Referrer-Policy"] = self.headers.referrer_policy
        
        if self.headers.permissions_policy:
            headers["Permissions-Policy"] = self.headers.permissions_policy
        
        if self.headers.cross_origin_embedder_policy:
            headers["Cross-Origin-Embedder-Policy"] = self.headers.cross_origin_embedder_policy
        
        if self.headers.cross_origin_opener_policy:
            headers["Cross-Origin-Opener-Policy"] = self.headers.cross_origin_opener_policy
        
        if self.headers.cross_origin_resource_policy:
            headers["Cross-Origin-Resource-Policy"] = self.headers.cross_origin_resource_policy
        
        return headers
    
    def validate_config(self) -> List[str]:
        """Validate security configuration and return any issues."""
        issues = []
        
        # Check password policy
        if self.authentication.min_password_length < 8:
            issues.append("Password minimum length should be at least 8 characters")
        
        if self.authentication.max_login_attempts > 10:
            issues.append("Maximum login attempts should not exceed 10")
        
        if self.authentication.session_timeout_minutes > 480:  # 8 hours
            issues.append("Session timeout should not exceed 8 hours")
        
        # Check encryption settings
        if not self.encryption.encrypt_sensitive_fields:
            issues.append("Sensitive fields should be encrypted")
        
        if self.encryption.bcrypt_rounds < 10:
            issues.append("BCrypt rounds should be at least 10")
        
        # Check environment-specific settings
        if self.environment == "production":
            if self.debug_mode:
                issues.append("Debug mode should be disabled in production")
            
            if not self.encryption.force_https:
                issues.append("HTTPS should be enforced in production")
            
            if self.headers.hsts_max_age < 31536000:  # 1 year
                issues.append("HSTS max age should be at least 1 year in production")
        
        return issues


# Default security configuration
default_security_config = SecurityConfig()


def get_security_config(environment: str = "production") -> SecurityConfig:
    """Get security configuration for specific environment."""
    config = SecurityConfig(environment=environment)
    return config


__all__ = [
    "SecurityConfig",
    "SecurityHeaders",
    "AuthenticationConfig",
    "RateLimitConfig",
    "ValidationConfig", 
    "EncryptionConfig",
    "AuditConfig",
    "default_security_config",
    "get_security_config"
]