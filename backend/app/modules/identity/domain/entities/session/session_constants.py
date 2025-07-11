"""
Session Constants

Constants used across session entities and services.
"""

from dataclasses import dataclass
from datetime import timedelta

# =============================================================================
# Session Configuration
# =============================================================================

@dataclass(frozen=True)
class SessionConfig:
    """Session configuration container."""
    timeout: timedelta
    idle_timeout: timedelta
    max_concurrent: int
    requires_mfa: bool
    privilege_level: int
    
    def is_privileged(self) -> bool:
        return self.privilege_level >= 3


# Session Type Configurations
SESSION_CONFIGS = {
    "web": SessionConfig(
        timeout=timedelta(hours=8),
        idle_timeout=timedelta(minutes=30),
        max_concurrent=5,
        requires_mfa=False,
        privilege_level=1
    ),
    "mobile": SessionConfig(
        timeout=timedelta(days=30),
        idle_timeout=timedelta(hours=24),
        max_concurrent=3,
        requires_mfa=False,
        privilege_level=1
    ),
    "api": SessionConfig(
        timeout=timedelta(hours=24),
        idle_timeout=timedelta(hours=1),
        max_concurrent=10,
        requires_mfa=False,
        privilege_level=2
    ),
    "service": SessionConfig(
        timeout=timedelta(days=365),
        idle_timeout=timedelta(days=365),
        max_concurrent=1,
        requires_mfa=False,
        privilege_level=4
    ),
    "admin": SessionConfig(
        timeout=timedelta(hours=4),
        idle_timeout=timedelta(minutes=15),
        max_concurrent=2,
        requires_mfa=True,
        privilege_level=5
    )
}

# Legacy timeout dictionaries for backward compatibility
SESSION_TIMEOUTS = {k: v.timeout for k, v in SESSION_CONFIGS.items()}
IDLE_TIMEOUTS = {k: v.idle_timeout for k, v in SESSION_CONFIGS.items()}


# =============================================================================
# Security & Risk Management
# =============================================================================

# Risk Assessment Weights
RISK_FACTORS = {
    # Authentication risks
    "failed_mfa_attempt": 0.1,
    "failed_verification": 0.2,
    "multiple_failures": 0.4,
    "brute_force_attempt": 0.3,
    
    # Device & Location risks
    "device_change": 0.15,
    "multiple_device_change": 0.2,
    "location_change": 0.1,
    "location_mismatch": 0.15,
    "impossible_travel": 0.5,
    
    # Behavioral risks
    "suspicious_pattern": 0.25,
    "suspicious_activity": 0.3,
    "unusual_time_access": 0.05,
    "concurrent_sessions_exceeded": 0.2,
    
    # System risks
    "security_policy_violation": 0.3,
    "privilege_escalation_attempt": 0.4,
    "malware_detection": 0.6
}

# Risk Level Thresholds
RISK_THRESHOLDS = {
    "low": 0.0,
    "medium": 0.3,
    "high": 0.6,
    "critical": 0.8
}

# Risk Decay Settings
RISK_DECAY_RATE = 0.05  # 5% per hour
MINIMUM_RISK_SCORE = 0.0
MAXIMUM_RISK_SCORE = 1.0
RISK_DECAY_INTERVAL = timedelta(hours=1)


# =============================================================================
# MFA & Challenge Settings
# =============================================================================

# MFA Configuration
MFA_SETTINGS = {
    "challenge_timeout": timedelta(minutes=5),
    "session_timeout": timedelta(minutes=15),
    "max_attempts": 3,
    "extension_minutes": 5,
    "backup_codes_count": 8,
    "totp_window_seconds": 30,
    "sms_timeout": timedelta(minutes=2),
    "email_timeout": timedelta(minutes=10)
}

# Challenge Types
CHALLENGE_TYPES = {
    "mfa_required": {"timeout": timedelta(minutes=5), "max_attempts": 3},
    "device_verification": {"timeout": timedelta(minutes=10), "max_attempts": 2},
    "location_verification": {"timeout": timedelta(minutes=15), "max_attempts": 2},
    "privilege_elevation": {"timeout": timedelta(minutes=15), "max_attempts": 3}
}


# =============================================================================
# Rate Limiting
# =============================================================================

@dataclass(frozen=True)
class RateLimit:
    """Rate limit configuration."""
    limit: int
    window_minutes: int
    
    @property
    def window_seconds(self) -> int:
        return self.window_minutes * 60


# Rate Limiting Rules
RATE_LIMITS = {
    "session_creation": RateLimit(limit=5, window_minutes=15),
    "challenge_refresh": RateLimit(limit=3, window_minutes=5),
    "mfa_attempt": RateLimit(limit=5, window_minutes=10),
    "token_refresh": RateLimit(limit=10, window_minutes=60),
    "session_extend": RateLimit(limit=5, window_minutes=15),
    "device_registration": RateLimit(limit=3, window_minutes=60),
    "password_attempt": RateLimit(limit=5, window_minutes=15),
    "privilege_elevation": RateLimit(limit=3, window_minutes=30)
}


# =============================================================================
# Security Constraints
# =============================================================================

# Geographic & Travel
IMPOSSIBLE_TRAVEL_SPEED_KMH = 500  # Maximum realistic travel speed
MIN_LOCATION_ACCURACY_METERS = 1000  # Minimum accuracy for location matching
TIMEZONE_TOLERANCE_HOURS = 2  # Allowed timezone difference

# Device Fingerprinting
DEVICE_FINGERPRINT_FACTORS = [
    "user_agent", "screen_resolution", "timezone", "language",
    "platform", "plugins", "canvas_fingerprint", "webgl_fingerprint"
]

# Session Security
MAX_CONCURRENT_SESSIONS = {
    "web": 5,
    "mobile": 3,
    "api": 10,
    "service": 1,
    "admin": 2
}

# Security Event Limits
SECURITY_EVENT_LIMITS = {
    "max_events_per_session": 50,
    "events_to_keep": 40,
    "cleanup_threshold": 100,
    "alert_threshold": 10
}


# =============================================================================
# Token & Refresh Management
# =============================================================================

# Token Lifetimes
TOKEN_LIFETIMES = {
    "access_token": timedelta(minutes=15),
    "refresh_token": timedelta(days=30),
    "id_token": timedelta(hours=1),
    "device_token": timedelta(days=90),
    "remember_me_token": timedelta(days=365)
}

# Refresh Strategy Settings
REFRESH_STRATEGIES = {
    "rotate": {"reuse_count": 0, "family_tracking": False},
    "reuse": {"reuse_count": 5, "family_tracking": False},
    "family": {"reuse_count": 1, "family_tracking": True}
}


# =============================================================================
# Privilege & Elevation
# =============================================================================

# Privilege Levels
PRIVILEGE_LEVELS = {
    "guest": 0,
    "user": 1,
    "moderator": 2,
    "admin": 3,
    "super_admin": 4,
    "system": 5
}

# Elevation Requirements
ELEVATION_REQUIREMENTS = {
    "admin": {"mfa_required": True, "timeout": timedelta(minutes=15)},
    "super_admin": {"mfa_required": True, "timeout": timedelta(minutes=10)},
    "system": {"mfa_required": True, "timeout": timedelta(minutes=5)}
}


# =============================================================================
# Monitoring & Alerting
# =============================================================================

# Alert Thresholds
ALERT_THRESHOLDS = {
    "failed_login_attempts": 5,
    "concurrent_sessions_exceeded": 3,
    "impossible_travel_detected": 1,
    "multiple_device_changes": 3,
    "suspicious_activity_score": 0.7,
    "privilege_escalation_attempts": 2
}

# Monitoring Intervals
MONITORING_INTERVALS = {
    "risk_calculation": timedelta(minutes=5),
    "session_cleanup": timedelta(hours=1),
    "security_scan": timedelta(minutes=15),
    "audit_log_rotation": timedelta(days=1)
}


# =============================================================================
# Validation Functions
# =============================================================================

def validate_session_type(session_type: str) -> bool:
    """Validate if session type is supported."""
    return session_type in SESSION_CONFIGS


def get_session_config(session_type: str) -> SessionConfig:
    """Get session configuration for type."""
    if not validate_session_type(session_type):
        raise ValueError(f"Invalid session type: {session_type}")
    return SESSION_CONFIGS[session_type]


def calculate_risk_score(risk_factors: dict[str, float]) -> float:
    """Calculate cumulative risk score."""
    total_risk = sum(
        RISK_FACTORS.get(factor, 0.0) * weight
        for factor, weight in risk_factors.items()
    )
    return min(max(total_risk, MINIMUM_RISK_SCORE), MAXIMUM_RISK_SCORE)


def get_risk_level(risk_score: float) -> str:
    """Get risk level from score."""
    if risk_score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    if risk_score >= RISK_THRESHOLDS["high"]:
        return "high"
    if risk_score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"


def is_privileged_session(session_type: str) -> bool:
    """Check if session type requires elevated privileges."""
    config = get_session_config(session_type)
    return config.is_privileged()


# Export key constants and functions
__all__ = [
    # Core configurations
    'SESSION_CONFIGS',
    'SessionConfig',
    
    # Legacy compatibility
    'SESSION_TIMEOUTS',
    'IDLE_TIMEOUTS',
    
    # Security & Risk
    'RISK_FACTORS',
    'RISK_THRESHOLDS',
    'RISK_DECAY_RATE',
    
    # MFA & Challenges
    'MFA_SETTINGS',
    'CHALLENGE_TYPES',
    
    # Rate Limiting
    'RATE_LIMITS',
    'RateLimit',
    
    # Security constraints
    'IMPOSSIBLE_TRAVEL_SPEED_KMH',
    'MAX_CONCURRENT_SESSIONS',
    'SECURITY_EVENT_LIMITS',
    
    # Tokens & Refresh
    'TOKEN_LIFETIMES',
    'REFRESH_STRATEGIES',
    
    # Privileges
    'PRIVILEGE_LEVELS',
    'ELEVATION_REQUIREMENTS',
    
    # Monitoring
    'ALERT_THRESHOLDS',
    'MONITORING_INTERVALS',
    
    # Validation functions
    'validate_session_type',
    'get_session_config',
    'calculate_risk_score',
    'get_risk_level',
    'is_privileged_session'
]