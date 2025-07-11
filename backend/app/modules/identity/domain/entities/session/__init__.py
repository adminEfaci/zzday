"""
Session Entity Module

Session-related entities, events, errors, constants, and mixins for session management.
"""

# Entities
from .partial_session import PartialSession
from .security_event import SecurityEvent

# Errors
from .session_errors import (
    ConcurrentSessionLimitError,
    InvalidTokenError,
    RefreshTokenExpiredError,
    SessionAlreadyTerminatedError,
    SessionError,
    SessionExpiredError,
    SessionNotFoundError,
    TokenExpiredError,
)

# Events
from .session_events import (
    SessionCreated,
    SessionExpired,
    SessionLocationChanged,
    SessionMFACompleted,
    SessionPrivilegeElevated,
    SessionResumed,
    SessionRevoked,
    SessionRiskScoreChanged,
    SessionSecurityEvent,
    SessionSuspended,
    TokenRefreshed,
    TokenRevoked,
)

# Constants
from .session_constants import (
    ALERT_THRESHOLDS,
    CHALLENGE_TYPES,
    ELEVATION_REQUIREMENTS,
    IMPOSSIBLE_TRAVEL_SPEED_KMH,
    MAX_CONCURRENT_SESSIONS,
    MFA_SETTINGS,
    MONITORING_INTERVALS,
    PRIVILEGE_LEVELS,
    RATE_LIMITS,
    REFRESH_STRATEGIES,
    RISK_DECAY_RATE,
    RISK_FACTORS,
    RISK_THRESHOLDS,
    SECURITY_EVENT_LIMITS,
    SESSION_CONFIGS,
    SessionConfig,
    TOKEN_LIFETIMES,
    RateLimit,
    calculate_risk_score,
    get_risk_level,
    get_session_config,
    is_privileged_session,
    validate_session_type,
)

# Mixins
from .session_mixins import (
    RateLimitingMixin,
    RiskManagementMixin,
    SessionValidationMixin,
)

__all__ = [
    # === ENTITIES ===
    "PartialSession",
    "SecurityEvent",
    
    # === ERRORS ===
    "ConcurrentSessionLimitError",
    "InvalidTokenError",
    "RefreshTokenExpiredError",
    "SessionAlreadyTerminatedError",
    "SessionError",
    "SessionExpiredError",
    "SessionNotFoundError",
    "TokenExpiredError",
    
    # === EVENTS ===
    "SessionCreated",
    "SessionExpired",
    "SessionLocationChanged",
    "SessionMFACompleted",
    "SessionPrivilegeElevated",
    "SessionResumed",
    "SessionRevoked",
    "SessionRiskScoreChanged",
    "SessionSecurityEvent",
    "SessionSuspended",
    "TokenRefreshed",
    "TokenRevoked",
    
    # === CONSTANTS ===
    "ALERT_THRESHOLDS",
    "CHALLENGE_TYPES",
    "ELEVATION_REQUIREMENTS",
    "IMPOSSIBLE_TRAVEL_SPEED_KMH",
    "MAX_CONCURRENT_SESSIONS",
    "MFA_SETTINGS",
    "MONITORING_INTERVALS",
    "PRIVILEGE_LEVELS",
    "RATE_LIMITS",
    "REFRESH_STRATEGIES",
    "RISK_DECAY_RATE",
    "RISK_FACTORS", 
    "RISK_THRESHOLDS",
    "SECURITY_EVENT_LIMITS",
    "SESSION_CONFIGS",
    "SessionConfig",
    "TOKEN_LIFETIMES",
    "RateLimit",
    "calculate_risk_score",
    "get_risk_level",
    "get_session_config",
    "is_privileged_session",
    "validate_session_type",
    
    # === MIXINS ===
    "RateLimitingMixin",
    "RiskManagementMixin", 
    "SessionValidationMixin",
]

# Metadata
__version__ = "1.0.0"
__domain__ = "identity"