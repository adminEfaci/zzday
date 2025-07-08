"""
Session Domain Specifications

Business rule specifications for session-related operations.
"""

from datetime import UTC, datetime, timedelta

from app.core.infrastructure.specification import Specification

from ..entities.session import Session
from ..enums import SessionType
from .base import BaseSpecification, ParameterizedSpecification, TimeBasedSpecification


class ActiveSessionSpecification(Specification[Session]):
    """Specification for active sessions."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is active."""
        return session.is_active


class ExpiredSessionSpecification(Specification[Session]):
    """Specification for expired sessions."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is expired."""
        return session.is_expired


class TrustedSessionSpecification(Specification[Session]):
    """Specification for trusted sessions."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is trusted."""
        return session.is_trusted


class SessionByTypeSpecification(Specification[Session]):
    """Specification for sessions of specific type."""
    
    def __init__(self, session_type: SessionType):
        self.session_type = session_type
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is of specific type."""
        return session.session_type == self.session_type


class SessionByRiskLevelSpecification(Specification[Session]):
    """Specification for sessions with specific risk level."""
    
    def __init__(self, max_risk_score: float):
        self.max_risk_score = max_risk_score
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session has acceptable risk level."""
        return session.risk_score <= self.max_risk_score


class LongRunningSessionSpecification(TimeBasedSpecification[Session], ParameterizedSpecification[Session]):
    """Specification for long-running sessions."""
    
    def __init__(self, hours: int = 8):
        TimeBasedSpecification.__init__(self)
        ParameterizedSpecification.__init__(self, hours=hours)
    
    def _validate_parameters(self) -> None:
        """Validate session duration parameters."""
        hours = self.parameters.get('hours', 8)
        if not isinstance(hours, int | float) or hours <= 0:
            raise ValueError("Hours must be a positive number")
        if hours > 168:  # 1 week
            raise ValueError("Hours cannot exceed 168 (1 week)")
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session has been running too long."""
        self.validate_candidate(session)
        
        max_duration = timedelta(hours=self.parameters['hours'])
        session_duration = self.get_current_time() - session.created_at
        return session_duration > max_duration


class InactiveSessionSpecification(Specification[Session]):
    """Specification for inactive sessions."""
    
    def __init__(self, minutes: int = 30):
        self.inactivity_threshold = timedelta(minutes=minutes)
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session has been inactive."""
        time_since_activity = datetime.now(UTC) - session.last_activity_at
        return time_since_activity > self.inactivity_threshold


class SuspiciousSessionSpecification(BaseSpecification[Session]):
    """Specification for suspicious sessions."""
    
    def __init__(self, risk_threshold: float = 0.7, max_security_events: int = 5):
        super().__init__()
        self.risk_threshold = risk_threshold
        self.max_security_events = max_security_events
        self._bot_indicators = {'bot', 'crawler', 'spider', 'scraper', 'automated'}
        self._admin_session_types = {SessionType.ADMIN, SessionType.API}
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session shows suspicious activity."""
        self.validate_candidate(session)
        
        return (
            self._has_high_risk_score(session) or
            self._is_untrusted_admin_session(session) or
            self._has_bot_user_agent(session) or
            self._has_too_many_security_events(session)
        )
    
    def _has_high_risk_score(self, session: Session) -> bool:
        """Check if session has high risk score."""
        return session.risk_score > self.risk_threshold
    
    def _is_untrusted_admin_session(self, session: Session) -> bool:
        """Check if session is untrusted admin session."""
        return (
            not session.is_trusted and 
            session.session_type in self._admin_session_types
        )
    
    def _has_bot_user_agent(self, session: Session) -> bool:
        """Check if session has bot-like user agent."""
        if not session.user_agent:
            return False
        
        user_agent_lower = session.user_agent.lower()
        return any(indicator in user_agent_lower for indicator in self._bot_indicators)
    
    def _has_too_many_security_events(self, session: Session) -> bool:
        """Check if session has too many security events."""
        return len(session.security_events) > self.max_security_events


class RequiresMFASessionSpecification(Specification[Session]):
    """Specification for sessions requiring MFA."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session requires MFA."""
        return session.requires_mfa and not session.mfa_completed


class ElevatedPrivilegeSessionSpecification(Specification[Session]):
    """Specification for sessions with elevated privileges."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session has elevated privileges."""
        return session.is_privilege_elevated()


class SessionFromUnknownLocationSpecification(Specification[Session]):
    """Specification for sessions from unknown locations."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is from unknown location."""
        if not session.ip_address:
            return True
        
        # Check if IP is from a known safe location
        known_safe_ranges = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.'  # Private ranges
        ]
        
        ip_str = str(session.ip_address)
        is_private = any(ip_str.startswith(prefix) for prefix in known_safe_ranges)
        
        # Unknown if not private and no geolocation data
        return not is_private and not session.geolocation


class ConcurrentSessionSpecification(Specification[Session]):
    """Specification for detecting concurrent sessions."""
    
    def __init__(self, user_sessions: list[Session], max_concurrent: int = 3):
        self.user_sessions = user_sessions
        self.max_concurrent = max_concurrent
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session would exceed concurrent session limit."""
        active_sessions = [
            s for s in self.user_sessions 
            if s.is_active and s.id != session.id
        ]
        return len(active_sessions) < self.max_concurrent


class SessionDeviceMismatchSpecification(Specification[Session]):
    """Specification for sessions with device mismatches."""
    
    def __init__(self, expected_fingerprint: str | None):
        self.expected_fingerprint = expected_fingerprint
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session device matches expected device."""
        if not self.expected_fingerprint or not session.device_fingerprint:
            return False  # Cannot verify
        
        return session.device_fingerprint != self.expected_fingerprint


class SessionIpChangeSpecification(Specification[Session]):
    """Specification for sessions with IP address changes."""
    
    def __init__(self, original_ip: str):
        self.original_ip = original_ip
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session IP has changed from original."""
        if not session.ip_address:
            return True  # No current IP is suspicious
        
        return str(session.ip_address) != self.original_ip


class HighVelocitySessionSpecification(Specification[Session]):
    """Specification for high velocity sessions."""
    
    def __init__(self, activity_threshold: int = 100):
        self.activity_threshold = activity_threshold
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session has high activity velocity."""
        session_duration_hours = (datetime.now(UTC) - session.created_at).total_seconds() / 3600
        if session_duration_hours == 0:
            return False
        
        activity_rate = session.activity_count / session_duration_hours
        return activity_rate > self.activity_threshold


class SessionRequiresRefreshSpecification(Specification[Session]):
    """Specification for sessions requiring token refresh."""
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session requires token refresh."""
        return session.needs_refresh


class StaleSessionSpecification(Specification[Session]):
    """Specification for stale sessions that should be cleaned up."""
    
    def __init__(self, stale_days: int = 30):
        self.stale_threshold = timedelta(days=stale_days)
    
    def is_satisfied_by(self, session: Session) -> bool:
        """Check if session is stale and should be cleaned up."""
        if session.is_active:
            return False  # Active sessions are not stale
        
        time_since_last_activity = datetime.now(UTC) - session.last_activity_at
        return time_since_last_activity > self.stale_threshold
