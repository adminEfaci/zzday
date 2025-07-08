"""
Session Mixins

Simple mixins for common session functionality.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from typing import Any

from .session_constants import (
    RISK_ADJUSTMENTS, MAX_SECURITY_EVENTS, SECURITY_EVENTS_KEEP_COUNT,
    DEFAULT_RATE_LIMITS, RISK_DECAY_RATE, MINIMUM_RISK_DECAY
)


class RiskManagementMixin(ABC):
    """Mixin for risk score management."""
    
    risk_score: float
    security_events: list[dict[str, Any]]
    
    def add_security_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Add security event and adjust risk score."""
        event = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "details": details
        }
        
        self.security_events.append(event)
        self._archive_old_events()
        self._adjust_risk_score(event_type)
        
        if self.risk_score >= 0.9:
            self._handle_high_risk()
    
    def _archive_old_events(self) -> None:
        """Keep only recent security events."""
        if len(self.security_events) > MAX_SECURITY_EVENTS:
            archived_count = len(self.security_events) - SECURITY_EVENTS_KEEP_COUNT
            
            if not hasattr(self, 'metadata'):
                self.metadata = {}
            
            archived_total = self.metadata.get('archived_security_events', 0)
            self.metadata['archived_security_events'] = archived_total + archived_count
            self.security_events = self.security_events[-SECURITY_EVENTS_KEEP_COUNT:]
    
    def _adjust_risk_score(self, event_type: str) -> None:
        """Adjust risk score with time-based decay."""
        adjustment = RISK_ADJUSTMENTS.get(event_type, 0.05)
        decay_factor = self._calculate_risk_decay()
        
        self.risk_score = min(1.0, max(0.0, 
            self.risk_score * decay_factor + adjustment
        ))
    
    def _calculate_risk_decay(self) -> float:
        """Calculate risk decay factor."""
        if not hasattr(self, 'last_activity_at'):
            return 1.0
        
        hours_since = (datetime.now(UTC) - self.last_activity_at).total_seconds() / 3600
        return max(MINIMUM_RISK_DECAY, 1.0 - (hours_since * RISK_DECAY_RATE))
    
    @abstractmethod
    def _handle_high_risk(self) -> None:
        """Handle high-risk scenarios."""
        pass


class RateLimitingMixin(ABC):
    """Mixin for rate limiting."""
    
    def check_rate_limit(self, action: str, custom_limit: int = None, window_minutes: int = None) -> bool:
        """Check if action is within rate limits."""
        config = DEFAULT_RATE_LIMITS.get(action, {"limit": 5, "window_minutes": 5})
        limit = custom_limit or config["limit"]
        window = window_minutes or config["window_minutes"]
        
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=window)
        
        rate_limits = getattr(self, 'metadata', {}).get('rate_limits', {})
        attempts = rate_limits.get(action, [])
        
        recent_attempts = [
            attempt for attempt in attempts
            if datetime.fromisoformat(attempt) > window_start
        ]
        
        return len(recent_attempts) < limit
    
    def record_rate_limited_action(self, action: str) -> None:
        """Record a rate-limited action."""
        if not hasattr(self, 'metadata'):
            self.metadata = {}
        
        if 'rate_limits' not in self.metadata:
            self.metadata['rate_limits'] = {}
        
        if action not in self.metadata['rate_limits']:
            self.metadata['rate_limits'][action] = []
        
        self.metadata['rate_limits'][action].append(datetime.now(UTC).isoformat())
        
        # Keep only last 20 attempts
        if len(self.metadata['rate_limits'][action]) > 20:
            self.metadata['rate_limits'][action] = self.metadata['rate_limits'][action][-20:]


class SessionValidationMixin(ABC):
    """Mixin for session validation."""
    
    def validate_integrity(self) -> list[str]:
        """Validate session integrity."""
        issues = []
        
        # Basic field validation
        if hasattr(self, 'access_token') and (not self.access_token or not self.access_token.value):
            issues.append("Missing or invalid access token")
        
        if hasattr(self, 'user_id') and not self.user_id:
            issues.append("Missing user ID")
        
        # Risk score validation
        if hasattr(self, 'risk_score') and not 0.0 <= self.risk_score <= 1.0:
            issues.append("Risk score out of valid range")
        
        # Timestamp validation
        if hasattr(self, 'last_activity_at') and hasattr(self, 'created_at'):
            if self.last_activity_at < self.created_at:
                issues.append("Last activity cannot be before creation")
        
        return issues