"""
Session Limit Policy

Business rules for concurrent session limits and session management.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .base import BusinessRule, PolicyViolation


@dataclass
class SessionLimitPolicy(BusinessRule):
    """Policy for session limit management."""
    
    # Configuration parameters
    max_concurrent_sessions: int = 5
    max_sessions_per_device_type: int = 2
    max_sessions_per_ip: int = 3
    enforce_single_session_per_browser: bool = True
    allow_session_override: bool = True
    prioritize_newer_sessions: bool = True
    
    # Device type limits (can be customized)
    device_type_limits: dict[str, int] = None
    
    def __post_init__(self):
        """Initialize device type limits if not provided."""
        if self.device_type_limits is None:
            self.device_type_limits = {
                'web': 3,
                'mobile': 2,
                'desktop': 2,
                'api': 1,
                'tablet': 2
            }
    
    def validate(self, **kwargs) -> list[PolicyViolation]:
        """Validate session limit policy."""
        violations = []
        
        # Extract parameters
        active_sessions = kwargs.get('active_sessions', [])
        new_session_info = kwargs.get('new_session_info', {})
        user_id = kwargs.get('user_id')
        
        # Check total concurrent sessions
        if len(active_sessions) >= self.max_concurrent_sessions:
            violations.append(PolicyViolation(
                rule_name="SessionLimitPolicy",
                description="Maximum concurrent sessions exceeded",
                severity="error" if not self.allow_session_override else "warning",
                current_value=len(active_sessions),
                expected_value=self.max_concurrent_sessions,
                context={
                    "user_id": user_id,
                    "oldest_session": self._get_oldest_session(active_sessions)
                }
            ))
        
        # Check per-device-type limits
        if new_session_info.get('device_type'):
            device_type = new_session_info['device_type']
            device_sessions = [s for s in active_sessions if s.get('device_type') == device_type]
            
            limit = self.device_type_limits.get(device_type, self.max_sessions_per_device_type)
            if len(device_sessions) >= limit:
                violations.append(PolicyViolation(
                    rule_name="SessionLimitPolicy",
                    description=f"Maximum sessions for device type '{device_type}' exceeded",
                    severity="error" if not self.allow_session_override else "warning",
                    current_value=len(device_sessions),
                    expected_value=limit,
                    context={"device_type": device_type}
                ))
        
        # Check per-IP limits
        if new_session_info.get('ip_address'):
            ip_address = new_session_info['ip_address']
            ip_sessions = [s for s in active_sessions if s.get('ip_address') == ip_address]
            
            if len(ip_sessions) >= self.max_sessions_per_ip:
                violations.append(PolicyViolation(
                    rule_name="SessionLimitPolicy",
                    description="Maximum sessions from IP address exceeded",
                    severity="warning",
                    current_value=len(ip_sessions),
                    expected_value=self.max_sessions_per_ip,
                    context={"ip_address": ip_address}
                ))
        
        # Check browser session uniqueness
        if self.enforce_single_session_per_browser and new_session_info.get('browser_fingerprint'):
            browser_fingerprint = new_session_info['browser_fingerprint']
            browser_sessions = [s for s in active_sessions 
                              if s.get('browser_fingerprint') == browser_fingerprint]
            
            if browser_sessions:
                violations.append(PolicyViolation(
                    rule_name="SessionLimitPolicy",
                    description="Session already exists for this browser",
                    severity="info",
                    current_value=len(browser_sessions),
                    expected_value=0,
                    context={
                        "browser_fingerprint": browser_fingerprint,
                        "existing_session_id": browser_sessions[0].get('id')
                    }
                ))
        
        return violations
    
    def is_compliant(self, **kwargs) -> bool:
        """Check if session limits are compliant."""
        violations = self.validate(**kwargs)
        return not self.has_blocking_violations(violations)
    
    def get_sessions_to_terminate(
        self,
        active_sessions: list[dict[str, Any]],
        new_session_info: dict[str, Any]
    ) -> list[str]:
        """
        Determine which sessions should be terminated to make room for new session.
        
        Returns:
            List of session IDs to terminate
        """
        sessions_to_terminate = []
        
        if not self.allow_session_override:
            return sessions_to_terminate
        
        # Sort sessions by creation time
        sorted_sessions = sorted(
            active_sessions,
            key=lambda s: s.get('created_at', datetime.min),
            reverse=self.prioritize_newer_sessions
        )
        
        # Determine how many sessions need to be terminated
        excess_count = len(active_sessions) - self.max_concurrent_sessions + 1
        
        if excess_count > 0:
            # Terminate oldest/newest sessions based on configuration
            for i in range(excess_count):
                if i < len(sorted_sessions):
                    sessions_to_terminate.append(sorted_sessions[i]['id'])
        
        # Also check device type limits
        if new_session_info.get('device_type'):
            device_type = new_session_info['device_type']
            device_sessions = [s for s in active_sessions 
                             if s.get('device_type') == device_type]
            
            limit = self.device_type_limits.get(device_type, self.max_sessions_per_device_type)
            device_excess = len(device_sessions) - limit + 1
            
            if device_excess > 0:
                sorted_device_sessions = sorted(
                    device_sessions,
                    key=lambda s: s.get('created_at', datetime.min),
                    reverse=self.prioritize_newer_sessions
                )
                
                for i in range(device_excess):
                    if i < len(sorted_device_sessions):
                        session_id = sorted_device_sessions[i]['id']
                        if session_id not in sessions_to_terminate:
                            sessions_to_terminate.append(session_id)
        
        return sessions_to_terminate
    
    def _get_oldest_session(self, sessions: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Get the oldest session from the list."""
        if not sessions:
            return None
        
        return min(sessions, key=lambda s: s.get('created_at', datetime.min))
    
    def get_session_statistics(self, active_sessions: list[dict[str, Any]]) -> dict[str, Any]:
        """Get statistics about current sessions."""
        stats = {
            'total_sessions': len(active_sessions),
            'sessions_by_device_type': defaultdict(int),
            'sessions_by_ip': defaultdict(int),
            'oldest_session': None,
            'newest_session': None
        }
        
        for session in active_sessions:
            if session.get('device_type'):
                stats['sessions_by_device_type'][session['device_type']] += 1
            if session.get('ip_address'):
                stats['sessions_by_ip'][session['ip_address']] += 1
        
        if active_sessions:
            stats['oldest_session'] = min(
                active_sessions,
                key=lambda s: s.get('created_at', datetime.max)
            )
            stats['newest_session'] = max(
                active_sessions,
                key=lambda s: s.get('created_at', datetime.min)
            )
        
        return stats