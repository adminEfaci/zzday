"""
Session Policy

Business rules for session management and validation.
"""

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from app.core.config import PolicyConfigManager


class SessionType(Enum):
    """Session types."""
    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    SERVICE = "service"
from .base import BusinessRule, PolicyViolation


class SessionPolicy(BusinessRule):
    """Session management policy validation."""
    
    def __init__(self, policy_config: dict[str, Any] | None = None):
        if policy_config:
            self.config = policy_config
        else:
            config_manager = PolicyConfigManager()
            session_config = config_manager.get_session_config()
            self.config = session_config.__dict__
    
    def validate(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate session against policy."""
        violations = []
        
        # Validate session timeout
        violations.extend(self._validate_session_timeout(session_data))
        
        # Validate concurrent sessions
        violations.extend(self._validate_concurrent_sessions(session_data))
        
        # Validate session type rules
        violations.extend(self._validate_session_type_rules(session_data))
        
        # Validate device restrictions
        violations.extend(self._validate_device_restrictions(session_data))
        
        # Validate activity requirements
        violations.extend(self._validate_activity_requirements(session_data))
        
        return violations
    
    def is_compliant(self, session_data: dict[str, Any]) -> bool:
        """Check if session is compliant with policy."""
        violations = self.validate(session_data)
        return not self.has_blocking_violations(violations)
    
    def _validate_session_timeout(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate session timeout rules."""
        violations = []
        
        created_at = session_data.get("created_at")
        last_activity = session_data.get("last_activity", created_at)
        session_type = session_data.get("session_type", SessionType.WEB)
        
        if not created_at:
            violations.append(PolicyViolation(
                rule_name="session_missing_created_at",
                description="Session missing creation timestamp",
                severity="error",
                current_value=None,
                expected_value="datetime"
            ))
            return violations
        
        now = datetime.now(UTC)
        
        # Check absolute timeout
        absolute_timeout = self._get_absolute_timeout(session_type)
        session_age = now - created_at
        
        if session_age > absolute_timeout:
            violations.append(PolicyViolation(
                rule_name="session_absolute_timeout",
                description="Session exceeds absolute timeout",
                severity="error",
                current_value=session_age,
                expected_value=absolute_timeout
            ))
        
        # Check idle timeout
        if last_activity:
            idle_timeout = self._get_idle_timeout(session_type)
            idle_time = now - last_activity
            
            if idle_time > idle_timeout:
                violations.append(PolicyViolation(
                    rule_name="session_idle_timeout",
                    description="Session idle timeout exceeded",
                    severity="error",
                    current_value=idle_time,
                    expected_value=idle_timeout
                ))
        
        # Check if session needs renewal
        renewal_threshold = absolute_timeout * 0.8
        if session_age > renewal_threshold:
            violations.append(PolicyViolation(
                rule_name="session_renewal_needed",
                description="Session approaching expiration, renewal recommended",
                severity="warning",
                current_value=session_age,
                expected_value=renewal_threshold
            ))
        
        return violations
    
    def _validate_concurrent_sessions(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate concurrent session limits."""
        violations = []
        
        session_data.get("user_id")
        concurrent_count = session_data.get("concurrent_sessions", 0)
        session_type = session_data.get("session_type", SessionType.WEB)
        user_role = session_data.get("user_role", "user")
        
        # Get max concurrent sessions based on type and role
        max_concurrent = self._get_max_concurrent_sessions(session_type, user_role)
        
        if concurrent_count > max_concurrent:
            violations.append(PolicyViolation(
                rule_name="concurrent_session_limit",
                description=f"Too many concurrent {session_type} sessions",
                severity="error",
                current_value=concurrent_count,
                expected_value=max_concurrent
            ))
        
        # Check device-specific limits
        if "device_sessions" in session_data:
            device_sessions = session_data["device_sessions"]
            max_per_device = self.config.get("max_sessions_per_device", 2)
            
            if device_sessions > max_per_device:
                violations.append(PolicyViolation(
                    rule_name="device_session_limit",
                    description="Too many sessions from same device",
                    severity="warning",
                    current_value=device_sessions,
                    expected_value=max_per_device
                ))
        
        return violations
    
    def _validate_session_type_rules(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate session type specific rules."""
        violations = []
        
        session_type = session_data.get("session_type", SessionType.WEB)
        device_type = session_data.get("device_type")
        
        # API sessions must have API key
        if session_type == SessionType.API and not session_data.get("api_key_id"):
            violations.append(PolicyViolation(
                rule_name="api_session_missing_key",
                description="API session must be associated with an API key",
                severity="error",
                current_value=None,
                expected_value="api_key_id"
            ))
        
        # Mobile sessions must have device info
        if session_type == SessionType.MOBILE:
            if not device_type:
                violations.append(PolicyViolation(
                    rule_name="mobile_session_missing_device",
                    description="Mobile session must have device type",
                    severity="error",
                    current_value=None,
                    expected_value="device_type"
                ))
            
            if not session_data.get("device_id"):
                violations.append(PolicyViolation(
                    rule_name="mobile_session_missing_device_id",
                    description="Mobile session must have device ID",
                    severity="warning",
                    current_value=None,
                    expected_value="device_id"
                ))
        
        # Service sessions have special rules
        if session_type == SessionType.SERVICE:
            if not session_data.get("service_account"):
                violations.append(PolicyViolation(
                    rule_name="service_session_missing_account",
                    description="Service session must be linked to service account",
                    severity="error",
                    current_value=None,
                    expected_value="service_account"
                ))
        
        return violations
    
    def _validate_device_restrictions(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate device-based restrictions."""
        violations = []
        
        device_trusted = session_data.get("device_trusted", False)
        device_type = session_data.get("device_type")
        require_trusted = session_data.get("require_trusted_device", False)
        
        # Check trusted device requirement
        if require_trusted and not device_trusted:
            violations.append(PolicyViolation(
                rule_name="untrusted_device",
                description="Session requires trusted device",
                severity="error",
                current_value=device_trusted,
                expected_value=True
            ))
        
        # Check device type restrictions
        if device_type and self.config.get("restricted_device_types"):
            restricted_types = self.config["restricted_device_types"]
            if device_type in restricted_types:
                violations.append(PolicyViolation(
                    rule_name="restricted_device_type",
                    description=f"Device type {device_type} is restricted",
                    severity="warning",
                    current_value=device_type,
                    expected_value=f"not in {restricted_types}"
                ))
        
        return violations
    
    def _validate_activity_requirements(self, session_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate session activity requirements."""
        violations = []
        
        session_data.get("last_activity")
        activity_count = session_data.get("activity_count", 0)
        session_age = datetime.now(UTC) - session_data.get("created_at", datetime.now(UTC))
        
        # Check for suspicious inactivity
        if session_age > timedelta(hours=1) and activity_count == 0:
            violations.append(PolicyViolation(
                rule_name="session_no_activity",
                description="Session has no activity after creation",
                severity="warning",
                current_value=activity_count,
                expected_value="> 0"
            ))
        
        # Check for activity spikes
        if "activity_rate" in session_data:
            max_rate = self.config.get("max_activity_rate", 100)  # per minute
            current_rate = session_data["activity_rate"]
            
            if current_rate > max_rate:
                violations.append(PolicyViolation(
                    rule_name="excessive_activity_rate",
                    description="Session activity rate too high",
                    severity="warning",
                    current_value=current_rate,
                    expected_value=max_rate
                ))
        
        return violations
    
    def _get_absolute_timeout(self, session_type: SessionType) -> timedelta:
        """Get absolute timeout for session type."""
        timeouts = self.config.get("timeout_by_type", {})
        default_timeout = self.config.get("absolute_timeout_minutes", 480)
        
        timeout_minutes = timeouts.get(session_type.value, default_timeout)
        return timedelta(minutes=timeout_minutes)
    
    def _get_idle_timeout(self, session_type: SessionType) -> timedelta:
        """Get idle timeout for session type."""
        timeouts = self.config.get("timeout_by_type", {})
        default_timeout = self.config.get("idle_timeout_minutes", 30)
        
        timeout_minutes = timeouts.get(session_type.value, default_timeout)
        return timedelta(minutes=timeout_minutes)
    
    def _get_max_concurrent_sessions(self, session_type: SessionType, user_role: str) -> int:
        """Get maximum concurrent sessions allowed."""
        # Role-based limits override type-based limits
        role_limits = self.config.get("max_concurrent_by_role", {})
        if user_role in role_limits:
            return role_limits[user_role]
        
        # Type-based limits
        type_limits = self.config.get("max_concurrent_by_type", {})
        if session_type.value in type_limits:
            return type_limits[session_type.value]
        
        # Default limit
        return self.config.get("max_concurrent_sessions", 5)
    
    def should_extend_session(self, session_data: dict[str, Any]) -> bool:
        """Determine if session should be extended."""
        # Don't extend if already violated
        if not self.is_compliant(session_data):
            return False
        
        # Check if approaching timeout
        created_at = session_data.get("created_at", datetime.now(UTC))
        session_type = session_data.get("session_type", SessionType.WEB)
        absolute_timeout = self._get_absolute_timeout(session_type)
        
        session_age = datetime.now(UTC) - created_at
        extension_threshold = absolute_timeout * 0.7
        
        return session_age > extension_threshold
    
    def calculate_session_risk_score(self, session_data: dict[str, Any]) -> float:
        """Calculate risk score for session (0.0 to 1.0)."""
        risk_score = 0.0
        
        # Untrusted device
        if not session_data.get("device_trusted", False):
            risk_score += 0.2
        
        # New device
        if session_data.get("device_new", False):
            risk_score += 0.15
        
        # Unusual location
        if session_data.get("location_unusual", False):
            risk_score += 0.25
        
        # High concurrent sessions
        concurrent = session_data.get("concurrent_sessions", 0)
        if concurrent > 3:
            risk_score += min(concurrent * 0.05, 0.2)
        
        # Suspicious activity pattern
        if session_data.get("suspicious_activity", False):
            risk_score += 0.3
        
        # API or service sessions have lower base risk
        session_type = session_data.get("session_type", SessionType.WEB)
        if session_type in [SessionType.API, SessionType.SERVICE]:
            risk_score *= 0.7
        
        return min(risk_score, 1.0)
