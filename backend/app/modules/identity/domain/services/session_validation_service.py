"""Basic implementation of SessionValidationService."""

import math
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from ..interfaces.services.session_validation_service import (
    ISessionValidationService,
    LocationValidationResult,
    PrivilegeElevationResult,
    SessionExtensionResult,
    SessionSecurityAssessment,
    SessionValidationResult,
)
from ..value_objects import Geolocation, IpAddress

if TYPE_CHECKING:
    from ..aggregates.session import Session


class SessionValidationService(ISessionValidationService):
    """Basic implementation of session validation service.
    
    This service implements session validation logic that was extracted
    from the Session aggregate to follow DDD principles.
    """
    
    def validate_session_integrity(self, session: "Session") -> SessionValidationResult:
        """Validate session integrity and consistency."""
        errors = []
        warnings = []
        recommendations = []
        
        # Check basic session requirements
        if not session.access_token:
            errors.append("Session missing access token")
        
        if not session.user_id:
            errors.append("Session missing user ID")
        
        # Check session status
        if session.status.value not in ["ACTIVE", "SUSPENDED", "EXPIRED"]:
            errors.append(f"Invalid session status: {session.status.value}")
        
        # Check risk score bounds
        if not (0.0 <= session.risk_score <= 1.0):
            errors.append(f"Risk score out of bounds: {session.risk_score}")
        
        # Check timestamp consistency
        if session.created_at > datetime.now(UTC):
            errors.append("Session creation time is in the future")
        
        if session.last_activity and session.last_activity > datetime.now(UTC):
            errors.append("Last activity time is in the future")
        
        # Check expiry logic
        if session.expires_at and session.expires_at < session.created_at:
            errors.append("Session expiry is before creation time")
        
        # Check MFA state consistency
        if session.mfa_completed and not session.mfa_required:
            warnings.append("MFA completed but not required")
        
        # Generate recommendations
        if session.risk_score > 0.7:
            recommendations.append("Consider terminating high-risk session")
        
        if not session.mfa_completed and session.mfa_required:
            recommendations.append("Complete MFA to improve session security")
        
        return SessionValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            risk_score=session.risk_score,
            recommendations=recommendations
        )
    
    def assess_session_security(self, session: "Session") -> SessionSecurityAssessment:
        """Assess session security and risk level."""
        security_events = []
        threat_indicators = []
        
        # Check for security events
        if hasattr(session, 'security_events') and session.security_events:
            security_events.extend([event.get('type', 'unknown') for event in session.security_events])
        
        # Check for threat indicators
        if session.risk_score > 0.8:
            threat_indicators.append("Very high risk score")
        
        if session.failed_attempts > 3:
            threat_indicators.append("Multiple failed attempts")
        
        # Check for impossible travel
        if hasattr(session, 'location_changes') and len(session.location_changes) > 1:
            # Simple check for rapid location changes
            recent_changes = [change for change in session.location_changes 
                            if change.get('timestamp', datetime.min) > datetime.now(UTC) - timedelta(hours=1)]
            if len(recent_changes) > 2:
                threat_indicators.append("Rapid location changes")
        
        # Calculate risk level
        risk_score = self.calculate_risk_score(session)
        
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return SessionSecurityAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            security_events=security_events,
            threat_indicators=threat_indicators,
            requires_termination=risk_score >= 0.9,
            requires_mfa=risk_score >= 0.7 and not session.mfa_completed
        )
    
    def validate_device_fingerprint(self, session: "Session", fingerprint: str) -> bool:
        """Validate device fingerprint for session security."""
        if not session.device_fingerprint:
            return True  # No fingerprint to validate against
        
        # Simple fingerprint validation
        return session.device_fingerprint == fingerprint
    
    def validate_location_change(self, session: "Session", new_ip: IpAddress, 
                               new_location: Geolocation | None) -> LocationValidationResult:
        """Validate location change for impossible travel detection."""
        if not session.ip_address or not session.geolocation:
            return LocationValidationResult(
                is_valid=True,
                is_impossible_travel=False,
                risk_factor=0.0
            )
        
        # Calculate distance and time difference
        if new_location and session.geolocation:
            distance_km = self._calculate_distance(
                session.geolocation.latitude,
                session.geolocation.longitude,
                new_location.latitude,
                new_location.longitude
            )
            
            time_diff_hours = (datetime.now(UTC) - session.last_activity).total_seconds() / 3600
            
            if time_diff_hours > 0:
                speed_kmh = distance_km / time_diff_hours
                
                # Check for impossible travel (faster than commercial flight)
                is_impossible = speed_kmh > 1000  # 1000 km/h threshold
                
                risk_factor = min(1.0, speed_kmh / 1000)
                
                return LocationValidationResult(
                    is_valid=not is_impossible,
                    is_impossible_travel=is_impossible,
                    travel_speed_kmh=speed_kmh,
                    distance_km=distance_km,
                    time_difference_hours=time_diff_hours,
                    risk_factor=risk_factor
                )
        
        return LocationValidationResult(
            is_valid=True,
            is_impossible_travel=False,
            risk_factor=0.1  # Small risk for location change
        )
    
    def calculate_session_expiry(self, session: "Session") -> datetime:
        """Calculate when session should expire."""
        base_duration = timedelta(hours=24)  # Default 24 hours
        
        # Adjust based on session type
        if session.session_type == "ADMIN":
            base_duration = timedelta(hours=1)  # Shorter for admin sessions
        elif session.session_type == "API":
            base_duration = timedelta(hours=24)  # Longer for API sessions
        
        # Adjust based on risk score
        if session.risk_score > 0.7:
            base_duration = base_duration / 2  # Halve duration for high risk
        
        return session.created_at + base_duration
    
    def should_session_expire(self, session: "Session") -> bool:
        """Determine if session should be expired."""
        if session.status.value == "EXPIRED":
            return True
        
        calculated_expiry = self.calculate_session_expiry(session)
        return datetime.now(UTC) >= calculated_expiry
    
    def validate_token_refresh(self, session: "Session") -> bool:
        """Validate if session tokens can be refreshed."""
        if session.status.value not in ["ACTIVE", "SUSPENDED"]:
            return False
        
        if not session.refresh_token:
            return False
        
        # Check if session is too old to refresh
        age_hours = (datetime.now(UTC) - session.created_at).total_seconds() / 3600
        if age_hours > 168:  # 7 days max
            return False
        
        return True
    
    def validate_session_extension(self, session: "Session", 
                                 duration: timedelta) -> SessionExtensionResult:
        """Validate session extension request."""
        max_extension = timedelta(hours=24)
        rate_limit_remaining = 5  # Allow 5 extensions per day
        
        can_extend = (
            session.status.value == "ACTIVE" and
            duration <= max_extension and
            session.risk_score < 0.6
        )
        
        restrictions = []
        if session.risk_score >= 0.6:
            restrictions.append("Cannot extend high-risk session")
        
        if duration > max_extension:
            restrictions.append(f"Extension cannot exceed {max_extension}")
        
        new_expiry = None
        if can_extend:
            new_expiry = datetime.now(UTC) + duration
        
        return SessionExtensionResult(
            can_extend=can_extend,
            max_extension=max_extension,
            new_expiry=new_expiry,
            rate_limit_remaining=rate_limit_remaining,
            restrictions=restrictions
        )
    
    def validate_privilege_elevation(self, session: "Session", 
                                   reason: str) -> PrivilegeElevationResult:
        """Validate privilege elevation request."""
        max_duration = timedelta(minutes=15)  # Default 15 minutes
        
        can_elevate = (
            session.status.value == "ACTIVE" and
            session.mfa_completed and
            session.risk_score < 0.5
        )
        
        requires_additional_auth = session.risk_score > 0.3
        
        restrictions = []
        if not session.mfa_completed:
            restrictions.append("MFA required for privilege elevation")
        
        if session.risk_score >= 0.5:
            restrictions.append("Risk score too high for elevation")
        
        return PrivilegeElevationResult(
            can_elevate=can_elevate,
            max_duration=max_duration,
            requires_additional_auth=requires_additional_auth,
            restrictions=restrictions
        )
    
    def should_require_mfa(self, session: "Session") -> bool:
        """Determine if session should require MFA."""
        # Always require MFA for admin sessions
        if session.session_type == "ADMIN":
            return True
        
        # Require MFA for high-risk sessions
        if session.risk_score > 0.6:
            return True
        
        # Require MFA for privilege elevation
        if hasattr(session, 'privilege_elevated') and session.privilege_elevated:
            return True
        
        return False
    
    def calculate_risk_score(self, session: "Session") -> float:
        """Calculate session risk score."""
        base_score = 0.0
        
        # Age factor
        age_hours = (datetime.now(UTC) - session.created_at).total_seconds() / 3600
        if age_hours > 24:
            base_score += 0.1
        
        # Failed attempts
        if hasattr(session, 'failed_attempts'):
            base_score += min(0.3, session.failed_attempts * 0.1)
        
        # Location changes
        if hasattr(session, 'location_changes') and session.location_changes:
            base_score += min(0.2, len(session.location_changes) * 0.05)
        
        # Apply risk decay
        decay_factor = self.calculate_risk_decay_factor(session)
        base_score *= decay_factor
        
        return min(1.0, base_score)
    
    def detect_anomalous_activity(self, session: "Session", 
                                 activity_type: str) -> bool:
        """Detect anomalous session activity."""
        # Check for unusual activity patterns
        if activity_type == "login" and session.failed_attempts > 5:
            return True
        
        if activity_type == "admin_action" and session.risk_score > 0.5:
            return True
        
        # Check for rapid requests
        if hasattr(session, 'request_count') and session.request_count > 100:
            return True
        
        return False
    
    def validate_rate_limit(self, session: "Session", action: str, 
                          custom_limit: int | None = None) -> bool:
        """Validate if action is within rate limits."""
        limits = {
            "login": 5,
            "api_call": 100,
            "admin_action": 10,
            "password_change": 3
        }
        
        limit = custom_limit or limits.get(action, 50)
        
        # Simple rate limiting check
        if hasattr(session, 'action_counts'):
            current_count = session.action_counts.get(action, 0)
            return current_count < limit
        
        return True
    
    def should_terminate_session(self, session: "Session") -> tuple[bool, str]:
        """Determine if session should be terminated."""
        if session.risk_score >= 0.9:
            return True, "Critical risk score"
        
        if self.should_session_expire(session):
            return True, "Session expired"
        
        if hasattr(session, 'failed_attempts') and session.failed_attempts > 10:
            return True, "Too many failed attempts"
        
        return False, ""
    
    def validate_session_resumption(self, session: "Session") -> bool:
        """Validate if suspended session can be resumed."""
        if session.status.value != "SUSPENDED":
            return False
        
        # Check if suspension period has expired
        if hasattr(session, 'suspended_until') and session.suspended_until:
            return datetime.now(UTC) >= session.suspended_until
        
        return True
    
    def get_session_security_recommendations(self, session: "Session") -> list[str]:
        """Get security recommendations for session."""
        recommendations = []
        
        if not session.mfa_completed:
            recommendations.append("Complete multi-factor authentication")
        
        if session.risk_score > 0.7:
            recommendations.append("Consider terminating high-risk session")
        
        if not session.device_fingerprint:
            recommendations.append("Enable device fingerprinting")
        
        age_hours = (datetime.now(UTC) - session.created_at).total_seconds() / 3600
        if age_hours > 24:
            recommendations.append("Consider refreshing long-lived session")
        
        return recommendations
    
    def calculate_idle_timeout(self, session: "Session") -> timedelta:
        """Calculate idle timeout for session."""
        base_timeout = timedelta(minutes=30)
        
        # Adjust based on session type
        if session.session_type == "ADMIN":
            base_timeout = timedelta(minutes=15)
        elif session.session_type == "API":
            base_timeout = timedelta(hours=1)
        
        # Adjust based on risk score
        if session.risk_score > 0.5:
            base_timeout = base_timeout / 2
        
        return base_timeout
    
    def validate_session_activity(self, session: "Session", 
                                 activity_type: str) -> bool:
        """Validate if session activity is allowed."""
        if session.status.value != "ACTIVE":
            return False
        
        # Check if activity is appropriate for session type
        if activity_type == "admin_action" and session.session_type != "ADMIN":
            return False
        
        # Check rate limits
        return self.validate_rate_limit(session, activity_type)
    
    def track_security_event(self, session: "Session", event_type: str, 
                           details: dict[str, Any]) -> None:
        """Track session security event."""
        # In a real implementation, this would log to a security monitoring system
        print(f"Security event: {event_type} for session {session.id}")
    
    def apply_risk_mitigation(self, session: "Session", 
                            mitigation_strategy: str) -> None:
        """Apply risk mitigation strategy to session."""
        # In a real implementation, this would apply various mitigation strategies
        print(f"Applying mitigation: {mitigation_strategy} to session {session.id}")
    
    def calculate_risk_decay_factor(self, session: "Session") -> float:
        """Calculate risk decay factor based on session activity."""
        if not session.last_activity:
            return 1.0
        
        hours_since_activity = (datetime.now(UTC) - session.last_activity).total_seconds() / 3600
        
        # Risk decays over time (half-life of 24 hours)
        decay_factor = 0.5 ** (hours_since_activity / 24)
        
        return max(0.1, decay_factor)  # Minimum decay factor
    
    def get_session_health_score(self, session: "Session") -> float:
        """Get overall session health score."""
        health_score = 1.0
        
        # Reduce score for high risk
        health_score -= session.risk_score * 0.5
        
        # Reduce score for age
        age_hours = (datetime.now(UTC) - session.created_at).total_seconds() / 3600
        if age_hours > 24:
            health_score -= 0.2
        
        # Reduce score for failed attempts
        if hasattr(session, 'failed_attempts'):
            health_score -= min(0.3, session.failed_attempts * 0.05)
        
        # Bonus for MFA completion
        if session.mfa_completed:
            health_score += 0.1
        
        return max(0.0, min(1.0, health_score))
    
    def _calculate_distance(self, lat1: float, lon1: float, 
                          lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates using Haversine formula."""
        R = 6371  # Earth's radius in kilometers
        
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        # Haversine formula
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c