"""Interface for Session Validation Domain Service."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.modules.identity.domain.value_objects import IpAddress, Geolocation


class SessionValidationResult(BaseModel):
    """Result of session validation."""
    is_valid: bool
    errors: list[str] = []
    warnings: list[str] = []
    risk_score: float = 0.0
    recommendations: list[str] = []


class SessionSecurityAssessment(BaseModel):
    """Result of session security assessment."""
    risk_level: str  # low, medium, high, critical
    risk_score: float
    security_events: list[str] = []
    threat_indicators: list[str] = []
    requires_termination: bool = False
    requires_mfa: bool = False


class LocationValidationResult(BaseModel):
    """Result of location validation."""
    is_valid: bool
    is_impossible_travel: bool
    travel_speed_kmh: float | None = None
    distance_km: float | None = None
    time_difference_hours: float | None = None
    risk_factor: float = 0.0


class PrivilegeElevationResult(BaseModel):
    """Result of privilege elevation validation."""
    can_elevate: bool
    max_duration: timedelta
    requires_additional_auth: bool = False
    restrictions: list[str] = []


class SessionExtensionResult(BaseModel):
    """Result of session extension validation."""
    can_extend: bool
    max_extension: timedelta
    new_expiry: datetime | None = None
    rate_limit_remaining: int = 0
    restrictions: list[str] = []


class ISessionValidationService(ABC):
    """Interface for Session Validation Domain Service.
    
    This service handles complex session validation logic that should not
    be embedded in the Session aggregate, following DDD principles.
    This focuses on domain-level validation within the aggregate.
    """
    
    @abstractmethod
    def validate_session_integrity(self, session: "Session") -> SessionValidationResult:
        """Validate session integrity and consistency.
        
        Args:
            session: The session to validate
            
        Returns:
            SessionValidationResult with validation details
        """
        pass
    
    @abstractmethod
    def assess_session_security(self, session: "Session") -> SessionSecurityAssessment:
        """Assess session security and risk level.
        
        Args:
            session: The session to assess
            
        Returns:
            SessionSecurityAssessment with security analysis
        """
        pass
    
    @abstractmethod
    def validate_device_fingerprint(self, session: "Session", fingerprint: str) -> bool:
        """Validate device fingerprint for session security.
        
        Args:
            session: The session to validate
            fingerprint: Device fingerprint to validate
            
        Returns:
            True if fingerprint is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_location_change(self, session: "Session", new_ip: IpAddress, 
                               new_location: Geolocation | None) -> LocationValidationResult:
        """Validate location change for impossible travel detection.
        
        Args:
            session: The session with location change
            new_ip: New IP address
            new_location: New geolocation (if available)
            
        Returns:
            LocationValidationResult with travel validation
        """
        pass
    
    @abstractmethod
    def calculate_session_expiry(self, session: "Session") -> datetime:
        """Calculate when session should expire.
        
        Args:
            session: The session to calculate expiry for
            
        Returns:
            Calculated expiry datetime
        """
        pass
    
    @abstractmethod
    def should_session_expire(self, session: "Session") -> bool:
        """Determine if session should be expired.
        
        Args:
            session: The session to check
            
        Returns:
            True if session should expire, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_token_refresh(self, session: "Session") -> bool:
        """Validate if session tokens can be refreshed.
        
        Args:
            session: The session requesting refresh
            
        Returns:
            True if tokens can be refreshed, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_session_extension(self, session: "Session", 
                                 duration: timedelta) -> SessionExtensionResult:
        """Validate session extension request.
        
        Args:
            session: The session to extend
            duration: Requested extension duration
            
        Returns:
            SessionExtensionResult with extension validation
        """
        pass
    
    @abstractmethod
    def validate_privilege_elevation(self, session: "Session", 
                                   reason: str) -> PrivilegeElevationResult:
        """Validate privilege elevation request.
        
        Args:
            session: The session requesting elevation
            reason: Reason for elevation
            
        Returns:
            PrivilegeElevationResult with elevation validation
        """
        pass
    
    @abstractmethod
    def should_require_mfa(self, session: "Session") -> bool:
        """Determine if session should require MFA.
        
        Args:
            session: The session to check
            
        Returns:
            True if MFA is required, False otherwise
        """
        pass
    
    @abstractmethod
    def calculate_risk_score(self, session: "Session") -> float:
        """Calculate session risk score.
        
        Args:
            session: The session to assess
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        pass
    
    @abstractmethod
    def detect_anomalous_activity(self, session: "Session", 
                                 activity_type: str) -> bool:
        """Detect anomalous session activity.
        
        Args:
            session: The session to check
            activity_type: Type of activity to analyze
            
        Returns:
            True if activity is anomalous, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_rate_limit(self, session: "Session", action: str, 
                          custom_limit: int | None = None) -> bool:
        """Validate if action is within rate limits.
        
        Args:
            session: The session performing the action
            action: Action being performed
            custom_limit: Optional custom rate limit
            
        Returns:
            True if within limits, False otherwise
        """
        pass
    
    @abstractmethod
    def should_terminate_session(self, session: "Session") -> tuple[bool, str]:
        """Determine if session should be terminated.
        
        Args:
            session: The session to check
            
        Returns:
            Tuple of (should_terminate, reason)
        """
        pass
    
    @abstractmethod
    def validate_session_resumption(self, session: "Session") -> bool:
        """Validate if suspended session can be resumed.
        
        Args:
            session: The session to resume
            
        Returns:
            True if session can be resumed, False otherwise
        """
        pass
    
    @abstractmethod
    def get_session_security_recommendations(self, session: "Session") -> list[str]:
        """Get security recommendations for session.
        
        Args:
            session: The session to analyze
            
        Returns:
            List of security recommendations
        """
        pass
    
    @abstractmethod
    def calculate_idle_timeout(self, session: "Session") -> timedelta:
        """Calculate idle timeout for session.
        
        Args:
            session: The session to calculate timeout for
            
        Returns:
            Idle timeout duration
        """
        pass
    
    @abstractmethod
    def validate_session_activity(self, session: "Session", 
                                 activity_type: str) -> bool:
        """Validate if session activity is allowed.
        
        Args:
            session: The session performing activity
            activity_type: Type of activity
            
        Returns:
            True if activity is allowed, False otherwise
        """
        pass
    
    @abstractmethod
    def track_security_event(self, session: "Session", event_type: str, 
                           details: dict[str, Any]) -> None:
        """Track session security event.
        
        Args:
            session: The session with security event
            event_type: Type of security event
            details: Event details
        """
        pass
    
    @abstractmethod
    def apply_risk_mitigation(self, session: "Session", 
                            mitigation_strategy: str) -> None:
        """Apply risk mitigation strategy to session.
        
        Args:
            session: The session to apply mitigation to
            mitigation_strategy: Type of mitigation to apply
        """
        pass
    
    @abstractmethod
    def calculate_risk_decay_factor(self, session: "Session") -> float:
        """Calculate risk decay factor based on session activity.
        
        Args:
            session: The session to calculate decay for
            
        Returns:
            Risk decay factor between 0.0 and 1.0
        """
        pass
    
    @abstractmethod
    def get_session_health_score(self, session: "Session") -> float:
        """Get overall session health score.
        
        Args:
            session: The session to assess
            
        Returns:
            Health score between 0.0 and 1.0
        """
        pass