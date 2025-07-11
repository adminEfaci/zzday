"""Interface for User Authentication Domain Service."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.modules.identity.domain.aggregates.user import User


class LoginAttemptResult(BaseModel):
    """Result of a login attempt."""
    success: bool
    should_lock_account: bool
    lock_duration: timedelta | None = None
    remaining_attempts: int
    risk_score: float
    metadata: dict[str, Any] = {}


class AuthenticationContext(BaseModel):
    """Context for authentication operations."""
    user_id: UUID
    ip_address: str | None = None
    user_agent: str | None = None
    device_fingerprint: str | None = None
    location: str | None = None
    timestamp: datetime
    additional_context: dict[str, Any] = {}


class PasswordValidationResult(BaseModel):
    """Result of password validation."""
    is_valid: bool
    errors: list[str] = []
    strength_score: float = 0.0
    meets_policy: bool = False
    suggestions: list[str] = []


class SecurityAssessmentResult(BaseModel):
    """Result of security assessment."""
    risk_level: str  # low, medium, high, critical
    risk_score: float
    factors: list[str] = []
    recommendations: list[str] = []
    requires_additional_verification: bool = False


class IUserAuthenticationService(ABC):
    """Interface for User Authentication Domain Service.
    
    This service handles complex authentication logic that should not
    be embedded in the User aggregate, following DDD principles.
    """
    
    @abstractmethod
    def validate_password_policy(self, password: str, user: User) -> PasswordValidationResult:
        """Validate password against security policies.
        
        Args:
            password: The password to validate
            user: The user attempting to change password
            
        Returns:
            PasswordValidationResult with validation details
        """
        pass
    
    @abstractmethod
    def process_login_attempt(self, user: User, success: bool, context: AuthenticationContext) -> LoginAttemptResult:
        """Process a login attempt and determine security actions.
        
        Args:
            user: The user attempting to log in
            success: Whether the login was successful
            context: Authentication context (IP, device, etc.)
            
        Returns:
            LoginAttemptResult with security recommendations
        """
        pass
    
    @abstractmethod
    def assess_authentication_risk(self, user: User, context: AuthenticationContext) -> SecurityAssessmentResult:
        """Assess the risk level of an authentication attempt.
        
        Args:
            user: The user being authenticated
            context: Authentication context
            
        Returns:
            SecurityAssessmentResult with risk assessment
        """
        pass
    
    @abstractmethod
    def should_require_mfa(self, user: User, context: AuthenticationContext) -> bool:
        """Determine if MFA should be required for this authentication.
        
        Args:
            user: The user being authenticated
            context: Authentication context
            
        Returns:
            True if MFA is required, False otherwise
        """
        pass
    
    @abstractmethod
    def calculate_lock_duration(self, user: User, failed_attempts: int) -> timedelta:
        """Calculate how long an account should be locked.
        
        Args:
            user: The user whose account is being locked
            failed_attempts: Number of failed login attempts
            
        Returns:
            Duration for account lock
        """
        pass
    
    @abstractmethod
    def should_unlock_account(self, user: User, unlock_context: AuthenticationContext) -> bool:
        """Determine if an account should be unlocked.
        
        Args:
            user: The user whose account is being unlocked
            unlock_context: Context for the unlock request
            
        Returns:
            True if account should be unlocked, False otherwise
        """
        pass
    
    @abstractmethod
    def evaluate_password_strength(self, password: str) -> float:
        """Evaluate password strength on a scale of 0.0 to 1.0.
        
        Args:
            password: The password to evaluate
            
        Returns:
            Password strength score (0.0 = very weak, 1.0 = very strong)
        """
        pass
    
    @abstractmethod
    def get_security_recommendations(self, user: User) -> list[str]:
        """Get security recommendations for a user.
        
        Args:
            user: The user to assess
            
        Returns:
            List of security recommendations
        """
        pass
    
    @abstractmethod
    def should_regenerate_security_stamp(self, user: User, operation: str) -> bool:
        """Determine if security stamp should be regenerated.
        
        Args:
            user: The user performing the operation
            operation: The type of operation (password_change, email_change, etc.)
            
        Returns:
            True if security stamp should be regenerated
        """
        pass
    
    @abstractmethod
    def validate_account_status(self, user: User) -> tuple[bool, str]:
        """Validate if account is in a valid state for authentication.
        
        Args:
            user: The user to validate
            
        Returns:
            Tuple of (is_valid, reason) where reason explains why account is invalid
        """
        pass
    
    @abstractmethod
    def track_security_event(self, user: User, event_type: str, context: AuthenticationContext) -> None:
        """Track security-related events for monitoring.
        
        Args:
            user: The user associated with the event
            event_type: Type of security event
            context: Context of the event
        """
        pass
    
    @abstractmethod
    def detect_anomalous_behavior(self, user: User, context: AuthenticationContext) -> bool:
        """Detect if authentication attempt shows anomalous behavior.
        
        Args:
            user: The user being authenticated
            context: Authentication context
            
        Returns:
            True if behavior is anomalous, False otherwise
        """
        pass
    
    @abstractmethod
    def get_authentication_history(self, user: User, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent authentication history for a user.
        
        Args:
            user: The user to get history for
            limit: Maximum number of records to return
            
        Returns:
            List of authentication history records
        """
        pass