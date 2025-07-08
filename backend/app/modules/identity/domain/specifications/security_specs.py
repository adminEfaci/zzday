"""
Security Domain Specifications

Business rule specifications for security-related operations.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.infrastructure.specification import Specification

from ..aggregates.user import User
from ..entities.login_attempt import LoginAttempt
from ..value_objects.ip_address import IpAddress
from .base import ParameterizedSpecification


class HighRiskSpecification(ParameterizedSpecification[LoginAttempt]):
    """Specification for high-risk login attempts."""
    
    def __init__(self, risk_threshold: float = 0.7):
        super().__init__(risk_threshold=risk_threshold)
    
    def _validate_parameters(self) -> None:
        """Validate risk threshold parameter."""
        threshold = self.parameters.get('risk_threshold', 0.7)
        if not isinstance(threshold, int | float):
            raise ValueError("Risk threshold must be a number")
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Risk threshold must be between 0.0 and 1.0")
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt is high risk."""
        self.validate_candidate(login_attempt)
        return login_attempt.risk_score >= self.parameters['risk_threshold']


class SuspiciousActivitySpecification(Specification[LoginAttempt]):
    """Specification for suspicious login activity."""
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt shows suspicious activity."""
        return login_attempt.is_suspicious()


class ComplianceSpecification(Specification[User]):
    """Specification for compliance requirements."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user meets compliance requirements."""
        # Must have verified email
        if not user.email_verified:
            return False
        
        # Must have strong password (check password change date)
        if not user.password_changed_at:
            return False
        
        # Password must not be too old
        password_age = datetime.now(UTC) - user.password_changed_at
        if password_age > timedelta(days=90):
            return False
        
        # High privilege users must have MFA
        return not (self._is_high_privilege_user(user) and not user.mfa_enabled)
    
    def _is_high_privilege_user(self, user: User) -> bool:
        """Check if user has high privileges."""
        admin_roles = ['admin', 'super_admin', 'system_admin']
        return any(r.name.lower() in admin_roles for r in user._roles)


class FailedLoginSpecification(Specification[LoginAttempt]):
    """Specification for failed login attempts."""
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt failed."""
        return not login_attempt.success


class SecurityEventSpecification(Specification[dict[str, Any]]):
    """Specification for security events."""
    
    def __init__(self, event_types: list[str]):
        self.event_types = event_types
    
    def is_satisfied_by(self, event: dict[str, Any]) -> bool:
        """Check if event is a security event of specified types."""
        return event.get('type') in self.event_types


class BotActivitySpecification(Specification[LoginAttempt]):
    """Specification for bot activity detection."""
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt shows bot activity."""
        user_agent = login_attempt.user_agent.lower()
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'automated']
        return any(indicator in user_agent for indicator in bot_indicators)


class AnomalousLocationSpecification(Specification[LoginAttempt]):
    """Specification for anomalous location detection."""
    
    def __init__(self, user_typical_locations: list[dict[str, Any]]):
        self.user_typical_locations = user_typical_locations
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt is from anomalous location."""
        if not login_attempt.country:
            return True  # Unknown location is anomalous
        
        typical_countries = {loc.get('country') for loc in self.user_typical_locations}
        return login_attempt.country not in typical_countries


class VelocityAttackSpecification(ParameterizedSpecification[list[LoginAttempt]]):
    """Specification for velocity-based attacks."""
    
    def __init__(self, time_window_minutes: int = 10, threshold: int = 5):
        super().__init__(
            time_window_minutes=time_window_minutes,
            threshold=threshold
        )
    
    def _validate_parameters(self) -> None:
        """Validate velocity attack parameters."""
        time_window = self.parameters.get('time_window_minutes', 10)
        threshold = self.parameters.get('threshold', 5)
        
        if not isinstance(time_window, int) or time_window <= 0:
            raise ValueError("Time window must be a positive integer")
        if not isinstance(threshold, int) or threshold <= 0:
            raise ValueError("Threshold must be a positive integer")
        if time_window > 1440:  # 24 hours
            raise ValueError("Time window cannot exceed 1440 minutes")
        if threshold > 1000:
            raise ValueError("Threshold cannot exceed 1000 attempts")
    
    def is_satisfied_by(self, login_attempts: list[LoginAttempt]) -> bool:
        """Check if login attempts show velocity attack pattern."""
        self.validate_candidate(login_attempts)
        
        threshold = self.parameters['threshold']
        time_window = timedelta(minutes=self.parameters['time_window_minutes'])
        
        if len(login_attempts) < threshold:
            return False
        
        # Sort by timestamp for efficient sliding window
        sorted_attempts = sorted(login_attempts, key=lambda x: x.timestamp)
        
        # Use sliding window approach for better performance
        return self._check_sliding_window(sorted_attempts, time_window, threshold)
    
    def _check_sliding_window(self, sorted_attempts: list[LoginAttempt], 
                             time_window: timedelta, threshold: int) -> bool:
        """Check sliding window for velocity attacks."""
        left = 0
        
        for right in range(len(sorted_attempts)):
            # Shrink window from left while it's too large
            while (sorted_attempts[right].timestamp - 
                   sorted_attempts[left].timestamp > time_window):
                left += 1
            
            # Check if current window has enough attempts
            if right - left + 1 >= threshold:
                return True
        
        return False


class CredentialStuffingSpecification(Specification[list[LoginAttempt]]):
    """Specification for credential stuffing attacks."""
    
    def __init__(self, unique_email_threshold: int = 10):
        self.unique_email_threshold = unique_email_threshold
    
    def is_satisfied_by(self, login_attempts: list[LoginAttempt]) -> bool:
        """Check if login attempts show credential stuffing pattern."""
        if len(login_attempts) < self.unique_email_threshold:
            return False
        
        # Group by IP address
        ip_groups = {}
        for attempt in login_attempts:
            ip = attempt.ip_address.value
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(attempt)
        
        # Check for IPs trying many different emails
        for ip, attempts in ip_groups.items():
            unique_emails = {attempt.email for attempt in attempts}
            if len(unique_emails) >= self.unique_email_threshold:
                return True
        
        return False


class BruteForceSpecification(Specification[list[LoginAttempt]]):
    """Specification for brute force attacks."""
    
    def __init__(self, failure_threshold: int = 5, time_window_minutes: int = 15):
        self.failure_threshold = failure_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
    
    def is_satisfied_by(self, login_attempts: list[LoginAttempt]) -> bool:
        """Check if login attempts show brute force pattern."""
        # Group by email
        email_groups = {}
        for attempt in login_attempts:
            email = attempt.email
            if email not in email_groups:
                email_groups[email] = []
            email_groups[email].append(attempt)
        
        # Check for emails with many failures in time window
        for email, attempts in email_groups.items():
            failed_attempts = [a for a in attempts if not a.success]
            
            if len(failed_attempts) < self.failure_threshold:
                continue
            
            # Sort by timestamp
            sorted_failures = sorted(failed_attempts, key=lambda x: x.timestamp)
            
            # Check if threshold failures within time window
            for i in range(len(sorted_failures) - self.failure_threshold + 1):
                window_start = sorted_failures[i].timestamp
                window_end = sorted_failures[i + self.failure_threshold - 1].timestamp
                
                if window_end - window_start <= self.time_window:
                    return True
        
        return False


class DistributedAttackSpecification(Specification[list[LoginAttempt]]):
    """Specification for distributed attacks."""
    
    def __init__(self, ip_threshold: int = 10, attempt_threshold: int = 50):
        self.ip_threshold = ip_threshold
        self.attempt_threshold = attempt_threshold
    
    def is_satisfied_by(self, login_attempts: list[LoginAttempt]) -> bool:
        """Check if login attempts show distributed attack pattern."""
        if len(login_attempts) < self.attempt_threshold:
            return False
        
        unique_ips = {attempt.ip_address.value for attempt in login_attempts}
        return len(unique_ips) >= self.ip_threshold


class GeographicAnomalySpecification(Specification[LoginAttempt]):
    """Specification for geographic anomalies."""
    
    def __init__(self, previous_location: dict[str, Any] | None, time_threshold_hours: int = 2):
        self.previous_location = previous_location
        self.time_threshold = timedelta(hours=time_threshold_hours)
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt shows geographic anomaly."""
        if not self.previous_location or not login_attempt.geolocation:
            return False
        
        # Calculate distance (simplified - would use proper geo calculation)
        # This is a placeholder for actual geolocation distance calculation
        return False  # Would implement proper distance calculation


class SuspiciousIpSpecification(Specification[IpAddress]):
    """Specification for suspicious IP addresses."""
    
    def is_satisfied_by(self, ip_address: IpAddress) -> bool:
        """Check if IP address is suspicious."""
        # Check for TOR, VPN, datacenter IPs
        return (
            ip_address.is_tor or
            ip_address.is_vpn or
            ip_address.is_datacenter
        )


class OffHoursActivitySpecification(Specification[LoginAttempt]):
    """Specification for off-hours activity."""
    
    def __init__(self, business_hours_start: int = 8, business_hours_end: int = 18):
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
    
    def is_satisfied_by(self, login_attempt: LoginAttempt) -> bool:
        """Check if login attempt is during off-hours."""
        hour = login_attempt.timestamp.hour
        return hour < self.business_hours_start or hour >= self.business_hours_end


class AccountTakeoverSpecification(Specification[dict[str, Any]]):
    """Specification for account takeover detection."""
    
    def is_satisfied_by(self, context: dict[str, Any]) -> bool:
        """Check if context indicates potential account takeover."""
        # Multiple indicators of compromise
        indicators = 0
        
        # Sudden change in login patterns
        if context.get('login_pattern_change', False):
            indicators += 1
        
        # Login from new device
        if context.get('new_device', False):
            indicators += 1
        
        # Login from new location
        if context.get('new_location', False):
            indicators += 1
        
        # Password recently changed
        if context.get('recent_password_change', False):
            indicators += 1
        
        # Unusual activity patterns
        if context.get('unusual_activity', False):
            indicators += 1
        
        # Multiple indicators suggest possible takeover
        return indicators >= 3
