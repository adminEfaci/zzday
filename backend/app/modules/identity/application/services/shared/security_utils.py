"""
Security Utilities

Static utility methods for security-related operations.
Addresses the static methods issue by extracting stateless security logic.
"""

import hashlib
import hmac
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.modules.identity.domain.enums import MFAMethod, RiskLevel, SecurityEventType
from app.modules.identity.domain.value_objects import IpAddress


class SecurityUtils:
    """Static utility methods for security operations."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Length of the token to generate
            
        Returns:
            Secure random token string
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_numeric_code(length: int = 6) -> str:
        """
        Generate a numeric code for MFA or verification.
        
        Args:
            length: Length of the numeric code
            
        Returns:
            Numeric code string
        """
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    @staticmethod
    def generate_backup_codes(count: int = 10, length: int = 8) -> list[str]:
        """
        Generate backup codes for MFA recovery.
        
        Args:
            count: Number of backup codes to generate
            length: Length of each backup code
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            code = ''.join(
                secrets.choice(string.ascii_uppercase + string.digits) 
                for _ in range(length)
            )
            # Format as XXXX-XXXX for readability
            if length == 8:
                code = f"{code[:4]}-{code[4:]}"
            codes.append(code)
        return codes
    
    @staticmethod
    def hash_token(token: str, salt: str = "") -> str:
        """
        Create a secure hash of a token for storage.
        
        Args:
            token: Token to hash
            salt: Optional salt for the hash
            
        Returns:
            Hashed token string
        """
        token_bytes = (token + salt).encode('utf-8')
        return hashlib.sha256(token_bytes).hexdigest()
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """
        Compare two strings in constant time to prevent timing attacks.
        
        Args:
            val1: First value to compare
            val2: Second value to compare
            
        Returns:
            True if values are equal
        """
        return hmac.compare_digest(val1.encode('utf-8'), val2.encode('utf-8'))
    
    @staticmethod
    def calculate_risk_score(factors: dict[str, Any]) -> float:
        """
        Calculate risk score based on various factors.
        
        Args:
            factors: Dictionary of risk factors
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        score = 0.0
        weights = {
            'new_device': 0.3,
            'new_location': 0.2,
            'unusual_time': 0.1,
            'failed_attempts': 0.2,
            'vpn_detected': 0.1,
            'tor_detected': 0.2,
            'suspicious_user_agent': 0.1,
            'impossible_travel': 0.4,
            'known_attacker_ip': 0.5,
            'account_age_days': -0.1,  # Negative weight for established accounts
        }
        
        for factor, weight in weights.items():
            if factor in factors:
                if factor == 'failed_attempts':
                    # Scale failed attempts (0-5 attempts)
                    value = min(factors[factor] / 5.0, 1.0)
                elif factor == 'account_age_days':
                    # Scale account age (0-365 days)
                    value = min(factors[factor] / 365.0, 1.0)
                else:
                    # Boolean factors
                    value = float(bool(factors[factor]))
                
                score += value * weight
        
        # Normalize to 0.0-1.0 range
        return max(0.0, min(1.0, score))
    
    @staticmethod
    def determine_risk_level(risk_score: float) -> RiskLevel:
        """
        Determine risk level from risk score.
        
        Args:
            risk_score: Risk score between 0.0 and 1.0
            
        Returns:
            Risk level enum
        """
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    @staticmethod
    def is_suspicious_user_agent(user_agent: str) -> bool:
        """
        Check if user agent appears suspicious.
        
        Args:
            user_agent: User agent string to check
            
        Returns:
            True if user agent is suspicious
        """
        if not user_agent:
            return True
        
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python', 'java', 'ruby', 'perl', 'php', 'scanner',
            'nmap', 'nikto', 'sqlmap', 'havij', 'acunetix'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)
    
    @staticmethod
    def detect_impossible_travel(
        previous_location: dict[str, Any],
        current_location: dict[str, Any],
        time_difference_minutes: int
    ) -> bool:
        """
        Detect impossible travel based on location and time.
        
        Args:
            previous_location: Previous location with lat/lon
            current_location: Current location with lat/lon
            time_difference_minutes: Time between locations in minutes
            
        Returns:
            True if travel appears impossible
        """
        if not previous_location or not current_location:
            return False
        
        # Calculate distance using Haversine formula (simplified)
        lat1 = previous_location.get('latitude', 0)
        lon1 = previous_location.get('longitude', 0)
        lat2 = current_location.get('latitude', 0)
        lon2 = current_location.get('longitude', 0)
        
        # Rough distance calculation (km)
        distance_km = ((lat2 - lat1) ** 2 + (lon2 - lon1) ** 2) ** 0.5 * 111
        
        # Maximum reasonable travel speed (1000 km/h for flights)
        max_speed_kmh = 1000
        max_distance_possible = (time_difference_minutes / 60) * max_speed_kmh
        
        return distance_km > max_distance_possible
    
    @staticmethod
    def is_known_vpn_ip(ip_address: str) -> bool:
        """
        Check if IP address belongs to known VPN providers.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is from known VPN provider
        """
        # In production, this would check against a VPN detection service
        # For now, return False as placeholder
        return False
    
    @staticmethod
    def is_known_tor_exit_node(ip_address: str) -> bool:
        """
        Check if IP address is a known Tor exit node.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is a Tor exit node
        """
        # In production, this would check against Tor exit node list
        # For now, return False as placeholder
        return False
    
    @staticmethod
    def generate_session_fingerprint(
        user_agent: str,
        ip_address: str,
        accept_language: str = "",
        accept_encoding: str = ""
    ) -> str:
        """
        Generate a session fingerprint for tracking.
        
        Args:
            user_agent: User agent string
            ip_address: IP address
            accept_language: Accept-Language header
            accept_encoding: Accept-Encoding header
            
        Returns:
            Session fingerprint hash
        """
        fingerprint_data = f"{user_agent}|{ip_address}|{accept_language}|{accept_encoding}"
        return hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def calculate_password_entropy(password: str) -> float:
        """
        Calculate password entropy in bits.
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy in bits
        """
        if not password:
            return 0.0
        
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += len(string.punctuation)
        
        if charset_size == 0:
            return 0.0
        
        import math
        return len(password) * math.log2(charset_size)
    
    @staticmethod
    def is_password_compromised(password_hash: str) -> bool:
        """
        Check if password hash appears in breach databases.
        
        Args:
            password_hash: SHA-1 hash of password (first 5 chars used for k-anonymity)
            
        Returns:
            True if password appears compromised
        """
        # In production, this would check against HaveIBeenPwned API
        # For now, return False as placeholder
        return False
    
    @staticmethod
    def get_preferred_mfa_method(mfa_devices: list[Any]) -> MFAMethod:
        """
        Determine preferred MFA method from available devices.
        
        Args:
            mfa_devices: List of MFA devices
            
        Returns:
            Preferred MFA method
        """
        if not mfa_devices:
            return MFAMethod.TOTP
        
        # Priority order: TOTP > SMS > EMAIL
        priority = {
            MFAMethod.TOTP: 3,
            MFAMethod.SMS: 2,
            MFAMethod.EMAIL: 1
        }
        
        # Find device with highest priority
        preferred_device = max(
            mfa_devices,
            key=lambda d: priority.get(d.method, 0)
        )
        
        return preferred_device.method
    
    @staticmethod
    def mask_ip_address(ip: str, level: str = "partial") -> str:
        """
        Mask IP address for privacy.
        
        Args:
            ip: IP address to mask
            level: Masking level ('partial' or 'full')
            
        Returns:
            Masked IP address
        """
        if not ip:
            return "***.***.***"
        
        parts = ip.split('.')
        if len(parts) != 4:
            return "***.***.***"
        
        if level == "full":
            return "***.***.***.***"
        else:  # partial
            return f"{parts[0]}.{parts[1]}.***.***"
    
    @staticmethod
    def generate_device_fingerprint(
        user_agent: str,
        screen_resolution: str = "",
        timezone: str = "",
        language: str = "",
        platform: str = ""
    ) -> str:
        """
        Generate device fingerprint for tracking.
        
        Args:
            user_agent: User agent string
            screen_resolution: Screen resolution (e.g., "1920x1080")
            timezone: Timezone string
            language: Browser language
            platform: Platform/OS
            
        Returns:
            Device fingerprint hash
        """
        fingerprint_data = f"{user_agent}|{screen_resolution}|{timezone}|{language}|{platform}"
        return hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def calculate_session_timeout(
        base_timeout_minutes: int,
        is_remembered: bool,
        is_admin: bool,
        risk_level: RiskLevel
    ) -> int:
        """
        Calculate dynamic session timeout based on factors.
        
        Args:
            base_timeout_minutes: Base timeout in minutes
            is_remembered: Whether "remember me" is enabled
            is_admin: Whether user is admin
            risk_level: Current risk level
            
        Returns:
            Timeout in minutes
        """
        timeout = base_timeout_minutes
        
        # Adjust for remember me
        if is_remembered:
            timeout *= 24  # Extend to days
        
        # Reduce for admin users
        if is_admin:
            timeout = min(timeout, 120)  # Max 2 hours for admins
        
        # Adjust for risk level
        risk_multipliers = {
            RiskLevel.CRITICAL: 0.1,  # 10% of normal
            RiskLevel.HIGH: 0.25,     # 25% of normal
            RiskLevel.MEDIUM: 0.5,    # 50% of normal
            RiskLevel.LOW: 0.75,      # 75% of normal
            RiskLevel.MINIMAL: 1.0    # Normal timeout
        }
        
        timeout *= risk_multipliers.get(risk_level, 1.0)
        
        return max(5, int(timeout))  # Minimum 5 minutes
    
    @staticmethod
    def should_require_reauthentication(
        last_auth_time: datetime,
        sensitive_action: bool = False,
        risk_change: bool = False
    ) -> bool:
        """
        Determine if reauthentication is required.
        
        Args:
            last_auth_time: Last authentication timestamp
            sensitive_action: Whether action is sensitive
            risk_change: Whether risk level has changed
            
        Returns:
            True if reauthentication required
        """
        if sensitive_action:
            # Require reauth for sensitive actions after 15 minutes
            return (datetime.now(UTC) - last_auth_time) > timedelta(minutes=15)
        
        if risk_change:
            # Require reauth if risk level increased
            return True
        
        # Standard reauth after 24 hours
        return (datetime.now(UTC) - last_auth_time) > timedelta(hours=24)
    
    @staticmethod
    def classify_security_event(
        event_type: str,
        severity_score: float
    ) -> SecurityEventType:
        """
        Classify security event based on type and severity.
        
        Args:
            event_type: Type of event
            severity_score: Severity score (0.0-1.0)
            
        Returns:
            Security event type classification
        """
        critical_events = {
            'account_takeover', 'data_breach', 'privilege_escalation',
            'sql_injection', 'xss_attack', 'authentication_bypass'
        }
        
        high_events = {
            'brute_force', 'suspicious_login', 'permission_violation',
            'session_hijack', 'api_abuse'
        }
        
        if event_type in critical_events or severity_score >= 0.8:
            return SecurityEventType.CRITICAL_INCIDENT
        elif event_type in high_events or severity_score >= 0.6:
            return SecurityEventType.SECURITY_VIOLATION
        elif severity_score >= 0.4:
            return SecurityEventType.SUSPICIOUS_ACTIVITY
        else:
            return SecurityEventType.AUTHENTICATION_FAILURE