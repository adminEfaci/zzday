"""
Security Domain Service

System-wide security operations and policy enforcement.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from ...enums import SecurityEventType, RiskLevel, AccountType
from ...value_objects import IpAddress


class SecurityService:
    """Domain service for system-wide security operations."""
    
    @staticmethod
    def assess_system_risk(events: list[dict[str, Any]]) -> RiskLevel:
        """Assess overall system risk based on recent events."""
        if not events:
            return RiskLevel.LOW
        
        risk_score = 0.0
        total_events = len(events)
        
        # Analyze event types and frequencies
        event_weights = {
            SecurityEventType.BRUTE_FORCE_ATTACK: 0.8,
            SecurityEventType.CREDENTIAL_STUFFING: 0.7,
            SecurityEventType.ACCOUNT_TAKEOVER: 0.9,
            SecurityEventType.SUSPICIOUS_LOGIN: 0.5,
            SecurityEventType.MULTIPLE_FAILED_LOGINS: 0.4,
            SecurityEventType.UNUSUAL_ACTIVITY: 0.3,
        }
        
        # Count events by type
        event_counts = {}
        for event in events:
            event_type = event.get('type')
            if event_type:
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        # Calculate weighted risk
        for event_type, count in event_counts.items():
            weight = event_weights.get(event_type, 0.2)
            frequency_multiplier = min(count / total_events, 1.0)
            risk_score += weight * frequency_multiplier
        
        # Assess based on score
        if risk_score >= 0.7:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    @staticmethod
    def should_block_ip(ip_address: str, events: list[dict[str, Any]]) -> bool:
        """Determine if an IP address should be blocked."""
        ip_events = [e for e in events if e.get('ip_address') == ip_address]
        
        if not ip_events:
            return False
        
        # Count events in different time windows
        now = datetime.now(UTC)
        events_1h = []
        events_24h = []
        
        for event in ip_events:
            event_time = event.get('timestamp')
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)
            
            if event_time and (now - event_time) <= timedelta(hours=1):
                events_1h.append(event)
            if event_time and (now - event_time) <= timedelta(hours=24):
                events_24h.append(event)
        
        # Block criteria
        if len(events_1h) >= 50:  # Too many events in 1 hour
            return True
        
        if len(events_24h) >= 200:  # Too many events in 24 hours
            return True
        
        # Check for attack patterns
        attack_types = {
            SecurityEventType.BRUTE_FORCE_ATTACK,
            SecurityEventType.CREDENTIAL_STUFFING,
            SecurityEventType.ACCOUNT_TAKEOVER
        }
        
        attack_events = [e for e in events_1h if e.get('type') in attack_types]
        if len(attack_events) >= 10:  # Multiple attack events
            return True
        
        return False
    
    @staticmethod
    def calculate_ip_reputation(ip_address: str, historical_data: dict[str, Any]) -> float:
        """Calculate reputation score for an IP address (0.0 = bad, 1.0 = good)."""
        try:
            ip_obj = IpAddress(ip_address)
        except ValueError:
            return 0.0  # Invalid IP
        
        reputation = 0.5  # Neutral starting point
        
        # Penalize known bad indicators
        if ip_obj.is_tor:
            reputation -= 0.4
        elif ip_obj.is_vpn:
            reputation -= 0.2
        elif ip_obj.is_datacenter:
            reputation -= 0.1
        
        # Check historical behavior
        if historical_data:
            successful_logins = historical_data.get('successful_logins', 0)
            failed_logins = historical_data.get('failed_logins', 0)
            attack_events = historical_data.get('attack_events', 0)
            
            total_events = successful_logins + failed_logins + attack_events
            
            if total_events > 0:
                success_rate = successful_logins / total_events
                attack_rate = attack_events / total_events
                
                # Adjust based on behavior
                reputation += (success_rate - 0.5) * 0.3  # Reward good behavior
                reputation -= attack_rate * 0.5  # Penalize attacks
        
        # Geographic reputation
        trusted_countries = {'US', 'CA', 'GB', 'AU', 'NZ', 'DE', 'FR', 'JP', 'KR', 'SG'}
        if ip_obj.country in trusted_countries:
            reputation += 0.1
        
        return max(0.0, min(1.0, reputation))
    
    @staticmethod
    def enforce_password_policy(password: str, account_type: AccountType) -> tuple[bool, list[str]]:
        """Enforce password policy based on account type."""
        errors = []
        
        # Base requirements
        min_length = 8
        if account_type == AccountType.ADMIN:
            min_length = 12  # Stricter for admins
        elif account_type == AccountType.SERVICE:
            min_length = 16  # Even stricter for service accounts
        
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters")
        
        if len(password) > 128:
            errors.append("Password must not exceed 128 characters")
        
        # Character requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not has_upper:
            errors.append("Password must contain uppercase letters")
        if not has_lower:
            errors.append("Password must contain lowercase letters")
        if not has_digit:
            errors.append("Password must contain numbers")
        if not has_special:
            errors.append("Password must contain special characters")
        
        # Additional requirements for admin/service accounts
        if account_type in [AccountType.ADMIN, AccountType.SERVICE]:
            # Require at least 2 of each character type
            if sum([has_upper, has_lower, has_digit, has_special]) < 4:
                errors.append("Password must contain all character types")
            
            # Check for common patterns
            if any(pattern in password.lower() for pattern in ['password', 'admin', 'service']):
                errors.append("Password cannot contain common words")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def calculate_session_timeout(account_type: AccountType, risk_level: RiskLevel) -> timedelta:
        """Calculate appropriate session timeout based on account type and risk."""
        base_timeouts = {
            AccountType.ADMIN: timedelta(hours=2),
            AccountType.SERVICE: timedelta(hours=24),
            AccountType.REGULAR: timedelta(hours=8),
            AccountType.GUEST: timedelta(hours=1),
        }
        
        base_timeout = base_timeouts.get(account_type, timedelta(hours=4))
        
        # Adjust based on risk level
        risk_multipliers = {
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 0.7,
            RiskLevel.HIGH: 0.5,
            RiskLevel.CRITICAL: 0.25,
        }
        
        multiplier = risk_multipliers.get(risk_level, 0.5)
        return timedelta(seconds=int(base_timeout.total_seconds() * multiplier))
    
    @staticmethod
    def should_require_step_up_auth(
        account_type: AccountType,
        operation: str,
        risk_level: RiskLevel
    ) -> bool:
        """Determine if step-up authentication is required for an operation."""
        # High-privilege operations always require step-up
        sensitive_operations = {
            'user_management',
            'role_assignment',
            'permission_grant',
            'system_configuration',
            'security_settings',
            'audit_log_access'
        }
        
        if operation in sensitive_operations:
            return True
        
        # Admin operations with elevated risk
        if account_type == AccountType.ADMIN and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # Critical risk always requires step-up
        if risk_level == RiskLevel.CRITICAL:
            return True
        
        return False
    
    @staticmethod
    def generate_security_recommendations(
        system_events: list[dict[str, Any]],
        user_behavior: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate security recommendations based on system state."""
        recommendations = []
        
        # Analyze attack patterns
        attack_events = [
            e for e in system_events 
            if e.get('type') in [
                SecurityEventType.BRUTE_FORCE_ATTACK,
                SecurityEventType.CREDENTIAL_STUFFING,
                SecurityEventType.ACCOUNT_TAKEOVER
            ]
        ]
        
        if len(attack_events) > 10:
            recommendations.append({
                'type': 'security_alert',
                'priority': 'high',
                'title': 'Multiple Attack Attempts Detected',
                'description': f'Detected {len(attack_events)} attack events recently',
                'action': 'Review and consider implementing additional security measures'
            })
        
        # Check for weak authentication patterns
        weak_auth_count = user_behavior.get('users_without_mfa', 0)
        if weak_auth_count > 0:
            recommendations.append({
                'type': 'authentication',
                'priority': 'medium',
                'title': 'Users Without MFA',
                'description': f'{weak_auth_count} users do not have MFA enabled',
                'action': 'Encourage or enforce MFA adoption'
            })
        
        # Check for old passwords
        old_passwords = user_behavior.get('users_with_old_passwords', 0)
        if old_passwords > 0:
            recommendations.append({
                'type': 'password_policy',
                'priority': 'medium',
                'title': 'Outdated Passwords',
                'description': f'{old_passwords} users have passwords older than 90 days',
                'action': 'Enforce password rotation policy'
            })
        
        return recommendations
