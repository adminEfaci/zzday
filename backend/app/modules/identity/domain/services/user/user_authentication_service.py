"""
User Authentication Service

Domain service for complex authentication logic and security assessments.
"""

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ..enums import AccountType, RiskLevel

if TYPE_CHECKING:
    from ..user import User


class UserAuthenticationService:
    """Domain service for authentication flows and security assessments."""
    
    def assess_login_risk(self, user: 'User', login_context: dict) -> RiskLevel:
        """Assess risk level for login attempt."""
        risk_factors = {}
        
        # Failed login history
        if user.failed_login_count > 0:
            risk_factors['failed_logins'] = min(user.failed_login_count / 5, 1.0)
        
        # Account age factor
        account_age_days = user.get_account_age_days()
        if account_age_days < 7:
            risk_factors['new_account'] = 0.6
        elif account_age_days < 30:
            risk_factors['young_account'] = 0.3
        
        # Login frequency
        if user.login_count == 0:
            risk_factors['first_login'] = 0.8
        
        # Time-based factors
        if user.last_login:
            days_since_login = (datetime.now(UTC) - user.last_login).days
            if days_since_login > 90:
                risk_factors['dormant_account'] = 0.7
            elif days_since_login > 30:
                risk_factors['inactive'] = 0.4
        
        # Context factors
        if login_context.get('new_device'):
            risk_factors['new_device'] = 0.5
        
        if login_context.get('unusual_location'):
            risk_factors['location'] = 0.6
        
        if login_context.get('suspicious_ip'):
            risk_factors['ip_reputation'] = 0.8
        
        # Calculate overall risk
        if not risk_factors:
            return RiskLevel.LOW
        
        avg_risk = sum(risk_factors.values()) / len(risk_factors)
        
        if avg_risk >= 0.7:
            return RiskLevel.CRITICAL
        if avg_risk >= 0.5:
            return RiskLevel.HIGH
        if avg_risk >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def should_require_mfa(self, user: 'User', login_context: dict) -> bool:
        """Determine if MFA should be required for login."""
        # Always require MFA if enabled
        if user.mfa_enabled:
            return True
        
        # Risk-based MFA requirements
        risk_level = self.assess_login_risk(user, login_context)
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # Account type based requirements
        if user.account_type == AccountType.ADMIN:
            return True
        
        # Context-based requirements
        if login_context.get('admin_panel_access'):
            return True
        
        if login_context.get('sensitive_operation'):
            return True
        
        return False
    
    def validate_password_strength(self, password: str, user: 'User') -> tuple[bool, list[str]]:
        """Validate password strength against policy."""
        errors = []
        
        # Length requirements
        if len(password) < 8:
            errors.append("Password must be at least 8 characters")
        
        if len(password) > 128:
            errors.append("Password must not exceed 128 characters")
        
        # Character requirements
        if not any(c.isupper() for c in password):
            errors.append("Password must contain uppercase letters")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain lowercase letters")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain numbers")
        
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            errors.append("Password must contain special characters")
        
        # User-specific validations
        if user.username.value.lower() in password.lower():
            errors.append("Password cannot contain username")
        
        if user.email.value.split('@')[0].lower() in password.lower():
            errors.append("Password cannot contain email address")
        
        # Common passwords check (simplified)
        common_passwords = {
            "password", "123456", "qwerty", "admin", "letmein"
        }
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return len(errors) == 0, errors
    
    def should_lock_account(self, user: 'User') -> tuple[bool, timedelta]:
        """Determine if account should be locked based on failed attempts."""
        # Progressive lockout duration
        if user.failed_login_count >= 10:
            return True, timedelta(hours=24)
        if user.failed_login_count >= 7:
            return True, timedelta(hours=4)
        if user.failed_login_count >= 5:
            return True, timedelta(hours=1)
        if user.failed_login_count >= 3:
            return True, timedelta(minutes=15)
        
        return False, timedelta(0)
    
    def calculate_password_expiry(self, user: 'User') -> datetime | None:
        """Calculate when password should expire."""
        if not user.password_changed_at:
            return None
        
        # Account type based expiry
        if user.account_type == AccountType.ADMIN:
            expiry_days = 60  # Stricter for admins
        elif user.account_type == AccountType.SERVICE:
            expiry_days = 365  # Service accounts change less frequently
        else:
            expiry_days = 90  # Regular users
        
        return user.password_changed_at + timedelta(days=expiry_days)
    
    def is_password_expired(self, user: 'User') -> bool:
        """Check if user's password has expired."""
        expiry_date = self.calculate_password_expiry(user)
        if not expiry_date:
            return False
        
        return datetime.now(UTC) > expiry_date
    
    def get_session_timeout(self, user: 'User') -> timedelta:
        """Get appropriate session timeout for user."""
        if user.account_type == AccountType.ADMIN:
            return timedelta(hours=2)  # Shorter for admins
        if user.account_type == AccountType.SERVICE:
            return timedelta(hours=24)  # Longer for service accounts
        return timedelta(hours=8)  # Standard timeout
    
    def validate_account_access(self, user: 'User') -> tuple[bool, str]:
        """Validate if user can access their account."""
        if user.deleted_at:
            return False, "Account has been deleted"
        
        if user.is_locked():
            return False, "Account is locked"
        
        if user.is_suspended():
            return False, "Account is suspended"
        
        if user.status.value not in ['active', 'pending']:
            return False, f"Account status is {user.status.value}"
        
        if self.is_password_expired(user) and user.require_password_change:
            return False, "Password has expired and must be changed"
        
        return True, "Account access permitted"


# Export the service
__all__ = ['UserAuthenticationService']