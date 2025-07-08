"""
User Domain Specifications

Business rule specifications for user-related operations.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.infrastructure.specification import Specification

from ..aggregates.user import User
from ..enums import UserRole, UserStatus
from .base import (
    BaseSpecification,
    CachedSpecification,
    ParameterizedSpecification,
    TimeBasedSpecification,
)


class ActiveUserSpecification(CachedSpecification[User]):
    """Specification for active users."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user is active."""
        self.validate_candidate(user)
        
        if self._cache_enabled:
            cache_key = self._get_cache_key(user)
            return self._cached_evaluation(cache_key, user)
        
        return self._evaluate_active(user)
    
    def _cached_evaluation(self, cache_key: str, user: User) -> bool:
        """Cached evaluation of user active status."""
        return self._evaluate_active(user)
    
    def _evaluate_active(self, user: User) -> bool:
        """Evaluate if user is active."""
        return (
            user.status == UserStatus.ACTIVE and
            not user.is_locked() and
            not user.is_suspended()
        )


class VerifiedEmailSpecification(Specification[User]):
    """Specification for users with verified email."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has verified email."""
        return user.email_verified


class MFAEnabledSpecification(Specification[User]):
    """Specification for users with MFA enabled."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has MFA enabled."""
        return user.mfa_enabled


class CanLoginSpecification(Specification[User]):
    """Specification for users who can login."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user can login."""
        active_spec = ActiveUserSpecification()
        verified_spec = VerifiedEmailSpecification()
        
        return (
            active_spec.is_satisfied_by(user) and
            verified_spec.is_satisfied_by(user)
        )


class AccountLockedSpecification(Specification[User]):
    """Specification for locked user accounts."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user account is locked."""
        return user.is_locked()


class SuspendedUserSpecification(Specification[User]):
    """Specification for suspended users."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user is suspended."""
        return user.is_suspended()


class UserByRoleSpecification(Specification[User]):
    """Specification for users with specific role."""
    
    def __init__(self, role: UserRole):
        self.role = role
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has specific role."""
        # Check if user has the role in their roles list
        return any(r.name == self.role.value for r in user._roles)


class UsersByDepartmentSpecification(Specification[User]):
    """Specification for users in a specific department."""
    
    def __init__(self, department_id: UUID):
        self.department_id = department_id
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user belongs to department."""
        return (
            user._profile and 
            hasattr(user._profile, 'department_id') and
            user._profile.department_id == self.department_id
        )


class RecentlyActiveUsersSpecification(TimeBasedSpecification[User], ParameterizedSpecification[User]):
    """Specification for recently active users."""
    
    def __init__(self, days: int = 30):
        TimeBasedSpecification.__init__(self)
        ParameterizedSpecification.__init__(self, days=days)
    
    def _validate_parameters(self) -> None:
        """Validate specification parameters."""
        days = self.parameters.get('days', 30)
        if not isinstance(days, int) or days <= 0:
            raise ValueError("Days must be a positive integer")
        if days > 365:
            raise ValueError("Days cannot exceed 365")
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user was recently active."""
        self.validate_candidate(user)
        
        days = self.parameters['days']
        cutoff_date = self.get_current_time() - timedelta(days=days)
        
        return (
            user.last_login is not None and
            user.last_login > cutoff_date
        )


class AdminUserSpecification(Specification[User]):
    """Specification for admin users."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user is admin."""
        admin_roles = ['admin', 'super_admin', 'system_admin']
        return any(r.name.lower() in admin_roles for r in user._roles)


class RequiresMFASpecification(BaseSpecification[User]):
    """Specification for users who require MFA."""
    
    def __init__(self, sensitive_permissions: set[str] | None = None):
        super().__init__()
        self.sensitive_permissions = sensitive_permissions or {
            'delete_user', 'grant_permission', 'system_admin',
            'modify_roles', 'access_audit_logs', 'system_config'
        }
        self._admin_spec = AdminUserSpecification()
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user requires MFA."""
        self.validate_candidate(user)
        
        # Admins always require MFA
        if self._admin_spec.is_satisfied_by(user):
            return True
        
        # Users with high-risk profiles require MFA
        if self._has_high_risk_profile(user):
            return True
        
        # Users with elevated permissions require MFA
        return self._has_sensitive_permissions(user)
    
    def _has_high_risk_profile(self, user: User) -> bool:
        """Check if user has high-risk profile."""
        return (
            user._profile and 
            hasattr(user._profile, 'risk_level') and
            user._profile.risk_level in ['high', 'critical']
        )
    
    def _has_sensitive_permissions(self, user: User) -> bool:
        """Check if user has sensitive permissions."""
        user_permissions = {p.name for p in user.get_all_permissions()}
        return bool(user_permissions.intersection(self.sensitive_permissions))


class CompliantUserSpecification(Specification[User]):
    """Specification for compliance-compliant users."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user is compliant with policies."""
        # Must have verified email
        verified_spec = VerifiedEmailSpecification()
        if not verified_spec.is_satisfied_by(user):
            return False
        
        # Admins must have MFA
        admin_spec = AdminUserSpecification()
        mfa_spec = MFAEnabledSpecification()
        if admin_spec.is_satisfied_by(user):
            if not mfa_spec.is_satisfied_by(user):
                return False
        
        # Must have emergency contact
        return len(user._emergency_contacts) != 0


class PasswordExpiredSpecification(Specification[User]):
    """Specification for users with expired passwords."""
    
    def __init__(self, max_age_days: int = 90):
        self.max_age = timedelta(days=max_age_days)
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user's password has expired."""
        if not user.password_changed_at:
            return True  # No password change date means expired
        
        age = datetime.now(UTC) - user.password_changed_at
        return age > self.max_age


class MultipleFailedLoginsSpecification(Specification[User]):
    """Specification for users with multiple failed login attempts."""
    
    def __init__(self, threshold: int = 3):
        self.threshold = threshold
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has multiple failed login attempts."""
        return user.failed_login_count >= self.threshold


class InactiveUserSpecification(Specification[User]):
    """Specification for inactive users."""
    
    def __init__(self, days: int = 90):
        self.cutoff_date = datetime.now(UTC) - timedelta(days=days)
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has been inactive."""
        if not user.last_login:
            # User never logged in - check account age
            return user.created_at < self.cutoff_date
        
        return user.last_login < self.cutoff_date


class HighPrivilegeUserSpecification(Specification[User]):
    """Specification for users with high privileges."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has high privileges."""
        admin_spec = AdminUserSpecification()
        if admin_spec.is_satisfied_by(user):
            return True
        
        # Check for sensitive permissions
        sensitive_permissions = {
            'delete_user', 'grant_permission', 'system_admin',
            'modify_roles', 'access_audit_logs', 'system_config'
        }
        
        user_permissions = {p.name for p in user.get_all_permissions()}
        return bool(user_permissions.intersection(sensitive_permissions))


class PendingVerificationSpecification(Specification[User]):
    """Specification for users pending verification."""
    
    def is_satisfied_by(self, user: User) -> bool:
        """Check if user has pending verifications."""
        return (
            not user.email_verified or
            (user.phone_number and not user.phone_verified) or
            user.status == UserStatus.PENDING
        )
