"""
User Aggregate Root

The main aggregate for the identity domain, managing user lifecycle and consistency.
Complex authentication and permission logic delegated to domain services.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TYPE_CHECKING
from uuid import UUID, uuid4

from app.core.domain.base import AggregateRoot

if TYPE_CHECKING:
    from ..interfaces.services.user_authentication_service import IUserAuthenticationService

# Import events from existing location
from ..entities.user.user_events import (
    UserActivated,
    UserDeactivated,
    UserDeleted,
    UserEmailChanged,
    UserLocked,
    UserPasswordChanged,
    UserPermissionGranted,
    UserPermissionRevoked,
    UserRegistered,
    UserReinstated,
    UserRoleAssigned,
    UserRoleRevoked,
    UserSuspended,
    UserUnlocked,
)

# Import enums from consolidated location
from ..enums import AccountType, UserStatus

# Import value objects
from ..value_objects import Email, PhoneNumber, Username


@dataclass
class User(AggregateRoot):
    """
    User aggregate root - the central entity in the identity domain.
    
    This aggregate maintains user identity, authentication, and core security concerns.
    It enforces domain invariants and encapsulates business rules for user management.
    
    Aggregate Boundaries:
    - User identity and authentication
    - Account status and lifecycle
    - Core security settings
    - Role and permission assignments (IDs only - logic in services)
    
    External Concerns (handled by domain services):
    - Complex authentication flows -> UserAuthenticationService
    - Password policy validation -> UserAuthenticationService
    - Permission calculations -> UserPermissionService
    - Risk assessments -> UserAuthenticationService
    """

    # Core identity - immutable after creation
    id: UUID
    username: Username
    created_at: datetime
    
    # Mutable core properties
    email: Email
    password_hash: str
    status: UserStatus
    account_type: AccountType
    updated_at: datetime

    # Contact verification
    email_verified: bool = False
    phone_number: PhoneNumber | None = None
    phone_verified: bool = False

    # Authentication tracking
    last_login: datetime | None = None
    login_count: int = 0
    failed_login_count: int = 0
    last_failed_login: datetime | None = None

    # Account security
    security_stamp: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    mfa_enabled: bool = False
    password_changed_at: datetime | None = None
    require_password_change: bool = False

    # Account lifecycle
    locked_until: datetime | None = None
    suspended_until: datetime | None = None
    deleted_at: datetime | None = None

    # Role and permission management (simplified - IDs only)
    _role_ids: set[UUID] = field(default_factory=set, init=False)
    _permission_ids: set[UUID] = field(default_factory=set, init=False)
    
    # Domain service dependencies (injected after construction)
    _authentication_service: IUserAuthenticationService | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        """Initialize user aggregate and enforce domain invariants."""
        super().__post_init__()
        self._validate_invariants()
        
        # Set password change timestamp if not provided
        if not self.password_changed_at:
            self.password_changed_at = self.created_at

    def set_authentication_service(self, service: IUserAuthenticationService) -> None:
        """Set the authentication service dependency.
        
        Args:
            service: The authentication service to use for complex authentication logic
        """
        self._authentication_service = service

    def _validate_invariants(self) -> None:
        """Validate domain invariants - NO EVENT EMISSION."""
        # Core identity validation
        if not isinstance(self.email, Email):
            raise TypeError("Email must be an Email value object")
        
        if not isinstance(self.username, Username):
            raise TypeError("Username must be a Username value object")
        
        if not isinstance(self.status, UserStatus):
            raise TypeError("Status must be a UserStatus enum")
        
        if not isinstance(self.account_type, AccountType):
            raise TypeError("Account type must be an AccountType enum")

        # Business rule validation
        if self.failed_login_count < 0:
            raise ValueError("Failed login count cannot be negative")

        if self.login_count < 0:
            raise ValueError("Login count cannot be negative")
        
        # Temporal validation
        if hasattr(self, 'updated_at') and hasattr(self, 'created_at') and self.updated_at < self.created_at:
            raise ValueError("Updated timestamp cannot be before created timestamp")
        
        # Status consistency
        if self.status == UserStatus.DELETED and not self.deleted_at:
            raise ValueError("Deleted users must have deletion timestamp")
        
        # Auto-unlock expired locks
        if self.locked_until and self.locked_until <= datetime.now(UTC):
            self.locked_until = None
            if self.status == UserStatus.LOCKED:
                self.status = UserStatus.ACTIVE

    @classmethod
    def register(
        cls,
        email: str,
        username: str,
        password_hash: str,
        account_type: AccountType = AccountType.PERSONAL,
        auto_activate: bool = False
    ) -> User:
        """
        Register a new user with proper domain validation.
        
        Note: Password should be hashed by the application service before calling this.
        """
        # Create value objects (validates format)
        email_vo = Email(email)
        username_vo = Username(username)
        
        now = datetime.now(UTC)

        # Create user with proper defaults
        user = cls(
            id=uuid4(),
            email=email_vo,
            username=username_vo,
            password_hash=password_hash,
            status=UserStatus.ACTIVE if auto_activate else UserStatus.PENDING,
            account_type=account_type,
            email_verified=auto_activate,
            created_at=now,
            updated_at=now,
            password_changed_at=now
        )

        # Record domain events
        user.add_domain_event(UserRegistered(
            user_id=user.id,
            email=email,
            username=username,
            account_type=account_type.value,
            auto_activated=auto_activate
        ))

        if auto_activate:
            user.add_domain_event(UserActivated(
                user_id=user.id,
                activated_by=user.id
            ))

        return user

    def activate(self, activated_by: UUID | None = None) -> None:
        """Activate user account."""
        if self.status == UserStatus.ACTIVE:
            return

        if self.status not in [UserStatus.PENDING, UserStatus.INACTIVE]:
            raise ValueError(f"Cannot activate user with status {self.status}")

        self.status = UserStatus.ACTIVE
        self.email_verified = True
        self._touch()

        self.add_domain_event(UserActivated(
            user_id=self.id,
            activated_by=activated_by or self.id
        ))

    def deactivate(self, deactivated_by: UUID, reason: str) -> None:
        """Deactivate user account."""
        if self.status != UserStatus.ACTIVE:
            return

        self.status = UserStatus.INACTIVE
        self._touch()

        self.add_domain_event(UserDeactivated(
            user_id=self.id,
            deactivated_by=deactivated_by,
            reason=reason
        ))

    def record_login_attempt(self, success: bool, login_context: dict | None = None) -> None:
        """Record login attempt and update tracking."""
        from ..interfaces.services.user_authentication_service import AuthenticationContext
        
        # Create authentication context
        context = AuthenticationContext(
            user_id=self.id,
            ip_address=login_context.get("ip_address") if login_context else None,
            user_agent=login_context.get("user_agent") if login_context else None,
            device_fingerprint=login_context.get("device_fingerprint") if login_context else None,
            location=login_context.get("location") if login_context else None,
            timestamp=datetime.now(UTC),
            additional_context=login_context or {}
        )
        
        # Use service for complex authentication logic if available
        if self._authentication_service:
            result = self._authentication_service.process_login_attempt(self, success, context)
            
            # Apply service recommendations
            if result.should_lock_account:
                self.lock(result.lock_duration)
            
            # Update basic tracking
            if success:
                self.failed_login_count = 0
                self.last_failed_login = None
                self.last_login = datetime.now(UTC)
                self.login_count += 1
            else:
                self.failed_login_count += 1
                self.last_failed_login = datetime.now(UTC)
        else:
            # Fallback to simple domain rule when service not available
            if success:
                self.failed_login_count = 0
                self.last_failed_login = None
                self.last_login = datetime.now(UTC)
                self.login_count += 1
            else:
                self.failed_login_count += 1
                self.last_failed_login = datetime.now(UTC)
                
                # Apply domain rule: Lock after 5 failed attempts
                if self.failed_login_count >= 5:
                    self.lock(timedelta(minutes=15))  # 15 minute lockout
        
        self._touch()

    def update_password_hash(self, new_password_hash: str, changed_by: UUID | None = None) -> None:
        """Update password hash (password should be validated by service before calling)."""
        # Use service to determine if security stamp should be regenerated
        should_regenerate = True
        if self._authentication_service:
            should_regenerate = self._authentication_service.should_regenerate_security_stamp(self, "password_change")
        
        self.password_hash = new_password_hash
        self.password_changed_at = datetime.now(UTC)
        self.require_password_change = False
        
        if should_regenerate:
            self._regenerate_security_stamp()
        
        self._touch()

        self.add_domain_event(UserPasswordChanged(
            user_id=self.id,
            changed_by=changed_by or self.id,
            sessions_invalidated=should_regenerate
        ))

    def change_email(self, new_email: str) -> None:
        """Change user email address."""
        # Use service to determine if security stamp should be regenerated
        should_regenerate = True
        if self._authentication_service:
            should_regenerate = self._authentication_service.should_regenerate_security_stamp(self, "email_change")
        
        old_email = self.email.value
        self.email = Email(new_email)
        self.email_verified = False
        
        if should_regenerate:
            self._regenerate_security_stamp()
        
        self._touch()

        self.add_domain_event(UserEmailChanged(
            user_id=self.id,
            old_email=old_email,
            new_email=new_email
        ))

    def verify_email(self) -> None:
        """Mark email as verified."""
        self.email_verified = True
        self._touch()

    def enable_mfa(self) -> None:
        """Enable MFA for user."""
        self.mfa_enabled = True
        self._regenerate_security_stamp()
        self._touch()

    def disable_mfa(self) -> None:
        """Disable MFA for user."""
        self.mfa_enabled = False
        self._regenerate_security_stamp()
        self._touch()

    def assign_role(self, role_id: UUID, assigned_by: UUID) -> None:
        """Assign role to user. Validation should be done at application layer."""
        if role_id in self._role_ids:
            return  # Already assigned

        # Simple aggregate business rule: user must be active to receive new roles
        if not self.is_active:
            raise ValueError("Cannot assign role to inactive user")

        self._role_ids.add(role_id)
        self._touch()

        self.add_domain_event(UserRoleAssigned(
            user_id=self.id,
            role_id=role_id,
            role_name="",  # Would be provided by service
            assigned_by=assigned_by
        ))

    def revoke_role(self, role_id: UUID, revoked_by: UUID) -> None:
        """Revoke role from user."""
        if role_id not in self._role_ids:
            return

        self._role_ids.remove(role_id)
        self._touch()

        self.add_domain_event(UserRoleRevoked(
            user_id=self.id,
            role_id=role_id,
            role_name="",  # Would be provided by service
            revoked_by=revoked_by
        ))

    def grant_permission(self, permission_id: UUID, granted_by: UUID) -> None:
        """Grant direct permission to user."""
        if permission_id in self._permission_ids:
            return

        self._permission_ids.add(permission_id)
        self._touch()

        self.add_domain_event(UserPermissionGranted(
            user_id=self.id,
            permission_id=permission_id,
            permission_name="",  # Would be provided by service
            granted_by=granted_by
        ))

    def revoke_permission(self, permission_id: UUID, revoked_by: UUID) -> None:
        """Revoke direct permission from user."""
        if permission_id not in self._permission_ids:
            return

        self._permission_ids.remove(permission_id)
        self._touch()

        self.add_domain_event(UserPermissionRevoked(
            user_id=self.id,
            permission_id=permission_id,
            permission_name="",  # Would be provided by service
            revoked_by=revoked_by
        ))

    def lock(self, duration: timedelta | None = None) -> None:
        """Lock user account."""
        if duration:
            self.locked_until = datetime.now(UTC) + duration
        else:
            self.locked_until = datetime.now(UTC) + timedelta(days=36500)  # ~100 years

        self.status = UserStatus.LOCKED
        self._touch()

        self.add_domain_event(UserLocked(
            user_id=self.id,
            locked_until=self.locked_until,
            lock_reason="Account security"
        ))

    def unlock(self, unlocked_by: UUID) -> None:
        """Unlock user account."""
        self.locked_until = None
        self.status = UserStatus.ACTIVE
        self.failed_login_count = 0
        self._touch()

        self.add_domain_event(UserUnlocked(
            user_id=self.id,
            unlocked_by=unlocked_by
        ))

    def suspend(self, duration: timedelta, suspended_by: UUID, reason: str) -> None:
        """Suspend user account."""
        self.suspended_until = datetime.now(UTC) + duration
        self.status = UserStatus.SUSPENDED
        self._touch()

        self.add_domain_event(UserSuspended(
            user_id=self.id,
            suspended_by=suspended_by,
            suspended_until=self.suspended_until,
            suspension_reason=reason
        ))

    def reinstate(self, reinstated_by: UUID) -> None:
        """Reinstate suspended user."""
        if self.status != UserStatus.SUSPENDED:
            return

        self.suspended_until = None
        self.status = UserStatus.ACTIVE
        self._touch()

        self.add_domain_event(UserReinstated(
            user_id=self.id,
            reinstated_by=reinstated_by
        ))

    def soft_delete(self, deleted_by: UUID) -> None:
        """Soft delete user account."""
        self.deleted_at = datetime.now(UTC)
        self.status = UserStatus.DELETED
        self._touch()

        self.add_domain_event(UserDeleted(
            user_id=self.id,
            deleted_by=deleted_by,
            deletion_type="soft"
        ))

    def restore(self, restored_by: UUID) -> None:
        """Restore soft-deleted user."""
        if not self.deleted_at:
            return

        self.deleted_at = None
        self.status = UserStatus.ACTIVE
        self._touch()

    # =============================================================================
    # COMPUTED PROPERTIES
    # =============================================================================

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.status == UserStatus.LOCKED:
            return True
        return bool(self.locked_until and self.locked_until > datetime.now(UTC))

    def is_suspended(self) -> bool:
        """Check if account is currently suspended."""
        if self.status == UserStatus.SUSPENDED:
            return True
        return bool(self.suspended_until and self.suspended_until > datetime.now(UTC))

    def is_active(self) -> bool:
        """Check if account is active and can be used."""
        return (
            self.status == UserStatus.ACTIVE and
            not self.is_locked() and
            not self.is_suspended() and
            not self.deleted_at
        )

    def get_account_age_days(self) -> int:
        """Get account age in days."""
        return (datetime.now(UTC) - self.created_at).days

    def requires_mfa(self, authentication_context: dict | None = None) -> bool:
        """Check if MFA is required for user - delegates to service."""
        if self._authentication_service and authentication_context:
            from ..interfaces.services.user_authentication_service import AuthenticationContext
            
            context = AuthenticationContext(
                user_id=self.id,
                ip_address=authentication_context.get("ip_address"),
                user_agent=authentication_context.get("user_agent"),
                device_fingerprint=authentication_context.get("device_fingerprint"),
                location=authentication_context.get("location"),
                timestamp=datetime.now(UTC),
                additional_context=authentication_context
            )
            
            return self._authentication_service.should_require_mfa(self, context)
        
        # Fallback to simple check
        return self.mfa_enabled

    # =============================================================================
    # SERVICE INTEGRATION METHODS
    # =============================================================================

    def validate_password_policy(self, password: str) -> dict[str, Any]:
        """Validate password against security policies using authentication service."""
        if self._authentication_service:
            result = self._authentication_service.validate_password_policy(password, self)
            return {
                "is_valid": result.is_valid,
                "errors": result.errors,
                "strength_score": result.strength_score,
                "meets_policy": result.meets_policy,
                "suggestions": result.suggestions
            }
        
        # Fallback validation - just check if password exists
        return {
            "is_valid": bool(password and len(password) >= 8),
            "errors": [] if password and len(password) >= 8 else ["Password must be at least 8 characters"],
            "strength_score": 0.5,
            "meets_policy": bool(password and len(password) >= 8),
            "suggestions": []
        }

    def assess_authentication_risk(self, context: dict | None = None) -> dict[str, Any]:
        """Assess authentication risk using authentication service."""
        if self._authentication_service and context:
            from ..interfaces.services.user_authentication_service import AuthenticationContext
            
            auth_context = AuthenticationContext(
                user_id=self.id,
                ip_address=context.get("ip_address"),
                user_agent=context.get("user_agent"),
                device_fingerprint=context.get("device_fingerprint"),
                location=context.get("location"),
                timestamp=datetime.now(UTC),
                additional_context=context
            )
            
            result = self._authentication_service.assess_authentication_risk(self, auth_context)
            return {
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "factors": result.factors,
                "recommendations": result.recommendations,
                "requires_additional_verification": result.requires_additional_verification
            }
        
        # Fallback assessment
        return {
            "risk_level": "low",
            "risk_score": 0.1,
            "factors": [],
            "recommendations": [],
            "requires_additional_verification": False
        }

    def get_security_recommendations(self) -> list[str]:
        """Get security recommendations from authentication service."""
        if self._authentication_service:
            return self._authentication_service.get_security_recommendations(self)
        
        # Fallback recommendations
        recommendations = []
        if not self.mfa_enabled:
            recommendations.append("Enable multi-factor authentication")
        if not self.email_verified:
            recommendations.append("Verify your email address")
        
        return recommendations

    def validate_account_status_for_authentication(self) -> tuple[bool, str]:
        """Validate account status for authentication using service."""
        if self._authentication_service:
            return self._authentication_service.validate_account_status(self)
        
        # Fallback validation
        if not self.is_active():
            return False, "Account is not active"
        
        return True, "Account is valid for authentication"

    def get_failed_login_count(self) -> int:
        """Get count of recent failed login attempts."""
        return self.failed_login_count
    
    def is_account_locked(self) -> bool:
        """Check if account is locked due to too many failed attempts."""
        return self.is_locked

    def get_role_ids(self) -> set[UUID]:
        """Get user's assigned role IDs. Permission calculation should be done at application layer."""
        return self._role_ids.copy()

    def has_role(self, role_id: UUID) -> bool:
        """Check if user has specific role."""
        return role_id in self._role_ids

    # =============================================================================
    # HELPER METHODS
    # =============================================================================

    def _regenerate_security_stamp(self) -> None:
        """Generate new security stamp to invalidate tokens."""
        self.security_stamp = secrets.token_urlsafe(32)

    def _touch(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "email": self.email.value,
            "username": self.username.value,
            "status": self.status.value,
            "account_type": self.account_type.value,
            "email_verified": self.email_verified,
            "phone_number": self.phone_number.value if self.phone_number else None,
            "phone_verified": self.phone_verified,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "login_count": self.login_count,
            "role_ids": [str(rid) for rid in self._role_ids],
            "permission_ids": [str(pid) for pid in self._permission_ids]
        }


# Export the aggregate
__all__ = ['User']