"""
Authentication Domain Service

Handles complex authentication logic including login, MFA, session management,
and risk assessment.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...interfaces.services.authentication.password_hasher import IPasswordHasher
from ...entities.user.login_attempt import LoginAttempt
from ...aggregates.device_registration import DeviceRegistration
from ...entities.user.user_errors import (
    AccountInactiveError,
    AccountLockedError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    MFARequiredError,
)
from ...entities.user.user_events import (
    LoginFailed,
    LoginSuccessful,
    SessionRevoked,
    UserSessionCreated,
)
from ...enums import DevicePlatform, DeviceType, LoginFailureReason, RiskLevel, AccountType
from ...value_objects import IpAddress


class AuthenticationService:
    """Domain service for authentication operations."""
    
    def __init__(self, password_hasher: IPasswordHasher):
        """Initialize authentication service with dependencies.
        
        Args:
            password_hasher: Password hashing interface implementation
        """
        self._password_hasher = password_hasher
    
    def authenticate(
        self,
        user: User,
        password: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None = None,
        mfa_code: str | None = None,
        login_context: dict = None
    ) -> dict[str, Any]:
        """
        Authenticate user and create session.
        
        Returns session data dictionary.
        """
        login_context = login_context or {}
        
        # Check account status
        if user.status != user.UserStatus.ACTIVE:
            if user.status == user.UserStatus.LOCKED:
                raise AccountLockedError()
            raise AccountInactiveError()
        
        # Check if account is locked
        if user.is_locked():
            raise AccountLockedError()
        
        # Create IP value object for validation
        ip_vo = IpAddress(ip_address)
        
        # Record login attempt
        login_attempt = AuthenticationService._record_login_attempt(
            user, ip_vo, user_agent, True
        )
        
        try:
            # Verify password
            if not self._password_hasher.verify_password(password, user.password_hash):
                AuthenticationService._handle_failed_login(
                    user, ip_vo, user_agent, LoginFailureReason.INVALID_PASSWORD
                )
                raise InvalidCredentialsError()
            
            # Assess login risk
            risk_level = self.assess_login_risk(user, login_context)
            
            # Check if MFA is required
            if self.should_require_mfa(user, login_context, risk_level):
                if not mfa_code:
                    raise MFARequiredError()
                
                # Verify MFA code
                if not AuthenticationService.verify_mfa_code(user, mfa_code):
                    raise InvalidMFACodeError()
            
            # Reset failed login count on successful auth
            user.failed_login_count = 0
            user.last_failed_login = None
            
            # Update login info
            user.last_login = datetime.now(UTC)
            user.login_count += 1
            user.updated_at = datetime.now(UTC)
            
            # Create session
            session = AuthenticationService._create_session(
                user, ip_vo, user_agent, device_fingerprint
            )
            
            # Record successful login
            login_attempt.success = True
            
            # Add login successful event
            user.add_domain_event(LoginSuccessful(
                user_id=user.id,
                session_id=session["id"],
                ip_address=ip_address,
                user_agent=user_agent,
                mfa_used=user.requires_mfa(),
                risk_level=risk_level.value
            ))
            
            # Check and register device if needed
            if device_fingerprint:
                AuthenticationService._register_or_update_device(
                    user, device_fingerprint, user_agent
                )
            
            return session
            
        except Exception as e:
            # Record failed login
            login_attempt.success = False
            if isinstance(e, InvalidCredentialsError):
                login_attempt.failure_reason = LoginFailureReason.INVALID_CREDENTIALS
            elif isinstance(e, AccountLockedError):
                login_attempt.failure_reason = LoginFailureReason.ACCOUNT_LOCKED
            elif isinstance(e, MFARequiredError):
                login_attempt.failure_reason = LoginFailureReason.MFA_REQUIRED
            elif isinstance(e, InvalidMFACodeError):
                login_attempt.failure_reason = LoginFailureReason.MFA_FAILED
            else:
                login_attempt.failure_reason = LoginFailureReason.UNKNOWN
            
            # Add login failed event
            user.add_domain_event(LoginFailed(
                user_id=user.id,
                reason=login_attempt.failure_reason.value,
                ip_address=ip_address,
                user_agent=user_agent
            ))
            
            raise
    
    def assess_login_risk(self, user: User, login_context: dict) -> RiskLevel:
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
        elif avg_risk >= 0.5:
            return RiskLevel.HIGH
        elif avg_risk >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def should_require_mfa(self, user: User, login_context: dict, risk_level: RiskLevel = None) -> bool:
        """Determine if MFA should be required for login."""
        # Always require MFA if enabled
        if user.mfa_enabled:
            return True
        
        # Risk-based MFA requirements
        if risk_level is None:
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
    
    def validate_password_strength(self, password: str, user: User) -> tuple[bool, list[str]]:
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
    
    def should_lock_account(self, user: User) -> tuple[bool, timedelta]:
        """Determine if account should be locked based on failed attempts."""
        # Progressive lockout duration
        if user.failed_login_count >= 10:
            return True, timedelta(hours=24)
        elif user.failed_login_count >= 7:
            return True, timedelta(hours=4)
        elif user.failed_login_count >= 5:
            return True, timedelta(hours=1)
        elif user.failed_login_count >= 3:
            return True, timedelta(minutes=15)
        
        return False, timedelta(0)
    
    def calculate_password_expiry(self, user: User) -> datetime | None:
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
    
    def is_password_expired(self, user: User) -> bool:
        """Check if user's password has expired."""
        expiry_date = self.calculate_password_expiry(user)
        if not expiry_date:
            return False
        
        return datetime.now(UTC) > expiry_date
    
    def get_session_timeout(self, user: User) -> timedelta:
        """Get appropriate session timeout for user."""
        if user.account_type == AccountType.ADMIN:
            return timedelta(hours=2)  # Shorter for admins
        elif user.account_type == AccountType.SERVICE:
            return timedelta(hours=24)  # Longer for service accounts
        else:
            return timedelta(hours=8)  # Standard timeout
    
    def validate_account_access(self, user: User) -> tuple[bool, str]:
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
    
    @staticmethod
    def _create_session(
        user: User,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None = None
    ) -> dict[str, Any]:
        """Create a new user session."""
        session_data = {
            "id": uuid4(),
            "user_id": user.id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "device_fingerprint": device_fingerprint,
            "created_at": datetime.utcnow(),
            "is_active": True
        }
        
        if not hasattr(user, '_sessions'):
            user._sessions = []
        user._sessions.append(session_data)
        
        user.add_domain_event(UserSessionCreated(
            user_id=user.id,
            session_id=session_data["id"],
            ip_address=ip_address.value,
            user_agent=user_agent,
            device_id=device_fingerprint if device_fingerprint else None
        ))
        
        return session_data
    
    @staticmethod
    def _handle_failed_login(
        user: User,
        ip_address: IpAddress,
        user_agent: str,
        reason: LoginFailureReason
    ) -> None:
        """Handle failed login attempt."""
        user.failed_login_count += 1
        user.last_failed_login = datetime.now(UTC)
        
        # Lock account if too many failed attempts
        from ...constants import SecurityLimits
        if user.failed_login_count >= SecurityLimits.MAX_FAILED_LOGIN_ATTEMPTS:
            user.lock(timedelta(minutes=SecurityLimits.ACCOUNT_LOCKOUT_DURATION_MINUTES))
    
    @staticmethod
    def _record_login_attempt(
        user: User,
        ip_address: IpAddress,
        user_agent: str,
        success: bool,
        failure_reason: LoginFailureReason | None = None
    ) -> LoginAttempt:
        """Record login attempt for audit."""
        if success:
            attempt = LoginAttempt.create_successful(
                email=user.email.value,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=uuid4(),
                mfa_used=user.requires_mfa()
            )
        else:
            attempt = LoginAttempt.create_failed(
                email=user.email.value,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason=failure_reason or LoginFailureReason.UNKNOWN,
                user_id=user.id
            )
        
        if not hasattr(user, '_login_attempts'):
            user._login_attempts = []
        user._login_attempts.append(attempt)
        
        # Keep only last 100 attempts
        if len(user._login_attempts) > 100:
            user._login_attempts = user._login_attempts[-100:]
        
        return attempt
    
    @staticmethod
    def _register_or_update_device(
        user: User,
        fingerprint: str,
        user_agent: str
    ) -> DeviceRegistration:
        """Register or update device."""
        if not hasattr(user, '_registered_devices'):
            user._registered_devices = []
            
        # Check if device exists
        existing = next(
            (d for d in user._registered_devices if d.device_id == fingerprint),
            None
        )
        
        if existing:
            existing.last_seen = datetime.now(UTC)
            return existing
        
        # Register new device
        device = DeviceRegistration.create(
            user_id=user.id,
            device_id=fingerprint,
            device_name=f"Device {len(user._registered_devices) + 1}",
            device_type=DeviceType.UNKNOWN,
            fingerprint=fingerprint,
            platform=DevicePlatform.UNKNOWN
        )
        
        user._registered_devices.append(device)
        return device
    
    @staticmethod
    def logout(user: User, session_id: UUID) -> None:
        """Logout from specific session."""
        if not hasattr(user, '_sessions'):
            return
            
        session = next((s for s in user._sessions if s.get("id") == session_id), None)
        if not session:
            return
        
        session["is_active"] = False
        session["revoked_at"] = datetime.utcnow()
        
        user.add_domain_event(SessionRevoked(
            session_id=session_id,
            user_id=user.id,
            reason="user_logout"
        ))
    
    @staticmethod
    def logout_all_devices(
        user: User,
        except_session_id: UUID | None = None
    ) -> None:
        """Logout from all sessions/devices."""
        if not hasattr(user, '_sessions'):
            return
            
        revoked_count = 0
        
        for session in user._sessions:
            if session.get("is_active") and session.get("id") != except_session_id:
                session["is_active"] = False
                session["revoked_at"] = datetime.utcnow()
                revoked_count += 1
                
                user.add_domain_event(SessionRevoked(
                    session_id=session.get("id"),
                    user_id=user.id,
                    reason="logout_all_devices",
                    revoke_all_sessions=True
                ))
        
        # Also revoke all access tokens
        if hasattr(user, '_access_tokens'):
            for token in user._access_tokens:
                if not token.revoked_at:
                    token.revoke(user.id, "logout_all_devices")
    
    @staticmethod
    def verify_mfa_code(user: User, code: str) -> bool:
        """Verify MFA code (TOTP or backup)."""
        # First try backup codes
        if code.replace('-', '').isdigit() and len(code.replace('-', '')) == 8:
            return AuthenticationService._use_backup_code(user, code)
        
        # Then try active MFA devices
        if hasattr(user, '_mfa_devices'):
            for device in user._mfa_devices:
                if device.is_active and device.verify_code(code):
                    device.update_last_used()
                    return True
        
        return False
    
    @staticmethod
    def _use_backup_code(user: User, code: str) -> bool:
        """Use MFA backup code."""
        if not hasattr(user, 'backup_codes') or not user.backup_codes:
            return False
        
        # Hash the provided code
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Check if code exists
        if code_hash not in user.backup_codes:
            return False
        
        # Remove used code
        user.backup_codes.remove(code_hash)
        user.updated_at = datetime.now(UTC)
        
        from ...entities.user.user_events import BackupCodeUsed
        user.add_domain_event(BackupCodeUsed(
            user_id=user.id,
            code_hash=code_hash,
            used_at=datetime.now(UTC),
            remaining_codes=len(user.backup_codes),
            ip_address=""  # Would be passed in from context
        ))
        
        return True
