"""
Authentication Domain Service

Handles complex authentication logic including login, MFA, and session management.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.core.security import verify_password

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...entities.admin.login_attempt import LoginAttempt
from ...entities.device.device_registration import DeviceRegistration
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
from ...enums import DevicePlatform, DeviceType, LoginFailureReason
from ...value_objects import IpAddress


class AuthenticationService:
    """Domain service for authentication operations."""
    
    @staticmethod
    def authenticate(
        user: User,
        password: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None = None,
        mfa_code: str | None = None
    ) -> dict[str, Any]:
        """
        Authenticate user and create session.
        
        Returns session data dictionary.
        """
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
            if not verify_password(password, user.password_hash):
                AuthenticationService._handle_failed_login(
                    user, ip_vo, user_agent, LoginFailureReason.INVALID_PASSWORD
                )
                raise InvalidCredentialsError()
            
            # Check if MFA is required
            if user.requires_mfa():
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
                mfa_used=user.requires_mfa()
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
        for device in user._mfa_devices:
            if device.is_active and device.verify_code(code):
                device.update_last_used()
                return True
        
        return False
    
    @staticmethod
    def _use_backup_code(user: User, code: str) -> bool:
        """Use MFA backup code."""
        if not user.backup_codes:
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