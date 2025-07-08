"""
Authentication mutation resolvers for GraphQL.

This module implements comprehensive authentication-related mutations including
login, logout, registration, MFA operations, and password management with
robust error handling, transaction management, and security features.
"""

from datetime import datetime, timedelta
from typing import Any

from strawberry import mutation
from strawberry.types import Info

from app.core.cache import get_cache
from app.core.database import get_db_context
from app.core.enums import EventType
from app.core.errors import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    SecurityError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import hash_password, verify_password
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.interfaces import (
    IAuthenticationService,
    IMFAService,
    ISecurityEventRepository,
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.presentation.graphql.types import (
    AuthResponse,
    MFASetupInput,
    MFAVerificationInput,
    UserCreateInput,
)

logger = get_logger(__name__)


class AuthMutations:
    """Authentication-related GraphQL mutations."""

    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        security_event_repository: ISecurityEventRepository,
        auth_service: IAuthenticationService,
        mfa_service: IMFAService
    ):
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.security_event_repository = security_event_repository
        self.auth_service = auth_service
        self.mfa_service = mfa_service
        self.cache = get_cache()
        self.logger = logger

    @mutation
    async def login(self, info: Info, email: str, password: str) -> AuthResponse:
        """
        Authenticate user login with comprehensive security checks.
        
        Args:
            email: User email address
            password: User password
            
        Returns:
            AuthResponse with tokens and user data
            
        Raises:
            AuthenticationError: Invalid credentials
            SecurityError: Account locked or security issues
            RateLimitError: Too many login attempts
        """
        async with get_db_context() as db:
            try:
                # Check rate limiting
                await self._check_login_rate_limit(email, info)

                # Validate input
                if not email or not password:
                    raise ValidationError("Email and password are required")

                # Find user
                user = await self.user_repository.find_by_email(email)
                if not user:
                    await self._log_failed_login(email, "User not found", info)
                    raise AuthenticationError("Invalid credentials")

                # Check account status
                if user.is_locked:
                    await self._log_security_event(
                        user.id,
                        EventType.LOGIN_BLOCKED,
                        "Attempted login to locked account",
                        info
                    )
                    raise SecurityError("Account is locked")

                if not user.is_active:
                    await self._log_security_event(
                        user.id,
                        EventType.LOGIN_BLOCKED,
                        "Attempted login to inactive account",
                        info
                    )
                    raise SecurityError("Account is inactive")

                # Verify password
                if not verify_password(password, user.password_hash):
                    await self._increment_failed_attempts(user.id)
                    await self._log_failed_login(email, "Invalid password", info)
                    raise AuthenticationError("Invalid credentials")

                # Check if MFA is required
                if user.mfa_enabled:
                    # Create pending MFA session
                    pending_session = await self._create_pending_mfa_session(user, info)
                    return AuthResponse(
                        access_token=None,
                        refresh_token=None,
                        user=user,
                        requires_mfa=True,
                        mfa_session_id=pending_session.id
                    )

                # Create session and tokens
                session = await self._create_user_session(user, info)
                tokens = await self.auth_service.generate_tokens(user.id, session.id)

                # Reset failed attempts
                await self._reset_failed_attempts(user.id)

                # Log successful login
                await self._log_security_event(
                    user.id,
                    EventType.LOGIN_SUCCESS,
                    "Successful login",
                    info
                )

                # Update last login
                user.last_login_at = datetime.utcnow()
                await self.user_repository.update(user)

                # Commit transaction
                await db.commit()

                return AuthResponse(
                    access_token=tokens["access_token"],
                    refresh_token=tokens["refresh_token"],
                    user=user,
                    requires_mfa=False
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Login failed: {e!s}")
                raise

    @mutation
    async def logout(self, info: Info) -> bool:
        """
        Logout current user session.
        
        Returns:
            True if logout successful
            
        Raises:
            AuthenticationError: No active session
        """
        async with get_db_context() as db:
            try:
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthenticationError("No active session")

                session_id = info.context.get("session_id")
                if session_id:
                    # Invalidate session
                    await self.session_repository.invalidate_session(session_id)

                    # Remove from cache
                    await self.cache.delete(f"session:{session_id}")
                    await self.cache.delete(f"user_sessions:{current_user.id}")

                # Log logout
                await self._log_security_event(
                    current_user.id,
                    EventType.LOGOUT,
                    "User logout",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Logout failed: {e!s}")
                raise

    @mutation
    async def logout_all(self, info: Info) -> bool:
        """
        Logout all user sessions.
        
        Returns:
            True if all sessions logged out
        """
        async with get_db_context() as db:
            try:
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthenticationError("No active session")

                # Invalidate all user sessions
                await self.session_repository.invalidate_all_user_sessions(current_user.id)

                # Clear cache
                await self.cache.delete(f"user_sessions:{current_user.id}")

                # Log logout all
                await self._log_security_event(
                    current_user.id,
                    EventType.LOGOUT_ALL,
                    "All sessions logged out",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Logout all failed: {e!s}")
                raise

    @mutation
    async def refresh_token(self, info: Info, refresh_token: str) -> AuthResponse:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            AuthResponse with new tokens
            
        Raises:
            AuthenticationError: Invalid refresh token
        """
        async with get_db_context() as db:
            try:
                # Validate refresh token
                token_data = await self.auth_service.verify_refresh_token(refresh_token)
                if not token_data:
                    raise AuthenticationError("Invalid refresh token")

                user_id = token_data.get("user_id")
                session_id = token_data.get("session_id")

                # Get user and session
                user = await self.user_repository.find_by_id(user_id)
                session = await self.session_repository.find_by_id(session_id)

                if not user or not session or not session.is_active:
                    raise AuthenticationError("Invalid session")

                # Generate new tokens
                new_tokens = await self.auth_service.generate_tokens(user_id, session_id)

                # Update session
                session.last_activity_at = datetime.utcnow()
                await self.session_repository.update(session)

                await db.commit()

                return AuthResponse(
                    access_token=new_tokens["access_token"],
                    refresh_token=new_tokens["refresh_token"],
                    user=user
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Token refresh failed: {e!s}")
                raise

    @mutation
    async def register_user(self, info: Info, input: UserCreateInput) -> AuthResponse:
        """
        Register new user account.
        
        Args:
            input: User creation data
            
        Returns:
            AuthResponse with user data and tokens
            
        Raises:
            ValidationError: Invalid input data
            ConflictError: User already exists
        """
        async with get_db_context() as db:
            try:
                # Validate input
                await self._validate_user_input(input)

                # Check if user exists
                existing_user = await self.user_repository.find_by_email(input.email)
                if existing_user:
                    raise ValidationError("User with this email already exists")

                # Hash password
                password_hash = hash_password(input.password)

                # Create user
                user_data = {
                    "email": input.email,
                    "password_hash": password_hash,
                    "first_name": input.first_name,
                    "last_name": input.last_name,
                    "phone_number": getattr(input, "phone_number", None),
                    "is_active": True,
                    "email_verified": False,
                    "created_at": datetime.utcnow()
                }

                user = await self.user_repository.create(user_data)

                # Send verification email
                await self.auth_service.send_verification_email(user)

                # Create session
                session = await self._create_user_session(user, info)
                tokens = await self.auth_service.generate_tokens(user.id, session.id)

                # Log registration
                await self._log_security_event(
                    user.id,
                    EventType.USER_REGISTERED,
                    "New user registration",
                    info
                )

                await db.commit()

                return AuthResponse(
                    access_token=tokens["access_token"],
                    refresh_token=tokens["refresh_token"],
                    user=user
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User registration failed: {e!s}")
                raise

    @mutation
    async def verify_email(self, info: Info, token: str) -> bool:
        """
        Verify user email address.
        
        Args:
            token: Email verification token
            
        Returns:
            True if verification successful
        """
        async with get_db_context() as db:
            try:
                # Verify token
                token_data = await self.auth_service.verify_email_token(token)
                if not token_data:
                    raise ValidationError("Invalid verification token")

                user_id = token_data.get("user_id")
                user = await self.user_repository.find_by_id(user_id)

                if not user:
                    raise NotFoundError("User not found")

                # Update user
                user.email_verified = True
                user.email_verified_at = datetime.utcnow()
                await self.user_repository.update(user)

                # Log verification
                await self._log_security_event(
                    user.id,
                    EventType.EMAIL_VERIFIED,
                    "Email address verified",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Email verification failed: {e!s}")
                raise

    @mutation
    async def reset_password(self, info: Info, email: str) -> bool:
        """
        Initiate password reset process.
        
        Args:
            email: User email address
            
        Returns:
            True if reset email sent
        """
        async with get_db_context() as db:
            try:
                # Find user
                user = await self.user_repository.find_by_email(email)
                if not user:
                    # Don't reveal if user exists
                    return True

                # Generate reset token
                await self.auth_service.send_password_reset_email(user)

                # Log password reset request
                await self._log_security_event(
                    user.id,
                    EventType.PASSWORD_RESET_REQUESTED,
                    "Password reset requested",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Password reset failed: {e!s}")
                raise

    @mutation
    async def change_password(
        self,
        info: Info,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password.
        
        Args:
            current_password: Current password
            new_password: New password
            
        Returns:
            True if password changed
        """
        async with get_db_context() as db:
            try:
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthenticationError("Authentication required")

                # Verify current password
                if not verify_password(current_password, current_user.password_hash):
                    raise AuthenticationError("Invalid current password")

                # Validate new password
                await self._validate_password(new_password)

                # Hash new password
                new_password_hash = hash_password(new_password)

                # Update user
                current_user.password_hash = new_password_hash
                current_user.password_changed_at = datetime.utcnow()
                await self.user_repository.update(current_user)

                # Invalidate all sessions except current
                session_id = info.context.get("session_id")
                await self.session_repository.invalidate_all_user_sessions(
                    current_user.id,
                    exclude_session_id=session_id
                )

                # Log password change
                await self._log_security_event(
                    current_user.id,
                    EventType.PASSWORD_CHANGED,
                    "Password changed by user",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Password change failed: {e!s}")
                raise

    @mutation
    async def setup_mfa(self, info: Info, input: MFASetupInput) -> dict[str, Any]:
        """
        Setup MFA device for user.
        
        Args:
            input: MFA setup input
            
        Returns:
            MFA setup data with QR code
        """
        async with get_db_context() as db:
            try:
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthenticationError("Authentication required")

                # Setup MFA device
                mfa_data = await self.mfa_service.setup_device(current_user.id, input)

                # Log MFA setup
                await self._log_security_event(
                    current_user.id,
                    EventType.MFA_SETUP_STARTED,
                    f"MFA setup started for device type: {input.device_type}",
                    info
                )

                await db.commit()
                return mfa_data

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"MFA setup failed: {e!s}")
                raise

    @mutation
    async def verify_mfa(self, info: Info, input: MFAVerificationInput) -> AuthResponse:
        """
        Verify MFA token and complete authentication.
        
        Args:
            input: MFA verification input
            
        Returns:
            AuthResponse with tokens
        """
        async with get_db_context() as db:
            try:
                # Verify MFA token
                verification_result = await self.mfa_service.verify_token(input)

                if not verification_result.is_valid:
                    await self._log_security_event(
                        verification_result.user_id,
                        EventType.MFA_FAILED,
                        "MFA verification failed",
                        info
                    )
                    raise AuthenticationError("Invalid MFA token")

                # Get user and create session
                user = await self.user_repository.find_by_id(verification_result.user_id)
                session = await self._create_user_session(user, info)
                tokens = await self.auth_service.generate_tokens(user.id, session.id)

                # Log successful MFA
                await self._log_security_event(
                    user.id,
                    EventType.MFA_SUCCESS,
                    "MFA verification successful",
                    info
                )

                await db.commit()

                return AuthResponse(
                    access_token=tokens["access_token"],
                    refresh_token=tokens["refresh_token"],
                    user=user
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"MFA verification failed: {e!s}")
                raise

    @mutation
    async def disable_mfa(self, info: Info, device_id: str) -> bool:
        """
        Disable MFA device.
        
        Args:
            device_id: MFA device ID
            
        Returns:
            True if device disabled
        """
        async with get_db_context() as db:
            try:
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthenticationError("Authentication required")

                # Disable MFA device
                await self.mfa_service.disable_device(current_user.id, device_id)

                # Log MFA disable
                await self._log_security_event(
                    current_user.id,
                    EventType.MFA_DISABLED,
                    f"MFA device disabled: {device_id}",
                    info
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"MFA disable failed: {e!s}")
                raise

    # Helper methods

    async def _check_login_rate_limit(self, email: str, info: Info) -> None:
        """Check login rate limiting."""
        ip_address = info.context.get("ip_address", "unknown")

        # Check IP-based rate limit
        ip_key = f"login_attempts:ip:{ip_address}"
        ip_attempts = await self.cache.get(ip_key) or 0

        if ip_attempts >= 10:  # 10 attempts per IP per hour
            raise RateLimitError("Too many login attempts from this IP")

        # Check email-based rate limit
        email_key = f"login_attempts:email:{email}"
        email_attempts = await self.cache.get(email_key) or 0

        if email_attempts >= 5:  # 5 attempts per email per hour
            raise RateLimitError("Too many login attempts for this account")

    async def _log_failed_login(self, email: str, reason: str, info: Info) -> None:
        """Log failed login attempt."""
        ip_address = info.context.get("ip_address", "unknown")

        # Increment rate limiting counters
        ip_key = f"login_attempts:ip:{ip_address}"
        email_key = f"login_attempts:email:{email}"

        await self.cache.increment(ip_key, expire_time=3600)  # 1 hour
        await self.cache.increment(email_key, expire_time=3600)  # 1 hour

        # Log security event
        event_data = {
            "event_type": EventType.LOGIN_FAILED,
            "description": f"Failed login attempt: {reason}",
            "ip_address": ip_address,
            "user_agent": info.context.get("user_agent"),
            "metadata": {"email": email, "reason": reason},
            "created_at": datetime.utcnow()
        }

        await self.security_event_repository.create(event_data)

    async def _log_security_event(
        self,
        user_id: str,
        event_type: EventType,
        description: str,
        info: Info
    ) -> None:
        """Log security event."""
        event_data = {
            "user_id": user_id,
            "event_type": event_type,
            "description": description,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "created_at": datetime.utcnow()
        }

        await self.security_event_repository.create(event_data)

    async def _create_user_session(self, user: User, info: Info) -> Session:
        """Create user session."""
        session_data = {
            "user_id": user.id,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_activity_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=30)
        }

        return await self.session_repository.create(session_data)

    async def _create_pending_mfa_session(self, user: User, info: Info) -> Session:
        """Create pending MFA session."""
        session_data = {
            "user_id": user.id,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "is_active": False,  # Not active until MFA verified
            "is_mfa_pending": True,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=15)  # Short expiry
        }

        return await self.session_repository.create(session_data)

    async def _increment_failed_attempts(self, user_id: str) -> None:
        """Increment failed login attempts for user."""
        key = f"failed_attempts:{user_id}"
        attempts = await self.cache.increment(key, expire_time=3600)  # 1 hour

        # Lock account after 5 failed attempts
        if attempts >= 5:
            user = await self.user_repository.find_by_id(user_id)
            if user:
                user.is_locked = True
                user.locked_at = datetime.utcnow()
                await self.user_repository.update(user)

    async def _reset_failed_attempts(self, user_id: str) -> None:
        """Reset failed login attempts for user."""
        key = f"failed_attempts:{user_id}"
        await self.cache.delete(key)

    async def _validate_user_input(self, input: UserCreateInput) -> None:
        """Validate user creation input."""
        if not input.email or "@" not in input.email:
            raise ValidationError("Valid email address is required")

        if not input.password or len(input.password) < 8:
            raise ValidationError("Password must be at least 8 characters")

        if not input.first_name or not input.last_name:
            raise ValidationError("First name and last name are required")

    async def _validate_password(self, password: str) -> None:
        """Validate password strength."""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters")

        if not any(c.isupper() for c in password):
            raise ValidationError("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            raise ValidationError("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            raise ValidationError("Password must contain at least one digit")
