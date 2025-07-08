"""
Consolidated Authentication Command Handler

Consolidates login, logout, token refresh, and social login commands into a single handler.
Addresses the service explosion issue by grouping related authentication operations.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Union
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.security.geolocation_service import IGeolocationService
from app.modules.identity.domain.interfaces.repositories.login_attempt_repository import ILoginAttemptRepository
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import IMFADeviceRepository
from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    AuthenticationParams,
    LogoutParams,
    RefreshTokenParams,
    SocialLoginParams,
)
from app.modules.identity.application.dtos.request import (
    LoginRequest,
    LogoutRequest,
    RefreshTokenRequest,
    SocialLoginRequest,
)
from app.modules.identity.application.dtos.response import (
    LoginResponse,
    LogoutResponse,
    MFAChallengeResponse,
    RefreshTokenResponse,
    SocialLoginResponse,
)
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.enums import (
    AuditAction,
    LoginFailureReason,
    MFAMethod,
    RiskLevel,
    SecurityEventType,
    SessionType,
    UserStatus,
)
from app.modules.identity.domain.events import (
    LoginAttemptFailed,
    SuspiciousLoginDetected,
    UserLoggedIn,
    UserLoggedOut,
    TokenRefreshed,
)
from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    AuthenticationError,
    InvalidCredentialsError,
    InvalidTokenError,
)
from app.modules.identity.domain.services import (
    PasswordService,
    RiskAssessmentService,
    SecurityService,
    SessionService,
    TokenService,
)
from app.modules.identity.domain.specifications import ActiveUserSpecification
from app.modules.identity.application.services.shared.validation_utils import ValidationUtils
from app.modules.identity.application.services.shared.security_utils import SecurityUtils


# Consolidated Commands
@dataclass
class LoginCommand(Command[LoginResponse]):
    """Command to authenticate a user."""
    params: AuthenticationParams
    device_fingerprint: str | None = None
    session_type: SessionType = SessionType.WEB


@dataclass
class LogoutCommand(Command[LogoutResponse]):
    """Command to logout a user."""
    params: LogoutParams


@dataclass
class RefreshTokenCommand(Command[RefreshTokenResponse]):
    """Command to refresh access token."""
    params: RefreshTokenParams


@dataclass
class SocialLoginCommand(Command[SocialLoginResponse]):
    """Command for social media login."""
    params: SocialLoginParams


@dataclass
class InvalidateAllTokensCommand(Command[LogoutResponse]):
    """Command to invalidate all user tokens."""
    user_id: UUID
    reason: str = "user_initiated"


# Dependency Groups
@dataclass
class AuthenticationRepositories:
    """Repository dependencies for authentication operations."""
    user_repository: IUserRepository
    session_repository: ISessionRepository
    login_attempt_repository: ILoginAttemptRepository
    mfa_device_repository: IMFADeviceRepository


@dataclass
class AuthenticationServices:
    """Service dependencies for authentication operations."""
    password_service: PasswordService
    session_service: SessionService
    security_service: SecurityService
    risk_assessment_service: RiskAssessmentService
    token_service: TokenService
    geolocation_service: IGeolocationService
    device_fingerprint_service: IDeviceFingerprintService
    cache_service: ICacheService


@dataclass
class AuthenticationInfrastructure:
    """Infrastructure dependencies for authentication operations."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class AuthenticationCommandHandler:
    """
    Consolidated handler for all authentication-related commands.
    
    Replaces individual handlers for:
    - LoginCommandHandler
    - LogoutCommandHandler  
    - RefreshTokenCommandHandler
    - SocialLoginCommandHandler
    - InvalidateAllTokensCommandHandler
    """
    
    def __init__(
        self,
        repositories: AuthenticationRepositories,
        services: AuthenticationServices,
        infrastructure: AuthenticationInfrastructure,
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._session_repository = repositories.session_repository
        self._login_attempt_repository = repositories.login_attempt_repository
        self._mfa_device_repository = repositories.mfa_device_repository
        
        # Service dependencies
        self._password_service = services.password_service
        self._session_service = services.session_service
        self._security_service = services.security_service
        self._risk_assessment_service = services.risk_assessment_service
        self._token_service = services.token_service
        self._geolocation_service = services.geolocation_service
        self._device_fingerprint_service = services.device_fingerprint_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work

    @audit_action(
        action=AuditAction.LOGIN_ATTEMPT,
        resource_type="user",
        include_request=False,
        include_errors=True
    )
    @validate_request(LoginRequest)
    @rate_limit(max_requests=5, window_seconds=300, strategy='ip')
    async def handle_login(self, command: LoginCommand) -> LoginResponse:
        """
        Authenticate user with comprehensive security checks.
        Consolidated from LoginCommandHandler.
        """
        async with self._unit_of_work:
            # Check login attempts and find user
            await self._check_login_attempts(command.params.ip_address)
            user = await self._get_and_validate_user(command.params.email)
            
            # Verify password
            if not await self._password_service.verify_password(
                command.params.password, user.password_hash
            ):
                await self._handle_failed_login(user, command.params)
                raise InvalidCredentialsError("Invalid email or password")
            
            # Get location and assess risk
            location = await self._geolocation_service.get_location(command.params.ip_address)
            risk_assessment = await self._assess_login_risk(user, command.params, location)
            
            # Handle suspicious logins
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                await self._handle_suspicious_login(user, command.params, risk_assessment)
                raise AuthenticationError("Login blocked due to security concerns.")
            
            # Check MFA requirements
            if await self._check_mfa_requirements(user, risk_assessment):
                return await self._create_mfa_challenge_response(user, command, location)
            
            # Create authenticated session and tokens
            session = await self._create_authenticated_session(
                user, command.params, location, risk_assessment
            )
            
            access_token = await self._token_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                scopes=await self._get_user_scopes(user)
            )
            
            refresh_token = await self._token_service.generate_refresh_token(
                user_id=user.id, session_id=session.id
            )
            
            # Update user and clear failed attempts
            user.record_login(command.params.ip_address, command.params.user_agent)
            await self._user_repository.update(user)
            await self._clear_failed_attempts(user.id, command.params.ip_address)
            
            # Publish events and notifications
            await self._publish_login_success_event(user, session, command.params, risk_assessment)
            await self._send_security_notifications(user, location, risk_assessment)
            
            await self._unit_of_work.commit()
            
            return LoginResponse(
                user_id=user.id,
                session_id=session.id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                expires_in=3600,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                requires_mfa=False,
                success=True,
                message="Login successful"
            )

    @audit_action(action=AuditAction.LOGOUT, resource_type="session")
    async def handle_logout(self, command: LogoutCommand) -> LogoutResponse:
        """
        Logout user and invalidate session.
        Consolidated from LogoutCommandHandler.
        """
        async with self._unit_of_work:
            session = await self._session_repository.find_by_id(command.params.session_id)
            if not session:
                raise InvalidTokenError("Invalid session")
            
            # Invalidate session
            session.terminate("user_logout")
            await self._session_repository.update(session)
            
            # Revoke tokens
            await self._token_service.revoke_session_tokens(session.id)
            
            # Publish logout event
            await self._event_bus.publish(
                UserLoggedOut(
                    aggregate_id=session.user_id,
                    session_id=session.id,
                    logout_reason="user_initiated"
                )
            )
            
            await self._unit_of_work.commit()
            
            return LogoutResponse(
                success=True,
                message="Logout successful"
            )

    @audit_action(action=AuditAction.TOKEN_REFRESH, resource_type="token")
    @rate_limit(max_requests=10, window_seconds=60, strategy='user')
    async def handle_refresh_token(self, command: RefreshTokenCommand) -> RefreshTokenResponse:
        """
        Refresh access token using refresh token.
        Consolidated from RefreshTokenCommandHandler.
        """
        async with self._unit_of_work:
            # Validate refresh token
            token_claims = await self._token_service.validate_refresh_token(
                command.params.refresh_token
            )
            
            user = await self._user_repository.find_by_id(token_claims.user_id)
            if not user or not ActiveUserSpecification().is_satisfied_by(user):
                raise InvalidTokenError("User account is not active")
            
            session = await self._session_repository.find_by_id(token_claims.session_id)
            if not session or session.is_terminated:
                raise InvalidTokenError("Session is no longer valid")
            
            # Generate new access token
            new_access_token = await self._token_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                scopes=await self._get_user_scopes(user)
            )
            
            # Optionally rotate refresh token
            new_refresh_token = None
            if await self._should_rotate_refresh_token(session):
                new_refresh_token = await self._token_service.generate_refresh_token(
                    user_id=user.id, session_id=session.id
                )
                await self._token_service.revoke_refresh_token(command.params.refresh_token)
            
            # Update session last activity
            session.update_last_activity()
            await self._session_repository.update(session)
            
            # Publish token refresh event
            await self._event_bus.publish(
                TokenRefreshed(
                    aggregate_id=user.id,
                    session_id=session.id,
                    old_token_id=token_claims.token_id,
                    new_token_id=new_access_token.id
                )
            )
            
            await self._unit_of_work.commit()
            
            return RefreshTokenResponse(
                access_token=new_access_token.value,
                refresh_token=new_refresh_token.value if new_refresh_token else command.params.refresh_token,
                token_type="Bearer",
                expires_in=3600,
                success=True,
                message="Token refreshed successfully"
            )

    async def handle_social_login(self, command: SocialLoginCommand) -> SocialLoginResponse:
        """
        Handle social media authentication.
        Consolidated from SocialLoginCommandHandler.
        """
        # Implementation for social login
        # This would integrate with OAuth providers
        pass

    @audit_action(action=AuditAction.TOKEN_REVOCATION, resource_type="user")
    async def handle_invalidate_all_tokens(self, command: InvalidateAllTokensCommand) -> LogoutResponse:
        """
        Invalidate all user tokens and sessions.
        Consolidated from InvalidateAllTokensCommandHandler.
        """
        async with self._unit_of_work:
            # Get all active sessions
            sessions = await self._session_repository.get_active_by_user(command.user_id)
            
            # Terminate all sessions
            for session in sessions:
                session.terminate(command.reason)
                await self._session_repository.update(session)
                await self._token_service.revoke_session_tokens(session.id)
            
            await self._unit_of_work.commit()
            
            return LogoutResponse(
                success=True,
                message=f"All tokens invalidated. Reason: {command.reason}"
            )

    # Private helper methods (static where appropriate)
    async def _check_login_attempts(self, ip_address: str) -> None:
        """Check recent login attempts from IP."""
        recent_attempts = await self._login_attempt_repository.get_recent_by_ip(
            ip_address=ip_address, minutes=30
        )
        
        failed_attempts = [a for a in recent_attempts if not a.successful]
        if len(failed_attempts) >= 10:
            raise AuthenticationError("Too many failed login attempts. Please try again later.")

    async def _get_and_validate_user(self, email: str) -> User:
        """Get user by email and validate account status."""
        user = await self._user_repository.find_by_email(email.lower())
        
        if not user:
            await self._log_failed_attempt(email, "", LoginFailureReason.INVALID_CREDENTIALS)
            raise InvalidCredentialsError("Invalid email or password")
        
        if not ActiveUserSpecification().is_satisfied_by(user):
            await self._log_failed_attempt(
                email, "", LoginFailureReason.ACCOUNT_INACTIVE, user.id
            )
            if user.status == UserStatus.LOCKED:
                raise AccountLockedException("Account is locked")
            raise AuthenticationError(f"Account is {user.status.value}")
        
        return user

    async def _assess_login_risk(self, user: User, params: AuthenticationParams, location: dict) -> Any:
        """Assess risk level of login attempt."""
        return await self._risk_assessment_service.assess_login(
            user_id=user.id,
            ip_address=params.ip_address,
            user_agent=params.user_agent,
            device_fingerprint=getattr(params, 'device_fingerprint', None),
            location=location
        )

    async def _handle_failed_login(self, user: User, params: AuthenticationParams) -> None:
        """Handle failed login attempt."""
        await self._log_failed_attempt(
            params.email, params.ip_address, LoginFailureReason.INVALID_PASSWORD, user.id
        )
        
        user.increment_failed_login_attempts()
        
        if user.failed_login_attempts >= 5:
            user.lock_account("Too many failed login attempts")
            await self._event_bus.publish(
                LoginAttemptFailed(
                    aggregate_id=user.id,
                    ip_address=params.ip_address,
                    reason=LoginFailureReason.INVALID_PASSWORD,
                    account_locked=True
                )
            )

    async def _log_failed_attempt(
        self, email: str, ip_address: str, reason: LoginFailureReason, user_id: UUID | None = None
    ) -> None:
        """Log failed login attempt."""
        await self._login_attempt_repository.add(
            email=email,
            ip_address=ip_address,
            user_id=user_id,
            successful=False,
            failure_reason=reason
        )

    async def _handle_suspicious_login(
        self, user: User, params: AuthenticationParams, risk_assessment: Any
    ) -> None:
        """Handle suspicious login attempt."""
        await self._security_service.log_security_incident(
            incident_type=SecurityEventType.SUSPICIOUS_LOGIN,
            severity=risk_assessment.risk_level,
            user_id=user.id,
            ip_address=params.ip_address,
            details={
                "risk_factors": risk_assessment.risk_factors,
                "risk_score": risk_assessment.risk_score
            }
        )
        
        await self._event_bus.publish(
            SuspiciousLoginDetected(
                aggregate_id=user.id,
                ip_address=params.ip_address,
                risk_level=risk_assessment.risk_level,
                risk_factors=risk_assessment.risk_factors
            )
        )

    async def _check_mfa_requirements(self, user: User, risk_assessment: Any) -> bool:
        """Check if MFA is required for login."""
        if user.mfa_enabled:
            return True
        
        if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        if user.require_mfa_setup:
            return True
        
        user_roles = await self._get_user_roles(user.id)
        return bool(any(role.require_mfa for role in user_roles))

    async def _create_mfa_challenge_response(
        self, user: User, command: LoginCommand, location: dict
    ) -> MFAChallengeResponse:
        """Create MFA challenge response."""
        mfa_session = await self._session_service.create_mfa_session(
            user_id=user.id,
            ip_address=command.params.ip_address,
            user_agent=command.params.user_agent,
            device_fingerprint=command.device_fingerprint,
            location=location
        )
        
        mfa_devices = await self._mfa_device_repository.get_verified_devices(user.id)
        
        return MFAChallengeResponse(
            session_id=mfa_session.id,
            challenge_id=mfa_session.id,
            available_methods=[device.method for device in mfa_devices],
            preferred_method=SecurityUtils.get_preferred_mfa_method(mfa_devices),
            expires_at=mfa_session.expires_at,
            success=True,
            message="MFA verification required"
        )

    async def _create_authenticated_session(
        self, user: User, params: AuthenticationParams, location: dict, risk_assessment: Any
    ) -> Session:
        """Create authenticated user session."""
        return await self._session_service.create_session({
            "user_id": user.id,
            "ip_address": params.ip_address,
            "user_agent": params.user_agent,
            "session_type": SessionType.WEB,
            "risk_score": risk_assessment.risk_score,
            "mfa_verified": False,
            "remember_me": getattr(params, 'remember_me', False),
            "trusted_device": await self._is_trusted_device(user.id, getattr(params, 'device_fingerprint', None)),
            "location": location
        })

    async def _publish_login_success_event(
        self, user: User, session: Session, params: AuthenticationParams, risk_assessment: Any
    ) -> None:
        """Publish successful login event."""
        await self._event_bus.publish(
            UserLoggedIn(
                aggregate_id=user.id,
                session_id=session.id,
                ip_address=params.ip_address,
                user_agent=params.user_agent,
                location=await self._geolocation_service.get_location(params.ip_address),
                risk_level=risk_assessment.risk_level
            )
        )

    async def _send_security_notifications(self, user: User, location: dict, risk_assessment: Any) -> None:
        """Send security notifications for high-risk logins."""
        if risk_assessment.risk_level == RiskLevel.HIGH:
            await self._security_service.notify_high_risk_login(
                user=user, location=location, risk_factors=risk_assessment.risk_factors
            )

    async def _clear_failed_attempts(self, user_id: UUID, ip_address: str) -> None:
        """Clear failed login attempts after successful login."""
        await self._login_attempt_repository.clear_failed_attempts(
            user_id=user_id, ip_address=ip_address
        )

    async def _get_user_scopes(self, user: User) -> list[str]:
        """Get user's permission scopes for token."""
        return ["user:read", "user:write", "profile:read", "profile:write"]

    async def _get_user_roles(self, user_id: UUID) -> list[Any]:
        """Get user's roles."""
        return []

    async def _is_trusted_device(self, user_id: UUID, device_fingerprint: str | None) -> bool:
        """Check if device is trusted."""
        if not device_fingerprint:
            return False
        
        return await self._device_fingerprint_service.is_trusted(
            user_id=user_id, fingerprint=device_fingerprint
        )

    @staticmethod
    def _should_rotate_refresh_token(session: Session) -> bool:
        """Determine if refresh token should be rotated."""
        # Rotate if session is older than 7 days
        return (datetime.now(UTC) - session.created_at).days >= 7