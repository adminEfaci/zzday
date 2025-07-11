"""
Login command implementation.

Handles user authentication with comprehensive security checks.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import AuthenticationParams
from app.modules.identity.application.dtos.internal import (
    RiskAssessmentResult,
    SecurityIncidentContext,
    SessionCreationContext,
)
from app.modules.identity.application.dtos.request import LoginRequest
from app.modules.identity.application.dtos.response import (
    LoginResponse,
    MFAChallengeResponse,
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
)
from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    AuthenticationError,
    InvalidCredentialsError,
)
from app.modules.identity.domain.interfaces.repositories.login_attempt_repository import (
    ILoginAttemptRepository,
)
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import (
    IMFADeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.interfaces.services.security.geolocation_service import (
    IGeolocationService,
)
from app.modules.identity.domain.interfaces.services import (
    IDeviceFingerprintService,
)
from app.modules.identity.domain.services import (
    PasswordService,
    RiskAssessmentService,
    SecurityService,
    SessionService,
    TokenService,
)
from app.modules.identity.domain.specifications import ActiveUserSpecification


@dataclass
class LoginRepositoryDependencies:
    """Repository dependencies for login handler."""
    user_repository: IUserRepository
    session_repository: ISessionRepository
    login_attempt_repository: ILoginAttemptRepository
    mfa_device_repository: IMFADeviceRepository


@dataclass
class LoginServiceDependencies:
    """Service dependencies for login handler."""
    password_service: PasswordService
    session_service: SessionService
    security_service: SecurityService
    risk_assessment_service: RiskAssessmentService
    token_service: TokenService
    geolocation_service: IGeolocationService
    device_fingerprint_service: IDeviceFingerprintService
    cache_service: ICacheService


@dataclass
class LoginInfrastructureDependencies:
    """Infrastructure dependencies for login handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class LoginCommand(Command[LoginResponse]):
    """Command to authenticate a user."""
    
    def __init__(self, params: AuthenticationParams, **kwargs: Any):
        self.params = params
        # Additional parameters not in base DTO
        self.device_fingerprint = kwargs.get('device_fingerprint')
        self.session_type = kwargs.get('session_type', SessionType.WEB)


class LoginCommandHandler(CommandHandler[LoginCommand, LoginResponse]):
    """Handler for user authentication."""
    
    def __init__(
        self,
        repositories: LoginRepositoryDependencies,
        services: LoginServiceDependencies,
        infrastructure: LoginInfrastructureDependencies
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
        include_request=False,  # Don't log password
        include_errors=True
    )
    @validate_request(LoginRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=300,  # 5 minutes
        strategy='ip'
    )
    async def handle(self, command: LoginCommand) -> LoginResponse:
        """
        Authenticate user with comprehensive security checks.
        
        Process:
        1. Check login attempts and lockout
        2. Find user by email
        3. Verify password
        4. Assess login risk
        5. Check MFA requirements
        6. Create session
        7. Generate tokens
        8. Log security events
        
        Returns:
            LoginResponse with tokens or MFAChallengeResponse
            
        Raises:
            InvalidCredentialsError: If credentials invalid
            AccountLockedException: If account locked
            MFARequiredError: If MFA required
        """
        async with self._unit_of_work:
            # 1. Check recent login attempts from this IP
            await self._check_login_attempts(command.ip_address)
            
            # 2. Find user by email
            user = await self._user_repository.find_by_email(command.email.lower())
            
            if not user:
                # Log failed attempt without revealing user existence
                await self._log_failed_attempt(
                    email=command.email,
                    ip_address=command.ip_address,
                    reason=LoginFailureReason.INVALID_CREDENTIALS
                )
                raise InvalidCredentialsError("Invalid email or password")
            
            # 3. Check if user is active
            if not ActiveUserSpecification().is_satisfied_by(user):
                await self._log_failed_attempt(
                    email=command.email,
                    ip_address=command.ip_address,
                    reason=LoginFailureReason.ACCOUNT_INACTIVE,
                    user_id=user.id
                )
                
                if user.status == UserStatus.LOCKED:
                    raise AccountLockedException("Account is locked")
                raise AuthenticationError(f"Account is {user.status.value}")
            
            # 4. Verify password
            is_valid = await self._password_service.verify_password(
                command.password,
                user.password_hash
            )
            
            if not is_valid:
                await self._handle_failed_login(user, command)
                raise InvalidCredentialsError("Invalid email or password")
            
            # 5. Get location data
            location = await self._geolocation_service.get_location(command.ip_address)
            
            # 6. Assess login risk
            risk_assessment = await self._assess_login_risk(
                user=user,
                ip_address=command.ip_address,
                user_agent=command.user_agent,
                device_fingerprint=command.device_fingerprint,
                location=location
            )
            
            # 7. Check if suspicious
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                await self._handle_suspicious_login(user, command, risk_assessment)
                raise AuthenticationError(
                    "Login blocked due to security concerns. Please check your email."
                )
            
            # 8. Check MFA requirements
            requires_mfa = await self._check_mfa_requirements(user, risk_assessment)
            
            if requires_mfa:
                # Create temporary session for MFA
                mfa_session = await self._create_mfa_session(user, command, location)
                
                # Get available MFA methods
                mfa_devices = await self._mfa_device_repository.get_verified_devices(user.id)
                
                return MFAChallengeResponse(
                    session_id=mfa_session.id,
                    challenge_id=mfa_session.id,  # Reuse session ID
                    available_methods=[device.method for device in mfa_devices],
                    preferred_method=self._get_preferred_mfa_method(mfa_devices),
                    expires_at=mfa_session.expires_at,
                    success=True,
                    message="MFA verification required"
                )
            
            # 9. Create authenticated session
            session = await self._create_authenticated_session(
                user=user,
                command=command,
                location=location,
                risk_assessment=risk_assessment
            )
            
            # 10. Generate tokens
            access_token = await self._token_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                scopes=await self._get_user_scopes(user)
            )
            
            refresh_token = await self._token_service.generate_refresh_token(
                user_id=user.id,
                session_id=session.id
            )
            
            # 11. Update user last login
            user.record_login(
                ip_address=command.ip_address,
                user_agent=command.user_agent
            )
            await self._user_repository.update(user)
            
            # 12. Clear failed login attempts
            await self._clear_failed_attempts(user.id, command.ip_address)
            
            # 13. Publish success event
            await self._event_bus.publish(
                UserLoggedIn(
                    aggregate_id=user.id,
                    session_id=session.id,
                    ip_address=command.ip_address,
                    user_agent=command.user_agent,
                    location=location,
                    risk_level=risk_assessment.risk_level
                )
            )
            
            # 14. Send notifications for high-risk logins
            if risk_assessment.risk_level == RiskLevel.HIGH:
                await self._security_service.notify_high_risk_login(
                    user=user,
                    location=location,
                    risk_factors=risk_assessment.risk_factors
                )
            
            # 15. Commit transaction
            await self._unit_of_work.commit()
            
            return LoginResponse(
                user_id=user.id,
                session_id=session.id,
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",  # noqa: S106
                expires_in=3600,  # 1 hour
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                requires_mfa=False,
                success=True,
                message="Login successful"
            )
    
    async def _check_login_attempts(self, ip_address: str) -> None:
        """Check recent login attempts from IP."""
        recent_attempts = await self._login_attempt_repository.get_recent_by_ip(
            ip_address=ip_address,
            minutes=30
        )
        
        failed_attempts = [a for a in recent_attempts if not a.successful]
        
        if len(failed_attempts) >= 10:
            raise AuthenticationError(
                "Too many failed login attempts. Please try again later."
            )
    
    async def _log_failed_attempt(
        self,
        email: str,
        ip_address: str,
        reason: LoginFailureReason,
        user_id: UUID | None = None
    ) -> None:
        """Log failed login attempt."""
        await self._login_attempt_repository.add(
            email=email,
            ip_address=ip_address,
            user_id=user_id,
            successful=False,
            failure_reason=reason
        )
    
    async def _handle_failed_login(
        self,
        user: User,
        command: LoginCommand
    ) -> None:
        """Handle failed login attempt."""
        # Log failed attempt
        await self._log_failed_attempt(
            email=command.email,
            ip_address=command.ip_address,
            reason=LoginFailureReason.INVALID_PASSWORD,
            user_id=user.id
        )
        
        # Increment failed attempts
        user.increment_failed_login_attempts()
        
        # Check if should lock account
        if user.failed_login_attempts >= 5:
            user.lock_account("Too many failed login attempts")
            
            # Publish event
            await self._event_bus.publish(
                LoginAttemptFailed(
                    aggregate_id=user.id,
                    ip_address=command.ip_address,
                    reason=LoginFailureReason.INVALID_PASSWORD,
                    account_locked=True
                )
            )
    
    async def _assess_login_risk(
        self,
        user: User,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None,
        location: dict
    ) -> RiskAssessmentResult:
        """Assess risk level of login attempt."""
        return await self._risk_assessment_service.assess_login(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            location=location
        )
    
    async def _handle_suspicious_login(
        self,
        user: User,
        command: LoginCommand,
        risk_assessment: RiskAssessmentResult
    ) -> None:
        """Handle suspicious login attempt."""
        # Log security incident
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_LOGIN,
                severity=risk_assessment.risk_level,
                user_id=user.id,
                ip_address=command.ip_address,
                details={
                    "risk_factors": risk_assessment.risk_factors,
                    "risk_score": risk_assessment.risk_score
                }
            )
        )
        
        # Publish event
        await self._event_bus.publish(
            SuspiciousLoginDetected(
                aggregate_id=user.id,
                ip_address=command.ip_address,
                risk_level=risk_assessment.risk_level,
                risk_factors=risk_assessment.risk_factors
            )
        )
        
        # Notify user
        await self._security_service.notify_suspicious_login(
            user=user,
            ip_address=command.ip_address,
            location=await self._geolocation_service.get_location(command.ip_address)
        )
    
    async def _check_mfa_requirements(
        self,
        user: User,
        risk_assessment: RiskAssessmentResult
    ) -> bool:
        """Check if MFA is required for login."""
        # Always require if user has MFA enabled
        if user.mfa_enabled:
            return True
        
        # Require for high-risk logins
        if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # Check if user requires MFA setup
        if user.require_mfa_setup:
            return True
        
        # Check role-based MFA requirements
        user_roles = await self._get_user_roles(user.id)
        return bool(any(role.require_mfa for role in user_roles))
    
    async def _create_mfa_session(
        self,
        user: User,
        command: LoginCommand,
        location: dict
    ) -> Session:
        """Create temporary session for MFA verification."""
        return await self._session_service.create_mfa_session(
            user_id=user.id,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            device_fingerprint=command.device_fingerprint,
            location=location
        )
    
    async def _create_authenticated_session(
        self,
        user: User,
        command: LoginCommand,
        location: dict,
        risk_assessment: RiskAssessmentResult
    ) -> Session:
        """Create authenticated user session."""
        context = SessionCreationContext(
            user_id=user.id,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            device_fingerprint=command.device_fingerprint,
            session_type=command.session_type,
            risk_score=risk_assessment.risk_score,
            mfa_verified=False,  # No MFA in this flow
            remember_me=command.remember_me,
            trusted_device=await self._is_trusted_device(user.id, command.device_fingerprint),
            location=location
        )
        
        return await self._session_service.create_session(context)
    
    async def _get_user_scopes(self, user: User) -> list[str]:
        """Get user's permission scopes for token."""
        # This would typically load from permission service
        return ["user:read", "user:write", "profile:read", "profile:write"]
    
    async def _get_user_roles(self, user_id: UUID) -> list[Any]:
        """Get user's roles."""
        # This would typically load from role repository
        return []
    
    async def _clear_failed_attempts(self, user_id: UUID, ip_address: str) -> None:
        """Clear failed login attempts after successful login."""
        await self._login_attempt_repository.clear_failed_attempts(
            user_id=user_id,
            ip_address=ip_address
        )
    
    async def _is_trusted_device(self, user_id: UUID, device_fingerprint: str | None) -> bool:
        """Check if device is trusted."""
        if not device_fingerprint:
            return False
        
        return await self._device_fingerprint_service.is_trusted(
            user_id=user_id,
            fingerprint=device_fingerprint
        )
    
    def _get_preferred_mfa_method(self, devices: list[Any]) -> MFAMethod | None:
        """Get user's preferred MFA method."""
        primary_devices = [d for d in devices if d.is_primary]
        if primary_devices:
            return primary_devices[0].method
        
        # Default preference order
        preference_order = [
            MFAMethod.AUTHENTICATOR_APP,
            MFAMethod.SMS,
            MFAMethod.EMAIL,
            MFAMethod.BACKUP_CODES
        ]
        
        for method in preference_order:
            if any(d.method == method for d in devices):
                return method
        
        return devices[0].method if devices else None