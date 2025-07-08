"""
Authentication Service

High-level service orchestrating the entire authentication flow including MFA.
"""

import logging
from datetime import datetime, UTC, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.domain.interfaces.repositories.session.session_repository import ISessionRepository
from app.modules.identity.domain.interfaces.repositories.session.login_attempt_repository import ILoginAttemptRepository
from app.modules.identity.domain.interfaces.repositories.session.device_registration_repository import IDeviceRegistrationRepository
from app.modules.identity.domain.interfaces.services.authentication.password_service import IPasswordService
from app.modules.identity.domain.interfaces.services.authentication.token_generator import ITokenGenerator
from app.modules.identity.domain.interfaces.services.security.risk_assessment_service import IRiskAssessmentService
from app.modules.identity.domain.interfaces.services.security.geolocation_service import IGeolocationService
from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import IEventPublisherPort
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort
from app.modules.identity.application.services.mfa_orchestration_service import MFAOrchestrationService
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities.session.session import Session
from app.modules.identity.domain.entities.session.session_enums import SessionStatus, SessionType
from app.modules.identity.domain.entities.device.device_registration import DeviceRegistration
from app.modules.identity.domain.value_objects.ip_address import IpAddress
from app.modules.identity.domain.value_objects.user_agent import UserAgent
from app.modules.identity.domain.value_objects.device_fingerprint import DeviceFingerprint
from app.modules.identity.domain.value_objects.risk_assessment import RiskLevel
from app.modules.identity.domain.events import (
    UserLoggedIn,
    UserLoginFailed,
    SuspiciousLoginDetected,
    DeviceRegistered,
    SessionCreated
)
from app.modules.identity.domain.entities.admin.login_attempt import LoginAttempt, LoginAttemptStatus

logger = logging.getLogger(__name__)


class AuthenticationResult:
    """Result of authentication attempt."""
    
    def __init__(
        self,
        success: bool,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        requires_mfa: bool = False,
        mfa_challenge: dict[str, Any] | None = None,
        error: str | None = None
    ):
        self.success = success
        self.user_id = user_id
        self.session_id = session_id
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.requires_mfa = requires_mfa
        self.mfa_challenge = mfa_challenge
        self.error = error


class AuthenticationService:
    """Service for managing user authentication flow."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        login_attempt_repository: ILoginAttemptRepository,
        device_repository: IDeviceRegistrationRepository,
        password_service: IPasswordService,
        token_generator: ITokenGenerator,
        risk_assessment_service: IRiskAssessmentService,
        geolocation_service: IGeolocationService,
        event_publisher: IEventPublisherPort,
        cache_port: ICachePort,
        mfa_orchestration: MFAOrchestrationService
    ):
        """Initialize authentication service."""
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.login_attempt_repository = login_attempt_repository
        self.device_repository = device_repository
        self.password_service = password_service
        self.token_generator = token_generator
        self.risk_assessment = risk_assessment_service
        self.geolocation = geolocation_service
        self.event_publisher = event_publisher
        self.cache = cache_port
        self.mfa_orchestration = mfa_orchestration
        
        # Configuration
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.session_timeout_minutes = 60
    
    async def authenticate(
        self,
        email: str,
        password: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None = None,
        remember_me: bool = False
    ) -> AuthenticationResult:
        """Authenticate user with credentials.
        
        Args:
            email: User email
            password: User password
            ip_address: Client IP address
            user_agent: Client user agent
            device_fingerprint: Optional device fingerprint
            remember_me: Whether to create long-lived session
            
        Returns:
            Authentication result
        """
        try:
            # Check for rate limiting
            if await self._is_rate_limited(ip_address):
                return AuthenticationResult(
                    success=False,
                    error="Too many login attempts. Please try again later."
                )
            
            # Find user
            user = await self.user_repository.find_by_email(email.lower())
            if not user:
                await self._record_failed_attempt(email, ip_address, "user_not_found")
                return AuthenticationResult(
                    success=False,
                    error="Invalid credentials"
                )
            
            # Check if user is locked
            if user.is_locked:
                await self._record_failed_attempt(email, ip_address, "account_locked", user.id)
                return AuthenticationResult(
                    success=False,
                    error="Account is locked"
                )
            
            # Check if user is active
            if not user.is_active:
                await self._record_failed_attempt(email, ip_address, "account_inactive", user.id)
                return AuthenticationResult(
                    success=False,
                    error="Account is not active"
                )
            
            # Verify password
            is_valid_password = await self.password_service.verify_password(
                password,
                user.password_hash
            )
            
            if not is_valid_password:
                await self._handle_failed_password(user, ip_address)
                return AuthenticationResult(
                    success=False,
                    error="Invalid credentials"
                )
            
            # Password is valid - perform risk assessment
            risk_assessment = await self._assess_login_risk(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint
            )
            
            # Handle suspicious login
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                await self._handle_suspicious_login(user, ip_address, risk_assessment)
                return AuthenticationResult(
                    success=False,
                    error="Login blocked due to security concerns. Please check your email."
                )
            
            # Check if MFA is required
            requires_mfa = await self._requires_mfa(user, risk_assessment)
            
            # Create session
            session = await self._create_session(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                session_type=SessionType.WEB,
                requires_mfa=requires_mfa,
                remember_me=remember_me
            )
            
            # Handle device registration
            if device_fingerprint:
                await self._handle_device_registration(
                    user_id=user.id,
                    device_fingerprint=device_fingerprint,
                    user_agent=user_agent,
                    trusted=risk_assessment.risk_level == RiskLevel.LOW
                )
            
            # If MFA required, create challenge and return
            if requires_mfa:
                mfa_challenge = await self.mfa_orchestration.create_mfa_session(
                    user_id=user.id,
                    session=session
                )
                
                return AuthenticationResult(
                    success=True,
                    user_id=user.id,
                    session_id=session.id,
                    requires_mfa=True,
                    mfa_challenge=mfa_challenge
                )
            
            # No MFA required - complete authentication
            return await self._complete_authentication(user, session)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error="An error occurred during authentication"
            )
    
    async def complete_mfa_authentication(
        self,
        session_id: UUID,
        code: str,
        device_id: UUID | None = None
    ) -> AuthenticationResult:
        """Complete authentication after successful MFA verification.
        
        Args:
            session_id: Session ID
            code: MFA verification code
            device_id: Optional device ID
            
        Returns:
            Authentication result with tokens
        """
        try:
            # Get session
            session = await self.session_repository.find_by_id(session_id)
            if not session:
                return AuthenticationResult(
                    success=False,
                    error="Session not found"
                )
            
            # Verify session is pending MFA
            if session.status != SessionStatus.PENDING_MFA:
                return AuthenticationResult(
                    success=False,
                    error="Session is not pending MFA verification"
                )
            
            # Check session expiry
            if session.is_expired:
                return AuthenticationResult(
                    success=False,
                    error="Session has expired"
                )
            
            # Verify MFA code
            is_valid, metadata = await self.mfa_orchestration.verify_challenge(
                session_id=session_id,
                code=code,
                device_id=device_id
            )
            
            if not is_valid:
                error = metadata.get("error", "Invalid verification code")
                remaining = metadata.get("remaining_attempts", 0)
                
                if remaining == 0:
                    # Terminate session after too many attempts
                    session.terminate("Too many failed MFA attempts")
                    await self.session_repository.save(session)
                
                return AuthenticationResult(
                    success=False,
                    error=f"{error}. {remaining} attempts remaining." if remaining > 0 else error
                )
            
            # MFA verified - complete authentication
            await self.mfa_orchestration.complete_mfa_verification(
                session_id=session_id,
                user_id=session.user_id
            )
            
            # Get user
            user = await self.user_repository.find_by_id(session.user_id)
            if not user:
                return AuthenticationResult(
                    success=False,
                    error="User not found"
                )
            
            return await self._complete_authentication(user, session)
            
        except Exception as e:
            logger.error(f"MFA authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error="An error occurred during MFA verification"
            )
    
    async def create_mfa_challenge(
        self,
        user_id: UUID,
        session_id: UUID
    ) -> dict[str, Any]:
        """Create new MFA challenge for existing session.
        
        Args:
            user_id: User ID
            session_id: Session ID
            
        Returns:
            MFA challenge information
        """
        return await self.mfa_orchestration.send_challenge(
            user_id=user_id,
            session_id=session_id
        )
    
    async def handle_risk_based_auth(
        self,
        user: User,
        risk_assessment: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle risk-based authentication decisions.
        
        Args:
            user: User entity
            risk_assessment: Risk assessment result
            
        Returns:
            Authentication requirements based on risk
        """
        risk_level = risk_assessment.get("risk_level", RiskLevel.LOW)
        
        requirements = {
            "mfa_required": False,
            "additional_verification": False,
            "trusted_device_required": False,
            "email_verification": False
        }
        
        # Low risk - standard auth
        if risk_level == RiskLevel.LOW:
            # Only require MFA if user has it enabled
            requirements["mfa_required"] = user.mfa_enabled
        
        # Medium risk - require MFA
        elif risk_level == RiskLevel.MEDIUM:
            requirements["mfa_required"] = True
        
        # High risk - require MFA and additional checks
        elif risk_level == RiskLevel.HIGH:
            requirements["mfa_required"] = True
            requirements["trusted_device_required"] = True
            requirements["email_verification"] = True
        
        # Critical risk - block authentication
        elif risk_level == RiskLevel.CRITICAL:
            requirements["blocked"] = True
            requirements["reason"] = "High security risk detected"
        
        return requirements
    
    async def _requires_mfa(self, user: User, risk_assessment: dict[str, Any]) -> bool:
        """Check if MFA is required for authentication.
        
        Args:
            user: User entity
            risk_assessment: Risk assessment result
            
        Returns:
            True if MFA is required
        """
        # Always require if user has MFA enabled
        if user.mfa_enabled:
            return True
        
        # Check risk-based requirements
        risk_level = risk_assessment.get("risk_level", RiskLevel.LOW)
        if risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # Check if user has sensitive roles
        if await self._has_privileged_roles(user.id):
            return True
        
        return False
    
    async def _create_session(
        self,
        user: User,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None,
        session_type: SessionType,
        requires_mfa: bool,
        remember_me: bool
    ) -> Session:
        """Create new session for user.
        
        Args:
            user: User entity
            ip_address: Client IP
            user_agent: Client user agent
            device_fingerprint: Device fingerprint
            session_type: Type of session
            requires_mfa: Whether MFA is required
            remember_me: Whether to create long-lived session
            
        Returns:
            Created session
        """
        # Get geolocation
        location = await self.geolocation.get_location(ip_address)
        
        # Create session
        session = Session.create_new(
            user_id=user.id,
            session_type=session_type,
            ip_address=IpAddress(ip_address) if ip_address else None,
            user_agent=UserAgent(user_agent) if user_agent else None,
            device_fingerprint=DeviceFingerprint(device_fingerprint) if device_fingerprint else None,
            requires_mfa=requires_mfa
        )
        
        # Set geolocation if available
        if location:
            from app.modules.identity.domain.value_objects.geolocation import Geolocation
            session.geolocation = Geolocation(
                latitude=location.get("latitude"),
                longitude=location.get("longitude"),
                city=location.get("city"),
                country=location.get("country"),
                region=location.get("region")
            )
        
        # Set session status based on MFA requirement
        if requires_mfa:
            session.status = SessionStatus.PENDING_MFA
        else:
            session.status = SessionStatus.ACTIVE
        
        # Handle remember me
        if remember_me:
            session.metadata["remember_me"] = True
            # Extend session expiry to 30 days
            session.expires_at = datetime.now(UTC) + timedelta(days=30)
        
        # Save session
        await self.session_repository.save(session)
        
        # Publish event
        await self.event_publisher.publish(
            SessionCreated(
                aggregate_id=user.id,
                session_id=session.id,
                session_type=session_type,
                requires_mfa=requires_mfa
            )
        )
        
        return session
    
    async def _complete_authentication(
        self,
        user: User,
        session: Session
    ) -> AuthenticationResult:
        """Complete authentication and generate tokens.
        
        Args:
            user: User entity
            session: Active session
            
        Returns:
            Authentication result with tokens
        """
        # Generate tokens
        access_token = await self.token_generator.generate_access_token(
            user_id=user.id,
            session_id=session.id,
            scopes=await self._get_user_scopes(user.id)
        )
        
        refresh_token = await self.token_generator.generate_refresh_token(
            user_id=user.id,
            session_id=session.id
        )
        
        # Update session with tokens
        session.access_token = access_token
        session.refresh_token = refresh_token
        session.status = SessionStatus.ACTIVE
        await self.session_repository.save(session)
        
        # Update user last login
        user.last_login_at = datetime.now(UTC)
        user.last_login_ip = session.ip_address.value if session.ip_address else None
        await self.user_repository.save(user)
        
        # Record successful login
        await self._record_successful_login(user.id, session.ip_address.value if session.ip_address else None)
        
        # Publish event
        await self.event_publisher.publish(
            UserLoggedIn(
                aggregate_id=user.id,
                session_id=session.id,
                ip_address=session.ip_address.value if session.ip_address else None,
                user_agent=session.user_agent.value if session.user_agent else None,
                mfa_used=session.mfa_completed
            )
        )
        
        logger.info(f"User {user.id} successfully authenticated")
        
        return AuthenticationResult(
            success=True,
            user_id=user.id,
            session_id=session.id,
            access_token=access_token.value,
            refresh_token=refresh_token.value if refresh_token else None
        )
    
    async def _assess_login_risk(
        self,
        user: User,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None
    ) -> dict[str, Any]:
        """Assess risk level of login attempt.
        
        Args:
            user: User entity
            ip_address: Client IP
            user_agent: Client user agent
            device_fingerprint: Device fingerprint
            
        Returns:
            Risk assessment result
        """
        return await self.risk_assessment.assess_login(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            previous_ips=await self._get_recent_ips(user.id),
            failed_attempts=await self._get_failed_attempt_count(user.id)
        )
    
    async def _is_rate_limited(self, ip_address: str) -> bool:
        """Check if IP is rate limited.
        
        Args:
            ip_address: Client IP
            
        Returns:
            True if rate limited
        """
        key = f"login_attempts:{ip_address}"
        attempts = await self.cache.get(key)
        
        if attempts and int(attempts) >= 10:
            return True
        
        return False
    
    async def _record_failed_attempt(
        self,
        email: str,
        ip_address: str,
        reason: str,
        user_id: UUID | None = None
    ) -> None:
        """Record failed login attempt.
        
        Args:
            email: Email used
            ip_address: Client IP
            reason: Failure reason
            user_id: User ID if found
        """
        # Create login attempt record
        attempt = LoginAttempt.create(
            email=email,
            ip_address=IpAddress(ip_address),
            status=LoginAttemptStatus.FAILED,
            failure_reason=reason,
            user_id=user_id
        )
        
        await self.login_attempt_repository.save(attempt)
        
        # Update rate limit counter
        key = f"login_attempts:{ip_address}"
        await self.cache.increment(key, ttl=3600)  # 1 hour TTL
        
        # Publish event if user exists
        if user_id:
            await self.event_publisher.publish(
                UserLoginFailed(
                    aggregate_id=user_id,
                    ip_address=ip_address,
                    reason=reason
                )
            )
    
    async def _record_successful_login(
        self,
        user_id: UUID,
        ip_address: str
    ) -> None:
        """Record successful login.
        
        Args:
            user_id: User ID
            ip_address: Client IP
        """
        # Clear failed attempts
        await self.login_attempt_repository.clear_failed_attempts(user_id, ip_address)
        
        # Clear rate limit
        key = f"login_attempts:{ip_address}"
        await self.cache.delete(key)
    
    async def _handle_failed_password(
        self,
        user: User,
        ip_address: str
    ) -> None:
        """Handle failed password attempt.
        
        Args:
            user: User entity
            ip_address: Client IP
        """
        # Increment failed attempts
        user.failed_login_count += 1
        
        # Check if should lock account
        if user.failed_login_count >= self.max_failed_attempts:
            user.lock_account("Too many failed login attempts")
            await self.user_repository.save(user)
            
            logger.warning(f"Account locked for user {user.id} after {user.failed_login_count} failed attempts")
        else:
            await self.user_repository.save(user)
        
        await self._record_failed_attempt(
            user.email.value,
            ip_address,
            "invalid_password",
            user.id
        )
    
    async def _handle_suspicious_login(
        self,
        user: User,
        ip_address: str,
        risk_assessment: dict[str, Any]
    ) -> None:
        """Handle suspicious login attempt.
        
        Args:
            user: User entity
            ip_address: Client IP
            risk_assessment: Risk assessment result
        """
        # Record as suspicious
        await self._record_failed_attempt(
            user.email.value,
            ip_address,
            "suspicious_activity",
            user.id
        )
        
        # Publish event
        await self.event_publisher.publish(
            SuspiciousLoginDetected(
                aggregate_id=user.id,
                ip_address=ip_address,
                risk_level=risk_assessment.get("risk_level"),
                risk_factors=risk_assessment.get("risk_factors", [])
            )
        )
        
        logger.warning(f"Suspicious login detected for user {user.id} from {ip_address}")
    
    async def _handle_device_registration(
        self,
        user_id: UUID,
        device_fingerprint: str,
        user_agent: str,
        trusted: bool
    ) -> None:
        """Handle device registration or update.
        
        Args:
            user_id: User ID
            device_fingerprint: Device fingerprint
            user_agent: User agent
            trusted: Whether device should be trusted
        """
        # Check if device exists
        existing = await self.device_repository.find_by_fingerprint(user_id, device_fingerprint)
        
        if existing:
            # Update last seen
            await self.device_repository.update_last_seen(existing.id)
        else:
            # Register new device
            device = DeviceRegistration.create(
                user_id=user_id,
                device_fingerprint=device_fingerprint,
                user_agent=user_agent,
                trusted=trusted
            )
            
            await self.device_repository.save(device)
            
            # Publish event
            await self.event_publisher.publish(
                DeviceRegistered(
                    aggregate_id=user_id,
                    device_id=device.id,
                    device_fingerprint=device_fingerprint,
                    trusted=trusted
                )
            )
    
    async def _get_user_scopes(self, user_id: UUID) -> list[str]:
        """Get user permission scopes.
        
        Args:
            user_id: User ID
            
        Returns:
            List of permission scopes
        """
        # This would integrate with permission service
        return ["user:read", "user:write", "profile:read", "profile:write"]
    
    async def _has_privileged_roles(self, user_id: UUID) -> bool:
        """Check if user has privileged roles requiring MFA.
        
        Args:
            user_id: User ID
            
        Returns:
            True if user has privileged roles
        """
        # This would integrate with role service
        # For now, return False
        return False
    
    async def _get_recent_ips(self, user_id: UUID) -> list[str]:
        """Get recent IP addresses used by user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of recent IPs
        """
        recent_sessions = await self.session_repository.find_by_user(user_id, limit=10)
        ips = []
        
        for session in recent_sessions:
            if session.ip_address:
                ips.append(session.ip_address.value)
        
        return list(set(ips))  # Unique IPs
    
    async def _get_failed_attempt_count(self, user_id: UUID) -> int:
        """Get recent failed login attempt count.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of recent failed attempts
        """
        attempts = await self.login_attempt_repository.count_recent_failed(
            user_id=user_id,
            hours=24
        )
        return attempts