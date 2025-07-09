"""
Forgot password command implementation.

Handles password reset request initiation.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.services.security.geolocation_service import IGeolocationService
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    RiskAssessmentResult,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import ForgotPasswordRequest
from app.modules.identity.application.dtos.response import PasswordResetResponse
from app.modules.identity.domain.entities import PasswordResetToken, User
from app.modules.identity.domain.enums import (
    AuditAction,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import PasswordResetRequested
from app.modules.identity.domain.exceptions import (
    RateLimitExceededError,
)
from app.modules.identity.domain.services import RiskAssessmentService, SecurityService


class ForgotPasswordCommand(Command[PasswordResetResponse]):
    """Command to initiate password reset."""
    
    def __init__(
        self,
        email: str,
        ip_address: str,
        user_agent: str | None = None,
        locale: str = "en"
    ):
        self.email = email
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.locale = locale


class ForgotPasswordCommandHandler(CommandHandler[ForgotPasswordCommand, PasswordResetResponse]):
    """Handler for password reset requests."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        password_reset_token_repository: IPasswordResetTokenRepository,
        security_service: SecurityService,
        risk_assessment_service: RiskAssessmentService,
        email_service: IEmailService,
        geolocation_service: IGeolocationService,
        password_reset_attempt_repository: IPasswordResetAttemptRepository,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._token_repository = password_reset_token_repository
        self._security_service = security_service
        self._risk_assessment_service = risk_assessment_service
        self._email_service = email_service
        self._geolocation_service = geolocation_service
        self._attempt_repository = password_reset_attempt_repository
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_RESET_REQUESTED,
        resource_type="user",
        include_request=True
    )
    @validate_request(ForgotPasswordRequest)
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='ip'
    )
    async def handle(self, command: ForgotPasswordCommand) -> PasswordResetResponse:
        """
        Initiate password reset process.
        
        Process:
        1. Check rate limits
        2. Find user by email (fail silently if not found)
        3. Assess request risk
        4. Invalidate existing tokens
        5. Generate new reset token
        6. Send reset email
        7. Log attempt
        8. Publish event
        
        Returns:
            PasswordResetResponse (always success for security)
            
        Note:
            Always returns success to prevent email enumeration
        """
        async with self._unit_of_work:
            # 1. Check recent attempts from this IP
            await self._check_reset_attempts(command.ip_address, command.email)
            
            # 2. Find user by email
            user = await self._user_repository.find_by_email(command.email.lower())
            
            # Always proceed to prevent email enumeration
            if not user:
                # Log attempt for non-existent email
                await self._log_attempt(
                    email=command.email,
                    ip_address=command.ip_address,
                    successful=False,
                    reason="email_not_found"
                )
                
                # Return success to prevent enumeration
                return PasswordResetResponse(
                    reset_requested=True,
                    email_sent=True,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    success=True,
                    message="If the email exists, a reset link has been sent."
                )
            
            # 3. Check if user can reset password
            if user.status in [UserStatus.DELETED, UserStatus.BANNED]:
                # Log but don't reveal account status
                await self._log_attempt(
                    email=command.email,
                    ip_address=command.ip_address,
                    successful=False,
                    reason=f"account_{user.status.value}",
                    user_id=user.id
                )
                
                return PasswordResetResponse(
                    reset_requested=True,
                    email_sent=False,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    success=True,
                    message="If the email exists, a reset link has been sent."
                )
            
            # 4. Get location for risk assessment
            location = await self._geolocation_service.get_location(command.ip_address)
            
            # 5. Assess request risk
            risk_assessment = await self._assess_reset_risk(
                user=user,
                ip_address=command.ip_address,
                location=location
            )
            
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                # Block suspicious request
                await self._handle_suspicious_reset(user, command, risk_assessment)
                
                # Still return success to prevent enumeration
                return PasswordResetResponse(
                    reset_requested=True,
                    email_sent=False,
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    success=True,
                    message="If the email exists, a reset link has been sent."
                )
            
            # 6. Invalidate existing active tokens
            await self._invalidate_existing_tokens(user.id)
            
            # 7. Generate new reset token
            token = PasswordResetToken.create(
                user_id=user.id,
                token=self._generate_secure_token(),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                ip_address=command.ip_address
            )
            
            await self._token_repository.add(token)
            
            # 8. Send reset email
            await self._send_reset_email(
                user=user,
                token=token.token,
                locale=command.locale,
                high_risk=risk_assessment.risk_level == RiskLevel.HIGH
            )
            
            # 9. Log successful attempt
            await self._log_attempt(
                email=command.email,
                ip_address=command.ip_address,
                successful=True,
                user_id=user.id
            )
            
            # 10. Publish event
            await self._event_bus.publish(
                PasswordResetRequested(
                    aggregate_id=user.id,
                    email=user.email,
                    ip_address=command.ip_address,
                    risk_level=risk_assessment.risk_level,
                    token_id=token.id
                )
            )
            
            # 11. Notify if high risk
            if risk_assessment.risk_level == RiskLevel.HIGH:
                await self._security_service.notify_high_risk_password_reset(
                    user=user,
                    ip_address=command.ip_address,
                    location=location
                )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            return PasswordResetResponse(
                reset_requested=True,
                email_sent=True,
                expires_at=token.expires_at,
                success=True,
                message="If the email exists, a reset link has been sent."
            )
    
    async def _check_reset_attempts(self, ip_address: str, email: str) -> None:
        """Check rate limits for reset attempts."""
        # Check IP-based attempts
        ip_attempts = await self._attempt_repository.count_recent_by_ip(
            ip_address=ip_address,
            minutes=60
        )
        
        if ip_attempts >= 10:
            raise RateLimitExceededError(
                "Too many password reset attempts. Please try again later."
            )
        
        # Check email-based attempts
        email_attempts = await self._attempt_repository.count_recent_by_email(
            email=email,
            minutes=60
        )
        
        if email_attempts >= 3:
            raise RateLimitExceededError(
                "Too many password reset attempts for this email. Please try again later."
            )
    
    async def _assess_reset_risk(
        self,
        user: User,
        ip_address: str,
        location: dict
    ) -> RiskAssessmentResult:
        """Assess risk of password reset request."""
        risk_factors = []
        risk_score = 0.0
        
        # Check if IP is different from usual
        last_ips = await self._get_user_recent_ips(user.id)
        if last_ips and ip_address not in last_ips:
            risk_factors.append("new_ip_address")
            risk_score += 0.3
        
        # Check location
        if location:
            usual_country = user.metadata.get("usual_country")
            if usual_country and location.get("country_code") != usual_country:
                risk_factors.append("different_country")
                risk_score += 0.4
        
        # Check frequency of reset requests
        recent_resets = await self._attempt_repository.count_recent_by_user(
            user_id=user.id,
            minutes=1440  # 24 hours
        )
        
        if recent_resets > 2:
            risk_factors.append("frequent_reset_attempts")
            risk_score += 0.3
        
        # Check account age
        account_age = datetime.now(UTC) - user.created_at
        if account_age.days < 7:
            risk_factors.append("new_account")
            risk_score += 0.2
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return RiskAssessmentResult(
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors
        )
    
    async def _invalidate_existing_tokens(self, user_id: UUID) -> None:
        """Invalidate any existing active reset tokens."""
        active_tokens = await self._token_repository.get_active_by_user(user_id)
        
        for token in active_tokens:
            token.invalidate()
            await self._token_repository.update(token)
    
    def _generate_secure_token(self) -> str:
        """Generate cryptographically secure reset token."""
        import secrets
        return secrets.token_urlsafe(32)
    
    async def _send_reset_email(
        self,
        user: User,
        token: str,
        locale: str,
        high_risk: bool
    ) -> None:
        """Send password reset email."""
        reset_url = f"https://app.example.com/reset-password?token={token}"
        
        template = "password_reset_high_risk" if high_risk else "password_reset"
        
        variables = {
            "username": user.username,
            "reset_link": reset_url,
            "expires_in": "1 hour",
            "support_email": "support@example.com",
            "locale": locale
        }
        
        if high_risk:
            variables["warning"] = "This request was flagged as potentially suspicious. If you didn't request this, please secure your account immediately."
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template=template,
                subject="Password Reset Request",
                variables=variables,
                priority="high"
            )
        )
    
    async def _log_attempt(
        self,
        email: str,
        ip_address: str,
        successful: bool,
        reason: str | None = None,
        user_id: UUID | None = None
    ) -> None:
        """Log password reset attempt."""
        await self._attempt_repository.add(
            email=email,
            ip_address=ip_address,
            user_id=user_id,
            successful=successful,
            failure_reason=reason
        )
    
    async def _handle_suspicious_reset(
        self,
        user: User,
        command: ForgotPasswordCommand,
        risk_assessment: RiskAssessmentResult
    ) -> None:
        """Handle suspicious password reset request."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_PASSWORD_RESET,
                severity=RiskLevel.HIGH,
                user_id=user.id,
                ip_address=command.ip_address,
                details={
                    "risk_factors": risk_assessment.risk_factors,
                    "risk_score": risk_assessment.risk_score
                }
            )
        )
    
    async def _get_user_recent_ips(self, user_id: UUID) -> list[str]:
        """Get user's recent IP addresses."""
        # This would typically query login history
        return []