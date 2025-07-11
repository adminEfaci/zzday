"""
Resend verification command implementation.

Handles resending email verification links to users.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import ResendVerificationRequest
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import VerificationEmailResent
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    RateLimitExceededError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import SecurityService


@dataclass
class ResendVerificationServiceDependencies:
    """Service dependencies for resend verification handler."""
    user_repository: IUserRepository
    security_service: SecurityService
    email_service: IEmailService
    cache_service: ICacheService
    rate_limit_service: IRateLimitService


@dataclass
class ResendVerificationInfrastructureDependencies:
    """Infrastructure dependencies for resend verification handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class ResendVerificationCommand(Command[BaseResponse]):
    """Command to resend verification email."""
    
    def __init__(
        self,
        email: str,
        verification_type: str = 'email',
        ip_address: str | None = None,
        user_agent: str | None = None
    ):
        self.email = email
        self.verification_type = verification_type
        self.ip_address = ip_address
        self.user_agent = user_agent


class ResendVerificationCommandHandler(CommandHandler[ResendVerificationCommand, BaseResponse]):
    """Handler for resending verification emails."""
    
    MAX_RESEND_ATTEMPTS = 5
    RESEND_COOLDOWN_MINUTES = 5
    
    def __init__(
        self,
        services: ResendVerificationServiceDependencies,
        infrastructure: ResendVerificationInfrastructureDependencies
    ):
        # Service dependencies
        self._user_repository = services.user_repository
        self._security_service = services.security_service
        self._email_service = services.email_service
        self._cache_service = services.cache_service
        self._rate_limit_service = services.rate_limit_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.VERIFICATION_RESENT,
        resource_type="user",
        include_request=True
    )
    @validate_request(ResendVerificationRequest)
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='email'
    )
    async def handle(self, command: ResendVerificationCommand) -> BaseResponse:
        """
        Resend verification email.
        
        Process:
        1. Find user by email
        2. Check if already verified
        3. Check resend attempts and cooldown
        4. Generate new verification token
        5. Send verification email
        6. Update resend tracking
        7. Publish event
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidOperationError: If already verified
            RateLimitExceededError: If too many attempts
        """
        async with self._unit_of_work:
            # 1. Find user by email
            user = await self._user_repository.find_by_email(command.email)
            
            if not user:
                # Don't reveal if email exists
                return BaseResponse(
                    success=True,
                    message="If the email exists, a verification link has been sent"
                )
            
            # 2. Check verification status
            if command.verification_type == 'email' and user.email_verified:
                raise InvalidOperationError("Email is already verified")
            
            # 3. Check resend attempts
            await self._check_resend_limits(user.id, command)
            
            # 4. Generate new verification token
            token = await self._security_service.generate_verification_token(
                user_id=user.id,
                email=user.email,
                purpose='email_verification'
            )
            
            # 5. Store verification data
            verification_url = await self._store_verification_data(
                user=user,
                token=token
            )
            
            # 6. Send verification email
            await self._send_verification_email(
                user=user,
                verification_url=verification_url
            )
            
            # 7. Update resend tracking
            await self._update_resend_tracking(user.id)
            
            # 8. Log the resend attempt
            await self._log_resend_attempt(user, command)
            
            # 9. Publish event
            await self._event_bus.publish(
                VerificationEmailResent(
                    aggregate_id=user.id,
                    email=user.email,
                    verification_type=command.verification_type,
                    ip_address=command.ip_address
                )
            )
            
            # 10. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message="Verification email has been sent"
            )
    
    async def _check_resend_limits(
        self,
        user_id: UUID,
        command: ResendVerificationCommand
    ) -> None:
        """Check if resend is allowed based on limits."""
        # Get resend tracking data
        tracking_key = f"verification_resend:{user_id}"
        tracking_data = await self._cache_service.get(tracking_key)
        
        if tracking_data:
            # Check cooldown
            last_sent = datetime.fromisoformat(tracking_data['last_sent'])
            cooldown_end = last_sent + timedelta(minutes=self.RESEND_COOLDOWN_MINUTES)
            
            if datetime.now(UTC) < cooldown_end:
                remaining_minutes = int((cooldown_end - datetime.now(UTC)).total_seconds() / 60)
                raise RateLimitExceededError(
                    f"Please wait {remaining_minutes} minutes before requesting another verification email"
                )
            
            # Check total attempts
            if tracking_data['attempts'] >= self.MAX_RESEND_ATTEMPTS:
                raise RateLimitExceededError(
                    "Maximum verification attempts reached. Please contact support."
                )
        
        # Check IP-based rate limiting
        if command.ip_address:
            ip_key = f"verification_resend_ip:{command.ip_address}"
            ip_attempts = await self._rate_limit_service.get_attempts(ip_key)
            
            if ip_attempts > 10:  # Max 10 attempts per IP per hour
                raise RateLimitExceededError(
                    "Too many verification requests from this IP address"
                )
    
    async def _store_verification_data(
        self,
        user: User,
        token: str
    ) -> str:
        """Store verification token and generate URL."""
        # Store token in cache
        await self._cache_service.set(
            key=f"email_verification:{token}",
            value={
                'user_id': str(user.id),
                'email': user.email,
                'created_at': datetime.now(UTC).isoformat(),
                'attempts': 0
            },
            ttl=86400  # 24 hours
        )
        
        # Generate verification URL
        base_url = "https://app.example.com"
        return f"{base_url}/verify-email?token={token}"
        
    
    async def _send_verification_email(
        self,
        user: User,
        verification_url: str
    ) -> None:
        """Send verification email to user."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="email_verification_resend",
                subject="Verify your email address",
                variables={
                    "username": user.username,
                    "verification_url": verification_url,
                    "expires_in": "24 hours",
                    "support_email": "support@example.com"
                },
                priority="high"
            )
        )
    
    async def _update_resend_tracking(self, user_id: UUID) -> None:
        """Update resend attempt tracking."""
        tracking_key = f"verification_resend:{user_id}"
        tracking_data = await self._cache_service.get(tracking_key)
        
        if tracking_data:
            tracking_data['attempts'] += 1
            tracking_data['last_sent'] = datetime.now(UTC).isoformat()
        else:
            tracking_data = {
                'attempts': 1,
                'last_sent': datetime.now(UTC).isoformat(),
                'first_sent': datetime.now(UTC).isoformat()
            }
        
        # Store for 7 days
        await self._cache_service.set(
            key=tracking_key,
            value=tracking_data,
            ttl=604800
        )
    
    async def _log_resend_attempt(
        self,
        user: User,
        command: ResendVerificationCommand
    ) -> None:
        """Log the resend attempt for security monitoring."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="verification_email_resent",
            ip_address=command.ip_address,
            details={
                "verification_type": command.verification_type,
                "user_agent": command.user_agent,
                "email": user.email
            }
        )