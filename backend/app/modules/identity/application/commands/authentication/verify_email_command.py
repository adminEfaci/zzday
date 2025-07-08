"""
Verify email command implementation.

Handles email verification token validation.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IEmailService,
    IEmailVerificationTokenRepository,
    INotificationService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import VerifyEmailRequest
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, TokenStatus, UserStatus
from app.modules.identity.domain.events import EmailVerified
from app.modules.identity.domain.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import EmailVerificationService


@dataclass
class VerifyEmailRepositoryDependencies:
    """Repository dependencies for verify email handler."""
    user_repository: IUserRepository
    email_verification_token_repository: IEmailVerificationTokenRepository


@dataclass
class VerifyEmailServiceDependencies:
    """Service dependencies for verify email handler."""
    email_verification_service: EmailVerificationService
    email_service: IEmailService
    notification_service: INotificationService
    cache_service: ICacheService


@dataclass
class VerifyEmailInfrastructureDependencies:
    """Infrastructure dependencies for verify email handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class VerifyEmailCommand(Command[BaseResponse]):
    """Command to verify email address."""
    
    def __init__(
        self,
        token: str,
        email: str | None = None,
        ip_address: str | None = None
    ):
        self.token = token
        self.email = email
        self.ip_address = ip_address


class VerifyEmailCommandHandler(CommandHandler[VerifyEmailCommand, BaseResponse]):
    """Handler for email verification."""
    
    def __init__(
        self,
        repositories: VerifyEmailRepositoryDependencies,
        services: VerifyEmailServiceDependencies,
        infrastructure: VerifyEmailInfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._token_repository = repositories.email_verification_token_repository
        
        # Service dependencies
        self._verification_service = services.email_verification_service
        self._email_service = services.email_service
        self._notification_service = services.notification_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.EMAIL_VERIFIED,
        resource_type="user",
        include_request=True
    )
    @validate_request(VerifyEmailRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='ip'
    )
    async def handle(self, command: VerifyEmailCommand) -> BaseResponse:
        """
        Verify email address using token.
        
        Process:
        1. Validate verification token
        2. Load user and check status
        3. Verify email matches if provided
        4. Update user status
        5. Mark token as used
        6. Send welcome email
        7. Publish event
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            InvalidTokenError: If token invalid
            TokenExpiredError: If token expired
            UserNotFoundError: If user not found
            InvalidOperationError: If already verified
        """
        async with self._unit_of_work:
            # 1. Validate token
            token_data = await self._verification_service.validate_token(command.token)
            
            if not token_data:
                raise InvalidTokenError("Invalid verification token")
            
            # 2. Check token status
            if token_data.status == TokenStatus.USED:
                raise InvalidTokenError("Verification token already used")
            
            if token_data.status == TokenStatus.EXPIRED:
                raise TokenExpiredError("Verification token has expired")
            
            if token_data.expires_at < datetime.now(UTC):
                # Mark as expired
                await self._verification_service.expire_token(command.token)
                raise TokenExpiredError("Verification token has expired")
            
            # 3. Load user
            user = await self._user_repository.get_by_id(token_data.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {token_data.user_id} not found")
            
            # 4. Verify email matches if provided
            if command.email:
                if command.email.lower() != token_data.email.lower():
                    raise InvalidTokenError("Email mismatch")
                
                if command.email.lower() != user.email.lower():
                    raise InvalidTokenError("Token does not match user email")
            
            # 5. Check if already verified
            if user.email_verified:
                # Already verified, but mark token as used
                await self._verification_service.mark_token_used(command.token)
                
                return BaseResponse(
                    success=True,
                    message="Email already verified"
                )
            
            # 6. Update user status
            user.verify_email()
            
            # Activate user if pending
            if user.status == UserStatus.PENDING:
                user.activate()
            
            await self._user_repository.update(user)
            
            # 7. Mark token as used
            await self._verification_service.mark_token_used(command.token)
            
            # 8. Clear any cached unverified status
            await self._cache_service.delete(f"user:{user.id}")
            await self._cache_service.delete(f"email_verification:{user.email}")
            
            # 9. Send welcome email
            await self._send_welcome_email(user)
            
            # 10. Check if this was a delayed verification
            account_age = datetime.now(UTC) - user.created_at
            is_delayed = account_age.days > 7
            
            # 11. Publish event
            await self._event_bus.publish(
                EmailVerified(
                    aggregate_id=user.id,
                    email=user.email,
                    verified_at=datetime.now(UTC),
                    delayed_verification=is_delayed,
                    ip_address=command.ip_address
                )
            )
            
            # 12. Notify admins if delayed verification
            if is_delayed:
                await self._notification_service.notify_admins(
                    "Delayed email verification",
                    {
                        "user_id": str(user.id),
                        "email": user.email,
                        "account_created": user.created_at.isoformat(),
                        "days_delayed": account_age.days
                    }
                )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message="Email verified successfully. Welcome!"
            )
    
    async def _send_welcome_email(self, user: User) -> None:
        """Send welcome email after verification."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="welcome_verified",
                subject="Welcome! Your email is verified",
                variables={
                    "username": user.username,
                    "first_name": user.first_name or user.username,
                    "login_url": "https://app.example.com/login",
                    "help_url": "https://app.example.com/help",
                    "features": [
                        "Complete your profile to unlock all features",
                        "Set up two-factor authentication for extra security",
                        "Explore our premium features"
                    ]
                }
            )
        )