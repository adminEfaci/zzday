"""
Register user command implementation.

Handles new user registration with email verification.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    InfrastructureDependencies,
    RegistrationConfig,
    ServiceDependencies,
    SessionContext,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    RiskAssessmentResult,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import RegisterUserRequest
from app.modules.identity.application.dtos.response import CreateUserResponse
from app.modules.identity.domain.entities import User, UserProfile
from app.modules.identity.domain.enums import (
    AuditAction,
    RegistrationSource,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import RegistrationBlocked, UserRegistered
from app.modules.identity.domain.exceptions import (
    DuplicateEmailError,
    DuplicateUsernameError,
    InvalidEmailFormatError,
    InvalidUsernameError,
    RegistrationBlockedError,
    TermsNotAcceptedError,
    WeakPasswordError,
)
from app.modules.identity.domain.specifications import (
    UniqueEmailSpecification,
    UniqueUsernameSpecification,
    ValidEmailFormatSpecification,
    ValidUsernameSpecification,
)


class RegisterUserCommand(Command[CreateUserResponse]):
    """Command to register a new user."""
    
    def __init__(
        self,
        registration_config: RegistrationConfig,
        session_context: SessionContext,
        additional_options: dict[str, Any] | None = None
    ):
        self.registration_config = registration_config
        self.session_context = session_context
        additional_options = additional_options or {}
        
        # For backward compatibility, expose common fields
        self.username = registration_config.username
        self.email = registration_config.email
        self.password = registration_config.password
        self.first_name = registration_config.first_name
        self.last_name = registration_config.last_name
        self.phone_number = registration_config.phone_number
        self.terms_accepted = additional_options.get('terms_accepted', False)
        self.marketing_consent = additional_options.get('marketing_consent', False)
        self.ip_address = session_context.ip_address
        self.user_agent = session_context.user_agent
        self.referral_code = additional_options.get('referral_code')
        self.registration_source = RegistrationSource(additional_options.get('registration_source', 'WEB'))


class RegisterUserCommandHandler(CommandHandler[RegisterUserCommand, CreateUserResponse]):
    """Handler for user registration."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._profile_repository = services.profile_repository
        self._password_service = services.password_service
        self._security_service = services.security_service
        self._risk_assessment_service = services.risk_assessment_service
        self._email_verification_service = services.email_verification_service
        self._email_service = services.email_service
        self._geolocation_service = services.geolocation_service
        self._registration_attempt_repository = services.registration_attempt_repository
        self._referral_service = services.referral_service
        self._cache_service = services.cache_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.USER_REGISTERED,
        resource_type="user",
        include_request=True,
        include_response=True
    )
    @validate_request(RegisterUserRequest)
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='ip'
    )
    async def handle(self, command: RegisterUserCommand) -> CreateUserResponse:
        """
        Register new user with comprehensive validation.
        
        Process:
        1. Validate terms acceptance
        2. Check registration attempts
        3. Validate uniqueness and format
        4. Assess registration risk
        5. Create user and profile
        6. Process referral
        7. Send verification email
        8. Publish events
        
        Returns:
            CreateUserResponse with user details
            
        Raises:
            TermsNotAcceptedError: If terms not accepted
            DuplicateUsernameError: If username exists
            DuplicateEmailError: If email exists
            RegistrationBlockedError: If blocked by security
        """
        async with self._unit_of_work:
            # 1. Validate terms acceptance
            if not command.terms_accepted:
                raise TermsNotAcceptedError("Terms of service must be accepted")
            
            # 2. Check recent registration attempts
            await self._check_registration_attempts(command.ip_address, command.email)
            
            # 3. Validate username format
            if not ValidUsernameSpecification().is_satisfied_by(command.username):
                raise InvalidUsernameError(
                    "Username must be 3-30 characters and contain only letters, numbers, dots, dashes and underscores"
                )
            
            # 4. Check username uniqueness
            if not await UniqueUsernameSpecification(
                self._user_repository,
                command.username.lower()
            ).is_satisfied_by(None):
                raise DuplicateUsernameError(f"Username '{command.username}' is already taken")
            
            # 5. Validate email format
            if not ValidEmailFormatSpecification().is_satisfied_by(command.email):
                raise InvalidEmailFormatError(f"Invalid email format: {command.email}")
            
            # 6. Check email uniqueness
            if not await UniqueEmailSpecification(
                self._user_repository,
                command.email.lower()
            ).is_satisfied_by(None):
                raise DuplicateEmailError(f"Email '{command.email}' is already registered")
            
            # 7. Validate password strength
            password_result = await self._password_service.validate_password(
                command.password,
                username=command.username,
                email=command.email,
                first_name=command.first_name,
                last_name=command.last_name
            )
            
            if not password_result.is_valid:
                raise WeakPasswordError(
                    f"Password does not meet requirements: {', '.join(password_result.issues)}"
                )
            
            # 8. Get location data
            location = None
            if command.ip_address:
                location = await self._geolocation_service.get_location(command.ip_address)
            
            # 9. Assess registration risk
            risk_assessment = await self._assess_registration_risk(
                command=command,
                location=location
            )
            
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                # Block registration
                await self._handle_blocked_registration(command, risk_assessment)
                raise RegistrationBlockedError(
                    "Registration blocked due to security concerns"
                )
            
            # 10. Create user entity
            user = User.create(
                username=command.username.lower(),
                email=command.email.lower(),
                password_hash="",  # Will be set below
                first_name=command.first_name,
                last_name=command.last_name,
                phone_number=command.phone_number,
                status=UserStatus.PENDING  # Pending email verification
            )
            
            # 11. Hash password
            password_hash = await self._password_service.hash_password(command.password)
            user.update_password_hash(password_hash)
            
            # 12. Set user metadata
            user.metadata = {
                "registration_ip": command.ip_address,
                "registration_source": command.registration_source.value,
                "marketing_consent": command.marketing_consent,
                "terms_accepted_at": datetime.now(UTC).isoformat(),
                "risk_score": risk_assessment.risk_score
            }
            
            # 13. Save user
            await self._user_repository.add(user)
            
            # 14. Create user profile
            profile = UserProfile.create(
                user_id=user.id,
                language="en",
                timezone="UTC"
            )
            await self._profile_repository.add(profile)
            
            # 15. Process referral if provided
            referrer_id = None
            if command.referral_code:
                referrer_id = await self._process_referral(
                    referral_code=command.referral_code,
                    new_user_id=user.id
                )
            
            # 16. Generate verification token
            verification_token = await self._email_verification_service.create_verification_token(
                user_id=user.id,
                email=user.email
            )
            
            # 17. Send verification email
            await self._send_verification_email(
                user=user,
                verification_token=verification_token
            )
            
            # 18. Log registration attempt
            await self._registration_attempt_repository.add(
                email=command.email,
                username=command.username,
                ip_address=command.ip_address,
                successful=True,
                user_id=user.id
            )
            
            # 19. Publish registration event
            await self._event_bus.publish(
                UserRegistered(
                    aggregate_id=user.id,
                    username=user.username,
                    email=user.email,
                    registration_source=command.registration_source,
                    referrer_id=referrer_id,
                    risk_level=risk_assessment.risk_level,
                    marketing_consent=command.marketing_consent
                )
            )
            
            # 20. Send high-risk notification
            if risk_assessment.risk_level == RiskLevel.HIGH:
                await self._security_service.notify_high_risk_registration(
                    user_id=user.id,
                    risk_factors=risk_assessment.risk_factors
                )
            
            # 21. Commit transaction
            await self._unit_of_work.commit()
            
            return CreateUserResponse(
                user_id=user.id,
                username=user.username,
                email=user.email,
                email_verification_required=True,
                email_verification_sent=True,
                message="Registration successful. Please check your email to verify your account.",
                success=True
            )
    
    async def _check_registration_attempts(
        self,
        ip_address: str | None,
        email: str
    ) -> None:
        """Check recent registration attempts."""
        if ip_address:
            # Check IP-based attempts
            ip_attempts = await self._registration_attempt_repository.count_recent_by_ip(
                ip_address=ip_address,
                minutes=60
            )
            
            if ip_attempts >= 5:
                raise RegistrationBlockedError(
                    "Too many registration attempts from this IP. Please try again later."
                )
        
        # Check email-based attempts
        email_attempts = await self._registration_attempt_repository.count_recent_by_email(
            email=email,
            minutes=1440  # 24 hours
        )
        
        if email_attempts >= 3:
            raise RegistrationBlockedError(
                "Too many registration attempts for this email. Please try again later."
            )
    
    async def _assess_registration_risk(
        self,
        command: RegisterUserCommand,
        location: dict | None
    ) -> RiskAssessmentResult:
        """Assess risk of registration."""
        return await self._risk_assessment_service.assess_registration(
            email=command.email,
            username=command.username,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            location=location,
            phone_number=command.phone_number
        )
    
    async def _handle_blocked_registration(
        self,
        command: RegisterUserCommand,
        risk_assessment: RiskAssessmentResult
    ) -> None:
        """Handle blocked registration attempt."""
        # Log security incident
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.SUSPICIOUS_REGISTRATION,
                severity=RiskLevel.HIGH,
                ip_address=command.ip_address,
                details={
                    "email": command.email,
                    "username": command.username,
                    "risk_factors": risk_assessment.risk_factors,
                    "risk_score": risk_assessment.risk_score
                }
            )
        )
        
        # Log failed attempt
        await self._registration_attempt_repository.add(
            email=command.email,
            username=command.username,
            ip_address=command.ip_address,
            successful=False,
            failure_reason="blocked_by_security"
        )
        
        # Publish event
        await self._event_bus.publish(
            RegistrationBlocked(
                email=command.email,
                username=command.username,
                ip_address=command.ip_address,
                risk_level=risk_assessment.risk_level,
                risk_factors=risk_assessment.risk_factors
            )
        )
    
    async def _process_referral(
        self,
        referral_code: str,
        new_user_id: UUID
    ) -> UUID | None:
        """Process referral code and return referrer ID."""
        try:
            return await self._referral_service.process_referral(
                code=referral_code,
                new_user_id=new_user_id
            )
        except Exception:
            # Don't fail registration if referral processing fails
            return None
    
    async def _send_verification_email(
        self,
        user: User,
        verification_token: str
    ) -> None:
        """Send email verification link."""
        verification_url = f"https://app.example.com/verify-email?token={verification_token}"
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="email_verification",
                subject="Verify your email address",
                variables={
                    "username": user.username,
                    "first_name": user.first_name,
                    "verification_link": verification_url,
                    "expires_in": "24 hours",
                    "support_email": "support@example.com"
                },
                priority="high"
            )
        )