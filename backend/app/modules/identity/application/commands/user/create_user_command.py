"""
Create user command implementation.

Handles new user creation with comprehensive validation and security.
"""

from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CommandHandlerDependencies,
    UserRegistrationParams,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import CreateUserRequest
from app.modules.identity.application.dtos.response import CreateUserResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import UserCreated
from app.modules.identity.domain.exceptions import (
    DuplicateEmailError,
    DuplicateUsernameError,
    InvalidEmailFormatError,
    UnauthorizedError,
    WeakPasswordError,
)
from app.modules.identity.domain.specifications import (
    UniqueEmailSpecification,
    UniqueUsernameSpecification,
    ValidEmailFormatSpecification,
)


class CreateUserCommand(Command[CreateUserResponse]):
    """Command to create a new user."""
    
    def __init__(self, params: UserRegistrationParams, **kwargs):
        self.params = params
        # Additional options not in base DTO
        self.roles = kwargs.get('roles', [])
        self.send_welcome_email = kwargs.get('send_welcome_email', True)
        self.require_email_verification = kwargs.get('require_email_verification', True)
        self.created_by = kwargs.get('created_by')
        self.ip_address = kwargs.get('ip_address')


class CreateUserCommandHandler(CommandHandler[CreateUserCommand, CreateUserResponse]):
    """Handler for creating new users."""
    
    def __init__(self, dependencies: CommandHandlerDependencies):
        self._user_repository = dependencies.repositories.user_repository
        self._password_service = getattr(dependencies.services, 'password_service', dependencies.services.encryption_service)
        self._authorization_service = dependencies.services.authorization_service
        self._security_service = dependencies.services.security_service
        self._email_service = dependencies.services.email_service
        self._notification_service = dependencies.services.notification_service
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.USER_CREATED,
        resource_type="user",
        include_request=True,
        include_response=True
    )
    @validate_request(CreateUserRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='ip'
    )
    @require_permission(
        "users.create",
        resource_type="system"
    )
    async def handle(self, command: CreateUserCommand) -> CreateUserResponse:
        """
        Create a new user with comprehensive validation.
        
        Process:
        1. Validate uniqueness (username, email)
        2. Validate email format
        3. Validate password strength
        4. Check authorization
        5. Create user entity
        6. Hash password
        7. Save to repository
        8. Send verification email
        9. Publish domain events
        
        Returns:
            CreateUserResponse with user details
            
        Raises:
            DuplicateUsernameError: If username exists
            DuplicateEmailError: If email exists
            InvalidEmailFormatError: If email format invalid
            WeakPasswordError: If password too weak
            UnauthorizedError: If lacks permission
        """
        async with self._unit_of_work:
            # 1. Validate uniqueness
            if not await UniqueUsernameSpecification(
                self._user_repository,
                command.username
            ).is_satisfied_by(None):
                raise DuplicateUsernameError(
                    f"Username '{command.username}' already exists"
                )
            
            if not await UniqueEmailSpecification(
                self._user_repository,
                command.email
            ).is_satisfied_by(None):
                raise DuplicateEmailError(
                    f"Email '{command.email}' already exists"
                )
            
            # 2. Validate email format
            if not ValidEmailFormatSpecification().is_satisfied_by(command.email):
                raise InvalidEmailFormatError(
                    f"Invalid email format: {command.email}"
                )
            
            # 3. Validate password strength
            password_result = await self._password_service.validate_password(
                command.password,
                username=command.username,
                email=command.email
            )
            
            if not password_result.is_valid:
                raise WeakPasswordError(
                    f"Password does not meet requirements: {', '.join(password_result.issues)}"
                )
            
            # 4. Check for suspicious patterns
            risk_assessment = await self._security_service.assess_registration_risk(
                email=command.email,
                username=command.username,
                ip_address=command.ip_address
            )
            
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                # Log security incident
                await self._security_service.log_security_incident(
                    SecurityIncidentContext(
                        incident_type=SecurityEventType.SUSPICIOUS_REGISTRATION,
                        severity=RiskLevel.HIGH,
                        ip_address=command.ip_address,
                        details={
                            "username": command.username,
                            "email": command.email,
                            "risk_factors": risk_assessment.risk_factors
                        }
                    )
                )
                
                raise UnauthorizedError(
                    "Registration blocked due to security concerns"
                )
            
            # 5. Create user entity
            user = User.create(
                username=command.username,
                email=command.email,
                password_hash="",  # Will be set below
                first_name=command.first_name,
                last_name=command.last_name,
                phone_number=command.phone_number,
                status=UserStatus.PENDING if command.require_email_verification else UserStatus.ACTIVE
            )
            
            # 6. Hash password
            password_hash = await self._password_service.hash_password(command.password)
            user.update_password_hash(password_hash)
            
            # 7. Save to repository
            await self._user_repository.add(user)
            
            # 8. Assign default roles if specified
            if command.roles:
                for _role_name in command.roles:
                    # This would typically involve role repository lookup
                    pass
            
            # 9. Send verification email if required
            if command.require_email_verification:
                verification_token = await self._generate_verification_token(user.id)
                
                await self._email_service.send_email(
                    EmailContext(
                        recipient=user.email,
                        template="email_verification",
                        subject="Verify your email address",
                        variables={
                            "username": user.username,
                            "verification_link": f"https://app.example.com/verify-email?token={verification_token}",
                            "expires_in": "24 hours"
                        }
                    )
                )
            
            # 10. Send welcome email if requested
            elif command.send_welcome_email:
                await self._email_service.send_email(
                    EmailContext(
                        recipient=user.email,
                        template="welcome",
                        subject="Welcome to our platform!",
                        variables={
                            "username": user.username,
                            "first_name": user.first_name or user.username
                        }
                    )
                )
            
            # 11. Publish domain event
            await self._event_bus.publish(
                UserCreated(
                    aggregate_id=user.id,
                    username=user.username,
                    email=user.email,
                    created_by=command.created_by,
                    require_verification=command.require_email_verification
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            # 13. Send notifications if high risk
            if risk_assessment.risk_level == RiskLevel.HIGH:
                await self._notification_service.notify_security_team(
                    "High-risk user registration",
                    {
                        "user_id": str(user.id),
                        "username": user.username,
                        "risk_factors": risk_assessment.risk_factors
                    }
                )
            
            return CreateUserResponse(
                user_id=user.id,
                username=user.username,
                email=user.email,
                email_verification_required=command.require_email_verification,
                email_verification_sent=command.require_email_verification,
                message="User created successfully"
            )
    
    async def _generate_verification_token(self, user_id: UUID) -> str:
        """Generate email verification token."""
        # This would typically use a token service
        import secrets
        return secrets.token_urlsafe(32)