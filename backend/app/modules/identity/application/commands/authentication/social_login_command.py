"""
Social login command implementation.

Handles authentication via social providers (Google, Facebook, etc).
"""

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    AuthenticationConfig,
    InfrastructureDependencies,
    ServiceDependencies,
    SessionContext,
    SocialAuthConfig,
)
from app.modules.identity.application.dtos.internal import EmailContext, SocialUserInfo
from app.modules.identity.application.dtos.request import SocialLoginRequest
from app.modules.identity.application.dtos.response import AuthenticationResponse
from app.modules.identity.domain.entities import Session, SocialAccount, User
from app.modules.identity.domain.enums import (
    AuditAction,
    AuthProvider,
    SessionType,
    UserStatus,
)
from app.modules.identity.domain.events import (
    SocialAccountLinked,
    UserLoggedIn,
    UserRegistered,
)
from app.modules.identity.domain.exceptions import (
    AccountLockedException,
    ExternalServiceError,
    InvalidCredentialsError,
    InvalidOperationError,
)


class SocialLoginCommand(Command[AuthenticationResponse]):
    """Command for social authentication."""
    
    def __init__(
        self,
        social_config: SocialAuthConfig,
        session_context: SessionContext,
        auth_config: AuthenticationConfig
    ):
        self.social_config = social_config
        self.session_context = session_context
        self.auth_config = auth_config
        
        # For backward compatibility, expose common fields
        self.provider = AuthProvider(social_config.provider)
        self.code = social_config.access_token  # Using access_token as code
        self.state = social_config.metadata.get('state')
        self.redirect_uri = social_config.metadata.get('redirect_uri')
        self.ip_address = session_context.ip_address
        self.user_agent = session_context.user_agent
        self.device_fingerprint = session_context.device_fingerprint
        self.remember_me = auth_config.remember_me


class SocialLoginCommandHandler(CommandHandler[SocialLoginCommand, AuthenticationResponse]):
    """Handler for social authentication."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._social_account_repository = services.social_account_repository
        self._session_repository = services.session_repository
        self._session_service = services.session_service
        self._security_service = services.security_service
        self._risk_assessment_service = services.risk_assessment_service
        self._social_auth_service = services.social_auth_service
        self._geolocation_service = services.geolocation_service
        self._email_service = services.email_service
        self._cache_service = services.cache_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.SOCIAL_LOGIN,
        resource_type="user",
        include_request=True
    )
    @validate_request(SocialLoginRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=300,
        strategy='ip'
    )
    async def handle(self, command: SocialLoginCommand) -> AuthenticationResponse:
        """
        Handle social authentication.
        
        Process:
        1. Exchange code for token
        2. Get user info from provider
        3. Find or create user account
        4. Link social account
        5. Check account status
        6. Assess security risk
        7. Create session
        8. Send notifications
        9. Publish events
        
        Returns:
            AuthenticationResponse with tokens
            
        Raises:
            ExternalServiceError: If provider fails
            AccountLockedException: If account locked
        """
        async with self._unit_of_work:
            # 1. Validate state token if provided
            if command.state:
                await self._validate_state_token(command.state)
            
            # 2. Exchange authorization code for access token
            try:
                provider_tokens = await self._social_auth_service.exchange_code(
                    provider=command.provider,
                    code=command.code,
                    redirect_uri=command.redirect_uri
                )
            except Exception as e:
                raise ExternalServiceError(
                    f"Failed to authenticate with {command.provider.value}: {e!s}"
                ) from e
            
            # 3. Get user info from provider
            social_user_info = await self._get_social_user_info(
                provider=command.provider,
                access_token=provider_tokens['access_token']
            )
            
            # 4. Find or create user
            user, is_new = await self._find_or_create_user(
                social_user_info=social_user_info,
                provider=command.provider
            )
            
            # 5. Link or update social account
            social_account = await self._link_social_account(
                user=user,
                provider=command.provider,
                social_user_info=social_user_info,
                provider_tokens=provider_tokens
            )
            
            # 6. Check account status
            if user.status == UserStatus.SUSPENDED:
                raise AccountLockedException("Account is suspended")
            
            if user.status == UserStatus.DEACTIVATED:
                raise InvalidOperationError("Account is deactivated")
            
            # 7. Get location info
            location = None
            if command.ip_address:
                with contextlib.suppress(Exception):
                    location = await self._geolocation_service.get_location(
                        command.ip_address
                    )
            
            # 8. Assess login risk
            await self._assess_social_login_risk(
                user=user,
                social_account=social_account,
                command=command,
                location=location
            )
            
            # 9. Create session
            session = await self._create_session(
                user=user,
                command=command,
                location=location,
                social_provider=command.provider
            )
            
            # 10. Generate tokens
            access_token = await self._security_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                permissions=await self._get_user_permissions(user.id)
            )
            
            refresh_token = await self._security_service.generate_refresh_token(
                user_id=user.id,
                session_id=session.id
            )
            
            # 11. Send notifications
            if is_new:
                await self._send_welcome_email(user, command.provider)
            else:
                await self._send_login_notification(
                    user=user,
                    provider=command.provider,
                    location=location
                )
            
            # 12. Publish events
            if is_new:
                await self._event_bus.publish(
                    UserRegistered(
                        aggregate_id=user.id,
                        username=user.username,
                        email=user.email,
                        registration_method=f"social_{command.provider.value}"
                    )
                )
            
            await self._event_bus.publish(
                UserLoggedIn(
                    aggregate_id=user.id,
                    session_id=session.id,
                    ip_address=command.ip_address,
                    user_agent=command.user_agent,
                    login_method=f"social_{command.provider.value}"
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return AuthenticationResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                expires_in=3600,
                user_id=user.id,
                username=user.username,
                email=user.email,
                is_new_user=is_new,
                requires_profile_completion=is_new and not user.full_name,
                success=True,
                message="Login successful"
            )
    
    async def _validate_state_token(self, state: str) -> None:
        """Validate CSRF state token."""
        state_data = await self._cache_service.get(f"oauth_state:{state}")
        
        if not state_data:
            raise InvalidCredentialsError("Invalid or expired state token")
        
        # Delete state to prevent replay
        await self._cache_service.delete(f"oauth_state:{state}")
    
    async def _get_social_user_info(
        self,
        provider: AuthProvider,
        access_token: str
    ) -> SocialUserInfo:
        """Get user information from social provider."""
        user_info = await self._social_auth_service.get_user_info(
            provider=provider,
            access_token=access_token
        )
        
        return SocialUserInfo(
            provider_id=user_info['id'],
            email=user_info.get('email'),
            email_verified=user_info.get('email_verified', False),
            name=user_info.get('name'),
            first_name=user_info.get('first_name'),
            last_name=user_info.get('last_name'),
            picture=user_info.get('picture'),
            locale=user_info.get('locale'),
            raw_data=user_info
        )
    
    async def _find_or_create_user(
        self,
        social_user_info: SocialUserInfo,
        provider: AuthProvider
    ) -> tuple[User, bool]:
        """Find existing user or create new one."""
        # First, check if social account exists
        social_account = await self._social_account_repository.get_by_provider_id(
            provider=provider,
            provider_user_id=social_user_info.provider_id
        )
        
        if social_account:
            # User exists
            user = await self._user_repository.get_by_id(social_account.user_id)
            return user, False
        
        # Check if user exists with same email
        if social_user_info.email:
            user = await self._user_repository.get_by_email(social_user_info.email)
            
            if user:
                # Link existing user
                return user, False
        
        # Create new user
        user = await self._create_user_from_social(social_user_info, provider)
        return user, True
    
    async def _create_user_from_social(
        self,
        social_user_info: SocialUserInfo,
        provider: AuthProvider
    ) -> User:
        """Create new user from social info."""
        # Generate username
        username = await self._generate_username(social_user_info)
        
        # Create user
        user = User(
            id=UUID(),
            username=username,
            email=social_user_info.email,
            email_verified=social_user_info.email_verified,
            full_name=social_user_info.name,
            first_name=social_user_info.first_name,
            last_name=social_user_info.last_name,
            avatar_url=social_user_info.picture,
            status=UserStatus.ACTIVE,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        # No password for social-only users
        user.password_hash = None
        user.requires_password_change = False
        
        await self._user_repository.add(user)
        
        return user
    
    async def _generate_username(self, social_user_info: SocialUserInfo) -> str:
        """Generate unique username from social info."""
        base_username = None
        
        # Try email prefix
        if social_user_info.email:
            base_username = social_user_info.email.split('@')[0]
        # Try first name
        elif social_user_info.first_name:
            base_username = social_user_info.first_name.lower()
        # Try full name
        elif social_user_info.name:
            base_username = social_user_info.name.replace(' ', '').lower()
        else:
            base_username = "user"
        
        # Ensure uniqueness
        username = base_username
        counter = 1
        
        while await self._user_repository.exists_by_username(username):
            username = f"{base_username}{counter}"
            counter += 1
        
        return username
    
    async def _link_social_account(
        self,
        user: User,
        provider: AuthProvider,
        social_user_info: SocialUserInfo,
        provider_tokens: dict[str, Any]
    ) -> SocialAccount:
        """Link or update social account."""
        social_account = await self._social_account_repository.get_by_user_and_provider(
            user_id=user.id,
            provider=provider
        )
        
        if social_account:
            # Update existing
            social_account.provider_user_id = social_user_info.provider_id
            social_account.provider_email = social_user_info.email
            social_account.provider_data = social_user_info.raw_data
            social_account.access_token = provider_tokens['access_token']
            social_account.refresh_token = provider_tokens.get('refresh_token')
            social_account.token_expires_at = datetime.now(UTC) + timedelta(
                seconds=provider_tokens.get('expires_in', 3600)
            )
            social_account.updated_at = datetime.now(UTC)
            
            await self._social_account_repository.update(social_account)
        else:
            # Create new
            social_account = SocialAccount(
                id=UUID(),
                user_id=user.id,
                provider=provider,
                provider_user_id=social_user_info.provider_id,
                provider_email=social_user_info.email,
                provider_data=social_user_info.raw_data,
                access_token=provider_tokens['access_token'],
                refresh_token=provider_tokens.get('refresh_token'),
                token_expires_at=datetime.now(UTC) + timedelta(
                    seconds=provider_tokens.get('expires_in', 3600)
                ),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            
            await self._social_account_repository.add(social_account)
            
            # Publish event
            await self._event_bus.publish(
                SocialAccountLinked(
                    aggregate_id=user.id,
                    provider=provider,
                    provider_user_id=social_user_info.provider_id
                )
            )
        
        return social_account
    
    async def _assess_social_login_risk(
        self,
        user: User,
        social_account: SocialAccount,
        command: SocialLoginCommand,
        location: dict | None
    ) -> dict:
        """Assess risk of social login."""
        risk_factors = []
        
        # New device
        if command.device_fingerprint:
            is_known = await self._security_service.is_known_device(
                user_id=user.id,
                device_fingerprint=command.device_fingerprint
            )
            if not is_known:
                risk_factors.append("new_device")
        
        # New location
        if location:
            is_known_location = await self._security_service.is_known_location(
                user_id=user.id,
                location=location
            )
            if not is_known_location:
                risk_factors.append("new_location")
        
        # Recently linked account
        if social_account.created_at > datetime.now(UTC) - timedelta(days=1):
            risk_factors.append("recently_linked")
        
        return {
            'risk_factors': risk_factors,
            'risk_level': 'high' if len(risk_factors) > 1 else 'low'
        }
    
    async def _create_session(
        self,
        user: User,
        command: SocialLoginCommand,
        location: dict | None,
        social_provider: AuthProvider
    ) -> Session:
        """Create new session for social login."""
        session_duration = timedelta(days=30 if command.remember_me else 1)
        
        session = Session(
            id=UUID(),
            user_id=user.id,
            session_type=SessionType.WEB,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            device_fingerprint=command.device_fingerprint,
            location=location,
            expires_at=datetime.now(UTC) + session_duration,
            created_at=datetime.now(UTC),
            last_activity_at=datetime.now(UTC),
            metadata={
                'login_method': f'social_{social_provider.value}',
                'provider': social_provider.value
            }
        )
        
        await self._session_repository.add(session)
        
        return session
    
    async def _get_user_permissions(self, user_id: UUID) -> list[str]:
        """Get user permissions for token."""
        # This would fetch from permission service
        return ["user.read", "user.write"]
    
    async def _send_welcome_email(self, user: User, provider: AuthProvider) -> None:
        """Send welcome email to new user."""
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="social_signup_welcome",
                subject=f"Welcome! You've signed up with {provider.value}",
                variables={
                    "username": user.username,
                    "provider": provider.value.title(),
                    "profile_url": "https://app.example.com/profile",
                    "help_url": "https://app.example.com/help"
                },
                priority="normal"
            )
        )
    
    async def _send_login_notification(
        self,
        user: User,
        provider: AuthProvider,
        location: dict | None
    ) -> None:
        """Send login notification for existing user."""
        location_text = "Unknown location"
        if location:
            location_text = f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="social_login_notification",
                subject=f"New login with {provider.value}",
                variables={
                    "username": user.username,
                    "provider": provider.value.title(),
                    "location": location_text,
                    "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                    "security_url": "https://app.example.com/security"
                },
                priority="normal"
            )
        )