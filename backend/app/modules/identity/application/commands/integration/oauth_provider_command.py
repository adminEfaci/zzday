"""
OAuth provider command implementation.

Handles OAuth 2.0 and OpenID Connect provider integrations.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    OAuthContext,
    SessionContext,
)
from app.modules.identity.application.dtos.request import OAuthProviderRequest
from app.modules.identity.application.dtos.response import OAuthProviderResponse
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    OAuthGrantType,
    OAuthResponseType,
    RiskLevel,
    SecurityEventType,
    SessionType,
)
from app.modules.identity.domain.events import (
    OAuthAuthenticated,
)
from app.modules.identity.domain.exceptions import (
    InvalidOAuthCodeError,
    OAuthAuthenticationError,
    OAuthConfigurationError,
    OAuthTokenError,
    OAuthValidationError,
    UserProvisioningError,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
    SecurityService,
    SessionService,
    UserService,
    ValidationService,
)


class OAuthProviderCommand(Command[OAuthProviderResponse]):
    """Command to handle OAuth provider authentication and operations."""
    
    def __init__(
        self,
        operation_type: str,  # "authenticate", "configure", "refresh_token", "revoke_token"
        oauth_provider_id: UUID,
        authorization_code: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        id_token: str | None = None,
        state: str | None = None,
        nonce: str | None = None,
        redirect_uri: str | None = None,
        scopes: list[str] | None = None,
        code_verifier: str | None = None,  # PKCE
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None,
        grant_type: OAuthGrantType = OAuthGrantType.AUTHORIZATION_CODE,
        response_type: OAuthResponseType = OAuthResponseType.CODE,
        auto_provision_users: bool = True,
        update_existing_users: bool = True,
        create_session: bool = True,
        session_duration_hours: int = 8,
        validate_issuer: bool = True,
        validate_audience: bool = True,
        validate_nonce: bool = True,
        allowed_clock_skew_seconds: int = 300,
        store_tokens: bool = True,
        notify_on_first_login: bool = True,
        provider_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.oauth_provider_id = oauth_provider_id
        self.authorization_code = authorization_code
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.id_token = id_token
        self.state = state
        self.nonce = nonce
        self.redirect_uri = redirect_uri
        self.scopes = scopes or []
        self.code_verifier = code_verifier
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.device_fingerprint = device_fingerprint
        self.grant_type = grant_type
        self.response_type = response_type
        self.auto_provision_users = auto_provision_users
        self.update_existing_users = update_existing_users
        self.create_session = create_session
        self.session_duration_hours = session_duration_hours
        self.validate_issuer = validate_issuer
        self.validate_audience = validate_audience
        self.validate_nonce = validate_nonce
        self.allowed_clock_skew_seconds = allowed_clock_skew_seconds
        self.store_tokens = store_tokens
        self.notify_on_first_login = notify_on_first_login
        self.provider_config = provider_config or {}
        self.metadata = metadata or {}


class OAuthProviderCommandHandler(CommandHandler[OAuthProviderCommand, OAuthProviderResponse]):
    """Handler for OAuth provider operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        device_repository: IDeviceRepository,
        oauth_repository: IOAuthRepository,
        oauth_service: IOAuthService,
        user_service: UserService,
        session_service: SessionService,
        validation_service: ValidationService,
        security_service: SecurityService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._device_repository = device_repository
        self._oauth_repository = oauth_repository
        self._oauth_service = oauth_service
        self._user_service = user_service
        self._session_service = session_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.OAUTH_OPERATION_ATTEMPTED,
        resource_type="oauth_authentication",
        include_request=True,
        include_response=True,
        include_ip_address=True
    )
    @validate_request(OAuthProviderRequest)
    @rate_limit(
        max_requests=60,
        window_seconds=900,  # 15 minutes
        strategy='ip'
    )
    async def handle(self, command: OAuthProviderCommand) -> OAuthProviderResponse:
        """
        Handle OAuth provider operations.
        
        Supports multiple operations:
        - authenticate: Handle OAuth authorization code flow
        - configure: Configure OAuth provider settings
        - refresh_token: Refresh OAuth access tokens
        - revoke_token: Revoke OAuth tokens
        
        Returns:
            OAuthProviderResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "authenticate":
                return await self._handle_authentication(command)
            if command.operation_type == "configure":
                return await self._handle_configuration(command)
            if command.operation_type == "refresh_token":
                return await self._handle_token_refresh(command)
            if command.operation_type == "revoke_token":
                return await self._handle_token_revocation(command)
            raise OAuthValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_authentication(self, command: OAuthProviderCommand) -> OAuthProviderResponse:
        """Handle OAuth authentication flow."""
        # 1. Load OAuth provider configuration
        oauth_provider = await self._oauth_repository.find_by_id(command.oauth_provider_id)
        if not oauth_provider:
            raise OAuthConfigurationError(f"OAuth provider {command.oauth_provider_id} not found")
        
        if not oauth_provider.enabled:
            raise OAuthConfigurationError("OAuth provider is disabled")
        
        # 2. Validate state parameter to prevent CSRF
        if command.state:
            await self._validate_oauth_state(command.state, oauth_provider)
        
        # 3. Exchange authorization code for tokens
        token_response = await self._exchange_code_for_tokens(
            command.authorization_code,
            oauth_provider,
            command
        )
        
        # 4. Validate and decode ID token if present (OpenID Connect)
        user_claims = None
        if token_response.get("id_token"):
            user_claims = await self._validate_and_decode_id_token(
                token_response["id_token"],
                oauth_provider,
                command
            )
        
        # 5. Get user info from userinfo endpoint if no ID token
        if not user_claims and token_response.get("access_token"):
            user_claims = await self._get_user_info_from_access_token(
                token_response["access_token"],
                oauth_provider
            )
        
        if not user_claims:
            raise OAuthAuthenticationError("Could not retrieve user information")
        
        # 6. Find or provision user
        user, is_new_user = await self._find_or_provision_oauth_user(
            user_claims,
            oauth_provider,
            command
        )
        
        # 7. Store OAuth tokens if enabled
        oauth_token_id = None
        if command.store_tokens:
            oauth_token_id = await self._store_oauth_tokens(
                user,
                token_response,
                oauth_provider,
                command
            )
        
        # 8. Perform security risk assessment
        risk_assessment = await self._assess_oauth_authentication_risk(
            user,
            user_claims,
            oauth_provider,
            command
        )
        
        # 9. Handle device registration/trust
        device = None
        if command.device_fingerprint:
            device = await self._handle_oauth_device_authentication(
                user,
                command.device_fingerprint,
                command.ip_address,
                command.user_agent,
                risk_assessment
            )
        
        # 10. Create user session if requested
        session = None
        if command.create_session:
            session = await self._create_oauth_session(
                user,
                device,
                oauth_provider,
                token_response,
                risk_assessment,
                command
            )
        
        # 11. Handle first-time login notifications
        if is_new_user and command.notify_on_first_login:
            await self._send_oauth_first_login_notifications(
                user,
                oauth_provider,
                command
            )
        
        # 12. Log successful authentication
        await self._log_oauth_authentication(
            user,
            session,
            oauth_provider,
            user_claims,
            risk_assessment,
            command
        )
        
        # 13. Publish domain event
        await self._event_bus.publish(
            OAuthAuthenticated(
                aggregate_id=user.id,
                user_id=user.id,
                session_id=session.id if session else None,
                device_id=device.id if device else None,
                oauth_provider_id=command.oauth_provider_id,
                oauth_provider_name=oauth_provider.name,
                subject=user_claims.get("sub"),
                email=user_claims.get("email"),
                is_new_user=is_new_user,
                scopes=command.scopes,
                ip_address=command.ip_address,
                user_agent=command.user_agent,
                risk_level=risk_assessment["risk_level"],
                authentication_method="oauth"
            )
        )
        
        # 14. Commit transaction
        await self._unit_of_work.commit()
        
        # 15. Generate response
        return OAuthProviderResponse(
            success=True,
            operation_type="authenticate",
            user_id=user.id,
            session_id=session.id if session else None,
            device_id=device.id if device else None,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            is_new_user=is_new_user,
            oauth_provider_id=command.oauth_provider_id,
            oauth_provider_name=oauth_provider.name,
            subject=user_claims.get("sub"),
            scopes=command.scopes,
            session_expires_at=session.expires_at if session else None,
            tokens_stored=command.store_tokens,
            oauth_token_id=oauth_token_id,
            risk_level=risk_assessment["risk_level"],
            risk_factors=risk_assessment["risk_factors"],
            authentication_time=datetime.now(UTC),
            redirect_url=self._determine_oauth_redirect_url(command.state),
            message="OAuth authentication successful"
        )
    
    async def _validate_oauth_state(
        self,
        state: str,
        oauth_provider: Any
    ) -> None:
        """Validate OAuth state parameter for CSRF protection."""
        # In a real implementation, you would validate the state against
        # a stored value (e.g., in session or cache)
        stored_state = await self._oauth_repository.get_stored_state(state)
        
        if not stored_state:
            raise OAuthValidationError("Invalid or expired state parameter")
        
        # Remove the used state to prevent replay attacks
        await self._oauth_repository.remove_stored_state(state)
    
    async def _exchange_code_for_tokens(
        self,
        authorization_code: str,
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> dict[str, Any]:
        """Exchange authorization code for access and ID tokens."""
        try:
            token_request_data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": command.redirect_uri,
                "client_id": oauth_provider.configuration["client_id"],
                "client_secret": oauth_provider.configuration["client_secret"]
            }
            
            # Add PKCE code verifier if present
            if command.code_verifier:
                token_request_data["code_verifier"] = command.code_verifier
            
            token_response = await self._oauth_service.exchange_code_for_tokens(
                OAuthContext(
                    provider_config=oauth_provider.configuration,
                    token_endpoint=oauth_provider.configuration["token_endpoint"],
                    request_data=token_request_data
                )
            )
            
            if "error" in token_response:
                raise OAuthTokenError(f"Token exchange failed: {token_response['error']}")
            
            return token_response
            
        except Exception as e:
            raise InvalidOAuthCodeError(f"Failed to exchange authorization code: {e!s}") from e
    
    async def _validate_and_decode_id_token(
        self,
        id_token: str,
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> dict[str, Any]:
        """Validate and decode OpenID Connect ID token."""
        try:
            # Get JWKS for token validation
            jwks = await self._oauth_service.get_jwks(
                oauth_provider.configuration.get("jwks_uri")
            )
            
            # Decode and validate ID token
            decoded_token = jwt.decode(
                id_token,
                key=jwks,
                algorithms=oauth_provider.configuration.get("id_token_signing_alg", ["RS256"]),
                audience=oauth_provider.configuration["client_id"],
                issuer=oauth_provider.configuration.get("issuer") if command.validate_issuer else None,
                options={
                    "verify_aud": command.validate_audience,
                    "verify_iss": command.validate_issuer,
                    "verify_exp": True,
                    "verify_iat": True
                },
                leeway=command.allowed_clock_skew_seconds
            )
            
            # Validate nonce if present
            if command.validate_nonce and command.nonce:
                token_nonce = decoded_token.get("nonce")
                if token_nonce != command.nonce:
                    raise OAuthValidationError(f"Nonce mismatch: {token_nonce} != {command.nonce}")
            
            return decoded_token
            
        except jwt.ExpiredSignatureError as e:
            raise OAuthValidationError("ID token has expired") from e
        except jwt.InvalidTokenError as e:
            raise OAuthValidationError(f"Invalid ID token: {e!s}") from e
        except Exception as e:
            raise OAuthValidationError(f"ID token validation failed: {e!s}") from e
    
    async def _get_user_info_from_access_token(
        self,
        access_token: str,
        oauth_provider: Any
    ) -> dict[str, Any]:
        """Get user information from OAuth userinfo endpoint."""
        userinfo_endpoint = oauth_provider.configuration.get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise OAuthConfigurationError("Userinfo endpoint not configured")
        
        try:
            return await self._oauth_service.get_userinfo(
                access_token,
                userinfo_endpoint
            )
            
            
        except Exception as e:
            raise OAuthAuthenticationError(f"Failed to get user info: {e!s}") from e
    
    async def _find_or_provision_oauth_user(
        self,
        user_claims: dict[str, Any],
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> tuple[User, bool]:
        """Find existing user or provision new user from OAuth claims."""
        # Try to find existing user by OAuth subject (sub claim)
        subject = user_claims.get("sub")
        if not subject:
            raise OAuthValidationError("Missing 'sub' claim in OAuth response")
        
        existing_user = await self._user_repository.find_by_oauth_subject(
            command.oauth_provider_id,
            subject
        )
        
        if existing_user:
            # Update existing user if enabled
            if command.update_existing_users:
                await self._update_user_from_oauth(existing_user, user_claims, command)
            return existing_user, False
        
        # Try to find by email if subject lookup failed
        email = user_claims.get("email")
        if email:
            existing_user = await self._user_repository.find_by_email(email)
            if existing_user:
                # Link existing user to OAuth provider
                await self._link_user_to_oauth_provider(
                    existing_user,
                    user_claims,
                    oauth_provider,
                    command
                )
                return existing_user, False
        
        # Provision new user if auto-provisioning is enabled
        if command.auto_provision_users:
            new_user = await self._provision_user_from_oauth(
                user_claims,
                oauth_provider,
                command
            )
            return new_user, True
        raise UserProvisioningError(
            f"User not found and auto-provisioning disabled for subject: {subject}"
        )
    
    async def _update_user_from_oauth(
        self,
        user: User,
        user_claims: dict[str, Any],
        command: OAuthProviderCommand
    ) -> None:
        """Update existing user with OAuth claims."""
        update_data = {}
        
        # Map OAuth claims to user fields
        claim_mapping = {
            "given_name": "first_name",
            "family_name": "last_name",
            "name": "full_name",
            "picture": "profile_image_url",
            "phone_number": "phone_number",
            "locale": "locale",
            "zoneinfo": "timezone"
        }
        
        for oauth_claim, user_field in claim_mapping.items():
            if user_claims.get(oauth_claim):
                current_value = getattr(user, user_field, None)
                new_value = user_claims[oauth_claim]
                
                if current_value != new_value:
                    update_data[user_field] = new_value
        
        # Update OAuth-specific metadata
        update_data["oauth_last_login"] = datetime.now(UTC)
        update_data["oauth_updated_claims"] = user_claims
        
        if update_data:
            await self._user_service.update_user(user.id, update_data)
    
    async def _link_user_to_oauth_provider(
        self,
        user: User,
        user_claims: dict[str, Any],
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> None:
        """Link existing user to OAuth provider."""
        oauth_link_data = {
            "oauth_provider_id": command.oauth_provider_id,
            "oauth_subject": user_claims["sub"],
            "oauth_email": user_claims.get("email"),
            "oauth_first_linked": datetime.now(UTC),
            "oauth_last_login": datetime.now(UTC),
            "oauth_claims": user_claims
        }
        
        await self._user_service.add_oauth_identity(user.id, oauth_link_data)
    
    async def _provision_user_from_oauth(
        self,
        user_claims: dict[str, Any],
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> User:
        """Provision new user from OAuth claims."""
        # Extract user data from claims
        email = user_claims.get("email")
        username = user_claims.get("preferred_username") or email
        
        if not email:
            raise UserProvisioningError("Email claim is required for user provisioning")
        
        # Generate unique username
        if username:
            username = await self._user_service.ensure_unique_username(username)
        else:
            username = await self._user_service.ensure_unique_username(email.split("@")[0])
        
        user_data = {
            "username": username,
            "email": email,
            "first_name": user_claims.get("given_name"),
            "last_name": user_claims.get("family_name"),
            "full_name": user_claims.get("name"),
            "profile_image_url": user_claims.get("picture"),
            "phone_number": user_claims.get("phone_number"),
            "locale": user_claims.get("locale"),
            "timezone": user_claims.get("zoneinfo"),
            "email_verified": user_claims.get("email_verified", False),
            "is_active": True,
            "source": "oauth",
            "oauth_provider_id": command.oauth_provider_id,
            "oauth_subject": user_claims["sub"],
            "oauth_email": email,
            "oauth_first_login": datetime.now(UTC),
            "oauth_last_login": datetime.now(UTC),
            "oauth_claims": user_claims
        }
        
        # Remove None values
        user_data = {k: v for k, v in user_data.items() if v is not None}
        
        try:
            return await self._user_service.create_user_from_external_source(user_data)
        except Exception as e:
            raise UserProvisioningError(f"Failed to provision user: {e!s}") from e
    
    async def _store_oauth_tokens(
        self,
        user: User,
        token_response: dict[str, Any],
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> UUID:
        """Store OAuth tokens for the user."""
        token_data = {
            "id": UUID(),
            "user_id": user.id,
            "oauth_provider_id": command.oauth_provider_id,
            "access_token": token_response.get("access_token"),
            "refresh_token": token_response.get("refresh_token"),
            "id_token": token_response.get("id_token"),
            "token_type": token_response.get("token_type", "Bearer"),
            "scope": " ".join(command.scopes) if command.scopes else None,
            "expires_in": token_response.get("expires_in"),
            "expires_at": (
                datetime.now(UTC) + timedelta(seconds=token_response["expires_in"])
                if token_response.get("expires_in") else None
            ),
            "created_at": datetime.now(UTC),
            "last_refreshed_at": None,
            "revoked_at": None,
            "metadata": {
                "ip_address": command.ip_address,
                "user_agent": command.user_agent,
                "scopes_granted": command.scopes
            }
        }
        
        return await self._oauth_repository.store_tokens(token_data)
    
    async def _assess_oauth_authentication_risk(
        self,
        user: User,
        user_claims: dict[str, Any],
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> dict[str, Any]:
        """Assess risk level for OAuth authentication."""
        risk_factors = []
        risk_score = 0
        
        # Check if this is a new user
        if user.created_at and (datetime.now(UTC) - user.created_at).total_seconds() < 300:
            risk_factors.append("new_user_account")
            risk_score += 20
        
        # Check email verification status
        if not user_claims.get("email_verified", False):
            risk_factors.append("unverified_email")
            risk_score += 15
        
        # Check for suspicious OAuth scopes
        suspicious_scopes = ["admin", "write", "delete", "manage"]
        if any(scope in " ".join(command.scopes).lower() for scope in suspicious_scopes):
            risk_factors.append("suspicious_oauth_scopes")
            risk_score += 25
        
        # Check time since last login
        if user.last_login_at:
            time_since_last_login = datetime.now(UTC) - user.last_login_at
            if time_since_last_login.days > 90:
                risk_factors.append("long_time_since_last_login")
                risk_score += 10
        
        # Check for new IP address
        if command.ip_address and user.login_history:
            recent_ips = [login.ip_address for login in user.login_history[-10:]]
            if command.ip_address not in recent_ips:
                risk_factors.append("new_ip_address")
                risk_score += 15
        
        # Check OAuth provider risk level
        provider_risk = oauth_provider.metadata.get("risk_level", "low")
        if provider_risk == "high":
            risk_factors.append("high_risk_oauth_provider")
            risk_score += 30
        elif provider_risk == "medium":
            risk_factors.append("medium_risk_oauth_provider")
            risk_score += 15
        
        # Determine overall risk level
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _handle_oauth_device_authentication(
        self,
        user: User,
        device_fingerprint: str,
        ip_address: str | None,
        user_agent: str | None,
        risk_assessment: dict[str, Any]
    ) -> Any | None:
        """Handle device registration/authentication for OAuth."""
        # Similar to SAML device handling but for OAuth context
        device = await self._device_repository.find_by_fingerprint(device_fingerprint)
        
        if device:
            # Update existing device
            device.last_seen_at = datetime.now(UTC)
            device.ip_address = ip_address
            device.user_agent = user_agent
            await self._device_repository.update(device)
            return device
        # Register new device
        device_data = {
            "user_id": user.id,
            "device_fingerprint": device_fingerprint,
            "device_type": "web",
            "device_name": "OAuth SSO Device",
            "ip_address": ip_address,
            "user_agent": user_agent,
            "trust_level": "untrusted",
            "source": "oauth_sso",
            "registered_at": datetime.now(UTC),
            "last_seen_at": datetime.now(UTC)
        }

        # Auto-trust device if low risk
        if risk_assessment["risk_level"] == "low":
            device_data["trust_level"] = "partially_trusted"

        return await self._device_repository.create(device_data)
    
    async def _create_oauth_session(
        self,
        user: User,
        device: Any | None,
        oauth_provider: Any,
        token_response: dict[str, Any],
        risk_assessment: dict[str, Any],
        command: OAuthProviderCommand
    ) -> Session:
        """Create OAuth authentication session."""
        session_data = {
            "user_id": user.id,
            "device_id": device.id if device else None,
            "session_type": SessionType.OAUTH_SSO,
            "ip_address": command.ip_address,
            "user_agent": command.user_agent,
            "expires_at": datetime.now(UTC) + timedelta(hours=command.session_duration_hours),
            "oauth_provider_id": command.oauth_provider_id,
            "oauth_access_token": token_response.get("access_token"),
            "oauth_scopes": command.scopes,
            "authentication_method": "oauth",
            "risk_level": risk_assessment["risk_level"],
            "created_at": datetime.now(UTC),
            "last_activity": datetime.now(UTC)
        }
        
        return await self._session_service.create_session(
            SessionContext(**session_data)
        )
    
    async def _send_oauth_first_login_notifications(
        self,
        user: User,
        oauth_provider: Any,
        command: OAuthProviderCommand
    ) -> None:
        """Send notifications for first-time OAuth login."""
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.FIRST_OAUTH_LOGIN,
                channel="in_app",
                template_id="first_oauth_login",
                template_data={
                    "oauth_provider_name": oauth_provider.name,
                    "login_time": datetime.now(UTC).isoformat(),
                    "ip_address": command.ip_address,
                    "scopes": command.scopes
                },
                priority="medium"
            )
        )
        
        # Email notification if email is verified
        if user.email_verified and user.email:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="first_oauth_login",
                    subject=f"Welcome - First login via {oauth_provider.name}",
                    variables={
                        "username": user.username,
                        "full_name": user.full_name,
                        "oauth_provider_name": oauth_provider.name,
                        "login_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "ip_address": command.ip_address,
                        "scopes": ", ".join(command.scopes) if command.scopes else "basic profile",
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
    
    async def _log_oauth_authentication(
        self,
        user: User,
        session: Session | None,
        oauth_provider: Any,
        user_claims: dict[str, Any],
        risk_assessment: dict[str, Any],
        command: OAuthProviderCommand
    ) -> None:
        """Log successful OAuth authentication."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.OAUTH_AUTHENTICATION_SUCCESS,
                actor_id=user.id,
                resource_type="authentication",
                resource_id=session.id if session else None,
                details={
                    "oauth_provider_id": str(command.oauth_provider_id),
                    "oauth_provider_name": oauth_provider.name,
                    "subject": user_claims.get("sub"),
                    "email": user_claims.get("email"),
                    "scopes": command.scopes,
                    "grant_type": command.grant_type.value,
                    "ip_address": command.ip_address,
                    "user_agent": command.user_agent,
                    "risk_assessment": risk_assessment,
                    "session_duration_hours": command.session_duration_hours,
                    "tokens_stored": command.store_tokens
                },
                risk_level=risk_assessment["risk_level"]
            )
        )
        
        # Log as security event if high risk
        if risk_assessment["risk_level"] == "high":
            await self._audit_service.log_security_incident(
                {
                    "incident_type": SecurityEventType.HIGH_RISK_LOGIN,
                    "severity": RiskLevel.HIGH,
                    "user_id": user.id,
                    "details": {
                        "authentication_method": "oauth",
                        "oauth_provider": oauth_provider.name,
                        "risk_factors": risk_assessment["risk_factors"],
                        "risk_score": risk_assessment["risk_score"]
                    },
                    "indicators": risk_assessment["risk_factors"]
                }
            )
    
    def _determine_oauth_redirect_url(self, state: str | None) -> str:
        """Determine where to redirect user after successful OAuth authentication."""
        if state:
            # State might contain redirect URL information
            # In practice, you'd decode/validate this securely
            pass
        
        # Default redirect URL
        return "https://app.example.com/dashboard"
    
    async def _handle_configuration(self, command: OAuthProviderCommand) -> OAuthProviderResponse:
        """Handle OAuth provider configuration."""
        # This would implement OAuth provider setup/configuration
        # Including client registration, discovery document retrieval, etc.
        raise NotImplementedError("OAuth provider configuration not yet implemented")
    
    async def _handle_token_refresh(self, command: OAuthProviderCommand) -> OAuthProviderResponse:
        """Handle OAuth token refresh."""
        # This would implement OAuth token refresh flow
        raise NotImplementedError("OAuth token refresh not yet implemented")
    
    async def _handle_token_revocation(self, command: OAuthProviderCommand) -> OAuthProviderResponse:
        """Handle OAuth token revocation."""
        # This would implement OAuth token revocation
        raise NotImplementedError("OAuth token revocation not yet implemented")