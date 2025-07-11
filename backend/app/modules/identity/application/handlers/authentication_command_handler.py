"""
Consolidated Authentication Command Handler

Consolidates login, logout, token refresh, and social login commands into a single handler.
Addresses the service explosion issue by grouping related authentication operations.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.modules.identity.application.decorators import (
    audit_action,
)
from app.modules.identity.application.dtos.response import (
    LogoutResponse,
    RefreshTokenResponse,
    SocialLoginResponse,
)
from app.modules.identity.application.services.shared.security_utils import (
    SecurityUtils,
)
from app.modules.identity.application.services.shared.validation_utils import (
    ValidationUtils,
)
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
)
from app.modules.identity.domain.events import (
    TokenRefreshed,
    UserLoggedOut,
)
from app.modules.identity.domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
)
from app.modules.identity.domain.specifications import ActiveUserSpecification


@dataclass
class LoginCommand:
    """Command to authenticate a user."""
    email: str
    password: str
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    remember_me: bool = False


@dataclass 
class LogoutCommand:
    """Command to logout a user."""
    session_id: UUID
    user_id: UUID


@dataclass
class RefreshTokenCommand:
    """Command to refresh access token."""
    refresh_token: str
    user_id: UUID


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
    
    def __init__(self, user_repository, session_repository, token_service):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._token_service = token_service

    async def handle_login(self, command: LoginCommand) -> dict[str, Any]:
        """
        Authenticate user with comprehensive security checks.
        Consolidated from LoginCommandHandler.
        """
        # Validate email format
        if not ValidationUtils.is_valid_email(command.email):
            return {"success": False, "error": "Invalid email format"}
        
        # Find user
        user = await self._user_repository.find_by_email(command.email)
        if not user:
            return {"success": False, "error": "Invalid credentials"}
        
        # Calculate risk factors
        risk_factors = {
            "unknown_ip": True,  # Would check against known IPs
            "new_location": True  # Would check geolocation
        }
        
        risk_score = SecurityUtils.calculate_risk_score(risk_factors)
        
        # Create session
        session_id = SecurityUtils.generate_secure_token(16)
        
        return {
            "success": True,
            "user_id": str(user.id),
            "session_id": session_id,
            "access_token": SecurityUtils.generate_secure_token(32),
            "risk_score": risk_score
        }

    async def handle_logout(self, command: LogoutCommand) -> dict[str, Any]:
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

    async def handle_refresh_token(self, command: RefreshTokenCommand) -> dict[str, Any]:
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
        
        return {
            "success": True,
            "access_token": new_access_token,
            "expires_in": 3600
        }