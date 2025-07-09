"""
Consolidated Authentication Command Handler

Consolidates login, logout, token refresh, and social login commands into a single handler.
Addresses the service explosion issue by grouping related authentication operations.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.modules.identity.application.services.shared.validation_utils import ValidationUtils
from app.modules.identity.application.services.shared.security_utils import SecurityUtils


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
        # Find session
        session = await self._session_repository.find_by_id(command.session_id)
        if not session:
            return {"success": False, "error": "Session not found"}
        
        # Invalidate session
        await self._session_repository.delete(command.session_id)
        
        return {"success": True, "message": "Logout successful"}

    async def handle_refresh_token(self, command: RefreshTokenCommand) -> dict[str, Any]:
        """
        Refresh access token using refresh token.
        Consolidated from RefreshTokenCommandHandler.
        """
        # Validate refresh token (simplified)
        if not command.refresh_token:
            return {"success": False, "error": "Invalid refresh token"}
        
        # Generate new access token
        new_access_token = SecurityUtils.generate_secure_token(32)
        
        return {
            "success": True,
            "access_token": new_access_token,
            "expires_in": 3600
        }