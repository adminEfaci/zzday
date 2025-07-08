"""
Refresh token command implementation.

Handles token refresh with security validation.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IDeviceFingerprintService,
    ISessionRepository,
    ITokenBlocklistService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import SecurityIncidentContext
from app.modules.identity.application.dtos.request import RefreshTokenRequest
from app.modules.identity.application.dtos.response import RefreshTokenResponse
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import (
    AuditAction,
    RiskLevel,
    SecurityEventType,
    SessionStatus,
)
from app.modules.identity.domain.events import TokenRefreshed
from app.modules.identity.domain.exceptions import (
    InvalidTokenError,
    SecurityViolationError,
    SessionExpiredError,
    TokenBlacklistedError,
)
from app.modules.identity.domain.services import (
    SecurityService,
    SessionService,
    TokenService,
)


@dataclass
class RefreshTokenRepositoryDependencies:
    """Repository dependencies for refresh token handler."""
    session_repository: ISessionRepository
    user_repository: IUserRepository


@dataclass
class RefreshTokenServiceDependencies:
    """Service dependencies for refresh token handler."""
    token_service: TokenService
    session_service: SessionService
    security_service: SecurityService
    token_blocklist_service: ITokenBlocklistService
    device_fingerprint_service: IDeviceFingerprintService
    cache_service: ICacheService


@dataclass
class RefreshTokenInfrastructureDependencies:
    """Infrastructure dependencies for refresh token handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class RefreshTokenCommand(Command[RefreshTokenResponse]):
    """Command to refresh authentication tokens."""
    
    def __init__(
        self,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None
    ):
        self.refresh_token = refresh_token
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.device_fingerprint = device_fingerprint


class RefreshTokenCommandHandler(CommandHandler[RefreshTokenCommand, RefreshTokenResponse]):
    """Handler for token refresh."""
    
    def __init__(
        self,
        repositories: RefreshTokenRepositoryDependencies,
        services: RefreshTokenServiceDependencies,
        infrastructure: RefreshTokenInfrastructureDependencies
    ):
        # Repository dependencies
        self._session_repository = repositories.session_repository
        self._user_repository = repositories.user_repository
        
        # Service dependencies
        self._token_service = services.token_service
        self._session_service = services.session_service
        self._security_service = services.security_service
        self._token_blocklist_service = services.token_blocklist_service
        self._device_fingerprint_service = services.device_fingerprint_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.TOKEN_REFRESHED,
        resource_type="session",
        include_errors=True
    )
    @validate_request(RefreshTokenRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=300,  # 5 minutes
        strategy='token'
    )
    async def handle(self, command: RefreshTokenCommand) -> RefreshTokenResponse:
        """
        Refresh authentication tokens with security checks.
        
        Process:
        1. Validate refresh token
        2. Check if blocked
        3. Load session and user
        4. Validate session state
        5. Check security constraints
        6. Generate new tokens
        7. Update session
        8. Block old refresh token
        
        Returns:
            RefreshTokenResponse with new tokens
            
        Raises:
            InvalidTokenError: If token invalid
            TokenBlockedError: If token blocked
            SessionExpiredError: If session expired
            SecurityViolationError: If security check fails
        """
        async with self._unit_of_work:
            # 1. Validate and decode refresh token
            try:
                token_payload = await self._token_service.verify_refresh_token(
                    command.refresh_token
                )
            except Exception as e:
                raise InvalidTokenError(f"Invalid refresh token: {e!s}") from e
            
            user_id = UUID(token_payload.get("user_id"))
            session_id = UUID(token_payload.get("session_id"))
            
            # 2. Check if token is blocked
            is_blocked = await self._token_blocklist_service.is_blocked(
                command.refresh_token
            )
            
            if is_blocked:
                # Potential token reuse attack
                await self._handle_token_reuse_attack(
                    user_id=user_id,
                    session_id=session_id,
                    command=command
                )
                raise TokenBlacklistedError("Token has been revoked")
            
            # 3. Load session
            session = await self._session_repository.get_by_id(session_id)
            
            if not session:
                raise InvalidTokenError("Session not found")
            
            if session.user_id != user_id:
                raise SecurityViolationError("Session user mismatch")
            
            # 4. Validate session state
            if session.status != SessionStatus.ACTIVE:
                raise SessionExpiredError(f"Session is {session.status.value}")
            
            if session.expires_at < datetime.now(UTC):
                # Mark session as expired
                await self._session_service.expire_session(session.id)
                raise SessionExpiredError("Session has expired")
            
            # 5. Load user and check status
            user = await self._user_repository.get_by_id(user_id)
            
            if not user or not user.is_active:
                raise InvalidTokenError("User account is not active")
            
            # 6. Perform security checks
            await self._validate_security_constraints(
                session=session,
                command=command
            )
            
            # 7. Generate new tokens
            access_token = await self._token_service.generate_access_token(
                user_id=user.id,
                session_id=session.id,
                scopes=await self._get_user_scopes(user.id)
            )
            
            new_refresh_token = await self._token_service.generate_refresh_token(
                user_id=user.id,
                session_id=session.id
            )
            
            # 8. Update session activity
            session.update_activity()
            
            # Extend session if needed
            if session.expires_at < datetime.now(UTC) + timedelta(hours=1):
                session.extend(timedelta(hours=24))
            
            await self._session_repository.update(session)
            
            # 9. Blacklist old refresh token
            await self._token_blocklist_service.block_token(
                token=command.refresh_token,
                token_type="refresh",  # noqa: S106
                expires_in=2592000  # 30 days
            )
            
            # 10. Clear token cache
            await self._cache_service.delete(f"token:{command.refresh_token}")
            
            # 11. Publish event
            await self._event_bus.publish(
                TokenRefreshed(
                    aggregate_id=user.id,
                    session_id=session.id,
                    ip_address=command.ip_address
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            return RefreshTokenResponse(
                access_token=access_token,
                refresh_token=new_refresh_token,
                token_type="Bearer",  # noqa: S106
                expires_in=3600,  # 1 hour
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                success=True,
                message="Token refreshed successfully"
            )
    
    async def _handle_token_reuse_attack(
        self,
        user_id: UUID,
        session_id: UUID,
        command: RefreshTokenCommand
    ) -> None:
        """Handle potential token reuse attack."""
        # Log security incident
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.TOKEN_REUSE,
                severity=RiskLevel.HIGH,
                user_id=user_id,
                ip_address=command.ip_address,
                details={
                    "session_id": str(session_id),
                    "user_agent": command.user_agent
                }
            )
        )
        
        # Revoke all sessions for this user as a precaution
        sessions = await self._session_repository.get_active_sessions(user_id)
        
        for session in sessions:
            await self._session_service.revoke_session(
                session_id=session.id,
                reason="Security: Token reuse detected"
            )
        
        # Notify user
        user = await self._user_repository.get_by_id(user_id)
        if user:
            await self._security_service.notify_security_alert(
                user=user,
                alert_type="token_reuse",
                details={
                    "action_taken": "All sessions revoked",
                    "recommendation": "Please login again and change your password"
                }
            )
    
    async def _validate_security_constraints(
        self,
        session: Session,
        command: RefreshTokenCommand
    ) -> None:
        """Validate security constraints for token refresh."""
        # Check IP address consistency
        if command.ip_address and session.ip_address and command.ip_address != session.ip_address:
                # IP address changed - could be legitimate or suspicious
                ip_risk = await self._security_service.assess_ip_change(
                    old_ip=session.ip_address,
                    new_ip=command.ip_address
                )
                
                if ip_risk.risk_score > 0.7:
                    raise SecurityViolationError(
                        "Token refresh blocked due to suspicious IP change"
                    )
        
        # Check device fingerprint if available
        if command.device_fingerprint and session.device_fingerprint and command.device_fingerprint != session.device_fingerprint:
                # Device changed - highly suspicious for same session
                raise SecurityViolationError(
                    "Token refresh blocked due to device mismatch"
                )
        
        # Check user agent consistency
        if command.user_agent and session.user_agent and not self._is_similar_user_agent(command.user_agent, session.user_agent):
                # Significant user agent change
                raise SecurityViolationError(
                    "Token refresh blocked due to user agent mismatch"
                )
    
    async def _get_user_scopes(self, user_id: UUID) -> list[str]:
        """Get user's permission scopes for token."""
        # This would typically load from permission service
        return ["user:read", "user:write", "profile:read", "profile:write"]
    
    def _is_similar_user_agent(self, ua1: str, ua2: str) -> bool:
        """Check if user agents are similar enough."""
        # Simple check - in production would use proper UA parsing
        # Allow minor version changes but not major browser/OS changes
        ua1_parts = ua1.lower().split()
        ua2_parts = ua2.lower().split()
        
        # Check if major components match (browser, OS)
        major_components = ['chrome', 'firefox', 'safari', 'edge', 'windows', 'mac', 'linux']
        
        for component in major_components:
            in_ua1 = any(component in part for part in ua1_parts)
            in_ua2 = any(component in part for part in ua2_parts)
            if in_ua1 != in_ua2:
                return False
        
        return True