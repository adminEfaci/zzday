"""
Get active sessions command implementation.

Handles retrieving all active sessions for a user.
"""

import contextlib
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
)
from app.modules.identity.application.dtos.response import (
    ActiveSessionsResponse,
    SessionResponse,
)
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.interfaces.services.security.geolocation_service import (
    IGeolocationService,
)
from app.modules.identity.domain.services import SecurityService


class GetActiveSessionsCommand(Command[ActiveSessionsResponse]):
    """Command to get active sessions."""
    
    def __init__(
        self,
        user_id: UUID,
        current_session_id: UUID | None = None,
        include_device_info: bool = True,
        include_location: bool = True
    ):
        self.user_id = user_id
        self.current_session_id = current_session_id
        self.include_device_info = include_device_info
        self.include_location = include_location


class GetActiveSessionsCommandHandler(CommandHandler[GetActiveSessionsCommand, ActiveSessionsResponse]):
    """Handler for getting active sessions."""
    
    def __init__(
        self,
        session_repository: ISessionRepository,
        security_service: SecurityService,
        geolocation_service: IGeolocationService,
        device_fingerprint_service: IDeviceFingerprintService,
        cache_service: ICacheService,
        unit_of_work: UnitOfWork
    ):
        self._session_repository = session_repository
        self._security_service = security_service
        self._geolocation_service = geolocation_service
        self._device_fingerprint_service = device_fingerprint_service
        self._cache_service = cache_service
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.SESSIONS_VIEWED,
        resource_type="user",
        resource_id_attr="user_id"
    )
    @require_auth
    @rate_limit(
        max_requests=20,
        window_seconds=300,
        strategy='user'
    )
    async def handle(self, command: GetActiveSessionsCommand) -> ActiveSessionsResponse:
        """
        Get all active sessions for user.
        
        Process:
        1. Check cache for sessions
        2. Load active sessions from repository
        3. Enrich with device and location info
        4. Sort by last activity
        5. Mark current session
        6. Cache results
        
        Returns:
            ActiveSessionsResponse with session list
        """
        async with self._unit_of_work:
            # 1. Try to get from cache
            cache_key = f"active_sessions:{command.user_id}"
            cached = await self._cache_service.get(cache_key)
            
            if cached and not command.include_location:
                # Use cached if not including dynamic location data
                return self._build_response_from_cache(cached, command)
            
            # 2. Load active sessions
            active_sessions = await self._session_repository.find_active_by_user(
                command.user_id
            )
            
            if not active_sessions:
                return ActiveSessionsResponse(
                    sessions=[],
                    total=0,
                    current_session_id=command.current_session_id,
                    success=True
                )
            
            # 3. Build session responses
            session_responses = []
            
            for session in active_sessions:
                session_response = await self._build_session_response(
                    session=session,
                    command=command
                )
                session_responses.append(session_response)
            
            # 4. Sort by last activity (most recent first)
            session_responses.sort(
                key=lambda s: s.last_activity_at,
                reverse=True
            )
            
            # 5. Cache results (short TTL for dynamic data)
            await self._cache_service.set(
                key=cache_key,
                value={
                    "sessions": [s.dict() for s in session_responses],
                    "total": len(session_responses)
                },
                ttl=60  # 1 minute
            )
            
            # 6. Log if many active sessions (potential security concern)
            if len(active_sessions) > 10:
                await self._log_many_active_sessions(
                    user_id=command.user_id,
                    count=len(active_sessions)
                )
            
            return ActiveSessionsResponse(
                sessions=session_responses,
                total=len(session_responses),
                current_session_id=command.current_session_id,
                success=True
            )
    
    async def _build_session_response(
        self,
        session: Session,
        command: GetActiveSessionsCommand
    ) -> SessionResponse:
        """Build detailed session response."""
        # Get location if requested
        location = None
        if command.include_location and session.ip_address:
            with contextlib.suppress(Exception):
                # Don't fail if location lookup fails
                location = await self._get_location_info(session.ip_address)
        
        # Get device info if requested
        device_info = None
        if command.include_device_info:
            device_info = await self._get_device_info(
                user_agent=session.user_agent,
                fingerprint=session.device_fingerprint
            )
        
        # Check if current session
        is_current = session.id == command.current_session_id
        
        return SessionResponse(
            id=session.id,
            session_type=session.session_type,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            location=location,
            device_info=device_info,
            created_at=session.created_at,
            last_activity_at=session.last_activity_at,
            expires_at=session.expires_at,
            is_current=is_current
        )
    
    async def _get_location_info(self, ip_address: str) -> dict:
        """Get location information for IP."""
        try:
            geo_data = await self._geolocation_service.get_location(ip_address)
            
            return {
                "country": geo_data.get("country_name", "Unknown"),
                "city": geo_data.get("city", "Unknown"),
                "region": geo_data.get("region", None),
                "country_code": geo_data.get("country_code", None)
            }
        except Exception:
            return {
                "country": "Unknown",
                "city": "Unknown"
            }
    
    async def _get_device_info(
        self,
        user_agent: str | None,
        fingerprint: str | None
    ) -> dict:
        """Get device information from user agent and fingerprint."""
        device_info = {}
        
        if user_agent:
            # Parse user agent (simplified - use proper UA parser in production)
            device_info.update(self._parse_user_agent(user_agent))
        
        if fingerprint:
            # Get device details from fingerprint service
            device_details = await self._device_fingerprint_service.get_device_info(
                fingerprint
            )
            if device_details:
                device_info.update(device_details)
        
        return device_info
    
    def _parse_user_agent(self, user_agent: str) -> dict:
        """Parse user agent string (simplified)."""
        ua_lower = user_agent.lower()
        
        # Detect OS
        if "windows" in ua_lower:
            os = "Windows"
        elif "mac" in ua_lower:
            os = "macOS"
        elif "linux" in ua_lower:
            os = "Linux"
        elif "android" in ua_lower:
            os = "Android"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            os = "iOS"
        else:
            os = "Unknown"
        
        # Detect browser
        if "chrome" in ua_lower and "edg" not in ua_lower:
            browser = "Chrome"
        elif "firefox" in ua_lower:
            browser = "Firefox"
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            browser = "Safari"
        elif "edg" in ua_lower:
            browser = "Edge"
        else:
            browser = "Unknown"
        
        return {
            "os": os,
            "browser": browser,
            "raw": user_agent[:100]  # Truncate for display
        }
    
    def _build_response_from_cache(
        self,
        cached: dict,
        command: GetActiveSessionsCommand
    ) -> ActiveSessionsResponse:
        """Build response from cached data."""
        sessions = [
            SessionResponse(**session_data)
            for session_data in cached["sessions"]
        ]
        
        # Update current session flag
        for session in sessions:
            session.is_current = session.id == command.current_session_id
        
        return ActiveSessionsResponse(
            sessions=sessions,
            total=cached["total"],
            current_session_id=command.current_session_id,
            success=True
        )
    
    async def _log_many_active_sessions(
        self,
        user_id: UUID,
        count: int
    ) -> None:
        """Log when user has many active sessions."""
        await self._security_service.log_security_event(
            user_id=user_id,
            event_type="many_active_sessions",
            details={
                "session_count": count,
                "threshold": 10
            }
        )