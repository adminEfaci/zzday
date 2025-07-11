"""
Session Domain Service

Session lifecycle management and security.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from ...aggregates.user import User
from ...entities.session.session import Session
from ...enums import SessionStatus, SessionType
from ...errors import InvalidTokenError
from ...value_objects.geolocation import Geolocation
from ...value_objects.ip_address import IpAddress


@dataclass
class SessionCreateData:
    """Data for session creation."""
    user_id: UUID
    session_type: SessionType
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    geolocation: dict[str, Any] | None = None
    metadata: dict[str, Any] = None


@dataclass
class SessionInfo:
    """Session information."""
    session_id: UUID
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    session_type: SessionType
    requires_mfa: bool


@dataclass
class SessionActivity:
    """Session activity data."""
    session_id: UUID
    user_id: UUID
    ip_address: str
    user_agent: str
    activity_type: str
    timestamp: datetime
    risk_score: float
    metadata: dict[str, Any]


class SessionService:
    """Domain service for session management."""
    
    def __init__(self):
        self._access_token_ttl = {
            SessionType.WEB: timedelta(minutes=30),
            SessionType.MOBILE: timedelta(hours=24),
            SessionType.API: timedelta(hours=1),
            SessionType.ADMIN: timedelta(minutes=15),
            SessionType.SERVICE: timedelta(days=365)
        }
        self._refresh_token_ttl = {
            SessionType.WEB: timedelta(days=7),
            SessionType.MOBILE: timedelta(days=30),
            SessionType.API: timedelta(days=1),
            SessionType.ADMIN: timedelta(hours=1),
            SessionType.SERVICE: None  # No refresh for service tokens
        }
        self._max_concurrent_sessions = {
            SessionType.WEB: 3,
            SessionType.MOBILE: 5,
            SessionType.API: 10,
            SessionType.ADMIN: 1,
            SessionType.SERVICE: 1
        }
    
    async def create_session(
        self,
        user: User,
        session_data: SessionCreateData
    ) -> SessionInfo:
        """Create new session for user."""
        
        # Validate session type permissions
        if not self._can_create_session_type(user, session_data.session_type):
            raise ValueError(f"User cannot create {session_data.session_type.value} sessions")
        
        # Check concurrent session limits
        await self._enforce_concurrent_session_limit(
            user,
            session_data.session_type
        )
        
        # Create IP and geo value objects
        ip_vo = IpAddress(session_data.ip_address)
        geo_vo = None
        if session_data.geolocation:
            geo_vo = Geolocation(
                latitude=session_data.geolocation["latitude"],
                longitude=session_data.geolocation["longitude"],
            )
        
        # Determine if MFA is required
        requires_mfa = self._session_requires_mfa(user, session_data.session_type)
        
        # Calculate initial risk score
        risk_score = await self._calculate_session_risk(
            user,
            ip_vo,
            session_data.device_fingerprint
        )
        
        # Create session
        session = Session.create_new(
            user_id=user.id,
            session_type=session_data.session_type,
            ip_address=ip_vo,
            user_agent=session_data.user_agent,
            device_fingerprint=session_data.device_fingerprint,
            requires_mfa=requires_mfa,
            metadata=session_data.metadata
        )
        
        # Set geolocation if available
        if geo_vo:
            session.geolocation = geo_vo
        
        # Set risk score
        session.risk_score = risk_score
        
        # Add session to user
        user._sessions.append(session)
        
        # Calculate expiry
        expires_at = datetime.now(UTC) + self._access_token_ttl[session_data.session_type]
        
        return SessionInfo(
            session_id=session.id,
            access_token=session.access_token,
            refresh_token=session.refresh_token,
            expires_at=expires_at,
            session_type=session.session_type,
            requires_mfa=session.requires_mfa
        )
    
    async def validate_session(
        self,
        session_id: UUID,
        access_token: str,
        ip_address: str | None = None
    ) -> tuple[bool, str | None]:
        """Validate session and access token."""
        
        # This would typically fetch from repository
        # For now, we'll assume we have the session
        session = await self._get_session(session_id)
        
        if not session:
            return False, "Session not found"
        
        # Check session status
        if not session.is_active:
            return False, "Session is not active"
        
        # Check token match
        if session.access_token != access_token:
            return False, "Invalid access token"
        
        # Check if expired
        if session.is_expired:
            return False, "Session has expired"
        
        # Check idle timeout
        if session.is_idle_timeout:
            session.expire()
            return False, "Session idle timeout"
        
        # Check IP change if provided
        if ip_address and session.ip_address:
            if str(session.ip_address) != ip_address:
                # IP changed - increase risk
                session.add_security_event("ip_change", {
                    "old_ip": str(session.ip_address),
                    "new_ip": ip_address
                })
        
        # Update activity
        session.record_activity()
        
        return True, None
    
    async def refresh_session(
        self,
        session_id: UUID,
        refresh_token: str
    ) -> SessionInfo:
        """Refresh session tokens."""
        
        session = await self._get_session(session_id)
        
        if not session:
            raise InvalidTokenError("Session not found")
        
        if not session.refresh_token:
            raise InvalidTokenError("Session does not support refresh")
        
        if session.refresh_token != refresh_token:
            raise InvalidTokenError("Invalid refresh token")
        
        # Refresh tokens
        new_access, new_refresh = session.refresh_tokens()
        
        # Calculate new expiry
        expires_at = datetime.now(UTC) + self._access_token_ttl[session.session_type]
        
        return SessionInfo(
            session_id=session.id,
            access_token=new_access,
            refresh_token=new_refresh,
            expires_at=expires_at,
            session_type=session.session_type,
            requires_mfa=session.requires_mfa
        )
    
    async def revoke_session(
        self,
        session_id: UUID,
        reason: str = "user_requested"
    ) -> bool:
        """Revoke a session."""
        
        session = await self._get_session(session_id)
        
        if not session:
            return False
        
        session.terminate(reason)
        return True
    
    async def revoke_all_user_sessions(
        self,
        user: User,
        except_session_id: UUID | None = None,
        reason: str = "security_event"
    ) -> int:
        """Revoke all sessions for a user."""
        
        revoked_count = 0
        
        for session in user._sessions:
            if session.id != except_session_id and session.is_active:
                session.terminate(reason)
                revoked_count += 1
        
        return revoked_count
    
    async def extend_session(
        self,
        session_id: UUID,
        duration: timedelta
    ) -> datetime:
        """Extend session duration."""
        
        session = await self._get_session(session_id)
        
        if not session:
            raise ValueError("Session not found")
        
        if not session.is_active:
            raise ValueError("Cannot extend inactive session")
        
        # Extend session
        session.extend_session(duration)
        
        # Return new expiry
        return datetime.now(UTC) + duration
    
    async def record_session_activity(
        self,
        session_id: UUID,
        activity: SessionActivity
    ) -> None:
        """Record activity for session."""
        
        session = await self._get_session(session_id)
        
        if not session:
            return
        
        # Record activity
        session.record_activity(activity.activity_type)
        
        # Update location if changed
        if activity.ip_address and str(session.ip_address) != activity.ip_address:
            new_ip = IpAddress(activity.ip_address)
            session.update_location(new_ip)
        
        # Add security event if risky
        if activity.risk_score > 0.7:
            session.add_security_event("high_risk_activity", {
                "activity_type": activity.activity_type,
                "risk_score": activity.risk_score,
                "metadata": activity.metadata
            })
    
    async def get_active_sessions(
        self,
        user: User,
        session_type: SessionType | None = None
    ) -> list[dict[str, Any]]:
        """Get user's active sessions."""
        
        sessions = [s for s in user._sessions if s.is_active]
        
        if session_type:
            sessions = [s for s in sessions if s.session_type == session_type]
        
        return [
            {
                "id": str(s.id),
                "type": s.session_type.value,
                "created_at": s.created_at.isoformat(),
                "last_activity": s.last_activity_at.isoformat(),
                "ip_address": str(s.ip_address) if s.ip_address else None,
                "user_agent": s.user_agent,
                "location": str(s.geolocation) if s.geolocation else None,
                "is_trusted": s.is_trusted,
                "risk_score": s.risk_score,
                "activity_count": s.activity_count
            }
            for s in sessions
        ]
    
    async def cleanup_expired_sessions(
        self,
        user: User,
        older_than: timedelta | None = None
    ) -> int:
        """Clean up expired sessions."""
        
        if not older_than:
            older_than = timedelta(days=30)
        
        cutoff_date = datetime.now(UTC) - older_than
        cleaned_count = 0
        
        # Mark for removal (don't modify list while iterating)
        to_remove = []
        
        for session in user._sessions:
            if (session.is_expired or 
                session.status in [SessionStatus.TERMINATED, SessionStatus.EXPIRED]):
                if session.last_activity_at < cutoff_date:
                    to_remove.append(session)
        
        # Remove sessions
        for session in to_remove:
            user._sessions.remove(session)
            cleaned_count += 1
        
        return cleaned_count
    
    def calculate_session_trust_score(
        self,
        session: Session,
        user_history: list[dict[str, Any]]
    ) -> float:
        """Calculate trust score for session."""
        
        trust_score = 0.5  # Start neutral
        
        # Device trust
        if session.device_fingerprint:
            known_devices = {h.get("device_fingerprint") for h in user_history}
            if session.device_fingerprint in known_devices:
                trust_score += 0.2
        
        # Location trust
        if session.ip_address:
            known_ips = {h.get("ip_address") for h in user_history}
            if str(session.ip_address) in known_ips:
                trust_score += 0.2
        
        # Session age
        session_age = (datetime.now(UTC) - session.created_at).days
        if session_age > 7:
            trust_score += 0.1
        
        # Activity patterns
        if session.activity_count > 10 and session.risk_score < 0.3:
            trust_score += 0.1
        
        # MFA completion
        if session.requires_mfa and session.mfa_completed:
            trust_score += 0.2
        
        # Security events
        if len(session.security_events) > 0:
            trust_score -= len(session.security_events) * 0.05
        
        return max(0.0, min(1.0, trust_score))
    
    # Private helper methods
    
    def _can_create_session_type(
        self,
        user: User,
        session_type: SessionType
    ) -> bool:
        """Check if user can create session type."""
        
        if session_type == SessionType.ADMIN:
            # Only admins can create admin sessions
            return any(r.name in ["admin", "super_admin"] for r in user._roles)
        
        if session_type == SessionType.SERVICE:
            # Only service accounts can create service sessions
            return any(r.name == "service_account" for r in user._roles)
        
        return True
    
    async def _enforce_concurrent_session_limit(
        self,
        user: User,
        session_type: SessionType
    ) -> None:
        """Enforce concurrent session limits."""
        
        max_sessions = self._max_concurrent_sessions.get(session_type, 5)
        
        # Count active sessions of this type
        active_sessions = [
            s for s in user._sessions
            if s.is_active and s.session_type == session_type
        ]
        
        if len(active_sessions) >= max_sessions:
            # Revoke oldest session
            oldest = min(active_sessions, key=lambda s: s.created_at)
            oldest.terminate("concurrent_session_limit")
    
    def _session_requires_mfa(
        self,
        user: User,
        session_type: SessionType
    ) -> bool:
        """Check if session type requires MFA."""
        
        # Admin sessions always require MFA
        if session_type == SessionType.ADMIN:
            return True
        
        # Service sessions don't require MFA
        if session_type == SessionType.SERVICE:
            return False
        
        # User preference
        return user.mfa_enabled
    
    async def _calculate_session_risk(
        self,
        user: User,
        ip_address: IpAddress,
        device_fingerprint: str | None
    ) -> float:
        """Calculate initial session risk score."""
        
        risk_score = 0.0
        
        # New device
        if device_fingerprint:
            known_devices = {
                d.fingerprint for d in user._registered_devices
                if d.fingerprint == device_fingerprint
            }
            if device_fingerprint not in known_devices:
                risk_score += 0.3
        
        # IP-based risk
        if ip_address.is_tor:
            risk_score += 0.4
        elif ip_address.is_vpn:
            risk_score += 0.2
        elif ip_address.is_datacenter:
            risk_score += 0.3
        
        # User account risk
        if user.failed_login_count > 0:
            risk_score += min(user.failed_login_count * 0.1, 0.3)
        
        return min(risk_score, 1.0)
    
    async def _get_session(self, session_id: UUID) -> Session | None:
        """Get session by ID."""
        # This would typically use repository
        # For now, returning None
        return None