"""
Session Aggregate Root

Manages session lifecycle, authentication state, and security events.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import AggregateRoot

from ...value_objects.device_fingerprint import DeviceFingerprint
from ...value_objects.geolocation import Geolocation
from ...value_objects.ip_address import IpAddress
from ...value_objects.token import Token, TokenType
from ...value_objects.user_agent import UserAgent
from .session_enums import SessionStatus, SessionType
from .session_errors import (
    SessionExpiredError, InvalidTokenError, SessionAlreadyTerminatedError
)
from .session_events import (
    SessionCreated, SessionExpired, SessionRevoked, TokenRefreshed, TokenRevoked
)
from .session_constants import (
    SESSION_TIMEOUTS, IDLE_TIMEOUTS, PRIVILEGE_ELEVATION_TIMEOUT,
    IMPOSSIBLE_TRAVEL_SPEED_KMH
)
from .session_mixins import RiskManagementMixin, RateLimitingMixin, SessionValidationMixin


# Additional Events (these would need to be defined in session_events.py)
from pydantic import Field
from ...events import IdentityDomainEvent


class SessionMFACompleted(IdentityDomainEvent):
    """Event raised when MFA is completed for a session."""
    session_id: UUID
    user_id: UUID
    completion_time: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionSecurityEvent(IdentityDomainEvent):
    """Event raised for session security incidents."""
    session_id: UUID
    user_id: UUID
    event_type: str
    risk_level: str
    details: dict[str, Any]

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionPrivilegeElevated(IdentityDomainEvent):
    """Event raised when session privileges are elevated."""
    session_id: UUID
    user_id: UUID
    reason: str
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionSuspended(IdentityDomainEvent):
    """Event raised when session is suspended."""
    session_id: UUID
    user_id: UUID
    reason: str
    suspended_until: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionResumed(IdentityDomainEvent):
    """Event raised when session is resumed."""
    session_id: UUID
    user_id: UUID

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


@dataclass
class Session(AggregateRoot, RiskManagementMixin, RateLimitingMixin, SessionValidationMixin):
    """Session aggregate root - manages authentication state and security."""
    
    id: UUID
    user_id: UUID
    session_type: SessionType
    status: SessionStatus
    access_token: Token
    refresh_token: Token | None = None
    
    # Session metadata
    ip_address: IpAddress | None = None
    user_agent: UserAgent | None = None
    device_fingerprint: DeviceFingerprint | None = None
    geolocation: Geolocation | None = None
    
    # Session properties
    is_trusted: bool = False
    requires_mfa: bool = False
    mfa_completed: bool = False
    
    # Activity tracking
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_refresh_at: datetime | None = None
    activity_count: int = 0
    
    # Session flags and metadata
    flags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    # Security
    risk_score: float = 0.0
    security_events: list[dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize session aggregate with validation."""
        super().__post_init__()
        self._validate_invariants()
    
    def _validate_invariants(self) -> None:
        """Validate domain invariants."""
        if not self.access_token or not self.access_token.value:
            raise ValueError("Access token is required")
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        if not isinstance(self.session_type, SessionType):
            raise ValueError("Session type must be a SessionType enum")
        
        if not isinstance(self.status, SessionStatus):
            raise ValueError("Status must be a SessionStatus enum")
        
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
        
        if self.mfa_completed and not self.requires_mfa:
            raise ValueError("MFA cannot be completed if not required")
        
        if self.last_activity_at < self.created_at:
            raise ValueError("Last activity cannot be before creation")
    
    @classmethod
    def create_new(
        cls,
        user_id: UUID,
        session_type: SessionType,
        ip_address: IpAddress | None = None,
        user_agent: UserAgent | None = None,
        device_fingerprint: DeviceFingerprint | None = None,
        geolocation: Geolocation | None = None,
        requires_mfa: bool = False,
        metadata: dict[str, Any] | None = None
    ) -> 'Session':
        """Create new session with proper event emission."""
        session_id = uuid4()
        
        # Generate tokens
        access_token = Token.generate(TokenType.ACCESS)
        refresh_token = Token.generate(TokenType.REFRESH)
        
        # Calculate initial risk score
        risk_score = 0.0
        if ip_address:
            risk_indicators = ip_address.get_risk_indicators()
            risk_score += sum(0.1 for _ in risk_indicators)
        
        now = datetime.now(UTC)
        
        session = cls(
            id=session_id,
            user_id=user_id,
            session_type=session_type,
            status=SessionStatus.ACTIVE,
            access_token=access_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            geolocation=geolocation,
            requires_mfa=requires_mfa,
            risk_score=risk_score,
            metadata=metadata or {},
            created_at=now,
            last_activity_at=now
        )
        
        # Emit creation event
        session.add_domain_event(SessionCreated(
            session_id=session_id,
            user_id=user_id,
            ip_address=str(ip_address) if ip_address else "",
            user_agent=user_agent.value if user_agent else "",
            device_info=session._get_device_info(),
            expires_at=session._calculate_expiry()
        ))
        
        return session
    
    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == SessionStatus.ACTIVE and bool(self.access_token.value)
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.status == SessionStatus.EXPIRED:
            return True
        
        expires_at = self._calculate_expiry()
        return datetime.now(UTC) > expires_at
    
    @property
    def needs_refresh(self) -> bool:
        """Check if session needs token refresh."""
        return self.refresh_token is not None and self.is_idle_timeout
    
    @property
    def is_high_risk(self) -> bool:
        """Check if session is high risk."""
        return self.risk_score > 0.7
    
    @property
    def is_idle_timeout(self) -> bool:
        """Check if session has idle timeout."""
        idle_duration = datetime.now(UTC) - self.last_activity_at
        
        timeout_map = {
            SessionType.WEB: timedelta(minutes=30),
            SessionType.MOBILE: timedelta(hours=24),
            SessionType.API: timedelta(hours=1),
            SessionType.SERVICE: timedelta(days=365),
            SessionType.ADMIN: timedelta(minutes=15)
        }
        
        max_idle = timeout_map.get(self.session_type, timedelta(minutes=30))
        return idle_duration > max_idle
    
    def record_activity(self, activity_type: str = "request") -> None:
        """Record session activity."""
        self.last_activity_at = datetime.now(UTC)
        self.activity_count += 1
        
        if "recent_activities" not in self.metadata:
            self.metadata["recent_activities"] = []
        
        self.metadata["recent_activities"].append({
            "type": activity_type,
            "timestamp": self.last_activity_at.isoformat()
        })
        
        # Keep only last 10 activities
        if len(self.metadata["recent_activities"]) > 10:
            self.metadata["recent_activities"] = self.metadata["recent_activities"][-10:]
    
    def refresh_tokens(self) -> tuple[str, str]:
        """Refresh session tokens with validation and events."""
        if not self.refresh_token:
            raise InvalidTokenError("No refresh token available")
        
        if self.status != SessionStatus.ACTIVE:
            raise SessionExpiredError()
        
        if self.is_expired:
            raise SessionExpiredError()
        
        if not self.check_rate_limit("token_refresh"):
            raise InvalidTokenError("Token refresh rate limit exceeded")
        
        self.record_rate_limited_action("token_refresh")
        
        # Store old token for event
        old_token_id = uuid4()  # Would be actual token ID in real implementation
        
        # Generate new tokens
        new_access = Token.generate(TokenType.ACCESS)
        new_refresh = Token.generate(TokenType.REFRESH)
        new_token_id = uuid4()  # Would be actual token ID in real implementation
        
        # Update session
        self.access_token = new_access
        self.refresh_token = new_refresh
        self.last_refresh_at = datetime.now(UTC)
        self.record_activity("token_refresh")
        
        # Emit event
        self.add_domain_event(TokenRefreshed(
            user_id=self.user_id,
            session_id=self.id,
            old_token_id=old_token_id,
            new_token_id=new_token_id,
            ip_address=str(self.ip_address) if self.ip_address else "",
            user_agent=self.user_agent.value if self.user_agent else ""
        ))
        
        return (new_access.value, new_refresh.value)
    
    def extend_session(self, duration: timedelta) -> str:
        """Extend session duration with rate limiting."""
        if not self.is_active:
            raise SessionExpiredError()
        
        if not self.check_rate_limit("session_extend"):
            raise InvalidTokenError("Session extension rate limit exceeded")
        
        self.record_rate_limited_action("session_extend")
        self.record_activity("session_extended")
        
        return self.access_token.value
    
    def complete_mfa(self) -> None:
        """Mark MFA as completed."""
        if not self.requires_mfa:
            raise ValueError("Session does not require MFA")
        
        self.mfa_completed = True
        self.add_flag("mfa_verified")
        
        # Reduce risk score
        self.risk_score = max(0, self.risk_score - 0.2)
        
        self.add_security_event("mfa_completed", {
            "completion_time": datetime.now(UTC).isoformat()
        })
        
        # Emit domain event
        self.add_domain_event(SessionMFACompleted(
            session_id=self.id,
            user_id=self.user_id,
            completion_time=datetime.now(UTC)
        ))
    
    def elevate_privileges(self, reason: str) -> None:
        """Elevate session privileges temporarily."""
        self.add_flag("elevated_privileges")
        self.metadata["elevation_reason"] = reason
        self.metadata["elevation_time"] = datetime.now(UTC).isoformat()
        
        expires_at = datetime.now(UTC) + PRIVILEGE_ELEVATION_TIMEOUT
        self.metadata["elevation_expires"] = expires_at.isoformat()
        
        self.add_security_event("privileges_elevated", {
            "reason": reason,
            "expires_at": expires_at.isoformat()
        })
        
        # Emit domain event
        self.add_domain_event(SessionPrivilegeElevated(
            session_id=self.id,
            user_id=self.user_id,
            reason=reason,
            expires_at=expires_at
        ))
    
    def is_privilege_elevated(self) -> bool:
        """Check if privileges are currently elevated."""
        if "elevated_privileges" not in self.flags:
            return False
        
        if "elevation_expires" in self.metadata:
            expires = datetime.fromisoformat(self.metadata["elevation_expires"])
            if datetime.now(UTC) > expires:
                self.remove_flag("elevated_privileges")
                return False
        
        return True
    
    def verify_device_fingerprint(self, fingerprint: str) -> bool:
        """Verify device fingerprint matches."""
        if not self.device_fingerprint:
            return True
        
        is_match = self.device_fingerprint.value == fingerprint
        if not is_match:
            self.add_security_event("device_fingerprint_mismatch", {
                "expected": self.device_fingerprint.value[:8] + "...",
                "received": fingerprint[:8] + "..."
            })
            
            # Emit security event
            self.add_domain_event(SessionSecurityEvent(
                session_id=self.id,
                user_id=self.user_id,
                event_type="device_fingerprint_mismatch",
                risk_level="medium",
                details={
                    "expected": self.device_fingerprint.value[:8] + "...",
                    "received": fingerprint[:8] + "..."
                }
            ))
        
        return is_match
    
    def update_location(self, new_ip: IpAddress, new_location: Geolocation | None = None) -> None:
        """Update session location with impossible travel detection."""
        if self.ip_address and self.geolocation and new_location:
            distance = self.geolocation.distance_to(new_location, "kilometers")
            time_diff = (datetime.now(UTC) - self.last_activity_at).total_seconds() / 3600
            
            if time_diff > 0 and distance / time_diff > IMPOSSIBLE_TRAVEL_SPEED_KMH:
                event_details = {
                    "from_location": str(self.geolocation),
                    "to_location": str(new_location),
                    "distance_km": distance,
                    "time_hours": time_diff,
                    "speed_kmh": distance / time_diff
                }
                
                self.add_security_event("impossible_travel", event_details)
                
                # Emit security event
                self.add_domain_event(SessionSecurityEvent(
                    session_id=self.id,
                    user_id=self.user_id,
                    event_type="impossible_travel",
                    risk_level="high",
                    details=event_details
                ))
        
        self.ip_address = new_ip
        self.geolocation = new_location
    
    def add_flag(self, flag: str) -> None:
        """Add a session flag."""
        self.flags.add(flag)
    
    def remove_flag(self, flag: str) -> None:
        """Remove a session flag."""
        self.flags.discard(flag)
    
    def has_flag(self, flag: str) -> bool:
        """Check if session has a flag."""
        return flag in self.flags
    
    def _handle_high_risk(self) -> None:
        """Handle high-risk scenarios by terminating session."""
        self.add_domain_event(SessionSecurityEvent(
            session_id=self.id,
            user_id=self.user_id,
            event_type="high_risk_termination",
            risk_level="critical",
            details={"risk_score": self.risk_score}
        ))
        self.terminate("high_risk_score")
    
    def terminate(self, reason: str) -> None:
        """Terminate the session with proper cleanup and events."""
        if self.status in [SessionStatus.TERMINATED, SessionStatus.REVOKED]:
            raise SessionAlreadyTerminatedError()
        
        old_status = self.status
        self.status = SessionStatus.TERMINATED
        self.metadata["termination_reason"] = reason
        self.metadata["terminated_at"] = datetime.now(UTC).isoformat()
        self.metadata["previous_status"] = old_status.value
        
        # Clear tokens securely
        self.access_token = Token(value="", token_type=TokenType.ACCESS)
        self.refresh_token = None
        
        self.add_security_event("session_terminated", {
            "reason": reason,
            "previous_status": old_status.value
        })
        
        # Emit termination event
        self.add_domain_event(SessionRevoked(
            session_id=self.id,
            user_id=self.user_id,
            revoked_by=None,
            reason=reason,
            revoke_all_sessions=False
        ))
    
    def expire(self) -> None:
        """Mark session as expired."""
        if self.status == SessionStatus.EXPIRED:
            return
            
        self.status = SessionStatus.EXPIRED
        self.metadata["expired_at"] = datetime.now(UTC).isoformat()
        
        # Emit expiration event
        self.add_domain_event(SessionExpired(
            session_id=self.id,
            user_id=self.user_id,
            expired_at=datetime.now(UTC),
            reason="timeout",
            automatic_cleanup=True
        ))
    
    def suspend(self, reason: str, duration: timedelta | None = None) -> None:
        """Suspend the session temporarily."""
        self.status = SessionStatus.SUSPENDED
        self.metadata["suspension_reason"] = reason
        self.metadata["suspended_at"] = datetime.now(UTC).isoformat()
        
        suspended_until = None
        if duration:
            suspended_until = datetime.now(UTC) + duration
            self.metadata["resume_at"] = suspended_until.isoformat()
        
        # Emit suspension event
        self.add_domain_event(SessionSuspended(
            session_id=self.id,
            user_id=self.user_id,
            reason=reason,
            suspended_until=suspended_until
        ))
    
    def resume(self) -> None:
        """Resume a suspended session."""
        if self.status != SessionStatus.SUSPENDED:
            raise ValueError("Can only resume suspended sessions")
        
        if "resume_at" in self.metadata:
            resume_at = datetime.fromisoformat(self.metadata["resume_at"])
            if datetime.now(UTC) < resume_at:
                raise ValueError("Suspension period has not ended")
        
        self.status = SessionStatus.ACTIVE
        self.metadata["resumed_at"] = datetime.now(UTC).isoformat()
        
        # Emit resume event
        self.add_domain_event(SessionResumed(
            session_id=self.id,
            user_id=self.user_id
        ))
    
    def _get_device_info(self) -> dict[str, Any]:
        """Extract device information for events."""
        return {
            "fingerprint": self.device_fingerprint.value if self.device_fingerprint else None,
            "user_agent": self.user_agent.value if self.user_agent else None,
            "trusted": self.is_trusted
        }
    
    def _calculate_expiry(self) -> datetime:
        """Calculate session expiry based on type."""
        timeout_map = {
            SessionType.WEB: timedelta(hours=8),
            SessionType.MOBILE: timedelta(days=30),
            SessionType.API: timedelta(hours=24),
            SessionType.SERVICE: timedelta(days=365),
            SessionType.ADMIN: timedelta(hours=4)
        }
        
        timeout = timeout_map.get(self.session_type, timedelta(hours=8))
        return self.created_at + timeout
    
    def get_session_info(self) -> dict[str, Any]:
        """Get session information for display."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "type": self.session_type.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity_at.isoformat(),
            "activity_count": self.activity_count,
            "is_trusted": self.is_trusted,
            "mfa_completed": self.mfa_completed,
            "risk_score": round(self.risk_score, 2),
            "flags": list(self.flags),
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "user_agent": self.user_agent.value if self.user_agent else None,
            "location": str(self.geolocation) if self.geolocation else None,
            "security_events_count": len(self.security_events),
            "expires_at": self._calculate_expiry().isoformat()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for persistence."""
        access_hash = None
        if self.access_token and self.access_token.value:
            access_hash = hashlib.sha256(self.access_token.value.encode()).hexdigest()
        
        refresh_hash = None
        if self.refresh_token and self.refresh_token.value:
            refresh_hash = hashlib.sha256(self.refresh_token.value.encode()).hexdigest()
        
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "session_type": self.session_type.value,
            "status": self.status.value,
            "access_token_hash": access_hash,
            "refresh_token_hash": refresh_hash,
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "user_agent": self.user_agent.value if self.user_agent else None,
            "device_fingerprint": self.device_fingerprint.value if self.device_fingerprint else None,
            "geolocation": self.geolocation.to_dict() if self.geolocation else None,
            "is_trusted": self.is_trusted,
            "requires_mfa": self.requires_mfa,
            "mfa_completed": self.mfa_completed,
            "created_at": self.created_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat(),
            "last_refresh_at": self.last_refresh_at.isoformat() if self.last_refresh_at else None,
            "activity_count": self.activity_count,
            "flags": list(self.flags),
            "metadata": self.metadata,
            "risk_score": self.risk_score,
            "security_events": self.security_events
        }