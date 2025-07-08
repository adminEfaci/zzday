"""
Session mapper for converting between Session domain objects and DTOs.

This module provides mapping functionality to convert Session entities
to/from DTOs for API requests and responses.
"""

from datetime import datetime, timedelta

from app.modules.identity.application.dtos.response import (
    ActiveSessionsResponse,
    ConcurrentSessionsResponse,
    SessionDetailResponse,
    SessionResponse,
    SessionTransferResponse,
)
from app.modules.identity.domain.entities.session.session import Session


class SessionMapper:
    """Mapper for Session domain objects to DTOs."""
    
    @staticmethod
    def to_response(session: Session, is_current: bool = False) -> SessionResponse:
        """Convert Session entity to SessionResponse DTO.
        
        Args:
            session: Session entity
            is_current: Whether this is the current session
            
        Returns:
            SessionResponse DTO
        """
        # Extract location info from geolocation
        location = None
        if session.geolocation:
            location = {
                'city': getattr(session.geolocation, 'city', None),
                'country': getattr(session.geolocation, 'country', None),
                'region': getattr(session.geolocation, 'region', None)
            }
        
        # Extract device info from user agent and fingerprint
        device_info = None
        if session.user_agent:
            device_info = {
                'browser': getattr(session.user_agent, 'browser', 'Unknown'),
                'os': getattr(session.user_agent, 'os', 'Unknown'),
                'device': getattr(session.user_agent, 'device', 'Unknown')
            }
        
        return SessionResponse(
            id=session.id,
            session_type=session.session_type,
            ip_address=str(session.ip_address) if session.ip_address else "Unknown",
            user_agent=session.user_agent.value if session.user_agent else "Unknown",
            location=location,
            device_info=device_info,
            created_at=session.created_at,
            last_activity_at=session.last_activity_at,
            expires_at=SessionMapper._calculate_expires_at(session),
            is_current=is_current
        )
    
    @staticmethod
    def to_detail_response(
        session: Session,
        include_security_events: bool = False
    ) -> SessionDetailResponse:
        """Convert Session entity to detailed SessionDetailResponse DTO.
        
        Args:
            session: Session entity
            include_security_events: Whether to include security events
            
        Returns:
            SessionDetailResponse DTO
        """
        # Create base session response
        base_session = SessionMapper.to_response(session)
        
        # Create mock risk assessment (in real implementation, this would come from security service)
        from app.modules.identity.application.dtos.response import (
            RiskAssessmentResponse,
        )
        
        risk_assessment = RiskAssessmentResponse(
            success=True,
            user_id=session.user_id,
            risk_score=session.risk_score,
            risk_level=SessionMapper._get_risk_level(session.risk_score),
            risk_factors=SessionMapper._get_risk_factors(session),
            recommendations=SessionMapper._get_security_recommendations(session),
            requires_action=session.risk_score > 0.7,
            assessed_at=datetime.utcnow()
        )
        
        # Activity summary
        activity_summary = {
            'total_requests': session.activity_count,
            'last_activity': session.last_activity_at.isoformat(),
            'session_duration_minutes': int(
                (session.last_activity_at - session.created_at).total_seconds() / 60
            ),
            'idle_time_minutes': int(
                (datetime.utcnow() - session.last_activity_at).total_seconds() / 60
            ),
            'is_idle': session.is_idle_timeout,
            'recent_activities': session.metadata.get('recent_activities', [])
        }
        
        # Security events
        security_events = []
        if include_security_events:
            from app.modules.identity.application.dtos.response import (
                SecurityEventResponse,
            )
            from app.modules.identity.domain.entities.user.user_enums import (
                SecurityEventType,
            )
            
            for event in session.security_events:
                security_events.append(SecurityEventResponse(
                    id=event.get('id', session.id),  # Use session ID as fallback
                    event_type=SecurityEventType.SUSPICIOUS_ACTIVITY,  # Default type
                    severity=SessionMapper._get_risk_level(0.5),  # Default severity
                    user_id=session.user_id,
                    ip_address=str(session.ip_address) if session.ip_address else None,
                    details=event.get('details', {}),
                    created_at=datetime.fromisoformat(event['timestamp']),
                    resolved=False
                ))
        
        # Permissions snapshot (would be populated by authorization service)
        permissions_snapshot = list(session.flags)
        
        return SessionDetailResponse(
            id=base_session.id,
            session_type=base_session.session_type,
            ip_address=base_session.ip_address,
            user_agent=base_session.user_agent,
            location=base_session.location,
            device_info=base_session.device_info,
            created_at=base_session.created_at,
            last_activity_at=base_session.last_activity_at,
            expires_at=base_session.expires_at,
            is_current=base_session.is_current,
            risk_assessment=risk_assessment,
            activity_summary=activity_summary,
            security_events=security_events,
            permissions_snapshot=permissions_snapshot,
            metadata=session.metadata
        )
    
    @staticmethod
    def to_active_sessions_response(
        sessions: list[Session],
        current_session_id: str | None = None
    ) -> ActiveSessionsResponse:
        """Convert list of Session entities to ActiveSessionsResponse DTO.
        
        Args:
            sessions: List of Session entities
            current_session_id: ID of the current session
            
        Returns:
            ActiveSessionsResponse DTO
        """
        session_responses = []
        for session in sessions:
            is_current = str(session.id) == current_session_id
            session_responses.append(SessionMapper.to_response(session, is_current))
        
        return ActiveSessionsResponse(
            success=True,
            sessions=session_responses,
            total=len(sessions),
            current_session_id=current_session_id
        )
    
    @staticmethod
    def to_concurrent_sessions_response(
        user_id: str,
        sessions: list[Session],
        max_allowed: int = 5
    ) -> ConcurrentSessionsResponse:
        """Convert sessions to ConcurrentSessionsResponse DTO.
        
        Args:
            user_id: User ID
            sessions: List of active sessions
            max_allowed: Maximum allowed concurrent sessions
            
        Returns:
            ConcurrentSessionsResponse DTO
        """
        # Group sessions by type and location
        sessions_by_type = {}
        sessions_by_location = {}
        
        oldest_session = None
        newest_session = None
        
        for session in sessions:
            # Group by type
            session_type = session.session_type.value
            if session_type not in sessions_by_type:
                sessions_by_type[session_type] = 0
            sessions_by_type[session_type] += 1
            
            # Group by location
            location_key = "Unknown"
            if session.geolocation:
                location_key = f"{getattr(session.geolocation, 'city', 'Unknown')}, {getattr(session.geolocation, 'country', 'Unknown')}"
            elif session.ip_address:
                location_key = str(session.ip_address)
            
            if location_key not in sessions_by_location:
                sessions_by_location[location_key] = 0
            sessions_by_location[location_key] += 1
            
            # Track oldest and newest
            if oldest_session is None or session.created_at < oldest_session.created_at:
                oldest_session = session
            if newest_session is None or session.created_at > newest_session.created_at:
                newest_session = session
        
        # Determine if action is required
        requires_action = len(sessions) > max_allowed
        recommended_action = None
        if requires_action:
            recommended_action = f"Consider terminating {len(sessions) - max_allowed} older sessions"
        
        return ConcurrentSessionsResponse(
            success=True,
            user_id=user_id,
            active_sessions=len(sessions),
            max_allowed=max_allowed,
            sessions_by_type=sessions_by_type,
            sessions_by_location=sessions_by_location,
            oldest_session=SessionMapper.to_response(oldest_session) if oldest_session else None,
            newest_session=SessionMapper.to_response(newest_session) if newest_session else None,
            requires_action=requires_action,
            recommended_action=recommended_action
        )
    
    @staticmethod
    def to_transfer_response(
        old_session_id: str,
        new_session_id: str,
        transfer_token: str,
        expires_at: datetime
    ) -> SessionTransferResponse:
        """Create SessionTransferResponse DTO.
        
        Args:
            old_session_id: ID of the session being transferred from
            new_session_id: ID of the new session
            transfer_token: Token for transfer verification
            expires_at: When the transfer token expires
            
        Returns:
            SessionTransferResponse DTO
        """
        return SessionTransferResponse(
            success=True,
            old_session_id=old_session_id,
            new_session_id=new_session_id,
            transfer_token=transfer_token,
            expires_at=expires_at,
            verification_required=True,
            verification_methods=['email', 'sms']
        )
    
    @staticmethod
    def _calculate_expires_at(session: Session) -> datetime:
        """Calculate when the session expires based on its type and activity.
        
        Args:
            session: Session entity
            
        Returns:
            Calculated expiration datetime
        """
        from app.modules.identity.domain.entities.session.session_enums import (
            SessionType,
        )
        
        # Different expiration times based on session type
        timeout_map = {
            SessionType.WEB: timedelta(minutes=30),
            SessionType.MOBILE: timedelta(hours=24),
            SessionType.API: timedelta(hours=1),
            SessionType.SERVICE: timedelta(days=365),
        }
        
        timeout_duration = timeout_map.get(session.session_type, timedelta(minutes=30))
        return session.last_activity_at + timeout_duration
    
    @staticmethod
    def _get_risk_level(risk_score: float):
        """Convert risk score to RiskLevel enum.
        
        Args:
            risk_score: Numeric risk score (0.0 - 1.0)
            
        Returns:
            RiskLevel enum value
        """
        from app.modules.identity.domain.entities.user.user_enums import RiskLevel
        
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        if risk_score >= 0.6:
            return RiskLevel.HIGH
        if risk_score >= 0.4:
            return RiskLevel.MEDIUM
        if risk_score >= 0.2:
            return RiskLevel.LOW
        return RiskLevel.VERY_LOW
    
    @staticmethod
    def _get_risk_factors(session: Session) -> list[str]:
        """Extract risk factors from session.
        
        Args:
            session: Session entity
            
        Returns:
            List of risk factor descriptions
        """
        risk_factors = []
        
        if session.risk_score > 0.7:
            risk_factors.append("High risk score detected")
        
        if session.is_idle_timeout:
            risk_factors.append("Session has been idle for extended period")
        
        if not session.is_trusted:
            risk_factors.append("Session from untrusted device")
        
        if len(session.security_events) > 0:
            risk_factors.append(f"{len(session.security_events)} security events recorded")
        
        if session.requires_mfa and not session.mfa_completed:
            risk_factors.append("MFA required but not completed")
        
        if 'suspicious_activity' in session.flags:
            risk_factors.append("Suspicious activity detected")
        
        return risk_factors
    
    @staticmethod
    def _get_security_recommendations(session: Session) -> list[str]:
        """Generate security recommendations for session.
        
        Args:
            session: Session entity
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        if session.risk_score > 0.7:
            recommendations.append("Consider terminating this session due to high risk score")
        
        if not session.is_trusted:
            recommendations.append("Verify device identity and consider marking as trusted")
        
        if session.requires_mfa and not session.mfa_completed:
            recommendations.append("Complete multi-factor authentication")
        
        if session.is_idle_timeout:
            recommendations.append("Session should be refreshed or terminated")
        
        if len(session.security_events) > 2:
            recommendations.append("Review security events and consider additional verification")
        
        if session.ip_address and hasattr(session.ip_address, 'is_suspicious') and session.ip_address.is_suspicious:
            recommendations.append("IP address may be suspicious - verify user location")
        
        return recommendations