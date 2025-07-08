"""
Extend session command implementation.

Handles extending session expiration time.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    ISessionRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    validate_request,
)
from app.modules.identity.application.dtos.internal import RiskAssessmentResult
from app.modules.identity.application.dtos.request import ExtendSessionRequest
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import Session
from app.modules.identity.domain.enums import AuditAction, RiskLevel, SessionStatus
from app.modules.identity.domain.events import SessionExtended
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    SecurityViolationError,
    SessionExpiredError,
    SessionNotFoundError,
)
from app.modules.identity.domain.services import (
    RiskAssessmentService,
    SecurityService,
    SessionService,
)


class ExtendSessionCommand(Command[BaseResponse]):
    """Command to extend session expiration."""
    
    def __init__(
        self,
        user_id: UUID,
        session_id: UUID,
        extension_minutes: int,
        ip_address: str | None = None,
        user_agent: str | None = None
    ):
        self.user_id = user_id
        self.session_id = session_id
        self.extension_minutes = extension_minutes
        self.ip_address = ip_address
        self.user_agent = user_agent


class ExtendSessionCommandHandler(CommandHandler[ExtendSessionCommand, BaseResponse]):
    """Handler for extending session expiration."""
    
    def __init__(
        self,
        session_repository: ISessionRepository,
        user_repository: IUserRepository,
        session_service: SessionService,
        security_service: SecurityService,
        risk_assessment_service: RiskAssessmentService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._session_repository = session_repository
        self._user_repository = user_repository
        self._session_service = session_service
        self._security_service = security_service
        self._risk_assessment_service = risk_assessment_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.SESSION_EXTENDED,
        resource_type="session",
        resource_id_attr="session_id",
        include_request=True
    )
    @require_auth
    @validate_request(ExtendSessionRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: ExtendSessionCommand) -> BaseResponse:
        """
        Extend session expiration time.
        
        Process:
        1. Load session and validate ownership
        2. Check session status and expiration
        3. Assess security risk
        4. Validate extension limits
        5. Extend session
        6. Update caches
        7. Publish event
        
        Returns:
            BaseResponse with new expiration time
            
        Raises:
            SessionNotFoundError: If session not found
            SessionExpiredError: If session expired
            InvalidOperationError: If invalid extension
            SecurityViolationError: If security risk
        """
        async with self._unit_of_work:
            # 1. Load session
            session = await self._session_repository.get_by_id(command.session_id)
            
            if not session:
                raise SessionNotFoundError(f"Session {command.session_id} not found")
            
            # 2. Verify ownership
            if session.user_id != command.user_id:
                raise InvalidOperationError("Session does not belong to user")
            
            # 3. Check session status
            if session.status != SessionStatus.ACTIVE:
                raise InvalidOperationError(
                    f"Cannot extend {session.status.value} session"
                )
            
            # 4. Check if already expired
            if session.expires_at < datetime.now(UTC):
                raise SessionExpiredError("Session has already expired")
            
            # 5. Validate extension amount
            if command.extension_minutes < 1 or command.extension_minutes > 1440:  # Max 24 hours
                raise InvalidOperationError(
                    "Extension must be between 1 minute and 24 hours"
                )
            
            # 6. Calculate new expiration
            current_remaining = session.expires_at - datetime.now(UTC)
            new_extension = timedelta(minutes=command.extension_minutes)
            total_duration = current_remaining + new_extension
            
            # 7. Check maximum session duration
            max_duration = await self._get_max_session_duration(session)
            if total_duration > max_duration:
                raise InvalidOperationError(
                    f"Total session duration cannot exceed {max_duration.total_seconds() / 3600:.0f} hours"
                )
            
            # 8. Assess security risk
            risk_assessment = await self._assess_extension_risk(
                session=session,
                command=command
            )
            
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                await self._handle_high_risk_extension(session, command, risk_assessment)
                raise SecurityViolationError(
                    "Session extension blocked due to security concerns"
                )
            
            # 9. Extend the session
            old_expiration = session.expires_at
            session.extend(new_extension)
            
            # Update activity
            session.update_activity()
            
            await self._session_repository.update(session)
            
            # 10. Update cache with new expiration
            await self._update_session_cache(session)
            
            # 11. Log if high risk
            if risk_assessment.risk_level == RiskLevel.HIGH:
                await self._security_service.log_security_event(
                    user_id=session.user_id,
                    event_type="high_risk_session_extension",
                    ip_address=command.ip_address,
                    details={
                        "session_id": str(session.id),
                        "risk_factors": risk_assessment.risk_factors,
                        "extension_minutes": command.extension_minutes
                    }
                )
            
            # 12. Publish event
            await self._event_bus.publish(
                SessionExtended(
                    aggregate_id=session.user_id,
                    session_id=session.id,
                    old_expiration=old_expiration,
                    new_expiration=session.expires_at,
                    extended_by_minutes=command.extension_minutes
                )
            )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message=f"Session extended by {command.extension_minutes} minutes. " +
                       f"New expiration: {session.expires_at.strftime('%Y-%m-%d %H:%M UTC')}"
            )
    
    async def _get_max_session_duration(self, session: Session) -> timedelta:
        """Get maximum allowed session duration."""
        # Load user to check for special policies
        user = await self._user_repository.get_by_id(session.user_id)
        
        # Different limits based on session type and user
        if session.session_type.value == "api":
            return timedelta(days=90)  # API sessions can be longer
        if user and user.is_admin:
            return timedelta(hours=12)  # Admins get shorter sessions
        return timedelta(days=7)  # Regular users
    
    async def _assess_extension_risk(
        self,
        session: Session,
        command: ExtendSessionCommand
    ) -> RiskAssessmentResult:
        """Assess risk of extending session."""
        risk_factors = []
        risk_score = 0.0
        
        # Check if IP changed
        if command.ip_address and session.ip_address:
            if command.ip_address != session.ip_address:
                risk_factors.append("ip_address_changed")
                risk_score += 0.4
        
        # Check if user agent changed
        if command.user_agent and session.user_agent:
            if command.user_agent != session.user_agent:
                risk_factors.append("user_agent_changed")
                risk_score += 0.3
        
        # Check session age
        session_age = datetime.now(UTC) - session.created_at
        if session_age > timedelta(days=30):
            risk_factors.append("old_session")
            risk_score += 0.2
        
        # Check extension frequency
        if session.extension_count > 5:
            risk_factors.append("frequent_extensions")
            risk_score += 0.3
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return RiskAssessmentResult(
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors
        )
    
    async def _handle_high_risk_extension(
        self,
        session: Session,
        command: ExtendSessionCommand,
        risk_assessment: RiskAssessmentResult
    ) -> None:
        """Handle high-risk session extension attempt."""
        await self._security_service.log_security_incident(
            incident_type="suspicious_session_extension",
            severity=risk_assessment.risk_level,
            user_id=session.user_id,
            details={
                "session_id": str(session.id),
                "risk_factors": risk_assessment.risk_factors,
                "extension_requested": command.extension_minutes,
                "session_ip": session.ip_address,
                "request_ip": command.ip_address
            }
        )
    
    async def _update_session_cache(self, session: Session) -> None:
        """Update session cache with new expiration."""
        # Calculate TTL based on session expiration
        ttl = int((session.expires_at - datetime.now(UTC)).total_seconds())
        
        await self._cache_service.set(
            key=f"session:{session.id}",
            value=session.to_dict(),
            ttl=ttl
        )