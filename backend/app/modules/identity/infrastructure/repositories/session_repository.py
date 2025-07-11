"""
Session Repository Implementation

SQLModel-based implementation of the session repository interface.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import Session, and_, col, func, select

from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.entities.session.session import (
    Session as DomainSession,
)
from app.modules.identity.domain.entities.session.session_enums import (
    SessionStatus,
)
from app.modules.identity.domain.interfaces.repositories.session.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.specifications.session_specs import (
    SessionSpecification,
)
from app.modules.identity.infrastructure.models.session_model import SessionModel


class SQLSessionRepository(BaseRepository[DomainSession, SessionModel], ISessionRepository):
    """SQLModel implementation of session repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, SessionModel)
    
    async def find_by_id(self, session_id: UUID) -> DomainSession | None:
        """Find session by ID."""
        stmt = select(SessionModel).where(SessionModel.id == session_id)
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_access_token(self, token: str) -> DomainSession | None:
        """Find session by access token."""
        stmt = select(SessionModel).where(SessionModel.access_token == token)
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_refresh_token(self, token: str) -> DomainSession | None:
        """Find session by refresh token."""
        stmt = select(SessionModel).where(SessionModel.refresh_token == token)
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_active_by_user(self, user_id: UUID, limit: int = 100) -> list[DomainSession]:
        """Find active sessions for user."""
        stmt = select(SessionModel).where(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.status == SessionStatus.ACTIVE.value
            )
        ).order_by(SessionModel.last_activity_at.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_by_user(self, user_id: UUID, limit: int = 100) -> list[DomainSession]:
        """Find all sessions for user."""
        stmt = select(SessionModel).where(
            SessionModel.user_id == user_id
        ).order_by(SessionModel.created_at.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_by_device_fingerprint(
        self,
        user_id: UUID,
        fingerprint: str
    ) -> list[DomainSession]:
        """Find sessions by device fingerprint."""
        stmt = select(SessionModel).where(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.device_fingerprint == fingerprint
            )
        ).order_by(SessionModel.created_at.desc())
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def save(self, session: DomainSession) -> None:
        """Save session."""
        model = SessionModel.from_domain(session)
        
        # Check if session exists
        existing = await self.session.get(SessionModel, session.id)
        if existing:
            # Update existing model
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()
    
    async def delete(self, session_id: UUID) -> bool:
        """Delete session by ID."""
        model = await self.session.get(SessionModel, session_id)
        if model:
            await self.session.delete(model)
            await self.session.commit()
            return True
        return False
    
    async def delete_by_user(self, user_id: UUID) -> int:
        """Delete all sessions for user."""
        stmt = select(SessionModel).where(SessionModel.user_id == user_id)
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            await self.session.delete(model)
        
        await self.session.commit()
        return count
    
    async def terminate_by_user(self, user_id: UUID, reason: str) -> int:
        """Terminate all sessions for user."""
        stmt = select(SessionModel).where(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.status == SessionStatus.ACTIVE.value
            )
        )
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            model.status = SessionStatus.TERMINATED.value
            model.metadata = model.metadata or {}
            model.metadata['termination_reason'] = reason
            model.metadata['terminated_at'] = datetime.now(UTC).isoformat()
            model.access_token = ""
            model.refresh_token = None
            self.session.add(model)
        
        await self.session.commit()
        return count
    
    async def count_active_by_user(self, user_id: UUID) -> int:
        """Count active sessions for user."""
        stmt = select(func.count(SessionModel.id)).where(
            and_(
                SessionModel.user_id == user_id,
                SessionModel.status == SessionStatus.ACTIVE.value
            )
        )
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def find_expired(self, limit: int = 1000) -> list[DomainSession]:
        """Find expired sessions."""
        # Sessions that are active but haven't been used recently
        idle_timeout = datetime.now(UTC).replace(hour=datetime.now(UTC).hour - 24)
        
        stmt = select(SessionModel).where(
            and_(
                SessionModel.status == SessionStatus.ACTIVE.value,
                SessionModel.last_activity_at < idle_timeout
            )
        ).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_by_ip_address(
        self,
        ip_address: str,
        limit: int = 100
    ) -> list[DomainSession]:
        """Find sessions by IP address."""
        stmt = select(SessionModel).where(
            SessionModel.ip_address == ip_address
        ).order_by(SessionModel.created_at.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_suspicious(
        self,
        risk_threshold: float = 0.7,
        limit: int = 100
    ) -> list[DomainSession]:
        """Find suspicious sessions."""
        stmt = select(SessionModel).where(
            SessionModel.risk_score >= risk_threshold
        ).order_by(SessionModel.risk_score.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def update_activity(
        self,
        session_id: UUID,
        ip_address: str | None = None
    ) -> None:
        """Update session activity timestamp."""
        model = await self.session.get(SessionModel, session_id)
        if model:
            model.last_activity_at = datetime.now(UTC)
            model.activity_count = (model.activity_count or 0) + 1
            
            if ip_address:
                model.ip_address = ip_address
            
            self.session.add(model)
            await self.session.commit()
    
    async def find_many(
        self,
        specification: SessionSpecification | None = None,
        offset: int = 0,
        limit: int = 100,
        order_by: str | None = None
    ) -> list[DomainSession]:
        """Find sessions matching specification."""
        stmt = select(SessionModel)
        
        # Apply specification if provided
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Apply ordering
        if order_by:
            if order_by.startswith('-'):
                stmt = stmt.order_by(col(SessionModel.__table__.c[order_by[1:]]).desc())
            else:
                stmt = stmt.order_by(col(SessionModel.__table__.c[order_by]))
        else:
            stmt = stmt.order_by(SessionModel.created_at.desc())
        
        # Apply pagination
        stmt = stmt.offset(offset).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def count(self, specification: SessionSpecification | None = None) -> int:
        """Count sessions matching specification."""
        stmt = select(func.count(SessionModel.id))
        
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def bulk_save(self, sessions: list[DomainSession]) -> None:
        """Save multiple sessions in a single transaction."""
        models = [SessionModel.from_domain(session) for session in sessions]
        
        for model in models:
            existing = await self.session.get(SessionModel, model.id)
            if existing:
                for key, value in model.dict(exclude={'id'}).items():
                    setattr(existing, key, value)
                self.session.add(existing)
            else:
                self.session.add(model)
        
        await self.session.commit()
    
    async def cleanup_old_sessions(self, days: int = 30) -> int:
        """Clean up old terminated/expired sessions."""
        cutoff_date = datetime.now(UTC).replace(day=datetime.now(UTC).day - days)
        
        stmt = select(SessionModel).where(
            and_(
                SessionModel.status.in_([
                    SessionStatus.TERMINATED.value,
                    SessionStatus.EXPIRED.value,
                    SessionStatus.REVOKED.value
                ]),
                SessionModel.created_at < cutoff_date
            )
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            await self.session.delete(model)
        
        await self.session.commit()
        return count
    
    def _build_conditions(self, specification: SessionSpecification) -> list[Any]:
        """Build SQLModel conditions from specification."""
        conditions = []
        
        # Map specification criteria to database conditions
        criteria = specification.to_dict()
        
        if criteria.get('user_id'):
            conditions.append(SessionModel.user_id == criteria['user_id'])
        
        if criteria.get('status'):
            if isinstance(criteria['status'], list):
                conditions.append(SessionModel.status.in_([s.value for s in criteria['status']]))
            else:
                conditions.append(SessionModel.status == criteria['status'].value)
        
        if criteria.get('session_type'):
            if isinstance(criteria['session_type'], list):
                conditions.append(SessionModel.session_type.in_([t.value for t in criteria['session_type']]))
            else:
                conditions.append(SessionModel.session_type == criteria['session_type'].value)
        
        if criteria.get('ip_address'):
            conditions.append(SessionModel.ip_address == criteria['ip_address'])
        
        if criteria.get('device_fingerprint'):
            conditions.append(SessionModel.device_fingerprint == criteria['device_fingerprint'])
        
        if criteria.get('is_trusted') is not None:
            conditions.append(SessionModel.is_trusted == criteria['is_trusted'])
        
        if criteria.get('requires_mfa') is not None:
            conditions.append(SessionModel.requires_mfa == criteria['requires_mfa'])
        
        if criteria.get('mfa_completed') is not None:
            conditions.append(SessionModel.mfa_completed == criteria['mfa_completed'])
        
        if criteria.get('risk_score_min') is not None:
            conditions.append(SessionModel.risk_score >= criteria['risk_score_min'])
        
        if criteria.get('risk_score_max') is not None:
            conditions.append(SessionModel.risk_score <= criteria['risk_score_max'])
        
        if criteria.get('created_after'):
            conditions.append(SessionModel.created_at >= criteria['created_after'])
        
        if criteria.get('created_before'):
            conditions.append(SessionModel.created_at <= criteria['created_before'])
        
        if criteria.get('last_activity_after'):
            conditions.append(SessionModel.last_activity_at >= criteria['last_activity_after'])
        
        if criteria.get('last_activity_before'):
            conditions.append(SessionModel.last_activity_at <= criteria['last_activity_before'])
        
        return conditions