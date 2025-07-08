"""
Login Attempt Repository Implementation

Concrete implementation of the login attempt repository interface.
"""

from datetime import datetime, timedelta, UTC
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.infrastructure.repository import BaseRepository
from app.modules.identity.domain.entities.admin.login_attempt import LoginAttempt, RiskIndicator
from app.modules.identity.domain.enums import LoginFailureReason
from app.modules.identity.domain.interfaces.repositories.login_attempt_repository import ILoginAttemptRepository
from app.modules.identity.domain.value_objects import IpAddress, Geolocation
from app.modules.identity.infrastructure.models.audit_model import LoginAttemptModel


class LoginAttemptRepository(BaseRepository[LoginAttemptModel], ILoginAttemptRepository):
    """Repository implementation for login attempts."""
    
    def __init__(self, session: AsyncSession):
        """Initialize login attempt repository.
        
        Args:
            session: AsyncIO database session
        """
        super().__init__(LoginAttemptModel, session)
    
    async def create(
        self, 
        email: str,
        ip_address: str,
        user_agent: str | None = None,
        user_id: UUID | None = None,
        success: bool = False,
        failure_reason: LoginFailureReason | None = None
    ) -> UUID:
        """Record login attempt.
        
        Args:
            email: Email address used for login
            ip_address: Source IP address
            user_agent: User agent string
            user_id: User ID if user was found
            success: Whether login was successful
            failure_reason: Reason for failure if applicable
            
        Returns:
            Created attempt ID
        """
        attempt_id = uuid4()
        
        # Parse IP address to get geolocation data
        ip_obj = IpAddress(ip_address)
        
        model = LoginAttemptModel(
            id=attempt_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user_id,
            success=success,
            failure_reason=failure_reason.value if failure_reason else None,
            timestamp=datetime.now(UTC),
            # Extract geolocation data from IP
            country=ip_obj.country,
            city=ip_obj.city,
            latitude=ip_obj.latitude,
            longitude=ip_obj.longitude,
            isp=ip_obj.isp,
            organization=ip_obj.organization
        )
        
        self.session.add(model)
        await self.session.flush()
        
        return attempt_id
    
    async def count_failed_attempts(
        self, 
        email: str,
        since: datetime | None = None
    ) -> int:
        """Count failed login attempts for email.
        
        Args:
            email: Email address
            since: Count attempts since this time
            
        Returns:
            Number of failed attempts
        """
        query = select(func.count(LoginAttemptModel.id)).where(
            and_(
                LoginAttemptModel.email == email,
                LoginAttemptModel.success == False
            )
        )
        
        if since:
            query = query.where(LoginAttemptModel.timestamp >= since)
        
        result = await self.session.execute(query)
        return result.scalar() or 0
    
    async def count_failed_attempts_by_ip(
        self, 
        ip_address: str,
        since: datetime | None = None
    ) -> int:
        """Count failed login attempts by IP.
        
        Args:
            ip_address: IP address
            since: Count attempts since this time
            
        Returns:
            Number of failed attempts
        """
        query = select(func.count(LoginAttemptModel.id)).where(
            and_(
                LoginAttemptModel.ip_address == ip_address,
                LoginAttemptModel.success == False
            )
        )
        
        if since:
            query = query.where(LoginAttemptModel.timestamp >= since)
        
        result = await self.session.execute(query)
        return result.scalar() or 0
    
    async def find_recent_attempts(
        self, 
        email: str,
        limit: int = 10
    ) -> list[dict]:
        """Find recent login attempts for email.
        
        Args:
            email: Email address
            limit: Maximum number of attempts to return
            
        Returns:
            List of recent attempts
        """
        query = (
            select(LoginAttemptModel)
            .where(LoginAttemptModel.email == email)
            .order_by(desc(LoginAttemptModel.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_dict(model) for model in models]
    
    async def find_successful_logins(
        self, 
        user_id: UUID,
        limit: int = 10
    ) -> list[dict]:
        """Find recent successful logins for user.
        
        Args:
            user_id: User identifier
            limit: Maximum number of logins to return
            
        Returns:
            List of successful logins
        """
        query = (
            select(LoginAttemptModel)
            .where(
                and_(
                    LoginAttemptModel.user_id == user_id,
                    LoginAttemptModel.success == True
                )
            )
            .order_by(desc(LoginAttemptModel.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_dict(model) for model in models]
    
    async def cleanup_old_attempts(self, older_than: datetime) -> int:
        """Remove old login attempts.
        
        Args:
            older_than: Remove attempts older than this date
            
        Returns:
            Number of attempts removed
        """
        # Count attempts to be deleted
        count_query = select(func.count(LoginAttemptModel.id)).where(
            LoginAttemptModel.timestamp < older_than
        )
        count_result = await self.session.execute(count_query)
        count = count_result.scalar() or 0
        
        # Delete old attempts
        if count > 0:
            delete_query = (
                LoginAttemptModel.__table__.delete()
                .where(LoginAttemptModel.timestamp < older_than)
            )
            await self.session.execute(delete_query)
        
        return count
    
    # Additional methods for enhanced functionality
    
    async def get_by_id(self, attempt_id: UUID) -> LoginAttempt | None:
        """Get login attempt by ID.
        
        Args:
            attempt_id: Attempt identifier
            
        Returns:
            Login attempt entity or None
        """
        model = await self.get(attempt_id)
        if not model:
            return None
        
        return self._model_to_entity(model)
    
    async def find_by_session(self, session_id: UUID) -> list[LoginAttempt]:
        """Find login attempts associated with a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of login attempts
        """
        query = (
            select(LoginAttemptModel)
            .where(LoginAttemptModel.session_id == session_id)
            .order_by(desc(LoginAttemptModel.timestamp))
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def find_suspicious_attempts(
        self,
        since: datetime | None = None,
        risk_threshold: float = 0.7,
        limit: int = 100
    ) -> list[LoginAttempt]:
        """Find suspicious login attempts.
        
        Args:
            since: Find attempts since this time
            risk_threshold: Minimum risk score
            limit: Maximum number of attempts to return
            
        Returns:
            List of suspicious attempts
        """
        query = (
            select(LoginAttemptModel)
            .where(LoginAttemptModel.risk_score >= risk_threshold)
            .order_by(desc(LoginAttemptModel.risk_score), desc(LoginAttemptModel.timestamp))
            .limit(limit)
        )
        
        if since:
            query = query.where(LoginAttemptModel.timestamp >= since)
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def find_by_device_fingerprint(
        self,
        device_fingerprint: str,
        limit: int = 50
    ) -> list[LoginAttempt]:
        """Find login attempts by device fingerprint.
        
        Args:
            device_fingerprint: Device fingerprint
            limit: Maximum number of attempts to return
            
        Returns:
            List of login attempts
        """
        query = (
            select(LoginAttemptModel)
            .where(LoginAttemptModel.device_fingerprint == device_fingerprint)
            .order_by(desc(LoginAttemptModel.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def get_unique_ips_count(
        self,
        email: str,
        since: datetime | None = None
    ) -> int:
        """Count unique IPs used by email.
        
        Args:
            email: Email address
            since: Count IPs since this time
            
        Returns:
            Number of unique IPs
        """
        query = (
            select(func.count(func.distinct(LoginAttemptModel.ip_address)))
            .where(LoginAttemptModel.email == email)
        )
        
        if since:
            query = query.where(LoginAttemptModel.timestamp >= since)
        
        result = await self.session.execute(query)
        return result.scalar() or 0
    
    async def get_attack_statistics(
        self,
        time_window: timedelta = timedelta(hours=24)
    ) -> dict[str, Any]:
        """Get attack statistics for monitoring.
        
        Args:
            time_window: Time window for statistics
            
        Returns:
            Attack statistics
        """
        since = datetime.now(UTC) - time_window
        
        # Total attempts
        total_query = select(func.count(LoginAttemptModel.id)).where(
            LoginAttemptModel.timestamp >= since
        )
        total_result = await self.session.execute(total_query)
        total_attempts = total_result.scalar() or 0
        
        # Failed attempts
        failed_query = select(func.count(LoginAttemptModel.id)).where(
            and_(
                LoginAttemptModel.timestamp >= since,
                LoginAttemptModel.success == False
            )
        )
        failed_result = await self.session.execute(failed_query)
        failed_attempts = failed_result.scalar() or 0
        
        # Unique IPs
        unique_ips_query = select(
            func.count(func.distinct(LoginAttemptModel.ip_address))
        ).where(LoginAttemptModel.timestamp >= since)
        unique_ips_result = await self.session.execute(unique_ips_query)
        unique_ips = unique_ips_result.scalar() or 0
        
        # High risk attempts
        high_risk_query = select(func.count(LoginAttemptModel.id)).where(
            and_(
                LoginAttemptModel.timestamp >= since,
                LoginAttemptModel.risk_score >= 0.7
            )
        )
        high_risk_result = await self.session.execute(high_risk_query)
        high_risk_attempts = high_risk_result.scalar() or 0
        
        # Attack patterns
        attack_pattern_query = (
            select(
                LoginAttemptModel.attack_pattern,
                func.count(LoginAttemptModel.id).label('count')
            )
            .where(
                and_(
                    LoginAttemptModel.timestamp >= since,
                    LoginAttemptModel.attack_pattern.isnot(None)
                )
            )
            .group_by(LoginAttemptModel.attack_pattern)
        )
        attack_pattern_result = await self.session.execute(attack_pattern_query)
        attack_patterns = {
            row.attack_pattern: row.count 
            for row in attack_pattern_result
        }
        
        return {
            "total_attempts": total_attempts,
            "failed_attempts": failed_attempts,
            "success_rate": (total_attempts - failed_attempts) / total_attempts if total_attempts > 0 else 0,
            "unique_ips": unique_ips,
            "high_risk_attempts": high_risk_attempts,
            "attack_patterns": attack_patterns,
            "time_window_hours": time_window.total_seconds() / 3600
        }
    
    def _model_to_dict(self, model: LoginAttemptModel) -> dict[str, Any]:
        """Convert model to dictionary.
        
        Args:
            model: Login attempt model
            
        Returns:
            Dictionary representation
        """
        return {
            "id": str(model.id),
            "email": model.email,
            "user_id": str(model.user_id) if model.user_id else None,
            "session_id": str(model.session_id) if model.session_id else None,
            "success": model.success,
            "failure_reason": model.failure_reason,
            "timestamp": model.timestamp.isoformat(),
            "ip_address": model.ip_address,
            "user_agent": model.user_agent,
            "device_fingerprint": model.device_fingerprint,
            "mfa_used": model.mfa_used,
            "country": model.country,
            "city": model.city,
            "risk_score": model.risk_score,
            "risk_indicators": model.risk_indicators,
            "is_known_device": model.is_known_device,
            "is_known_location": model.is_known_location,
            "attack_pattern": model.attack_pattern
        }
    
    def _model_to_entity(self, model: LoginAttemptModel) -> LoginAttempt:
        """Convert model to domain entity.
        
        Args:
            model: Login attempt model
            
        Returns:
            Login attempt entity
        """
        # Create IP address value object
        ip_address = IpAddress(model.ip_address)
        
        # Create geolocation if coordinates are available
        geolocation = None
        if model.latitude is not None and model.longitude is not None:
            geolocation = Geolocation(
                latitude=model.latitude,
                longitude=model.longitude,
                country=model.country,
                city=model.city
            )
        
        # Create entity
        attempt = LoginAttempt(
            id=model.id,
            email=model.email,
            ip_address=ip_address,
            user_agent=model.user_agent or "",
            success=model.success,
            failure_reason=LoginFailureReason(model.failure_reason) if model.failure_reason else None,
            risk_score=model.risk_score,
            timestamp=model.timestamp,
            user_id=model.user_id,
            session_id=model.session_id,
            mfa_used=model.mfa_used,
            country=model.country,
            city=model.city,
            device_fingerprint=model.device_fingerprint,
            geolocation=geolocation,
            risk_indicators={RiskIndicator(ind) for ind in model.risk_indicators},
            risk_breakdown=model.risk_breakdown,
            login_velocity=model.login_velocity,
            unique_ips_used=model.unique_ips_used,
            failed_attempts_24h=model.failed_attempts_24h,
            last_successful_login=model.last_successful_login,
            typical_login_hours=model.typical_login_hours,
            device_trust_score=model.device_trust_score,
            location_trust_score=model.location_trust_score,
            is_known_device=model.is_known_device,
            is_known_location=model.is_known_location,
            is_distributed_attack=model.is_distributed_attack,
            attack_pattern=model.attack_pattern,
            credential_stuffing_score=model.credential_stuffing_score,
            ml_risk_score=model.ml_risk_score,
            ml_confidence=model.ml_confidence,
            ml_features=model.ml_features
        )
        
        return attempt