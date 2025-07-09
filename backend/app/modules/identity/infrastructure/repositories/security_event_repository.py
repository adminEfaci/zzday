"""
Security Event Repository Implementation

Concrete implementation of the security event repository interface.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.identity.domain.entities.session.security_event import SecurityEvent
from app.modules.identity.domain.enums import RiskLevel, SecurityEventType
from app.modules.identity.domain.enums_security import SecurityEventStatus
from app.modules.identity.domain.interfaces.repositories.security_event_repository import (
    ISecurityEventRepository,
)
from app.modules.identity.domain.value_objects import Geolocation, IpAddress
from app.modules.identity.infrastructure.models.audit_model import SecurityEventModel


class SecurityEventRepository(BaseRepository[SecurityEventModel], ISecurityEventRepository):
    """Repository implementation for security events."""
    
    def __init__(self, session: AsyncSession):
        """Initialize security event repository.
        
        Args:
            session: AsyncIO database session
        """
        super().__init__(SecurityEventModel, session)
    
    async def create(self, event_data: dict) -> UUID:
        """Create new security event.
        
        Args:
            event_data: Security event data including:
                - user_id (optional): User identifier
                - event_type: SecurityEventType enum value
                - description: Event description
                - ip_address (optional): Source IP address
                - user_agent (optional): User agent string
                - metadata (optional): Additional event metadata
                - created_at: Event timestamp
                
        Returns:
            Created event ID
        """
        event_id = uuid4()
        
        # Extract and process IP address if provided
        ip_str = event_data.get("ip_address")
        country = None
        city = None
        latitude = None
        longitude = None
        
        if ip_str:
            try:
                ip_obj = IpAddress(ip_str)
                country = ip_obj.country
                city = ip_obj.city
                latitude = ip_obj.latitude
                longitude = ip_obj.longitude
            except Exception:
                # Invalid IP, store as-is
                pass
        
        # Determine risk level based on event type
        event_type = event_data.get("event_type")
        if isinstance(event_type, str):
            try:
                event_type = SecurityEventType(event_type)
            except ValueError:
                event_type = SecurityEventType.ANOMALOUS_BEHAVIOR
        
        risk_level = self._determine_risk_level(event_type, event_data.get("metadata", {}))
        
        model = SecurityEventModel(
            id=event_id,
            event_type=event_type.value if isinstance(event_type, SecurityEventType) else str(event_type),
            risk_level=risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level),
            status=SecurityEventStatus.PENDING.value,
            timestamp=event_data.get("created_at", datetime.now(UTC)),
            user_id=event_data.get("user_id"),
            session_id=event_data.get("session_id"),
            device_id=event_data.get("device_id"),
            ip_address=ip_str,
            user_agent=event_data.get("user_agent"),
            description=event_data.get("description", ""),
            details=event_data.get("metadata", {}),
            affected_resources=event_data.get("affected_resources", []),
            country=country,
            city=city,
            latitude=latitude,
            longitude=longitude,
            correlation_id=event_data.get("correlation_id"),
            attack_pattern=event_data.get("attack_pattern"),
            source_system=event_data.get("source_system", "identity"),
            requires_review=risk_level.value >= RiskLevel.HIGH.value if isinstance(risk_level, RiskLevel) else True
        )
        
        self.session.add(model)
        await self.session.flush()
        
        return event_id
    
    async def find_by_user(
        self, 
        user_id: UUID, 
        limit: int = 100,
        offset: int = 0
    ) -> list[dict]:
        """Find security events for a user.
        
        Args:
            user_id: User identifier
            limit: Maximum number of events to return
            offset: Number of events to skip
            
        Returns:
            List of security events
        """
        query = (
            select(SecurityEventModel)
            .where(SecurityEventModel.user_id == user_id)
            .order_by(desc(SecurityEventModel.timestamp))
            .limit(limit)
            .offset(offset)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_dict(model) for model in models]
    
    async def find_by_type(
        self, 
        event_type: Any,  # Accept both EventType and SecurityEventType
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[dict]:
        """Find security events by type.
        
        Args:
            event_type: Event type to filter by (EventType or SecurityEventType)
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        # Handle both EventType and SecurityEventType
        event_type_value = event_type.value if hasattr(event_type, 'value') else str(event_type)
        conditions = [SecurityEventModel.event_type == event_type_value]
        
        if start_date:
            conditions.append(SecurityEventModel.timestamp >= start_date)
        if end_date:
            conditions.append(SecurityEventModel.timestamp <= end_date)
        
        query = (
            select(SecurityEventModel)
            .where(and_(*conditions))
            .order_by(desc(SecurityEventModel.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_dict(model) for model in models]
    
    async def find_by_ip(
        self, 
        ip_address: str,
        limit: int = 100
    ) -> list[dict]:
        """Find security events by IP address.
        
        Args:
            ip_address: IP address to filter by
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        query = (
            select(SecurityEventModel)
            .where(SecurityEventModel.ip_address == ip_address)
            .order_by(desc(SecurityEventModel.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_dict(model) for model in models]
    
    async def count_by_user_and_type(
        self, 
        user_id: UUID, 
        event_type: Any,  # Accept both EventType and SecurityEventType
        since: datetime | None = None
    ) -> int:
        """Count security events for a user by type.
        
        Args:
            user_id: User identifier
            event_type: Event type to count (EventType or SecurityEventType)
            since: Optional start date filter
            
        Returns:
            Number of matching events
        """
        # Handle both EventType and SecurityEventType
        event_type_value = event_type.value if hasattr(event_type, 'value') else str(event_type)
        conditions = [
            SecurityEventModel.user_id == user_id,
            SecurityEventModel.event_type == event_type_value
        ]
        
        if since:
            conditions.append(SecurityEventModel.timestamp >= since)
        
        query = select(func.count(SecurityEventModel.id)).where(and_(*conditions))
        
        result = await self.session.execute(query)
        return result.scalar() or 0
    
    async def cleanup_old_events(self, older_than: datetime) -> int:
        """Remove old security events.
        
        Args:
            older_than: Remove events older than this date
            
        Returns:
            Number of events removed
        """
        # Count events to be deleted
        count_query = select(func.count(SecurityEventModel.id)).where(
            SecurityEventModel.timestamp < older_than
        )
        count_result = await self.session.execute(count_query)
        count = count_result.scalar() or 0
        
        # Delete old events
        if count > 0:
            delete_query = (
                SecurityEventModel.__table__.delete()
                .where(SecurityEventModel.timestamp < older_than)
            )
            await self.session.execute(delete_query)
        
        return count
    
    # Additional methods for enhanced functionality
    
    async def get_by_id(self, event_id: UUID) -> SecurityEvent | None:
        """Get security event by ID.
        
        Args:
            event_id: Event identifier
            
        Returns:
            Security event entity or None
        """
        model = await self.get(event_id)
        if not model:
            return None
        
        return self._model_to_entity(model)
    
    async def find_pending_review(
        self,
        risk_level: RiskLevel | None = None,
        limit: int = 50
    ) -> list[SecurityEvent]:
        """Find events pending review.
        
        Args:
            risk_level: Optional risk level filter
            limit: Maximum number of events to return
            
        Returns:
            List of security events pending review
        """
        conditions = [
            SecurityEventModel.status == SecurityEventStatus.PENDING.value,
            SecurityEventModel.requires_review == True
        ]
        
        if risk_level:
            conditions.append(SecurityEventModel.risk_level == risk_level.value)
        
        query = (
            select(SecurityEventModel)
            .where(and_(*conditions))
            .order_by(
                desc(SecurityEventModel.risk_level),
                desc(SecurityEventModel.timestamp)
            )
            .limit(limit)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def find_correlated_events(
        self,
        correlation_id: str
    ) -> list[SecurityEvent]:
        """Find all events with the same correlation ID.
        
        Args:
            correlation_id: Correlation identifier
            
        Returns:
            List of correlated security events
        """
        query = (
            select(SecurityEventModel)
            .where(SecurityEventModel.correlation_id == correlation_id)
            .order_by(SecurityEventModel.timestamp)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def find_related_events(
        self,
        event_id: UUID
    ) -> list[SecurityEvent]:
        """Find events related to a specific event.
        
        Args:
            event_id: Event identifier
            
        Returns:
            List of related security events
        """
        # First get the event
        event_model = await self.get(event_id)
        if not event_model:
            return []
        
        # Find events that reference this event or are referenced by it
        event_id_str = str(event_id)
        query = (
            select(SecurityEventModel)
            .where(
                or_(
                    SecurityEventModel.related_event_ids.contains([event_id_str]),
                    SecurityEventModel.id.in_(event_model.related_event_ids)
                )
            )
            .order_by(SecurityEventModel.timestamp)
        )
        
        result = await self.session.execute(query)
        models = result.scalars().all()
        
        return [self._model_to_entity(model) for model in models]
    
    async def update_status(
        self,
        event_id: UUID,
        status: SecurityEventStatus,
        updated_by: UUID | None = None,
        notes: str | None = None
    ) -> bool:
        """Update security event status.
        
        Args:
            event_id: Event identifier
            status: New status
            updated_by: User making the update
            notes: Optional notes about the update
            
        Returns:
            True if updated successfully
        """
        model = await self.get(event_id)
        if not model:
            return False
        
        model.status = status.value
        model.updated_at = datetime.now(UTC)
        
        if status in [SecurityEventStatus.RESOLVED, SecurityEventStatus.FALSE_POSITIVE]:
            model.resolved_at = datetime.now(UTC)
            model.resolved_by = updated_by
            model.requires_review = False
        
        if status == SecurityEventStatus.INVESTIGATING:
            model.investigated_by = updated_by
        
        if notes and updated_by:
            if not model.investigation_notes:
                model.investigation_notes = []
            model.investigation_notes.append({
                "investigator_id": str(updated_by),
                "timestamp": datetime.now(UTC).isoformat(),
                "note": notes
            })
        
        await self.session.flush()
        return True
    
    async def get_statistics(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> dict[str, Any]:
        """Get security event statistics.
        
        Args:
            start_date: Optional start date filter
            end_date: Optional end date filter
            
        Returns:
            Statistics dictionary
        """
        conditions = []
        if start_date:
            conditions.append(SecurityEventModel.timestamp >= start_date)
        if end_date:
            conditions.append(SecurityEventModel.timestamp <= end_date)
        
        base_query = select(SecurityEventModel)
        if conditions:
            base_query = base_query.where(and_(*conditions))
        
        # Total events
        total_query = select(func.count(SecurityEventModel.id))
        if conditions:
            total_query = total_query.where(and_(*conditions))
        total_result = await self.session.execute(total_query)
        total_events = total_result.scalar() or 0
        
        # Events by status
        status_query = (
            select(
                SecurityEventModel.status,
                func.count(SecurityEventModel.id).label('count')
            )
            .group_by(SecurityEventModel.status)
        )
        if conditions:
            status_query = status_query.where(and_(*conditions))
        status_result = await self.session.execute(status_query)
        events_by_status = {row.status: row.count for row in status_result}
        
        # Events by risk level
        risk_query = (
            select(
                SecurityEventModel.risk_level,
                func.count(SecurityEventModel.id).label('count')
            )
            .group_by(SecurityEventModel.risk_level)
        )
        if conditions:
            risk_query = risk_query.where(and_(*conditions))
        risk_result = await self.session.execute(risk_query)
        events_by_risk = {row.risk_level: row.count for row in risk_result}
        
        # Events by type
        type_query = (
            select(
                SecurityEventModel.event_type,
                func.count(SecurityEventModel.id).label('count')
            )
            .group_by(SecurityEventModel.event_type)
        )
        if conditions:
            type_query = type_query.where(and_(*conditions))
        type_result = await self.session.execute(type_query)
        events_by_type = {row.event_type: row.count for row in type_result}
        
        # Average resolution time
        resolved_query = select(
            func.avg(
                func.extract('epoch', SecurityEventModel.resolved_at - SecurityEventModel.timestamp)
            )
        ).where(
            and_(
                SecurityEventModel.resolved_at.isnot(None),
                *conditions
            )
        )
        resolved_result = await self.session.execute(resolved_query)
        avg_resolution_seconds = resolved_result.scalar()
        avg_resolution_hours = avg_resolution_seconds / 3600 if avg_resolution_seconds else None
        
        return {
            "total_events": total_events,
            "events_by_status": events_by_status,
            "events_by_risk_level": events_by_risk,
            "events_by_type": events_by_type,
            "pending_review": events_by_status.get(SecurityEventStatus.PENDING.value, 0),
            "resolved": events_by_status.get(SecurityEventStatus.RESOLVED.value, 0),
            "false_positives": events_by_status.get(SecurityEventStatus.FALSE_POSITIVE.value, 0),
            "avg_resolution_hours": round(avg_resolution_hours, 2) if avg_resolution_hours else None
        }
    
    def _determine_risk_level(
        self,
        event_type: SecurityEventType,
        metadata: dict[str, Any]
    ) -> RiskLevel:
        """Determine risk level based on event type and metadata.
        
        Args:
            event_type: Type of security event
            metadata: Event metadata
            
        Returns:
            Risk level
        """
        # Critical risk events
        critical_types = {
            SecurityEventType.DATA_EXFILTRATION,
            SecurityEventType.PRIVILEGE_ESCALATION,
            SecurityEventType.UNAUTHORIZED_ACCESS
        }
        if event_type in critical_types:
            return RiskLevel.CRITICAL
        
        # High risk events
        high_risk_types = {
            SecurityEventType.BRUTE_FORCE_ATTACK,
            SecurityEventType.CREDENTIAL_STUFFING,
            SecurityEventType.MALWARE_DETECTION
        }
        if event_type in high_risk_types:
            return RiskLevel.HIGH
        
        # Medium risk events
        medium_risk_types = {
            SecurityEventType.ANOMALOUS_BEHAVIOR,
            SecurityEventType.SUSPICIOUS_LOGIN,
            SecurityEventType.IMPOSSIBLE_TRAVEL,
            SecurityEventType.MULTIPLE_FAILED_ATTEMPTS
        }
        if event_type in medium_risk_types:
            return RiskLevel.MEDIUM
        
        # Low risk events
        return RiskLevel.LOW
    
    def _model_to_dict(self, model: SecurityEventModel) -> dict[str, Any]:
        """Convert model to dictionary.
        
        Args:
            model: Security event model
            
        Returns:
            Dictionary representation
        """
        return {
            "id": str(model.id),
            "event_type": model.event_type,
            "risk_level": model.risk_level,
            "status": model.status,
            "timestamp": model.timestamp.isoformat(),
            "user_id": str(model.user_id) if model.user_id else None,
            "session_id": str(model.session_id) if model.session_id else None,
            "device_id": str(model.device_id) if model.device_id else None,
            "ip_address": model.ip_address,
            "user_agent": model.user_agent,
            "description": model.description,
            "details": model.details,
            "affected_resources": model.affected_resources,
            "country": model.country,
            "city": model.city,
            "investigated_by": str(model.investigated_by) if model.investigated_by else None,
            "investigation_notes": model.investigation_notes,
            "resolved_at": model.resolved_at.isoformat() if model.resolved_at else None,
            "resolved_by": str(model.resolved_by) if model.resolved_by else None,
            "resolution": model.resolution,
            "correlation_id": model.correlation_id,
            "related_event_ids": model.related_event_ids,
            "attack_pattern": model.attack_pattern,
            "alert_sent": model.alert_sent,
            "auto_mitigated": model.auto_mitigated,
            "requires_review": model.requires_review
        }
    
    def _model_to_entity(self, model: SecurityEventModel) -> SecurityEvent:
        """Convert model to domain entity.
        
        Args:
            model: Security event model
            
        Returns:
            Security event entity
        """
        # Create IP address value object if available
        ip_address = None
        if model.ip_address:
            try:
                ip_address = IpAddress(model.ip_address)
            except Exception:
                # Invalid IP, create basic one
                ip_address = IpAddress("0.0.0.0")
        
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
        event = SecurityEvent(
            id=model.id,
            event_type=SecurityEventType(model.event_type),
            risk_level=RiskLevel[model.risk_level.upper()],
            status=SecurityEventStatus(model.status),
            timestamp=model.timestamp,
            user_id=model.user_id,
            ip_address=ip_address,
            user_agent=model.user_agent,
            device_id=model.device_id,
            session_id=model.session_id,
            description=model.description,
            details=model.details,
            affected_resources=model.affected_resources,
            country=model.country,
            city=model.city,
            geolocation=geolocation,
            investigated_by=model.investigated_by,
            investigation_notes=model.investigation_notes,
            resolved_at=model.resolved_at,
            resolved_by=model.resolved_by,
            resolution=model.resolution,
            false_positive_reason=model.false_positive_reason,
            correlation_id=model.correlation_id,
            related_event_ids=[UUID(id_str) for id_str in model.related_event_ids],
            attack_pattern=model.attack_pattern,
            source_system=model.source_system,
            alert_sent=model.alert_sent,
            auto_mitigated=model.auto_mitigated,
            requires_review=model.requires_review,
            metadata=model.metadata
        )
        
        return event