"""Audit session repository implementation.

This module implements the repository for audit sessions that group
related audit entries within a user session.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_session import AuditSession
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.infrastructure.models.audit_models import AuditSessionModel

logger = get_logger(__name__)


class AuditSessionRepository(BaseRepository[AuditSession, UUID]):
    """
    Repository for audit sessions.

    Manages audit sessions that group related audit entries and track
    user activity across operations.
    """

    def __init__(self, session_factory, cache=None):
        """
        Initialize audit session repository.

        Args:
            session_factory: Factory for creating database sessions
            cache: Optional cache implementation
        """
        super().__init__(AuditSession, session_factory, cache)

    async def find_by_id(self, entity_id: UUID) -> AuditSession | None:
        """Find audit session by ID."""
        async with self.operation_context("find_by_id"):
            async with self.get_session() as session:
                stmt = select(AuditSessionModel).where(
                    AuditSessionModel.id == entity_id
                )
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find all audit sessions with pagination."""
        async with self.operation_context("find_all"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditSessionModel)
                    .order_by(AuditSessionModel.created_at.desc())
                    .offset(offset)
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def save(self, entity: AuditSession) -> AuditSession:
        """Save audit session."""
        async with self.operation_context("save"):
            async with self.get_session() as session:
                model = await self._get_or_create_model(session, entity)

                # Update model from entity
                self._update_model_from_entity(model, entity)

                # Add to session and commit
                session.add(model)
                await session.commit()

                # Refresh to get any database-generated values
                await session.refresh(model)

                # Invalidate cache
                await self.invalidate_cache_for_entity(entity.id)

                return self._model_to_entity(model)

    async def delete(self, entity_id: UUID) -> bool:
        """Delete audit session (end the session)."""
        async with self.operation_context("delete"):
            async with self.get_session() as session:
                stmt = select(AuditSessionModel).where(
                    AuditSessionModel.id == entity_id
                )
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return False

                # End the session
                model.is_active = False
                model.ended_at = datetime.utcnow()

                await session.commit()
                await self.invalidate_cache_for_entity(entity_id)

                return True

    async def exists(self, entity_id: UUID) -> bool:
        """Check if audit session exists."""
        async with self.operation_context("exists"):
            async with self.get_session() as session:
                stmt = select(func.count()).where(AuditSessionModel.id == entity_id)
                result = await session.execute(stmt)
                count = result.scalar()
                return count > 0

    async def count(self) -> int:
        """Count total audit sessions."""
        async with self.operation_context("count"):
            async with self.get_session() as session:
                stmt = select(func.count()).select_from(AuditSessionModel)
                result = await session.execute(stmt)
                return result.scalar()

    async def find_active_sessions(
        self, user_id: UUID | None = None, inactive_threshold_minutes: int = 30
    ) -> list[AuditSession]:
        """Find active sessions with optional user filter."""
        async with self.operation_context("find_active_sessions"):
            async with self.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(
                    minutes=inactive_threshold_minutes
                )

                conditions = [
                    AuditSessionModel.is_active is True,
                    AuditSessionModel.last_activity_at >= cutoff_time,
                ]

                if user_id:
                    conditions.append(AuditSessionModel.user_id == user_id)

                stmt = (
                    select(AuditSessionModel)
                    .where(and_(*conditions))
                    .order_by(AuditSessionModel.last_activity_at.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_correlation_id(self, correlation_id: str) -> AuditSession | None:
        """Find session by correlation ID."""
        async with self.operation_context("find_by_correlation_id"):
            async with self.get_session() as session:
                stmt = select(AuditSessionModel).where(
                    AuditSessionModel.correlation_id == correlation_id
                )
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_active_user_session(self, user_id: UUID) -> AuditSession | None:
        """Find the active session for a specific user."""
        async with self.operation_context("find_active_user_session"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditSessionModel)
                    .where(
                        and_(
                            AuditSessionModel.user_id == user_id,
                            AuditSessionModel.is_active is True,
                        )
                    )
                    .order_by(AuditSessionModel.started_at.desc())
                    .limit(1)
                )

                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_user_sessions(
        self,
        user_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        include_inactive: bool = True,
    ) -> list[AuditSession]:
        """Find all sessions for a user within date range."""
        async with self.operation_context("find_user_sessions"):
            async with self.get_session() as session:
                conditions = [AuditSessionModel.user_id == user_id]

                if start_date:
                    conditions.append(AuditSessionModel.started_at >= start_date)
                if end_date:
                    conditions.append(AuditSessionModel.started_at <= end_date)
                if not include_inactive:
                    conditions.append(AuditSessionModel.is_active is True)

                stmt = (
                    select(AuditSessionModel)
                    .where(and_(*conditions))
                    .order_by(AuditSessionModel.started_at.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def update_session_activity(
        self,
        session_id: UUID,
        increment_entry_count: bool = True,
        increment_error_count: bool = False,
    ) -> None:
        """Update session activity timestamp and counters."""
        async with self.operation_context("update_session_activity"):
            async with self.get_session() as session:
                update_values = {"last_activity_at": datetime.utcnow()}

                if increment_entry_count:
                    update_values["entry_count"] = AuditSessionModel.entry_count + 1
                if increment_error_count:
                    update_values["error_count"] = AuditSessionModel.error_count + 1

                stmt = (
                    update(AuditSessionModel)
                    .where(AuditSessionModel.id == session_id)
                    .values(**update_values)
                )

                await session.execute(stmt)
                await session.commit()

                # Invalidate cache
                await self.invalidate_cache_for_entity(session_id)

    async def end_inactive_sessions(self, inactive_threshold_minutes: int = 30) -> int:
        """End sessions that have been inactive beyond threshold."""
        async with self.operation_context("end_inactive_sessions"):
            async with self.get_session() as session:
                cutoff_time = datetime.utcnow() - timedelta(
                    minutes=inactive_threshold_minutes
                )

                stmt = (
                    update(AuditSessionModel)
                    .where(
                        and_(
                            AuditSessionModel.is_active is True,
                            AuditSessionModel.last_activity_at < cutoff_time,
                        )
                    )
                    .values(is_active=False, ended_at=datetime.utcnow())
                )

                result = await session.execute(stmt)
                await session.commit()

                ended_count = result.rowcount

                logger.info(
                    "Ended inactive sessions",
                    count=ended_count,
                    threshold_minutes=inactive_threshold_minutes,
                )

                return ended_count

    async def get_session_statistics(
        self, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get session statistics for a date range."""
        async with self.operation_context("get_session_statistics"):
            async with self.get_session() as session:
                # Base query for date range
                base_conditions = [
                    AuditSessionModel.started_at >= start_date,
                    AuditSessionModel.started_at <= end_date,
                ]

                # Get overall statistics
                stats_query = select(
                    func.count(AuditSessionModel.id).label("total_sessions"),
                    func.count(func.distinct(AuditSessionModel.user_id)).label(
                        "unique_users"
                    ),
                    func.avg(
                        func.extract(
                            "epoch",
                            AuditSessionModel.ended_at - AuditSessionModel.started_at,
                        )
                    ).label("avg_duration_seconds"),
                    func.sum(AuditSessionModel.entry_count).label("total_entries"),
                    func.sum(AuditSessionModel.error_count).label("total_errors"),
                    func.count(
                        func.case((AuditSessionModel.is_active is True, 1), else_=None)
                    ).label("active_sessions"),
                ).where(and_(*base_conditions))

                stats_result = await session.execute(stats_query)
                stats = stats_result.one()

                # Get session type distribution
                type_query = (
                    select(
                        AuditSessionModel.session_type,
                        func.count(AuditSessionModel.id).label("count"),
                    )
                    .where(and_(*base_conditions))
                    .group_by(AuditSessionModel.session_type)
                )

                type_result = await session.execute(type_query)
                type_distribution = {row.session_type: row.count for row in type_result}

                # Get hourly distribution
                hourly_query = (
                    select(
                        func.extract("hour", AuditSessionModel.started_at).label(
                            "hour"
                        ),
                        func.count(AuditSessionModel.id).label("count"),
                    )
                    .where(and_(*base_conditions))
                    .group_by("hour")
                    .order_by("hour")
                )

                hourly_result = await session.execute(hourly_query)
                hourly_distribution = {
                    int(row.hour): row.count for row in hourly_result
                }

                return {
                    "period": {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat(),
                    },
                    "total_sessions": stats.total_sessions,
                    "unique_users": stats.unique_users,
                    "avg_duration_seconds": float(stats.avg_duration_seconds)
                    if stats.avg_duration_seconds
                    else None,
                    "total_entries": stats.total_entries or 0,
                    "total_errors": stats.total_errors or 0,
                    "error_rate": (
                        stats.total_errors / stats.total_entries
                        if stats.total_entries > 0
                        else 0
                    ),
                    "active_sessions": stats.active_sessions,
                    "session_type_distribution": type_distribution,
                    "hourly_distribution": hourly_distribution,
                }

    async def find_by_user_id(
        self, user_id: UUID, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find audit sessions by user ID."""
        async with self.operation_context("find_by_user_id"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditSessionModel)
                    .where(AuditSessionModel.user_id == user_id)
                    .order_by(AuditSessionModel.started_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_active_sessions(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find currently active audit sessions."""
        async with self.operation_context("find_active_sessions"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditSessionModel)
                    .where(AuditSessionModel.is_active is True)
                    .order_by(AuditSessionModel.started_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_completed_sessions(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find completed audit sessions."""
        async with self.operation_context("find_completed_sessions"):
            async with self.get_session() as session:
                conditions = [AuditSessionModel.is_active is False]

                if since:
                    conditions.append(AuditSessionModel.ended_at >= since)

                stmt = (
                    select(AuditSessionModel)
                    .where(and_(*conditions))
                    .order_by(AuditSessionModel.ended_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_failed_sessions(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find failed audit sessions."""
        async with self.operation_context("find_failed_sessions"):
            async with self.get_session() as session:
                conditions = [AuditSessionModel.error_count > 0]

                if since:
                    conditions.append(AuditSessionModel.started_at >= since)

                stmt = (
                    select(AuditSessionModel)
                    .where(and_(*conditions))
                    .order_by(AuditSessionModel.started_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_sessions_by_time_range(
        self, time_range: Any, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions within a time range."""
        async with self.operation_context("find_sessions_by_time_range"):
            async with self.get_session() as session:
                conditions = []

                if hasattr(time_range, "start_time") and time_range.start_time:
                    conditions.append(
                        AuditSessionModel.started_at >= time_range.start_time
                    )
                if hasattr(time_range, "end_time") and time_range.end_time:
                    conditions.append(
                        AuditSessionModel.started_at <= time_range.end_time
                    )

                stmt = select(AuditSessionModel)
                if conditions:
                    stmt = stmt.where(and_(*conditions))
                stmt = stmt.order_by(AuditSessionModel.started_at.desc())

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    # Stub implementations for remaining required methods
    async def find_long_running_sessions(
        self, min_duration_minutes: int = 60, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find long-running audit sessions."""
        # TODO: Implement duration-based filtering
        return []

    async def find_sessions_with_errors(
        self, since: datetime | None = None, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions that encountered errors."""
        return await self.find_failed_sessions(since, limit, offset)

    async def find_sessions_by_entry_count(
        self,
        min_entries: int,
        max_entries: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditSession]:
        """Find sessions by entry count range."""
        # TODO: Implement entry count filtering
        return []

    async def find_orphaned_sessions(
        self, older_than_hours: int = 24
    ) -> list[AuditSession]:
        """Find sessions that appear to be orphaned."""
        # TODO: Implement orphaned session detection
        return []

    async def get_session_statistics(self, session_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific session."""
        # TODO: Implement session statistics
        return None

    async def get_user_session_summary(
        self, user_id: UUID, time_range: Any | None = None
    ) -> dict[str, Any]:
        """Get session summary for a user."""
        # TODO: Implement user session summary
        return {}

    async def get_system_session_statistics(
        self, time_range: Any | None = None
    ) -> dict[str, Any]:
        """Get system-wide session statistics."""
        # TODO: Implement system session statistics
        return {}

    async def count_sessions_by_status(
        self, time_range: Any | None = None
    ) -> dict[str, int]:
        """Count sessions grouped by status."""
        # TODO: Implement status counting
        return {}

    async def count_sessions_by_user(
        self, time_range: Any | None = None, limit: int = 10
    ) -> dict[UUID, int]:
        """Count sessions grouped by user."""
        # TODO: Implement user counting
        return {}

    async def get_average_session_duration(
        self, time_range: Any | None = None
    ) -> float:
        """Get average session duration in minutes."""
        # TODO: Implement average duration calculation
        return 0.0

    async def get_session_duration_distribution(
        self, time_range: Any | None = None
    ) -> dict[str, int]:
        """Get distribution of session durations."""
        # TODO: Implement duration distribution
        return {}

    async def find_concurrent_sessions(
        self, time_point: datetime, limit: int | None = None
    ) -> list[AuditSession]:
        """Find sessions that were active at a specific time."""
        # TODO: Implement concurrent session finding
        return []

    async def get_peak_concurrent_sessions(
        self, time_range: Any, resolution_minutes: int = 60
    ) -> dict[datetime, int]:
        """Get peak concurrent session counts over time."""
        # TODO: Implement peak concurrent calculation
        return {}

    async def cleanup_old_sessions(
        self, older_than_days: int = 90, keep_failed: bool = True
    ) -> int:
        """Clean up old completed sessions."""
        # TODO: Implement cleanup logic
        return 0

    async def force_complete_stale_sessions(
        self, stale_threshold_hours: int = 24
    ) -> int:
        """Force completion of stale active sessions."""
        # TODO: Implement stale session completion
        return 0

    async def get_session_health_report(self) -> dict[str, Any]:
        """Get health report for audit sessions."""
        # TODO: Implement health report
        return {"status": "healthy"}

    async def export_session_data(
        self, session_id: UUID, include_entries: bool = True
    ) -> dict[str, Any]:
        """Export complete session data."""
        # TODO: Implement session export
        return {}

    async def search_sessions(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditSession]:
        """Search sessions by text query."""
        # TODO: Implement session search
        return []

    async def find_sessions_by_ip_address(
        self, ip_address: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions by IP address."""
        # TODO: Implement IP address filtering
        return []

    async def find_sessions_by_user_agent(
        self, user_agent_pattern: str, limit: int | None = None, offset: int = 0
    ) -> list[AuditSession]:
        """Find sessions by user agent pattern."""
        # TODO: Implement user agent filtering
        return []

    async def detect_suspicious_sessions(
        self, time_range: Any | None = None, anomaly_threshold: float = 2.0
    ) -> list[AuditSession]:
        """Detect potentially suspicious session patterns."""
        # TODO: Implement anomaly detection
        return []

    async def get_session_performance_metrics(
        self, time_range: Any | None = None
    ) -> dict[str, Any]:
        """Get performance metrics for sessions."""
        # TODO: Implement performance metrics
        return {}

    async def _get_or_create_model(
        self, session: AsyncSession, entity: AuditSession
    ) -> AuditSessionModel:
        """Get existing model or create new one."""
        if entity.id:
            stmt = select(AuditSessionModel).where(AuditSessionModel.id == entity.id)
            result = await session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return model

        # Create new model
        return AuditSessionModel(id=entity.id)

    def _update_model_from_entity(
        self, model: AuditSessionModel, entity: AuditSession
    ) -> None:
        """Update model fields from entity."""
        model.user_id = entity.user_id
        model.correlation_id = entity.correlation_id
        model.session_type = entity.session_type
        model.ip_address = entity.context.ip_address
        model.user_agent = entity.context.user_agent
        model.is_active = entity.is_active
        model.started_at = entity.started_at
        model.last_activity_at = entity.started_at  # Will be updated with activity
        model.ended_at = entity.ended_at
        model.entry_count = entity.summary.get("entry_count", 0)
        model.error_count = entity.summary.get("failure_count", 0)
        model.context_data = entity.context.to_dict()

    def _model_to_entity(self, model: AuditSessionModel) -> AuditSession:
        """Convert database model to domain entity."""
        # Recreate context from stored data
        context = AuditContext(
            ip_address=model.ip_address,
            user_agent=model.user_agent,
            request_id=model.context_data.get("request_id")
            if model.context_data
            else None,
            additional_data=model.context_data,
        )

        entity = AuditSession(
            user_id=model.user_id,
            correlation_id=model.correlation_id,
            session_type=model.session_type,
            context=context,
            parent_session_id=None,  # Not stored in this model
            entity_id=model.id,
        )

        # Set additional fields
        entity.is_active = model.is_active
        entity.started_at = model.started_at
        entity.ended_at = model.ended_at
        entity.summary["entry_count"] = model.entry_count
        entity.summary["failure_count"] = model.error_count
        entity.summary["success_count"] = model.entry_count - model.error_count

        # Set timestamps
        entity.created_at = model.created_at
        entity.updated_at = model.updated_at

        return entity

    async def _test_database_connectivity(self, session: AsyncSession) -> None:
        """Test database connectivity."""
        from sqlalchemy import text

        async with session.begin():
            from app.core.constants import HEALTH_CHECK_QUERY
            await session.execute(text(HEALTH_CHECK_QUERY))


__all__ = ["AuditSessionRepository"]
