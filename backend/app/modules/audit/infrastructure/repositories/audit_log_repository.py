"""Audit log repository implementation with partitioning support.

This module implements the repository for audit logs with support for
time-based partitioning and efficient querying at scale.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.infrastructure.repository import BaseRepository
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.enums.audit_enums import AuditStatus, RetentionPolicy
from app.modules.audit.infrastructure.models.audit_models import (
    AuditEntryModel,
    AuditLogModel,
)

logger = get_logger(__name__)


class AuditLogRepository(BaseRepository[AuditLog, UUID]):
    """
    Repository for audit logs with partitioning and archival support.

    Provides efficient access to audit logs with support for time-based
    partitioning, bulk operations, and archival queries.
    """

    def __init__(self, session_factory, cache=None):
        """
        Initialize audit log repository.

        Args:
            session_factory: Factory for creating database sessions
            cache: Optional cache implementation
        """
        super().__init__(AuditLog, session_factory, cache)

    async def find_by_id(self, entity_id: UUID) -> AuditLog | None:
        """Find audit log by ID."""
        async with self.operation_context("find_by_id"):
            async with self.get_session() as session:
                # Query with eager loading of relationships
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.id == entity_id)
                    .options(selectinload(AuditLogModel.entries))
                )

                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditLog]:
        """Find all audit logs with pagination."""
        async with self.operation_context("find_all"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .order_by(AuditLogModel.created_at.desc())
                    .offset(offset)
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def save(self, entity: AuditLog) -> AuditLog:
        """Save audit log."""
        async with self.operation_context("save"):
            async with self.get_session() as session:
                model = await self._get_or_create_model(session, entity)

                # Update model from entity
                self._update_model_from_entity(model, entity)

                # Add to session and flush
                session.add(model)
                await session.flush()

                # Refresh to get any database-generated values
                await session.refresh(model)

                # Commit transaction
                await session.commit()

                # Invalidate cache
                await self.invalidate_cache_for_entity(entity.id)

                return self._model_to_entity(model)

    async def delete(self, entity_id: UUID) -> bool:
        """Delete audit log (soft delete by archiving)."""
        async with self.operation_context("delete"):
            async with self.get_session() as session:
                stmt = select(AuditLogModel).where(AuditLogModel.id == entity_id)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return False

                # Soft delete by setting status to archived
                model.status = AuditStatus.ARCHIVED
                model.archived_at = datetime.utcnow()

                await session.commit()
                await self.invalidate_cache_for_entity(entity_id)

                return True

    async def exists(self, entity_id: UUID) -> bool:
        """Check if audit log exists."""
        async with self.operation_context("exists"):
            async with self.get_session() as session:
                stmt = select(func.count()).where(AuditLogModel.id == entity_id)
                result = await session.execute(stmt)
                count = result.scalar()
                return count > 0

    async def count(self) -> int:
        """Count total audit logs."""
        async with self.operation_context("count"):
            async with self.get_session() as session:
                stmt = select(func.count()).select_from(AuditLogModel)
                result = await session.execute(stmt)
                return result.scalar()

    async def find_active_logs(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditLog]:
        """Find active audit logs."""
        async with self.operation_context("find_active_logs"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.status == AuditStatus.ACTIVE)
                    .order_by(AuditLogModel.created_at.desc())
                    .offset(offset)
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_expired_logs(
        self, as_of_date: datetime | None = None
    ) -> list[AuditLog]:
        """Find logs that have exceeded their retention period."""
        async with self.operation_context("find_expired_logs"):
            if not as_of_date:
                as_of_date = datetime.utcnow()

            async with self.get_session() as session:
                # Build conditions for each retention policy
                conditions = []

                for policy in RetentionPolicy:
                    if not policy.is_permanent():
                        days = policy.get_retention_days()
                        expiry_date = as_of_date - timedelta(days=days)

                        conditions.append(
                            and_(
                                AuditLogModel.retention_policy == policy,
                                AuditLogModel.last_entry_at < expiry_date,
                            )
                        )

                if not conditions:
                    return []

                stmt = select(AuditLogModel).where(
                    and_(AuditLogModel.status == AuditStatus.ACTIVE, or_(*conditions))
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_logs_pending_archive(self) -> list[AuditLog]:
        """Find logs that are pending archival."""
        async with self.operation_context("find_logs_pending_archive"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.status == AuditStatus.PENDING_ARCHIVE)
                    .order_by(AuditLogModel.created_at)
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_date_range(
        self, start_date: datetime, end_date: datetime, include_archived: bool = False
    ) -> list[AuditLog]:
        """Find logs within a date range."""
        async with self.operation_context("find_by_date_range"):
            async with self.get_session() as session:
                conditions = [
                    AuditLogModel.created_at >= start_date,
                    AuditLogModel.created_at <= end_date,
                ]

                if not include_archived:
                    conditions.append(AuditLogModel.status != AuditStatus.ARCHIVED)

                stmt = (
                    select(AuditLogModel)
                    .where(and_(*conditions))
                    .order_by(AuditLogModel.created_at)
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def get_statistics_by_period(
        self, start_date: datetime, end_date: datetime, group_by: str = "day"
    ) -> dict[str, Any]:
        """Get audit statistics grouped by time period."""
        async with self.operation_context("get_statistics_by_period"):
            async with self.get_session() as session:
                # Determine date truncation based on grouping
                if group_by == "hour":
                    date_trunc = func.date_trunc("hour", AuditEntryModel.created_at)
                elif group_by == "day":
                    date_trunc = func.date_trunc("day", AuditEntryModel.created_at)
                elif group_by == "week":
                    date_trunc = func.date_trunc("week", AuditEntryModel.created_at)
                elif group_by == "month":
                    date_trunc = func.date_trunc("month", AuditEntryModel.created_at)
                else:
                    raise ValueError(f"Invalid group_by value: {group_by}")

                # Query for entry counts and statistics
                stmt = (
                    select(
                        date_trunc.label("period"),
                        func.count(AuditEntryModel.id).label("entry_count"),
                        func.count(func.distinct(AuditEntryModel.user_id)).label(
                            "unique_users"
                        ),
                        func.count(func.distinct(AuditEntryModel.session_id)).label(
                            "unique_sessions"
                        ),
                        func.sum(
                            func.case(
                                (AuditEntryModel.outcome == "failure", 1), else_=0
                            )
                        ).label("failure_count"),
                        func.avg(AuditEntryModel.duration_ms).label("avg_duration_ms"),
                    )
                    .where(
                        and_(
                            AuditEntryModel.created_at >= start_date,
                            AuditEntryModel.created_at <= end_date,
                        )
                    )
                    .group_by(date_trunc)
                    .order_by(date_trunc)
                )

                result = await session.execute(stmt)
                rows = result.all()

                # Format results
                statistics = {
                    "period": group_by,
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "data": [],
                }

                for row in rows:
                    statistics["data"].append(
                        {
                            "period": row.period.isoformat(),
                            "entry_count": row.entry_count,
                            "unique_users": row.unique_users,
                            "unique_sessions": row.unique_sessions,
                            "failure_count": row.failure_count,
                            "failure_rate": row.failure_count / row.entry_count
                            if row.entry_count > 0
                            else 0,
                            "avg_duration_ms": float(row.avg_duration_ms)
                            if row.avg_duration_ms
                            else None,
                        }
                    )

                return statistics

    async def create_partition(self, partition_date: datetime) -> None:
        """Create a new partition for the given date."""
        async with self.operation_context("create_partition"):
            async with self.get_session() as session:
                # Create monthly partition for audit_logs
                partition_name = (
                    f"audit_logs_{partition_date.year}_{partition_date.month:02d}"
                )
                next_month = (
                    partition_date.replace(day=1) + timedelta(days=32)
                ).replace(day=1)

                sql = text(
                    f"""
                    CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_logs
                    FOR VALUES FROM ('{partition_date.strftime('%Y-%m-%d')}')
                    TO ('{next_month.strftime('%Y-%m-%d')}');
                """
                )

                await session.execute(sql)
                await session.commit()

                logger.info(
                    "Created audit log partition",
                    partition_name=partition_name,
                    date_range=f"{partition_date.strftime('%Y-%m-%d')} to {next_month.strftime('%Y-%m-%d')}",
                )

    async def drop_old_partitions(self, retention_days: int) -> int:
        """Drop partitions older than retention period."""
        async with self.operation_context("drop_old_partitions"):
            async with self.get_session() as session:
                cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

                # Get list of partitions to drop
                sql = text(
                    """
                    SELECT tablename 
                    FROM pg_tables 
                    WHERE schemaname = 'public' 
                    AND tablename LIKE 'audit_logs_%'
                    AND tablename < :cutoff_pattern
                    ORDER BY tablename;
                """
                )

                cutoff_pattern = (
                    f"audit_logs_{cutoff_date.year}_{cutoff_date.month:02d}"
                )
                result = await session.execute(sql, {"cutoff_pattern": cutoff_pattern})
                partitions = [row[0] for row in result]

                # Drop each partition
                dropped_count = 0
                for partition in partitions:
                    drop_sql = text(f"DROP TABLE IF EXISTS {partition};")
                    await session.execute(drop_sql)
                    dropped_count += 1

                    logger.info(
                        "Dropped old audit log partition", partition_name=partition
                    )

                await session.commit()
                return dropped_count

    async def find_active(self) -> AuditLog | None:
        """Find the currently active audit log."""
        async with self.operation_context("find_active"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.status == AuditStatus.ACTIVE)
                    .order_by(AuditLogModel.created_at.desc())
                    .limit(1)
                )

                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if model:
                    return self._model_to_entity(model)
                return None

    async def get_statistics(self) -> dict[str, Any]:
        """Get overall audit statistics."""
        async with self.operation_context("get_statistics"):
            async with self.get_session() as session:
                # Get total logs count
                total_stmt = select(func.count()).select_from(AuditLogModel)
                total_result = await session.execute(total_stmt)
                total_logs = total_result.scalar() or 0

                # Get logs by status
                status_stmt = select(AuditLogModel.status, func.count()).group_by(
                    AuditLogModel.status
                )
                status_result = await session.execute(status_stmt)
                status_counts = {row[0]: row[1] for row in status_result}

                # Get total entries count
                entries_stmt = select(func.sum(AuditLogModel.entry_count))
                entries_result = await session.execute(entries_stmt)
                total_entries = entries_result.scalar() or 0

                # Get date range
                date_stmt = select(
                    func.min(AuditLogModel.created_at),
                    func.max(AuditLogModel.last_entry_at),
                )
                date_result = await session.execute(date_stmt)
                date_row = date_result.one()

                return {
                    "total_logs": total_logs,
                    "status_counts": status_counts,
                    "total_entries": total_entries,
                    "date_range": {
                        "start": date_row[0].isoformat() if date_row[0] else None,
                        "end": date_row[1].isoformat() if date_row[1] else None,
                    },
                    "active_logs": status_counts.get(AuditStatus.ACTIVE, 0),
                    "archived_logs": status_counts.get(AuditStatus.ARCHIVED, 0),
                }

    async def find_by_title(self, title: str) -> AuditLog | None:
        """Find audit log by title."""
        async with self.operation_context("find_by_title"):
            async with self.get_session() as session:
                stmt = select(AuditLogModel).where(AuditLogModel.title == title)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if model:
                    return self._model_to_entity(model)
                return None

    async def find_by_status(self, status: AuditStatus) -> list[AuditLog]:
        """Find audit logs by status."""
        async with self.operation_context("find_by_status"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.status == status)
                    .order_by(AuditLogModel.created_at.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_retention_policy(self, policy: RetentionPolicy) -> list[AuditLog]:
        """Find audit logs by retention policy."""
        async with self.operation_context("find_by_retention_policy"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.retention_policy == policy)
                    .order_by(AuditLogModel.created_at.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_full_logs(self, max_entries: int | None = None) -> list[AuditLog]:
        """Find audit logs that are at or near capacity."""
        async with self.operation_context("find_full_logs"):
            async with self.get_session() as session:
                # Default max entries if not specified
                threshold = max_entries or 10000

                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.entry_count >= threshold * 0.9)  # 90% full
                    .order_by(AuditLogModel.entry_count.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_logs_for_archival(
        self, min_age_days: int = 30, min_entries: int = 1000
    ) -> list[AuditLog]:
        """Find logs ready for archival."""
        async with self.operation_context("find_logs_for_archival"):
            async with self.get_session() as session:
                age_threshold = datetime.utcnow() - timedelta(days=min_age_days)

                stmt = (
                    select(AuditLogModel)
                    .where(
                        and_(
                            AuditLogModel.status == AuditStatus.ACTIVE,
                            AuditLogModel.created_at <= age_threshold,
                            AuditLogModel.entry_count >= min_entries,
                        )
                    )
                    .order_by(AuditLogModel.created_at)
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_logs_by_time_range(
        self, time_range: Any, include_archived: bool = False
    ) -> list[AuditLog]:
        """Find logs with entries in the specified time range."""
        async with self.operation_context("find_logs_by_time_range"):
            async with self.get_session() as session:
                conditions = []

                if hasattr(time_range, "start_time") and time_range.start_time:
                    conditions.append(
                        AuditLogModel.last_entry_at >= time_range.start_time
                    )
                if hasattr(time_range, "end_time") and time_range.end_time:
                    conditions.append(AuditLogModel.created_at <= time_range.end_time)

                if not include_archived:
                    conditions.append(AuditLogModel.status != AuditStatus.ARCHIVED)

                stmt = select(AuditLogModel)
                if conditions:
                    stmt = stmt.where(and_(*conditions))
                stmt = stmt.order_by(AuditLogModel.created_at.desc())

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_logs_by_owner(self, owner_id: UUID) -> list[AuditLog]:
        """Find logs created by a specific user."""
        async with self.operation_context("find_logs_by_owner"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.created_by == owner_id)
                    .order_by(AuditLogModel.created_at.desc())
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def get_log_statistics(self, log_id: UUID) -> dict[str, Any] | None:
        """Get statistics for a specific log."""
        async with self.operation_context("get_log_statistics"):
            async with self.get_session() as session:
                stmt = select(AuditLogModel).where(AuditLogModel.id == log_id)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return {
                    "log_id": str(model.id),
                    "title": model.title,
                    "status": model.status,
                    "entry_count": model.entry_count,
                    "created_at": model.created_at.isoformat(),
                    "last_entry_at": model.last_entry_at.isoformat()
                    if model.last_entry_at
                    else None,
                    "retention_policy": model.retention_policy,
                    "is_archived": model.status == AuditStatus.ARCHIVED,
                    "archive_date": model.archived_at.isoformat()
                    if model.archived_at
                    else None,
                }

    async def get_system_statistics(self) -> dict[str, Any]:
        """Get system-wide audit log statistics."""
        # This method delegates to get_statistics for now
        return await self.get_statistics()

    async def search_logs(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditLog]:
        """Search audit logs by text query."""
        async with self.operation_context("search_logs"):
            async with self.get_session() as session:
                # Simple text search on title and description
                search_pattern = f"%{query}%"

                stmt = (
                    select(AuditLogModel)
                    .where(
                        or_(
                            AuditLogModel.title.ilike(search_pattern),
                            AuditLogModel.description.ilike(search_pattern),
                        )
                    )
                    .order_by(AuditLogModel.created_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit).offset(offset)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    # Stub implementations for remaining required methods
    async def find_logs_with_entries_by_filter(
        self, entry_filter: Any, limit: int | None = None, offset: int = 0
    ) -> list[AuditLog]:
        """Find logs containing entries matching the filter."""
        # TODO: Implement complex filtering logic
        return []

    async def count_logs_by_status(self) -> dict[AuditStatus, int]:
        """Count logs grouped by status."""
        async with self.operation_context("count_logs_by_status"):
            async with self.get_session() as session:
                stmt = select(AuditLogModel.status, func.count()).group_by(
                    AuditLogModel.status
                )

                result = await session.execute(stmt)
                return {row[0]: row[1] for row in result}

    async def count_logs_by_retention_policy(self) -> dict[RetentionPolicy, int]:
        """Count logs grouped by retention policy."""
        async with self.operation_context("count_logs_by_retention_policy"):
            async with self.get_session() as session:
                stmt = select(AuditLogModel.retention_policy, func.count()).group_by(
                    AuditLogModel.retention_policy
                )

                result = await session.execute(stmt)
                return {row[0]: row[1] for row in result}

    async def find_logs_needing_attention(self) -> list[AuditLog]:
        """Find logs that need administrative attention."""
        # TODO: Implement logic to identify logs needing attention
        return []

    async def get_storage_usage_by_log(self) -> dict[UUID, dict[str, Any]]:
        """Get storage usage statistics by log."""
        # TODO: Implement storage usage calculation
        return {}

    async def find_recently_modified_logs(
        self, since: datetime, limit: int | None = None
    ) -> list[AuditLog]:
        """Find logs modified since a specific time."""
        async with self.operation_context("find_recently_modified_logs"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditLogModel)
                    .where(AuditLogModel.updated_at >= since)
                    .order_by(AuditLogModel.updated_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def cleanup_empty_logs(self, max_age_days: int = 7) -> int:
        """Clean up empty logs older than specified days."""
        # TODO: Implement cleanup logic
        return 0

    async def archive_completed_logs(
        self, archive_location_template: str, compression_enabled: bool = True
    ) -> list[UUID]:
        """Archive logs marked for archival."""
        # TODO: Implement archival logic
        return []

    async def restore_archived_log(
        self, log_id: UUID, archive_location: str
    ) -> AuditLog | None:
        """Restore an archived log."""
        # TODO: Implement restoration logic
        return None

    async def validate_log_integrity(self, log_id: UUID) -> dict[str, Any]:
        """Validate the integrity of a log and its entries."""
        # TODO: Implement integrity validation
        return {"valid": True, "errors": []}

    async def get_retention_summary(self) -> dict[str, Any]:
        """Get summary of retention policies and their impact."""
        # TODO: Implement retention summary
        return {}

    async def find_logs_by_health_status(
        self,
        include_healthy: bool = True,
        include_warnings: bool = True,
        include_errors: bool = True,
    ) -> list[AuditLog]:
        """Find logs by their health status."""
        # TODO: Implement health status filtering
        return []

    async def _get_or_create_model(
        self, session: AsyncSession, entity: AuditLog
    ) -> AuditLogModel:
        """Get existing model or create new one."""
        if entity.id:
            stmt = select(AuditLogModel).where(AuditLogModel.id == entity.id)
            result = await session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return model

        # Create new model
        return AuditLogModel(id=entity.id)

    def _update_model_from_entity(self, model: AuditLogModel, entity: AuditLog) -> None:
        """Update model fields from entity."""
        model.title = entity.title
        model.description = entity.description
        model.retention_policy = entity.retention_policy
        model.status = entity.status
        model.entry_count = entity.entry_count
        model.last_entry_at = entity.last_entry_at
        model.archived_at = entity.archived_at
        model.archive_location = entity.archive_location
        model.created_by = entity.created_at  # Assuming created_by is stored in entity

    def _model_to_entity(self, model: AuditLogModel) -> AuditLog:
        """Convert database model to domain entity."""
        entity = AuditLog(
            title=model.title,
            retention_policy=model.retention_policy,
            description=model.description,
            created_by=model.created_by,
            entity_id=model.id,
        )

        # Set additional fields
        entity.status = model.status
        entity.entry_count = model.entry_count
        entity.last_entry_at = model.last_entry_at
        entity.archived_at = model.archived_at
        entity.archive_location = model.archive_location

        # Set timestamps
        entity.created_at = model.created_at
        entity.updated_at = model.updated_at

        # Load entries if needed (lazy loading)
        # Note: In practice, you might want to load entries separately
        # to avoid N+1 queries and memory issues with large logs

        return entity

    async def _test_database_connectivity(self, session: AsyncSession) -> None:
        """Test database connectivity."""
        async with session.begin():
            from app.core.constants import HEALTH_CHECK_QUERY
            await session.execute(text(HEALTH_CHECK_QUERY))


__all__ = ["AuditLogRepository"]
