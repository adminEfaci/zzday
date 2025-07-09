"""Audit report repository implementation.

This module implements the repository for audit reports with support
for storing generated reports and their metadata.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.infrastructure.repository import BaseRepository
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_report import AuditReport
from app.modules.audit.infrastructure.models.audit_models import AuditReportModel

logger = get_logger(__name__)


class AuditReportRepository(BaseRepository[AuditReport, UUID]):
    """
    Repository for audit reports.

    Manages storage and retrieval of generated audit reports with
    support for various formats and retention policies.
    """

    def __init__(self, session_factory, cache=None):
        """
        Initialize audit report repository.

        Args:
            session_factory: Factory for creating database sessions
            cache: Optional cache implementation
        """
        super().__init__(AuditReport, session_factory, cache)

    async def find_by_id(self, entity_id: UUID) -> AuditReport | None:
        """Find audit report by ID."""
        async with self.operation_context("find_by_id"):
            async with self.get_session() as session:
                stmt = select(AuditReportModel).where(AuditReportModel.id == entity_id)
                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditReport]:
        """Find all audit reports with pagination."""
        async with self.operation_context("find_all"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditReportModel)
                    .order_by(AuditReportModel.created_at.desc())
                    .offset(offset)
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def save(self, entity: AuditReport) -> AuditReport:
        """Save audit report."""
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
        """Delete audit report."""
        async with self.operation_context("delete"):
            async with self.get_session() as session:
                stmt = delete(AuditReportModel).where(AuditReportModel.id == entity_id)
                result = await session.execute(stmt)
                await session.commit()

                if result.rowcount > 0:
                    await self.invalidate_cache_for_entity(entity_id)
                    return True

                return False

    async def exists(self, entity_id: UUID) -> bool:
        """Check if audit report exists."""
        async with self.operation_context("exists"):
            async with self.get_session() as session:
                stmt = select(func.count()).where(AuditReportModel.id == entity_id)
                result = await session.execute(stmt)
                count = result.scalar()
                return count > 0

    async def count(self) -> int:
        """Count total audit reports."""
        async with self.operation_context("count"):
            async with self.get_session() as session:
                stmt = select(func.count()).select_from(AuditReportModel)
                result = await session.execute(stmt)
                return result.scalar()

    async def find_by_type(
        self,
        report_type: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditReport]:
        """Find reports by type with optional date range."""
        async with self.operation_context("find_by_type"):
            async with self.get_session() as session:
                conditions = [AuditReportModel.report_type == report_type]

                if start_date:
                    conditions.append(AuditReportModel.created_at >= start_date)
                if end_date:
                    conditions.append(AuditReportModel.created_at <= end_date)

                stmt = (
                    select(AuditReportModel)
                    .where(and_(*conditions))
                    .order_by(AuditReportModel.created_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_period(
        self,
        period_start: datetime,
        period_end: datetime,
        report_type: str | None = None,
    ) -> list[AuditReport]:
        """Find reports covering a specific period."""
        async with self.operation_context("find_by_period"):
            async with self.get_session() as session:
                # Find reports that overlap with the given period
                conditions = [
                    or_(
                        and_(
                            AuditReportModel.period_start <= period_start,
                            AuditReportModel.period_end >= period_start,
                        ),
                        and_(
                            AuditReportModel.period_start <= period_end,
                            AuditReportModel.period_end >= period_end,
                        ),
                        and_(
                            AuditReportModel.period_start >= period_start,
                            AuditReportModel.period_end <= period_end,
                        ),
                    )
                ]

                if report_type:
                    conditions.append(AuditReportModel.report_type == report_type)

                stmt = (
                    select(AuditReportModel)
                    .where(and_(*conditions))
                    .order_by(AuditReportModel.period_start)
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_user(
        self, user_id: UUID, limit: int | None = None
    ) -> list[AuditReport]:
        """Find reports generated by a specific user."""
        async with self.operation_context("find_by_user"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditReportModel)
                    .where(AuditReportModel.generated_by == user_id)
                    .order_by(AuditReportModel.created_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_expired_reports(
        self, as_of_date: datetime | None = None
    ) -> list[AuditReport]:
        """Find reports that have exceeded their retention period."""
        async with self.operation_context("find_expired_reports"):
            if not as_of_date:
                as_of_date = datetime.utcnow()

            async with self.get_session() as session:
                stmt = (
                    select(AuditReportModel)
                    .where(
                        and_(
                            AuditReportModel.expires_at.isnot(None),
                            AuditReportModel.expires_at <= as_of_date,
                            AuditReportModel.is_archived is False,
                        )
                    )
                    .order_by(AuditReportModel.expires_at)
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def archive_report(self, report_id: UUID, archive_location: str) -> bool:
        """Archive a report."""
        async with self.operation_context("archive_report"):
            async with self.get_session() as session:
                stmt = (
                    update(AuditReportModel)
                    .where(AuditReportModel.id == report_id)
                    .values(
                        is_archived=True,
                        file_location=archive_location,
                        updated_at=datetime.utcnow(),
                    )
                )

                result = await session.execute(stmt)
                await session.commit()

                if result.rowcount > 0:
                    await self.invalidate_cache_for_entity(report_id)
                    return True

                return False

    async def update_access_count(self, report_id: UUID) -> None:
        """Increment access count for a report."""
        async with self.operation_context("update_access_count"):
            async with self.get_session() as session:
                stmt = (
                    update(AuditReportModel)
                    .where(AuditReportModel.id == report_id)
                    .values(
                        access_count=AuditReportModel.access_count + 1,
                        last_accessed_at=datetime.utcnow(),
                    )
                )

                await session.execute(stmt)
                await session.commit()

                # Invalidate cache
                await self.invalidate_cache_for_entity(report_id)

    async def get_report_statistics(
        self, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get report generation statistics for a date range."""
        async with self.operation_context("get_report_statistics"):
            async with self.get_session() as session:
                # Base conditions
                conditions = [
                    AuditReportModel.created_at >= start_date,
                    AuditReportModel.created_at <= end_date,
                ]

                # Get overall statistics
                stats_query = select(
                    func.count(AuditReportModel.id).label("total_reports"),
                    func.count(func.distinct(AuditReportModel.generated_by)).label(
                        "unique_users"
                    ),
                    func.avg(AuditReportModel.generation_duration_ms).label(
                        "avg_generation_time"
                    ),
                    func.sum(AuditReportModel.file_size_bytes).label(
                        "total_storage_bytes"
                    ),
                    func.sum(AuditReportModel.access_count).label("total_accesses"),
                    func.count(
                        func.case((AuditReportModel.status == "failed", 1), else_=None)
                    ).label("failed_reports"),
                ).where(and_(*conditions))

                stats_result = await session.execute(stats_query)
                stats = stats_result.one()

                # Get type distribution
                type_query = (
                    select(
                        AuditReportModel.report_type,
                        func.count(AuditReportModel.id).label("count"),
                    )
                    .where(and_(*conditions))
                    .group_by(AuditReportModel.report_type)
                )

                type_result = await session.execute(type_query)
                type_distribution = {row.report_type: row.count for row in type_result}

                # Get format distribution
                format_query = (
                    select(
                        AuditReportModel.file_format,
                        func.count(AuditReportModel.id).label("count"),
                    )
                    .where(and_(*conditions, AuditReportModel.file_format.isnot(None)))
                    .group_by(AuditReportModel.file_format)
                )

                format_result = await session.execute(format_query)
                format_distribution = {
                    row.file_format: row.count for row in format_result
                }

                return {
                    "period": {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat(),
                    },
                    "total_reports": stats.total_reports,
                    "unique_users": stats.unique_users,
                    "avg_generation_time_ms": float(stats.avg_generation_time)
                    if stats.avg_generation_time
                    else None,
                    "total_storage_bytes": stats.total_storage_bytes or 0,
                    "total_storage_mb": (stats.total_storage_bytes or 0)
                    / (1024 * 1024),
                    "total_accesses": stats.total_accesses or 0,
                    "failed_reports": stats.failed_reports,
                    "success_rate": (
                        (stats.total_reports - stats.failed_reports)
                        / stats.total_reports
                        if stats.total_reports > 0
                        else 0
                    ),
                    "type_distribution": type_distribution,
                    "format_distribution": format_distribution,
                }

    async def cleanup_old_reports(
        self, retention_days: int, dry_run: bool = False
    ) -> int:
        """Clean up old reports beyond retention period."""
        async with self.operation_context("cleanup_old_reports"):
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            async with self.get_session() as session:
                # Find reports to delete
                stmt = select(AuditReportModel).where(
                    and_(
                        AuditReportModel.created_at < cutoff_date,
                        AuditReportModel.is_archived is True,
                    )
                )

                result = await session.execute(stmt)
                reports_to_delete = result.scalars().all()

                if dry_run:
                    return len(reports_to_delete)

                # Delete reports
                deleted_count = 0
                for report in reports_to_delete:
                    delete_stmt = delete(AuditReportModel).where(
                        AuditReportModel.id == report.id
                    )
                    await session.execute(delete_stmt)
                    deleted_count += 1

                    # Invalidate cache
                    await self.invalidate_cache_for_entity(report.id)

                await session.commit()

                logger.info(
                    "Cleaned up old audit reports",
                    count=deleted_count,
                    retention_days=retention_days,
                )

                return deleted_count

    async def _get_or_create_model(
        self, session: AsyncSession, entity: AuditReport
    ) -> AuditReportModel:
        """Get existing model or create new one."""
        if entity.id:
            stmt = select(AuditReportModel).where(AuditReportModel.id == entity.id)
            result = await session.execute(stmt)
            model = result.scalar_one_or_none()

            if model:
                return model

        # Create new model
        return AuditReportModel(id=entity.id)

    def _update_model_from_entity(
        self, model: AuditReportModel, entity: AuditReport
    ) -> None:
        """Update model fields from entity."""
        model.title = entity.title
        model.description = entity.description
        model.report_type = (
            entity.report_type.value
            if hasattr(entity.report_type, "value")
            else entity.report_type
        )
        model.period_start = entity.period_start
        model.period_end = entity.period_end
        model.generated_by = entity.generated_by
        model.generation_duration_ms = entity.generation_duration_ms
        model.summary_data = entity.summary_data
        model.detailed_data = entity.detailed_data
        model.status = (
            entity.status.value if hasattr(entity.status, "value") else entity.status
        )
        model.error_message = entity.error_message
        model.file_location = entity.file_location
        model.file_size_bytes = entity.file_size_bytes
        model.file_format = entity.file_format
        model.expires_at = entity.expires_at
        model.is_archived = entity.is_archived

    def _model_to_entity(self, model: AuditReportModel) -> AuditReport:
        """Convert database model to domain entity."""
        entity = AuditReport(
            title=model.title,
            report_type=model.report_type,
            period_start=model.period_start,
            period_end=model.period_end,
            generated_by=model.generated_by,
            summary_data=model.summary_data,
            description=model.description,
            entity_id=model.id,
        )

        # Set additional fields
        entity.generation_duration_ms = model.generation_duration_ms
        entity.detailed_data = model.detailed_data
        entity.status = model.status
        entity.error_message = model.error_message
        entity.file_location = model.file_location
        entity.file_size_bytes = model.file_size_bytes
        entity.file_format = model.file_format
        entity.access_count = model.access_count
        entity.last_accessed_at = model.last_accessed_at
        entity.expires_at = model.expires_at
        entity.is_archived = model.is_archived

        # Set timestamps
        entity.created_at = model.created_at
        entity.updated_at = model.updated_at

        return entity

    async def _test_database_connectivity(self, session: AsyncSession) -> None:
        """Test database connectivity."""
        from sqlalchemy import text

        await session.execute(text("SELECT 1"))


__all__ = ["AuditReportRepository"]
