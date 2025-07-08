"""Audit entry repository with bulk operations support.

This module implements the repository for audit entries with optimized
bulk insert operations and efficient querying capabilities.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.errors import InfrastructureError
from app.core.infrastructure.repository import BaseRepository
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_entry import AuditEntry, AuditField
from app.modules.audit.domain.entities.audit_filter import AuditFilter
from app.modules.audit.domain.enums.audit_enums import AuditSeverity
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)
from app.modules.audit.infrastructure.models.audit_models import (
    AuditEntryModel,
    AuditFieldModel,
)

logger = get_logger(__name__)


class AuditEntryRepository(BaseRepository[AuditEntry, UUID]):
    """
    Repository for audit entries with bulk operations support.

    Provides high-performance access to audit entries with support for
    bulk inserts, complex queries, and time-based partitioning.
    """

    BULK_INSERT_BATCH_SIZE = 1000  # Optimal batch size for bulk inserts

    def __init__(self, session_factory, cache=None):
        """
        Initialize audit entry repository.

        Args:
            session_factory: Factory for creating database sessions
            cache: Optional cache implementation
        """
        super().__init__(AuditEntry, session_factory, cache)

    async def find_by_id(self, entity_id: UUID) -> AuditEntry | None:
        """Find audit entry by ID."""
        async with self.operation_context("find_by_id"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditEntryModel)
                    .where(AuditEntryModel.id == entity_id)
                    .options(joinedload(AuditEntryModel.fields))
                )

                result = await session.execute(stmt)
                model = result.scalar_one_or_none()

                if not model:
                    return None

                return self._model_to_entity(model)

    async def find_all(
        self, limit: int | None = None, offset: int = 0
    ) -> list[AuditEntry]:
        """Find all audit entries with pagination."""
        async with self.operation_context("find_all"):
            async with self.get_session() as session:
                stmt = (
                    select(AuditEntryModel)
                    .order_by(AuditEntryModel.created_at.desc())
                    .offset(offset)
                    .options(joinedload(AuditEntryModel.fields))
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.unique().scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def save(self, entity: AuditEntry) -> AuditEntry:
        """Save single audit entry."""
        async with self.operation_context("save"):
            async with self.get_session() as session:
                model = self._entity_to_model(entity)

                # Add to session
                session.add(model)

                # Add field models if any
                for field in entity.changes:
                    field_model = self._field_to_model(field, model.id)
                    session.add(field_model)

                # Commit transaction
                await session.commit()

                # Refresh to get any database-generated values
                await session.refresh(model)

                return self._model_to_entity(model)

    async def bulk_save(self, entities: list[AuditEntry]) -> list[AuditEntry]:
        """
        Bulk save audit entries for high throughput.

        Uses PostgreSQL's efficient bulk insert capabilities with
        proper batching for optimal performance.
        """
        async with self.operation_context("bulk_save"):
            if not entities:
                return []

            async with self.get_session() as session:
                saved_entities = []

                # Process in batches
                for i in range(0, len(entities), self.BULK_INSERT_BATCH_SIZE):
                    batch = entities[i : i + self.BULK_INSERT_BATCH_SIZE]

                    # Prepare entry data for bulk insert
                    entry_data = []
                    field_data = []

                    for entity in batch:
                        entry_dict = self._entity_to_dict(entity)
                        entry_data.append(entry_dict)

                        # Collect field data
                        for field in entity.changes:
                            field_dict = self._field_to_dict(field, entity.id)
                            field_data.append(field_dict)

                    # Bulk insert entries
                    if entry_data:
                        stmt = pg_insert(AuditEntryModel).values(entry_data)
                        stmt = stmt.on_conflict_do_nothing(index_elements=["id"])
                        await session.execute(stmt)

                    # Bulk insert fields
                    if field_data:
                        stmt = pg_insert(AuditFieldModel).values(field_data)
                        stmt = stmt.on_conflict_do_nothing(index_elements=["id"])
                        await session.execute(stmt)

                    saved_entities.extend(batch)

                # Commit all batches
                await session.commit()

                logger.info(
                    "Bulk saved audit entries",
                    count=len(saved_entities),
                    batch_size=self.BULK_INSERT_BATCH_SIZE,
                )

                return saved_entities

    async def delete(self, entity_id: UUID) -> bool:
        """Delete audit entry (not typically allowed due to immutability)."""
        raise InfrastructureError(
            "Audit entries cannot be deleted due to immutability requirements"
        )

    async def exists(self, entity_id: UUID) -> bool:
        """Check if audit entry exists."""
        async with self.operation_context("exists"):
            async with self.get_session() as session:
                stmt = select(func.count()).where(AuditEntryModel.id == entity_id)
                result = await session.execute(stmt)
                count = result.scalar()
                return count > 0

    async def count(self) -> int:
        """Count total audit entries."""
        async with self.operation_context("count"):
            async with self.get_session() as session:
                stmt = select(func.count()).select_from(AuditEntryModel)
                result = await session.execute(stmt)
                return result.scalar()

    async def find_by_filter(
        self, filter: AuditFilter, include_fields: bool = False
    ) -> tuple[list[AuditEntry], int]:
        """
        Find entries matching filter criteria.

        Returns tuple of (entries, total_count) for pagination.
        """
        async with self.operation_context("find_by_filter"):
            async with self.get_session() as session:
                # Build base query
                query = select(AuditEntryModel)

                # Apply filters
                conditions = self._build_filter_conditions(filter)
                if conditions:
                    query = query.where(and_(*conditions))

                # Include fields if requested
                if include_fields:
                    query = query.options(joinedload(AuditEntryModel.fields))

                # Get total count before pagination
                count_query = select(func.count()).select_from(query.subquery())
                count_result = await session.execute(count_query)
                total_count = count_result.scalar()

                # Apply sorting
                query = self._apply_sorting(query, filter)

                # Apply pagination
                query = query.offset(filter.offset).limit(filter.limit)

                # Execute query
                result = await session.execute(query)
                models = (
                    result.unique().scalars().all()
                    if include_fields
                    else result.scalars().all()
                )

                entries = [self._model_to_entity(model) for model in models]

                return entries, total_count

    async def find_by_user(
        self,
        user_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """Find entries by user with optional date range."""
        async with self.operation_context("find_by_user"):
            async with self.get_session() as session:
                conditions = [AuditEntryModel.user_id == user_id]

                if start_date:
                    conditions.append(AuditEntryModel.created_at >= start_date)
                if end_date:
                    conditions.append(AuditEntryModel.created_at <= end_date)

                stmt = (
                    select(AuditEntryModel)
                    .where(and_(*conditions))
                    .order_by(AuditEntryModel.created_at.desc())
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_by_resource(
        self,
        resource_type: str,
        resource_id: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """Find entries by resource."""
        async with self.operation_context("find_by_resource"):
            async with self.get_session() as session:
                conditions = [AuditEntryModel.resource_type == resource_type]

                if resource_id:
                    conditions.append(AuditEntryModel.resource_id == resource_id)

                stmt = (
                    select(AuditEntryModel)
                    .where(and_(*conditions))
                    .order_by(AuditEntryModel.created_at.desc())
                    .options(joinedload(AuditEntryModel.fields))
                )

                if limit:
                    stmt = stmt.limit(limit)

                result = await session.execute(stmt)
                models = result.unique().scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def find_failures(
        self,
        start_date: datetime,
        end_date: datetime,
        severity_threshold: AuditSeverity | None = None,
    ) -> list[AuditEntry]:
        """Find failed operations within date range."""
        async with self.operation_context("find_failures"):
            async with self.get_session() as session:
                conditions = [
                    AuditEntryModel.outcome == "failure",
                    AuditEntryModel.created_at >= start_date,
                    AuditEntryModel.created_at <= end_date,
                ]

                if severity_threshold:
                    # Get severities at or above threshold
                    severities = [
                        s for s in AuditSeverity if s.value >= severity_threshold.value
                    ]
                    conditions.append(AuditEntryModel.severity.in_(severities))

                stmt = (
                    select(AuditEntryModel)
                    .where(and_(*conditions))
                    .order_by(
                        AuditEntryModel.severity.desc(),
                        AuditEntryModel.created_at.desc(),
                    )
                )

                result = await session.execute(stmt)
                models = result.scalars().all()

                return [self._model_to_entity(model) for model in models]

    async def get_activity_summary(
        self,
        user_id: UUID | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get activity summary statistics."""
        async with self.operation_context("get_activity_summary"):
            async with self.get_session() as session:
                conditions = []

                if user_id:
                    conditions.append(AuditEntryModel.user_id == user_id)
                if start_date:
                    conditions.append(AuditEntryModel.created_at >= start_date)
                if end_date:
                    conditions.append(AuditEntryModel.created_at <= end_date)

                base_query = select(AuditEntryModel)
                if conditions:
                    base_query = base_query.where(and_(*conditions))

                # Get summary statistics
                stats_query = select(
                    func.count(AuditEntryModel.id).label("total_entries"),
                    func.count(func.distinct(AuditEntryModel.user_id)).label(
                        "unique_users"
                    ),
                    func.count(func.distinct(AuditEntryModel.session_id)).label(
                        "unique_sessions"
                    ),
                    func.count(func.distinct(AuditEntryModel.resource_type)).label(
                        "unique_resource_types"
                    ),
                    func.sum(
                        func.case((AuditEntryModel.outcome == "success", 1), else_=0)
                    ).label("success_count"),
                    func.sum(
                        func.case((AuditEntryModel.outcome == "failure", 1), else_=0)
                    ).label("failure_count"),
                    func.avg(AuditEntryModel.duration_ms).label("avg_duration_ms"),
                    func.min(AuditEntryModel.created_at).label("first_entry"),
                    func.max(AuditEntryModel.created_at).label("last_entry"),
                ).select_from(base_query.subquery())

                stats_result = await session.execute(stats_query)
                stats = stats_result.one()

                # Get action type distribution
                action_query = (
                    select(
                        AuditEntryModel.action_type,
                        func.count(AuditEntryModel.id).label("count"),
                    )
                    .select_from(base_query.subquery())
                    .group_by(AuditEntryModel.action_type)
                    .order_by(func.count(AuditEntryModel.id).desc())
                )

                action_result = await session.execute(action_query)
                action_distribution = {
                    row.action_type: row.count for row in action_result
                }

                # Get severity distribution
                severity_query = (
                    select(
                        AuditEntryModel.severity,
                        func.count(AuditEntryModel.id).label("count"),
                    )
                    .select_from(base_query.subquery())
                    .group_by(AuditEntryModel.severity)
                )

                severity_result = await session.execute(severity_query)
                severity_distribution = {
                    row.severity.value: row.count for row in severity_result
                }

                return {
                    "total_entries": stats.total_entries,
                    "unique_users": stats.unique_users,
                    "unique_sessions": stats.unique_sessions,
                    "unique_resource_types": stats.unique_resource_types,
                    "success_count": stats.success_count,
                    "failure_count": stats.failure_count,
                    "success_rate": (
                        stats.success_count / stats.total_entries
                        if stats.total_entries > 0
                        else 0
                    ),
                    "avg_duration_ms": float(stats.avg_duration_ms)
                    if stats.avg_duration_ms
                    else None,
                    "first_entry": stats.first_entry.isoformat()
                    if stats.first_entry
                    else None,
                    "last_entry": stats.last_entry.isoformat()
                    if stats.last_entry
                    else None,
                    "action_distribution": action_distribution,
                    "severity_distribution": severity_distribution,
                }

    async def create_partition(self, partition_date: datetime) -> None:
        """Create a new daily partition for audit entries."""
        async with self.operation_context("create_partition"):
            async with self.get_session() as session:
                partition_name = f"audit_entries_{partition_date.year}_{partition_date.month:02d}_{partition_date.day:02d}"
                next_day = partition_date + timedelta(days=1)

                sql = text(
                    f"""
                    CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_entries
                    FOR VALUES FROM ('{partition_date.strftime('%Y-%m-%d')}')
                    TO ('{next_day.strftime('%Y-%m-%d')}');
                """
                )

                await session.execute(sql)
                await session.commit()

                logger.info(
                    "Created audit entry partition",
                    partition_name=partition_name,
                    date=partition_date.strftime("%Y-%m-%d"),
                )

    def _build_filter_conditions(self, filter: AuditFilter) -> list[Any]:
        """Build SQLAlchemy conditions from filter."""
        conditions = []

        # Time range filter
        if filter.time_range:
            if filter.time_range.start_time:
                conditions.append(
                    AuditEntryModel.created_at >= filter.time_range.start_time
                )
            if filter.time_range.end_time:
                conditions.append(
                    AuditEntryModel.created_at <= filter.time_range.end_time
                )

        # User filters
        if filter.user_ids:
            conditions.append(AuditEntryModel.user_id.in_(filter.user_ids))
        elif not filter.include_system:
            conditions.append(AuditEntryModel.user_id.isnot(None))

        # Resource filters
        if filter.resource_types:
            conditions.append(AuditEntryModel.resource_type.in_(filter.resource_types))
        if filter.resource_ids:
            conditions.append(AuditEntryModel.resource_id.in_(filter.resource_ids))

        # Action filters
        if filter.action_types:
            conditions.append(AuditEntryModel.action_type.in_(filter.action_types))
        if filter.operations:
            conditions.append(AuditEntryModel.operation.in_(filter.operations))

        # Classification filters
        if filter.severities:
            conditions.append(AuditEntryModel.severity.in_(filter.severities))
        if filter.categories:
            conditions.append(AuditEntryModel.category.in_(filter.categories))

        # Outcome filter
        if filter.outcomes:
            conditions.append(AuditEntryModel.outcome.in_(filter.outcomes))

        # Session filter
        if filter.session_ids:
            conditions.append(AuditEntryModel.session_id.in_(filter.session_ids))

        # Correlation filter
        if filter.correlation_ids:
            conditions.append(
                AuditEntryModel.correlation_id.in_(filter.correlation_ids)
            )

        # Text search
        if filter.search_text:
            search_pattern = f"%{filter.search_text}%"
            conditions.append(
                or_(
                    AuditEntryModel.action_description.ilike(search_pattern),
                    AuditEntryModel.resource_name.ilike(search_pattern),
                    AuditEntryModel.user_agent.ilike(search_pattern),
                )
            )

        return conditions

    def _apply_sorting(self, query, filter: AuditFilter):
        """Apply sorting to query based on filter."""
        if filter.sort_by == "created_at":
            order_by = AuditEntryModel.created_at
        elif filter.sort_by == "severity":
            order_by = AuditEntryModel.severity
        else:
            order_by = AuditEntryModel.created_at

        if filter.sort_order == "desc":
            query = query.order_by(order_by.desc())
        else:
            query = query.order_by(order_by.asc())

        return query

    def _entity_to_model(self, entity: AuditEntry) -> AuditEntryModel:
        """Convert domain entity to database model."""
        return AuditEntryModel(
            id=entity.id,
            audit_log_id=entity.session_id,  # Assuming session_id maps to log_id
            session_id=entity.session_id,
            user_id=entity.user_id,
            action_type=entity.action.action_type,
            operation=entity.action.operation,
            action_description=entity.action.description,
            resource_type=entity.resource.resource_type,
            resource_id=entity.resource.resource_id,
            resource_name=entity.resource.get_display_name(),
            ip_address=entity.context.ip_address,
            user_agent=entity.context.user_agent,
            request_id=entity.context.request_id,
            severity=entity.severity,
            category=entity.category,
            outcome=entity.outcome,
            error_details=entity.error_details,
            duration_ms=entity.duration_ms,
            correlation_id=entity.correlation_id,
            metadata=entity.metadata.to_dict() if entity.metadata else None,
            created_at=entity.created_at,
        )

    def _entity_to_dict(self, entity: AuditEntry) -> dict[str, Any]:
        """Convert entity to dictionary for bulk insert."""
        return {
            "id": entity.id,
            "audit_log_id": entity.session_id,  # Assuming session_id maps to log_id
            "session_id": entity.session_id,
            "user_id": entity.user_id,
            "action_type": entity.action.action_type,
            "operation": entity.action.operation,
            "action_description": entity.action.description,
            "resource_type": entity.resource.resource_type,
            "resource_id": entity.resource.resource_id,
            "resource_name": entity.resource.get_display_name(),
            "ip_address": entity.context.ip_address,
            "user_agent": entity.context.user_agent,
            "request_id": entity.context.request_id,
            "severity": entity.severity.value,
            "category": entity.category.value,
            "outcome": entity.outcome,
            "error_details": entity.error_details,
            "duration_ms": entity.duration_ms,
            "correlation_id": entity.correlation_id,
            "metadata": entity.metadata.to_dict() if entity.metadata else None,
            "created_at": entity.created_at,
        }

    def _field_to_model(self, field: AuditField, entry_id: UUID) -> AuditFieldModel:
        """Convert field entity to model."""
        return AuditFieldModel(
            id=field.id,
            audit_entry_id=entry_id,
            field_name=field.field_name,
            field_path=field.field_path,
            old_value=field.old_value,
            new_value=field.new_value,
            value_type=field.value_type,
            is_sensitive=field.is_sensitive,
        )

    def _field_to_dict(self, field: AuditField, entry_id: UUID) -> dict[str, Any]:
        """Convert field to dictionary for bulk insert."""
        return {
            "id": field.id,
            "audit_entry_id": entry_id,
            "field_name": field.field_name,
            "field_path": field.field_path,
            "old_value": field.old_value,
            "new_value": field.new_value,
            "value_type": field.value_type,
            "is_sensitive": field.is_sensitive,
        }

    def _model_to_entity(self, model: AuditEntryModel) -> AuditEntry:
        """Convert database model to domain entity."""
        # Create value objects
        action = AuditAction(
            action_type=model.action_type,
            operation=model.operation,
            description=model.action_description,
            resource_type=model.resource_type,
        )

        resource = ResourceIdentifier(
            resource_type=model.resource_type,
            resource_id=model.resource_id,
            resource_name=model.resource_name,
        )

        context = AuditContext(
            ip_address=model.ip_address,
            user_agent=model.user_agent,
            request_id=model.request_id,
        )

        metadata = AuditMetadata.from_dict(model.metadata) if model.metadata else None

        # Convert field models
        changes = []
        if model.fields:
            for field_model in model.fields:
                field = AuditField(
                    field_name=field_model.field_name,
                    old_value=field_model.old_value,
                    new_value=field_model.new_value,
                    field_path=field_model.field_path,
                    value_type=field_model.value_type,
                    is_sensitive=field_model.is_sensitive,
                    entity_id=field_model.id,
                )
                changes.append(field)

        # Create entity
        entity = AuditEntry(
            user_id=model.user_id,
            action=action,
            resource=resource,
            context=context,
            metadata=metadata,
            severity=model.severity,
            category=model.category,
            outcome=model.outcome,
            error_details=model.error_details,
            duration_ms=model.duration_ms,
            changes=changes,
            correlation_id=model.correlation_id,
            session_id=model.session_id,
            entity_id=model.id,
        )

        # Set timestamp
        entity.created_at = model.created_at

        return entity

    async def _test_database_connectivity(self, session: AsyncSession) -> None:
        """Test database connectivity."""
        await session.execute(text("SELECT 1"))


__all__ = ["AuditEntryRepository"]
