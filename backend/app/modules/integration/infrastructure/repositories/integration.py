"""Integration repository implementation.

This module provides the repository for Integration aggregates with
optimistic locking and comprehensive query support.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.errors import ConflictError, NotFoundError
from app.core.infrastructure.repositories import BaseRepository
from app.modules.integration.domain.aggregates import Integration
from app.modules.integration.domain.enums import ConnectionStatus, IntegrationType
from app.modules.integration.domain.value_objects import ApiEndpoint, RateLimitConfig
from app.modules.integration.infrastructure.models import IntegrationModel


class IntegrationRepository(BaseRepository[Integration, IntegrationModel]):
    """Repository for managing Integration aggregates."""

    def __init__(self, session: Session):
        """Initialize repository with database session."""
        super().__init__(session, IntegrationModel)

    def _to_domain(self, model: IntegrationModel) -> Integration:
        """Convert database model to domain aggregate."""
        data = model.to_entity_dict()

        # Reconstruct value objects
        api_endpoint = ApiEndpoint(**data.pop("api_endpoint"))
        rate_limit = None
        if data.get("rate_limit"):
            rate_limit = RateLimitConfig(**data.pop("rate_limit"))

        # Create aggregate
        integration = Integration(
            name=data.pop("name"),
            integration_type=data.pop("integration_type"),
            system_name=data.pop("system_name"),
            api_endpoint=api_endpoint,
            owner_id=data.pop("owner_id"),
            description=data.pop("description"),
            rate_limit=rate_limit,
            capabilities=data.pop("capabilities"),
            configuration=data.pop("configuration"),
            entity_id=data.pop("entity_id"),
        )

        # Set state fields
        integration.status = data.pop("status")
        integration.is_active = data.pop("is_active")
        integration.last_health_check = data.pop("last_health_check")
        integration.health_check_failures = data.pop("health_check_failures")

        # Set timestamps
        integration.created_at = data.pop("created_at")
        integration.updated_at = data.pop("updated_at")
        integration._version = data.pop("version")

        # Set related entity IDs
        integration._credential_ids = data.pop("_credential_ids", [])
        integration._sync_job_ids = data.pop("_sync_job_ids", [])
        integration._mapping_ids = data.pop("_mapping_ids", [])
        integration._webhook_endpoint_ids = data.pop("_webhook_endpoint_ids", [])

        # Clear modification tracking
        integration._events.clear()
        integration._modified = False

        return integration

    def _to_model(self, aggregate: Integration) -> IntegrationModel:
        """Convert domain aggregate to database model."""
        data = aggregate.to_dict()

        # Convert value objects to dicts
        data["api_endpoint"] = aggregate.api_endpoint.to_dict()
        if aggregate.rate_limit:
            data["rate_limit"] = aggregate.rate_limit.to_dict()

        # Remove computed properties
        computed_fields = [
            "is_connected",
            "is_healthy",
            "needs_attention",
            "can_sync",
            "can_receive_webhooks",
            "credential_count",
            "sync_job_count",
            "mapping_count",
            "webhook_endpoint_count",
        ]
        for field in computed_fields:
            data.pop(field, None)

        # Map id to entity_id
        data["entity_id"] = data.pop("id")

        return IntegrationModel.from_entity_dict(data)

    async def find_by_id(self, integration_id: UUID) -> Integration | None:
        """Find integration by ID with related entities."""
        stmt = (
            select(IntegrationModel)
            .where(IntegrationModel.id == integration_id)
            .options(
                selectinload(IntegrationModel.credentials),
                selectinload(IntegrationModel.mappings),
                selectinload(IntegrationModel.webhook_endpoints),
            )
        )

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_owner(
        self, owner_id: UUID, include_inactive: bool = False
    ) -> list[Integration]:
        """Find all integrations for a specific owner."""
        stmt = select(IntegrationModel).where(IntegrationModel.owner_id == owner_id)

        if not include_inactive:
            stmt = stmt.where(IntegrationModel.is_active is True)

        stmt = stmt.order_by(IntegrationModel.created_at.desc())

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_system(
        self, system_name: str, owner_id: UUID | None = None
    ) -> list[Integration]:
        """Find integrations by system name."""
        stmt = select(IntegrationModel).where(
            IntegrationModel.system_name == system_name
        )

        if owner_id:
            stmt = stmt.where(IntegrationModel.owner_id == owner_id)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_type(
        self,
        integration_type: IntegrationType,
        owner_id: UUID | None = None,
        active_only: bool = True,
    ) -> list[Integration]:
        """Find integrations by type."""
        stmt = select(IntegrationModel).where(
            IntegrationModel.integration_type == integration_type
        )

        if owner_id:
            stmt = stmt.where(IntegrationModel.owner_id == owner_id)

        if active_only:
            stmt = stmt.where(IntegrationModel.is_active is True)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_status(
        self, status: ConnectionStatus, owner_id: UUID | None = None
    ) -> list[Integration]:
        """Find integrations by connection status."""
        stmt = select(IntegrationModel).where(IntegrationModel.status == status)

        if owner_id:
            stmt = stmt.where(IntegrationModel.owner_id == owner_id)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_needing_health_check(
        self, check_interval_minutes: int = 5
    ) -> list[Integration]:
        """Find integrations needing health check."""
        cutoff_time = datetime.now(UTC).replace(
            minute=datetime.now(UTC).minute - check_interval_minutes
        )

        stmt = select(IntegrationModel).where(
            and_(
                IntegrationModel.is_active is True,
                IntegrationModel.status == ConnectionStatus.CONNECTED,
                or_(
                    IntegrationModel.last_health_check is None,
                    IntegrationModel.last_health_check < cutoff_time,
                ),
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_with_webhooks(self, active_only: bool = True) -> list[Integration]:
        """Find integrations that have webhook endpoints."""
        stmt = (
            select(IntegrationModel)
            .join(IntegrationModel.webhook_endpoints)
            .options(selectinload(IntegrationModel.webhook_endpoints))
            .distinct()
        )

        if active_only:
            stmt = stmt.where(IntegrationModel.is_active is True)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def count_by_owner(self, owner_id: UUID) -> int:
        """Count integrations for an owner."""
        stmt = select(func.count(IntegrationModel.id)).where(
            IntegrationModel.owner_id == owner_id
        )

        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def exists_by_name(
        self, name: str, owner_id: UUID, exclude_id: UUID | None = None
    ) -> bool:
        """Check if integration with name exists for owner."""
        stmt = select(IntegrationModel.id).where(
            and_(IntegrationModel.name == name, IntegrationModel.owner_id == owner_id)
        )

        if exclude_id:
            stmt = stmt.where(IntegrationModel.id != exclude_id)

        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def search(
        self,
        query: str,
        owner_id: UUID | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[Integration]:
        """Search integrations with filters."""
        stmt = select(IntegrationModel)

        # Text search on name, system_name, description
        if query:
            search_filter = or_(
                IntegrationModel.name.ilike(f"%{query}%"),
                IntegrationModel.system_name.ilike(f"%{query}%"),
                IntegrationModel.description.ilike(f"%{query}%"),
            )
            stmt = stmt.where(search_filter)

        # Owner filter
        if owner_id:
            stmt = stmt.where(IntegrationModel.owner_id == owner_id)

        # Apply additional filters
        if filters:
            if "integration_type" in filters:
                stmt = stmt.where(
                    IntegrationModel.integration_type == filters["integration_type"]
                )
            if "status" in filters:
                stmt = stmt.where(IntegrationModel.status == filters["status"])
            if "is_active" in filters:
                stmt = stmt.where(IntegrationModel.is_active == filters["is_active"])

        # Apply pagination
        stmt = stmt.limit(limit).offset(offset)
        stmt = stmt.order_by(IntegrationModel.created_at.desc())

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def save_with_lock(self, integration: Integration) -> Integration:
        """Save integration with optimistic locking."""
        model = self._to_model(integration)

        if integration._version > 1:
            # Update with version check
            stmt = select(IntegrationModel).where(
                and_(
                    IntegrationModel.id == model.id,
                    IntegrationModel.version == integration._version - 1,
                )
            )

            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                raise ConflictError("Integration has been modified by another process")

            # Update fields
            for key, value in model.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)

            existing.version = integration._version
            model = existing
        else:
            # New integration
            self._session.add(model)

        try:
            await self._session.flush()
            integration._version = model.version
            return integration
        except IntegrityError as e:
            if "uq_integrations_name_owner" in str(e):
                raise ConflictError(
                    f"Integration with name '{integration.name}' already exists"
                )
            raise

    async def delete(self, integration_id: UUID) -> None:
        """Delete integration and all related data."""
        stmt = select(IntegrationModel).where(IntegrationModel.id == integration_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Integration {integration_id} not found")

        await self._session.delete(model)
        await self._session.flush()
