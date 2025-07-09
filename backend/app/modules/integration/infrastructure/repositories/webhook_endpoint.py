"""Webhook endpoint repository implementation.

This module provides the repository for webhook endpoints with
comprehensive query support and event management.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, selectinload

from app.core.errors import ConflictError, NotFoundError
from app.core.infrastructure.repositories import BaseRepository
from app.modules.integration.domain.aggregates import WebhookEndpoint
from app.modules.integration.domain.enums import WebhookMethod, WebhookStatus
from app.modules.integration.domain.value_objects import (
    RateLimitConfig,
    WebhookSignature,
)
from app.modules.integration.infrastructure.models import (
from app.core.infrastructure.repository import BaseRepository
    WebhookEndpointModel,
    WebhookEventModel,
)


class WebhookEndpointRepository(BaseRepository[WebhookEndpoint, WebhookEndpointModel]):
    """Repository for managing webhook endpoints."""

    def __init__(self, session: Session):
        """Initialize repository with database session."""
        super().__init__(session, WebhookEndpointModel)

    def _to_domain(self, model: WebhookEndpointModel) -> WebhookEndpoint:
        """Convert database model to domain aggregate."""
        data = model.to_entity_dict()

        # Reconstruct value objects
        signature_config = WebhookSignature(**data.pop("signature_config"))

        rate_limit_config = None
        if data.get("rate_limit_config"):
            rate_limit_config = RateLimitConfig(**data.pop("rate_limit_config"))

        # Convert method strings to enums
        allowed_methods = [
            WebhookMethod(method) for method in data.pop("allowed_methods")
        ]

        # Create aggregate
        endpoint = WebhookEndpoint(
            integration_id=data.pop("integration_id"),
            name=data.pop("name"),
            path=data.pop("path"),
            allowed_methods=allowed_methods,
            secret_token=data.pop("secret_token"),
            signature_config=signature_config,
            description=data.pop("description"),
            event_types=data.pop("event_types"),
            required_headers=data.pop("required_headers"),
            rate_limit_config=rate_limit_config,
            retry_config=data.pop("retry_config"),
            timeout_seconds=data.pop("timeout_seconds"),
            metadata=data.pop("metadata"),
            entity_id=data.pop("entity_id"),
        )

        # Set state
        endpoint.is_active = data.pop("is_active")

        # Set timestamps
        endpoint.created_at = data.pop("created_at")
        endpoint.updated_at = data.pop("updated_at")
        endpoint._version = data.pop("version")

        # Set event count
        endpoint._event_count = data.pop("_event_count", 0)

        # Clear modification tracking
        endpoint._events.clear()
        endpoint._modified = False

        return endpoint

    def _to_model(self, aggregate: WebhookEndpoint) -> WebhookEndpointModel:
        """Convert domain aggregate to database model."""
        data = aggregate.to_dict()

        # Convert value objects
        data["signature_config"] = aggregate.signature_config.to_dict()
        if aggregate.rate_limit_config:
            data["rate_limit_config"] = aggregate.rate_limit_config.to_dict()

        # Convert method enums to strings
        data["allowed_methods"] = [method.value for method in aggregate.allowed_methods]

        # Remove computed fields
        computed_fields = [
            "full_url",
            "is_rate_limited",
            "supports_retries",
            "event_count",
        ]
        for field in computed_fields:
            data.pop(field, None)

        # Map id to entity_id
        data["entity_id"] = data.pop("id")

        return WebhookEndpointModel.from_entity_dict(data)

    async def find_by_id(
        self, endpoint_id: UUID, include_events: bool = False
    ) -> WebhookEndpoint | None:
        """Find webhook endpoint by ID."""
        stmt = select(WebhookEndpointModel).where(
            WebhookEndpointModel.id == endpoint_id
        )

        if include_events:
            stmt = stmt.options(selectinload(WebhookEndpointModel.events))

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_integration(
        self, integration_id: UUID, active_only: bool = True
    ) -> list[WebhookEndpoint]:
        """Find all webhook endpoints for an integration."""
        stmt = select(WebhookEndpointModel).where(
            WebhookEndpointModel.integration_id == integration_id
        )

        if active_only:
            stmt = stmt.where(WebhookEndpointModel.is_active is True)

        stmt = stmt.order_by(WebhookEndpointModel.created_at.desc())

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_path(
        self, path: str, integration_id: UUID | None = None
    ) -> WebhookEndpoint | None:
        """Find webhook endpoint by path."""
        stmt = select(WebhookEndpointModel).where(WebhookEndpointModel.path == path)

        if integration_id:
            stmt = stmt.where(WebhookEndpointModel.integration_id == integration_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_secret_token(self, secret_token: str) -> WebhookEndpoint | None:
        """Find webhook endpoint by secret token."""
        stmt = select(WebhookEndpointModel).where(
            WebhookEndpointModel.secret_token == secret_token
        )

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_supporting_event_type(
        self, event_type: str, active_only: bool = True
    ) -> list[WebhookEndpoint]:
        """Find endpoints supporting a specific event type."""
        stmt = select(WebhookEndpointModel).where(
            func.json_contains(
                WebhookEndpointModel.event_types, func.json_quote(event_type)
            )
        )

        if active_only:
            stmt = stmt.where(WebhookEndpointModel.is_active is True)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_with_pending_events(self) -> list[WebhookEndpoint]:
        """Find endpoints with pending webhook events."""
        stmt = (
            select(WebhookEndpointModel)
            .join(WebhookEndpointModel.events)
            .where(
                and_(
                    WebhookEndpointModel.is_active is True,
                    WebhookEventModel.status == WebhookStatus.PENDING,
                )
            )
            .distinct()
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def count_events(
        self, endpoint_id: UUID, status: WebhookStatus | None = None
    ) -> int:
        """Count webhook events for an endpoint."""
        stmt = select(func.count(WebhookEventModel.id)).where(
            WebhookEventModel.endpoint_id == endpoint_id
        )

        if status:
            stmt = stmt.where(WebhookEventModel.status == status)

        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def get_event_statistics(self, endpoint_id: UUID) -> dict[str, Any]:
        """Get webhook event statistics for an endpoint."""
        # Count by status
        status_counts = {}
        for status in WebhookStatus:
            count = await self.count_events(endpoint_id, status)
            status_counts[status.value] = count

        # Get average processing time
        stmt = select(
            func.avg(
                func.extract(
                    "epoch",
                    WebhookEventModel.processed_at - WebhookEventModel.received_at,
                )
            )
        ).where(
            and_(
                WebhookEventModel.endpoint_id == endpoint_id,
                WebhookEventModel.processed_at is not None,
            )
        )

        result = await self._session.execute(stmt)
        avg_processing_time = result.scalar()

        # Get event type distribution
        stmt = (
            select(WebhookEventModel.event_type, func.count(WebhookEventModel.id))
            .where(WebhookEventModel.endpoint_id == endpoint_id)
            .group_by(WebhookEventModel.event_type)
        )

        result = await self._session.execute(stmt)
        event_type_counts = dict(result.all())

        return {
            "total_events": sum(status_counts.values()),
            "status_distribution": status_counts,
            "average_processing_seconds": avg_processing_time,
            "event_type_distribution": event_type_counts,
        }

    async def exists_by_path(
        self, integration_id: UUID, path: str, exclude_id: UUID | None = None
    ) -> bool:
        """Check if endpoint with path exists for integration."""
        stmt = select(WebhookEndpointModel.id).where(
            and_(
                WebhookEndpointModel.integration_id == integration_id,
                WebhookEndpointModel.path == path,
            )
        )

        if exclude_id:
            stmt = stmt.where(WebhookEndpointModel.id != exclude_id)

        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def save_with_lock(self, endpoint: WebhookEndpoint) -> WebhookEndpoint:
        """Save webhook endpoint with optimistic locking."""
        model = self._to_model(endpoint)

        if endpoint._version > 1:
            # Update with version check
            stmt = select(WebhookEndpointModel).where(
                and_(
                    WebhookEndpointModel.id == model.id,
                    WebhookEndpointModel.version == endpoint._version - 1,
                )
            )

            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                raise ConflictError(
                    "Webhook endpoint has been modified by another process"
                )

            # Update fields
            for key, value in model.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)

            existing.version = endpoint._version
            model = existing
        else:
            # New endpoint
            self._session.add(model)

        try:
            await self._session.flush()
            endpoint._version = model.version
            return endpoint
        except IntegrityError as e:
            if "uq_webhook_endpoints_integration_path" in str(e):
                raise ConflictError(
                    f"Webhook endpoint with path '{endpoint.path}' already exists"
                )
            raise

    async def delete(self, endpoint_id: UUID) -> None:
        """Delete webhook endpoint and all events."""
        stmt = select(WebhookEndpointModel).where(
            WebhookEndpointModel.id == endpoint_id
        )

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Webhook endpoint {endpoint_id} not found")

        await self._session.delete(model)
        await self._session.flush()

    async def cleanup_old_events(
        self, days_old: int = 30, status: WebhookStatus | None = None
    ) -> int:
        """Clean up old webhook events."""
        cutoff_date = datetime.now(UTC) - timedelta(days=days_old)

        stmt = select(WebhookEventModel).where(
            WebhookEventModel.created_at < cutoff_date
        )

        if status:
            stmt = stmt.where(WebhookEventModel.status == status)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        count = len(models)
        for model in models:
            await self._session.delete(model)

        await self._session.flush()
        return count
