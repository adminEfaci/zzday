"""Mapping repository implementation.

This module provides the repository for field mappings with
validation and transformation support.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError
from app.core.infrastructure.repositories import BaseRepository
from app.modules.integration.domain.entities import IntegrationMapping
from app.modules.integration.domain.enums import MappingTransformation
from app.modules.integration.infrastructure.models import MappingModel
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError


class MappingRepository(BaseRepository[IntegrationMapping, MappingModel]):
    """Repository for managing integration field mappings."""

    def __init__(self, session: Session):
        """Initialize repository with database session."""
        super().__init__(session, MappingModel)

    def _to_domain(self, model: MappingModel) -> IntegrationMapping:
        """Convert database model to domain entity."""
        data = model.to_entity_dict()

        # Create entity
        mapping = IntegrationMapping(
            integration_id=data.pop("integration_id"),
            name=data.pop("name"),
            entity_type=data.pop("entity_type"),
            source_field=data.pop("source_field"),
            target_field=data.pop("target_field"),
            source_type=data.pop("source_type"),
            target_type=data.pop("target_type"),
            description=data.pop("description"),
            transformation=data.pop("transformation"),
            transformation_config=data.pop("transformation_config"),
            custom_script=data.pop("custom_script"),
            validation_rules=data.pop("validation_rules"),
            default_value=data.pop("default_value"),
            use_default_on_error=data.pop("use_default_on_error"),
            is_required=data.pop("is_required"),
            metadata=data.pop("metadata"),
            entity_id=data.pop("entity_id"),
        )

        # Set state
        mapping.is_active = data.pop("is_active")

        # Set timestamps
        mapping.created_at = data.pop("created_at")
        mapping.updated_at = data.pop("updated_at")
        mapping._version = data.pop("version")

        # Clear modification tracking
        mapping._modified = False

        return mapping

    def _to_model(self, entity: IntegrationMapping) -> MappingModel:
        """Convert domain entity to database model."""
        data = entity.to_dict()

        # Remove computed fields
        computed_fields = [
            "requires_transformation",
            "has_validation",
            "is_type_compatible",
        ]
        for field in computed_fields:
            data.pop(field, None)

        # Map id to entity_id
        data["entity_id"] = data.pop("id")

        return MappingModel.from_entity_dict(data)

    async def find_by_id(self, mapping_id: UUID) -> IntegrationMapping | None:
        """Find mapping by ID."""
        stmt = select(MappingModel).where(MappingModel.id == mapping_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_integration(
        self,
        integration_id: UUID,
        entity_type: str | None = None,
        active_only: bool = True,
    ) -> list[IntegrationMapping]:
        """Find all mappings for an integration."""
        stmt = select(MappingModel).where(MappingModel.integration_id == integration_id)

        if entity_type:
            stmt = stmt.where(MappingModel.entity_type == entity_type)

        if active_only:
            stmt = stmt.where(MappingModel.is_active is True)

        stmt = stmt.order_by(MappingModel.entity_type, MappingModel.source_field)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_ids(self, mapping_ids: list[UUID]) -> list[IntegrationMapping]:
        """Find mappings by multiple IDs."""
        if not mapping_ids:
            return []

        stmt = select(MappingModel).where(MappingModel.id.in_(mapping_ids))

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_source_field(
        self, integration_id: UUID, source_field: str, entity_type: str | None = None
    ) -> list[IntegrationMapping]:
        """Find mappings by source field."""
        stmt = select(MappingModel).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.source_field == source_field,
            )
        )

        if entity_type:
            stmt = stmt.where(MappingModel.entity_type == entity_type)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_target_field(
        self, integration_id: UUID, target_field: str, entity_type: str | None = None
    ) -> list[IntegrationMapping]:
        """Find mappings by target field."""
        stmt = select(MappingModel).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.target_field == target_field,
            )
        )

        if entity_type:
            stmt = stmt.where(MappingModel.entity_type == entity_type)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_with_transformation(
        self, integration_id: UUID, transformation: MappingTransformation
    ) -> list[IntegrationMapping]:
        """Find mappings using specific transformation."""
        stmt = select(MappingModel).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.transformation == transformation,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_required(
        self, integration_id: UUID, entity_type: str | None = None
    ) -> list[IntegrationMapping]:
        """Find required mappings."""
        stmt = select(MappingModel).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.is_required is True,
                MappingModel.is_active is True,
            )
        )

        if entity_type:
            stmt = stmt.where(MappingModel.entity_type == entity_type)

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_with_custom_script(
        self, integration_id: UUID
    ) -> list[IntegrationMapping]:
        """Find mappings with custom transformation scripts."""
        stmt = select(MappingModel).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.custom_script is not None,
                MappingModel.custom_script != "",
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def get_entity_types(self, integration_id: UUID) -> list[str]:
        """Get all entity types for an integration."""
        stmt = (
            select(MappingModel.entity_type)
            .where(MappingModel.integration_id == integration_id)
            .distinct()
            .order_by(MappingModel.entity_type)
        )

        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_integration(
        self, integration_id: UUID, active_only: bool = True
    ) -> int:
        """Count mappings for an integration."""
        stmt = select(func.count(MappingModel.id)).where(
            MappingModel.integration_id == integration_id
        )

        if active_only:
            stmt = stmt.where(MappingModel.is_active is True)

        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def exists_by_fields(
        self,
        integration_id: UUID,
        source_field: str,
        target_field: str,
        exclude_id: UUID | None = None,
    ) -> bool:
        """Check if mapping exists for field combination."""
        stmt = select(MappingModel.id).where(
            and_(
                MappingModel.integration_id == integration_id,
                MappingModel.source_field == source_field,
                MappingModel.target_field == target_field,
            )
        )

        if exclude_id:
            stmt = stmt.where(MappingModel.id != exclude_id)

        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def validate_mapping_compatibility(
        self, mapping: IntegrationMapping
    ) -> dict[str, Any]:
        """Validate mapping compatibility."""
        issues = []
        warnings = []

        # Check type compatibility
        if not mapping.is_type_compatible:
            issues.append(
                f"Type incompatibility: {mapping.source_type.value} "
                f"-> {mapping.target_type.value}"
            )

        # Check if transformation is needed but not configured
        if mapping.source_type != mapping.target_type:
            if mapping.transformation == MappingTransformation.NONE:
                warnings.append(
                    "Type conversion may be needed but no transformation configured"
                )

        # Check required fields with no default
        if mapping.is_required and mapping.default_value is None:
            warnings.append("Required field has no default value configured")

        # Check custom script syntax (basic check)
        if mapping.custom_script and "return" not in mapping.custom_script:
            warnings.append("Custom script should include a return statement")

        return {"is_valid": len(issues) == 0, "issues": issues, "warnings": warnings}

    async def save_with_lock(self, mapping: IntegrationMapping) -> IntegrationMapping:
        """Save mapping with optimistic locking."""
        model = self._to_model(mapping)

        if mapping._version > 1:
            # Update with version check
            stmt = select(MappingModel).where(
                and_(
                    MappingModel.id == model.id,
                    MappingModel.version == mapping._version - 1,
                )
            )

            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                raise ConflictError("Mapping has been modified by another process")

            # Update fields
            for key, value in model.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)

            existing.version = mapping._version
            model = existing
        else:
            # New mapping
            self._session.add(model)

        try:
            await self._session.flush()
            mapping._version = model.version
            return mapping
        except IntegrityError as e:
            if "uq_mappings_integration_source_target" in str(e):
                raise ConflictError(
                    f"Mapping already exists for {mapping.source_field} "
                    f"-> {mapping.target_field}"
                )
            raise

    async def delete(self, mapping_id: UUID) -> None:
        """Delete mapping."""
        stmt = select(MappingModel).where(MappingModel.id == mapping_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Mapping {mapping_id} not found")

        await self._session.delete(model)
        await self._session.flush()

    async def bulk_update_active_status(
        self, mapping_ids: list[UUID], is_active: bool
    ) -> int:
        """Bulk update active status for multiple mappings."""
        if not mapping_ids:
            return 0

        stmt = select(MappingModel).where(MappingModel.id.in_(mapping_ids))

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        for model in models:
            model.is_active = is_active
            model.updated_at = datetime.now(timezone.utc)

        await self._session.flush()
        return len(models)
