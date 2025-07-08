"""Repository implementation for NotificationTemplate aggregate."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.enums import (
    NotificationChannel,
    TemplateType,
    VariableType,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    TemplateVariable,
)
from app.modules.notification.infrastructure.models.notification_template import (
    NotificationTemplateModel,
)


class NotificationTemplateRepository(
    BaseRepository[NotificationTemplate, NotificationTemplateModel]
):
    """Repository for managing notification template persistence."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        super().__init__(session, NotificationTemplateModel)

    async def find_by_name(self, name: str) -> NotificationTemplate | None:
        """Find template by name.

        Args:
            name: Template name

        Returns:
            Template if found, None otherwise
        """
        stmt = select(self.model_class).where(self.model_class.name == name)
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def find_default_by_type(
        self, template_type: TemplateType
    ) -> NotificationTemplate | None:
        """Find default template for a given type.

        Args:
            template_type: Type of template

        Returns:
            Default template if found, None otherwise
        """
        stmt = select(self.model_class).where(
            and_(
                self.model_class.template_type == template_type,
                self.model_class.is_default is True,
                self.model_class.is_active is True,
            )
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def find_by_type_and_tags(
        self,
        template_type: TemplateType | None = None,
        tags: list[str] | None = None,
        is_active: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NotificationTemplate]:
        """Find templates by type and tags.

        Args:
            template_type: Optional template type filter
            tags: Optional list of tags (templates must have all tags)
            is_active: Optional active status filter
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of templates
        """
        stmt = select(self.model_class)

        if template_type:
            stmt = stmt.where(self.model_class.template_type == template_type)

        if tags:
            # Use PostgreSQL array operators for JSON array
            for tag in tags:
                stmt = stmt.where(
                    func.jsonb_contains(self.model_class.tags, f'["{tag}"]')
                )

        if is_active is not None:
            stmt = stmt.where(self.model_class.is_active == is_active)

        stmt = stmt.order_by(self.model_class.name.asc())
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_by_channel(
        self,
        channel: NotificationChannel,
        template_type: TemplateType | None = None,
        is_active: bool = True,
    ) -> list[NotificationTemplate]:
        """Find templates that support a specific channel.

        Args:
            channel: Notification channel
            template_type: Optional template type filter
            is_active: Whether to filter by active status

        Returns:
            List of templates supporting the channel
        """
        stmt = select(self.model_class).where(
            func.jsonb_exists(self.model_class.channel_contents, channel.value)
        )

        if template_type:
            stmt = stmt.where(self.model_class.template_type == template_type)

        if is_active:
            stmt = stmt.where(self.model_class.is_active is True)

        stmt = stmt.order_by(self.model_class.name.asc())

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def search_templates(
        self, query: str, limit: int = 50
    ) -> list[NotificationTemplate]:
        """Search templates by name or description.

        Args:
            query: Search query
            limit: Maximum number of results

        Returns:
            List of matching templates
        """
        search_pattern = f"%{query}%"

        stmt = select(self.model_class).where(
            or_(
                self.model_class.name.ilike(search_pattern),
                self.model_class.description.ilike(search_pattern),
            )
        )

        stmt = stmt.order_by(self.model_class.name.asc())
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def get_usage_statistics(
        self,
        template_ids: list[UUID] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get usage statistics for templates.

        Args:
            template_ids: Optional list of template IDs to filter
            start_date: Optional start date for usage
            end_date: Optional end date for usage

        Returns:
            Dictionary with usage statistics
        """
        # This would typically join with notification table
        # For now, return aggregated usage counts from templates
        stmt = select(
            func.count(self.model_class.id).label("template_count"),
            func.sum(self.model_class.usage_count).label("total_usage"),
            func.avg(self.model_class.usage_count).label("avg_usage"),
        ).where(self.model_class.is_active is True)

        if template_ids:
            stmt = stmt.where(self.model_class.id.in_(template_ids))

        result = await self.session.execute(stmt)
        stats = result.one()

        return {
            "template_count": stats.template_count or 0,
            "total_usage": stats.total_usage or 0,
            "avg_usage": float(stats.avg_usage or 0),
        }

    async def increment_usage_count(self, template_id: UUID) -> None:
        """Increment template usage count.

        Args:
            template_id: Template ID
        """
        stmt = (
            update(self.model_class)
            .where(self.model_class.id == template_id)
            .values(
                usage_count=self.model_class.usage_count + 1,
                last_used_at=datetime.utcnow(),
            )
        )

        await self.session.execute(stmt)
        await self.session.commit()

    async def set_default_template(
        self, template_id: UUID, template_type: TemplateType
    ) -> None:
        """Set a template as default for its type.

        Args:
            template_id: Template to set as default
            template_type: Template type
        """
        # First, unset any existing default for this type
        unset_stmt = (
            update(self.model_class)
            .where(
                and_(
                    self.model_class.template_type == template_type,
                    self.model_class.is_default is True,
                )
            )
            .values(is_default=False)
        )

        await self.session.execute(unset_stmt)

        # Then set the new default
        set_stmt = (
            update(self.model_class)
            .where(self.model_class.id == template_id)
            .values(is_default=True)
        )

        await self.session.execute(set_stmt)
        await self.session.commit()

    def _to_entity(self, model: NotificationTemplateModel) -> NotificationTemplate:
        """Convert database model to domain aggregate.

        Args:
            model: Database model

        Returns:
            Domain aggregate
        """
        if not model:
            return None

        # Create aggregate
        template = NotificationTemplate(
            name=model.name,
            template_type=model.template_type,
            created_by=model.created_by,
            description=model.description,
            tags=model.tags,
            entity_id=model.id,
        )

        # Set timestamps
        template.created_at = model.created_at
        template.updated_at = model.updated_at

        # Set channel contents
        if model.channel_contents:
            for channel_str, content_data in model.channel_contents.items():
                channel = NotificationChannel(channel_str)
                content = NotificationContent(
                    subject=content_data.get("subject"),
                    body=content_data.get("body", ""),
                    html_body=content_data.get("html_body"),
                    variables=content_data.get("variables"),
                    attachments=content_data.get("attachments"),
                    metadata=content_data.get("metadata"),
                )
                template.channel_contents[channel] = content

        # Set variable definitions
        if model.variables:
            for var_name, var_data in model.variables.items():
                variable = TemplateVariable(
                    name=var_name,
                    var_type=VariableType(var_data["type"]),
                    required=var_data.get("required", True),
                    default_value=var_data.get("default_value"),
                    description=var_data.get("description"),
                    format_pattern=var_data.get("format_pattern"),
                    validation_rules=var_data.get("validation_rules"),
                )
                template.variables[var_name] = variable

        # Set versioning
        template.version = model.version
        template.version_history = model.version_history or []

        # Set status
        template.is_active = model.is_active
        template.is_default = model.is_default
        template.last_used_at = model.last_used_at
        template.usage_count = model.usage_count

        # Set configuration
        template.required_channels = {
            NotificationChannel(ch) for ch in (model.required_channels or [])
        }
        template.validation_rules = model.validation_rules or {}

        # Set metadata
        if model.metadata:
            template.metadata = model.metadata

        # Clear events (we don't want to replay them)
        template.clear_events()

        return template

    def _to_model(self, entity: NotificationTemplate) -> NotificationTemplateModel:
        """Convert domain aggregate to database model.

        Args:
            entity: Domain aggregate

        Returns:
            Database model
        """
        # Serialize channel contents
        channel_contents = {}
        for channel, content in entity.channel_contents.items():
            channel_contents[channel.value] = {
                "subject": content.subject,
                "body": content.body,
                "html_body": content.html_body,
                "variables": content.variables,
                "attachments": content.attachments,
                "metadata": content.metadata,
            }

        # Serialize variable definitions
        variables = {}
        for var_name, variable in entity.variables.items():
            variables[var_name] = {
                "type": variable.var_type.value,
                "required": variable.required,
                "default_value": variable.default_value,
                "description": variable.description,
                "format_pattern": variable.format_pattern,
                "validation_rules": variable.validation_rules,
            }

        return NotificationTemplateModel(
            id=entity.id,
            name=entity.name,
            template_type=entity.template_type,
            description=entity.description,
            tags=entity.tags,
            channel_contents=channel_contents,
            variables=variables,
            version=entity.version,
            version_history=entity.version_history,
            is_active=entity.is_active,
            is_default=entity.is_default,
            usage_count=entity.usage_count,
            last_used_at=entity.last_used_at,
            required_channels=[ch.value for ch in entity.required_channels],
            validation_rules=entity.validation_rules,
            metadata=getattr(entity, "metadata", None),
            created_by=entity.created_by,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
