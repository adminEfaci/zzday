"""Update mapping command and handler.

This module provides the command and handler for updating integration mappings
with validation and transformation rules.
"""

from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import MappingConfigDTO
from app.modules.integration.domain.enums import FieldType, MappingTransformation

logger = get_logger(__name__)


class UpdateMappingCommand(Command):
    """Command to update integration mapping configuration."""

    def __init__(
        self,
        mapping_id: UUID,
        name: str | None = None,
        description: str | None = None,
        field_mappings: list[dict[str, Any]] | None = None,
        filters: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
        is_active: bool | None = None,
    ):
        """Initialize update mapping command.

        Args:
            mapping_id: ID of mapping to update
            name: New mapping name
            description: New description
            field_mappings: Updated field mappings
            filters: Updated filters
            options: Updated options
            is_active: Active status
        """
        super().__init__()

        self.mapping_id = mapping_id
        self.name = name
        self.description = description
        self.field_mappings = field_mappings
        self.filters = filters
        self.options = options
        self.is_active = is_active

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.mapping_id:
            raise ValidationError("mapping_id is required")

        # At least one field must be updated
        if all(
            field is None
            for field in [
                self.name,
                self.description,
                self.field_mappings,
                self.filters,
                self.options,
                self.is_active,
            ]
        ):
            raise ValidationError("At least one field must be provided for update")

        # Validate field mappings if provided
        if self.field_mappings is not None:
            self._validate_field_mappings()

    def _validate_field_mappings(self) -> None:
        """Validate field mappings structure."""
        if not isinstance(self.field_mappings, list):
            raise ValidationError("field_mappings must be a list")

        for idx, mapping in enumerate(self.field_mappings):
            if not isinstance(mapping, dict):
                raise ValidationError(
                    f"Field mapping at index {idx} must be a dictionary"
                )

            # Required fields
            required_fields = [
                "source_field",
                "target_field",
                "field_type",
                "transformation",
            ]
            for field in required_fields:
                if field not in mapping:
                    raise ValidationError(
                        f"Field mapping at index {idx} missing required field: {field}"
                    )

            # Validate field type
            try:
                FieldType(mapping["field_type"])
            except ValueError:
                raise ValidationError(
                    f"Invalid field_type at index {idx}: {mapping['field_type']}"
                )

            # Validate transformation
            try:
                MappingTransformation(mapping["transformation"])
            except ValueError:
                raise ValidationError(
                    f"Invalid transformation at index {idx}: {mapping['transformation']}"
                )


class UpdateMappingCommandHandler(
    CommandHandler[UpdateMappingCommand, MappingConfigDTO]
):
    """Handler for updating integration mappings."""

    def __init__(
        self,
        mapping_repository: Any,
        integration_repository: Any,
        mapping_validator: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            mapping_repository: Repository for mapping persistence
            integration_repository: Repository for integrations
            mapping_validator: Service for validating mappings
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._mapping_repository = mapping_repository
        self._integration_repository = integration_repository
        self._mapping_validator = mapping_validator
        self._event_publisher = event_publisher

    async def handle(self, command: UpdateMappingCommand) -> MappingConfigDTO:
        """Handle update mapping command.

        Args:
            command: Update mapping command

        Returns:
            MappingConfigDTO: Updated mapping configuration

        Raises:
            NotFoundError: If mapping not found
            ValidationError: If updates are invalid
        """
        logger.info("Updating mapping", mapping_id=command.mapping_id)

        # Get mapping
        mapping = await self._mapping_repository.get_by_id(command.mapping_id)
        if not mapping:
            raise NotFoundError(f"Mapping not found: {command.mapping_id}")

        # Get integration for validation
        integration = await self._integration_repository.get_by_id(
            mapping.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {mapping.integration_id}")

        # Track changes for event
        changes = {}

        # Update fields if provided
        if command.name is not None:
            if not command.name.strip():
                raise ValidationError("Mapping name cannot be empty")
            changes["name"] = (mapping.name, command.name)
            mapping.update_name(command.name)

        if command.description is not None:
            changes["description"] = (mapping.description, command.description)
            mapping.update_description(command.description)

        if command.field_mappings is not None:
            # Validate field mappings before updating
            validation_result = await self._mapping_validator.validate_field_mappings(
                integration=integration, field_mappings=command.field_mappings
            )

            if not validation_result.is_valid:
                raise ValidationError(
                    f"Invalid field mappings: {validation_result.errors}"
                )

            changes["field_mappings"] = (mapping.field_mappings, command.field_mappings)
            mapping.update_field_mappings(command.field_mappings)

        if command.filters is not None:
            changes["filters"] = (mapping.filters, command.filters)
            mapping.update_filters(command.filters)

        if command.options is not None:
            changes["options"] = (mapping.options, command.options)
            mapping.update_options(command.options)

        if command.is_active is not None:
            changes["is_active"] = (mapping.is_active, command.is_active)
            if command.is_active:
                mapping.activate()
            else:
                mapping.deactivate()

        # Save changes
        await self._mapping_repository.save(mapping)

        # Publish events
        for event in mapping.collect_events():
            await self._event_publisher.publish(event)

        logger.info(
            "Mapping updated successfully",
            mapping_id=mapping.id,
            changes=list(changes.keys()),
        )

        return MappingConfigDTO.from_domain(mapping)

    @property
    def command_type(self) -> type[UpdateMappingCommand]:
        """Get command type this handler processes."""
        return UpdateMappingCommand
