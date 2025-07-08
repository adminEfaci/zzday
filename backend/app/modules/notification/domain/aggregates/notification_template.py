"""NotificationTemplate aggregate for managing notification templates.

This aggregate manages reusable notification templates with variable substitution,
multi-channel support, and versioning.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    NotificationChannel,
    TemplateType,
    VariableType,
)
from app.modules.notification.domain.errors import (
    InvalidTemplateError,
    TemplateVariableError,
)
from app.modules.notification.domain.events import (
    TemplateCreated,
    TemplateDeleted,
    TemplateUpdated,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    TemplateVariable,
)

# Constants
MAX_TEMPLATE_NAME_LENGTH = 100
MAX_SMS_LENGTH = 1600
MAX_PUSH_TITLE_LENGTH = 65
MAX_PUSH_BODY_LENGTH = 240


class NotificationTemplate(AggregateRoot):
    """Aggregate for managing notification templates.

    This aggregate handles the creation, modification, and lifecycle of
    notification templates that can be used across multiple channels with
    variable substitution support.
    """

    def __init__(
        self,
        name: str,
        template_type: TemplateType,
        created_by: UUID,
        description: str | None = None,
        tags: list[str] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize notification template.

        Args:
            name: Template name
            template_type: Type of template
            created_by: User who created the template
            description: Template description
            tags: Template tags for categorization
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Basic fields
        self.name = self._validate_name(name)
        self.template_type = template_type
        self.created_by = created_by
        self.description = description
        self.tags = tags or []

        # Template content by channel
        self.channel_contents: dict[NotificationChannel, NotificationContent] = {}

        # Variable definitions
        self.variables: dict[str, TemplateVariable] = {}

        # Versioning
        self.version: int = 1
        self.version_history: list[dict[str, Any]] = []

        # Status tracking
        self.is_active: bool = True
        self.is_default: bool = False
        self.last_used_at: datetime | None = None
        self.usage_count: int = 0

        # Validation rules
        self.required_channels: set[NotificationChannel] = set()
        self.validation_rules: dict[str, Any] = {}

        # Add creation event
        self.add_event(
            TemplateCreated(
                template_id=self.id,
                name=self.name,
                template_type=self.template_type,
                channels=[],  # Will be updated when content is added
                created_by=self.created_by,
                is_active=self.is_active,
            )
        )

    def _validate_name(self, name: str) -> str:
        """Validate template name."""
        if not name or not name.strip():
            raise ValidationError("Template name is required")

        name = name.strip()
        if len(name) > MAX_TEMPLATE_NAME_LENGTH:
            raise ValidationError(f"Template name cannot exceed {MAX_TEMPLATE_NAME_LENGTH} characters")

        return name

    def add_channel_content(
        self,
        channel: NotificationChannel,
        content: NotificationContent,
        updated_by: UUID,
    ) -> None:
        """Add or update content for a channel.

        Args:
            channel: Target channel
            content: Notification content
            updated_by: User making the update
        """
        # Validate content for channel
        self._validate_channel_content(channel, content)

        # Extract variables from content
        content_variables = content.extract_variables()

        # Ensure all template variables are defined
        for var_name in content_variables:
            if var_name not in self.variables:
                # Auto-create variable definition with default type
                self.variables[var_name] = TemplateVariable(
                    name=var_name,
                    var_type=VariableType.STRING,
                    required=True,
                    description=f"Variable {var_name} used in {channel.value} content",
                )

        # Store content
        is_new_channel = channel not in self.channel_contents
        self.channel_contents[channel] = content

        # Update version
        self._increment_version(updated_by, f"Added/updated {channel.value} content")

        # Add update event
        changes = {
            "channel": channel.value,
            "action": "added" if is_new_channel else "updated",
        }
        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def _validate_channel_content(
        self, channel: NotificationChannel, content: NotificationContent
    ) -> None:
        """Validate content for specific channel requirements."""
        # Email requires subject
        if channel == NotificationChannel.EMAIL and not content.subject:
            raise InvalidTemplateError(
                template_id=self.id,
                template_name=self.name,
                reason="Email templates require a subject",
            )

        # SMS has length limits
        if channel == NotificationChannel.SMS and len(content.body) > MAX_SMS_LENGTH:
            raise InvalidTemplateError(
                template_id=self.id,
                template_name=self.name,
                reason=f"SMS template body cannot exceed {MAX_SMS_LENGTH} characters",
            )

        # Push notifications have length limits
        if channel == NotificationChannel.PUSH:
            if content.subject and len(content.subject) > MAX_PUSH_TITLE_LENGTH:
                raise InvalidTemplateError(
                    template_id=self.id,
                    template_name=self.name,
                    reason=f"Push notification title cannot exceed {MAX_PUSH_TITLE_LENGTH} characters",
                )
            if len(content.body) > MAX_PUSH_BODY_LENGTH:
                raise InvalidTemplateError(
                    template_id=self.id,
                    template_name=self.name,
                    reason=f"Push notification body cannot exceed {MAX_PUSH_BODY_LENGTH} characters",
                )

    def remove_channel_content(
        self, channel: NotificationChannel, updated_by: UUID
    ) -> None:
        """Remove content for a channel.

        Args:
            channel: Channel to remove
            updated_by: User making the update
        """
        if channel not in self.channel_contents:
            raise ValidationError(f"No content found for channel {channel.value}")

        # Check if this is a required channel
        if channel in self.required_channels:
            raise ValidationError(f"Cannot remove required channel {channel.value}")

        del self.channel_contents[channel]

        # Update version
        self._increment_version(updated_by, f"Removed {channel.value} content")

        # Add update event
        changes = {"channel": channel.value, "action": "removed"}
        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def define_variable(self, variable: TemplateVariable, updated_by: UUID) -> None:
        """Define or update a template variable.

        Args:
            variable: Variable definition
            updated_by: User making the update
        """
        is_new = variable.name not in self.variables
        self.variables[variable.name] = variable

        # Update version
        action = "defined" if is_new else "updated"
        self._increment_version(updated_by, f"{action} variable {variable.name}")

        # Add update event
        changes = {
            "variable": variable.name,
            "action": action,
            "type": variable.var_type.value,
        }
        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def remove_variable(self, variable_name: str, updated_by: UUID) -> None:
        """Remove a variable definition.

        Args:
            variable_name: Variable to remove
            updated_by: User making the update
        """
        if variable_name not in self.variables:
            raise ValidationError(f"Variable {variable_name} not found")

        # Check if variable is used in any content
        for channel, content in self.channel_contents.items():
            if variable_name in content.extract_variables():
                raise ValidationError(
                    f"Cannot remove variable {variable_name} - "
                    f"it is used in {channel.value} content"
                )

        del self.variables[variable_name]

        # Update version
        self._increment_version(updated_by, f"Removed variable {variable_name}")

        # Add update event
        changes = {"variable": variable_name, "action": "removed"}
        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def validate_variables(self, provided_variables: dict[str, Any]) -> None:
        """Validate provided variables against template requirements.

        Args:
            provided_variables: Variables to validate

        Raises:
            TemplateVariableError: If validation fails
        """
        missing_variables = []
        invalid_variables = {}

        # Check required variables
        for var_name, var_def in self.variables.items():
            if var_def.required and var_name not in provided_variables:
                if var_def.default_value is None:
                    missing_variables.append(var_name)

        # Validate provided variables
        for var_name, value in provided_variables.items():
            if var_name in self.variables:
                var_def = self.variables[var_name]
                if not var_def.validate_value(value):
                    invalid_variables[
                        var_name
                    ] = f"Invalid value for {var_def.var_type.value} type"

        if missing_variables or invalid_variables:
            raise TemplateVariableError(
                template_id=self.id,
                missing_variables=missing_variables,
                invalid_variables=invalid_variables,
            )

    def render_for_channel(
        self, channel: NotificationChannel, variables: dict[str, Any]
    ) -> NotificationContent:
        """Render template content for a specific channel.

        Args:
            channel: Target channel
            variables: Template variables

        Returns:
            Rendered notification content
        """
        if channel not in self.channel_contents:
            raise InvalidTemplateError(
                template_id=self.id,
                template_name=self.name,
                reason=f"No content defined for channel {channel.value}",
            )

        # Validate variables
        self.validate_variables(variables)

        # Apply defaults for missing optional variables
        full_variables = {}
        for var_name, var_def in self.variables.items():
            if var_name in variables:
                full_variables[var_name] = variables[var_name]
            elif var_def.default_value is not None:
                full_variables[var_name] = var_def.default_value

        # Format variables
        formatted_variables = {}
        for var_name, value in full_variables.items():
            if var_name in self.variables:
                formatted_variables[var_name] = self.variables[var_name].format_value(
                    value
                )
            else:
                formatted_variables[var_name] = str(value)

        # Render content
        content = self.channel_contents[channel]
        return content.render(formatted_variables)

    def set_required_channels(
        self, channels: list[NotificationChannel], updated_by: UUID
    ) -> None:
        """Set required channels for this template.

        Args:
            channels: Required channels
            updated_by: User making the update
        """
        # Validate all required channels have content
        for channel in channels:
            if channel not in self.channel_contents:
                raise ValidationError(
                    f"Cannot require channel {channel.value} without content"
                )

        self.required_channels = set(channels)

        # Update version
        self._increment_version(
            updated_by,
            f"Set required channels: {', '.join(ch.value for ch in channels)}",
        )

        self.mark_modified()

    def activate(self, updated_by: UUID) -> None:
        """Activate the template.

        Args:
            updated_by: User making the update
        """
        if self.is_active:
            return

        # Validate template has at least one channel
        if not self.channel_contents:
            raise InvalidTemplateError(
                template_id=self.id,
                template_name=self.name,
                reason="Cannot activate template without any channel content",
            )

        self.is_active = True
        self._increment_version(updated_by, "Activated template")

        # Add update event
        changes = {"is_active": True}
        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def deactivate(self, updated_by: UUID, reason: str | None = None) -> None:
        """Deactivate the template.

        Args:
            updated_by: User making the update
            reason: Deactivation reason
        """
        if not self.is_active:
            return

        self.is_active = False
        self._increment_version(
            updated_by, f"Deactivated template{': ' + reason if reason else ''}"
        )

        # Add update event
        changes = {"is_active": False}
        if reason:
            changes["reason"] = reason

        self.add_event(
            TemplateUpdated(
                template_id=self.id,
                updated_by=updated_by,
                changes=changes,
                version=self.version,
            )
        )

        self.mark_modified()

    def mark_as_used(self) -> None:
        """Mark template as used."""
        self.last_used_at = datetime.utcnow()
        self.usage_count += 1
        self.mark_modified()

    def set_as_default(self, updated_by: UUID) -> None:
        """Set this template as default for its type.

        Args:
            updated_by: User making the update
        """
        if not self.is_active:
            raise ValidationError("Cannot set inactive template as default")

        self.is_default = True
        self._increment_version(updated_by, "Set as default template")

        self.mark_modified()

    def add_tag(self, tag: str) -> None:
        """Add a tag to the template.

        Args:
            tag: Tag to add
        """
        if tag not in self.tags:
            self.tags.append(tag)
            self.mark_modified()

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the template.

        Args:
            tag: Tag to remove
        """
        if tag in self.tags:
            self.tags.remove(tag)
            self.mark_modified()

    def delete(self, deleted_by: UUID, reason: str | None = None) -> None:
        """Soft delete the template.

        Args:
            deleted_by: User deleting the template
            reason: Deletion reason
        """
        self.is_active = False
        self.add_metadata("deleted", True)
        self.add_metadata("deleted_by", str(deleted_by))
        self.add_metadata("deleted_at", datetime.utcnow().isoformat())
        if reason:
            self.add_metadata("deletion_reason", reason)

        # Add deletion event
        self.add_event(
            TemplateDeleted(template_id=self.id, deleted_by=deleted_by, reason=reason)
        )

        self.mark_modified()

    def _increment_version(self, updated_by: UUID, change_description: str) -> None:
        """Increment template version and record in history.

        Args:
            updated_by: User making the change
            change_description: Description of the change
        """
        self.version += 1

        # Add to version history
        self.version_history.append(
            {
                "version": self.version,
                "updated_by": str(updated_by),
                "updated_at": datetime.utcnow().isoformat(),
                "description": change_description,
            }
        )

        # Keep only last 50 versions
        if len(self.version_history) > 50:
            self.version_history = self.version_history[-50:]

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to template.

        Args:
            key: Metadata key
            value: Metadata value
        """
        if not hasattr(self, "metadata"):
            self.metadata = {}
        self.metadata[key] = value
        self.mark_modified()

    def get_supported_channels(self) -> list[NotificationChannel]:
        """Get list of channels this template supports."""
        return list(self.channel_contents.keys())

    def get_usage_stats(self) -> dict[str, Any]:
        """Get template usage statistics."""
        return {
            "usage_count": self.usage_count,
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "version": self.version,
            "channel_count": len(self.channel_contents),
            "variable_count": len(self.variables),
            "is_active": self.is_active,
            "is_default": self.is_default,
        }

    def export(self) -> dict[str, Any]:
        """Export template configuration."""
        return {
            "id": str(self.id),
            "name": self.name,
            "template_type": self.template_type.value,
            "description": self.description,
            "tags": self.tags,
            "version": self.version,
            "is_active": self.is_active,
            "is_default": self.is_default,
            "channels": {
                channel.value: {
                    "subject": content.subject,
                    "body": content.body,
                    "html_body": content.html_body,
                    "attachments": content.attachments,
                }
                for channel, content in self.channel_contents.items()
            },
            "variables": {
                name: {
                    "type": var.var_type.value,
                    "required": var.required,
                    "default_value": var.default_value,
                    "description": var.description,
                    "format_pattern": var.format_pattern,
                    "validation_rules": var.validation_rules,
                }
                for name, var in self.variables.items()
            },
            "required_channels": [ch.value for ch in self.required_channels],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def __str__(self) -> str:
        """String representation."""
        channels = ", ".join(ch.value for ch in self.channel_contents)
        return (
            f"NotificationTemplate({self.name}) - "
            f"Type: {self.template_type.value} - "
            f"Channels: [{channels}] - "
            f"v{self.version}"
        )
