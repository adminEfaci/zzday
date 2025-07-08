"""
Template GraphQL Input Types

Input types for template operations including creation, updates, testing,
and management.
"""

from uuid import UUID

import strawberry

from ..types.notification_type import NotificationCategoryType
from ..types.recipient_type import ContactMethodType
from ..types.template_type import TemplateFormatType, TemplateStatusType


@strawberry.input
class TemplateVariableInput:
    """Input for template variable definition."""

    name: str = strawberry.field(
        description="Variable name (e.g., 'user_name', 'order_id')"
    )

    type: str = strawberry.field(
        description="Variable type (string, number, boolean, date, array, object)"
    )

    required: bool = strawberry.field(description="Whether this variable is required")

    default_value: str | None = strawberry.field(
        description="Default value if not provided"
    )

    description: str | None = strawberry.field(description="Variable description")

    validation_rules: str | None = strawberry.field(
        description="Validation rules (JSON)"
    )

    example_value: str | None = strawberry.field(
        description="Example value for documentation"
    )


@strawberry.input
class TemplateContentInput:
    """Input for template content."""

    channel: ContactMethodType = strawberry.field(
        description="Channel this content is for"
    )

    format: TemplateFormatType = strawberry.field(description="Content format")

    subject: str | None = strawberry.field(
        description="Subject template (for email/push)"
    )

    body: str = strawberry.field(description="Main content template")

    html_body: str | None = strawberry.field(
        description="HTML content template (for email)"
    )

    short_text: str | None = strawberry.field(
        description="Short text template (for SMS/push)"
    )

    metadata: str | None = strawberry.field(
        description="Additional content metadata (JSON)"
    )


@strawberry.input
class TemplateCreateInput:
    """Input for creating a new template."""

    name: str = strawberry.field(description="Template name")

    description: str | None = strawberry.field(description="Template description")

    category: NotificationCategoryType = strawberry.field(
        description="Template category"
    )

    status: TemplateStatusType | None = strawberry.field(
        description="Template status", default=TemplateStatusType.DRAFT
    )

    variables: list[TemplateVariableInput] = strawberry.field(
        description="Template variables"
    )

    content: list[TemplateContentInput] = strawberry.field(
        description="Template content for different channels"
    )

    supported_channels: list[ContactMethodType] = strawberry.field(
        description="Channels this template supports"
    )

    locale: str | None = strawberry.field(
        description="Template locale (e.g., 'en-US', 'es-ES')"
    )

    timezone: str | None = strawberry.field(
        description="Default timezone for date formatting"
    )

    validation_schema: str | None = strawberry.field(
        description="JSON schema for variable validation"
    )

    tags: list[str] | None = strawberry.field(description="Tags for organization")

    folder: str | None = strawberry.field(description="Folder/category path")

    is_public: bool | None = strawberry.field(
        description="Whether template is publicly accessible", default=False
    )


@strawberry.input
class TemplateUpdateInput:
    """Input for updating an existing template."""

    name: str | None = strawberry.field(description="Template name")

    description: str | None = strawberry.field(description="Template description")

    category: NotificationCategoryType | None = strawberry.field(
        description="Template category"
    )

    status: TemplateStatusType | None = strawberry.field(description="Template status")

    variables: list[TemplateVariableInput] | None = strawberry.field(
        description="Template variables"
    )

    content: list[TemplateContentInput] | None = strawberry.field(
        description="Template content for different channels"
    )

    supported_channels: list[ContactMethodType] | None = strawberry.field(
        description="Channels this template supports"
    )

    locale: str | None = strawberry.field(
        description="Template locale (e.g., 'en-US', 'es-ES')"
    )

    timezone: str | None = strawberry.field(
        description="Default timezone for date formatting"
    )

    validation_schema: str | None = strawberry.field(
        description="JSON schema for variable validation"
    )

    tags: list[str] | None = strawberry.field(description="Tags for organization")

    folder: str | None = strawberry.field(description="Folder/category path")

    is_public: bool | None = strawberry.field(
        description="Whether template is publicly accessible"
    )


@strawberry.input
class TemplateFilterInput:
    """Filter input for template queries."""

    status: list[TemplateStatusType] | None = strawberry.field(
        description="Filter by template status"
    )

    category: list[NotificationCategoryType] | None = strawberry.field(
        description="Filter by category"
    )

    supported_channels: list[ContactMethodType] | None = strawberry.field(
        description="Filter by supported channels"
    )

    tags: list[str] | None = strawberry.field(description="Filter by tags (OR logic)")

    tags_all: list[str] | None = strawberry.field(
        description="Filter by tags (AND logic - must have all)"
    )

    folder: str | None = strawberry.field(description="Filter by folder/category path")

    search_query: str | None = strawberry.field(
        description="Search in template name and description"
    )

    is_public: bool | None = strawberry.field(
        description="Filter by public/private templates"
    )

    is_system_template: bool | None = strawberry.field(
        description="Filter by system templates"
    )

    created_by: UUID | None = strawberry.field(description="Filter by creator")

    usage_count_min: int | None = strawberry.field(description="Minimum usage count")

    usage_count_max: int | None = strawberry.field(description="Maximum usage count")


@strawberry.input
class TemplateTestInput:
    """Input for testing template rendering."""

    template_id: UUID = strawberry.field(description="Template to test")

    channel: ContactMethodType = strawberry.field(description="Channel to test for")

    test_variables: str = strawberry.field(description="Test variables as JSON string")

    locale: str | None = strawberry.field(
        description="Locale for testing (overrides template default)"
    )

    timezone: str | None = strawberry.field(
        description="Timezone for testing (overrides template default)"
    )


@strawberry.input
class TemplatePreviewInput:
    """Input for template preview generation."""

    template_id: UUID = strawberry.field(description="Template to preview")

    channel: ContactMethodType = strawberry.field(description="Channel to preview for")

    sample_variables: str | None = strawberry.field(
        description="Sample variables as JSON string (optional - uses defaults)"
    )


@strawberry.input
class TemplateCloneInput:
    """Input for cloning an existing template."""

    source_template_id: UUID = strawberry.field(description="Template to clone from")

    new_name: str = strawberry.field(description="Name for the cloned template")

    new_description: str | None = strawberry.field(
        description="Description for the cloned template"
    )

    copy_content: bool | None = strawberry.field(
        description="Whether to copy template content", default=True
    )

    copy_variables: bool | None = strawberry.field(
        description="Whether to copy template variables", default=True
    )

    folder: str | None = strawberry.field(description="Folder for the cloned template")


@strawberry.input
class BulkTemplateUpdateInput:
    """Input for bulk template operations."""

    template_ids: list[UUID] = strawberry.field(description="Template IDs to update")

    status: TemplateStatusType | None = strawberry.field(
        description="New status for all templates"
    )

    tags_to_add: list[str] | None = strawberry.field(
        description="Tags to add to all templates"
    )

    tags_to_remove: list[str] | None = strawberry.field(
        description="Tags to remove from all templates"
    )

    folder: str | None = strawberry.field(description="New folder for all templates")

    is_public: bool | None = strawberry.field(
        description="Update public/private status"
    )
