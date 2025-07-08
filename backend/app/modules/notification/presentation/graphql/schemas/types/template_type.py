"""
Template GraphQL Types

Types for notification templates including template management, variable substitution,
and multi-channel template support.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from .notification_type import NotificationCategoryType
from .recipient_type import ContactMethodType


@strawberry.enum
class TemplateStatusType(str):
    """Template status."""

    DRAFT = "draft"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"


@strawberry.enum
class TemplateFormatType(str):
    """Template content format."""

    TEXT = "text"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    HANDLEBARS = "handlebars"
    JINJA2 = "jinja2"


@strawberry.type
class TemplateVariableType:
    """Template variable definition."""

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


@strawberry.type
class TemplateContentType:
    """Template content for different channels."""

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


@strawberry.type
class TemplateVersionType:
    """Template version information."""

    id: UUID = strawberry.field(description="Version identifier")

    version_number: str = strawberry.field(
        description="Version number (e.g., '1.0.0', '2.1.3')"
    )

    is_current: bool = strawberry.field(
        description="Whether this is the current active version"
    )

    changelog: str | None = strawberry.field(description="Changes made in this version")

    created_by: UUID = strawberry.field(description="User who created this version")

    created_at: datetime = strawberry.field(description="When this version was created")


@strawberry.type
class TemplateTestResultType:
    """Result of template testing/preview."""

    success: bool = strawberry.field(description="Whether the test was successful")

    rendered_content: str | None = strawberry.field(
        description="Rendered template content"
    )

    rendered_subject: str | None = strawberry.field(description="Rendered subject line")

    errors: list[str] = strawberry.field(description="List of errors if test failed")

    warnings: list[str] = strawberry.field(description="List of warnings")

    variable_usage: str | None = strawberry.field(
        description="Variable usage report (JSON)"
    )

    size_info: str | None = strawberry.field(
        description="Content size information (JSON)"
    )

    tested_at: datetime = strawberry.field(description="When the test was performed")


@strawberry.type
class TemplateAnalyticsType:
    """Template usage analytics."""

    total_notifications: int = strawberry.field(
        description="Total notifications sent using this template"
    )

    total_deliveries: int = strawberry.field(description="Total successful deliveries")

    total_opens: int = strawberry.field(description="Total opens (email only)")

    total_clicks: int = strawberry.field(description="Total clicks")

    delivery_rate: float = strawberry.field(
        description="Delivery success rate (0.0 - 1.0)"
    )

    open_rate: float = strawberry.field(description="Open rate (0.0 - 1.0)")

    click_rate: float = strawberry.field(description="Click-through rate (0.0 - 1.0)")

    avg_engagement_time: float | None = strawberry.field(
        description="Average engagement time in seconds"
    )

    by_channel: str = strawberry.field(description="Performance by channel (JSON)")

    usage_over_time: str = strawberry.field(description="Usage over time (JSON)")

    top_variables: str = strawberry.field(description="Most used variables (JSON)")


@strawberry.type
class NotificationTemplateType:
    """Comprehensive notification template."""

    id: UUID = strawberry.field(description="Unique template identifier")

    name: str = strawberry.field(description="Template name")

    description: str | None = strawberry.field(description="Template description")

    category: NotificationCategoryType = strawberry.field(
        description="Template category"
    )

    status: TemplateStatusType = strawberry.field(description="Template status")

    # Template definition
    variables: list[TemplateVariableType] = strawberry.field(
        description="Template variables"
    )

    content: list[TemplateContentType] = strawberry.field(
        description="Template content for different channels"
    )

    supported_channels: list[ContactMethodType] = strawberry.field(
        description="Channels this template supports"
    )

    # Versioning
    version: str = strawberry.field(description="Current version number")

    versions: list[TemplateVersionType] = strawberry.field(
        description="All template versions"
    )

    # Configuration
    locale: str | None = strawberry.field(
        description="Template locale (e.g., 'en-US', 'es-ES')"
    )

    timezone: str | None = strawberry.field(
        description="Default timezone for date formatting"
    )

    # Validation and testing
    validation_schema: str | None = strawberry.field(
        description="JSON schema for variable validation"
    )

    last_tested: datetime | None = strawberry.field(
        description="When template was last tested"
    )

    # Usage and analytics
    usage_count: int = strawberry.field(
        description="Number of times this template has been used"
    )

    analytics: TemplateAnalyticsType | None = strawberry.field(
        description="Template performance analytics"
    )

    # Organization
    tags: list[str] = strawberry.field(description="Tags for organization")

    folder: str | None = strawberry.field(description="Folder/category path")

    # Permissions and access
    is_system_template: bool = strawberry.field(
        description="Whether this is a system template"
    )

    is_public: bool = strawberry.field(
        description="Whether template is publicly accessible"
    )

    # Audit fields
    created_by: UUID = strawberry.field(description="User who created the template")

    created_at: datetime = strawberry.field(description="When the template was created")

    updated_by: UUID | None = strawberry.field(
        description="User who last updated the template"
    )

    updated_at: datetime = strawberry.field(
        description="When the template was last updated"
    )

    last_used: datetime | None = strawberry.field(
        description="When the template was last used"
    )


@strawberry.type
class TemplatePreviewType:
    """Template preview with sample data."""

    template_id: UUID = strawberry.field(description="Template identifier")

    channel: ContactMethodType = strawberry.field(description="Channel being previewed")

    sample_variables: str = strawberry.field(description="Sample variables used (JSON)")

    rendered_subject: str | None = strawberry.field(description="Rendered subject line")

    rendered_body: str = strawberry.field(description="Rendered body content")

    rendered_html: str | None = strawberry.field(description="Rendered HTML content")

    rendered_short_text: str | None = strawberry.field(
        description="Rendered short text"
    )

    character_count: int = strawberry.field(description="Total character count")

    word_count: int = strawberry.field(description="Total word count")

    estimated_send_time: float | None = strawberry.field(
        description="Estimated send time in milliseconds"
    )

    generated_at: datetime = strawberry.field(
        description="When the preview was generated"
    )


@strawberry.type
class TemplateListType:
    """Paginated list of templates."""

    items: list[NotificationTemplateType] = strawberry.field(
        description="Templates in this page"
    )

    total_count: int = strawberry.field(description="Total number of templates")

    page: int = strawberry.field(description="Current page number")

    page_size: int = strawberry.field(description="Number of items per page")

    total_pages: int = strawberry.field(description="Total number of pages")

    has_next: bool = strawberry.field(description="Whether there are more pages")

    has_previous: bool = strawberry.field(
        description="Whether there are previous pages"
    )


@strawberry.type
class TemplateSummaryType:
    """Summary statistics for templates."""

    total_templates: int = strawberry.field(description="Total number of templates")

    active_templates: int = strawberry.field(description="Number of active templates")

    by_category: str = strawberry.field(description="Count by category (JSON object)")

    by_status: str = strawberry.field(description="Count by status (JSON object)")

    by_channel: str = strawberry.field(
        description="Count by supported channels (JSON object)"
    )

    most_used_templates: list[NotificationTemplateType] = strawberry.field(
        description="Most frequently used templates"
    )

    recently_updated: list[NotificationTemplateType] = strawberry.field(
        description="Recently updated templates"
    )

    avg_usage_per_template: float = strawberry.field(
        description="Average usage count per template"
    )
