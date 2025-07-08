"""Template input types.

This module contains GraphQL input types for managing notification templates.
"""

from typing import Any

import strawberry

from ..enums import NotificationChannelEnum, TemplateTypeEnum, VariableTypeEnum


@strawberry.input
class TemplateVariableInput:
    """GraphQL input for template variables."""

    name: str
    type: VariableTypeEnum
    description: str | None = None
    required: bool = True
    default_value: str | None = None
    validation_pattern: str | None = None
    format: str | None = None
    example: str | None = None

    # Validation rules
    min_length: int | None = None
    max_length: int | None = None
    min_value: float | None = None
    max_value: float | None = None
    allowed_values: list[str] | None = None


@strawberry.input
class TemplateCreateInput:
    """GraphQL input for creating templates."""

    # Basic information
    code: str
    name: str
    description: str | None = None
    template_type: TemplateTypeEnum
    channel: NotificationChannelEnum

    # Template content
    subject_template: str | None = None
    body_template: str
    html_template: str | None = None

    # Variables
    variables: list[TemplateVariableInput] | None = None

    # Settings
    is_active: bool = True

    # Categorization
    tags: list[str] | None = None
    category: str | None = None

    # A/B Testing
    ab_test_enabled: bool = False
    ab_test_variants: list[dict[str, Any]] | None = None

    # Validation settings
    require_all_variables: bool = True
    validate_html: bool = True

    # Localization
    language: str = "en"
    localized_versions: dict[str, dict[str, str]] | None = None


@strawberry.input
class TemplateUpdateInput:
    """GraphQL input for updating templates."""

    # Basic information
    name: str | None = None
    description: str | None = None

    # Template content
    subject_template: str | None = None
    body_template: str | None = None
    html_template: str | None = None

    # Variables (full replacement)
    variables: list[TemplateVariableInput] | None = None

    # Settings
    is_active: bool | None = None

    # Categorization
    tags: list[str] | None = None
    category: str | None = None

    # Version notes
    change_notes: str | None = None

    # Create new version or update current
    create_new_version: bool = False


@strawberry.input
class TemplateTestInput:
    """GraphQL input for testing templates."""

    template_id: strawberry.ID

    # Test variables
    test_variables: dict[str, str]

    # Test recipient
    test_recipient: str

    # Test options
    send_test_notification: bool = False
    validate_only: bool = True
    check_all_variables: bool = True

    # Preview options
    include_tracking: bool = False
    format_html: bool = True


@strawberry.input
class TemplateImportInput:
    """GraphQL input for importing templates."""

    # Import source
    import_data: str  # JSON string containing template data
    import_format: str = "json"  # "json", "yaml", "csv"

    # Import options
    update_existing: bool = False
    skip_duplicates: bool = True
    validate_before_import: bool = True

    # Default values for missing fields
    default_template_type: TemplateTypeEnum | None = None
    default_channel: NotificationChannelEnum | None = None
    default_language: str = "en"

    # Import settings
    create_inactive: bool = False  # Create templates as inactive initially
    assign_tags: list[str] | None = None


@strawberry.input
class TemplateCloneInput:
    """GraphQL input for cloning templates."""

    source_template_id: strawberry.ID

    # New template details
    new_code: str
    new_name: str
    new_description: str | None = None

    # Modifications to apply during clone
    channel: NotificationChannelEnum | None = None
    template_type: TemplateTypeEnum | None = None

    # Content modifications
    subject_template: str | None = None
    body_template: str | None = None
    html_template: str | None = None

    # Settings
    is_active: bool = False  # Start as inactive for review
    copy_variables: bool = True
    copy_tags: bool = True


@strawberry.input
class TemplateValidationInput:
    """GraphQL input for validating templates."""

    # Template content to validate
    subject_template: str | None = None
    body_template: str
    html_template: str | None = None

    # Variables for validation
    variables: list[TemplateVariableInput]

    # Channel for validation rules
    channel: NotificationChannelEnum

    # Validation options
    check_variable_usage: bool = True
    check_html_validity: bool = True
    check_character_limits: bool = True
    check_required_elements: bool = True

    # Sample data for testing
    sample_variables: dict[str, str] | None = None


@strawberry.input
class TemplateSearchInput:
    """GraphQL input for searching templates."""

    # Text search
    query: str | None = None

    # Filters
    template_types: list[TemplateTypeEnum] | None = None
    channels: list[NotificationChannelEnum] | None = None
    is_active: bool | None = None
    tags: list[str] | None = None
    categories: list[str] | None = None
    languages: list[str] | None = None

    # Usage filters
    min_usage_count: int | None = None
    max_usage_count: int | None = None
    used_after: str | None = None  # ISO date string
    used_before: str | None = None

    # Performance filters
    min_open_rate: float | None = None
    min_click_rate: float | None = None
    min_performance_score: float | None = None

    # A/B test filters
    has_ab_test: bool | None = None
    ab_test_winner: bool | None = None

    # Pagination and sorting
    limit: int = 50
    offset: int = 0
    sort_by: str = "updated_at"
    sort_direction: str = "desc"


@strawberry.input
class TemplateExportInput:
    """GraphQL input for exporting templates."""

    # Templates to export
    template_ids: list[strawberry.ID] | None = None

    # Export filters (if not specifying IDs)
    filters: TemplateSearchInput | None = None

    # Export format
    format: str = "json"  # "json", "yaml", "csv", "xlsx"

    # Export options
    include_usage_stats: bool = False
    include_version_history: bool = False
    include_inactive: bool = False

    # Compression
    compress_output: bool = False

    # Security
    exclude_sensitive_data: bool = True


@strawberry.input
class TemplateBulkActionInput:
    """GraphQL input for bulk template actions."""

    template_ids: list[strawberry.ID]
    action: str  # "activate", "deactivate", "delete", "tag", "untag", "categorize"

    # Action-specific parameters
    tags_to_add: list[str] | None = None
    tags_to_remove: list[str] | None = None
    new_category: str | None = None

    # Confirmation for destructive actions
    confirm_delete: bool = False

    # Batch processing options
    continue_on_error: bool = True

    # Reason for bulk action
    reason: str | None = None


@strawberry.input
class TemplateVersionInput:
    """GraphQL input for managing template versions."""

    template_id: strawberry.ID
    action: str  # "create", "activate", "rollback", "delete"

    # For creating new version
    new_content: TemplateUpdateInput | None = None

    # For activating/rolling back to specific version
    target_version: int | None = None

    # Version metadata
    change_notes: str | None = None

    # Rollback options
    preserve_current_as_draft: bool = True
