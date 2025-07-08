"""
Comprehensive GraphQL input types for audit operations.

This module provides input types for creating, updating, and managing audit entries
with comprehensive validation and transformation capabilities.
"""

from datetime import datetime
from typing import Any

import strawberry

from ..enums import (
    AuditActionTypeEnum,
    AuditCategoryEnum,
    AuditOutcomeEnum,
    AuditResourceTypeEnum,
    AuditSeverityEnum,
)


@strawberry.input
class AuditActionInput:
    """Input type for audit action details."""

    action_type: AuditActionTypeEnum
    operation: str
    description: str

    def validate(self) -> list[str]:
        """Validate action input."""
        errors = []

        if not self.operation or len(self.operation.strip()) == 0:
            errors.append("Operation is required")
        elif len(self.operation) > 255:
            errors.append("Operation too long (max 255 characters)")

        if not self.description or len(self.description.strip()) == 0:
            errors.append("Description is required")
        elif len(self.description) > 1000:
            errors.append("Description too long (max 1000 characters)")

        return errors


@strawberry.input
class AuditResourceInput:
    """Input type for audit resource details."""

    resource_type: AuditResourceTypeEnum
    resource_id: str
    resource_name: str

    def validate(self) -> list[str]:
        """Validate resource input."""
        errors = []

        if not self.resource_id or len(self.resource_id.strip()) == 0:
            errors.append("Resource ID is required")
        elif len(self.resource_id) > 255:
            errors.append("Resource ID too long (max 255 characters)")

        if not self.resource_name or len(self.resource_name.strip()) == 0:
            errors.append("Resource name is required")
        elif len(self.resource_name) > 500:
            errors.append("Resource name too long (max 500 characters)")

        return errors


@strawberry.input
class AuditContextInput:
    """Input type for audit context information."""

    ip_address: str | None = None
    user_agent: str | None = None
    session_id: strawberry.ID | None = None
    correlation_id: str | None = None

    def validate(self) -> list[str]:
        """Validate context input."""
        errors = []

        if self.ip_address and not self._is_valid_ip(self.ip_address):
            errors.append("Invalid IP address format")

        if self.user_agent and len(self.user_agent) > 1000:
            errors.append("User agent too long (max 1000 characters)")

        if self.correlation_id and len(self.correlation_id) > 255:
            errors.append("Correlation ID too long (max 255 characters)")

        return errors

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import re

        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))


@strawberry.input
class AuditResultInput:
    """Input type for audit result information."""

    outcome: AuditOutcomeEnum
    severity: AuditSeverityEnum
    category: AuditCategoryEnum
    duration_ms: int | None = None
    error_details: str | None = None

    def validate(self) -> list[str]:
        """Validate result input."""
        errors = []

        if self.duration_ms is not None:
            if self.duration_ms < 0:
                errors.append("Duration cannot be negative")
            elif self.duration_ms > 300000:  # 5 minutes
                errors.append("Duration too long (max 5 minutes)")

        if self.error_details and len(self.error_details) > 2000:
            errors.append("Error details too long (max 2000 characters)")

        return errors


@strawberry.input
class AuditFieldChangeInput:
    """Input type for audit field changes."""

    field_name: str
    old_value: str | None = None
    new_value: str | None = None
    field_type: str = "string"

    def validate(self) -> list[str]:
        """Validate field change input."""
        errors = []

        if not self.field_name or len(self.field_name.strip()) == 0:
            errors.append("Field name is required")
        elif len(self.field_name) > 255:
            errors.append("Field name too long (max 255 characters)")

        if self.old_value and len(self.old_value) > 1000:
            errors.append("Old value too long (max 1000 characters)")

        if self.new_value and len(self.new_value) > 1000:
            errors.append("New value too long (max 1000 characters)")

        valid_types = ["string", "number", "boolean", "date", "json", "binary"]
        if self.field_type not in valid_types:
            errors.append(
                f"Invalid field type. Must be one of: {', '.join(valid_types)}"
            )

        return errors


@strawberry.input
class AuditMetadataInput:
    """Input type for audit metadata."""

    tags: list[str] = strawberry.field(default_factory=list)
    compliance_tags: list[str] = strawberry.field(default_factory=list)
    custom_fields: str | None = None  # JSON string

    def validate(self) -> list[str]:
        """Validate metadata input."""
        errors = []

        # Validate tags
        if len(self.tags) > 50:
            errors.append("Too many tags (max 50)")

        for tag in self.tags:
            if not tag or len(tag.strip()) == 0:
                errors.append("Empty tags are not allowed")
            elif len(tag) > 100:
                errors.append(f"Tag too long: {tag} (max 100 characters)")

        # Validate compliance tags
        if len(self.compliance_tags) > 20:
            errors.append("Too many compliance tags (max 20)")

        valid_compliance_frameworks = [
            "SOC2",
            "HIPAA",
            "GDPR",
            "PCI-DSS",
            "ISO27001",
            "NIST",
            "CUSTOM",
        ]

        for tag in self.compliance_tags:
            if tag.upper() not in valid_compliance_frameworks:
                errors.append(f"Invalid compliance tag: {tag}")

        # Validate custom fields JSON
        if self.custom_fields:
            try:
                import json

                json.loads(self.custom_fields)
            except json.JSONDecodeError:
                errors.append("Custom fields must be valid JSON")

            if len(self.custom_fields) > 5000:
                errors.append("Custom fields too large (max 5000 characters)")

        return errors


@strawberry.input
class CreateAuditEntryInput:
    """Input type for creating audit entries."""

    # User information
    user_id: strawberry.ID | None = None

    # Action details
    action: AuditActionInput

    # Resource details
    resource: AuditResourceInput

    # Context information
    context: AuditContextInput

    # Result information
    result: AuditResultInput

    # Field changes (for update operations)
    changes: list[AuditFieldChangeInput] = strawberry.field(default_factory=list)

    # Metadata
    metadata: AuditMetadataInput

    def validate(self) -> list[str]:
        """Validate audit entry creation input."""
        errors = []

        # Validate nested inputs
        errors.extend(self.action.validate())
        errors.extend(self.resource.validate())
        errors.extend(self.context.validate())
        errors.extend(self.result.validate())
        errors.extend(self.metadata.validate())

        # Validate changes
        if len(self.changes) > 100:
            errors.append("Too many field changes (max 100)")

        for change in self.changes:
            errors.extend(change.validate())

        # Validate that changes are provided for update operations
        if (
            self.action.action_type == AuditActionTypeEnum.UPDATE
            and len(self.changes) == 0
        ):
            errors.append("Field changes are required for update operations")

        return errors


@strawberry.input
class UpdateAuditEntryInput:
    """Input type for updating audit entries."""

    audit_entry_id: strawberry.ID

    # Optional updates
    metadata: AuditMetadataInput | None = None
    result: AuditResultInput | None = None
    additional_changes: list[AuditFieldChangeInput] = strawberry.field(
        default_factory=list
    )

    def validate(self) -> list[str]:
        """Validate audit entry update input."""
        errors = []

        # Validate nested inputs
        if self.metadata:
            errors.extend(self.metadata.validate())

        if self.result:
            errors.extend(self.result.validate())

        for change in self.additional_changes:
            errors.extend(change.validate())

        # At least one field must be updated
        if not self.metadata and not self.result and not self.additional_changes:
            errors.append("At least one field must be updated")

        return errors


@strawberry.input
class BulkAuditEntryInput:
    """Input type for bulk audit entry creation."""

    entries: list[CreateAuditEntryInput]
    batch_metadata: dict[str, Any] | None = None

    def validate(self) -> list[str]:
        """Validate bulk audit entry input."""
        errors = []

        if not self.entries:
            errors.append("At least one audit entry is required")
        elif len(self.entries) > 1000:
            errors.append("Too many entries in bulk operation (max 1000)")

        # Validate each entry
        for i, entry in enumerate(self.entries):
            entry_errors = entry.validate()
            for error in entry_errors:
                errors.append(f"Entry {i+1}: {error}")

        return errors


@strawberry.input
class AuditEntrySearchInput:
    """Input type for searching audit entries."""

    # Text search
    search_text: str | None = None
    search_fields: list[str] = strawberry.field(default_factory=list)

    # Filters
    user_ids: list[strawberry.ID] = strawberry.field(default_factory=list)
    resource_types: list[AuditResourceTypeEnum] = strawberry.field(default_factory=list)
    action_types: list[AuditActionTypeEnum] = strawberry.field(default_factory=list)
    severities: list[AuditSeverityEnum] = strawberry.field(default_factory=list)
    categories: list[AuditCategoryEnum] = strawberry.field(default_factory=list)
    outcomes: list[AuditOutcomeEnum] = strawberry.field(default_factory=list)

    # Time range
    start_date: datetime | None = None
    end_date: datetime | None = None

    # Pagination
    page: int = 1
    page_size: int = 50

    # Sorting
    sort_by: str = "created_at"
    sort_order: str = "desc"

    def validate(self) -> list[str]:
        """Validate search input."""
        errors = []

        # Text search validation
        if self.search_text and len(self.search_text) > 1000:
            errors.append("Search text too long (max 1000 characters)")

        # Date range validation
        if self.start_date and self.end_date:
            if self.start_date >= self.end_date:
                errors.append("Start date must be before end date")

            # Limit search range to prevent performance issues
            delta = self.end_date - self.start_date
            if delta.days > 365:
                errors.append("Search range too large (max 365 days)")

        # Pagination validation
        if self.page < 1:
            errors.append("Page must be positive")

        if self.page_size < 1 or self.page_size > 1000:
            errors.append("Page size must be between 1 and 1000")

        # Sorting validation
        valid_sort_fields = [
            "created_at",
            "user_id",
            "action_type",
            "resource_type",
            "severity",
            "category",
            "outcome",
            "duration_ms",
        ]

        if self.sort_by not in valid_sort_fields:
            errors.append(
                f"Invalid sort field. Must be one of: {', '.join(valid_sort_fields)}"
            )

        if self.sort_order not in ["asc", "desc"]:
            errors.append("Sort order must be 'asc' or 'desc'")

        # Filter validation
        if len(self.user_ids) > 100:
            errors.append("Too many user IDs (max 100)")

        return errors


@strawberry.input
class AuditRetentionPolicyInput:
    """Input type for audit retention policy configuration."""

    policy_name: str
    retention_days: int
    archive_enabled: bool = True
    compliance_frameworks: list[str] = strawberry.field(default_factory=list)
    auto_delete_enabled: bool = False
    archive_location: str | None = None

    def validate(self) -> list[str]:
        """Validate retention policy input."""
        errors = []

        if not self.policy_name or len(self.policy_name.strip()) == 0:
            errors.append("Policy name is required")
        elif len(self.policy_name) > 255:
            errors.append("Policy name too long (max 255 characters)")

        if self.retention_days < 1:
            errors.append("Retention period must be positive")
        elif self.retention_days < 30:
            errors.append("Minimum retention period is 30 days")
        elif self.retention_days > 2555:  # ~7 years
            errors.append("Maximum retention period is 7 years")

        if self.archive_enabled and not self.archive_location:
            errors.append("Archive location required when archival is enabled")

        if self.archive_location and len(self.archive_location) > 500:
            errors.append("Archive location too long (max 500 characters)")

        return errors
