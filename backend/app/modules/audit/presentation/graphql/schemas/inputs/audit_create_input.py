"""GraphQL input types for creating audit entries."""

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

        if len(self.field_name) > 255:
            errors.append("Field name too long (max 255 characters)")

        valid_field_types = ["string", "number", "boolean", "date", "json", "text"]
        if self.field_type not in valid_field_types:
            errors.append(f"Invalid field type: {self.field_type}")

        return errors


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

        if len(self.operation) > 255:
            errors.append("Operation too long (max 255 characters)")

        if not self.description or len(self.description.strip()) == 0:
            errors.append("Description is required")

        if len(self.description) > 1000:
            errors.append("Description too long (max 1000 characters)")

        return errors


@strawberry.input
class AuditResourceInput:
    """Input type for audit resource details."""

    resource_type: AuditResourceTypeEnum
    resource_id: str
    resource_name: str | None = None

    def validate(self) -> list[str]:
        """Validate resource input."""
        errors = []

        if not self.resource_id or len(self.resource_id.strip()) == 0:
            errors.append("Resource ID is required")

        if len(self.resource_id) > 255:
            errors.append("Resource ID too long (max 255 characters)")

        if self.resource_name and len(self.resource_name) > 255:
            errors.append("Resource name too long (max 255 characters)")

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

        # Basic IP address validation
        if self.ip_address:
            import re

            ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
            ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"

            if not (
                re.match(ip_pattern, self.ip_address)
                or re.match(ipv6_pattern, self.ip_address)
            ):
                errors.append("Invalid IP address format")

        if self.user_agent and len(self.user_agent) > 1000:
            errors.append("User agent too long (max 1000 characters)")

        if self.correlation_id and len(self.correlation_id) > 255:
            errors.append("Correlation ID too long (max 255 characters)")

        return errors


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

        if self.duration_ms is not None and self.duration_ms < 0:
            errors.append("Duration must be non-negative")

        if self.duration_ms is not None and self.duration_ms > 3600000:  # 1 hour
            errors.append("Duration seems too large (max 1 hour)")

        if self.error_details and len(self.error_details) > 5000:
            errors.append("Error details too long (max 5000 characters)")

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
        for tag in self.tags + self.compliance_tags:
            if not tag or len(tag.strip()) == 0:
                errors.append("Tags cannot be empty")
            elif len(tag) > 100:
                errors.append(f"Tag too long: {tag}")

        # Limit number of tags
        if len(self.tags) > 50:
            errors.append("Too many tags (max 50)")

        if len(self.compliance_tags) > 20:
            errors.append("Too many compliance tags (max 20)")

        # Validate JSON format for custom fields
        if self.custom_fields:
            try:
                import json

                json.loads(self.custom_fields)
            except json.JSONDecodeError:
                errors.append("Custom fields must be valid JSON")

            if len(self.custom_fields) > 10000:
                errors.append("Custom fields too large (max 10KB)")

        return errors


@strawberry.input
class AuditCreateInput:
    """Input type for creating audit entries."""

    # User information
    user_id: strawberry.ID | None = None

    # Action details
    action: AuditActionInput

    # Resource details
    resource: AuditResourceInput

    # Context information
    context: AuditContextInput | None = None

    # Result information
    result: AuditResultInput

    # Changes (for update operations)
    changes: list[AuditFieldChangeInput] = strawberry.field(default_factory=list)

    # Metadata
    metadata: AuditMetadataInput | None = None

    def validate(self) -> list[str]:
        """Validate complete audit entry input."""
        errors = []

        # Validate all nested inputs
        errors.extend(self.action.validate())
        errors.extend(self.resource.validate())
        errors.extend(self.result.validate())

        if self.context:
            errors.extend(self.context.validate())

        if self.metadata:
            errors.extend(self.metadata.validate())

        for change in self.changes:
            errors.extend(change.validate())

        # Business rule validations
        if len(self.changes) > 100:
            errors.append("Too many field changes (max 100)")

        # Require changes for update operations
        if (
            self.action.action_type == AuditActionTypeEnum.UPDATE
            and len(self.changes) == 0
        ):
            errors.append("Update operations must include field changes")

        # Validate severity vs outcome consistency
        if (
            self.result.outcome in [AuditOutcomeEnum.ERROR, AuditOutcomeEnum.FAILURE]
            and self.result.severity == AuditSeverityEnum.LOW
        ):
            errors.append("Low severity not appropriate for error/failure outcomes")

        return errors

    def to_dto(self) -> dict[str, Any]:
        """Convert to DTO format for application layer."""
        from datetime import datetime
        from uuid import uuid4

        # Convert to dictionary format that matches DTO structure
        return {
            "id": str(uuid4()),
            "audit_log_id": str(uuid4()),
            "user_id": str(self.user_id) if self.user_id else None,
            "action_type": self.action.action_type.value,
            "operation": self.action.operation,
            "description": self.action.description,
            "resource_type": self.resource.resource_type.value,
            "resource_id": self.resource.resource_id,
            "resource_name": self.resource.resource_name or self.resource.resource_id,
            "ip_address": self.context.ip_address if self.context else None,
            "user_agent": self.context.user_agent if self.context else None,
            "session_id": str(self.context.session_id)
            if self.context and self.context.session_id
            else None,
            "correlation_id": self.context.correlation_id if self.context else None,
            "outcome": self.result.outcome.value,
            "severity": self.result.severity.value,
            "category": self.result.category.value,
            "duration_ms": self.result.duration_ms,
            "error_details": self.result.error_details,
            "changes": [
                {
                    "field_name": change.field_name,
                    "old_value": change.old_value,
                    "new_value": change.new_value,
                    "field_type": change.field_type,
                }
                for change in self.changes
            ],
            "metadata": {
                "tags": self.metadata.tags if self.metadata else [],
                "compliance_tags": self.metadata.compliance_tags
                if self.metadata
                else [],
                "custom_fields": self.metadata.custom_fields if self.metadata else None,
            },
            "created_at": datetime.utcnow(),
        }
