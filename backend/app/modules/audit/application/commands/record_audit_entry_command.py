"""Record audit entry command.

This module implements the command and handler for recording audit entries,
the core functionality of the audit module.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.entities.audit_entry import AuditEntry, AuditField
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)

logger = get_logger(__name__)


class RecordAuditEntryCommand(Command):
    """
    Command to record an audit entry.

    This command captures all information needed to create
    an immutable audit trail entry.
    """

    def __init__(
        self,
        # Actor information
        user_id: UUID | None,
        # Action details
        action_type: str,
        operation: str,
        description: str,
        # Resource information
        resource_type: str,
        resource_id: str,
        resource_name: str | None = None,
        # Context
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        # Result
        outcome: str = "success",
        error_details: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        # Classification
        severity: str | None = None,
        category: str | None = None,
        # Tracking
        session_id: UUID | None = None,
        correlation_id: str | None = None,
        # Changes
        changes: list[dict[str, Any]] | None = None,
        # Metadata
        tags: list[str] | None = None,
        custom_fields: dict[str, Any] | None = None,
        compliance_tags: list[str] | None = None,
    ):
        """
        Initialize record audit entry command.

        Args:
            user_id: User who performed the action (None for system actions)
            action_type: Type of action performed
            operation: Specific operation (e.g., "create", "update", "delete")
            description: Human-readable description
            resource_type: Type of resource affected
            resource_id: Unique identifier of the resource
            resource_name: Optional human-readable resource name
            ip_address: Client IP address
            user_agent: Client user agent string
            request_id: Unique request identifier
            outcome: Action outcome ("success", "failure", "partial")
            error_details: Error information if failed
            duration_ms: Action duration in milliseconds
            severity: Event severity level
            category: Event category
            session_id: User session identifier
            correlation_id: Correlation identifier for related events
            changes: List of field-level changes
            tags: General tags
            custom_fields: Custom metadata fields
            compliance_tags: Compliance-specific tags
        """
        super().__init__()

        # Actor
        self.user_id = user_id

        # Action
        self.action_type = self._validate_not_empty(action_type, "action_type")
        self.operation = self._validate_not_empty(operation, "operation")
        self.description = self._validate_not_empty(description, "description")

        # Resource
        self.resource_type = self._validate_not_empty(resource_type, "resource_type")
        self.resource_id = self._validate_not_empty(resource_id, "resource_id")
        self.resource_name = resource_name

        # Context
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_id = request_id

        # Result
        self.outcome = self._validate_outcome(outcome)
        self.error_details = error_details
        self.duration_ms = self._validate_duration(duration_ms)

        # Classification
        self.severity = severity
        self.category = category

        # Tracking
        self.session_id = session_id
        self.correlation_id = correlation_id

        # Changes
        self.changes = changes or []

        # Metadata
        self.tags = tags or []
        self.custom_fields = custom_fields or {}
        self.compliance_tags = compliance_tags or []

        self._freeze()

    def _validate_not_empty(self, value: str, field_name: str) -> str:
        """Validate that a string field is not empty."""
        if not value or not value.strip():
            raise ValidationError(f"{field_name} cannot be empty")
        return value.strip()

    def _validate_outcome(self, outcome: str) -> str:
        """Validate outcome value."""
        valid_outcomes = ["success", "failure", "partial"]
        if outcome not in valid_outcomes:
            raise ValidationError(
                f"Invalid outcome: {outcome}. Must be one of: {valid_outcomes}"
            )
        return outcome

    def _validate_duration(self, duration: int | None) -> int | None:
        """Validate duration value."""
        if duration is not None and duration < 0:
            raise ValidationError("Duration cannot be negative")
        return duration


class RecordAuditEntryCommandHandler(
    CommandHandler[RecordAuditEntryCommand, AuditEntry]
):
    """
    Handler for recording audit entries.

    This handler manages the creation of audit entries, ensuring they are
    properly recorded in an active audit log with all business rules enforced.
    """

    def __init__(self, audit_repository: Any, event_publisher: Any):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit log persistence
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.event_publisher = event_publisher

    async def handle(self, command: RecordAuditEntryCommand) -> AuditEntry:
        """
        Handle the record audit entry command.

        Args:
            command: Command containing audit entry details

        Returns:
            Created audit entry

        Raises:
            NotFoundError: If no active audit log exists
            ValidationError: If command validation fails
        """
        logger.info(
            "Recording audit entry",
            user_id=command.user_id,
            action_type=command.action_type,
            resource_type=command.resource_type,
            resource_id=command.resource_id,
        )

        # Get or create active audit log
        audit_log = await self._get_or_create_active_log()

        # Create value objects
        action = AuditAction(
            action_type=command.action_type,
            operation=command.operation,
            description=command.description,
        )

        resource = ResourceIdentifier(
            resource_type=command.resource_type,
            resource_id=command.resource_id,
            resource_name=command.resource_name,
        )

        context = AuditContext(
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            request_id=command.request_id,
        )

        # Create metadata if provided
        metadata = None
        if command.tags or command.custom_fields or command.compliance_tags:
            metadata = AuditMetadata(
                tags=command.tags,
                custom_fields=command.custom_fields,
                compliance_tags=command.compliance_tags,
            )

        # Parse severity and category
        severity = None
        if command.severity:
            severity = AuditSeverity.from_string(command.severity)

        category = None
        if command.category:
            category = AuditCategory.from_string(command.category)

        # Parse changes
        changes = []
        for change_data in command.changes:
            changes.append(
                AuditField(
                    field_name=change_data["field_name"],
                    old_value=change_data.get("old_value"),
                    new_value=change_data.get("new_value"),
                    value_type=change_data.get(
                        "field_type", "string"
                    ),  # Changed from field_type to value_type
                )
            )

        # Add entry to audit log
        entry = audit_log.add_entry(
            user_id=command.user_id,
            action=action,
            resource=resource,
            context=context,
            metadata=metadata,
            severity=severity,
            category=category,
            outcome=command.outcome,
            error_details=command.error_details,
            duration_ms=command.duration_ms,
            changes=changes,
            correlation_id=command.correlation_id,
            session_id=command.session_id,
        )

        # Save audit log
        await self.audit_repository.save(audit_log)

        # Publish domain events
        for event in audit_log.collect_events():
            await self.event_publisher.publish(event)

        logger.info(
            "Audit entry recorded successfully",
            entry_id=entry.id,
            audit_log_id=audit_log.id,
        )

        return entry

    async def _get_or_create_active_log(self) -> AuditLog:
        """
        Get active audit log or create a new one.

        Returns:
            Active audit log
        """
        # Try to find active log
        active_log = await self.audit_repository.find_active()

        if active_log and not active_log.is_full():
            return active_log

        # Create new log if none exists or current is full
        from app.modules.audit.domain.enums.audit_enums import RetentionPolicy

        new_log = AuditLog(
            title=f"Audit Log {datetime.utcnow().strftime('%Y-%m-%d')}",
            retention_policy=RetentionPolicy.YEARS_7,
            description="System audit trail",
        )

        await self.audit_repository.save(new_log)

        logger.info("Created new audit log", audit_log_id=new_log.id)

        return new_log

    @property
    def command_type(self) -> type[RecordAuditEntryCommand]:
        """Get command type this handler processes."""
        return RecordAuditEntryCommand


__all__ = ["RecordAuditEntryCommand", "RecordAuditEntryCommandHandler"]
