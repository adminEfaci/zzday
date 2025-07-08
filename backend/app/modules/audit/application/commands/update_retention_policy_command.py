"""Update retention policy command.

This module implements the command and handler for updating audit retention policies,
ensuring compliance with data retention requirements.
"""

from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.enums.audit_enums import RetentionPolicy

logger = get_logger(__name__)


class UpdateRetentionPolicyCommand(Command):
    """
    Command to update audit log retention policy.

    Updates retention policies while ensuring compliance
    with regulatory requirements.
    """

    def __init__(
        self,
        audit_log_id: UUID,
        new_retention_policy: str,
        reason: str | None = None,
        updated_by: UUID | None = None,
    ):
        """
        Initialize update retention policy command.

        Args:
            audit_log_id: ID of the audit log to update
            new_retention_policy: New retention policy to apply
            reason: Reason for the policy change
            updated_by: User making the change
        """
        super().__init__()

        self.audit_log_id = self._validate_audit_log_id(audit_log_id)
        self.new_retention_policy = self._validate_retention_policy(
            new_retention_policy
        )
        self.reason = reason
        self.updated_by = updated_by

        self._freeze()

    def _validate_audit_log_id(self, audit_log_id: UUID) -> UUID:
        """Validate audit log ID."""
        if not isinstance(audit_log_id, UUID):
            raise ValidationError("Audit log ID must be a valid UUID")
        return audit_log_id

    def _validate_retention_policy(self, policy: str) -> str:
        """Validate retention policy."""
        try:
            # This will raise ValueError if invalid
            RetentionPolicy.from_string(policy)
            return policy
        except ValueError as e:
            raise ValidationError(f"Invalid retention policy: {e}")


class UpdateRetentionPolicyCommandHandler(
    CommandHandler[UpdateRetentionPolicyCommand, None]
):
    """
    Handler for updating retention policies.

    This handler manages retention policy updates while enforcing
    business rules and compliance requirements.
    """

    def __init__(
        self, audit_repository: Any, compliance_service: Any, event_publisher: Any
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit log persistence
            compliance_service: Service for compliance validation
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.compliance_service = compliance_service
        self.event_publisher = event_publisher

    async def handle(self, command: UpdateRetentionPolicyCommand) -> None:
        """
        Handle the update retention policy command.

        Args:
            command: Command containing policy update details

        Raises:
            NotFoundError: If audit log not found
            ValidationError: If policy update violates rules
        """
        logger.info(
            "Updating retention policy",
            audit_log_id=command.audit_log_id,
            new_policy=command.new_retention_policy,
            updated_by=command.updated_by,
        )

        # Retrieve audit log
        audit_log = await self.audit_repository.find_by_id(command.audit_log_id)
        if not audit_log:
            raise NotFoundError(f"Audit log not found: {command.audit_log_id}")

        # Parse new retention policy
        new_policy = RetentionPolicy.from_string(command.new_retention_policy)

        # Validate compliance requirements
        await self._validate_compliance_requirements(
            audit_log, new_policy, command.updated_by
        )

        # Store old policy for auditing
        old_policy = audit_log.retention_policy

        # Update retention policy (this validates business rules)
        audit_log.update_retention_policy(new_policy)

        # Add audit metadata about the change
        audit_log.mark_modified()

        # Save changes
        await self.audit_repository.save(audit_log)

        # Record the policy change as an audit entry
        await self._record_policy_change_audit(
            audit_log, old_policy, new_policy, command.reason, command.updated_by
        )

        # Publish domain events
        for event in audit_log.collect_events():
            await self.event_publisher.publish(event)

        logger.info(
            "Retention policy updated successfully",
            audit_log_id=audit_log.id,
            old_policy=str(old_policy),
            new_policy=str(new_policy),
        )

    async def _validate_compliance_requirements(
        self, audit_log: AuditLog, new_policy: RetentionPolicy, updated_by: UUID | None
    ) -> None:
        """
        Validate that policy change meets compliance requirements.

        Args:
            audit_log: Audit log being updated
            new_policy: New retention policy
            updated_by: User making the change

        Raises:
            ValidationError: If compliance requirements not met
        """
        # Check if user has permission to change policies
        if updated_by:
            has_permission = (
                await self.compliance_service.check_retention_policy_permission(
                    updated_by
                )
            )
            if not has_permission:
                raise ValidationError(
                    "User does not have permission to change retention policies"
                )

        # Check compliance framework requirements
        compliance_frameworks = await self.compliance_service.get_applicable_frameworks(
            audit_log
        )

        for framework in compliance_frameworks:
            min_retention = await self.compliance_service.get_minimum_retention(
                framework,
                audit_log.category if hasattr(audit_log, "category") else "general",
            )

            if (
                not new_policy.is_permanent()
                and new_policy.get_retention_days() < min_retention
            ):
                raise ValidationError(
                    f"New retention policy violates {framework} minimum retention "
                    f"requirement of {min_retention} days"
                )

        # Check for critical entries that require extended retention
        has_critical_entries = await self._check_for_critical_entries(audit_log)
        if (
            has_critical_entries
            and not new_policy.is_permanent()
            and (
                new_policy.get_retention_days()
                < RetentionPolicy.YEARS_7.get_retention_days()
            )
        ):
            raise ValidationError(
                "Audit log contains critical entries requiring 7+ year retention"
            )

    async def _check_for_critical_entries(self, audit_log: AuditLog) -> bool:
        """
        Check if audit log contains entries requiring extended retention.

        Args:
            audit_log: Audit log to check

        Returns:
            True if critical entries found
        """
        # This would typically query the database for critical entries
        # For now, we'll check the in-memory entries

        from app.modules.audit.domain.enums.audit_enums import AuditSeverity

        for entry in audit_log.entries:
            if entry.severity == AuditSeverity.CRITICAL:
                return True

            # Check for specific action types requiring extended retention
            critical_actions = [
                "delete_user",
                "delete_data",
                "security_breach",
                "compliance_violation",
                "privilege_escalation",
            ]
            if entry.action.action_type in critical_actions:
                return True

        return False

    async def _record_policy_change_audit(
        self,
        audit_log: AuditLog,
        old_policy: RetentionPolicy,
        new_policy: RetentionPolicy,
        reason: str | None,
        updated_by: UUID | None,
    ) -> None:
        """
        Record the policy change as an audit entry.

        Args:
            audit_log: Audit log that was updated
            old_policy: Previous retention policy
            new_policy: New retention policy
            reason: Reason for the change
            updated_by: User who made the change
        """
        from app.modules.audit.application.commands.record_audit_entry_command import (
            RecordAuditEntryCommand,
            RecordAuditEntryCommandHandler,
        )

        # Create command to record the policy change
        record_command = RecordAuditEntryCommand(
            user_id=updated_by,
            action_type="update_retention_policy",
            operation="update",
            description=f"Updated retention policy from {old_policy} to {new_policy}",
            resource_type="audit_log",
            resource_id=str(audit_log.id),
            resource_name=audit_log.title,
            outcome="success",
            severity="medium",
            category="configuration",
            changes=[
                {
                    "field_name": "retention_policy",
                    "old_value": str(old_policy),
                    "new_value": str(new_policy),
                    "field_type": "enum",
                }
            ],
            custom_fields={
                "reason": reason,
                "policy_change_type": "retention_policy_update",
            },
        )

        # Execute the command through the handler
        # Note: In a real implementation, this would use the command bus
        handler = RecordAuditEntryCommandHandler(
            self.audit_repository, self.event_publisher
        )

        await handler.handle(record_command)

    @property
    def command_type(self) -> type[UpdateRetentionPolicyCommand]:
        """Get command type this handler processes."""
        return UpdateRetentionPolicyCommand


__all__ = ["UpdateRetentionPolicyCommand", "UpdateRetentionPolicyCommandHandler"]
