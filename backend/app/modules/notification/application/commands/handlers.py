"""Notification command handlers.

This module contains handlers for processing notification commands,
implementing the business logic for notification operations.
"""

from datetime import datetime

from app.core.cqrs.base import CommandHandler
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.notification.application.commands import (
    CancelScheduledNotificationCommand,
    CreateTemplateCommand,
    ProcessBatchCommand,
    RetryNotificationCommand,
    ScheduleNotificationCommand,
    SendNotificationCommand,
    UpdateRecipientPreferencesCommand,
    UpdateTemplateCommand,
)
from app.modules.notification.application.dto import (
    BatchStatusDTO,
    NotificationResponseDTO,
    RecipientPreferencesDTO,
    ScheduledNotificationDTO,
    TemplateDTO,
)
from app.modules.notification.domain.aggregates.notification_batch import (
    NotificationBatch,
)
from app.modules.notification.domain.aggregates.notification_template import (
    NotificationTemplate,
)
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.entities.notification_recipient import (
    NotificationRecipient,
)
from app.modules.notification.domain.entities.notification_schedule import (
    NotificationSchedule,
)
from app.modules.notification.domain.enums import DeliveryStatus, ScheduleStatus
from app.modules.notification.domain.errors import (
    InvalidTemplateError,
    RecipientBlockedError,
    TemplateNotFoundError,
)
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    NotificationPriorityValue,
    TemplateVariable,
)

logger = get_logger(__name__)


class SendNotificationCommandHandler(
    CommandHandler[SendNotificationCommand, NotificationResponseDTO]
):
    """Handler for sending notifications."""

    def __init__(
        self,
        notification_repository,
        template_repository,
        recipient_repository,
        delivery_service,
        event_publisher,
    ):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository
        self.template_repository = template_repository
        self.recipient_repository = recipient_repository
        self.delivery_service = delivery_service
        self.event_publisher = event_publisher

    async def handle(self, command: SendNotificationCommand) -> NotificationResponseDTO:
        """Handle send notification command."""
        # Check for duplicate notification if idempotency key provided
        if command.idempotency_key:
            existing = await self.notification_repository.find_by_idempotency_key(
                command.idempotency_key
            )
            if existing:
                logger.info(
                    "Duplicate notification request",
                    idempotency_key=command.idempotency_key,
                    notification_id=existing.id,
                )
                return NotificationResponseDTO.from_notification(existing)

        # Get recipient
        recipient = await self.recipient_repository.find_by_id(command.recipient_id)
        if not recipient:
            raise NotFoundError("Recipient", command.recipient_id)

        # Check if recipient can receive notifications
        if not recipient.can_receive_on_channel(command.channel):
            raise RecipientBlockedError(
                recipient_id=command.recipient_id,
                recipient_address=str(command.recipient_id),
                block_reason=f"Recipient has disabled {command.channel.value} notifications",
            )

        # Get recipient address for channel
        recipient_address = recipient.get_address_for_channel(command.channel)
        if not recipient_address:
            raise ValidationError(
                f"Recipient has no {command.channel.value} address configured"
            )

        # Prepare notification content
        if command.template_id or command.template_code:
            content = await self._prepare_templated_content(command)
        else:
            content = NotificationContent(
                subject=command.subject,
                body=command.body,
                html_body=command.html_body,
                attachments=command.attachments,
                metadata=command.metadata,
            )

        # Create notification entity
        notification = Notification(
            recipient_id=command.recipient_id,
            channel=command.channel,
            content=content,
            recipient_address=recipient_address,
            template_id=command.template_id,
            priority=NotificationPriorityValue(level=command.priority),
            expires_at=command.expires_at,
            idempotency_key=command.idempotency_key,
            metadata=command.metadata,
        )

        # Set user context
        notification.created_by = command.user_id

        # Schedule if needed
        if command.scheduled_for:
            notification.schedule(command.scheduled_for)

        # Save notification
        await self.notification_repository.save(notification)

        # Send immediately if not scheduled
        if not command.scheduled_for:
            try:
                await self.delivery_service.send(notification)
            except Exception as e:
                logger.exception(
                    "Failed to send notification",
                    notification_id=notification.id,
                    error=str(e),
                )
                # Mark as failed but don't raise - notification is saved
                notification.update_status(DeliveryStatus.FAILED, details=str(e))
                await self.notification_repository.save(notification)

        # Publish notification created event
        await self.event_publisher.publish_notification_created(notification)

        return NotificationResponseDTO.from_notification(notification)

    async def _prepare_templated_content(
        self, command: SendNotificationCommand
    ) -> NotificationContent:
        """Prepare content from template."""
        # Get template
        if command.template_id:
            template = await self.template_repository.find_by_id(command.template_id)
            if not template:
                raise TemplateNotFoundError(command.template_id)
        else:
            template = await self.template_repository.find_by_code(
                command.template_code
            )
            if not template:
                raise InvalidTemplateError(
                    template_name=command.template_code, reason="Template not found"
                )

        # Validate template is active
        if not template.is_active:
            raise InvalidTemplateError(
                template_id=template.id, reason="Template is inactive"
            )

        # Validate template channel
        if template.channel != command.channel:
            raise InvalidTemplateError(
                template_id=template.id,
                reason=f"Template is for {template.channel.value}, not {command.channel.value}",
            )

        # Render template with variables
        return template.render(command.variables)

    @property
    def command_type(self):
        """Get command type."""
        return SendNotificationCommand


class CreateTemplateCommandHandler(CommandHandler[CreateTemplateCommand, TemplateDTO]):
    """Handler for creating notification templates."""

    def __init__(self, template_repository, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.template_repository = template_repository
        self.event_publisher = event_publisher

    async def handle(self, command: CreateTemplateCommand) -> TemplateDTO:
        """Handle create template command."""
        # Check if template code already exists
        existing = await self.template_repository.find_by_code(command.code)
        if existing:
            raise ConflictError(f"Template with code '{command.code}' already exists")

        # Parse variables from command
        variables = []
        for var_def in command.variables:
            variable = TemplateVariable(
                name=var_def["name"],
                var_type=var_def["type"],
                required=var_def.get("required", True),
                default_value=var_def.get("default_value"),
                description=var_def.get("description"),
                format_pattern=var_def.get("format_pattern"),
                validation_rules=var_def.get("validation_rules", {}),
            )
            variables.append(variable)

        # Create template
        template = NotificationTemplate(
            code=command.code,
            name=command.name,
            channel=command.channel,
            template_type=command.template_type,
            subject_template=command.subject_template,
            body_template=command.body_template,
            html_template=command.html_template,
            description=command.description,
            variables=variables,
            tags=command.tags,
            metadata=command.metadata,
            is_active=command.is_active,
        )

        # Set user context
        template.created_by = command.user_id

        # Save template
        await self.template_repository.save(template)

        # Publish template created event
        await self.event_publisher.publish_template_created(template)

        # Return DTO
        return TemplateDTO(
            template_id=template.id,
            code=template.code,
            name=template.name,
            description=template.description,
            template_type=template.template_type,
            channel=template.channel,
            subject_template=template.subject_template,
            body_template=template.body_template,
            html_template=template.html_template,
            variables=[var.__dict__ for var in template.variables],
            is_active=template.is_active,
            version=template.version,
            created_at=template.created_at,
            updated_at=template.updated_at,
            tags=template.tags,
            metadata=template.metadata,
        )

    @property
    def command_type(self):
        """Get command type."""
        return CreateTemplateCommand


class ScheduleNotificationCommandHandler(
    CommandHandler[ScheduleNotificationCommand, ScheduledNotificationDTO]
):
    """Handler for scheduling notifications."""

    def __init__(self, schedule_repository, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.schedule_repository = schedule_repository
        self.event_publisher = event_publisher

    async def handle(
        self, command: ScheduleNotificationCommand
    ) -> ScheduledNotificationDTO:
        """Handle schedule notification command."""
        # Create schedule
        schedule = NotificationSchedule(
            notification_request=command.notification_request,
            scheduled_for=command.scheduled_for,
            is_recurring=command.is_recurring,
            recurrence_pattern=command.recurrence_pattern,
            recurrence_interval=command.recurrence_interval,
            recurrence_end_date=command.recurrence_end_date,
            metadata=command.metadata,
        )

        # Set user context
        schedule.created_by = command.user_id

        # Save schedule
        await self.schedule_repository.save(schedule)

        # Publish schedule created event
        await self.event_publisher.publish_schedule_created(schedule)

        # Return DTO
        from app.modules.notification.application.dto import NotificationRequestDTO

        return ScheduledNotificationDTO(
            schedule_id=schedule.id,
            notification_request=NotificationRequestDTO(
                **schedule.notification_request
            ),
            scheduled_for=schedule.scheduled_for,
            is_recurring=schedule.is_recurring,
            recurrence_pattern=schedule.recurrence_pattern,
            recurrence_interval=schedule.recurrence_interval,
            recurrence_end_date=schedule.recurrence_end_date,
            is_active=schedule.status == ScheduleStatus.ACTIVE,
            last_run_at=schedule.last_run_at,
            next_run_at=schedule.next_run_at,
            run_count=schedule.run_count,
            created_at=schedule.created_at,
            created_by=schedule.created_by,
            metadata=schedule.metadata,
        )

    @property
    def command_type(self):
        """Get command type."""
        return ScheduleNotificationCommand


class ProcessBatchCommandHandler(CommandHandler[ProcessBatchCommand, BatchStatusDTO]):
    """Handler for processing notification batches."""

    def __init__(self, batch_repository, notification_service, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.batch_repository = batch_repository
        self.notification_service = notification_service
        self.event_publisher = event_publisher

    async def handle(self, command: ProcessBatchCommand) -> BatchStatusDTO:
        """Handle process batch command."""
        # Create batch
        batch = NotificationBatch(
            name=command.batch_name or f"Batch {datetime.utcnow().isoformat()}",
            metadata=command.metadata,
        )

        # Set user context
        batch.created_by = command.user_id

        # Add notifications to batch
        for notification_data in command.notifications:
            batch.add_notification(notification_data)

        # Save batch
        await self.batch_repository.save(batch)

        # Process immediately if requested
        if command.process_immediately:
            batch.start_processing()
            await self.batch_repository.save(batch)

            # Queue batch for processing
            await self.notification_service.process_batch(batch.id)

        # Publish batch created event
        await self.event_publisher.publish_batch_created(batch)

        # Return status DTO
        return BatchStatusDTO(
            batch_id=batch.id,
            status=batch.status,
            total_notifications=batch.total_notifications,
            pending_count=batch.pending_count,
            sent_count=batch.sent_count,
            delivered_count=batch.delivered_count,
            failed_count=batch.failed_count,
            created_at=batch.created_at,
            started_at=batch.started_at,
            completed_at=batch.completed_at,
            processing_duration_seconds=batch.get_processing_duration(),
            average_delivery_time_seconds=None,  # Will be calculated during processing
            error_summary=batch.error_summary,
        )

    @property
    def command_type(self):
        """Get command type."""
        return ProcessBatchCommand


class UpdateRecipientPreferencesCommandHandler(
    CommandHandler[UpdateRecipientPreferencesCommand, RecipientPreferencesDTO]
):
    """Handler for updating recipient preferences."""

    def __init__(self, recipient_repository, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.recipient_repository = recipient_repository
        self.event_publisher = event_publisher

    async def handle(
        self, command: UpdateRecipientPreferencesCommand
    ) -> RecipientPreferencesDTO:
        """Handle update recipient preferences command."""
        # Get or create recipient
        recipient = await self.recipient_repository.find_by_id(command.recipient_id)
        if not recipient:
            recipient = NotificationRecipient(
                recipient_id=command.recipient_id, preferences={}
            )

        # Update preferences
        for key, value in command.preferences.items():
            recipient.update_preference(key, value)

        # Update contact information
        if command.email_addresses is not None:
            recipient.set_email_addresses(command.email_addresses)

        if command.phone_numbers is not None:
            recipient.set_phone_numbers(command.phone_numbers)

        if command.device_tokens is not None:
            recipient.set_device_tokens(command.device_tokens)

        # Save recipient
        await self.recipient_repository.save(recipient)

        # Publish preferences updated event
        await self.event_publisher.publish_preferences_updated(recipient)

        # Return DTO
        return RecipientPreferencesDTO(
            recipient_id=recipient.recipient_id,
            preferences=recipient.preferences,
            email_enabled=recipient.is_channel_enabled("email"),
            sms_enabled=recipient.is_channel_enabled("sms"),
            push_enabled=recipient.is_channel_enabled("push"),
            in_app_enabled=recipient.is_channel_enabled("in_app"),
            marketing_enabled=recipient.is_type_enabled("marketing"),
            transactional_enabled=recipient.is_type_enabled("transactional"),
            system_enabled=recipient.is_type_enabled("system"),
            alert_enabled=recipient.is_type_enabled("alert"),
            quiet_hours_enabled=recipient.quiet_hours_enabled,
            quiet_hours_start=recipient.quiet_hours_start,
            quiet_hours_end=recipient.quiet_hours_end,
            timezone=recipient.timezone,
            email_addresses=recipient.email_addresses,
            phone_numbers=recipient.phone_numbers,
            device_tokens=recipient.device_tokens,
            updated_at=recipient.updated_at,
        )

    @property
    def command_type(self):
        """Get command type."""
        return UpdateRecipientPreferencesCommand


class CancelScheduledNotificationCommandHandler(
    CommandHandler[CancelScheduledNotificationCommand, bool]
):
    """Handler for cancelling scheduled notifications."""

    def __init__(self, schedule_repository, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.schedule_repository = schedule_repository
        self.event_publisher = event_publisher

    async def handle(self, command: CancelScheduledNotificationCommand) -> bool:
        """Handle cancel scheduled notification command."""
        # Get schedule
        schedule = await self.schedule_repository.find_by_id(command.schedule_id)
        if not schedule:
            raise NotFoundError("Schedule", command.schedule_id)

        # Cancel schedule
        schedule.cancel(command.reason)

        # Save schedule
        await self.schedule_repository.save(schedule)

        # Publish schedule cancelled event
        await self.event_publisher.publish_schedule_cancelled(schedule)

        return True

    @property
    def command_type(self):
        """Get command type."""
        return CancelScheduledNotificationCommand


class RetryNotificationCommandHandler(
    CommandHandler[RetryNotificationCommand, NotificationResponseDTO]
):
    """Handler for retrying failed notifications."""

    def __init__(self, notification_repository, delivery_service, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository
        self.delivery_service = delivery_service
        self.event_publisher = event_publisher

    async def handle(
        self, command: RetryNotificationCommand
    ) -> NotificationResponseDTO:
        """Handle retry notification command."""
        # Get notification
        notification = await self.notification_repository.find_by_id(
            command.notification_id
        )
        if not notification:
            raise NotFoundError("Notification", command.notification_id)

        # Check if can retry
        if not notification.can_retry:
            raise ValidationError("Notification cannot be retried")

        # Mark for retry
        notification.mark_for_retry(command.delay_seconds)

        # Save notification
        await self.notification_repository.save(notification)

        # Queue for retry if no delay
        if not command.delay_seconds:
            try:
                await self.delivery_service.send(notification)
            except Exception as e:
                logger.exception(
                    "Failed to retry notification",
                    notification_id=notification.id,
                    error=str(e),
                )

        # Publish notification retried event
        await self.event_publisher.publish_notification_retried(notification)

        return NotificationResponseDTO.from_notification(notification)

    @property
    def command_type(self):
        """Get command type."""
        return RetryNotificationCommand


class UpdateTemplateCommandHandler(CommandHandler[UpdateTemplateCommand, TemplateDTO]):
    """Handler for updating notification templates."""

    def __init__(self, template_repository, event_publisher):
        """Initialize handler with dependencies."""
        super().__init__()
        self.template_repository = template_repository
        self.event_publisher = event_publisher

    async def handle(self, command: UpdateTemplateCommand) -> TemplateDTO:
        """Handle update template command."""
        # Get template
        template = await self.template_repository.find_by_id(command.template_id)
        if not template:
            raise TemplateNotFoundError(command.template_id)

        # Update fields if provided
        if command.name is not None:
            template.update_name(command.name)

        if command.description is not None:
            template.update_description(command.description)

        if command.subject_template is not None:
            template.update_subject_template(command.subject_template)

        if command.body_template is not None:
            template.update_body_template(command.body_template)

        if command.html_template is not None:
            template.update_html_template(command.html_template)

        if command.variables is not None:
            # Parse variables
            variables = []
            for var_def in command.variables:
                variable = TemplateVariable(
                    name=var_def["name"],
                    var_type=var_def["type"],
                    required=var_def.get("required", True),
                    default_value=var_def.get("default_value"),
                    description=var_def.get("description"),
                    format_pattern=var_def.get("format_pattern"),
                    validation_rules=var_def.get("validation_rules", {}),
                )
                variables.append(variable)
            template.update_variables(variables)

        if command.tags is not None:
            template.update_tags(command.tags)

        if command.metadata is not None:
            template.update_metadata(command.metadata)

        if command.is_active is not None:
            if command.is_active:
                template.activate()
            else:
                template.deactivate()

        # Save template
        await self.template_repository.save(template)

        # Publish template updated event
        await self.event_publisher.publish_template_updated(template)

        # Return DTO
        return TemplateDTO(
            template_id=template.id,
            code=template.code,
            name=template.name,
            description=template.description,
            template_type=template.template_type,
            channel=template.channel,
            subject_template=template.subject_template,
            body_template=template.body_template,
            html_template=template.html_template,
            variables=[var.__dict__ for var in template.variables],
            is_active=template.is_active,
            version=template.version,
            created_at=template.created_at,
            updated_at=template.updated_at,
            tags=template.tags,
            metadata=template.metadata,
        )

    @property
    def command_type(self):
        """Get command type."""
        return UpdateTemplateCommand


# Export all handlers
__all__ = [
    "CancelScheduledNotificationCommandHandler",
    "CreateTemplateCommandHandler",
    "ProcessBatchCommandHandler",
    "RetryNotificationCommandHandler",
    "ScheduleNotificationCommandHandler",
    "SendNotificationCommandHandler",
    "UpdateRecipientPreferencesCommandHandler",
    "UpdateTemplateCommandHandler",
]
