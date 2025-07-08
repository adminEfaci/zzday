"""Notification application commands.

This module contains command classes for the notification module,
representing intents to modify the notification system state.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.core.cqrs.base import Command
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
    TemplateType,
)

# Constants
MAX_BATCH_SIZE = 10000


@dataclass
class NotificationContent:
    """Data class for notification content."""
    subject: str | None = None
    body: str | None = None
    html_body: str | None = None
    attachments: list[dict[str, Any]] | None = None


class SendNotificationCommand(Command):
    """Command to send a notification."""

    def __init__(
        self,
        recipient_id: UUID,
        channel: NotificationChannel,
        template_id: UUID | None = None,
        template_code: str | None = None,
        variables: dict[str, Any] | None = None,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        scheduled_for: datetime | None = None,
        expires_at: datetime | None = None,
        idempotency_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        subject: str | None = None,
        body: str | None = None,
        html_body: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ):
        """Initialize send notification command."""
        super().__init__()

        self.recipient_id = recipient_id
        self.channel = channel
        self.template_id = template_id
        self.template_code = template_code
        self.variables = variables or {}
        self.priority = priority
        self.scheduled_for = scheduled_for
        self.expires_at = expires_at
        self.idempotency_key = idempotency_key
        self.metadata = metadata or {}
        self.subject = subject
        self.body = body
        self.html_body = html_body
        self.attachments = attachments or []

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        # Either template or direct content must be provided
        if not (self.template_id or self.template_code) and not self.body:
            raise ValidationError("Either template or direct content must be provided")

        # Validate scheduling
        if self.scheduled_for and self.scheduled_for <= datetime.utcnow():
            raise ValidationError("Scheduled time must be in the future")

        # Validate expiration
        if self.expires_at and self.expires_at <= datetime.utcnow():
            raise ValidationError("Expiration time must be in the future")

        if (
            self.scheduled_for
            and self.expires_at
            and self.scheduled_for > self.expires_at
        ):
            raise ValidationError("Scheduled time cannot be after expiration time")


class CreateTemplateCommand(Command):
    """Command to create a notification template."""

    def __init__(
        self,
        code: str,
        name: str,
        channel: NotificationChannel,
        template_type: TemplateType,
        subject_template: str | None = None,
        body_template: str = "",
        html_template: str | None = None,
        description: str | None = None,
        variables: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        is_active: bool = True,
    ):
        """Initialize create template command."""
        super().__init__()

        self.code = code.strip()
        self.name = name.strip()
        self.channel = channel
        self.template_type = template_type
        self.subject_template = subject_template.strip() if subject_template else None
        self.body_template = body_template.strip()
        self.html_template = html_template.strip() if html_template else None
        self.description = description
        self.variables = variables or []
        self.tags = tags or []
        self.metadata = metadata or {}
        self.is_active = is_active

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.code:
            raise ValidationError("Template code is required")

        if not self.name:
            raise ValidationError("Template name is required")

        if not self.body_template:
            raise ValidationError("Template body is required")

        # Email templates require subject
        if self.channel == NotificationChannel.EMAIL and not self.subject_template:
            raise ValidationError("Email templates require a subject")


class ScheduleNotificationCommand(Command):
    """Command to schedule a notification."""

    def __init__(
        self,
        notification_request: dict[str, Any],
        scheduled_for: datetime,
        is_recurring: bool = False,
        recurrence_pattern: str | None = None,
        recurrence_interval: int | None = None,
        recurrence_end_date: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize schedule notification command."""
        super().__init__()

        self.notification_request = notification_request
        self.scheduled_for = scheduled_for
        self.is_recurring = is_recurring
        self.recurrence_pattern = recurrence_pattern
        self.recurrence_interval = recurrence_interval
        self.recurrence_end_date = recurrence_end_date
        self.metadata = metadata or {}

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if self.scheduled_for <= datetime.utcnow():
            raise ValidationError("Scheduled time must be in the future")

        if self.is_recurring:
            if not self.recurrence_pattern:
                raise ValidationError(
                    "Recurrence pattern is required for recurring notifications"
                )

            valid_patterns = ["daily", "weekly", "monthly"]
            if self.recurrence_pattern not in valid_patterns:
                raise ValidationError(
                    f"Invalid recurrence pattern. Must be one of: {', '.join(valid_patterns)}"
                )

            if self.recurrence_interval and self.recurrence_interval < 1:
                raise ValidationError("Recurrence interval must be positive")

            if (
                self.recurrence_end_date
                and self.recurrence_end_date <= self.scheduled_for
            ):
                raise ValidationError(
                    "Recurrence end date must be after scheduled time"
                )


class ProcessBatchCommand(Command):
    """Command to process a batch of notifications."""

    def __init__(
        self,
        notifications: list[dict[str, Any]],
        batch_name: str | None = None,
        process_immediately: bool = False,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize process batch command."""
        super().__init__()

        self.notifications = notifications
        self.batch_name = batch_name
        self.process_immediately = process_immediately
        self.metadata = metadata or {}

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.notifications:
            raise ValidationError("Batch must contain at least one notification")

        if len(self.notifications) > MAX_BATCH_SIZE:
            raise ValidationError(f"Batch size cannot exceed {MAX_BATCH_SIZE:,} notifications")


class UpdateRecipientPreferencesCommand(Command):
    """Command to update recipient notification preferences."""

    def __init__(
        self,
        recipient_id: UUID,
        preferences: dict[str, Any],
        email_addresses: list[str] | None = None,
        phone_numbers: list[str] | None = None,
        device_tokens: list[str] | None = None,
    ):
        """Initialize update preferences command."""
        super().__init__()

        self.recipient_id = recipient_id
        self.preferences = preferences
        self.email_addresses = email_addresses
        self.phone_numbers = phone_numbers
        self.device_tokens = device_tokens

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        # Validate email addresses
        if self.email_addresses:
            for email in self.email_addresses:
                if "@" not in email:
                    raise ValidationError(f"Invalid email address: {email}")

        # Validate phone numbers
        if self.phone_numbers:
            for phone in self.phone_numbers:
                if not phone.startswith("+"):
                    raise ValidationError(f"Phone number must start with +: {phone}")


class CancelScheduledNotificationCommand(Command):
    """Command to cancel a scheduled notification."""

    def __init__(self, schedule_id: UUID, reason: str | None = None):
        """Initialize cancel scheduled notification command."""
        super().__init__()

        self.schedule_id = schedule_id
        self.reason = reason

        self._freeze()


class RetryNotificationCommand(Command):
    """Command to retry a failed notification."""

    def __init__(self, notification_id: UUID, delay_seconds: int | None = None):
        """Initialize retry notification command."""
        super().__init__()

        self.notification_id = notification_id
        self.delay_seconds = delay_seconds

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if self.delay_seconds is not None and self.delay_seconds < 0:
            raise ValidationError("Delay seconds cannot be negative")


class UpdateTemplateCommand(Command):
    """Command to update a notification template."""

    def __init__(
        self,
        template_id: UUID,
        name: str | None = None,
        subject_template: str | None = None,
        body_template: str | None = None,
        html_template: str | None = None,
        description: str | None = None,
        variables: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        is_active: bool | None = None,
    ):
        """Initialize update template command."""
        super().__init__()

        self.template_id = template_id
        self.name = name.strip() if name else None
        self.subject_template = subject_template.strip() if subject_template else None
        self.body_template = body_template.strip() if body_template else None
        self.html_template = html_template.strip() if html_template else None
        self.description = description
        self.variables = variables
        self.tags = tags
        self.metadata = metadata
        self.is_active = is_active

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        # At least one field must be updated
        update_fields = [
            self.name,
            self.subject_template,
            self.body_template,
            self.html_template,
            self.description,
            self.variables,
            self.tags,
            self.metadata,
            self.is_active,
        ]
        if not any(field is not None for field in update_fields):
            raise ValidationError("At least one field must be updated")


# Export all commands
__all__ = [
    "CancelScheduledNotificationCommand",
    "CreateTemplateCommand",
    "ProcessBatchCommand",
    "RetryNotificationCommand",
    "ScheduleNotificationCommand",
    "SendNotificationCommand",
    "UpdateRecipientPreferencesCommand",
    "UpdateTemplateCommand",
]
