"""Notification domain errors.

This module contains domain-specific exceptions for the notification module,
providing detailed error information for various failure scenarios.
"""

from typing import Any, Optional
from uuid import UUID

from app.core.errors import DomainError, NotFoundError


class NotificationError(DomainError):
    """Base error for notification domain."""

    default_code = "NOTIFICATION_ERROR"


class NotificationNotFoundError(NotFoundError):
    """Raised when a notification is not found."""

    def __init__(self, notification_id: UUID, **kwargs):
        super().__init__(resource="Notification", identifier=notification_id, **kwargs)


class TemplateNotFoundError(NotFoundError):
    """Raised when a notification template is not found."""

    def __init__(self, template_id: UUID, **kwargs):
        super().__init__(
            resource="NotificationTemplate", identifier=template_id, **kwargs
        )


class InvalidTemplateError(NotificationError):
    """Raised when a template is invalid or malformed."""

    default_code = "INVALID_TEMPLATE"

    def __init__(
        self,
        template_id: UUID | None = None,
        template_name: str | None = None,
        reason: str = "Template validation failed",
        **kwargs,
    ):
        message = "Invalid template"
        if template_name:
            message += f" '{template_name}'"
        elif template_id:
            message += f" {template_id}"
        message += f": {reason}"

        super().__init__(
            message=message,
            details={
                "template_id": str(template_id) if template_id else None,
                "template_name": template_name,
                "reason": reason,
            },
            **kwargs,
        )


class DeliveryFailedError(NotificationError):
    """Raised when notification delivery fails."""

    default_code = "DELIVERY_FAILED"

    def __init__(
        self,
        notification_id: UUID,
        channel: str,
        reason: str,
        provider_error: str | None = None,
        is_permanent: bool = False,
        **kwargs,
    ):
        message = (
            f"Failed to deliver notification {notification_id} via {channel}: {reason}"
        )

        super().__init__(
            message=message,
            details={
                "notification_id": str(notification_id),
                "channel": channel,
                "reason": reason,
                "provider_error": provider_error,
                "is_permanent": is_permanent,
            },
            user_message="Failed to send notification. Please try again later.",
            recovery_hint="Check the delivery channel configuration and recipient status.",
            **kwargs,
        )

        # Set retryable based on whether failure is permanent
        self.retryable = not is_permanent


class ChannelNotConfiguredError(NotificationError):
    """Raised when a notification channel is not properly configured."""

    default_code = "CHANNEL_NOT_CONFIGURED"

    def __init__(self, channel: str, reason: str | None = None, **kwargs):
        message = f"Channel '{channel}' is not configured"
        if reason:
            message += f": {reason}"

        super().__init__(
            message=message,
            details={"channel": channel, "reason": reason},
            user_message=f"The {channel} notification service is not available.",
            recovery_hint="Contact administrator to configure the notification channel.",
            **kwargs,
        )


class RecipientNotFoundError(NotFoundError):
    """Raised when a notification recipient is not found."""

    def __init__(
        self,
        recipient_id: UUID | None = None,
        recipient_address: str | None = None,
        **kwargs,
    ):
        identifier = recipient_id or recipient_address
        super().__init__(resource="Recipient", identifier=identifier, **kwargs)


class RecipientBlockedError(NotificationError):
    """Raised when attempting to send to a blocked recipient."""

    default_code = "RECIPIENT_BLOCKED"

    def __init__(
        self, recipient_id: UUID, recipient_address: str, block_reason: str, **kwargs
    ):
        message = f"Recipient {recipient_address} is blocked: {block_reason}"

        super().__init__(
            message=message,
            details={
                "recipient_id": str(recipient_id),
                "recipient_address": recipient_address,
                "block_reason": block_reason,
            },
            user_message="Cannot send notification to this recipient.",
            **kwargs,
        )


class TemplateVariableError(InvalidTemplateError):
    """Raised when template variables are missing or invalid."""

    default_code = "TEMPLATE_VARIABLE_ERROR"

    def __init__(
        self,
        template_id: UUID,
        missing_variables: list | None = None,
        invalid_variables: dict[str, str] | None = None,
        **kwargs,
    ):
        reasons = []
        if missing_variables:
            reasons.append(f"Missing variables: {', '.join(missing_variables)}")
        if invalid_variables:
            invalid_msgs = [
                f"{var}: {reason}" for var, reason in invalid_variables.items()
            ]
            reasons.append(f"Invalid variables: {', '.join(invalid_msgs)}")

        super().__init__(
            template_id=template_id,
            reason="; ".join(reasons) or "Variable validation failed",
            **kwargs,
        )

        self.details.update(
            {
                "missing_variables": missing_variables,
                "invalid_variables": invalid_variables,
            }
        )


class BatchProcessingError(NotificationError):
    """Raised when batch processing fails."""

    default_code = "BATCH_PROCESSING_ERROR"

    def __init__(
        self,
        batch_id: UUID,
        total_notifications: int,
        failed_count: int,
        reason: str,
        **kwargs,
    ):
        message = f"Batch {batch_id} processing failed: {failed_count}/{total_notifications} notifications failed. {reason}"

        super().__init__(
            message=message,
            details={
                "batch_id": str(batch_id),
                "total_notifications": total_notifications,
                "failed_count": failed_count,
                "success_count": total_notifications - failed_count,
                "reason": reason,
            },
            user_message=f"Failed to process notification batch. {failed_count} out of {total_notifications} notifications failed.",
            **kwargs,
        )


class ScheduleError(NotificationError):
    """Raised when notification scheduling fails."""

    default_code = "SCHEDULE_ERROR"

    def __init__(
        self,
        schedule_id: UUID | None = None,
        reason: str = "Schedule validation failed",
        **kwargs,
    ):
        message = "Notification scheduling error"
        if schedule_id:
            message = f"Schedule {schedule_id} error"
        message += f": {reason}"

        super().__init__(
            message=message,
            details={
                "schedule_id": str(schedule_id) if schedule_id else None,
                "reason": reason,
            },
            **kwargs,
        )


class RateLimitExceededError(NotificationError):
    """Raised when notification rate limit is exceeded."""

    default_code = "RATE_LIMIT_EXCEEDED"

    def __init__(
        self,
        channel: str,
        limit: int,
        window: str,
        retry_after: int | None = None,
        **kwargs,
    ):
        message = f"Rate limit exceeded for {channel}: {limit} per {window}"

        super().__init__(
            message=message,
            details={
                "channel": channel,
                "limit": limit,
                "window": window,
                "retry_after": retry_after,
            },
            user_message="Too many notifications sent. Please wait before sending more.",
            recovery_hint=f"Wait {retry_after or 60} seconds before sending more notifications.",
            **kwargs,
        )

        self.retryable = True


class DuplicateNotificationError(NotificationError):
    """Raised when attempting to create a duplicate notification."""

    default_code = "DUPLICATE_NOTIFICATION"

    def __init__(self, idempotency_key: str, existing_notification_id: UUID, **kwargs):
        message = (
            f"Notification with idempotency key '{idempotency_key}' already exists"
        )

        super().__init__(
            message=message,
            details={
                "idempotency_key": idempotency_key,
                "existing_notification_id": str(existing_notification_id),
            },
            user_message="This notification has already been sent.",
            **kwargs,
        )


class InvalidChannelError(NotificationError):
    """Raised when an invalid channel is specified."""

    default_code = "INVALID_CHANNEL"

    def __init__(self, channel: str, available_channels: list, **kwargs):
        message = f"Invalid notification channel: '{channel}'. Available channels: {', '.join(available_channels)}"

        super().__init__(
            message=message,
            details={
                "invalid_channel": channel,
                "available_channels": available_channels,
            },
            user_message=f"The notification channel '{channel}' is not supported.",
            **kwargs,
        )


class TemplateRenderError(InvalidTemplateError):
    """Raised when template rendering fails."""

    default_code = "TEMPLATE_RENDER_ERROR"

    def __init__(self, template_id: UUID, render_error: str, **kwargs):
        super().__init__(
            template_id=template_id,
            reason=f"Failed to render template: {render_error}",
            **kwargs,
        )

        self.details["render_error"] = render_error


class InvalidPriorityError(NotificationError):
    """Raised when an invalid priority is specified."""

    default_code = "INVALID_PRIORITY"

    def __init__(self, priority: str, valid_priorities: list, **kwargs):
        message = f"Invalid notification priority: '{priority}'. Valid priorities: {', '.join(valid_priorities)}"

        super().__init__(
            message=message,
            details={
                "invalid_priority": priority,
                "valid_priorities": valid_priorities,
            },
            **kwargs,
        )


class NotificationExpiredError(NotificationError):
    """Raised when attempting to process an expired notification."""

    default_code = "NOTIFICATION_EXPIRED"

    def __init__(self, notification_id: UUID, expired_at: str, **kwargs):
        message = f"Notification {notification_id} has expired at {expired_at}"

        super().__init__(
            message=message,
            details={"notification_id": str(notification_id), "expired_at": expired_at},
            user_message="This notification has expired and cannot be sent.",
            **kwargs,
        )


# Export all errors
__all__ = [
    "BatchProcessingError",
    "ChannelNotConfiguredError",
    "DeliveryFailedError",
    "DuplicateNotificationError",
    "InvalidChannelError",
    "InvalidPriorityError",
    "InvalidTemplateError",
    "NotificationError",
    "NotificationExpiredError",
    "NotificationNotFoundError",
    "RateLimitExceededError",
    "RecipientBlockedError",
    "RecipientNotFoundError",
    "ScheduleError",
    "TemplateNotFoundError",
    "TemplateRenderError",
    "TemplateVariableError",
]
