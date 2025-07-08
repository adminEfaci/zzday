"""Notification application services.

This module contains application services that orchestrate complex business
operations across multiple domain entities and external services.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from app.core.errors import ApplicationError, ValidationError
from app.core.logging import get_logger
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.entities.notification_channel import (
    NotificationChannel as ChannelEntity,
)
from app.modules.notification.domain.enums import (
    ChannelStatus,
    DeliveryStatus,
    NotificationChannel,
)
from app.modules.notification.domain.errors import (
    ChannelNotConfiguredError,
    DeliveryFailedError,
    RateLimitExceededError,
)

logger = get_logger(__name__)


class NotificationService:
    """Service for notification orchestration and coordination."""

    def __init__(
        self,
        notification_repository,
        template_repository,
        recipient_repository,
        delivery_service,
        event_publisher,
    ):
        """Initialize notification service."""
        self.notification_repository = notification_repository
        self.template_repository = template_repository
        self.recipient_repository = recipient_repository
        self.delivery_service = delivery_service
        self.event_publisher = event_publisher

    async def send_notification(
        self, notification: Notification, retry_on_failure: bool = True
    ) -> None:
        """Send a notification through the appropriate channel.

        Args:
            notification: Notification to send
            retry_on_failure: Whether to retry on failure
        """
        try:
            # Update status to sending
            notification.update_status(DeliveryStatus.SENDING)
            await self.notification_repository.save(notification)

            # Send through delivery service
            result = await self.delivery_service.send(notification)

            # Update with result
            notification.update_status(
                DeliveryStatus.SENT,
                provider_message_id=result.get("message_id"),
                provider_status=result.get("status"),
            )
            notification.set_provider_info(
                provider=result.get("provider"), provider_response=result
            )

            await self.notification_repository.save(notification)

            # Publish sent event
            await self.event_publisher.publish_notification_sent(notification)

        except RateLimitExceededError as e:
            # Handle rate limiting
            logger.warning(
                "Rate limit exceeded",
                notification_id=notification.id,
                channel=notification.channel.value,
                retry_after=e.details.get("retry_after"),
            )

            if retry_on_failure and notification.can_retry:
                retry_after = e.details.get("retry_after", 60)
                notification.mark_for_retry(retry_after)
            else:
                notification.update_status(
                    DeliveryStatus.FAILED,
                    details="Rate limit exceeded",
                    error_code="RATE_LIMIT",
                )

            await self.notification_repository.save(notification)

        except DeliveryFailedError as e:
            # Handle delivery failure
            logger.exception(
                "Delivery failed",
                notification_id=notification.id,
                error=str(e),
                is_permanent=e.details.get("is_permanent"),
            )

            if (
                retry_on_failure
                and notification.can_retry
                and not e.details.get("is_permanent")
            ):
                notification.mark_for_retry()
            else:
                notification.update_status(
                    DeliveryStatus.FAILED,
                    details=str(e),
                    error_code=e.details.get("provider_error"),
                )

            await self.notification_repository.save(notification)

            # Publish failed event
            await self.event_publisher.publish_notification_failed(notification)

        except Exception as e:
            # Handle unexpected errors
            logger.exception(
                "Unexpected error sending notification",
                notification_id=notification.id,
                error=str(e),
            )

            if retry_on_failure and notification.can_retry:
                notification.mark_for_retry()
            else:
                notification.update_status(
                    DeliveryStatus.FAILED,
                    details=f"Unexpected error: {e!s}",
                    error_code="UNKNOWN",
                )

            await self.notification_repository.save(notification)
            raise

    async def process_scheduled_notifications(self) -> int:
        """Process notifications scheduled for delivery.

        Returns:
            Number of notifications processed
        """
        # Get notifications ready to send
        ready_notifications = await self.notification_repository.find_ready_to_send(
            max_items=100
        )

        if not ready_notifications:
            return 0

        logger.info(f"Processing {len(ready_notifications)} scheduled notifications")

        # Process in parallel with concurrency limit
        semaphore = asyncio.Semaphore(10)

        async def process_with_semaphore(notification):
            async with semaphore:
                await self.send_notification(notification)

        tasks = [
            process_with_semaphore(notification) for notification in ready_notifications
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        return len(ready_notifications)

    async def process_retry_queue(self) -> int:
        """Process notifications in retry queue.

        Returns:
            Number of notifications retried
        """
        # Get notifications ready for retry
        retry_notifications = await self.notification_repository.find_ready_for_retry(
            max_items=50
        )

        if not retry_notifications:
            return 0

        logger.info(f"Processing {len(retry_notifications)} retry notifications")

        # Process retries
        for notification in retry_notifications:
            await self.send_notification(notification, retry_on_failure=True)

        return len(retry_notifications)

    async def check_delivery_status(self, notification_id: UUID) -> DeliveryStatus:
        """Check and update delivery status from provider.

        Args:
            notification_id: Notification ID to check

        Returns:
            Current delivery status
        """
        notification = await self.notification_repository.find_by_id(notification_id)
        if not notification:
            raise ValidationError(f"Notification {notification_id} not found")

        # Only check if sent and has provider info
        if (
            notification.current_status != DeliveryStatus.SENT
            or not notification.provider
            or not notification.provider_message_id
        ):
            return notification.current_status

        try:
            # Get status from provider
            status = await self.delivery_service.get_provider_status(
                notification.provider, notification.provider_message_id
            )

            if status and status["status"] != notification.current_status.value:
                # Map provider status to our status
                new_status = self._map_provider_status(status["status"])
                if new_status:
                    notification.update_status(
                        new_status,
                        provider_status=status["status"],
                        details=status.get("details"),
                    )
                    await self.notification_repository.save(notification)

        except Exception as e:
            logger.warning(
                "Failed to check delivery status",
                notification_id=notification_id,
                error=str(e),
            )

        return notification.current_status

    def _map_provider_status(self, provider_status: str) -> DeliveryStatus | None:
        """Map provider status to our delivery status."""
        status_map = {
            "delivered": DeliveryStatus.DELIVERED,
            "failed": DeliveryStatus.FAILED,
            "bounced": DeliveryStatus.BOUNCED,
            "read": DeliveryStatus.READ,
            "opened": DeliveryStatus.READ,
            "clicked": DeliveryStatus.READ,
        }
        return status_map.get(provider_status.lower())


class TemplateService:
    """Service for template management and operations."""

    def __init__(self, template_repository, event_publisher):
        """Initialize template service."""
        self.template_repository = template_repository
        self.event_publisher = event_publisher

    async def validate_template_variables(
        self, template_id: UUID, variables: dict[str, Any]
    ) -> dict[str, list[str]]:
        """Validate variables against template requirements.

        Args:
            template_id: Template ID
            variables: Variables to validate

        Returns:
            Dictionary with 'missing' and 'invalid' variable lists
        """
        template = await self.template_repository.find_by_id(template_id)
        if not template:
            raise ValidationError(f"Template {template_id} not found")

        errors = {"missing": [], "invalid": []}

        # Check required variables
        for var in template.variables:
            if var.required and var.name not in variables:
                if var.default_value is None:
                    errors["missing"].append(var.name)
            elif var.name in variables:
                # Validate value
                if not var.validate_value(variables[var.name]):
                    errors["invalid"].append(var.name)

        return errors

    async def clone_template(
        self,
        template_id: UUID,
        new_code: str,
        new_name: str,
        modifications: dict[str, Any] | None = None,
    ) -> UUID:
        """Clone an existing template with modifications.

        Args:
            template_id: Source template ID
            new_code: Code for new template
            new_name: Name for new template
            modifications: Optional modifications to apply

        Returns:
            New template ID
        """
        source_template = await self.template_repository.find_by_id(template_id)
        if not source_template:
            raise ValidationError(f"Template {template_id} not found")

        # Check if new code already exists
        existing = await self.template_repository.find_by_code(new_code)
        if existing:
            raise ValidationError(f"Template with code '{new_code}' already exists")

        # Clone template
        cloned = source_template.clone(new_code, new_name)

        # Apply modifications
        if modifications:
            if "description" in modifications:
                cloned.update_description(modifications["description"])
            if "subject_template" in modifications:
                cloned.update_subject_template(modifications["subject_template"])
            if "body_template" in modifications:
                cloned.update_body_template(modifications["body_template"])
            if "html_template" in modifications:
                cloned.update_html_template(modifications["html_template"])

        # Save cloned template
        await self.template_repository.save(cloned)

        # Publish event
        await self.event_publisher.publish_template_cloned(source_template, cloned)

        return cloned.id

    async def preview_template(
        self,
        template_id: UUID,
        variables: dict[str, Any],
        channel: NotificationChannel | None = None,
    ) -> dict[str, str]:
        """Preview rendered template content.

        Args:
            template_id: Template ID
            variables: Variables for rendering
            channel: Optional channel for optimization

        Returns:
            Dictionary with rendered content
        """
        template = await self.template_repository.find_by_id(template_id)
        if not template:
            raise ValidationError(f"Template {template_id} not found")

        # Validate variables
        validation_errors = await self.validate_template_variables(
            template_id, variables
        )
        if validation_errors["missing"] or validation_errors["invalid"]:
            raise ValidationError(f"Invalid variables: {validation_errors}")

        # Render template
        content = template.render(variables)

        # Optimize for channel if specified
        if channel and channel != template.channel:
            content = content.for_channel(channel)

        return {
            "subject": content.subject,
            "body": content.body,
            "html_body": content.html_body,
        }


class DeliveryService:
    """Service for notification delivery coordination."""

    def __init__(self, channel_providers, rate_limiter, metrics_service):
        """Initialize delivery service."""
        self.channel_providers = channel_providers
        self.rate_limiter = rate_limiter
        self.metrics_service = metrics_service

    async def send(self, notification: Notification) -> dict[str, Any]:
        """Send notification through appropriate provider.

        Args:
            notification: Notification to send

        Returns:
            Provider response
        """
        # Get provider for channel
        provider = self._get_provider(notification.channel)
        if not provider:
            raise ChannelNotConfiguredError(
                channel=notification.channel.value, reason="No provider configured"
            )

        # Check rate limits
        if not await self.rate_limiter.check_and_consume(
            channel=notification.channel, recipient_id=notification.recipient_id
        ):
            retry_after = await self.rate_limiter.get_retry_after(
                channel=notification.channel, recipient_id=notification.recipient_id
            )
            raise RateLimitExceededError(
                channel=notification.channel.value,
                limit=await self.rate_limiter.get_limit(notification.channel),
                window="minute",
                retry_after=retry_after,
            )

        # Record send attempt
        start_time = datetime.utcnow()

        try:
            # Send through provider
            result = await provider.send(
                recipient_address=str(notification.recipient_address),
                content=notification.content,
                metadata=notification.metadata,
            )

            # Record metrics
            await self.metrics_service.record_delivery(
                channel=notification.channel,
                provider=provider.name,
                success=True,
                duration=(datetime.utcnow() - start_time).total_seconds(),
            )

            return {
                "provider": provider.name,
                "message_id": result.get("message_id"),
                "status": result.get("status", "sent"),
                **result,
            }

        except Exception as e:
            # Record failure metrics
            await self.metrics_service.record_delivery(
                channel=notification.channel,
                provider=provider.name,
                success=False,
                duration=(datetime.utcnow() - start_time).total_seconds(),
                error_code=getattr(e, "code", "UNKNOWN"),
            )

            # Determine if permanent failure
            is_permanent = self._is_permanent_failure(e)

            raise DeliveryFailedError(
                notification_id=notification.id,
                channel=notification.channel.value,
                reason=str(e),
                provider_error=getattr(e, "provider_error", None),
                is_permanent=is_permanent,
            )

    async def get_provider_status(
        self, provider_name: str, message_id: str
    ) -> dict[str, Any] | None:
        """Get delivery status from provider.

        Args:
            provider_name: Provider name
            message_id: Provider message ID

        Returns:
            Status information or None
        """
        provider = self.channel_providers.get(provider_name)
        if not provider or not hasattr(provider, "get_status"):
            return None

        try:
            return await provider.get_status(message_id)
        except Exception as e:
            logger.warning(
                "Failed to get provider status",
                provider=provider_name,
                message_id=message_id,
                error=str(e),
            )
            return None

    def _get_provider(self, channel: NotificationChannel):
        """Get provider for channel."""
        return self.channel_providers.get(channel.value)

    def _is_permanent_failure(self, error: Exception) -> bool:
        """Determine if error is a permanent failure."""
        permanent_error_codes = [
            "INVALID_RECIPIENT",
            "UNSUBSCRIBED",
            "BLOCKED",
            "INVALID_CONTENT",
            "AUTHENTICATION_FAILED",
        ]

        error_code = getattr(error, "code", "").upper()
        return error_code in permanent_error_codes


class SchedulingService:
    """Service for notification scheduling operations."""

    def __init__(self, schedule_repository, notification_service, event_publisher):
        """Initialize scheduling service."""
        self.schedule_repository = schedule_repository
        self.notification_service = notification_service
        self.event_publisher = event_publisher

    async def process_schedules(self) -> int:
        """Process active schedules that are due.

        Returns:
            Number of schedules processed
        """
        # Get schedules due for execution
        due_schedules = await self.schedule_repository.find_due_schedules(max_items=50)

        if not due_schedules:
            return 0

        logger.info(f"Processing {len(due_schedules)} due schedules")

        processed = 0
        for schedule in due_schedules:
            try:
                await self._execute_schedule(schedule)
                processed += 1
            except Exception as e:
                logger.exception(
                    "Failed to execute schedule", schedule_id=schedule.id, error=str(e)
                )

        return processed

    async def _execute_schedule(self, schedule) -> None:
        """Execute a single schedule."""
        # Create notification from schedule
        from app.modules.notification.application.commands import (
            SendNotificationCommand,
        )

        command = SendNotificationCommand(**schedule.notification_request)

        # Send notification
        result = await self.notification_service.send_notification_from_command(command)

        # Update schedule
        schedule.record_execution()

        # Calculate next run for recurring schedules
        if schedule.is_recurring and schedule.should_continue():
            next_run = schedule.calculate_next_run()
            if next_run:
                schedule.update_next_run(next_run)
        else:
            # Mark as completed
            schedule.complete()

        await self.schedule_repository.save(schedule)

        # Publish event
        await self.event_publisher.publish_schedule_executed(schedule, result)


class PreferenceService:
    """Service for managing recipient preferences."""

    def __init__(self, recipient_repository, event_publisher):
        """Initialize preference service."""
        self.recipient_repository = recipient_repository
        self.event_publisher = event_publisher

    async def apply_preferences(
        self, recipient_id: UUID, channel: NotificationChannel, notification_type: str
    ) -> bool:
        """Check if notification should be sent based on preferences.

        Args:
            recipient_id: Recipient ID
            channel: Notification channel
            notification_type: Type of notification

        Returns:
            True if notification should be sent
        """
        recipient = await self.recipient_repository.find_by_id(recipient_id)
        if not recipient:
            # Default to allowing if no preferences set
            return True

        # Check channel preference
        if not recipient.is_channel_enabled(channel.value):
            logger.info(
                "Channel disabled by recipient",
                recipient_id=recipient_id,
                channel=channel.value,
            )
            return False

        # Check notification type preference
        if not recipient.is_type_enabled(notification_type):
            logger.info(
                "Notification type disabled by recipient",
                recipient_id=recipient_id,
                notification_type=notification_type,
            )
            return False

        # Check quiet hours
        if recipient.is_in_quiet_hours():
            logger.info("Recipient in quiet hours", recipient_id=recipient_id)
            return False

        return True

    async def unsubscribe_recipient(
        self,
        recipient_id: UUID,
        channel: NotificationChannel | None = None,
        notification_type: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Unsubscribe recipient from notifications.

        Args:
            recipient_id: Recipient ID
            channel: Optional specific channel to unsubscribe
            notification_type: Optional specific type to unsubscribe
            reason: Unsubscribe reason
        """
        recipient = await self.recipient_repository.find_by_id(recipient_id)
        if not recipient:
            recipient = NotificationRecipient(recipient_id=recipient_id, preferences={})

        if channel:
            # Unsubscribe from specific channel
            recipient.disable_channel(channel.value)
        elif notification_type:
            # Unsubscribe from specific type
            recipient.disable_type(notification_type)
        else:
            # Global unsubscribe
            recipient.unsubscribe_all(reason)

        await self.recipient_repository.save(recipient)

        # Publish event
        await self.event_publisher.publish_recipient_unsubscribed(
            recipient,
            channel=channel,
            notification_type=notification_type,
            reason=reason,
        )


# Export all services
__all__ = [
    "DeliveryService",
    "NotificationService",
    "PreferenceService",
    "SchedulingService",
    "TemplateService",
]
