"""Notification application queries.

This module contains query classes for the notification module,
representing requests for information without modifying state.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from app.core.cqrs.base import Query
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import DeliveryStatus, NotificationChannel


class GetNotificationQuery(Query):
    """Query to get a specific notification."""

    def __init__(self, notification_id: UUID):
        """Initialize get notification query."""
        super().__init__()

        self.notification_id = notification_id

        self._freeze()


class GetTemplateQuery(Query):
    """Query to get a notification template."""

    def __init__(
        self, template_id: UUID | None = None, template_code: str | None = None
    ):
        """Initialize get template query."""
        super().__init__()

        self.template_id = template_id
        self.template_code = template_code

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        if not self.template_id and not self.template_code:
            raise ValidationError(
                "Either template_id or template_code must be provided"
            )


class GetRecipientPreferencesQuery(Query):
    """Query to get recipient notification preferences."""

    def __init__(self, recipient_id: UUID):
        """Initialize get recipient preferences query."""
        super().__init__()

        self.recipient_id = recipient_id

        self._freeze()


class GetNotificationHistoryQuery(Query):
    """Query to get notification history for a recipient."""

    def __init__(
        self,
        recipient_id: UUID | None = None,
        channel: NotificationChannel | None = None,
        status: DeliveryStatus | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        template_id: UUID | None = None,
        include_details: bool = False,
    ):
        """Initialize get notification history query."""
        super().__init__()

        self.recipient_id = recipient_id
        self.channel = channel
        self.status = status
        self.date_from = date_from
        self.date_to = date_to
        self.template_id = template_id
        self.include_details = include_details

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        # Validate date range
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValidationError("date_from must be before date_to")


class GetDeliveryStatusQuery(Query):
    """Query to get detailed delivery status for a notification."""

    def __init__(
        self,
        notification_id: UUID | None = None,
        provider_message_id: str | None = None,
    ):
        """Initialize get delivery status query."""
        super().__init__()

        self.notification_id = notification_id
        self.provider_message_id = provider_message_id

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        if not self.notification_id and not self.provider_message_id:
            raise ValidationError(
                "Either notification_id or provider_message_id must be provided"
            )


class GetBatchStatusQuery(Query):
    """Query to get batch processing status."""

    def __init__(self, batch_id: UUID):
        """Initialize get batch status query."""
        super().__init__()

        self.batch_id = batch_id

        self._freeze()


class ListTemplatesQuery(Query):
    """Query to list notification templates."""

    def __init__(
        self,
        channel: NotificationChannel | None = None,
        template_type: str | None = None,
        is_active: bool | None = None,
        tags: list[str] | None = None,
        search_term: str | None = None,
    ):
        """Initialize list templates query."""
        super().__init__()

        self.channel = channel
        self.template_type = template_type
        self.is_active = is_active
        self.tags = tags or []
        self.search_term = search_term

        self._freeze()


class ListScheduledNotificationsQuery(Query):
    """Query to list scheduled notifications."""

    def __init__(
        self,
        recipient_id: UUID | None = None,
        is_active: bool | None = True,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        include_recurring: bool = True,
    ):
        """Initialize list scheduled notifications query."""
        super().__init__()

        self.recipient_id = recipient_id
        self.is_active = is_active
        self.from_date = from_date
        self.to_date = to_date
        self.include_recurring = include_recurring

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        # Validate date range
        if self.from_date and self.to_date and self.from_date > self.to_date:
            raise ValidationError("from_date must be before to_date")


class GetChannelStatusQuery(Query):
    """Query to get channel status and health."""

    def __init__(
        self, channel: NotificationChannel | None = None, include_metrics: bool = True
    ):
        """Initialize get channel status query."""
        super().__init__()

        self.channel = channel
        self.include_metrics = include_metrics

        self._freeze()


class GetNotificationMetricsQuery(Query):
    """Query to get notification metrics and statistics."""

    def __init__(
        self,
        date_from: datetime,
        date_to: datetime,
        channel: NotificationChannel | None = None,
        template_id: UUID | None = None,
        group_by: str | None = "day",  # "hour", "day", "week", "month"
    ):
        """Initialize get notification metrics query."""
        super().__init__()

        self.date_from = date_from
        self.date_to = date_to
        self.channel = channel
        self.template_id = template_id
        self.group_by = group_by

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        # Validate date range
        if self.date_from > self.date_to:
            raise ValidationError("date_from must be before date_to")

        # Validate group_by
        valid_groups = ["hour", "day", "week", "month"]
        if self.group_by not in valid_groups:
            raise ValidationError(
                f"Invalid group_by value. Must be one of: {', '.join(valid_groups)}"
            )


class SearchNotificationsQuery(Query):
    """Query to search notifications with various filters."""

    def __init__(
        self,
        search_term: str | None = None,
        recipient_ids: list[UUID] | None = None,
        channels: list[NotificationChannel] | None = None,
        statuses: list[DeliveryStatus] | None = None,
        template_ids: list[UUID] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        has_error: bool | None = None,
        provider: str | None = None,
    ):
        """Initialize search notifications query."""
        super().__init__()

        self.search_term = search_term
        self.recipient_ids = recipient_ids or []
        self.channels = channels or []
        self.statuses = statuses or []
        self.template_ids = template_ids or []
        self.date_from = date_from
        self.date_to = date_to
        self.has_error = has_error
        self.provider = provider

        self._freeze()

    def _validate_query(self) -> None:
        """Validate query state."""
        super()._validate_query()

        # Validate date range
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValidationError("date_from must be before date_to")

        # At least one filter should be provided
        if not any(
            [
                self.search_term,
                self.recipient_ids,
                self.channels,
                self.statuses,
                self.template_ids,
                self.date_from,
                self.date_to,
                self.has_error is not None,
                self.provider,
            ]
        ):
            raise ValidationError("At least one search filter must be provided")


# Export all queries
__all__ = [
    "GetBatchStatusQuery",
    "GetChannelStatusQuery",
    "GetDeliveryStatusQuery",
    "GetNotificationHistoryQuery",
    "GetNotificationMetricsQuery",
    "GetNotificationQuery",
    "GetRecipientPreferencesQuery",
    "GetTemplateQuery",
    "ListScheduledNotificationsQuery",
    "ListTemplatesQuery",
    "SearchNotificationsQuery",
]
