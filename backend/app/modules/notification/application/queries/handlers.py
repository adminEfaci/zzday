"""Notification query handlers.

This module contains handlers for processing notification queries,
implementing the logic for retrieving notification data.
"""

from datetime import datetime
from typing import Any

from app.core.cqrs.base import QueryHandler
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.notification.application.dto import (
    BatchStatusDTO,
    ChannelStatusDTO,
    DeliveryReportDTO,
    NotificationHistoryDTO,
    NotificationResponseDTO,
    RecipientPreferencesDTO,
    ScheduledNotificationDTO,
    TemplateDTO,
)
from app.modules.notification.application.queries import (
    GetBatchStatusQuery,
    GetChannelStatusQuery,
    GetDeliveryStatusQuery,
    GetNotificationHistoryQuery,
    GetNotificationMetricsQuery,
    GetNotificationQuery,
    GetRecipientPreferencesQuery,
    GetTemplateQuery,
    ListScheduledNotificationsQuery,
    ListTemplatesQuery,
    SearchNotificationsQuery,
)
from app.modules.notification.domain.errors import (
    NotificationNotFoundError,
    TemplateNotFoundError,
)

logger = get_logger(__name__)


class GetNotificationQueryHandler(
    QueryHandler[GetNotificationQuery, NotificationResponseDTO]
):
    """Handler for getting a specific notification."""

    def __init__(self, notification_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository

    async def handle(self, query: GetNotificationQuery) -> NotificationResponseDTO:
        """Handle get notification query."""
        notification = await self.notification_repository.find_by_id(
            query.notification_id
        )
        if not notification:
            raise NotificationNotFoundError(query.notification_id)

        return NotificationResponseDTO.from_notification(notification)

    @property
    def query_type(self):
        """Get query type."""
        return GetNotificationQuery


class GetTemplateQueryHandler(QueryHandler[GetTemplateQuery, TemplateDTO]):
    """Handler for getting a notification template."""

    def __init__(self, template_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.template_repository = template_repository

    async def handle(self, query: GetTemplateQuery) -> TemplateDTO:
        """Handle get template query."""
        if query.template_id:
            template = await self.template_repository.find_by_id(query.template_id)
            if not template:
                raise TemplateNotFoundError(query.template_id)
        else:
            template = await self.template_repository.find_by_code(query.template_code)
            if not template:
                raise NotFoundError("Template", query.template_code)

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
    def query_type(self):
        """Get query type."""
        return GetTemplateQuery


class GetRecipientPreferencesQueryHandler(
    QueryHandler[GetRecipientPreferencesQuery, RecipientPreferencesDTO]
):
    """Handler for getting recipient preferences."""

    def __init__(self, recipient_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.recipient_repository = recipient_repository

    async def handle(
        self, query: GetRecipientPreferencesQuery
    ) -> RecipientPreferencesDTO:
        """Handle get recipient preferences query."""
        recipient = await self.recipient_repository.find_by_id(query.recipient_id)

        # Return default preferences if recipient not found
        if not recipient:
            return RecipientPreferencesDTO(
                recipient_id=query.recipient_id,
                preferences={},
                email_enabled=True,
                sms_enabled=True,
                push_enabled=True,
                in_app_enabled=True,
                marketing_enabled=True,
                transactional_enabled=True,
                system_enabled=True,
                alert_enabled=True,
                quiet_hours_enabled=False,
                timezone="UTC",
                updated_at=datetime.utcnow(),
            )

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
    def query_type(self):
        """Get query type."""
        return GetRecipientPreferencesQuery


class GetNotificationHistoryQueryHandler(
    QueryHandler[GetNotificationHistoryQuery, NotificationHistoryDTO]
):
    """Handler for getting notification history."""

    def __init__(self, notification_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository

    async def handle(
        self, query: GetNotificationHistoryQuery
    ) -> NotificationHistoryDTO:
        """Handle get notification history query."""
        # Build filter criteria
        filters = {}
        if query.recipient_id:
            filters["recipient_id"] = query.recipient_id
        if query.channel:
            filters["channel"] = query.channel
        if query.status:
            filters["status"] = query.status
        if query.date_from:
            filters["created_at__gte"] = query.date_from
        if query.date_to:
            filters["created_at__lte"] = query.date_to
        if query.template_id:
            filters["template_id"] = query.template_id

        # Get notifications with pagination
        (
            notifications,
            total_count,
        ) = await self.notification_repository.find_with_filters(
            filters=filters,
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by or "created_at",
            sort_direction=query.sort_direction,
        )

        # Convert to DTOs
        notification_dtos = [
            NotificationResponseDTO.from_notification(notification)
            for notification in notifications
        ]

        return NotificationHistoryDTO(
            notifications=notification_dtos,
            total_count=total_count,
            page=query.page,
            page_size=query.page_size,
            recipient_id=query.recipient_id,
            channel=query.channel,
            status=query.status,
            date_from=query.date_from,
            date_to=query.date_to,
        )

    @property
    def query_type(self):
        """Get query type."""
        return GetNotificationHistoryQuery


class GetDeliveryStatusQueryHandler(
    QueryHandler[GetDeliveryStatusQuery, DeliveryReportDTO]
):
    """Handler for getting detailed delivery status."""

    def __init__(self, notification_repository, delivery_service):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository
        self.delivery_service = delivery_service

    async def handle(self, query: GetDeliveryStatusQuery) -> DeliveryReportDTO:
        """Handle get delivery status query."""
        # Get notification
        if query.notification_id:
            notification = await self.notification_repository.find_by_id(
                query.notification_id
            )
        else:
            notification = (
                await self.notification_repository.find_by_provider_message_id(
                    query.provider_message_id
                )
            )

        if not notification:
            raise NotificationNotFoundError(
                query.notification_id or query.provider_message_id
            )

        # Get latest status from provider if available
        if notification.provider and notification.provider_message_id:
            try:
                provider_status = await self.delivery_service.get_provider_status(
                    notification.provider, notification.provider_message_id
                )
                # Update notification with latest status if changed
                if provider_status and provider_status != notification.current_status:
                    notification.update_status(
                        provider_status["status"],
                        details=provider_status.get("details"),
                        provider_status=provider_status.get("raw_status"),
                    )
                    await self.notification_repository.save(notification)
            except Exception as e:
                logger.warning(
                    "Failed to get provider status",
                    notification_id=notification.id,
                    error=str(e),
                )

        # Build delivery report
        return DeliveryReportDTO(
            notification_id=notification.id,
            channel=notification.channel,
            status=notification.current_status,
            created_at=notification.created_at,
            queued_at=next(
                (
                    s.timestamp
                    for s in notification.status_history
                    if s.status.value == "queued"
                ),
                None,
            ),
            sent_at=notification.sent_at,
            delivered_at=notification.delivered_at,
            read_at=notification.read_at,
            failed_at=notification.failed_at,
            provider=notification.provider,
            provider_message_id=notification.provider_message_id,
            provider_status=notification.provider_response.get("status")
            if notification.provider_response
            else None,
            retry_count=notification.retry_count,
            error_code=next(
                (
                    s.error_code
                    for s in reversed(notification.status_history)
                    if s.error_code
                ),
                None,
            ),
            error_message=next(
                (
                    s.details
                    for s in reversed(notification.status_history)
                    if s.status.value == "failed"
                ),
                None,
            ),
            delivery_duration_seconds=(
                notification.get_delivery_duration().total_seconds()
                if notification.get_delivery_duration()
                else None
            ),
            processing_duration_seconds=(
                notification.get_processing_duration().total_seconds()
                if notification.get_processing_duration()
                else None
            ),
            status_history=[
                {
                    "status": s.status.value,
                    "timestamp": s.timestamp.isoformat(),
                    "details": s.details,
                    "error_code": s.error_code,
                }
                for s in notification.status_history
            ],
        )

    @property
    def query_type(self):
        """Get query type."""
        return GetDeliveryStatusQuery


class GetBatchStatusQueryHandler(QueryHandler[GetBatchStatusQuery, BatchStatusDTO]):
    """Handler for getting batch processing status."""

    def __init__(self, batch_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.batch_repository = batch_repository

    async def handle(self, query: GetBatchStatusQuery) -> BatchStatusDTO:
        """Handle get batch status query."""
        batch = await self.batch_repository.find_by_id(query.batch_id)
        if not batch:
            raise NotFoundError("Batch", query.batch_id)

        # Calculate average delivery time
        avg_delivery_time = None
        if batch.delivered_count > 0:
            total_delivery_time = await self.batch_repository.get_total_delivery_time(
                query.batch_id
            )
            avg_delivery_time = total_delivery_time / batch.delivered_count

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
            average_delivery_time_seconds=avg_delivery_time,
            error_summary=batch.error_summary,
        )

    @property
    def query_type(self):
        """Get query type."""
        return GetBatchStatusQuery


class ListTemplatesQueryHandler(QueryHandler[ListTemplatesQuery, list[TemplateDTO]]):
    """Handler for listing notification templates."""

    def __init__(self, template_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.template_repository = template_repository

    async def handle(self, query: ListTemplatesQuery) -> list[TemplateDTO]:
        """Handle list templates query."""
        # Build filter criteria
        filters = {}
        if query.channel:
            filters["channel"] = query.channel
        if query.template_type:
            filters["template_type"] = query.template_type
        if query.is_active is not None:
            filters["is_active"] = query.is_active
        if query.tags:
            filters["tags__in"] = query.tags
        if query.search_term:
            filters["search"] = query.search_term

        # Get templates with pagination
        templates, _ = await self.template_repository.find_with_filters(
            filters=filters,
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by or "name",
            sort_direction=query.sort_direction,
        )

        # Convert to DTOs
        return [
            TemplateDTO(
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
            for template in templates
        ]

    @property
    def query_type(self):
        """Get query type."""
        return ListTemplatesQuery


class ListScheduledNotificationsQueryHandler(
    QueryHandler[ListScheduledNotificationsQuery, list[ScheduledNotificationDTO]]
):
    """Handler for listing scheduled notifications."""

    def __init__(self, schedule_repository):
        """Initialize handler with dependencies."""
        super().__init__()
        self.schedule_repository = schedule_repository

    async def handle(
        self, query: ListScheduledNotificationsQuery
    ) -> list[ScheduledNotificationDTO]:
        """Handle list scheduled notifications query."""
        # Build filter criteria
        filters = {}
        if query.recipient_id:
            filters["notification_request__recipient_id"] = query.recipient_id
        if query.is_active is not None:
            filters["is_active"] = query.is_active
        if query.from_date:
            filters["scheduled_for__gte"] = query.from_date
        if query.to_date:
            filters["scheduled_for__lte"] = query.to_date
        if not query.include_recurring:
            filters["is_recurring"] = False

        # Get schedules with pagination
        schedules, _ = await self.schedule_repository.find_with_filters(
            filters=filters,
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by or "scheduled_for",
            sort_direction=query.sort_direction,
        )

        # Convert to DTOs
        from app.modules.notification.application.dto import NotificationRequestDTO

        return [
            ScheduledNotificationDTO(
                schedule_id=schedule.id,
                notification_request=NotificationRequestDTO(
                    **schedule.notification_request
                ),
                scheduled_for=schedule.scheduled_for,
                is_recurring=schedule.is_recurring,
                recurrence_pattern=schedule.recurrence_pattern,
                recurrence_interval=schedule.recurrence_interval,
                recurrence_end_date=schedule.recurrence_end_date,
                is_active=schedule.is_active,
                last_run_at=schedule.last_run_at,
                next_run_at=schedule.next_run_at,
                run_count=schedule.run_count,
                created_at=schedule.created_at,
                created_by=schedule.created_by,
                metadata=schedule.metadata,
            )
            for schedule in schedules
        ]

    @property
    def query_type(self):
        """Get query type."""
        return ListScheduledNotificationsQuery


class GetChannelStatusQueryHandler(
    QueryHandler[GetChannelStatusQuery, list[ChannelStatusDTO]]
):
    """Handler for getting channel status and health."""

    def __init__(self, channel_service, metrics_service):
        """Initialize handler with dependencies."""
        super().__init__()
        self.channel_service = channel_service
        self.metrics_service = metrics_service

    async def handle(self, query: GetChannelStatusQuery) -> list[ChannelStatusDTO]:
        """Handle get channel status query."""
        # Get channel configurations
        if query.channel:
            channels = [query.channel]
        else:
            channels = await self.channel_service.get_configured_channels()

        results = []
        for channel in channels:
            # Get channel configuration
            config = await self.channel_service.get_channel_config(channel)
            if not config:
                continue

            # Get health status
            health = await self.channel_service.check_channel_health(channel)

            # Get metrics if requested
            metrics = {}
            if query.include_metrics:
                metrics = await self.metrics_service.get_channel_metrics(
                    channel=channel, period="24h"
                )

            results.append(
                ChannelStatusDTO(
                    channel=channel,
                    is_active=config.get("is_active", False),
                    provider=config.get("provider", "unknown"),
                    health_status=health.get("status", "unknown"),
                    last_check_at=health.get("last_check_at", datetime.utcnow()),
                    uptime_percentage=health.get("uptime_percentage", 0.0),
                    average_delivery_time_seconds=metrics.get("avg_delivery_time", 0.0),
                    success_rate=metrics.get("success_rate", 0.0),
                    rate_limit=config.get("rate_limit"),
                    rate_limit_window=config.get("rate_limit_window"),
                    current_usage=metrics.get("current_usage", 0),
                    features=config.get("features", []),
                    settings=config.get("settings", {}),
                )
            )

        return results

    @property
    def query_type(self):
        """Get query type."""
        return GetChannelStatusQuery


class GetNotificationMetricsQueryHandler(
    QueryHandler[GetNotificationMetricsQuery, dict[str, Any]]
):
    """Handler for getting notification metrics."""

    def __init__(self, metrics_service):
        """Initialize handler with dependencies."""
        super().__init__()
        self.metrics_service = metrics_service

    async def handle(self, query: GetNotificationMetricsQuery) -> dict[str, Any]:
        """Handle get notification metrics query."""
        # Get metrics from service
        return await self.metrics_service.get_notification_metrics(
            date_from=query.date_from,
            date_to=query.date_to,
            channel=query.channel,
            template_id=query.template_id,
            group_by=query.group_by,
        )

    @property
    def query_type(self):
        """Get query type."""
        return GetNotificationMetricsQuery


class SearchNotificationsQueryHandler(
    QueryHandler[SearchNotificationsQuery, NotificationHistoryDTO]
):
    """Handler for searching notifications."""

    def __init__(self, notification_repository, search_service):
        """Initialize handler with dependencies."""
        super().__init__()
        self.notification_repository = notification_repository
        self.search_service = search_service

    async def handle(self, query: SearchNotificationsQuery) -> NotificationHistoryDTO:
        """Handle search notifications query."""
        # Use search service for full-text search if search term provided
        if query.search_term:
            notification_ids = await self.search_service.search_notifications(
                search_term=query.search_term,
                limit=query.page_size * 10,  # Get more for filtering
            )
            if not notification_ids:
                return NotificationHistoryDTO(
                    notifications=[],
                    total_count=0,
                    page=query.page,
                    page_size=query.page_size,
                )
        else:
            notification_ids = None

        # Build filter criteria
        filters = {}
        if notification_ids:
            filters["id__in"] = notification_ids
        if query.recipient_ids:
            filters["recipient_id__in"] = query.recipient_ids
        if query.channels:
            filters["channel__in"] = query.channels
        if query.statuses:
            filters["status__in"] = query.statuses
        if query.template_ids:
            filters["template_id__in"] = query.template_ids
        if query.date_from:
            filters["created_at__gte"] = query.date_from
        if query.date_to:
            filters["created_at__lte"] = query.date_to
        if query.has_error is not None:
            if query.has_error:
                filters["status__in"] = ["failed", "bounced"]
            else:
                filters["status__not_in"] = ["failed", "bounced"]
        if query.provider:
            filters["provider"] = query.provider

        # Get notifications with pagination
        (
            notifications,
            total_count,
        ) = await self.notification_repository.find_with_filters(
            filters=filters,
            page=query.page,
            page_size=query.page_size,
            sort_by=query.sort_by or "created_at",
            sort_direction=query.sort_direction,
        )

        # Convert to DTOs
        notification_dtos = [
            NotificationResponseDTO.from_notification(notification)
            for notification in notifications
        ]

        return NotificationHistoryDTO(
            notifications=notification_dtos,
            total_count=total_count,
            page=query.page,
            page_size=query.page_size,
        )

    @property
    def query_type(self):
        """Get query type."""
        return SearchNotificationsQuery


# Export all handlers
__all__ = [
    "GetBatchStatusQueryHandler",
    "GetChannelStatusQueryHandler",
    "GetDeliveryStatusQueryHandler",
    "GetNotificationHistoryQueryHandler",
    "GetNotificationMetricsQueryHandler",
    "GetNotificationQueryHandler",
    "GetRecipientPreferencesQueryHandler",
    "GetTemplateQueryHandler",
    "ListScheduledNotificationsQueryHandler",
    "ListTemplatesQueryHandler",
    "SearchNotificationsQueryHandler",
]
