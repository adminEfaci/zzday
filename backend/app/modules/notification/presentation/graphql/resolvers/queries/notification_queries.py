"""
Notification Query Resolvers

GraphQL query resolvers for notification management including history, status,
preferences, and analytics.
"""

from datetime import datetime
from uuid import UUID

import strawberry

from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger
from app.modules.identity.presentation.graphql.decorators import (
    audit_log,
    cache_result,
    rate_limit,
    require_auth,
    require_permission,
    track_metrics,
)

logger = get_logger(__name__)

# Constants
MIN_SEARCH_QUERY_LENGTH = 3

from ...schemas.inputs.notification_inputs import (
    DateRangeInput,
    NotificationFilterInput,
    PaginationInput,
)
from ...schemas.types.notification_type import (
    NotificationAnalyticsType,
    NotificationBatchType,
    NotificationListType,
    NotificationSummaryType,
    NotificationType,
)


@strawberry.type
class NotificationQueries:
    """Notification query resolvers with comprehensive features."""

    @strawberry.field(description="Get notification by ID")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_read", max_attempts=100, window=60)
    @audit_log("notification.get_by_id")
    @track_metrics("notification_get_by_id")
    @cache_result(ttl=60, key_prefix="notification")
    async def notification(
        self, info: strawberry.Info, id: UUID
    ) -> NotificationType | None:
        """Get a specific notification by ID."""
        try:
            service = info.context["container"].resolve("NotificationService")
            notification_dto = await service.get_notification_by_id(id)

            if not notification_dto:
                return None

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.to_graphql_type(notification_dto)

        except Exception as e:
            logger.exception(f"Error fetching notification {id}: {e}")
            raise ValidationError("Failed to fetch notification")

    @strawberry.field(description="List notifications with filtering and pagination")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_list", max_attempts=50, window=60)
    @audit_log("notification.list")
    @track_metrics("notification_list")
    async def notifications(
        self,
        info: strawberry.Info,
        filters: NotificationFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> NotificationListType:
        """List notifications with advanced filtering and pagination."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Convert GraphQL inputs to DTOs
            filter_dto = None
            if filters:
                from ...mappers.notification_mapper import NotificationMapper

                filter_dto = NotificationMapper.filter_input_to_dto(filters)

            pagination_dto = None
            if pagination:
                pagination_dto = {
                    "page": pagination.page or 1,
                    "page_size": min(pagination.page_size or 20, 100),  # Max 100 items
                    "sort_by": pagination.sort_by,
                    "sort_order": pagination.sort_order,
                }

            result = await service.list_notifications(
                filters=filter_dto, pagination=pagination_dto
            )

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.list_result_to_graphql_type(result)

        except Exception as e:
            logger.exception(f"Error listing notifications: {e}")
            raise ValidationError("Failed to list notifications")

    @strawberry.field(description="Get notifications for current user")
    @require_auth()
    @rate_limit(key="my_notifications", max_attempts=100, window=60)
    @audit_log("notification.my_notifications")
    @track_metrics("my_notifications")
    async def my_notifications(
        self,
        info: strawberry.Info,
        pagination: PaginationInput | None = None,
        status_filter: list[str] | None = None,
    ) -> NotificationListType:
        """Get notifications for the current authenticated user."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve("NotificationService")

            # Build filter for current user
            filters = {"created_by": auth_context.user_id, "status": status_filter}

            pagination_dto = None
            if pagination:
                pagination_dto = {
                    "page": pagination.page or 1,
                    "page_size": min(
                        pagination.page_size or 20, 50
                    ),  # Smaller limit for user queries
                    "sort_by": pagination.sort_by or "created_at",
                    "sort_order": pagination.sort_order or "desc",
                }

            result = await service.list_notifications(
                filters=filters, pagination=pagination_dto
            )

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.list_result_to_graphql_type(result)

        except Exception as e:
            logger.exception(f"Error fetching user notifications: {e}")
            raise ValidationError("Failed to fetch your notifications")

    @strawberry.field(description="Get notification analytics")
    @require_auth()
    @require_permission("notifications:analytics")
    @rate_limit(key="notification_analytics", max_attempts=20, window=60)
    @audit_log("notification.analytics")
    @track_metrics("notification_analytics")
    @cache_result(ttl=300, key_prefix="notification_analytics")  # 5 min cache
    async def notification_analytics(
        self,
        info: strawberry.Info,
        date_range: DateRangeInput | None = None,
        filters: NotificationFilterInput | None = None,
    ) -> NotificationAnalyticsType:
        """Get comprehensive notification analytics."""
        try:
            service = info.context["container"].resolve("NotificationAnalyticsService")

            # Convert inputs to DTOs
            date_range_dto = None
            if date_range:
                date_range_dto = {
                    "start_date": date_range.start_date,
                    "end_date": date_range.end_date,
                }

            filter_dto = None
            if filters:
                from ...mappers.notification_mapper import NotificationMapper

                filter_dto = NotificationMapper.filter_input_to_dto(filters)

            analytics_dto = await service.get_analytics(
                date_range=date_range_dto, filters=filter_dto
            )

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.analytics_dto_to_graphql_type(analytics_dto)

        except Exception as e:
            logger.exception(f"Error fetching notification analytics: {e}")
            raise ValidationError("Failed to fetch analytics")

    @strawberry.field(description="Get notification summary statistics")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_summary", max_attempts=30, window=60)
    @audit_log("notification.summary")
    @track_metrics("notification_summary")
    @cache_result(ttl=180, key_prefix="notification_summary")  # 3 min cache
    async def notification_summary(
        self, info: strawberry.Info, date_range: DateRangeInput | None = None
    ) -> NotificationSummaryType:
        """Get summary statistics for notifications."""
        try:
            service = info.context["container"].resolve("NotificationService")

            date_range_dto = None
            if date_range:
                date_range_dto = {
                    "start_date": date_range.start_date,
                    "end_date": date_range.end_date,
                }

            summary_dto = await service.get_summary(date_range=date_range_dto)

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.summary_dto_to_graphql_type(summary_dto)

        except Exception as e:
            logger.exception(f"Error fetching notification summary: {e}")
            raise ValidationError("Failed to fetch summary")

    @strawberry.field(description="Get notification batch by ID")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_batch", max_attempts=50, window=60)
    @audit_log("notification.get_batch")
    @track_metrics("notification_get_batch")
    @cache_result(ttl=120, key_prefix="notification_batch")
    async def notification_batch(
        self, info: strawberry.Info, id: UUID
    ) -> NotificationBatchType | None:
        """Get a notification batch by ID."""
        try:
            service = info.context["container"].resolve("NotificationBatchService")
            batch_dto = await service.get_batch_by_id(id)

            if not batch_dto:
                return None

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.batch_dto_to_graphql_type(batch_dto)

        except Exception as e:
            logger.exception(f"Error fetching notification batch {id}: {e}")
            raise ValidationError("Failed to fetch notification batch")

    @strawberry.field(description="Search notifications by content")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_search", max_attempts=30, window=60)
    @audit_log("notification.search")
    @track_metrics("notification_search")
    async def search_notifications(
        self,
        info: strawberry.Info,
        query: str,
        filters: NotificationFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> NotificationListType:
        """Search notifications by content and metadata."""
        try:
            if len(query.strip()) < MIN_SEARCH_QUERY_LENGTH:
                raise ValidationError(f"Search query must be at least {MIN_SEARCH_QUERY_LENGTH} characters")

            service = info.context["container"].resolve("NotificationSearchService")

            # Convert inputs
            filter_dto = None
            if filters:
                from ...mappers.notification_mapper import NotificationMapper

                filter_dto = NotificationMapper.filter_input_to_dto(filters)

            pagination_dto = {
                "page": pagination.page or 1 if pagination else 1,
                "page_size": min(
                    (pagination.page_size or 20) if pagination else 20, 50
                ),
                "sort_by": "relevance",  # Search results sorted by relevance
            }

            result = await service.search_notifications(
                query=query.strip(), filters=filter_dto, pagination=pagination_dto
            )

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.list_result_to_graphql_type(result)

        except Exception as e:
            logger.exception(f"Error searching notifications: {e}")
            raise ValidationError("Failed to search notifications")

    @strawberry.field(description="Get notifications by campaign")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notifications_by_campaign", max_attempts=50, window=60)
    @audit_log("notification.by_campaign")
    @track_metrics("notifications_by_campaign")
    async def notifications_by_campaign(
        self,
        info: strawberry.Info,
        campaign_id: UUID,
        pagination: PaginationInput | None = None,
    ) -> NotificationListType:
        """Get all notifications for a specific campaign."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Build filter for campaign
            filters = {"campaign_id": campaign_id}

            pagination_dto = None
            if pagination:
                pagination_dto = {
                    "page": pagination.page or 1,
                    "page_size": min(pagination.page_size or 20, 100),
                    "sort_by": pagination.sort_by or "created_at",
                    "sort_order": pagination.sort_order or "desc",
                }

            result = await service.list_notifications(
                filters=filters, pagination=pagination_dto
            )

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.list_result_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                f"Error fetching notifications for campaign {campaign_id}: {e}"
            )
            raise ValidationError("Failed to fetch campaign notifications")

    @strawberry.field(description="Get notification status history")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="notification_status_history", max_attempts=50, window=60)
    @audit_log("notification.status_history")
    @track_metrics("notification_status_history")
    async def notification_status_history(
        self, info: strawberry.Info, notification_id: UUID
    ) -> list[str]:  # JSON string array of status changes
        """Get the status change history for a notification."""
        try:
            service = info.context["container"].resolve("NotificationService")
            history = await service.get_status_history(notification_id)

            # Return as JSON string for GraphQL compatibility
            import json

            return json.dumps(history) if history else "[]"

        except Exception as e:
            logger.exception(
                f"Error fetching status history for {notification_id}: {e}"
            )
            raise ValidationError("Failed to fetch status history")

    @strawberry.field(description="Get recent notifications (last 24 hours)")
    @require_auth()
    @require_permission("notifications:read")
    @rate_limit(key="recent_notifications", max_attempts=50, window=60)
    @audit_log("notification.recent")
    @track_metrics("recent_notifications")
    @cache_result(ttl=300, key_prefix="recent_notifications")
    async def recent_notifications(
        self, info: strawberry.Info, limit: int | None = 10
    ) -> list[NotificationType]:
        """Get recent notifications from the last 24 hours."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Get notifications from last 24 hours
            from datetime import timedelta

            yesterday = datetime.utcnow() - timedelta(days=1)

            filters = {"created_after": yesterday}

            pagination = {
                "page": 1,
                "page_size": min(limit or 10, 50),
                "sort_by": "created_at",
                "sort_order": "desc",
            }

            result = await service.list_notifications(
                filters=filters, pagination=pagination
            )

            from ...mappers.notification_mapper import NotificationMapper

            return [
                NotificationMapper.to_graphql_type(dto)
                for dto in result.get("items", [])
            ]

        except Exception as e:
            logger.exception(f"Error fetching recent notifications: {e}")
            raise ValidationError("Failed to fetch recent notifications")
